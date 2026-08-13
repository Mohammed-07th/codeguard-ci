"""FastAPI service — the deployed face of the review system.

Endpoints:

* ``GET  /health``                      liveness plus real component checks
* ``POST /webhook/pr``                  a pull request arrives; a review starts
* ``GET  /review/{thread_id}``          current state of a review
* ``POST /review/{thread_id}/resume``   deliver a human decision to a paused graph
* ``GET  /reports``                     artifacts written to object storage

The resume endpoint is what makes human-in-the-loop deployable rather than a
notebook trick: the graph pauses inside ``interrupt()`` with its state
checkpointed, this process can be restarted or replaced, and the decision
arrives later over HTTP against the same ``thread_id``.

Reviews run as background tasks. A full review takes minutes, and a webhook that
blocks for minutes gets retried by the sender and times out.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Literal

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

# Loaded before settings are read so the container picks up a mounted .env even
# when the values were not injected as environment variables.
load_dotenv(override=False)

from codeguard.config import get_settings  # noqa: E402
from codeguard.deps import dependency_report  # noqa: E402
from codeguard.graph.build import (  # noqa: E402
    build_graph,
    make_checkpointer,
    prepare_initial_state,
)
from codeguard.graph.resume import checkpoint_summary, pending_interrupt  # noqa: E402
from codeguard.guardrails import injection  # noqa: E402
from codeguard.obs.metrics import METRICS, run_context, summarize  # noqa: E402
from codeguard.obs.tracing import setup_tracing  # noqa: E402
from codeguard.state import current_findings, new_state  # noqa: E402
from codeguard.storage import artifacts  # noqa: E402

log = logging.getLogger(__name__)
settings = get_settings()
setup_tracing()

app = FastAPI(
    title="CodeGuard CI",
    version="0.1.0",
    description="Agentic code-review and secrets-scanning for CI pipelines.",
)

# thread_id -> lightweight status, so a caller can poll without touching SQLite.
_RUNS: dict[str, dict[str, Any]] = {}

# Injection seam for the LLM router. Left as None in production, where the graph
# builds its own live router. Tests set it to a stub so the API surface can be
# exercised end to end without spending a rate-limited model call.
ROUTER_FACTORY: Any = None


def _router():
    return ROUTER_FACTORY() if ROUTER_FACTORY is not None else None


# --------------------------------------------------------------------------- #
# schemas
# --------------------------------------------------------------------------- #

class PRWebhook(BaseModel):
    """Incoming pull request.

    Either name a bundled ``fixture`` (the demo path) or supply the PR content
    inline, including the file tree so the analysers have something real to read.
    """

    pr_id: str | None = Field(default=None, examples=["PR-1042"])
    title: str = ""
    description: str = ""
    changed_files: list[str] = Field(default_factory=list)
    diff: str = ""
    files: dict[str, str] = Field(
        default_factory=dict,
        description="path -> content. Required for a real review; the analysers "
                    "run against actual files.",
    )
    fixture: str | None = Field(
        default=None, description="Name of a bundled fixture, e.g. 'pr_with_secret'."
    )


class ResumeRequest(BaseModel):
    decision: Literal["approve", "reject"]
    reason: str = ""


# --------------------------------------------------------------------------- #
# health
# --------------------------------------------------------------------------- #

@app.get("/health")
def health() -> dict[str, Any]:
    """Liveness plus the state of each dependency.

    Reports component status without failing the check: the service is genuinely
    usable when object storage is down (reports fall back to local disk), so a
    hard 503 there would take a working deployment out of rotation.
    """
    checkpoint = settings.checkpoint_path
    return {
        "status": "ok",
        "service": "codeguard-ci",
        "version": "0.1.0",
        "components": {
            "checkpointer": {
                "path": str(checkpoint),
                "present": checkpoint.exists(),
                "size_bytes": checkpoint.stat().st_size if checkpoint.exists() else 0,
            },
            "artifact_store": {
                "endpoint": settings.minio_endpoint,
                "reachable": artifacts.is_available(settings),
                "bucket": settings.minio_bucket,
            },
            "tracing": {"collector": settings.phoenix_collector_endpoint},
            "models": {
                "primary": settings.primary_model,
                "fallback": settings.fallback_model,
                "synthesis": settings.synthesis_model,
            },
            "guardrails_enabled": settings.guardrails_enabled,
            # Which library versions actually produced a verdict. A review is
            # not reproducible without them.
            "dependencies": dependency_report(),
        },
        "active_reviews": len([r for r in _RUNS.values() if r["state"] == "running"]),
    }


# --------------------------------------------------------------------------- #
# review lifecycle
# --------------------------------------------------------------------------- #

def _materialise(payload: PRWebhook, thread_id: str):
    """Turn a webhook body into an initial state with a real working copy."""
    if payload.fixture:
        return prepare_initial_state(
            settings.fixtures_dir / payload.fixture, workdir_name=thread_id
        )

    if not payload.pr_id:
        raise HTTPException(422, "pr_id is required when no fixture is named")

    # Fail closed at the API boundary. The graph's guardrail scans the title,
    # description and diff — but an inline payload also carries FILE CONTENTS,
    # which are attacker-supplied and get written to disk before the graph runs.
    # A payload hidden in a submitted file with no diff supplied would otherwise
    # not be scanned until an agent read that file back.
    if settings.guardrails_enabled:
        try:
            injection.enforce({
                "pr_title": payload.title,
                "pr_description": payload.description,
                "diff": payload.diff,
                **{f"file:{k}": v for k, v in payload.files.items()},
            })
        except injection.InjectionBlocked as exc:
            raise HTTPException(
                400,
                f"Prompt injection detected in the submitted payload; refused before "
                f"any file was written. Rules: {', '.join(exc.verdict.rule_ids)}",
            ) from exc

    root = settings.workdir / thread_id
    root.mkdir(parents=True, exist_ok=True)
    for rel, content in payload.files.items():
        target = (root / rel).resolve()
        if root.resolve() not in target.parents:
            # The payload is remote input; a path escaping the working copy is
            # an attack, not a mistake.
            raise HTTPException(400, f"file path escapes the working directory: {rel}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    return new_state(
        pr_id=payload.pr_id,
        pr_title=payload.title,
        pr_description=payload.description,
        changed_files=payload.changed_files or sorted(payload.files),
        diff=payload.diff,
        workdir_path=str(root),
    )


def _run_review(thread_id: str, payload: PRWebhook) -> None:
    """Execute a review to completion or to its human-approval pause."""
    _RUNS[thread_id] = {"state": "running", "started": time.time(), "pr_id": payload.pr_id}
    try:
        state = _materialise(payload, thread_id)
        graph = build_graph(router=_router(), checkpointer=make_checkpointer(), verbose=False)
        with run_context(thread_id=thread_id, pr_id=state["pr_id"]):
            graph.invoke(
                state,
                {"configurable": {"thread_id": thread_id}, "recursion_limit": 60},
            )
        paused = pending_interrupt(graph, thread_id) is not None
        _RUNS[thread_id].update({
            "state": "awaiting_human" if paused else "complete",
            "pr_id": state["pr_id"],
            "finished": time.time(),
        })
    except Exception as exc:  # noqa: BLE001 - surfaced through the status endpoint
        log.exception("review %s failed", thread_id)
        _RUNS[thread_id].update(
            {"state": "failed", "error": f"{type(exc).__name__}: {exc}", "finished": time.time()}
        )


@app.post("/webhook/pr", status_code=202)
def webhook_pr(
    payload: PRWebhook,
    background: BackgroundTasks,
    wait: bool = Query(False, description="Run synchronously. Slow; for demos only."),
) -> dict[str, Any]:
    """Accept a pull request and start a review.

    Returns 202 with a ``thread_id`` to poll. A full review takes minutes, and a
    webhook sender will time out and retry long before that.
    """
    thread_id = f"pr-{payload.fixture or payload.pr_id or 'inline'}-{int(time.time())}"

    if wait:
        _run_review(thread_id, payload)
        return {"thread_id": thread_id, **review_status(thread_id)}

    background.add_task(_run_review, thread_id, payload)
    return {
        "thread_id": thread_id,
        "state": "accepted",
        "poll": f"/review/{thread_id}",
        "resume": f"/review/{thread_id}/resume",
    }


@app.get("/review/{thread_id}")
def review_status(thread_id: str) -> dict[str, Any]:
    """Current state of a review, read from the checkpointer."""
    run = _RUNS.get(thread_id)
    graph = build_graph(router=_router(), checkpointer=make_checkpointer(), verbose=False)
    try:
        snapshot = checkpoint_summary(graph, thread_id)
    except Exception:  # noqa: BLE001
        snapshot = {}
    if not run and not snapshot.get("pr_id"):
        raise HTTPException(404, f"no review found for thread_id {thread_id!r}")

    payload = pending_interrupt(graph, thread_id)
    state = graph.get_state({"configurable": {"thread_id": thread_id}}).values or {}

    return {
        "thread_id": thread_id,
        "state": (run or {}).get("state", "unknown"),
        "error": (run or {}).get("error"),
        "checkpoint": snapshot,
        "awaiting_human": payload is not None,
        "approval_request": payload,
        "findings": [f.model_dump(mode="json") for f in current_findings(state)]
        if state else [],
        "metrics": summarize(METRICS.read(thread_id=thread_id)),
    }


@app.post("/review/{thread_id}/resume")
def resume(thread_id: str, body: ResumeRequest) -> dict[str, Any]:
    """Deliver a human decision to a paused review.

    The graph resumes from its checkpoint — in this process or any other, which
    is the point of persisting the pause rather than holding it in memory.
    """
    from codeguard.graph.resume import resume_review

    # One checkpointer, shared by the readiness check and the resume itself.
    # Letting resume_review build its own would silently point at a different
    # database from the one this request just inspected.
    checkpointer = make_checkpointer()
    graph = build_graph(router=_router(), checkpointer=checkpointer, verbose=False)
    if pending_interrupt(graph, thread_id) is None:
        raise HTTPException(409, f"review {thread_id!r} is not awaiting a human decision")

    final = resume_review(thread_id, body.decision, body.reason,
                          router=_router(), checkpointer=checkpointer, verbose=False)
    verdict = final.get("verdict")
    _RUNS.setdefault(thread_id, {})["state"] = "complete"
    return {
        "thread_id": thread_id,
        "hitl_decision": final.get("hitl_decision"),
        "decision": verdict.decision if verdict else None,
        "rationale": verdict.rationale if verdict else None,
        "status": final.get("status"),
    }


@app.get("/reports")
def reports(limit: int = 20) -> dict[str, Any]:
    """Review reports written to object storage."""
    return {
        "bucket": settings.minio_bucket,
        "reachable": artifacts.is_available(settings),
        "objects": artifacts.list_reports(limit=limit, settings=settings),
    }


if __name__ == "__main__":  # pragma: no cover - entrypoint
    # Mirrors the container CMD, so `python -m codeguard.api.main` serves the
    # same app locally without needing the uvicorn CLI on PATH.
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
