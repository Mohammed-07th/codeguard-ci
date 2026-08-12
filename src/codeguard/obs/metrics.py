"""Structured monitoring: one JSON line per LLM call, tool call and guardrail event.

Deliverable 4 requires structured monitoring that captures tool calls, latency,
cost and failures — "not print statements". Every row written here is machine
readable and appended to ``evidence/metrics.jsonl``, which is what the evidence
notebook aggregates into the run summary table.

Nothing in this module ever fabricates a number: cost comes from token counts
reported by the provider, latency from a monotonic clock. When a model's price is
unknown the row is flagged ``price_known: false`` rather than being given a
made-up cost.
"""

from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Literal

from codeguard.config import PROJECT_ROOT, get_settings

EventKind = Literal["llm", "tool", "guardrail", "node", "graph"]

# Set once per review run so every row can be traced back to its PR / thread.
_current_thread_id: ContextVar[str | None] = ContextVar("codeguard_thread_id", default=None)
_current_pr_id: ContextVar[str | None] = ContextVar("codeguard_pr_id", default=None)
_current_agent: ContextVar[str | None] = ContextVar("codeguard_agent", default=None)


@contextmanager
def current_agent(agent: str) -> Iterator[None]:
    """Attribute every event emitted in this block to ``agent``."""
    token = _current_agent.set(agent)
    try:
        yield
    finally:
        _current_agent.reset(token)


@contextmanager
def run_context(thread_id: str, pr_id: str | None = None) -> Iterator[None]:
    """Tag every metrics row emitted inside this block with a thread / PR id."""
    t1 = _current_thread_id.set(thread_id)
    t2 = _current_pr_id.set(pr_id)
    try:
        yield
    finally:
        _current_thread_id.reset(t1)
        _current_pr_id.reset(t2)


class MetricsLogger:
    """Append-only JSONL sink. Thread-safe because the agent fan-out is parallel."""

    def __init__(self, path: Path | str | None = None) -> None:
        if path is None:
            path = get_settings().metrics_file
        self.path = Path(path)
        if not self.path.is_absolute():
            self.path = PROJECT_ROOT / self.path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def record(self, kind: EventKind, **fields: Any) -> dict[str, Any]:
        row: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "kind": kind,
            "thread_id": _current_thread_id.get(),
            "pr_id": _current_pr_id.get(),
            **fields,
        }
        line = json.dumps(row, default=str)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return row

    # --- typed helpers -----------------------------------------------------

    def log_llm_call(
        self,
        *,
        tag: str,
        requested_model: str,
        actual_model: str | None,
        complexity: str,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
        price_known: bool,
        latency_ms: float,
        ok: bool,
        shadow_cost_usd: float = 0.0,
        attempts: int = 1,
        fallback_used: bool = False,
        error: str | None = None,
    ) -> dict[str, Any]:
        return self.record(
            "llm",
            tag=tag,
            requested_model=requested_model,
            actual_model=actual_model,
            complexity=complexity,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            cost_usd=cost_usd,
            shadow_cost_usd=shadow_cost_usd,
            price_known=price_known,
            latency_ms=round(latency_ms, 1),
            ok=ok,
            attempts=attempts,
            fallback_used=fallback_used,
            error=error,
        )

    def log_tool_call(
        self,
        *,
        tool: str,
        agent: str | None,
        args_summary: str,
        latency_ms: float,
        ok: bool,
        result_summary: str = "",
        error: str | None = None,
    ) -> dict[str, Any]:
        return self.record(
            "tool",
            tool=tool,
            agent=agent or _current_agent.get(),
            args_summary=args_summary,
            latency_ms=round(latency_ms, 1),
            ok=ok,
            result_summary=result_summary,
            error=error,
        )

    def log_guardrail(
        self,
        *,
        guardrail: str,
        triggered: bool,
        detail: str,
        matched_pattern: str | None = None,
        excerpt: str = "",
    ) -> dict[str, Any]:
        return self.record(
            "guardrail",
            guardrail=guardrail,
            triggered=triggered,
            detail=detail,
            matched_pattern=matched_pattern,
            excerpt=excerpt,
        )

    # --- reading back ------------------------------------------------------

    def read(self, thread_id: str | None = None) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        rows = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if thread_id is None or row.get("thread_id") == thread_id:
                rows.append(row)
        return rows


@contextmanager
def timed() -> Iterator[dict[str, float]]:
    """Measure wall-clock latency in ms: ``with timed() as t: ...; t['ms']``."""
    holder = {"ms": 0.0}
    start = time.perf_counter()
    try:
        yield holder
    finally:
        holder["ms"] = (time.perf_counter() - start) * 1000.0


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate metrics rows into the run summary used in the evidence notebook."""
    llm = [r for r in rows if r.get("kind") == "llm"]
    tools = [r for r in rows if r.get("kind") == "tool"]
    guards = [r for r in rows if r.get("kind") == "guardrail"]

    lat = sorted(r.get("latency_ms", 0.0) for r in llm)
    def _pct(p: float) -> float:
        if not lat:
            return 0.0
        idx = min(len(lat) - 1, int(round((p / 100.0) * (len(lat) - 1))))
        return round(lat[idx], 1)

    by_model: dict[str, dict[str, Any]] = {}
    for r in llm:
        m = r.get("actual_model") or r.get("requested_model") or "unknown"
        e = by_model.setdefault(m, {"calls": 0, "tokens": 0, "cost_usd": 0.0})
        e["calls"] += 1
        e["tokens"] += r.get("total_tokens", 0)
        e["cost_usd"] = round(e["cost_usd"] + r.get("cost_usd", 0.0), 8)

    return {
        "llm_calls": len(llm),
        "llm_failures": sum(1 for r in llm if not r.get("ok", True)),
        "fallback_calls": sum(1 for r in llm if r.get("fallback_used")),
        "total_input_tokens": sum(r.get("input_tokens", 0) for r in llm),
        "total_output_tokens": sum(r.get("output_tokens", 0) for r in llm),
        "total_cost_usd": round(sum(r.get("cost_usd", 0.0) for r in llm), 6),
        "shadow_cost_usd": round(sum(r.get("shadow_cost_usd", 0.0) for r in llm), 6),
        "unpriced_calls": sum(1 for r in llm if not r.get("price_known", True)),
        "latency_p50_ms": _pct(50),
        "latency_p95_ms": _pct(95),
        "tool_calls": len(tools),
        "tool_failures": sum(1 for r in tools if not r.get("ok", True)),
        "guardrail_events": len(guards),
        "guardrail_triggered": sum(1 for r in guards if r.get("triggered")),
        "by_model": by_model,
    }


def print_summary(rows: list[dict[str, Any]], title: str = "Run summary") -> dict[str, Any]:
    """Render the summary as a table. Returns the aggregate dict for assertions."""
    s = summarize(rows)
    try:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        t = Table(title=title, header_style="bold")
        t.add_column("Metric")
        t.add_column("Value", justify="right")
        for k in (
            "llm_calls", "llm_failures", "fallback_calls",
            "total_input_tokens", "total_output_tokens", "total_cost_usd", "shadow_cost_usd",
            "latency_p50_ms", "latency_p95_ms",
            "tool_calls", "tool_failures", "guardrail_triggered",
        ):
            t.add_row(k, str(s[k]))
        console.print(t)

        if s["by_model"]:
            m = Table(title="Per-model breakdown", header_style="bold")
            m.add_column("Model")
            m.add_column("Calls", justify="right")
            m.add_column("Tokens", justify="right")
            m.add_column("Cost USD", justify="right")
            for name, e in s["by_model"].items():
                m.add_row(name, str(e["calls"]), str(e["tokens"]), f"{e['cost_usd']:.6f}")
            console.print(m)
    except ImportError:  # rich is optional at runtime
        print(f"--- {title} ---")
        for k, v in s.items():
            print(f"  {k}: {v}")
    return s


class PromptLogger:
    """Records the exact text sent to the model, for the redaction grep proof.

    Deliverable 4 asks for evidence that no raw secret reached the LLM. The only
    honest way to show that is to capture what was actually transmitted and grep
    it. This writes that record; ``guardrails.redaction.assert_clean`` checks it.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        p = Path(path) if path else PROJECT_ROOT / "evidence" / "prompts.jsonl"
        self.path = p if p.is_absolute() else PROJECT_ROOT / p
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def log(self, tag: str, messages: Any, model: str = "") -> None:
        rendered: list[dict[str, str]] = []
        if isinstance(messages, str):
            rendered.append({"role": "user", "content": messages})
        else:
            for m in messages or []:
                rendered.append({
                    "role": getattr(m, "type", m.__class__.__name__),
                    "content": str(getattr(m, "content", m)),
                })
        row = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "thread_id": _current_thread_id.get(),
            "pr_id": _current_pr_id.get(),
            "agent": _current_agent.get(),
            "tag": tag,
            "model": model,
            "messages": rendered,
        }
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, default=str) + "\n")

    def read_text(self) -> str:
        """The whole transmitted corpus as one string, ready to grep."""
        return self.path.read_text(encoding="utf-8") if self.path.exists() else ""


# Module-level sinks used across the app.
METRICS = MetricsLogger()
PROMPTS = PromptLogger()
