"""Every node in the review graph.

Each function takes the shared :class:`~codeguard.state.ReviewState` and returns
**only the channels it updates** — LangGraph merges those updates through the
channel reducers, which is what lets three specialist agents write ``findings``
concurrently in the same superstep without clobbering one another.

Node names carry the course vocabulary deliberately: ``security_agent_node``,
``route_after_synthesis``, ``apply_fix``.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from langgraph.types import interrupt

from codeguard.agents.base import AgentRun
from codeguard.agents.coordinator import CoordinatorAgent
from codeguard.agents.coverage_agent import TestCoverageAgent
from codeguard.agents.security_agent import SecurityAgent
from codeguard.agents.style_agent import StyleAgent
from codeguard.agents.synthesizer import ReviewSynthesizerAgent
from codeguard.config import PROJECT_ROOT, Settings, get_settings
from codeguard.guardrails.injection import check_and_log
from codeguard.guardrails.redaction import redact
from codeguard.llm.router import LLMRouter, get_router
from codeguard.state import (
    Finding,
    ReviewState,
    Severity,
    Verdict,
    blocking_findings,
    current_findings,
)
from codeguard.tools.repo_tools import PullRequest, pr_context
from codeguard.tools.sandbox import review_root

SPECIALISTS = {
    "SecurityAgent": SecurityAgent,
    "StyleAgent": StyleAgent,
    "TestCoverageAgent": TestCoverageAgent,
}


class GraphNodes:
    """Node implementations, bound to a router so tests can inject a stub."""

    def __init__(
        self,
        router: LLMRouter | None = None,
        settings: Settings | None = None,
        verbose: bool = True,
    ) -> None:
        self.router = router or get_router()
        self.settings = settings or get_settings()
        self.verbose = verbose

    # --- helpers -----------------------------------------------------------

    def _pr(self, state: ReviewState) -> PullRequest:
        """Rebuild the PR handle from state, pointing at the working copy."""
        return PullRequest(
            pr_id=state["pr_id"],
            title=state.get("pr_title", ""),
            description=state.get("pr_description", ""),
            changed_files=list(state.get("changed_files", [])),
            root=Path(state["workdir_path"]),
        )

    def _say(self, line: str) -> None:
        if self.verbose:
            print(line, flush=True)

    def _run_specialist(self, state: ReviewState, agent_name: str) -> dict[str, Any]:
        """Shared body for the three specialist nodes (the parallel fan-out)."""
        iteration = state.get("iteration", 0)
        if agent_name not in state.get("delegated_agents", []) and iteration == 0:
            self._say(f"  [{agent_name}] skipped — coordinator did not delegate to it")
            return {"scratchpad": [f"[{agent_name}] skipped by coordinator delegation"]}

        agent = SPECIALISTS[agent_name](router=self.router, verbose=self.verbose)
        pr = self._pr(state)
        task = (
            f"Review pull request {pr.pr_id} — '{pr.title}'.\n"
            f"Description: {pr.description[:600]}\n"
            f"Changed files: {', '.join(pr.changed_files)}\n"
        )
        if iteration > 0:
            task += (
                f"\nThis is REMEDIATION ITERATION {iteration}. Fixes were applied to "
                "the working copy since the last scan. Re-run your tools and report "
                "only what is STILL wrong.\n"
            )

        with review_root(pr.root), pr_context(pr):
            run: AgentRun = agent.run(task, prior_scratchpad=state.get("scratchpad", []))

        if run.error or run.report is None:
            self._say(f"  [{agent_name}] degraded: {run.error}")
            return {
                "scratchpad": [*run.scratchpad, f"[{agent_name}] DEGRADED: {run.error}"],
                "cost_usd": run.cost_usd,
            }

        # Stamp the iteration so a re-scan is distinguishable from the first pass.
        findings = [
            f.model_copy(update={"iteration": iteration, "agent": agent_name})
            for f in run.report.findings
        ]
        self._say(
            f"  [{agent_name}] iteration {iteration}: {len(findings)} finding(s), "
            f"{sum(f.is_false_positive for f in findings)} triaged as false positive"
        )
        return {
            "findings": findings,
            "scratchpad": [*run.scratchpad, f"[{agent_name}] judgment: {run.report.judgment}"],
            "cost_usd": run.cost_usd,
        }

    # --- nodes -------------------------------------------------------------

    def ingest_pr(self, state: ReviewState) -> dict[str, Any]:
        """Entry node: record the PR and confirm the working copy exists."""
        root = Path(state["workdir_path"])
        self._say(f"\n{'#' * 78}\n# ingest_pr  {state['pr_id']} — {state.get('pr_title', '')}\n{'#' * 78}")
        self._say(f"  working copy : {root}")
        self._say(f"  changed files: {len(state.get('changed_files', []))}")
        if not root.is_dir():
            return {"status": "error", "scratchpad": [f"[ingest_pr] missing working copy {root}"]}
        return {
            "status": "ingested",
            "scratchpad": [
                f"[ingest_pr] {state['pr_id']} with "
                f"{len(state.get('changed_files', []))} changed files"
            ],
        }

    def guardrail_input(self, state: ReviewState) -> dict[str, Any]:
        """INPUT GUARDRAIL — injection detection, then redaction.

        Order matters. Detection runs on the raw text, because redacting first
        could mangle the very payload we are trying to recognise. Redaction runs
        second, so whatever continues downstream is already masked.
        """
        enabled = self.settings.guardrails_enabled
        sources = {
            "pr_title": state.get("pr_title", ""),
            "pr_description": state.get("pr_description", ""),
            "diff": state.get("diff", ""),
        }
        verdict = check_and_log(sources, enabled=enabled)

        banner = "guardrail_input" + ("" if enabled else "  [DISABLED — A/B run]")
        self._say(f"\n{'#' * 78}\n# {banner}\n{'#' * 78}")
        if verdict.matches:
            self._say(f"  DETECTED {len(verdict.matches)} injection match(es): "
                      f"{', '.join(verdict.rule_ids)}")
            for m in verdict.matches[:4]:
                self._say(f"    - {m['rule_id']:<22} in {m['source']}: {m['excerpt'][:88]}")
        else:
            self._say("  clean — no injection patterns matched")

        event = verdict.to_event()
        event["guardrails_enabled"] = enabled
        updates: dict[str, Any] = {"guardrail_events": [event]}

        if verdict.blocked:
            self._say("  -> routing to blocked; PR text never reaches the model")
            return {**updates, "status": "blocked",
                    "scratchpad": [f"[guardrail_input] BLOCKED: {', '.join(verdict.rule_ids)}"]}

        # Data guardrail: mask anything sensitive in the PR text itself.
        red_title = redact(state.get("pr_title", ""), source="pr_title")
        red_desc = redact(state.get("pr_description", ""), source="pr_description")
        red_diff = redact(state.get("diff", ""), source="diff")
        masked = red_title.masked_count + red_desc.masked_count + red_diff.masked_count
        if masked:
            self._say(f"  redacted {masked} sensitive value(s) from PR text before the model")

        return {
            **updates,
            "status": "guardrail_passed",
            "pr_title": red_title.text,
            "pr_description": red_desc.text,
            "diff": red_diff.text,
            "scratchpad": [
                f"[guardrail_input] passed; redacted {masked} value(s) from PR text"
            ],
        }

    def blocked(self, state: ReviewState) -> dict[str, Any]:
        """Terminal node for a PR that failed the input guardrail."""
        events = state.get("guardrail_events", [])
        rules = events[-1].get("rule_ids", []) if events else []
        self._say(f"\n{'#' * 78}\n# blocked — review abandoned\n{'#' * 78}")
        verdict = Verdict(
            decision="BLOCK_MERGE",
            rationale=(
                "Blocked by the input guardrail before any analysis. The PR text "
                f"contains prompt-injection patterns ({', '.join(rules)}) attempting to "
                "manipulate the automated reviewer. No PR content was sent to the model."
            ),
            blocking_findings=[],
        )
        return {"verdict": verdict, "status": "blocked",
                "scratchpad": ["[blocked] review terminated by input guardrail"]}

    def coordinator_node(self, state: ReviewState) -> dict[str, Any]:
        """Centralized coordinator: plans the review and delegates hierarchically."""
        self._say(f"\n{'#' * 78}\n# coordinator — planning and delegation\n{'#' * 78}")
        agent = CoordinatorAgent(router=self.router, verbose=self.verbose)
        pr = self._pr(state)
        task = (
            f"Plan the review of pull request {pr.pr_id} — '{pr.title}'.\n"
            f"Description: {pr.description[:600]}\n"
            f"Changed files: {', '.join(pr.changed_files)}\n"
        )
        with review_root(pr.root), pr_context(pr):
            run = agent.run(task)

        if run.error or run.report is None:
            # Degrading to "run everything" is the safe direction: a planning
            # failure must not silently skip the security review.
            self._say(f"  coordinator degraded ({run.error}) — delegating to all specialists")
            return {
                "plan": ["fallback: full review"],
                "delegated_agents": list(SPECIALISTS),
                "status": "planned",
                "cost_usd": run.cost_usd,
                "scratchpad": [*run.scratchpad, "[coordinator] DEGRADED -> full delegation"],
            }

        plan = run.report
        delegated = [a for a in plan.delegate_to if a in SPECIALISTS] or list(SPECIALISTS)
        self._say(f"  plan      : {plan.steps}")
        self._say(f"  delegating: {delegated}")
        self._say(f"  rationale : {plan.rationale[:200]}")
        return {
            "plan": plan.steps,
            "delegated_agents": delegated,
            "status": "planned",
            "cost_usd": run.cost_usd,
            "scratchpad": [*run.scratchpad, f"[CoordinatorAgent] delegation: {delegated}"],
        }

    # --- the parallel fan-out ---------------------------------------------

    def security_agent_node(self, state: ReviewState) -> dict[str, Any]:
        return self._run_specialist(state, "SecurityAgent")

    def style_agent_node(self, state: ReviewState) -> dict[str, Any]:
        return self._run_specialist(state, "StyleAgent")

    def coverage_agent_node(self, state: ReviewState) -> dict[str, Any]:
        return self._run_specialist(state, "TestCoverageAgent")

    # --- fan-in ------------------------------------------------------------

    def synthesizer_node(self, state: ReviewState) -> dict[str, Any]:
        """Fan-in: merge the specialists' findings into one verdict."""
        iteration = state.get("iteration", 0)
        findings = current_findings(state)
        self._say(f"\n{'#' * 78}\n# synthesizer — iteration {iteration}, "
                  f"{len(findings)} finding(s) in scope\n{'#' * 78}")

        agent = ReviewSynthesizerAgent(router=self.router, verbose=self.verbose)
        try:
            verdict, scratch, cost = agent.synthesize(
                findings,
                pr_title=state.get("pr_title", ""),
                agents_run=state.get("delegated_agents", []),
            )
        except Exception as exc:  # noqa: BLE001 - never lose the review to synthesis
            self._say(f"  synthesizer degraded: {exc}")
            worst = max((f.severity for f in findings if not f.is_false_positive),
                        key=lambda s: list(Severity).index(s), default=None)
            decision = "BLOCK_MERGE" if worst == Severity.CRITICAL else (
                "REQUEST_CHANGES" if findings else "APPROVE")
            verdict = Verdict(
                decision=decision,
                rationale=f"Synthesis degraded ({type(exc).__name__}); "
                          "decision derived mechanically from finding severities.",
                blocking_findings=[f for f in findings if f.is_blocking()],
            )
            scratch, cost = [f"[synthesizer] DEGRADED: {exc}"], 0.0

        history = {
            "iteration": iteration,
            "findings_total": len(findings),
            "findings_blocking": len([f for f in findings if f.is_blocking()]),
            "false_positives": len([f for f in findings if f.is_false_positive]),
            "decision": verdict.decision,
        }
        self._say(f"  iteration {iteration}: {history['findings_total']} findings "
                  f"({history['findings_blocking']} blocking) -> {verdict.decision}")
        return {
            "verdict": verdict,
            "status": "synthesized",
            "cost_usd": cost,
            "iteration_history": [history],
            "scratchpad": scratch,
        }

    # --- the remediation loop ---------------------------------------------

    def remediation_loop(self, state: ReviewState) -> dict[str, Any]:
        """Bookkeeping node: records why the loop is being entered."""
        iteration = state.get("iteration", 0)
        blocking = blocking_findings(state)
        fixable = [f for f in blocking if f.suggested_fix]
        self._say(f"\n{'#' * 78}\n# remediation_loop — iteration {iteration} -> "
                  f"{iteration + 1} (max {self.settings.max_iter})\n{'#' * 78}")
        self._say(f"  {len(blocking)} blocking finding(s), {len(fixable)} with an applicable fix")
        return {
            "status": "remediating",
            "scratchpad": [
                f"[remediation_loop] entering iteration {iteration + 1}: "
                f"{len(blocking)} blocking, {len(fixable)} fixable"
            ],
        }

    def apply_fix(self, state: ReviewState) -> dict[str, Any]:
        """Patch the WORKING COPY so the next scan sees genuinely different code.

        Line-level substitution is enough here — the point is that the next
        iteration analyses changed bytes on disk, not that the patch semantics
        are sophisticated. The fixture is never touched.
        """
        root = Path(state["workdir_path"])
        iteration = state.get("iteration", 0)
        patched: list[str] = []
        notes: list[str] = []

        for f in blocking_findings(state):
            if not f.suggested_fix or f.line is None:
                continue
            target = root / f.file
            if not target.exists():
                continue
            try:
                lines = target.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            if not 1 <= f.line <= len(lines):
                continue

            old = lines[f.line - 1]
            new = f.suggested_fix.rstrip("\n").splitlines()[0] if f.suggested_fix.strip() else ""
            if not new or old.strip() == new.strip():
                continue
            # Preserve the original indentation; the model rarely gets it right.
            indent = old[: len(old) - len(old.lstrip())]
            if not new.startswith((" ", "\t")):
                new = indent + new.lstrip()

            lines[f.line - 1] = new
            target.write_text("\n".join(lines) + "\n", encoding="utf-8")
            patched.append(f"{f.file}:{f.line}")
            notes.append(f"    {f.file}:{f.line}\n      - {old.strip()[:70]}\n      + {new.strip()[:70]}")

        self._say(f"  applied {len(patched)} fix(es) to the working copy:")
        for n in notes:
            self._say(n)
        if not patched:
            self._say("    (nothing applicable — the loop will terminate on the next route)")

        return {
            "iteration": iteration + 1,
            "patched_files": patched,
            "status": "patched",
            "scratchpad": [f"[apply_fix] iteration {iteration}: patched {len(patched)} line(s): "
                           f"{', '.join(patched) or 'none'}"],
        }

    # --- human in the loop -------------------------------------------------

    def hitl_approval(self, state: ReviewState) -> dict[str, Any]:
        """HUMAN-IN-THE-LOOP: pause the graph until a person decides.

        ``interrupt()`` suspends execution and persists state via the
        checkpointer. The process can exit entirely; resuming the same
        ``thread_id`` with ``Command(resume=...)`` continues from this point.
        """
        verdict = state.get("verdict")
        blocking = blocking_findings(state)
        self._say(f"\n{'#' * 78}\n# hitl_approval — PAUSING for human decision\n{'#' * 78}")
        for f in blocking[:6]:
            self._say(f"    {f.severity.value:<9}{f.file}:{f.line}  {f.message[:56]}")

        decision = interrupt({
            "type": "human_approval_required",
            "pr_id": state["pr_id"],
            "pr_title": state.get("pr_title", ""),
            "proposed_verdict": verdict.decision if verdict else "UNKNOWN",
            "rationale": verdict.rationale if verdict else "",
            "blocking_findings": [
                {"severity": f.severity.value, "file": f.file, "line": f.line,
                 "message": f.message}
                for f in blocking
            ],
            "options": ["approve", "reject"],
        })

        if isinstance(decision, dict):
            choice = str(decision.get("decision", "reject")).lower()
            reason = str(decision.get("reason", ""))
        else:
            choice, reason = str(decision).lower(), ""

        self._say(f"  human decision received: {choice}  ({reason[:80]})")
        return {
            "hitl_decision": choice,
            "hitl_reason": reason,
            "status": "hitl_decided",
            "scratchpad": [f"[hitl_approval] human decided: {choice} — {reason[:120]}"],
        }

    def apply_decision(self, state: ReviewState) -> dict[str, Any]:
        """Fold the human's decision into the verdict."""
        decision = (state.get("hitl_decision") or "reject").lower()
        verdict = state.get("verdict")
        blocking = blocking_findings(state)
        reason = state.get("hitl_reason") or ""

        if decision in ("approve", "approved", "override"):
            new_verdict = Verdict(
                decision="APPROVE",
                rationale=(
                    "Human reviewer overrode the automated BLOCK_MERGE after reviewing "
                    f"{len(blocking)} critical finding(s). Reviewer reason: {reason or 'n/a'}. "
                    "Original automated rationale: "
                    f"{verdict.rationale if verdict else 'n/a'}"
                ),
                blocking_findings=[],
            )
        else:
            new_verdict = Verdict(
                decision="BLOCK_MERGE",
                rationale=(
                    f"Human reviewer confirmed the block. Reason: {reason or 'n/a'}. "
                    f"{len(blocking)} critical finding(s) must be resolved before merge."
                ),
                blocking_findings=blocking,
            )
        self._say(f"  apply_decision -> {new_verdict.decision}")
        return {"verdict": new_verdict, "status": "decided",
                "scratchpad": [f"[apply_decision] final verdict {new_verdict.decision}"]}

    # --- exit --------------------------------------------------------------

    def finalize(self, state: ReviewState) -> dict[str, Any]:
        verdict = state.get("verdict")
        self._say(f"\n{'#' * 78}\n# finalize — {verdict.decision if verdict else 'NO VERDICT'}\n{'#' * 78}")
        return {"status": "finalized",
                "scratchpad": [f"[finalize] {verdict.decision if verdict else 'none'}"]}

    def persist_report(self, state: ReviewState) -> dict[str, Any]:
        """Write the review report as an artifact."""
        verdict = state.get("verdict")
        report = {
            "pr_id": state["pr_id"],
            "pr_title": state.get("pr_title", ""),
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "decision": verdict.decision if verdict else "UNKNOWN",
            "rationale": verdict.rationale if verdict else "",
            "iterations_run": state.get("iteration", 0),
            "iteration_history": state.get("iteration_history", []),
            "patched_files": state.get("patched_files", []),
            "hitl_decision": state.get("hitl_decision"),
            "guardrail_events": state.get("guardrail_events", []),
            "cost_usd": round(state.get("cost_usd", 0.0), 8),
            "findings": [f.model_dump(mode="json") for f in current_findings(state)],
        }
        out_dir = PROJECT_ROOT / "artifacts"
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{state['pr_id']}-{int(time.time())}.json"
        path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        self._say(f"  report written: {path.relative_to(PROJECT_ROOT)}")

        uploaded = self._upload(path, report)
        return {
            "status": "reported",
            "scratchpad": [f"[persist_report] {path.name}" + (f" -> {uploaded}" if uploaded else "")],
        }

    def _upload(self, path: Path, report: dict[str, Any]) -> str | None:
        """Upload to MinIO when it is reachable. Wired fully in Phase 8."""
        try:
            from codeguard.storage.artifacts import upload_report
        except ImportError:
            return None
        try:
            return upload_report(path, report)
        except Exception:  # noqa: BLE001 - artifact storage is not on the critical path
            return None
