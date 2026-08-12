"""Conditional routing functions — the branching logic of the state graph.

Three decision points, each a genuine branch on state rather than a fixed chain:

* :func:`route_after_guardrail` — blocked, or on to the coordinator.
* :func:`fan_out_to_specialists` — returns a *list* of nodes, so the
  coordinator's delegation decision actually changes which nodes execute rather
  than merely being logged.
* :func:`route_after_synthesis` — **the conditional edge**: human approval,
  another remediation iteration, or finalize.
"""

from __future__ import annotations

from codeguard.config import get_settings
from codeguard.state import (
    SEVERITY_ORDER,
    ReviewState,
    Severity,
    blocking_findings,
    current_findings,
)


def route_after_guardrail(state: ReviewState) -> str:
    """Blocked PRs never reach the coordinator, so their text never reaches a model."""
    return "blocked" if state.get("status") == "blocked" else "coordinator"


def fan_out_to_specialists(state: ReviewState) -> list[str]:
    """PARALLEL FAN-OUT. Returns every specialist node to run in this superstep.

    Returning a list is what makes the delegation decision real: a docs-only PR
    that the coordinator judged not to need coverage analysis genuinely does not
    execute that node.
    """
    delegated = state.get("delegated_agents") or list(
        ("SecurityAgent", "StyleAgent", "TestCoverageAgent")
    )
    mapping = {
        "SecurityAgent": "security_agent",
        "StyleAgent": "style_agent",
        "TestCoverageAgent": "coverage_agent",
    }
    nodes = [mapping[a] for a in delegated if a in mapping]
    # Security review is never optional on a PR that reached this point.
    if "security_agent" not in nodes:
        nodes.append("security_agent")
    return nodes


def fan_out_after_fix(state: ReviewState) -> list[str]:
    """LOOP BACK. After patching, re-scan with the agents whose findings can change.

    Only security and style re-run: a one-line substitution cannot change which
    branches the test suite exercises, so re-running coverage would spend a
    minute of free-tier latency to re-derive the identical answer.
    """
    delegated = state.get("delegated_agents") or []
    nodes = ["security_agent"]
    if "StyleAgent" in delegated or not delegated:
        nodes.append("style_agent")
    return nodes


def route_after_synthesis(state: ReviewState) -> str:
    """THE CONDITIONAL EDGE.

    Rules, in order:

    * any genuine ``CRITICAL`` finding -> ``hitl_approval``. Criticals are not
      safely auto-remediable; a human decides.
    * ``HIGH`` findings still present and ``iteration < MAX_ITER`` -> another
      remediation pass, provided at least one carries an applicable fix.
    * otherwise -> ``finalize``.

    Termination is guaranteed by three independent conditions: findings clear,
    the iteration ceiling, or no fix left to apply. The third matters — without
    it a finding the agent cannot repair would loop until the ceiling, burning
    the budget to re-derive the same result.
    """
    settings = get_settings()
    iteration = state.get("iteration", 0)
    findings = current_findings(state)
    blocking = blocking_findings(state)

    has_critical = any(
        f.severity == Severity.CRITICAL and not f.is_false_positive for f in findings
    )
    if has_critical:
        return "hitl_approval"

    has_high = any(
        SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[Severity.HIGH]
        and not f.is_false_positive
        for f in findings
    )
    fixable = [f for f in blocking if f.suggested_fix]

    if has_high and iteration < settings.max_iter and fixable:
        return "remediation_loop"
    return "finalize"


def loop_should_terminate(state: ReviewState) -> tuple[bool, str]:
    """Explain the termination decision. Used by tests and the evidence notebook."""
    settings = get_settings()
    iteration = state.get("iteration", 0)
    blocking = blocking_findings(state)
    fixable = [f for f in blocking if f.suggested_fix]

    if not blocking:
        return True, "findings_clear"
    if iteration >= settings.max_iter:
        return True, f"iteration >= MAX_ITER ({settings.max_iter})"
    if not fixable:
        return True, "no remaining finding carries an applicable fix"
    return False, f"{len(fixable)} fixable blocking finding(s) remain"
