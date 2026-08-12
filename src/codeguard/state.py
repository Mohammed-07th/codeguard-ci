"""The shared graph state and the structured contracts agents exchange.

Deliverable 2 asks for "state as a real shared object read and updated by nodes".
:class:`ReviewState` is exactly that: a typed ``TypedDict`` threaded through every
node in the graph, where the ``Annotated[..., operator.add]`` reducers let several
nodes append to the same channel concurrently without clobbering one another.
That matters because ``security_agent``, ``style_agent`` and ``coverage_agent``
run as a **parallel fan-out** — all three write ``findings``, ``scratchpad`` and
``cost_usd`` in the same superstep, and the reducer is what merges them.

Deliverable 3 asks that agents communicate through structured messages rather
than free text. They do: agents append :class:`Finding` objects, never prose.
"""

from __future__ import annotations

import hashlib
import operator
from enum import Enum
from typing import Annotated, Literal, TypedDict

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity as judged by the *agent*, not as reported by the raw tool.

    StyleAgent in particular must derive its own severity: a bare ``except:``
    swallowing errors in a payment path is not the same finding as a long line,
    even though ruff reports both as ordinary lint hits.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Ordering used by the router and the synthesizer to compare severities.
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Finding(BaseModel):
    """One structured observation produced by one agent.

    This is the *only* currency agents use to talk to each other. No agent reads
    another agent's free text; the synthesizer reads these objects out of shared
    state and reasons over them.
    """

    agent: str = Field(description="Name of the agent that produced this finding.")
    category: Literal["secret", "vulnerability", "style", "coverage"] = Field(
        description="Finding class, used for grouping and dedup."
    )
    severity: Severity = Field(description="Severity as judged by the agent.")
    file: str = Field(description="Path of the offending file.")
    line: int | None = Field(default=None, description="1-indexed line, when known.")
    message: str = Field(description="What is wrong, in one sentence.")
    evidence: str = Field(
        default="",
        description="Supporting snippet. MUST already be redacted — never a raw secret.",
    )
    suggested_fix: str | None = Field(
        default=None,
        description="Replacement source line applied by the remediation loop's apply_fix node.",
    )
    # Stamped by the graph after the agent returns, never by the model. The
    # findings channel is append-only (the parallel fan-out requires that), so
    # without this tag a re-scan would add to the previous iteration's findings
    # and the count could only ever go up.
    iteration: int = Field(default=0, description="Set by the graph; leave as 0.")
    # Set by SecurityAgent's triage step when it judges a tool hit to be a false
    # positive (e.g. a password literal inside tests/conftest.py). Kept rather
    # than dropped so the downgrade is visible in the evidence.
    triage_note: str | None = Field(
        default=None, description="Agent's justification when it overrides the tool's verdict."
    )
    is_false_positive: bool = Field(default=False)

    def fingerprint(self) -> str:
        """Stable identity used by the synthesizer to deduplicate overlapping findings."""
        raw = f"{self.category}|{self.file}|{self.line}|{self.message.lower().strip()}"
        return hashlib.sha1(raw.encode()).hexdigest()[:12]

    def is_blocking(self) -> bool:
        return (
            not self.is_false_positive
            and SEVERITY_ORDER[self.severity] >= SEVERITY_ORDER[Severity.HIGH]
        )


class Verdict(BaseModel):
    """The synthesizer's final decision on the pull request."""

    decision: Literal["APPROVE", "REQUEST_CHANGES", "BLOCK_MERGE"]
    rationale: str = Field(
        description="Why. Must reference the contributing agents by name so the "
        "conflict-resolution step is auditable."
    )
    blocking_findings: list[Finding] = Field(default_factory=list)


class ReviewPlan(BaseModel):
    """CoordinatorAgent's output: an ordered plan plus a real delegation decision.

    ``delegate_to`` is the judgment: a docs-only PR does not need the coverage
    agent, and skipping it is a decision the coordinator must justify.
    """

    steps: list[str] = Field(description="Ordered review steps, most important first.")
    delegate_to: list[str] = Field(
        description="Which specialist agents to run: SecurityAgent, StyleAgent, TestCoverageAgent."
    )
    rationale: str = Field(description="Why these agents, and why any were left out.")


class AgentReport(BaseModel):
    """Envelope a specialist agent returns after its ReAct loop.

    Carries the agent's judgment layer separately from the findings so evidence
    can show the raw tool output and the agent's reasoning side by side.
    """

    agent: str
    findings: list[Finding] = Field(default_factory=list)
    judgment: str = Field(
        default="",
        description="The reasoning the tool could not provide: triage, exploitability, risk.",
    )


class ReviewState(TypedDict, total=False):
    """Shared state object, read and updated by every node in the graph.

    Channels annotated with ``operator.add`` are append-only and safe for the
    parallel agent fan-out; unannotated channels are last-write-wins and are only
    ever written by a single node per superstep.
    """

    # --- pull request under review (written by ingest_pr) ---
    pr_id: str
    pr_title: str
    pr_description: str
    changed_files: list[str]
    diff: str
    # Working copy under workdir/. Every analyser runs against this, never the
    # fixture, so apply_fix can patch files and the demo stays repeatable.
    workdir_path: str

    # --- coordinator output: the ordered plan and the delegation decision ---
    plan: list[str]
    delegated_agents: list[str]

    # --- ReAct short-term memory: Thought/Action/Observation lines across steps ---
    scratchpad: Annotated[list[str], operator.add]

    # --- structured findings appended by each specialist agent (fan-in) ---
    findings: Annotated[list[Finding], operator.add]

    # --- synthesis + routing ---
    verdict: Verdict | None
    iteration: int
    status: str

    # --- guardrails (Deliverable 4): every block/redaction is recorded here ---
    guardrail_events: Annotated[list[dict], operator.add]

    # --- human-in-the-loop (Deliverable 5) ---
    hitl_decision: str | None
    hitl_reason: str | None

    # --- cost metering; reducer required because agents run in parallel ---
    cost_usd: Annotated[float, operator.add]

    # --- remediation loop bookkeeping: findings count per iteration ---
    iteration_history: Annotated[list[dict], operator.add]
    patched_files: Annotated[list[str], operator.add]


def current_findings(state: ReviewState) -> list[Finding]:
    """Findings produced in the current remediation iteration.

    Routing and reporting must look only at the latest scan. The full history
    stays in state so the evidence can show 3 -> 1 -> 0 across iterations.
    """
    it = state.get("iteration", 0)
    return [f for f in state.get("findings", []) if f.iteration == it]


def blocking_findings(state: ReviewState) -> list[Finding]:
    """Current findings that are genuinely blocking (triaged ones excluded)."""
    return [f for f in current_findings(state) if f.is_blocking()]


def new_state(
    pr_id: str,
    pr_title: str,
    pr_description: str,
    changed_files: list[str],
    diff: str,
    workdir_path: str = "",
) -> ReviewState:
    """Build a fully-initialised state object so no node has to guard against missing keys."""
    return ReviewState(
        pr_id=pr_id,
        pr_title=pr_title,
        pr_description=pr_description,
        changed_files=changed_files,
        diff=diff,
        workdir_path=workdir_path,
        plan=[],
        delegated_agents=[],
        scratchpad=[],
        findings=[],
        verdict=None,
        iteration=0,
        status="ingested",
        guardrail_events=[],
        hitl_decision=None,
        hitl_reason=None,
        cost_usd=0.0,
        iteration_history=[],
        patched_files=[],
    )
