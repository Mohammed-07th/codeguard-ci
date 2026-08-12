"""ReviewSynthesizerAgent — resolves conflicts between agents and issues the verdict.

This agent holds **no tools at all**. It reads the ``Finding`` objects the
specialists wrote into shared state and reasons over them. That is the point:
Deliverable 3 asks that agents communicate through structured messages, and the
synthesizer is where that pays off — it never sees another agent's prose.

Judgment the tool cannot provide (§6.1): conflict resolution. StyleAgent may be
content while SecurityAgent wants the merge blocked. Something has to adjudicate,
weigh severity against confidence, merge findings that describe the same defect
from two different tools, and justify the outcome by name.

Division of labour: **exact** duplicates are removed mechanically by fingerprint
(deterministic, free, no reason to spend a model call on it). **Semantic**
overlap — bandit's B105 and the secret scanner's HARDCODED_PASSWORD describing
one line — is a judgment call and is left to the model.
"""

from __future__ import annotations

from typing import Literal, Sequence

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field

from codeguard.config import TaskComplexity, get_settings
from codeguard.guardrails.validation import validate_or_repair
from codeguard.llm.router import LLMRouter, get_router
from codeguard.state import SEVERITY_ORDER, Finding, Severity, Verdict

SYSTEM_PROMPT = """\
You are ReviewSynthesizerAgent, the adjudicator in a multi-agent code review.

You have NO tools. You cannot re-scan anything. You decide using only the findings
the specialist agents placed in shared state, which are listed for you below.

YOUR JUDGMENT:

1. RESOLVE CONFLICTS BETWEEN AGENTS.
   The specialists disagree by design — each sees only its own slice. When
   StyleAgent is satisfied and SecurityAgent is not, security wins: a clean-looking
   diff with a live credential in it is not approvable. State the disagreement
   explicitly in your rationale and say how you settled it.

2. MERGE FINDINGS THAT DESCRIBE THE SAME DEFECT.
   Two tools reporting one line — a scanner calling it a hardcoded password and
   bandit calling it B105 — is one defect, not two. Exact duplicates are already
   removed; you handle the ones that only a reader would notice are the same.
   Cite the merged finding once and mention the corroboration.

3. RESPECT TRIAGE.
   A finding marked is_false_positive was deliberately downgraded by the agent that
   raised it, and it must NOT block the merge. Do not silently re-promote it.

4. DECIDE.
     BLOCK_MERGE      - at least one genuine critical finding. Needs a human.
     REQUEST_CHANGES  - genuine high findings, or several mediums. Fixable.
     APPROVE          - nothing real is outstanding. Style noise alone never
                        justifies withholding approval.

Reference the contributing agents BY NAME in your rationale, so the decision is
auditable. Two to five sentences. List the id of every finding you consider
blocking in blocking_finding_ids; leave it empty when you approve.
"""


class SynthesisResult(BaseModel):
    """What the model returns.

    It reports blocking findings **by id** rather than restating them: asking a
    free-tier model to faithfully reproduce whole nested objects invites
    transcription errors, and the ids map back to the originals exactly.
    """

    decision: Literal["APPROVE", "REQUEST_CHANGES", "BLOCK_MERGE"]
    rationale: str = Field(description="Why, naming the agents that contributed.")
    blocking_finding_ids: list[int] = Field(
        default_factory=list, description="Ids of the findings that block the merge."
    )
    merge_notes: str = Field(
        default="", description="Findings judged to describe the same defect."
    )


def dedupe(findings: Sequence[Finding]) -> tuple[list[Finding], int]:
    """Drop exact duplicates by fingerprint. Returns ``(kept, removed_count)``."""
    seen: set[str] = set()
    kept: list[Finding] = []
    for f in findings:
        fp = f.fingerprint()
        if fp in seen:
            continue
        seen.add(fp)
        kept.append(f)
    return kept, len(findings) - len(kept)


def render_findings(findings: Sequence[Finding]) -> str:
    """Render findings as a compact numbered table for the model."""
    if not findings:
        return "(no findings were reported by any agent)"
    lines = []
    for i, f in enumerate(findings):
        flag = "  [DOWNGRADED: triaged as false positive]" if f.is_false_positive else ""
        lines.append(
            f"id={i} | {f.agent} | {f.category} | severity={f.severity.value} | "
            f"{f.file}:{f.line or '-'}{flag}\n"
            f"    message: {f.message}\n"
            f"    evidence: {f.evidence[:160]}"
            + (f"\n    triage_note: {f.triage_note}" if f.triage_note else "")
        )
    return "\n".join(lines)


class ReviewSynthesizerAgent:
    """Aggregates specialist findings into a single :class:`Verdict`."""

    name = "ReviewSynthesizerAgent"
    complexity = TaskComplexity.COMPLEX  # the one genuinely hard call in the graph

    def __init__(self, router: LLMRouter | None = None, verbose: bool = True) -> None:
        self.router = router or get_router()
        self.settings = get_settings()
        self.verbose = verbose

    def synthesize(
        self, findings: Sequence[Finding], pr_title: str = "", agents_run: Sequence[str] = ()
    ) -> tuple[Verdict, list[str], float]:
        """Return ``(verdict, scratchpad_lines, cost_usd)``."""
        scratchpad: list[str] = []
        unique, removed = dedupe(findings)
        scratchpad.append(
            f"[{self.name}] deduplicated {len(findings)} findings -> {len(unique)} "
            f"({removed} exact duplicates removed mechanically)"
        )

        task = (
            f"Pull request: {pr_title}\n"
            f"Specialist agents that reported: {', '.join(agents_run) or 'none'}\n\n"
            f"FINDINGS IN SHARED STATE:\n{render_findings(unique)}\n\n"
            "Adjudicate and return your decision."
        )
        messages = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=task)]

        # Not wrapped here: synthesizer_node owns the degraded path and derives a
        # verdict mechanically from finding severities when this raises. Swallowing
        # the error here would hide that the verdict was not actually reasoned.
        result = self.router.invoke(
            messages,
            tag=f"{self.name}.synthesize",
            complexity=self.complexity,
            structured_output=SynthesisResult,
        )
        cost = result.cost_usd

        def repair(instruction: str):
            retry = self.router.invoke(
                [*messages, HumanMessage(content=instruction)],
                tag=f"{self.name}.synthesize.repair",
                complexity=self.complexity,
                structured_output=SynthesisResult,
            )
            nonlocal cost
            cost += retry.cost_usd
            return retry.parsed

        parsed = validate_or_repair(SynthesisResult, result.parsed, repair, agent=self.name)

        blocking = [
            unique[i] for i in parsed.blocking_finding_ids
            if 0 <= i < len(unique) and not unique[i].is_false_positive
        ]
        decision = self._reconcile(parsed.decision, unique, scratchpad)

        verdict = Verdict(
            decision=decision, rationale=parsed.rationale, blocking_findings=blocking
        )
        scratchpad.append(f"[{self.name}] verdict: {decision} — {parsed.rationale[:300]}")
        if parsed.merge_notes:
            scratchpad.append(f"[{self.name}] merges: {parsed.merge_notes[:300]}")
        if self.verbose:
            for line in scratchpad:
                print(line, flush=True)
        return verdict, scratchpad, cost

    def _reconcile(
        self, decision: str, findings: Sequence[Finding], scratchpad: list[str]
    ) -> str:
        """Refuse to approve over the top of a genuine critical finding.

        A safety floor, not a replacement for the model's reasoning. The model
        chooses freely between REQUEST_CHANGES and APPROVE; it may not approve a
        PR carrying an untriaged critical finding, because on a free-tier model
        an occasional malformed judgment must not be able to wave through an RCE.
        Every override is recorded rather than applied silently.
        """
        worst = max(
            (SEVERITY_ORDER[f.severity] for f in findings if not f.is_false_positive),
            default=-1,
        )
        if worst >= SEVERITY_ORDER[Severity.CRITICAL] and decision != "BLOCK_MERGE":
            scratchpad.append(
                f"[{self.name}] SAFETY FLOOR: model said {decision} but an untriaged "
                "critical finding is present — forcing BLOCK_MERGE."
            )
            return "BLOCK_MERGE"
        if worst >= SEVERITY_ORDER[Severity.HIGH] and decision == "APPROVE":
            scratchpad.append(
                f"[{self.name}] SAFETY FLOOR: model said APPROVE but untriaged high "
                "findings remain — downgrading to REQUEST_CHANGES."
            )
            return "REQUEST_CHANGES"
        return decision
