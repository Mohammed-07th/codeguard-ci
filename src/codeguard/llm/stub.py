"""A deterministic stand-in for :class:`~codeguard.llm.router.LLMRouter`.

Two reasons this exists, both practical:

* **Quota.** The project runs on free-tier models with real rate limits. Debugging
  a graph by re-running it fifty times against a live provider is not viable.
* **Test determinism.** Graph and routing tests must assert on exact behaviour.
  A test that depends on what a 20B model felt like saying is not a test.

The stub honours the same ``invoke()`` contract as the real router, including
tool calls and structured output, so agents cannot tell the difference. It is a
development and testing aid — every number in ``evidence/`` comes from the real
router, and the stub is never used to produce graded output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from langchain_core.messages import AIMessage
from pydantic import BaseModel

from codeguard.config import TaskComplexity
from codeguard.llm.router import LLMResult


@dataclass
class StubResponse:
    """One scripted model reply.

    ``parsed_factory`` makes a reply *reactive*: it receives the message history
    and derives the structured output from what the tools actually returned.
    That matters for the remediation loop — a stub that replays a fixed finding
    list reports the same count no matter how much code was repaired, which is
    indistinguishable from a loop that does nothing.
    """

    content: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    parsed: BaseModel | None = None
    parsed_factory: Any = None
    raise_error: Exception | None = None

    def to_message(self) -> AIMessage:
        calls = [
            {
                "name": c["name"],
                "args": c.get("args", {}),
                "id": c.get("id", f"stub_call_{i}"),
                "type": "tool_call",
            }
            for i, c in enumerate(self.tool_calls)
        ]
        return AIMessage(
            content=self.content,
            tool_calls=calls,
            response_metadata={"model_name": "stub/deterministic"},
            usage_metadata={"input_tokens": 100, "output_tokens": 20, "total_tokens": 120},
        )


class StubRouter:
    """Replays scripted responses keyed by the caller's ``tag``."""

    def __init__(
        self,
        script: dict[str, list[StubResponse]] | None = None,
        default: StubResponse | None = None,
    ) -> None:
        self.script = {k: list(v) for k, v in (script or {}).items()}
        self.default = default or StubResponse(content="(stub: nothing further to do)")
        self.calls: list[dict[str, Any]] = []
        self._cursor: dict[str, int] = {}
        self._total_cost = 0.0

    # --- LLMRouter-compatible surface --------------------------------------

    def pick_model(self, complexity: TaskComplexity | str) -> str:
        c = TaskComplexity(complexity) if isinstance(complexity, str) else complexity
        return "stub/large" if c is TaskComplexity.COMPLEX else "stub/small"

    def fallback_for(self, model: str) -> str:
        return "stub/fallback"

    def invoke(
        self,
        messages: Sequence[Any] | str,
        *,
        tag: str,
        complexity: TaskComplexity | str = TaskComplexity.STANDARD,
        tools: Sequence[Any] | None = None,
        structured_output: Any | None = None,
        **kwargs: Any,
    ) -> LLMResult:
        self.calls.append({"tag": tag, "complexity": str(complexity), "tools": bool(tools)})

        # Scripts CYCLE rather than being consumed. A remediation iteration
        # re-enters the same agent, and it must replay the whole sequence —
        # scan, cross-check, conclude — so it actually re-runs its tools against
        # the patched files. Sticking on the final "conclude" response instead
        # made the second iteration report zero findings because it never
        # scanned: the count fell for the wrong reason, which is exactly the
        # kind of hollow loop this evidence is supposed to rule out.
        queue = self.script.get(tag)
        if queue:
            i = self._cursor.get(tag, 0)
            response = queue[i % len(queue)]
            self._cursor[tag] = i + 1
        else:
            response = self.default
        if response.raise_error is not None:
            raise response.raise_error

        parsed = response.parsed
        if parsed is None and response.parsed_factory is not None:
            parsed = response.parsed_factory(messages)
        if structured_output is not None and parsed is None:
            # Nothing scripted: hand back an empty-but-valid instance where the
            # schema allows it, so a test that does not care about the report
            # body does not have to script one.
            try:
                parsed = structured_output()
            except Exception:  # noqa: BLE001 - required fields; leave it None
                parsed = None

        return LLMResult(
            message=response.to_message(),
            parsed=parsed,
            requested_model=self.pick_model(complexity),
            actual_model="stub/deterministic",
            input_tokens=100,
            output_tokens=20,
            cost_usd=0.0,
            shadow_cost_usd=0.00007,
            price_known=True,
            latency_ms=1.0,
            attempts=1,
            fallback_used=False,
        )

    @property
    def total_cost_usd(self) -> float:
        return self._total_cost

    def reset_cost(self) -> None:
        self._total_cost = 0.0


def _tool_payloads(messages: Any, marker: str) -> list[dict[str, Any]]:
    """Pull parsed JSON tool results out of the message history."""
    import json as _json

    out = []
    for m in messages or []:
        content = getattr(m, "content", None)
        if isinstance(content, str) and marker in content:
            try:
                out.append(_json.loads(content))
            except _json.JSONDecodeError:
                continue
    return out


def _identifier(excerpt: str) -> str | None:
    """Recover the assigned name from a masked source line, e.g. `DB_PASSWORD = "..."`."""
    import re as _re

    m = _re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*[:=]", excerpt or "")
    return m.group(1) if m else None


def security_report_from_tools(messages: Any):
    """Derive SecurityAgent's report from what the scanner ACTUALLY reported.

    A deterministic rule standing in for the model's triage: every hit outside a
    test path is a real leak with an env-var fix; a hit inside one is downgraded
    with a reason. Because it reads live scanner output, the finding count falls
    as the remediation loop repairs files — which is the behaviour under test.
    """
    from codeguard.state import AgentReport, Finding, Severity

    payloads = _tool_payloads(messages, '"tool": "secret_scanner"')
    hits = payloads[-1].get("hits", []) if payloads else []

    findings, downgraded = [], 0
    for h in hits:
        in_test = bool(h.get("in_test_path"))
        name = _identifier(h.get("line_excerpt", ""))
        is_pii = h.get("rule_id") in {"EMAIL", "IBAN", "SA_NATIONAL_ID"}
        if in_test:
            downgraded += 1
            findings.append(Finding(
                agent="SecurityAgent", category="secret", severity=Severity.LOW,
                file=h["file"], line=h["line"],
                message=f"{h['rule_name']} inside a test fixture",
                evidence=h["masked_match"], is_false_positive=True,
                triage_note=f"{h['file']} is a test path; this configures an ephemeral "
                            "CI resource and is not a production credential."))
            continue
        findings.append(Finding(
            agent="SecurityAgent", category="secret",
            severity=Severity.MEDIUM if is_pii else Severity.HIGH,
            file=h["file"], line=h["line"],
            message=f"{h['rule_name']} hardcoded in application code",
            evidence=h["masked_match"],
            suggested_fix=(f'{name} = os.environ["{name}"]' if name else None)))

    real = len(findings) - downgraded
    return AgentReport(
        agent="SecurityAgent", findings=findings,
        judgment=(f"The scanner reported {len(hits)} hit(s). {real} sit in application "
                  f"code and are genuine leaks, each repairable by reading the value "
                  f"from the environment. {downgraded} sit in a test path and were "
                  f"downgraded rather than reported as production credentials."))


def style_report_from_tools(messages: Any):
    """Derive StyleAgent's report from ruff's ACTUAL output, ranking by consequence."""
    from codeguard.state import AgentReport, Finding, Severity

    payloads = _tool_payloads(messages, '"tool": "ruff"')
    violations = payloads[-1].get("findings", []) if payloads else []

    # The judgment ruff cannot make: same linter, wildly different real-world risk.
    RANK = {
        "E722": (Severity.HIGH, "a bare except in the fee path swallows the error it "
                                "was meant to raise", "    except (ValueError, TypeError):"),
        "F401": (Severity.LOW, "dead import; harmless but suggests an unfinished change", None),
        "E501": (Severity.INFO, "line length is formatting and has never caused an "
                                "incident", None),
    }
    findings = []
    for v in violations:
        sev, why, fix = RANK.get(v.get("rule_id"), (Severity.LOW, v.get("message", ""), None))
        findings.append(Finding(
            agent="StyleAgent", category="style", severity=sev,
            file=v["file"], line=v["line"],
            message=f"{v.get('rule_id')}: {why}",
            evidence=v.get("message", "")[:120], suggested_fix=fix))

    codes = [v.get("rule_id") for v in violations]
    return AgentReport(
        agent="StyleAgent", findings=findings,
        judgment=(f"ruff reported {len(violations)} violation(s) {codes} at a single flat "
                  "severity. Ranked by what the code does: the bare except is high because "
                  "it hides a raise on a money path, the unused import is low, and the long "
                  "line is informational. Only the first would block a merge."))


def _synthesis(decision: str, rationale: str, ids: list[int]):
    """Build a SynthesisResult. Imported lazily to keep stub import cost low."""
    from codeguard.agents.synthesizer import SynthesisResult

    return SynthesisResult(decision=decision, rationale=rationale, blocking_finding_ids=ids)


def synthesis_from_findings(messages: Any):
    """Adjudicate from the findings the specialists actually placed in state.

    Parses the numbered table the synthesizer is shown, so the verdict tracks the
    live findings instead of being fixed in advance — otherwise the remediation
    loop would keep reporting the same decision after every repair.
    """
    import re as _re

    text = ""
    for m in messages or []:
        c = getattr(m, "content", None)
        if isinstance(c, str) and "FINDINGS IN SHARED STATE" in c:
            text = c
    rows = _re.findall(
        r"id=(\d+) \| (\S+) \| (\S+) \| severity=(\w+) \| ([^\n]*)", text
    )
    blocking, worst, agents = [], "info", set()
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for idx, agent, _cat, sev, tail in rows:
        agents.add(agent)
        if "DOWNGRADED" in tail:
            continue
        if order.get(sev, 0) > order.get(worst, 0):
            worst = sev
        if order.get(sev, 0) >= order["high"]:
            blocking.append(int(idx))

    decision = ("BLOCK_MERGE" if worst == "critical"
                else "REQUEST_CHANGES" if order.get(worst, 0) >= order["medium"]
                else "APPROVE")
    named = ", ".join(sorted(agents)) or "no agent"
    rationale = (
        f"{named} contributed {len(rows)} finding(s); the most severe untriaged one is "
        f"{worst}. {len(blocking)} block the merge. Findings the raising agent triaged as "
        "false positives are excluded rather than re-promoted, and where specialists "
        "disagreed the security assessment governs: a diff that lints cleanly but carries "
        "a live credential is not approvable."
    )
    return _synthesis(decision, rationale, blocking)


def scripted_critical_router() -> StubRouter:
    """Stub for the pr_critical fixture: findings severe enough to demand a human.

    Drives the hitl_approval branch, where route_after_synthesis sends any
    genuine CRITICAL finding. The bandit run behind it is real — these are the
    issues it actually reports on that fixture.
    """
    from codeguard.state import AgentReport, Finding, ReviewPlan, Severity

    return StubRouter({
        "CoordinatorAgent.react": [
            StubResponse(content="Reading the diff before planning.",
                         tool_calls=[{"name": "get_diff", "args": {}}]),
            StubResponse(content="Planned."),
        ],
        "CoordinatorAgent.final": [StubResponse(parsed=ReviewPlan(
            steps=["audit src/payments.py for unsafe calls",
                   "check deploy/ for committed key material"],
            delegate_to=["SecurityAgent"],
            rationale="No test suite ships with this PR and the change is a security "
                      "surface, so the security specialist carries the review."))],
        "SecurityAgent.react": [
            StubResponse(content="Running bandit over the payment helpers.",
                         tool_calls=[{"name": "run_bandit", "args": {"path": "."}}]),
            StubResponse(content="Checking for committed key material.",
                         tool_calls=[{"name": "scan_secrets", "args": {"path": "."}}]),
            StubResponse(content="Assessed."),
        ],
        "SecurityAgent.final": [StubResponse(parsed=AgentReport(
            agent="SecurityAgent",
            findings=[
                Finding(agent="SecurityAgent", category="vulnerability",
                        severity=Severity.CRITICAL, file="src/payments.py", line=10,
                        message="Shell injection: subprocess(shell=True) on a "
                                "merchant-controlled string",
                        evidence="subprocess.check_output(command, shell=True)"),
                Finding(agent="SecurityAgent", category="vulnerability",
                        severity=Severity.CRITICAL, file="src/payments.py", line=15,
                        message="Arbitrary code execution: eval() of a merchant-supplied "
                                "expression",
                        evidence="eval(expression, ...)"),
                Finding(agent="SecurityAgent", category="secret",
                        severity=Severity.CRITICAL, file="deploy/id_rsa", line=1,
                        message="RSA private key committed to the repository",
                        evidence="-----BEGIN RSA PRIVATE KEY-----"),
            ],
            judgment="Three critical issues, none safely auto-remediable. Rewriting a "
                     "shell call or an eval changes behaviour, and a committed key must "
                     "be rotated, not deleted. This needs a human decision."))],
        "ReviewSynthesizerAgent.synthesize": [StubResponse(parsed=_synthesis(
            "BLOCK_MERGE",
            "SecurityAgent reports shell injection, arbitrary code execution and a "
            "committed private key, all on merchant-facing paths. No other specialist "
            "was delegated, so there is no competing assessment to weigh. None of the "
            "three is safely auto-remediable, so this escalates to a human.",
            [0, 1, 2]))],
    }, default=StubResponse(content="(stub: concluding)"))


def scripted_review_router() -> StubRouter:
    """A stub that drives a *realistic* full review: every agent calls its real tools.

    Used where the LLM is not what is under test but the rest of the system is —
    the persistence proof and the HITL tests. The tools genuinely execute (bandit,
    ruff and pytest all run as real subprocesses), so the graph does real work and
    takes real time. That is what makes a mid-run kill meaningful rather than a
    race against an instant no-op.
    """
    from codeguard.state import AgentReport, Finding, ReviewPlan, Severity

    sec_findings = [
        Finding(agent="SecurityAgent", category="secret", severity=Severity.HIGH,
                file="src/config.py", line=8,
                message="Hardcoded AWS access key id in application configuration",
                evidence="AKIA****************(len=20)",
                suggested_fix='AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]'),
        Finding(agent="SecurityAgent", category="secret", severity=Severity.HIGH,
                file="src/config.py", line=15,
                message="Hardcoded database password in application configuration",
                evidence="Hunt**************(len=18)",
                suggested_fix='DB_PASSWORD = os.environ["DB_PASSWORD"]'),
        Finding(agent="SecurityAgent", category="secret", severity=Severity.LOW,
                file="tests/conftest.py", line=7,
                message="Password literal in a test fixture",
                evidence="test***(len=7)", is_false_positive=True,
                triage_note="tests/conftest.py provisions an ephemeral CI database; "
                            "this is not a production credential."),
    ]

    return StubRouter({
        "CoordinatorAgent.react": [
            StubResponse(content="I need the file list before I can plan.",
                         tool_calls=[{"name": "list_changed_files", "args": {}}]),
            StubResponse(content="Now the diff itself.",
                         tool_calls=[{"name": "get_diff", "args": {}}]),
            StubResponse(content="Enough to plan."),
        ],
        "CoordinatorAgent.final": [StubResponse(parsed=ReviewPlan(
            steps=["scan src/config.py for credentials",
                   "lint src/settlement.py",
                   "check coverage of the authorisation path"],
            delegate_to=["SecurityAgent", "StyleAgent", "TestCoverageAgent"],
            rationale="Source and config changed, so security review is mandatory; "
                      "logic changed, so coverage matters."))],
        "SecurityAgent.react": [
            StubResponse(content="Scanning the whole PR for credentials first.",
                         tool_calls=[{"name": "scan_secrets", "args": {"path": "."}}]),
            StubResponse(content="Cross-checking with bandit.",
                         tool_calls=[{"name": "run_bandit", "args": {"path": "."}}]),
            StubResponse(content="I have enough to triage."),
        ],
        "SecurityAgent.final": [StubResponse(parsed_factory=security_report_from_tools)],
        "StyleAgent.react": [
            StubResponse(content="Running the linter.",
                         tool_calls=[{"name": "run_ruff", "args": {"path": "."}}]),
            StubResponse(content="Ranked."),
        ],
        "StyleAgent.final": [StubResponse(parsed_factory=style_report_from_tools)],
        "TestCoverageAgent.react": [
            StubResponse(content="Running the suite under coverage.",
                         tool_calls=[{"name": "run_pytest_coverage", "args": {}}]),
            StubResponse(content="Judged."),
        ],
        "TestCoverageAgent.final": [StubResponse(parsed=AgentReport(
            agent="TestCoverageAgent",
            findings=[Finding(agent="TestCoverageAgent", category="coverage",
                              severity=Severity.MEDIUM, file="src/settlement.py", line=11,
                              message="is_authorized is untested; assert it returns False "
                                      "when mfa_verified is absent")],
            judgment="The percentage is not the point: the untested lines are the "
                     "authorisation branch."))],
        "ReviewSynthesizerAgent.synthesize": [
            StubResponse(parsed_factory=synthesis_from_findings)],
    }, default=StubResponse(content="(stub: concluding)"))
