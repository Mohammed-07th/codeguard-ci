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
    """One scripted model reply."""

    content: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    parsed: BaseModel | None = None
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

        queue = self.script.get(tag)
        # The last scripted response for a tag repeats rather than being consumed:
        # a remediation iteration re-enters the same agent, and a script that ran
        # dry mid-loop would silently change behaviour between iterations.
        if queue:
            response = queue.pop(0) if len(queue) > 1 else queue[0]
        else:
            response = self.default
        if response.raise_error is not None:
            raise response.raise_error

        parsed = response.parsed
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


def _synthesis(decision: str, rationale: str, ids: list[int]):
    """Build a SynthesisResult. Imported lazily to keep stub import cost low."""
    from codeguard.agents.synthesizer import SynthesisResult

    return SynthesisResult(decision=decision, rationale=rationale, blocking_finding_ids=ids)


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
        "SecurityAgent.final": [StubResponse(parsed=AgentReport(
            agent="SecurityAgent", findings=sec_findings,
            judgment="Two genuine leaks in src/config.py. The conftest hit is a CI "
                     "fixture and is downgraded."))],
        "StyleAgent.react": [
            StubResponse(content="Running the linter.",
                         tool_calls=[{"name": "run_ruff", "args": {"path": "."}}]),
            StubResponse(content="Ranked."),
        ],
        "StyleAgent.final": [StubResponse(parsed=AgentReport(
            agent="StyleAgent",
            findings=[Finding(agent="StyleAgent", category="style", severity=Severity.MEDIUM,
                              file="src/settlement.py", line=22,
                              message="Bare except swallows the fee-validation error",
                              evidence="except:",
                              suggested_fix="    except (ValueError, TypeError):")],
            judgment="The bare except sits in the fee path and hides a raise; the long "
                     "line is formatting and does not block."))],
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
        "ReviewSynthesizerAgent.synthesize": [StubResponse(parsed=_synthesis(
            "REQUEST_CHANGES",
            "SecurityAgent found two live credentials in src/config.py and StyleAgent "
            "found a bare except in the fee path; TestCoverageAgent notes the "
            "authorisation branch is untested. SecurityAgent's findings dominate — a "
            "clean-looking diff carrying a live key is not approvable. The conftest "
            "hit SecurityAgent triaged as a fixture is not counted against the merge.",
            [0, 1]))],
    }, default=StubResponse(content="(stub: concluding)"))
