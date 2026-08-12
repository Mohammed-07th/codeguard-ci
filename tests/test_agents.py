"""Agent-layer tests. All deterministic — the stub router replaces the network."""

from __future__ import annotations

import json

import pytest

from codeguard.agents.base import ReActAgent
from codeguard.agents.security_agent import SecurityAgent
from codeguard.agents.synthesizer import ReviewSynthesizerAgent, SynthesisResult, dedupe
from codeguard.config import get_settings
from codeguard.guardrails.redaction import assert_clean, redact
from codeguard.guardrails.validation import SchemaValidationFailed, validate_or_repair
from codeguard.llm.stub import StubResponse, StubRouter
from codeguard.state import AgentReport, Finding, Severity
from codeguard.tools import repo_tools
from codeguard.tools.sandbox import review_root

FIXTURES = get_settings().fixtures_dir
RAW_SECRETS = ["AKIA3XQ7MZPLK2VNWR4T", "Hunter2!Settlement",
               "ahmed.alqahtani@example-bank.com.sa"]


@pytest.fixture()
def secret_pr():
    pr = repo_tools.load_pull_request(FIXTURES / "pr_with_secret")
    with review_root(pr.root), repo_tools.pr_context(pr):
        yield pr


def _report(**kw) -> AgentReport:
    return AgentReport(agent="SecurityAgent", judgment="j", findings=[], **kw)


# --- the ReAct loop -----------------------------------------------------------

def test_react_loop_records_thought_action_observation(secret_pr):
    router = StubRouter({
        "SecurityAgent.react": [
            StubResponse(content="I should scan for credentials.",
                         tool_calls=[{"name": "scan_secrets", "args": {"path": "."}}]),
            StubResponse(content="Enough evidence."),
        ],
        "SecurityAgent.final": [StubResponse(parsed=_report())],
    })
    run = SecurityAgent(router=router, verbose=False).run("review")

    joined = "\n".join(run.scratchpad)
    assert "Thought:" in joined
    assert "Action: scan_secrets" in joined
    assert "Observation:" in joined
    assert run.tool_calls == 1
    assert run.error is None


def test_scratchpad_is_short_term_memory_across_steps(secret_pr):
    """Prior scratchpad lines must be visible to the agent on a later invocation."""
    router = StubRouter({"SecurityAgent.react": [StubResponse(content="done")],
                         "SecurityAgent.final": [StubResponse(parsed=_report())]})
    agent = SecurityAgent(router=router, verbose=False)
    agent.run("review", prior_scratchpad=["[SecurityAgent] earlier: found AKIA key"])
    sent = json.dumps(router.calls)  # tags only; inspect the built task instead
    assert sent  # sanity
    task = agent._build_task("review", ["[SecurityAgent] earlier: found AKIA key"])
    assert "Shared scratchpad" in task and "earlier: found AKIA key" in task


def test_react_loop_is_bounded(secret_pr):
    """An agent that never stops calling tools must still terminate."""
    always_tool = StubResponse(
        content="looping", tool_calls=[{"name": "scan_secrets", "args": {"path": "."}}]
    )
    router = StubRouter(
        {"SecurityAgent.final": [StubResponse(parsed=_report())]}, default=always_tool
    )
    run = SecurityAgent(router=router, max_steps=3, verbose=False).run("review")
    assert len(run.steps) == 3
    assert run.tool_calls == 3


def test_denied_tool_is_returned_as_observation_not_raised(secret_pr):
    """A refusal should teach the agent, not crash the review."""
    router = StubRouter({
        "StyleAgent.react": [
            StubResponse(content="I will try the secret scanner.",
                         tool_calls=[{"name": "scan_secrets", "args": {"path": "."}}]),
            StubResponse(content="Understood, that is not mine to call."),
        ],
        "StyleAgent.final": [StubResponse(parsed=AgentReport(agent="StyleAgent"))],
    })

    class _Style(ReActAgent):
        name = "StyleAgent"
        system_prompt = "s"
        output_schema = AgentReport

    run = _Style(router=router, verbose=False).run("review")
    assert run.error is None
    assert run.steps[0].denied is True
    assert "ToolAccessDenied" in run.steps[0].observation


# --- output guardrail: schema validation with repair ---------------------------

def test_validation_repairs_an_invalid_first_attempt():
    calls = {"n": 0}

    def repair(_instruction: str):
        calls["n"] += 1
        return AgentReport(agent="SecurityAgent", judgment="repaired")

    out = validate_or_repair(AgentReport, {"bogus": True}, repair, agent="SecurityAgent")
    assert out.judgment == "repaired"
    assert calls["n"] == 1


def test_validation_accepts_a_dict_matching_the_schema():
    out = validate_or_repair(
        AgentReport, {"agent": "X", "findings": [], "judgment": "ok"},
        lambda _: None, agent="X",
    )
    assert out.agent == "X"


def test_validation_gives_up_after_one_repair():
    with pytest.raises(SchemaValidationFailed):
        validate_or_repair(AgentReport, None, lambda _: None, agent="SecurityAgent")


# --- data guardrail: redaction -------------------------------------------------

def test_redaction_masks_secrets_in_plain_text():
    text = 'AWS_ACCESS_KEY_ID = "AKIA3XQ7MZPLK2VNWR4T"'
    assert assert_clean(redact(text).text, RAW_SECRETS) == []


def test_redaction_handles_json_escaped_quotes():
    """Tool output is serialised, so `= \\"secret\\"` must still be caught."""
    text = json.dumps({"code": '15 DB_PASSWORD = "Hunter2!Settlement"'})
    assert "Hunter2!Settlement" in text
    assert assert_clean(redact(text).text, RAW_SECRETS) == []


def test_redaction_catches_secret_quoted_in_a_tool_message():
    """bandit repeats the password inside its own issue_text."""
    text = "Possible hardcoded password: 'Hunter2!Settlement'"
    assert assert_clean(redact(text).text, RAW_SECRETS) == []


def test_redaction_masks_every_occurrence_not_just_the_first():
    text = 'A = "AKIA3XQ7MZPLK2VNWR4T"\nB = "AKIA3XQ7MZPLK2VNWR4T"'
    r = redact(text)
    assert r.masked_count == 2
    assert assert_clean(r.text, RAW_SECRETS) == []


def test_redaction_leaves_ordinary_code_untouched():
    text = "def add(a, b):\n    return a + b\n"
    assert redact(text).text == text


def test_dispatch_redacts_tool_output_before_it_can_reach_a_model(secret_pr):
    """The choke-point guarantee: read_file returns source, but not raw secrets."""
    from codeguard.tools.registry import dispatch

    out = dispatch("SecurityAgent", "read_file", {"path": "src/config.py"})
    assert "AWS_ACCESS_KEY_ID" in out          # structure survives
    assert assert_clean(out, RAW_SECRETS) == []  # values do not


# --- synthesizer ---------------------------------------------------------------

def _finding(sev: Severity, *, fp: bool = False, line: int = 1) -> Finding:
    return Finding(agent="SecurityAgent", category="secret", severity=sev,
                   file="src/config.py", line=line, message="hardcoded credential",
                   is_false_positive=fp)


def test_dedupe_removes_exact_duplicates():
    kept, removed = dedupe([_finding(Severity.HIGH), _finding(Severity.HIGH)])
    assert len(kept) == 1 and removed == 1


def test_dedupe_keeps_distinct_findings():
    kept, removed = dedupe([_finding(Severity.HIGH, line=1), _finding(Severity.HIGH, line=2)])
    assert len(kept) == 2 and removed == 0


def test_safety_floor_blocks_when_model_would_approve_a_critical():
    router = StubRouter({"ReviewSynthesizerAgent.synthesize": [StubResponse(
        parsed=SynthesisResult(decision="APPROVE", rationale="looks fine"))]})
    verdict, scratch, _ = ReviewSynthesizerAgent(router=router, verbose=False).synthesize(
        [_finding(Severity.CRITICAL)], pr_title="t", agents_run=["SecurityAgent"]
    )
    assert verdict.decision == "BLOCK_MERGE"
    assert any("SAFETY FLOOR" in s for s in scratch)


def test_safety_floor_downgrades_approve_when_high_findings_remain():
    router = StubRouter({"ReviewSynthesizerAgent.synthesize": [StubResponse(
        parsed=SynthesisResult(decision="APPROVE", rationale="fine"))]})
    verdict, _, _ = ReviewSynthesizerAgent(router=router, verbose=False).synthesize(
        [_finding(Severity.HIGH)], pr_title="t"
    )
    assert verdict.decision == "REQUEST_CHANGES"


def test_triaged_false_positive_does_not_trigger_the_safety_floor():
    """A finding the agent deliberately downgraded must not force a block."""
    router = StubRouter({"ReviewSynthesizerAgent.synthesize": [StubResponse(
        parsed=SynthesisResult(decision="APPROVE", rationale="only a test fixture"))]})
    verdict, _, _ = ReviewSynthesizerAgent(router=router, verbose=False).synthesize(
        [_finding(Severity.CRITICAL, fp=True)], pr_title="t"
    )
    assert verdict.decision == "APPROVE"


def test_blocking_findings_exclude_triaged_false_positives():
    router = StubRouter({"ReviewSynthesizerAgent.synthesize": [StubResponse(
        parsed=SynthesisResult(decision="BLOCK_MERGE", rationale="r",
                               blocking_finding_ids=[0, 1]))]})
    verdict, _, _ = ReviewSynthesizerAgent(router=router, verbose=False).synthesize(
        [_finding(Severity.CRITICAL), _finding(Severity.CRITICAL, fp=True, line=2)],
        pr_title="t",
    )
    assert len(verdict.blocking_findings) == 1
    assert verdict.blocking_findings[0].is_false_positive is False


# --- resilience: total provider failure must degrade, not crash ---------------

def test_llm_failure_mid_react_loop_degrades_one_agent(secret_pr):
    """A provider 429 during the loop must not take down the whole review.

    Regression test: an upstream rate limit mid-loop propagated out of run()
    and killed the graph after a full iteration of real work had completed.
    """
    import openai, httpx

    def _429(_):
        resp = httpx.Response(429, request=httpx.Request("POST", "https://x"))
        raise openai.RateLimitError("rate limited", response=resp, body=None)

    router = StubRouter({
        "SecurityAgent.react": [
            StubResponse(content="scanning",
                         tool_calls=[{"name": "scan_secrets", "args": {"path": "."}}]),
            StubResponse(raise_error=openai.RateLimitError(
                "rate limited",
                response=httpx.Response(429, request=httpx.Request("POST", "https://x")),
                body=None)),
        ],
    })
    run = SecurityAgent(router=router, verbose=False).run("review")

    assert run.error is not None and "RateLimitError" in run.error
    assert run.report is None
    assert run.tool_calls == 1                      # the work it did do is preserved
    assert any("LLM unavailable" in s for s in run.scratchpad)


def test_degraded_agent_does_not_stop_the_graph_node(secret_pr):
    """The node records the degradation and returns; it does not raise."""
    import openai, httpx
    from codeguard.graph.nodes import GraphNodes

    router = StubRouter({
        "SecurityAgent.react": [StubResponse(raise_error=openai.RateLimitError(
            "rate limited",
            response=httpx.Response(429, request=httpx.Request("POST", "https://x")),
            body=None))],
    })
    state = {"pr_id": "PR-T", "pr_title": "t", "pr_description": "d",
             "changed_files": ["src/config.py"], "workdir_path": str(secret_pr.root),
             "iteration": 0, "delegated_agents": ["SecurityAgent"], "scratchpad": []}

    out = GraphNodes(router=router, verbose=False).security_agent_node(state)

    assert "findings" not in out          # nothing invented
    assert any("DEGRADED" in s for s in out["scratchpad"])
