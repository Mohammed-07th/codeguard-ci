"""Graph tests: topology, conditional routing, loop termination, and real remediation.

All deterministic. The stub router replaces the network; the *tools* stay real,
so the remediation test proves the loop genuinely changes code on disk and that
the scanner genuinely finds less afterwards.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codeguard.config import get_settings
from codeguard.graph.build import build_graph, make_checkpointer, prepare_initial_state
from codeguard.graph.edges import (
    fan_out_after_fix,
    fan_out_to_specialists,
    loop_should_terminate,
    route_after_guardrail,
    route_after_synthesis,
)
from codeguard.graph.nodes import GraphNodes
from codeguard.llm.stub import StubResponse, StubRouter
from codeguard.state import Finding, ReviewPlan, Severity, new_state
from codeguard.tools.registry import scan_secrets_impl
from codeguard.tools.repo_tools import load_pull_request, pr_context
from codeguard.tools.sandbox import review_root

SETTINGS = get_settings()
FIXTURES = SETTINGS.fixtures_dir


def _finding(sev: Severity, *, fix: str | None = "X = os.environ['X']",
             fp: bool = False, line: int = 8, it: int = 0,
             file: str = "src/config.py") -> Finding:
    return Finding(agent="SecurityAgent", category="secret", severity=sev, file=file,
                   line=line, message="hardcoded credential", suggested_fix=fix,
                   is_false_positive=fp, iteration=it)


def _state(**kw):
    s = new_state("PR-T", "t", "d", ["src/config.py"], "diff", workdir_path="/tmp")
    s.update(kw)
    return s


# --- topology -----------------------------------------------------------------

@pytest.fixture(scope="module")
def compiled():
    return build_graph(router=StubRouter(), checkpointer=make_checkpointer(), verbose=False)


def test_graph_contains_every_required_node(compiled):
    names = set(compiled.get_graph().nodes)
    for required in (
        "ingest_pr", "guardrail_input", "blocked", "coordinator",
        "security_agent", "style_agent", "coverage_agent", "synthesizer",
        "remediation_loop", "apply_fix", "hitl_approval", "apply_decision",
        "finalize", "persist_report",
    ):
        assert required in names, f"missing node: {required}"


def test_graph_has_a_checkpointer(compiled):
    assert compiled.checkpointer is not None


# --- conditional routing ------------------------------------------------------

def test_guardrail_routes_blocked_pr_away_from_the_coordinator():
    assert route_after_guardrail(_state(status="blocked")) == "blocked"
    assert route_after_guardrail(_state(status="guardrail_passed")) == "coordinator"


def test_critical_finding_routes_to_human_approval():
    s = _state(findings=[_finding(Severity.CRITICAL)], iteration=0)
    assert route_after_synthesis(s) == "hitl_approval"


def test_high_finding_routes_to_the_remediation_loop():
    s = _state(findings=[_finding(Severity.HIGH)], iteration=0)
    assert route_after_synthesis(s) == "remediation_loop"


def test_clean_review_routes_straight_to_finalize():
    assert route_after_synthesis(_state(findings=[], iteration=0)) == "finalize"


def test_low_severity_findings_do_not_trigger_remediation():
    s = _state(findings=[_finding(Severity.LOW)], iteration=0)
    assert route_after_synthesis(s) == "finalize"


def test_triaged_false_positive_does_not_route_to_hitl():
    """A critical the agent downgraded must not pause the graph for a human."""
    s = _state(findings=[_finding(Severity.CRITICAL, fp=True)], iteration=0)
    assert route_after_synthesis(s) == "finalize"


# --- loop termination (the property that must be provable) --------------------

def test_loop_terminates_at_max_iter():
    s = _state(findings=[_finding(Severity.HIGH, it=SETTINGS.max_iter)],
               iteration=SETTINGS.max_iter)
    assert route_after_synthesis(s) == "finalize"
    done, why = loop_should_terminate(s)
    assert done and "MAX_ITER" in why


def test_loop_terminates_when_findings_clear():
    done, why = loop_should_terminate(_state(findings=[], iteration=1))
    assert done and why == "findings_clear"


def test_loop_terminates_when_nothing_is_fixable():
    """Without this, an unfixable finding would loop to the ceiling for nothing."""
    s = _state(findings=[_finding(Severity.HIGH, fix=None)], iteration=0)
    assert route_after_synthesis(s) == "finalize"
    done, why = loop_should_terminate(s)
    assert done and "applicable fix" in why


@pytest.mark.parametrize("iteration", range(0, 6))
def test_routing_always_terminates_within_max_iter(iteration):
    """Whatever the iteration, routing must never loop past the ceiling."""
    s = _state(findings=[_finding(Severity.HIGH, it=iteration)], iteration=iteration)
    route = route_after_synthesis(s)
    if iteration >= SETTINGS.max_iter:
        assert route == "finalize"
    else:
        assert route == "remediation_loop"


def test_only_current_iteration_findings_are_routed_on():
    """findings is append-only, so stale findings must not keep the loop alive."""
    s = _state(findings=[_finding(Severity.HIGH, it=0)], iteration=1)
    assert route_after_synthesis(s) == "finalize"


# --- delegation actually changes which nodes run -------------------------------

def test_fan_out_follows_the_coordinators_delegation():
    s = _state(delegated_agents=["SecurityAgent", "StyleAgent"])
    assert set(fan_out_to_specialists(s)) == {"security_agent", "style_agent"}


def test_fan_out_always_includes_security_even_if_skipped():
    s = _state(delegated_agents=["StyleAgent"])
    assert "security_agent" in fan_out_to_specialists(s)


def test_loop_back_skips_coverage():
    s = _state(delegated_agents=["SecurityAgent", "StyleAgent", "TestCoverageAgent"])
    assert "coverage_agent" not in fan_out_after_fix(s)


# --- apply_fix does real work --------------------------------------------------

@pytest.fixture()
def working_copy(tmp_path):
    state = prepare_initial_state(FIXTURES / "pr_with_secret", workdir_name="test-remediation")
    return state


def test_apply_fix_patches_the_working_copy_not_the_fixture(working_copy):
    root = Path(working_copy["workdir_path"])
    fixture_file = FIXTURES / "pr_with_secret" / "files" / "src" / "config.py"
    before_fixture = fixture_file.read_text()

    working_copy["findings"] = [
        _finding(Severity.HIGH, line=8,
                 fix='AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]')
    ]
    nodes = GraphNodes(router=StubRouter(), verbose=False)
    out = nodes.apply_fix(working_copy)

    assert out["patched_files"] == ["src/config.py:8"]
    assert out["iteration"] == 1
    patched = (root / "src" / "config.py").read_text()
    assert 'os.environ["AWS_ACCESS_KEY_ID"]' in patched
    assert "AKIA3XQ7MZPLK2VNWR4T" not in patched
    # The fixture itself is untouched, so the demo is repeatable.
    assert fixture_file.read_text() == before_fixture
    assert "AKIA3XQ7MZPLK2VNWR4T" in before_fixture


def test_remediation_genuinely_reduces_real_scanner_findings(working_copy):
    """The substance of the loop: patch, then let the REAL scanner re-count.

    No LLM here — the fixes are applied and the actual secret scanner runs again.
    If the count did not drop, the loop would be scaffolding.
    """
    root = Path(working_copy["workdir_path"])
    pr = load_pull_request(FIXTURES / "pr_with_secret")

    def count_real_hits() -> int:
        with review_root(root), pr_context(pr):
            hits = scan_secrets_impl(".")["hits"]
        return len([h for h in hits if not h["in_test_path"]])

    before = count_real_hits()
    assert before == 3, f"expected 3 real leaks in the fixture, found {before}"

    working_copy["findings"] = [
        _finding(Severity.HIGH, line=8,
                 fix='AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]'),
        _finding(Severity.HIGH, line=15, fix='DB_PASSWORD = os.environ["DB_PASSWORD"]'),
        _finding(Severity.HIGH, line=18,
                 fix='SUPPORT_CONTACT_EMAIL = os.environ["SUPPORT_CONTACT_EMAIL"]'),
    ]
    GraphNodes(router=StubRouter(), verbose=False).apply_fix(working_copy)

    after = count_real_hits()
    assert after < before, f"remediation did not reduce findings: {before} -> {after}"
    assert after == 0, f"expected all three repaired, {after} remain"


# --- end to end, offline -------------------------------------------------------

def test_injection_fixture_is_blocked_before_reaching_any_agent():
    router = StubRouter()
    graph = build_graph(router=router, checkpointer=make_checkpointer(), verbose=False)
    state = prepare_initial_state(FIXTURES / "pr_injection", workdir_name="test-injection")

    final = graph.invoke(state, {"configurable": {"thread_id": "test-injection"}})

    assert final["status"] == "blocked"
    assert final["verdict"].decision == "BLOCK_MERGE"
    # The decisive assertion: no model call was made at all.
    assert router.calls == [], f"model was called despite the block: {router.calls}"
    events = [e for e in final["guardrail_events"] if e.get("guardrail") == "prompt_injection"]
    assert events and events[0]["blocked"] is True


def test_clean_pr_runs_end_to_end_to_a_verdict():
    router = StubRouter({
        "CoordinatorAgent.final": [StubResponse(parsed=ReviewPlan(
            steps=["review formatting helpers"],
            delegate_to=["SecurityAgent", "StyleAgent"],
            rationale="no logic changes"))],
    })
    graph = build_graph(router=router, checkpointer=make_checkpointer(), verbose=False)
    state = prepare_initial_state(FIXTURES / "pr_clean", workdir_name="test-clean")

    final = graph.invoke(state, {"configurable": {"thread_id": "test-clean"}})

    assert final["status"] == "reported"
    assert final["verdict"] is not None
    assert final["iteration"] == 0
    tags = [c["tag"] for c in router.calls]
    assert "CoordinatorAgent.react" in tags
    # Delegation was respected: coverage was not requested, so it never ran.
    assert not any(t.startswith("TestCoverageAgent") for t in tags)


def test_blocked_pr_still_writes_an_audit_report():
    """An attempted attack is exactly the event worth keeping a record of.

    Regression: `blocked` originally routed straight to END, so a blocked
    injection produced no artifact at all — the deployed MinIO bucket stayed
    empty after the guardrail fired.
    """
    graph = build_graph(router=StubRouter(), checkpointer=make_checkpointer(), verbose=False)
    state = prepare_initial_state(FIXTURES / "pr_injection", workdir_name="test-blocked-report")

    final = graph.invoke(state, {"configurable": {"thread_id": "test-blocked-report"}})

    # The terminal status still says WHY the review ended...
    assert final["status"] == "blocked"
    # ...and a report was nonetheless written.
    assert final.get("report_path")
    assert Path(final["report_path"]).exists()
    report = json.loads(Path(final["report_path"]).read_text())
    assert report["decision"] == "BLOCK_MERGE"
    assert report["guardrail_events"], "the audit record must carry the guardrail event"


# --- the delegation decision genuinely changes execution ----------------------

def test_docs_only_pr_skips_the_coverage_agent():
    """A docs-only PR has no coverage to measure — the coordinator should skip it.

    fan_out_to_specialists returns a LIST of nodes, so this is a routing
    decision rather than a logged intention; the node does not execute.
    """
    router = StubRouter({
        "CoordinatorAgent.final": [StubResponse(parsed=ReviewPlan(
            steps=["check the runbook for accidental credential disclosure"],
            delegate_to=["SecurityAgent", "StyleAgent"],
            rationale="Documentation only: nothing executable, so there is no coverage "
                      "to measure. Security still runs — docs are a common place to "
                      "paste a real key by accident."))],
    })
    graph = build_graph(router=router, checkpointer=make_checkpointer(), verbose=False)
    state = prepare_initial_state(FIXTURES / "pr_docs_only", workdir_name="test-docs-only")

    final = graph.invoke(state, {"configurable": {"thread_id": "test-docs-only"}})

    assert final["delegated_agents"] == ["SecurityAgent", "StyleAgent"]
    tags = [c["tag"] for c in router.calls]
    assert not any(t.startswith("TestCoverageAgent") for t in tags), \
        "coverage agent ran despite being excluded from the delegation"
    assert any(t.startswith("SecurityAgent") for t in tags)


def test_docs_only_pr_produces_no_secret_findings():
    """Variable NAMES in documentation must not be reported as credentials."""
    pr = load_pull_request(FIXTURES / "pr_docs_only")
    with review_root(pr.root), pr_context(pr):
        assert scan_secrets_impl(".")["hit_count"] == 0
