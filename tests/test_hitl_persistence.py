"""Human-in-the-loop and checkpoint durability.

Deterministic: the stub replaces the model, but the interrupt, the SqliteSaver,
the on-disk database and the resume are all real.
"""

from __future__ import annotations

import sqlite3

import pytest
from langgraph.types import Command

from codeguard.config import get_settings
from codeguard.graph.build import build_graph, make_checkpointer, prepare_initial_state
from codeguard.graph.resume import checkpoint_summary, pending_interrupt
from codeguard.llm.stub import scripted_critical_router, scripted_review_router

FIXTURES = get_settings().fixtures_dir


@pytest.fixture()
def db(tmp_path):
    """A throwaway checkpoint database per test."""
    path = tmp_path / "checkpoints.sqlite"
    yield path, make_checkpointer(path)


def _paused_graph(db, thread_id):
    """Run pr_critical until the graph pauses for a human."""
    path, saver = db
    graph = build_graph(router=scripted_critical_router(), checkpointer=saver, verbose=False)
    state = prepare_initial_state(FIXTURES / "pr_critical", workdir_name=thread_id)
    graph.invoke(state, {"configurable": {"thread_id": thread_id}, "recursion_limit": 60})
    return graph


# --- the pause ----------------------------------------------------------------

def test_critical_finding_pauses_the_graph(db):
    graph = _paused_graph(db, "t-pause")
    assert pending_interrupt(graph, "t-pause") is not None
    assert checkpoint_summary(graph, "t-pause")["next_nodes"] == ["hitl_approval"]


def test_interrupt_payload_gives_the_operator_what_they_need(db):
    graph = _paused_graph(db, "t-payload")
    payload = pending_interrupt(graph, "t-payload")
    assert payload["pr_id"] == "PR-1103"
    assert payload["options"] == ["approve", "reject"]
    assert payload["proposed_verdict"] == "BLOCK_MERGE"
    assert len(payload["blocking_findings"]) == 3
    assert all({"severity", "file", "line", "message"} <= set(f) for f
               in payload["blocking_findings"])


def test_graph_does_not_finish_while_paused(db):
    graph = _paused_graph(db, "t-halted")
    assert checkpoint_summary(graph, "t-halted")["status"] != "reported"


# --- both resume decisions ----------------------------------------------------

@pytest.mark.parametrize(
    "decision,expected,expect_blocking",
    [("approve", "APPROVE", 0), ("reject", "BLOCK_MERGE", 3)],
)
def test_resume_decision_changes_the_verdict(db, decision, expected, expect_blocking):
    thread = f"t-{decision}"
    graph = _paused_graph(db, thread)
    final = graph.invoke(
        Command(resume={"decision": decision, "reason": "test"}),
        {"configurable": {"thread_id": thread}, "recursion_limit": 60},
    )
    assert final["hitl_decision"] == decision
    assert final["verdict"].decision == expected
    assert len(final["verdict"].blocking_findings) == expect_blocking
    assert final["status"] == "reported"


def test_the_human_reason_is_recorded_on_the_verdict(db):
    graph = _paused_graph(db, "t-reason")
    final = graph.invoke(
        Command(resume={"decision": "reject", "reason": "rotate the committed key first"}),
        {"configurable": {"thread_id": "t-reason"}, "recursion_limit": 60},
    )
    assert "rotate the committed key first" in final["verdict"].rationale


def test_an_unrecognised_decision_fails_closed(db):
    """Anything that is not an explicit approval must not approve the merge."""
    graph = _paused_graph(db, "t-garbage")
    final = graph.invoke(
        Command(resume={"decision": "¯\\_(ツ)_/¯", "reason": ""}),
        {"configurable": {"thread_id": "t-garbage"}, "recursion_limit": 60},
    )
    assert final["verdict"].decision == "BLOCK_MERGE"


# --- durability ---------------------------------------------------------------

def test_checkpoint_is_written_to_the_file_not_just_memory(db):
    path, _ = db
    _paused_graph(db, "t-ondisk")
    assert path.exists() and path.stat().st_size > 0
    # Read the table directly: no LangGraph involved in the assertion.
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        n = conn.execute(
            "SELECT COUNT(*) FROM checkpoints WHERE thread_id = ?", ("t-ondisk",)
        ).fetchone()[0]
    finally:
        conn.close()
    assert n > 0


def test_a_brand_new_graph_object_recovers_the_paused_state(db):
    """Simulates a restart: nothing shared with the first run but the file."""
    path, _ = db
    _paused_graph(db, "t-restart")

    try:
        fresh = build_graph(
            router=scripted_critical_router(), checkpointer=make_checkpointer(path),
            verbose=False
        )
        recovered = checkpoint_summary(fresh, "t-restart")
        assert recovered["pr_id"] == "PR-1103"
        assert recovered["next_nodes"] == ["hitl_approval"]
        assert recovered["scratchpad_lines"] > 0
        # And it can still be driven to completion from there.
        final = fresh.invoke(
            Command(resume={"decision": "reject", "reason": "after restart"}),
            {"configurable": {"thread_id": "t-restart"}, "recursion_limit": 60},
        )
        assert final["status"] == "reported"
    finally:
        pass


def test_threads_are_isolated_from_one_another(db):
    """Two reviews on one database must not read each other's state."""
    path, saver = db
    graph = build_graph(router=scripted_review_router(), checkpointer=saver, verbose=False)
    for thread, fixture in (("t-iso-a", "pr_clean"), ("t-iso-b", "pr_with_secret")):
        state = prepare_initial_state(FIXTURES / fixture, workdir_name=thread)
        graph.invoke(state, {"configurable": {"thread_id": thread}, "recursion_limit": 60})

    a = checkpoint_summary(graph, "t-iso-a")
    b = checkpoint_summary(graph, "t-iso-b")
    assert a["pr_id"] == "PR-1017"
    assert b["pr_id"] == "PR-1042"
    assert a["pr_id"] != b["pr_id"]
