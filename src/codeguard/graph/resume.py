"""Resuming an interrupted review — the other half of human-in-the-loop.

``hitl_approval`` calls :func:`langgraph.types.interrupt`, which suspends the
graph and persists everything through the checkpointer. The process may then
exit entirely. Resuming means re-opening the same ``thread_id`` and invoking the
graph with :class:`langgraph.types.Command`, whose ``resume`` value becomes the
return value of the original ``interrupt()`` call inside the paused node.

That is what makes the pause real rather than a blocking sleep: the decision can
arrive minutes later, from a different process, or over HTTP.
"""

from __future__ import annotations

from typing import Any

from langgraph.types import Command

from codeguard.graph.build import build_graph, make_checkpointer
from codeguard.llm.router import LLMRouter
from codeguard.obs.metrics import run_context


def pending_interrupt(graph: Any, thread_id: str) -> dict[str, Any] | None:
    """Return the payload the graph is waiting on, or ``None`` if it is not paused."""
    snapshot = graph.get_state({"configurable": {"thread_id": thread_id}})
    interrupts = getattr(snapshot, "interrupts", None) or []
    if not interrupts:
        # Older/newer shapes surface interrupts on the pending tasks instead.
        for task in getattr(snapshot, "tasks", ()) or ():
            for itr in getattr(task, "interrupts", ()) or ():
                return getattr(itr, "value", itr)
        return None
    return getattr(interrupts[0], "value", interrupts[0])


def checkpoint_summary(graph: Any, thread_id: str) -> dict[str, Any]:
    """What survived the process boundary — read straight back out of SQLite."""
    snapshot = graph.get_state({"configurable": {"thread_id": thread_id}})
    values = snapshot.values or {}
    return {
        "thread_id": thread_id,
        "next_nodes": list(snapshot.next or ()),
        "pr_id": values.get("pr_id"),
        "status": values.get("status"),
        "iteration": values.get("iteration", 0),
        "findings": len(values.get("findings", [])),
        "scratchpad_lines": len(values.get("scratchpad", [])),
        "guardrail_events": len(values.get("guardrail_events", [])),
        "cost_usd": values.get("cost_usd", 0.0),
        "verdict": (values.get("verdict").decision if values.get("verdict") else None),
        "checkpoint_id": (snapshot.config or {}).get("configurable", {}).get("checkpoint_id"),
    }


def resume_review(
    thread_id: str,
    decision: str,
    reason: str = "",
    router: LLMRouter | None = None,
    checkpointer: Any | None = None,
    verbose: bool = True,
) -> dict[str, Any]:
    """Resume a paused review with a human decision.

    Args:
        thread_id: The thread that was interrupted.
        decision: ``"approve"`` or ``"reject"``.
        reason: Free text recorded on the verdict for audit.
    """
    graph = build_graph(
        router=router, checkpointer=checkpointer or make_checkpointer(), verbose=verbose
    )
    config = {"configurable": {"thread_id": thread_id}, "recursion_limit": 60}

    before = checkpoint_summary(graph, thread_id)
    if verbose:
        print(f"  resuming thread {thread_id!r} from checkpoint "
              f"{before['checkpoint_id']}, next node(s): {before['next_nodes']}")

    # Command(resume=...) delivers the decision back into the paused interrupt().
    with run_context(thread_id=thread_id, pr_id=before.get("pr_id")):
        final = graph.invoke(
            Command(resume={"decision": decision, "reason": reason}), config
        )
    return final
