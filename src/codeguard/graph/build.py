"""StateGraph assembly — nodes, edges, and the compiled graph.

The topology built here:

    START -> ingest_pr -> guardrail_input
                            |-- (injection) --> blocked -> END
                            '-- (clean) -----> coordinator
                                                  |
                        (PARALLEL FAN-OUT, conditional on delegation)
                    security_agent   style_agent   coverage_agent
                                '---------|---------'
                                     (FAN-IN)
                                    synthesizer
                                         |
                            route_after_synthesis   <-- CONDITIONAL EDGE
                    |-------------------|--------------------|
              hitl_approval      remediation_loop         finalize
                    |                   |                    |
              apply_decision        apply_fix           persist_report
                    |                   |                    |
                 finalize      (LOOP back to agents)         END

The checkpointer is a real ``SqliteSaver`` over a file on disk, which is what
allows an interrupted run to resume in a different process.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph

from codeguard.config import PROJECT_ROOT, Settings, get_settings
from codeguard.graph.edges import (
    fan_out_after_fix,
    fan_out_to_specialists,
    route_after_guardrail,
    route_after_synthesis,
)
from codeguard.graph.nodes import GraphNodes
from codeguard.llm.router import LLMRouter
from codeguard.obs.tracing import setup_tracing, span
from codeguard.state import ReviewState, new_state
from codeguard.tools.repo_tools import load_pull_request, materialize

SPECIALIST_NODES = ["security_agent", "style_agent", "coverage_agent"]


def make_checkpointer(path: Path | str | None = None) -> SqliteSaver:
    """A file-backed checkpointer that survives process exit.

    Constructed from a raw connection rather than ``from_conn_string``, which is
    a context manager and would close the database as soon as the block exits —
    useless for a long-lived API process.

    ``check_same_thread=False`` is required because the parallel agent fan-out
    writes checkpoints from worker threads.
    """
    p = Path(path) if path else get_settings().checkpoint_path
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), check_same_thread=False)
    return SqliteSaver(conn)


def build_graph(
    router: LLMRouter | None = None,
    checkpointer: Any | None = None,
    settings: Settings | None = None,
    verbose: bool = True,
):
    """Assemble and compile the review graph."""
    settings = settings or get_settings()
    setup_tracing()  # idempotent; installs the provider on first call
    nodes = GraphNodes(router=router, settings=settings, verbose=verbose)

    graph = StateGraph(ReviewState)

    def traced(name: str, fn):
        """Wrap a node so the trace waterfall shows the graph's real shape.

        Node spans are what make the parallel fan-out visible: the three
        specialists overlap on the timeline, and the synthesizer starts only
        once the last of them finishes.
        """

        def _node(state: ReviewState) -> Any:
            with span(f"node.{name}", kind="CHAIN", **{
                "graph.node": name,
                "graph.iteration": state.get("iteration", 0),
                "pr.id": state.get("pr_id"),
            }) as sp:
                out = fn(state)
                try:
                    if isinstance(out, dict):
                        sp.set_attribute("graph.findings_added", len(out.get("findings", []) or []))
                        sp.set_attribute("graph.status", str(out.get("status", "")))
                except Exception:  # noqa: BLE001
                    pass
                return out

        _node.__name__ = name
        return _node

    # --- nodes ---
    graph.add_node("ingest_pr", traced("ingest_pr", nodes.ingest_pr))
    graph.add_node("guardrail_input", traced("guardrail_input", nodes.guardrail_input))
    graph.add_node("blocked", traced("blocked", nodes.blocked))
    graph.add_node("coordinator", traced("coordinator", nodes.coordinator_node))
    graph.add_node("security_agent", traced("security_agent", nodes.security_agent_node))
    graph.add_node("style_agent", traced("style_agent", nodes.style_agent_node))
    graph.add_node("coverage_agent", traced("coverage_agent", nodes.coverage_agent_node))
    graph.add_node("synthesizer", traced("synthesizer", nodes.synthesizer_node))
    graph.add_node("remediation_loop", traced("remediation_loop", nodes.remediation_loop))
    graph.add_node("apply_fix", traced("apply_fix", nodes.apply_fix))
    # NOT traced: interrupt() unwinds the stack to suspend the graph, and an
    # enclosing span would record that control-flow signal as a span error.
    graph.add_node("hitl_approval", nodes.hitl_approval)
    graph.add_node("apply_decision", traced("apply_decision", nodes.apply_decision))
    graph.add_node("finalize", traced("finalize", nodes.finalize))
    graph.add_node("persist_report", traced("persist_report", nodes.persist_report))

    # --- edges ---
    graph.add_edge(START, "ingest_pr")
    graph.add_edge("ingest_pr", "guardrail_input")

    # Input guardrail: a blocked PR never reaches the coordinator.
    graph.add_conditional_edges(
        "guardrail_input", route_after_guardrail,
        {"blocked": "blocked", "coordinator": "coordinator"},
    )
    graph.add_edge("blocked", END)

    # PARALLEL FAN-OUT, driven by the coordinator's delegation decision.
    graph.add_conditional_edges("coordinator", fan_out_to_specialists, SPECIALIST_NODES)

    # FAN-IN: synthesizer waits for every specialist that actually ran.
    for node in SPECIALIST_NODES:
        graph.add_edge(node, "synthesizer")

    # THE CONDITIONAL EDGE.
    graph.add_conditional_edges(
        "synthesizer", route_after_synthesis,
        {
            "hitl_approval": "hitl_approval",
            "remediation_loop": "remediation_loop",
            "finalize": "finalize",
        },
    )

    # THE LOOP: patch the working copy, then re-scan the patched code.
    # The path map lists only the nodes fan_out_after_fix can actually return —
    # passing all three would draw an apply_fix -> coverage_agent edge in the
    # rendered diagram that the routing function never takes.
    graph.add_edge("remediation_loop", "apply_fix")
    graph.add_conditional_edges(
        "apply_fix", fan_out_after_fix, ["security_agent", "style_agent"]
    )

    # Human-in-the-loop branch.
    graph.add_edge("hitl_approval", "apply_decision")
    graph.add_edge("apply_decision", "finalize")

    # Exit.
    graph.add_edge("finalize", "persist_report")
    graph.add_edge("persist_report", END)

    return graph.compile(checkpointer=checkpointer or make_checkpointer())


def prepare_initial_state(
    fixture_dir: Path | str, workdir_name: str | None = None
) -> ReviewState:
    """Load a PR fixture and materialise a working copy under ``workdir/``.

    Analysis runs entirely against the copy, so ``apply_fix`` can rewrite files
    without ever touching the fixture — which is what makes the demo repeatable.
    """
    pr = load_pull_request(fixture_dir)
    dest = get_settings().workdir / (workdir_name or pr.pr_id)
    working = materialize(pr, dest)
    return new_state(
        pr_id=working.pr_id,
        pr_title=working.title,
        pr_description=working.description,
        changed_files=list(working.changed_files),
        diff=working.diff,
        workdir_path=str(working.root),
    )


def render_graph(compiled: Any, out_dir: Path | str | None = None) -> dict[str, str]:
    """Write the graph diagram to ``docs/``. Returns the paths written."""
    out = Path(out_dir) if out_dir else PROJECT_ROOT / "docs"
    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}

    drawable = compiled.get_graph()
    mermaid = drawable.draw_mermaid()
    mmd_path = out / "graph.mmd"
    mmd_path.write_text(mermaid, encoding="utf-8")
    written["mermaid"] = str(mmd_path)

    ascii_path = out / "graph.txt"
    try:
        ascii_path.write_text(drawable.draw_ascii(), encoding="utf-8")
        written["ascii"] = str(ascii_path)
    except Exception:  # noqa: BLE001 - grandalf may be absent; mermaid is enough
        pass

    # PNG rendering calls out to mermaid.ink and needs network. Optional.
    try:
        png = drawable.draw_mermaid_png()
        png_path = out / "graph.png"
        png_path.write_bytes(png)
        written["png"] = str(png_path)
    except Exception as exc:  # noqa: BLE001
        written["png_error"] = f"{type(exc).__name__}: {exc}"

    return written
