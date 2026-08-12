#!/usr/bin/env python
"""Run the full review graph over a fixture, end to end, against real models.

    .venv/bin/python scripts/run_review.py pr_with_secret [thread_id]

Prints the state after every node, the finding count per remediation iteration,
and the termination reason — the Deliverable-2 evidence.
"""

from __future__ import annotations

import sys
import time

from codeguard.config import get_settings
from codeguard.graph.build import build_graph, make_checkpointer, prepare_initial_state
from codeguard.graph.edges import loop_should_terminate
from codeguard.obs.metrics import METRICS, print_summary, run_context
from codeguard.state import current_findings


def main() -> int:
    fixture = sys.argv[1] if len(sys.argv) > 1 else "pr_with_secret"
    thread_id = sys.argv[2] if len(sys.argv) > 2 else f"{fixture}-{int(time.time())}"
    settings = get_settings()

    print("=" * 82)
    print(f"FULL GRAPH RUN — {fixture}")
    print("=" * 82)
    print(f"thread_id  : {thread_id}")
    print(f"MAX_ITER   : {settings.max_iter}")
    print(f"guardrails : {settings.guardrails_enabled}")
    print(f"models     : {settings.primary_model} / synthesis {settings.synthesis_model}")

    state = prepare_initial_state(settings.fixtures_dir / fixture, workdir_name=thread_id)
    graph = build_graph(checkpointer=make_checkpointer(), verbose=True)
    config = {"configurable": {"thread_id": thread_id}, "recursion_limit": 60}

    started = time.time()
    with run_context(thread_id=thread_id, pr_id=state["pr_id"]):
        final = graph.invoke(state, config)
    elapsed = time.time() - started

    # --- paused for a human? ------------------------------------------------
    interrupts = final.get("__interrupt__") or []
    if interrupts:
        payload = interrupts[0].value if hasattr(interrupts[0], "value") else interrupts[0]
        print("\n" + "=" * 82)
        print("GRAPH PAUSED AT hitl_approval — awaiting a human decision")
        print("=" * 82)
        print(f"  proposed verdict : {payload.get('proposed_verdict')}")
        print(f"  blocking findings: {len(payload.get('blocking_findings', []))}")
        for f in payload.get("blocking_findings", [])[:5]:
            print(f"    {f['severity']:<9}{f['file']}:{f['line']}  {f['message'][:52]}")
        print(f"\n  State is checkpointed. Resume with thread_id={thread_id!r}.")
        print(f"  elapsed: {elapsed:.0f}s")
        return 0

    # --- the loop evidence ---------------------------------------------------
    print("\n" + "=" * 82)
    print("REMEDIATION LOOP — findings per iteration")
    print("=" * 82)
    history = final.get("iteration_history", [])
    if history:
        print(f"  {'iter':>4}  {'total':>6}  {'blocking':>9}  {'triaged FP':>11}  decision")
        print("  " + "-" * 62)
        for h in history:
            print(f"  {h['iteration']:>4}  {h['findings_total']:>6}  "
                  f"{h['findings_blocking']:>9}  {h['false_positives']:>11}  {h['decision']}")
        counts = [h["findings_blocking"] for h in history]
        arrow = " -> ".join(str(c) for c in counts)
        print(f"\n  blocking findings across iterations: {arrow}")
        if len(counts) > 1:
            print(f"  strictly decreasing: {all(b < a for a, b in zip(counts, counts[1:]))}")
    done, why = loop_should_terminate(final)
    print(f"  terminated because: {why}")
    print(f"  patched files: {final.get('patched_files', []) or 'none'}")

    # --- verdict -------------------------------------------------------------
    verdict = final.get("verdict")
    print("\n" + "=" * 82)
    print(f"VERDICT: {verdict.decision if verdict else 'NONE'}")
    print("=" * 82)
    if verdict:
        print(f"  {verdict.rationale[:600]}")
        print(f"\n  blocking findings: {len(verdict.blocking_findings)}")

    findings = current_findings(final)
    if findings:
        print(f"\n  final findings ({len(findings)}):")
        for f in findings:
            fp = "  [TRIAGED FP]" if f.is_false_positive else ""
            print(f"    {f.agent:<20}{f.severity.value:<9}{f.file}:{f.line}  "
                  f"{f.message[:44]}{fp}")

    print(f"\n  status: {final.get('status')}   iterations: {final.get('iteration')}   "
          f"elapsed: {elapsed:.0f}s")
    print()
    print_summary(METRICS.read(thread_id=thread_id), title=f"{fixture} — measured metrics")
    print("=" * 82)
    return 0


if __name__ == "__main__":
    sys.exit(main())
