#!/usr/bin/env python
"""Human-in-the-loop: pause on a critical finding, then show BOTH resume decisions.

A single happy path proves nothing about an approval gate — the interesting
question is whether the two decisions actually produce different outcomes. So the
review is run once to the interrupt, the checkpoint database is then *copied*,
and the same paused thread is resumed twice: approve against one copy, reject
against the other.

Copying the checkpoint rather than re-running is not a shortcut for its own sake:
it means both branches resume from the byte-identical pause, so any difference in
outcome is attributable to the human decision and nothing else. It also halves
the model calls, which matters on a rate-limited free tier.

    .venv/bin/python scripts/hitl_demo.py [--real]
"""

from __future__ import annotations

import argparse
import shutil
import sys
import time
from pathlib import Path

from codeguard.config import PROJECT_ROOT, get_settings
from codeguard.graph.build import build_graph, make_checkpointer, prepare_initial_state
from codeguard.graph.resume import checkpoint_summary, pending_interrupt, resume_review
from codeguard.llm.stub import scripted_critical_router
from codeguard.obs.metrics import run_context


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--real", action="store_true", help="drive with live models")
    ap.add_argument("--fixture", default="pr_critical")
    args = ap.parse_args()

    settings = get_settings()
    thread_id = f"hitl-{int(time.time())}"
    router = None if args.real else scripted_critical_router()

    print("=" * 82)
    print("HUMAN-IN-THE-LOOP — interrupt on a critical finding, then approve AND reject")
    print("=" * 82)
    print(f"thread_id : {thread_id}")
    print(f"fixture   : {args.fixture}")
    print(f"llm       : {'live models' if args.real else 'stubbed (graph and pause are real)'}")

    # ---------------------------------------------------------------- 1. pause
    print("\n" + "-" * 82)
    print("[1] RUN UNTIL THE GRAPH PAUSES FOR A HUMAN")
    print("-" * 82)
    state = prepare_initial_state(settings.fixtures_dir / args.fixture, workdir_name=thread_id)
    graph = build_graph(router=router, checkpointer=make_checkpointer(), verbose=False)
    config = {"configurable": {"thread_id": thread_id}, "recursion_limit": 60}

    with run_context(thread_id=thread_id, pr_id=state["pr_id"]):
        graph.invoke(state, config)

    payload = pending_interrupt(graph, thread_id)
    if payload is None:
        print("  !! graph did not pause — no critical finding was produced")
        print(f"  final state: {checkpoint_summary(graph, thread_id)}")
        return 1

    print(f"  PAUSED. interrupt() payload delivered to the operator:")
    print(f"    pr_id            : {payload.get('pr_id')}")
    print(f"    proposed verdict : {payload.get('proposed_verdict')}")
    print(f"    options          : {payload.get('options')}")
    print(f"    blocking findings: {len(payload.get('blocking_findings', []))}")
    for f in payload.get("blocking_findings", []):
        print(f"      {f['severity']:<9}{f['file']}:{f['line']}  {f['message'][:56]}")

    snap = checkpoint_summary(graph, thread_id)
    print(f"\n  graph is halted at node(s): {snap['next_nodes']}")
    print("  the process may now exit entirely; the decision can arrive later")

    # ------------------------------------------------- 2. snapshot the database
    db = settings.checkpoint_path
    approve_db = db.with_name("checkpoints_approve.sqlite")
    reject_db = db.with_name("checkpoints_reject.sqlite")
    for target in (approve_db, reject_db):
        for suffix in ("", "-wal", "-shm"):
            src = Path(str(db) + suffix)
            if src.exists():
                shutil.copy2(src, Path(str(target) + suffix))
    print(f"\n  checkpoint snapshotted twice so both branches resume from the same pause")

    # -------------------------------------------------------- 3. both decisions
    results = {}
    for decision, dbfile, reason in (
        ("approve", approve_db,
         "Reviewed with the platform team: the eval path is behind an internal-only "
         "flag and the key was already rotated. Accepting the risk for this release."),
        ("reject", reject_db,
         "Shell injection on merchant-controlled input is not acceptable. Rotate the "
         "committed key and resubmit."),
    ):
        print("\n" + "-" * 82)
        print(f"[{'2' if decision == 'approve' else '3'}] RESUME WITH decision={decision!r}")
        print("-" * 82)
        # make_checkpointer, not a bare SqliteSaver: it installs the serializer
        # that registers our state types, without which every resume warns that
        # deserialising them will be blocked in a future LangGraph.
        final = resume_review(
            thread_id, decision, reason, router=router,
            checkpointer=make_checkpointer(dbfile), verbose=False,
        )
        verdict = final.get("verdict")
        results[decision] = verdict
        print(f"  hitl_decision : {final.get('hitl_decision')}")
        print(f"  FINAL VERDICT : {verdict.decision if verdict else 'NONE'}")
        print(f"  rationale     : {(verdict.rationale if verdict else '')[:300]}")
        print(f"  status        : {final.get('status')}")

    # ----------------------------------------------------------- 4. the contrast
    print("\n" + "=" * 82)
    print("BOTH PATHS, FROM THE SAME PAUSE")
    print("=" * 82)
    print(f"  {'decision':<12}{'verdict':<18}blocking findings carried forward")
    print("  " + "-" * 68)
    for d, v in results.items():
        print(f"  {d:<12}{(v.decision if v else 'NONE'):<18}{len(v.blocking_findings) if v else 0}")

    ok = (
        results.get("approve") is not None
        and results.get("reject") is not None
        and results["approve"].decision == "APPROVE"
        and results["reject"].decision == "BLOCK_MERGE"
    )
    print()
    print(f"  [{'PASS' if payload else 'FAIL'}] graph paused at hitl_approval via interrupt()")
    print(f"  [{'PASS' if ok else 'FAIL'}] the two decisions produced genuinely different "
          "verdicts from an identical checkpoint")
    for f in (approve_db, reject_db):
        for suffix in ("", "-wal", "-shm"):
            Path(str(f) + suffix).unlink(missing_ok=True)
    print("=" * 82)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
