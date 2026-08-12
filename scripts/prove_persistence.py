#!/usr/bin/env python
"""Prove checkpoint durability: SIGKILL a running review, resume it in a fresh process.

Three separate OS processes are involved, which is the whole point — a claim of
persistence that never crosses a process boundary proves nothing.

  1. WORKER   starts a review and is hard-killed (SIGKILL, no cleanup, no
              exception handler, no chance to flush anything gracefully).
  2. PARENT   re-opens state/checkpoints.sqlite on a fresh connection and reads
              the surviving checkpoint straight out of the file.
  3. RESUMER  a brand-new process, different PID, resumes the same thread_id and
              runs the review to completion.

The LLM is stubbed by default: the checkpointer, SQLite, the process kill and the
resume are all genuinely real, and none of them depend on which model answered.
Stubbing keeps the proof deterministic and lets an evaluator re-run it without an
API key. Pass --real to drive it with live models instead.

    .venv/bin/python scripts/prove_persistence.py
"""

from __future__ import annotations

import argparse
import os
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from codeguard.config import PROJECT_ROOT, get_settings

CHECKPOINTS = get_settings().checkpoint_path


def count_checkpoints(thread_id: str) -> int:
    """Read the checkpoint table directly — no LangGraph in the way."""
    if not CHECKPOINTS.exists():
        return 0
    try:
        conn = sqlite3.connect(f"file:{CHECKPOINTS}?mode=ro", uri=True, timeout=5)
        try:
            cur = conn.execute(
                "SELECT COUNT(*) FROM checkpoints WHERE thread_id = ?", (thread_id,)
            )
            return int(cur.fetchone()[0])
        finally:
            conn.close()
    except sqlite3.Error:
        return 0


# --------------------------------------------------------------------------- #
# child modes
# --------------------------------------------------------------------------- #

def run_worker(thread_id: str, fixture: str, real: bool) -> int:
    """Start a review. Expects to be killed part-way through."""
    from codeguard.graph.build import build_graph, make_checkpointer, prepare_initial_state
    from codeguard.llm.stub import scripted_review_router
    from codeguard.obs.metrics import run_context

    router = None if real else scripted_review_router()
    state = prepare_initial_state(get_settings().fixtures_dir / fixture, workdir_name=thread_id)
    graph = build_graph(router=router, checkpointer=make_checkpointer(), verbose=False)
    print(f"[worker pid={os.getpid()}] starting review {state['pr_id']} thread={thread_id}",
          flush=True)
    with run_context(thread_id=thread_id, pr_id=state["pr_id"]):
        graph.invoke(state, {"configurable": {"thread_id": thread_id}, "recursion_limit": 60})
    print(f"[worker pid={os.getpid()}] finished without being killed", flush=True)
    return 0


def run_resumer(thread_id: str, real: bool) -> int:
    """A fresh process: resume the same thread and finish the review."""
    from codeguard.graph.build import build_graph, make_checkpointer
    from codeguard.graph.resume import checkpoint_summary
    from codeguard.llm.stub import scripted_review_router
    from codeguard.obs.metrics import run_context

    router = None if real else scripted_review_router()
    graph = build_graph(router=router, checkpointer=make_checkpointer(), verbose=False)
    config = {"configurable": {"thread_id": thread_id}, "recursion_limit": 60}

    before = checkpoint_summary(graph, thread_id)
    print(f"[resumer pid={os.getpid()}] state recovered from SQLite:", flush=True)
    for k in ("pr_id", "status", "iteration", "findings", "scratchpad_lines",
              "guardrail_events", "next_nodes"):
        print(f"    {k:<18}{before[k]}", flush=True)

    if not before["next_nodes"]:
        print(f"[resumer pid={os.getpid()}] nothing pending; graph already complete", flush=True)
        return 0

    # Invoking with None continues from the last committed checkpoint. If the
    # graph happened to stop at the human-approval interrupt, it needs a decision
    # instead — Command(resume=...) delivers one back into the paused node.
    from codeguard.graph.resume import pending_interrupt

    payload = pending_interrupt(graph, thread_id)
    resume_with = None
    if payload is not None:
        from langgraph.types import Command
        print(f"[resumer pid={os.getpid()}] thread was paused at human approval; "
              "resuming with a decision", flush=True)
        resume_with = Command(resume={"decision": "reject",
                                      "reason": "resumed after process kill"})

    with run_context(thread_id=thread_id, pr_id=before.get("pr_id")):
        graph.invoke(resume_with, config)

    after = checkpoint_summary(graph, thread_id)
    print(f"[resumer pid={os.getpid()}] resumed and completed:", flush=True)
    print(f"    status            {after['status']}", flush=True)
    print(f"    verdict           {after['verdict']}", flush=True)
    print(f"    scratchpad_lines  {before['scratchpad_lines']} -> {after['scratchpad_lines']}",
          flush=True)
    return 0


# --------------------------------------------------------------------------- #
# orchestrator
# --------------------------------------------------------------------------- #

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--worker", metavar="THREAD")
    ap.add_argument("--resume", metavar="THREAD")
    ap.add_argument("--fixture", default="pr_with_secret")
    ap.add_argument("--real", action="store_true", help="drive with live models")
    args = ap.parse_args()

    if args.worker:
        return run_worker(args.worker, args.fixture, args.real)
    if args.resume:
        return run_resumer(args.resume, args.real)

    thread_id = f"persistence-{int(time.time())}"
    py = sys.executable
    here = str(Path(__file__).resolve())
    extra = ["--real"] if args.real else []

    print("=" * 80)
    print("CHECKPOINT DURABILITY PROOF — SIGKILL mid-run, resume in a fresh process")
    print("=" * 80)
    print(f"thread_id  : {thread_id}")
    print(f"checkpoint : {CHECKPOINTS.relative_to(PROJECT_ROOT)}")
    print(f"llm        : {'live models' if args.real else 'stubbed (checkpointer is real)'}")
    print(f"parent pid : {os.getpid()}")

    # --- 1. start the worker and kill it once it has committed real progress ---
    print("\n" + "-" * 80)
    print("[1] START WORKER, then SIGKILL it mid-review")
    print("-" * 80)
    proc = subprocess.Popen(
        [py, here, "--worker", thread_id, "--fixture", args.fixture, *extra],
        cwd=str(PROJECT_ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    print(f"  worker pid: {proc.pid}")

    deadline = time.time() + (600 if args.real else 90)
    killed = False
    while time.time() < deadline:
        if count_checkpoints(thread_id) >= 2:
            os.kill(proc.pid, signal.SIGKILL)   # no cleanup, no handlers, no flush
            killed = True
            break
        if proc.poll() is not None:
            break
        time.sleep(0.05)

    out, _ = proc.communicate(timeout=30)
    for line in (out or "").splitlines()[:6]:
        print(f"  {line}")
    if not killed:
        print("  !! worker completed before it could be killed — nothing to resume")
        return 1
    print(f"  SIGKILL delivered to pid {proc.pid}; exit code {proc.returncode} "
          f"(-9 = killed, not a clean exit)")

    # --- 2. read what survived, from a fresh connection to the file -----------
    print("\n" + "-" * 80)
    print("[2] READ THE SURVIVING CHECKPOINT STRAIGHT OUT OF SQLITE")
    print("-" * 80)
    n = count_checkpoints(thread_id)
    size = CHECKPOINTS.stat().st_size if CHECKPOINTS.exists() else 0
    print(f"  checkpoints on disk for this thread: {n}")
    print(f"  {CHECKPOINTS.name}: {size:,} bytes")
    if n == 0:
        print("  !! no checkpoint survived — persistence is NOT proven")
        return 1

    # --- 3. resume in a genuinely different process --------------------------
    print("\n" + "-" * 80)
    print("[3] RESUME IN A FRESH PROCESS (new PID, nothing shared but the file)")
    print("-" * 80)
    res = subprocess.run(
        [py, here, "--resume", thread_id, *extra],
        cwd=str(PROJECT_ROOT), capture_output=True, text=True, timeout=900,
    )
    print(res.stdout.rstrip() or res.stderr[-1500:])

    ok = res.returncode == 0 and "resumed and completed" in res.stdout
    print("\n" + "=" * 80)
    print(f"  [{'PASS' if ok else 'FAIL'}] worker killed with SIGKILL mid-review")
    print(f"  [{'PASS' if n else 'FAIL'}] checkpoint survived the kill ({n} rows in SQLite)")
    print(f"  [{'PASS' if ok else 'FAIL'}] fresh process resumed the same thread_id "
          "and completed the review")
    print("=" * 80)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
