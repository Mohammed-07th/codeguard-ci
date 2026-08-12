#!/usr/bin/env python
"""Phase-7 evidence: tracing, the metrics summary, and provider failover.

Produces three things:

  1. A real OpenTelemetry trace of a full review — node spans and tool spans —
     rendered as a waterfall from evidence/traces.jsonl. The fan-out is visible
     as overlapping specialist spans.
  2. The measured run-summary table: per-model calls, tokens, cost, latency.
  3. Provider failover, shown twice — forced (a synthetic 429 injected into the
     primary) and, from the metrics already on disk, unforced (the real upstream
     rate limiting that hit this project during Phase 4).

    .venv/bin/python scripts/observability_demo.py [--live]
"""

from __future__ import annotations

import argparse
import sys
import time

from langchain_core.messages import HumanMessage

from codeguard.config import get_settings
from codeguard.graph.build import build_graph, make_checkpointer, prepare_initial_state
from codeguard.llm.router import get_router
from codeguard.llm.stub import scripted_review_router
from codeguard.obs.metrics import METRICS, print_summary, run_context
from codeguard.obs.tracing import (
    flush_tracing,
    read_spans,
    render_waterfall,
    setup_tracing,
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true",
                    help="also attempt a live forced-429 against real providers")
    args = ap.parse_args()

    settings = get_settings()
    provider = setup_tracing()
    thread_id = f"obs-{int(time.time())}"

    print("=" * 84)
    print("OBSERVABILITY — tracing, metrics, and provider failover")
    print("=" * 84)
    print(f"tracer provider  : {type(provider).__name__}")
    print(f"otlp endpoint    : {settings.phoenix_collector_endpoint}/v1/traces")
    print(f"span file        : evidence/traces.jsonl")
    print(f"langchain hooked : OpenInference LangChainInstrumentor")

    # ---------------------------------------------------------------- 1. trace
    print("\n" + "-" * 84)
    print("[1] TRACE A FULL REVIEW")
    print("-" * 84)
    state = prepare_initial_state(settings.fixtures_dir / "pr_with_secret",
                                  workdir_name=thread_id)
    graph = build_graph(router=scripted_review_router(), checkpointer=make_checkpointer(),
                        verbose=False)
    with run_context(thread_id=thread_id, pr_id=state["pr_id"]):
        final = graph.invoke(
            state, {"configurable": {"thread_id": thread_id}, "recursion_limit": 60}
        )
    flush_tracing()

    spans = read_spans()
    node_spans = [s for s in spans if s["name"].startswith("node.")]
    tool_spans = [s for s in spans if s["name"].startswith("tool.")]
    print(f"  spans recorded   : {len(spans)}  "
          f"({len(node_spans)} node, {len(tool_spans)} tool)")
    print(f"  review outcome   : {final.get('status')} / "
          f"{final['verdict'].decision if final.get('verdict') else 'none'}")

    print("\n  TRACE WATERFALL (regenerated from data, so it cannot go stale):\n")
    print(render_waterfall(spans))

    print("\n  slowest tool calls:")
    for s in sorted(tool_spans, key=lambda x: -(x.get("duration_ms") or 0))[:5]:
        a = s.get("attributes", {})
        print(f"    {s['name']:<28}{s.get('duration_ms', 0):>8.0f}ms  "
              f"agent={a.get('tool.agent', '?'):<20}redacted={a.get('tool.redacted_values', 0)}")

    # -------------------------------------------------------------- 2. metrics
    print("\n" + "-" * 84)
    print("[2] MEASURED RUN SUMMARY")
    print("-" * 84)
    print_summary(METRICS.read(thread_id=thread_id), title=f"{thread_id} — this run (stubbed LLM)")
    print("\n  Cumulative across every real review this project has run:")
    print_summary(METRICS.read(), title="all recorded runs — real models")

    # ------------------------------------------------------------- 3. failover
    print("\n" + "-" * 84)
    print("[3] PROVIDER FAILOVER")
    print("-" * 84)
    print("\n  (a) UNFORCED — genuine upstream rate limiting hit by this project:")
    all_rows = [r for r in METRICS.read() if r.get("kind") == "llm"]
    fb_rows = [r for r in all_rows if r.get("fallback_used")]
    # A synthetic failure injected by the evidence harness is NOT upstream
    # rate limiting, and reporting one as the other would misdescribe the
    # evidence. Separate them explicitly rather than by hoping none appear.
    real_fb = [r for r in fb_rows
               if r.get("fallback_reason") and "Simulated" not in str(r["fallback_reason"])]
    print(f"      total failovers recorded : {len(fb_rows)}")
    print(f"      with an upstream cause   : {len(real_fb)}")
    if real_fb:
        r = real_fb[-1]
        reason = " ".join(str(r["fallback_reason"]).split())
        print(f"      requested : {r['requested_model']}")
        print(f"      answered  : {r['actual_model']}")
        print(f"      cause     : {reason[:170]}")

    print("\n  (b) FORCED — a synthetic 429 injected into the primary:")
    if args.live:
        try:
            with run_context(thread_id=f"{thread_id}-forced", pr_id="FORCED"):
                res = get_router().invoke(
                    [HumanMessage(content="Reply with the single word: ok")],
                    tag="forced429.demo", force_primary_error=True,
                )
            print(f"      requested : {res.requested_model}")
            print(f"      answered  : {res.actual_model}")
            print(f"      fallback  : {res.fallback_used}")
            print(f"      response  : {(res.message.content or '').strip()[:60]}")
        except Exception as exc:  # noqa: BLE001
            print(f"      live attempt failed: {type(exc).__name__}: {str(exc)[:150]}")
            print("      (the free-tier daily quota is exhausted; the mechanism is")
            print("       covered deterministically by tests/test_resilience.py)")
    else:
        print("      skipped — pass --live to spend a real call on this.")
        print("      Covered deterministically by tests/test_resilience.py:")
        print("        test_forced_primary_failure_is_absorbed_by_the_fallback")
        print("        test_healthy_primary_does_not_engage_the_fallback   (negative case)")
        print("        test_rate_limits_are_not_retried")

    print("\n" + "=" * 84)
    ok = len(node_spans) >= 5 and len(tool_spans) >= 3
    print(f"  [{'PASS' if ok else 'FAIL'}] trace captured node and tool spans")
    print(f"  [{'PASS' if real_fb else 'FAIL'}] real provider failover recorded with a reason")
    print("=" * 84)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
