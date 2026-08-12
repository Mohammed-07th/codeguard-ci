#!/usr/bin/env python
"""Phase-1 smoke test: prove the OpenRouter router, model routing and cost metering are real.

Makes genuine API calls. Every number printed is measured from the provider
response — token counts come back from OpenRouter, cost is those counts through
the price table, latency is a monotonic clock.

    .venv/bin/python scripts/smoke_llm.py
"""

from __future__ import annotations

import sys

from langchain_core.messages import HumanMessage, SystemMessage

from codeguard.config import TaskComplexity, get_settings
from codeguard.llm.router import get_router
from codeguard.obs.metrics import METRICS, print_summary, run_context


def main() -> int:
    settings = get_settings()
    router = get_router()

    print("=" * 78)
    print("PHASE 1 SMOKE TEST — OpenRouter router, model routing, cost metering")
    print("=" * 78)
    print(f"base_url        : {settings.openrouter_base_url}")
    print(f"primary model   : {settings.primary_model}")
    print(f"fallback model  : {settings.fallback_model}")
    print(f"synthesis model : {settings.synthesis_model}")
    print(f"cost cap        : ${settings.cost_cap_usd}")
    print()

    with run_context(thread_id="smoke-phase1", pr_id="SMOKE"):
        # --- 1. Cheap route: classification-grade work -> primary model --------
        print("-" * 78)
        print("[1] TaskComplexity.CHEAP  -> pick_model() ->", router.pick_model(TaskComplexity.CHEAP))
        r1 = router.invoke(
            [
                SystemMessage(content="You are a terse code-review classifier."),
                HumanMessage(
                    content="Classify this change in one word (security|style|docs): "
                    "'removed hardcoded AWS access key from settings.py'"
                ),
            ],
            tag="smoke.classify",
            complexity=TaskComplexity.CHEAP,
        )
        print(f"    response    : {r1.message.content.strip()[:120]}")
        print(f"    COST ROW    : {r1.cost_row()}")
        print()

        # --- 2. Complex route: synthesis-grade work -> stronger model ----------
        print("-" * 78)
        print("[2] TaskComplexity.COMPLEX -> pick_model() ->", router.pick_model(TaskComplexity.COMPLEX))
        r2 = router.invoke(
            [
                SystemMessage(content="You are a senior reviewer resolving disagreements."),
                HumanMessage(
                    content="SecurityAgent says BLOCK (hardcoded key in prod config). "
                    "StyleAgent says APPROVE (formatting is clean). "
                    "Give the final verdict and one sentence of rationale."
                ),
            ],
            tag="smoke.synthesize",
            complexity=TaskComplexity.COMPLEX,
        )
        print(f"    response    : {r2.message.content.strip()[:200]}")
        print(f"    COST ROW    : {r2.cost_row()}")
        print()

    # --- routing actually changed the model, not just the label ---------------
    print("-" * 78)
    print("ROUTING CHECK")
    print(f"  cheap   call used : {r1.actual_model}")
    print(f"  complex call used : {r2.actual_model}")
    routed = (r1.actual_model or "") != (r2.actual_model or "")
    print(f"  -> different model for different complexity: {routed}")
    print()

    rows = METRICS.read(thread_id="smoke-phase1")
    summary = print_summary(rows, title="Phase 1 smoke — measured metrics")

    print()
    ok = True
    checks = [
        ("2 LLM calls recorded", summary["llm_calls"] == 2),
        ("no LLM failures", summary["llm_failures"] == 0),
        ("tokens measured (>0)", summary["total_input_tokens"] > 0),
        ("all models priced", summary["unpriced_calls"] == 0),
        ("complexity changed the model", routed),
    ]
    for label, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {label}")
        ok = ok and passed

    print()
    print(f"TOTAL REAL COST THIS RUN    : ${summary['total_cost_usd']:.6f}  (free-tier models)")
    print(f"SHADOW COST (if gpt-4o-mini): ${summary['shadow_cost_usd']:.6f}  <- projection only")
    print(f"router.total_cost_usd       : ${get_router().total_cost_usd:.6f}")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
