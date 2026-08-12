#!/usr/bin/env python
"""Measure the input guardrail against an adversarial set. No LLM involved.

Reports block rate on attacks AND false-positive rate on benign controls. Both
matter: a guardrail that blocks everything scores 100% on the first and is
useless, so the second number is what makes the first meaningful.

    .venv/bin/python scripts/adversarial_check.py
"""

from __future__ import annotations

import json
import sys

from codeguard.config import get_settings
from codeguard.guardrails.injection import detect_injection


def main() -> int:
    path = get_settings().fixtures_dir / "adversarial" / "injections.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    variants = data["variants"]

    print("=" * 100)
    print("ADVERSARIAL INJECTION SET — input guardrail block rate")
    print("=" * 100)
    print(f"{'id':<5}{'technique':<28}{'expect':<8}{'result':<9}{'ok':<5}rules matched")
    print("-" * 100)

    attacks_total = attacks_blocked = 0
    benign_total = benign_blocked = 0
    missed: list[dict] = []
    false_positives: list[dict] = []

    for v in variants:
        verdict = detect_injection({"pr_description": v["text"]})
        blocked = verdict.blocked
        expected = v["expect_block"]
        ok = blocked == expected

        if expected:
            attacks_total += 1
            attacks_blocked += int(blocked)
            if not blocked:
                missed.append(v)
        else:
            benign_total += 1
            benign_blocked += int(blocked)
            if blocked:
                false_positives.append({**v, "rules": verdict.rule_ids})

        print(f"{v['id']:<5}{v['technique']:<28}"
              f"{'BLOCK' if expected else 'allow':<8}"
              f"{'BLOCKED' if blocked else 'allowed':<9}"
              f"{'ok' if ok else 'MISS':<5}"
              f"{','.join(verdict.rule_ids)[:44]}")

    print("-" * 100)
    block_rate = attacks_blocked / attacks_total if attacks_total else 0.0
    fp_rate = benign_blocked / benign_total if benign_total else 0.0
    print(f"\n  ATTACK BLOCK RATE   : {attacks_blocked}/{attacks_total}  ({block_rate:.0%})")
    print(f"  FALSE POSITIVE RATE : {benign_blocked}/{benign_total}  ({fp_rate:.0%})"
          "   <- benign PRs wrongly blocked")

    if missed:
        print("\n  HONEST FAILURES — attacks that got through:")
        for m in missed:
            print(f"    {m['id']} ({m['technique']}): {m.get('note', '')}")
            print(f"       text: {m['text'][:88]}...")
    else:
        print("\n  No attack in this set evaded the guardrail.")

    if false_positives:
        print("\n  FALSE POSITIVES — benign PRs wrongly blocked:")
        for f in false_positives:
            print(f"    {f['id']}: matched {f['rules']}")
            print(f"       text: {f['text'][:88]}...")

    print("\n" + "=" * 100)
    print("  Note: this is pattern-based detection. It is a filter, not a proof.")
    print("  The measured numbers above are the honest claim; completeness is not claimed.")
    print("=" * 100)
    return 0


if __name__ == "__main__":
    sys.exit(main())
