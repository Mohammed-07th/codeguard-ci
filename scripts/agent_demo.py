#!/usr/bin/env python
"""Phase-3 evidence: run SecurityAgent for real and capture its ReAct trace.

This is the Deliverable-1 and Deliverable-3 evidence in one run:

* the full **Thought -> Action -> Observation** trace, with real function calls
* the **raw tool output** and the **agent's judgment** side by side, so the layer
  the agent adds on top of the scanner is visible rather than asserted
* the **false-positive triage**: the planted `TEST_DB_PASSWORD` in
  tests/conftest.py, which the tools flag and the agent must downgrade

    .venv/bin/python scripts/agent_demo.py [fixture_name]
"""

from __future__ import annotations

import json
import sys
import time

from codeguard.agents.security_agent import SecurityAgent
from codeguard.config import get_settings
from codeguard.guardrails.redaction import assert_clean
from codeguard.obs.metrics import METRICS, PROMPTS, print_summary, run_context
from codeguard.tools import repo_tools
from codeguard.tools.registry import allowed_tools
from codeguard.tools.sandbox import review_root


def main() -> int:
    fixture = sys.argv[1] if len(sys.argv) > 1 else "pr_with_secret"
    settings = get_settings()
    pr = repo_tools.load_pull_request(settings.fixtures_dir / fixture)
    # Unique per run: metrics.jsonl is a cumulative record, so a fixed thread id
    # would aggregate this run with every previous one and inflate the totals.
    thread_id = f"phase3-{fixture}-{int(time.time())}"

    print("=" * 78)
    print(f"PHASE 3 — SecurityAgent (real LLM) on {fixture}")
    print("=" * 78)
    print(f"PR        : {pr.pr_id}  {pr.title}")
    print(f"files     : {', '.join(pr.changed_files)}")
    print(f"model     : {settings.primary_model}")
    print(f"tool ACL  : {', '.join(allowed_tools('SecurityAgent'))}")
    print(f"max steps : {settings.max_react_steps}")

    agent = SecurityAgent(verbose=True)
    task = (
        f"Review pull request {pr.pr_id} — '{pr.title}'.\n"
        f"Changed files: {', '.join(pr.changed_files)}\n\n"
        "Find every hardcoded credential, secret and piece of personal data, then "
        "triage each one: decide whether it is a genuine production leak or a test "
        "fixture, and write a concrete one-line fix for the genuine ones."
    )

    with run_context(thread_id=thread_id, pr_id=pr.pr_id):
        with review_root(pr.root), repo_tools.pr_context(pr):
            run = agent.run(task)

    if run.error:
        print(f"\n!! agent error: {run.error}")
        return 1

    report = run.report

    # ---- raw tool output vs. the agent's interpretation of it ---------------
    print("\n" + "=" * 78)
    print("RAW TOOL OUTPUT vs AGENT JUDGMENT — the layer the tool cannot provide")
    print("=" * 78)
    for obs in run.raw_observations:
        try:
            payload = json.loads(obs["raw_output"])
        except json.JSONDecodeError:
            continue
        if obs["tool"] == "scan_secrets":
            print(f"\n  RAW ({obs['tool']}): {payload.get('hit_count')} hits, "
                  "every one reported at full severity, no triage:")
            for h in payload.get("hits", []):
                print(f"    - {h['rule_id']:<20} {h['file']}:{h['line']}  "
                      f"hint={h['severity_hint']}  in_test_path={h['in_test_path']}")
        elif obs["tool"] == "run_bandit":
            print(f"\n  RAW ({obs['tool']}): {payload.get('finding_count')} issues")
            for f in payload.get("findings", [])[:6]:
                print(f"    - {f['rule_id']:<7}{f['severity']:<9}{f['file']}:{f['line']}")

    print(f"\n  AGENT JUDGMENT:\n    {report.judgment}")

    # ---- the findings, with triage visible ---------------------------------
    print("\n" + "=" * 78)
    print("STRUCTURED FINDINGS (the only currency agents exchange)")
    print("=" * 78)
    print(f"  {'sev':<9}{'file':<24}{'line':>5}  {'FP?':<5} message")
    print("  " + "-" * 74)
    for f in report.findings:
        print(f"  {f.severity.value:<9}{f.file:<24}{str(f.line or '-'):>5}  "
              f"{'YES' if f.is_false_positive else '':<5} {f.message[:44]}")
        if f.suggested_fix:
            print(f"      fix: {f.suggested_fix[:66]}")
        if f.triage_note:
            print(f"      triage: {f.triage_note[:66]}")

    # ---- the checks that make this evidence rather than output -------------
    print("\n" + "=" * 78)
    print("VERIFICATION")
    print("=" * 78)
    checks = []
    fps = [f for f in report.findings if f.is_false_positive]
    reals = [f for f in report.findings if not f.is_false_positive]

    checks.append(("ReAct loop executed >= 1 tool call", run.tool_calls >= 1))
    checks.append(("Thought/Action/Observation recorded", len(run.scratchpad) >= 3))
    checks.append(("agent produced schema-valid output", report is not None))
    checks.append(("agent reported real findings", len(reals) >= 1))
    checks.append((
        "TRIAGE: the tests/conftest.py hit was downgraded",
        any("conftest" in f.file for f in fps),
    ))
    checks.append((
        "triage was justified in writing",
        all(bool(f.triage_note) for f in fps) if fps else False,
    ))
    checks.append((
        "real findings carry an applicable one-line fix",
        all(bool(f.suggested_fix) for f in reals) if reals else False,
    ))
    raw_secrets = ["AKIA3XQ7MZPLK2VNWR4T", "Hunter2!Settlement",
                   "ahmed.alqahtani@example-bank.com.sa"]
    leaked_findings = assert_clean(json.dumps(report.model_dump(), default=str), raw_secrets)
    checks.append(("no raw secret leaked into any finding", not leaked_findings))

    # The Deliverable-4 grep proof: search the record of what was actually
    # transmitted to the model, not what we hoped was transmitted.
    transmitted = PROMPTS.read_text()
    leaked_prompts = assert_clean(transmitted, raw_secrets)
    checks.append((
        f"no raw secret in the {len(transmitted):,}-char transmitted prompt log",
        not leaked_prompts,
    ))
    if leaked_prompts:
        print(f"      LEAKED TO MODEL: {leaked_prompts}")

    ok = True
    for label, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {label}")
        ok = ok and passed

    print()
    print_summary(METRICS.read(thread_id=thread_id), title=f"Phase 3 — {fixture} metrics")
    print(f"\n  ReAct steps: {len(run.steps)}   LLM calls: {run.llm_calls}   "
          f"tool calls: {run.tool_calls}")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
