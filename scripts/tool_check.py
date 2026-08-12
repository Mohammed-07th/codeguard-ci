#!/usr/bin/env python
"""Phase-2 verification: exercise every tool against the real fixtures.

No LLM is involved. This proves the tool layer is real — genuine subprocesses,
genuine parsed output — and that the two access controls actually refuse things:
the path sandbox and the per-agent allow-list.

    .venv/bin/python scripts/tool_check.py
"""

from __future__ import annotations

import json
import sys

from codeguard.config import get_settings
from codeguard.tools import repo_tools
from codeguard.tools.registry import (
    AGENT_TOOLS,
    ToolAccessDenied,
    dispatch,
    roster,
    run_bandit_impl,
    run_pytest_coverage_impl,
    run_ruff_impl,
    scan_secrets_impl,
)
from codeguard.tools.sandbox import SandboxViolation, review_root

RAW_SECRETS = [
    "AKIA3XQ7MZPLK2VNWR4T",
    "Hunter2!Settlement",
    "ahmed.alqahtani@example-bank.com.sa",
]

results: list[tuple[str, bool]] = []


def check(label: str, passed: bool, detail: str = "") -> None:
    results.append((label, passed))
    print(f"  [{'PASS' if passed else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))


def hr(title: str) -> None:
    print("\n" + "=" * 84)
    print(title)
    print("=" * 84)


def main() -> int:
    s = get_settings()

    # ---------------------------------------------------------------- fixtures
    hr("FIXTURE LOADING")
    prs = {}
    for name in ("pr_clean", "pr_with_secret", "pr_injection", "pr_critical"):
        pr = repo_tools.load_pull_request(s.fixtures_dir / name)
        prs[name] = pr
        print(f"  {name:<16} {pr.pr_id:<9} {len(pr.changed_files)} files  "
              f"diff={len(pr.diff)} chars  '{pr.title[:44]}'")
    check("all four fixtures load", len(prs) == 4)

    # ------------------------------------------------------- secret scanner
    hr("TOOL 1 — secret_scanner (regex + Shannon entropy) on pr_with_secret")
    pr = prs["pr_with_secret"]
    with review_root(pr.root), repo_tools.pr_context(pr):
        scan = scan_secrets_impl(".")
    print(f"  scanned {len(scan['scanned_files'])} files, {scan['hit_count']} hits\n")
    print(f"  {'rule':<22}{'file':<24}{'line':>5}  {'ent':>5}  {'test?':>6}  masked")
    print("  " + "-" * 80)
    for h in scan["hits"]:
        print(f"  {h['rule_id']:<22}{h['file']:<24}{h['line']:>5}  {h['entropy']:>5}  "
              f"{str(h['in_test_path']):>6}  {h['masked_match']}")

    rules = {h["rule_id"] for h in scan["hits"]}
    check("AWS access key detected", "AWS_ACCESS_KEY" in rules)
    check("hardcoded password detected", "HARDCODED_PASSWORD" in rules)
    check("customer email (PII) detected", "EMAIL" in rules)
    fp = [h for h in scan["hits"] if h["in_test_path"]]
    check("false-positive candidate flagged in tests/", len(fp) > 0,
          f"{len(fp)} hit(s) in a test path, left for the agent to triage")

    # The masking guarantee that makes the Deliverable-4 grep proof possible.
    blob = json.dumps(scan)
    leaked = [sec for sec in RAW_SECRETS if sec in blob]
    check("NO raw secret appears in scanner output", not leaked,
          "masked at detection" if not leaked else f"LEAKED: {leaked}")

    # ------------------------------------------------------------- bandit
    hr("TOOL 2 — bandit (real subprocess) on pr_critical")
    pr = prs["pr_critical"]
    with review_root(pr.root), repo_tools.pr_context(pr):
        band = run_bandit_impl(".")
    print(f"  command : {band['command']}")
    print(f"  exit    : {band['exit_code']}   findings: {band['finding_count']}\n")
    for f in band["findings"]:
        print(f"  {f['rule_id']:<7}{f['severity']:<9}{f['confidence']:<9}"
              f"{f['file']}:{f['line']}  {f['message'][:52]}")
    check("bandit executed and parsed", band["error"] is None)
    check("bandit found the critical issues", band["finding_count"] >= 3,
          f"{band['finding_count']} issues")
    high = [f for f in band["findings"] if f["severity"] == "high"]
    check("at least one HIGH severity issue", len(high) >= 1, f"{len(high)} high")

    # --------------------------------------------------------------- ruff
    hr("TOOL 3 — ruff (real subprocess)")
    ruff_codes: dict[str, list[str]] = {}
    for name in ("pr_clean", "pr_with_secret"):
        pr = prs[name]
        with review_root(pr.root), repo_tools.pr_context(pr):
            r = run_ruff_impl(".")
        codes = [f["rule_id"] for f in r["findings"]]
        ruff_codes[name] = codes
        print(f"  {name:<16} exit={r['exit_code']}  violations={r['finding_count']}  {codes[:8]}")
        for f in r["findings"]:
            print(f"      {f['rule_id']:<7}{f['file']}:{f['line']}  {f['message'][:56]}")
    check("ruff reports the clean fixture clean", len(ruff_codes["pr_clean"]) == 0,
          "no cry-wolf on benign code")
    # StyleAgent's judgment layer needs a genuine severity contrast to rank:
    # a bare except swallowing errors in a money path vs. a long line.
    check("E722 (bare except in the fee path) present", "E722" in ruff_codes["pr_with_secret"])
    check("E501 (long line — noise) present", "E501" in ruff_codes["pr_with_secret"])
    check("StyleAgent has a severity contrast to judge",
          {"E722", "E501"} <= set(ruff_codes["pr_with_secret"]),
          "same linter, wildly different real-world risk")

    # ------------------------------------------------------- pytest --cov
    hr("TOOL 4 — pytest --cov (real subprocess)")
    for name in ("pr_clean", "pr_with_secret"):
        pr = prs[name]
        with review_root(pr.root), repo_tools.pr_context(pr):
            cov = run_pytest_coverage_impl()
        print(f"\n  {name}: {cov['total_percent_covered']}% covered, "
              f"{cov['tests_passed']} passed / {cov['tests_failed']} failed  "
              f"(exit {cov['exit_code']})")
        if cov["error"]:
            print(f"    error: {cov['error']}")
        for f in cov["files"]:
            print(f"    {f['file']:<22}{f['percent_covered']:>6}%  "
                  f"{f['missing_line_count']} uncovered")
            for u in f["uncovered_lines"][:4]:
                print(f"        L{u['line']:<4} {u['code'][:64]}")

        if name == "pr_clean":
            check("clean fixture: tests pass", cov["tests_passed"] > 0 and cov["tests_failed"] == 0)
            check("clean fixture: high coverage", cov["total_percent_covered"] >= 95.0,
                  f"{cov['total_percent_covered']}%")
        else:
            uncovered_code = " ".join(
                u["code"] for f in cov["files"] for u in f["uncovered_lines"]
            )
            check("uncovered SOURCE TEXT returned, not just line numbers",
                  bool(uncovered_code.strip()))
            check("the untested authorisation check is visible to the agent",
                  "role" in uncovered_code or "mfa" in uncovered_code,
                  "TestCoverageAgent can judge risk, not just percentage")

    # ------------------------------------------- pr_critical has no tests
    pr = prs["pr_critical"]
    with review_root(pr.root), repo_tools.pr_context(pr):
        cov = run_pytest_coverage_impl()
    check("missing tests/ degrades gracefully, no crash",
          cov["error"] is not None and "no tests" in cov["error"].lower(),
          repr(cov["error"]))

    # --------------------------------------------------------- repo tools
    hr("TOOLS 5-7 — repo tools (read_file / list_changed_files / get_diff)")
    pr = prs["pr_with_secret"]
    with review_root(pr.root), repo_tools.pr_context(pr):
        rf = repo_tools.read_file("src/settlement.py")
        lc = repo_tools.list_changed_files()
        gd = repo_tools.get_diff()
        print(f"  read_file          : {rf['line_count']} lines, truncated={rf['truncated']}")
        print(f"  list_changed_files : {lc['count']} files")
        print(f"  get_diff           : {len(gd['diff'])} chars, truncated={gd['truncated']}")
        check("read_file returns numbered content", "1 |" in rf["content"])
        check("list_changed_files matches the fixture", lc["count"] == len(pr.changed_files))
        check("get_diff produces a unified diff", "+++ b/" in gd["diff"])

        # ------------------------------------------------ sandbox refusal
        hr("SECURITY CONTROL 1 — path sandbox refuses traversal")
        for attempt in ("../../.env", "/etc/passwd", "../../../../etc/hosts"):
            try:
                repo_tools.read_file(attempt)
                check(f"refuse {attempt!r}", False, "NOT REFUSED — sandbox is broken")
            except SandboxViolation as e:
                check(f"refuse {attempt!r}", True, str(e)[:56] + "...")

    # ------------------------------------------------------- RBAC refusal
    hr("SECURITY CONTROL 2 — per-agent tool allow-list (RBAC)")
    print(f"  {'agent':<26}{'n':>3}  tools")
    print("  " + "-" * 78)
    for row in roster():
        print(f"  {row['agent']:<26}{row['tool_count']:>3}  {', '.join(row['tools'])}")
    print()

    pr = prs["pr_with_secret"]
    with review_root(pr.root), repo_tools.pr_context(pr):
        out = dispatch("SecurityAgent", "scan_secrets", {"path": "src/config.py"})
        check("allowed call succeeds (SecurityAgent -> scan_secrets)",
              json.loads(out)["hit_count"] > 0)

        for agent, tool in (
            ("StyleAgent", "scan_secrets"),          # style must not read secrets
            ("CoordinatorAgent", "run_bandit"),      # coordinator plans, does not scan
            ("ReviewSynthesizerAgent", "read_file"),  # synthesizer reasons over state only
        ):
            try:
                dispatch(agent, tool, {"path": "."})
                check(f"deny {agent} -> {tool}", False, "NOT DENIED — RBAC is decorative")
            except ToolAccessDenied:
                check(f"deny {agent} -> {tool}", True, "ToolAccessDenied raised")

    # ------------------------------------------------------------ summary
    hr("PHASE 2 SUMMARY")
    passed = sum(1 for _, p in results if p)
    for label, p in results:
        if not p:
            print(f"  FAILED: {label}")
    print(f"\n  {passed}/{len(results)} checks passed")
    print("=" * 84)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
