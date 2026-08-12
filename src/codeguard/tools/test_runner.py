"""Subprocess wrapper around ``pytest --cov``.

The coverage percentage on its own is close to meaningless — 95% coverage that
misses the authorisation branch is worse than 70% that covers it. So this tool
returns the **source text of the uncovered lines**, not just their numbers.

That is deliberate: it is what lets TestCoverageAgent perform the judgment its
tool cannot, deciding whether the specific uncovered lines carry risk (auth
checks, error handling, money arithmetic) rather than reciting a percentage.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from codeguard.obs.metrics import METRICS, timed

TEST_TIMEOUT_S = 180
MAX_UNCOVERED_SNIPPETS = 25


@dataclass
class CoverageRun:
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    total_percent: float = 0.0
    tests_passed: int = 0
    tests_failed: int = 0
    files: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "pytest_coverage",
            "command": " ".join(self.command),
            "exit_code": self.exit_code,
            "total_percent_covered": round(self.total_percent, 1),
            "tests_passed": self.tests_passed,
            "tests_failed": self.tests_failed,
            "files": self.files,
            "error": self.error,
            "raw_stdout_excerpt": self.stdout[-2000:],
        }


def _uncovered_snippets(source_file: Path, missing: list[int]) -> list[dict[str, Any]]:
    """Pair each uncovered line number with its actual source text."""
    try:
        lines = source_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return [{"line": n, "code": "<unreadable>"} for n in missing[:MAX_UNCOVERED_SNIPPETS]]
    out = []
    for n in missing[:MAX_UNCOVERED_SNIPPETS]:
        if 1 <= n <= len(lines):
            out.append({"line": n, "code": lines[n - 1].strip()[:160]})
    return out


def _parse_junit(report: Path) -> tuple[int, int]:
    """Read pass/fail counts from pytest's JUnit XML.

    Scraping the terminal summary is unreliable — under ``-q`` with a coverage
    section pytest may not emit the "N passed" line at all. The JUnit report is
    machine-readable and always written.
    """
    if not report.exists():
        return 0, 0
    try:
        tree = ElementTree.parse(report)
    except ElementTree.ParseError:
        return 0, 0
    root = tree.getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    total = failed = 0
    for s in suites:
        total += int(s.get("tests", 0))
        failed += int(s.get("failures", 0)) + int(s.get("errors", 0))
        total -= int(s.get("skipped", 0))
    return max(total - failed, 0), failed


def run_pytest_coverage(
    root: Path, source_dir: str = "src", test_dir: str = "tests"
) -> CoverageRun:
    """Run the PR's own test suite under coverage, from inside ``root``."""
    src_path = root / source_dir
    tests_path = root / test_dir

    if not tests_path.exists():
        return CoverageRun(
            command=[], exit_code=-1, stdout="", stderr="",
            error=f"no {test_dir}/ directory in this PR — nothing to run",
        )

    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "coverage.json"
        junit = Path(tmp) / "junit.xml"
        cmd = [
            sys.executable, "-m", "pytest", test_dir,
            f"--cov={source_dir}",
            f"--cov-report=json:{report}",
            f"--junit-xml={junit}",
            "-q", "--no-header",
            "-p", "no:cacheprovider",
            "-p", "pytest_cov",  # explicitly re-enabled, see PYTEST_DISABLE_PLUGIN_AUTOLOAD
        ]

        # The PR's test run must not inherit plugins from the analysis
        # environment: they are irrelevant to the PR and can break the run
        # outright. arize-phoenix-client ships a pytest11 plugin that raises on
        # import under Python 3.11, which would otherwise abort every review.
        env = {**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}

        with timed() as t:
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=TEST_TIMEOUT_S,
                    cwd=str(root), check=False, env=env,
                )
                code, out, err = proc.returncode, proc.stdout, proc.stderr
            except subprocess.TimeoutExpired:
                METRICS.log_tool_call(
                    tool="run_pytest_coverage", agent=None, args_summary=str(root),
                    latency_ms=TEST_TIMEOUT_S * 1000, ok=False, error="timeout",
                )
                return CoverageRun([], -1, "", "", error="timeout")

        run = CoverageRun(cmd, code, out, err)
        run.tests_passed, run.tests_failed = _parse_junit(junit)

        if report.exists():
            try:
                data = json.loads(report.read_text(encoding="utf-8"))
                run.total_percent = float(
                    (data.get("totals") or {}).get("percent_covered", 0.0)
                )
                for fname, fdata in (data.get("files") or {}).items():
                    missing = fdata.get("missing_lines", []) or []
                    summary = fdata.get("summary", {}) or {}
                    run.files.append({
                        "file": fname,
                        "percent_covered": round(
                            float(summary.get("percent_covered", 0.0)), 1
                        ),
                        "num_statements": summary.get("num_statements", 0),
                        "missing_line_count": len(missing),
                        # The judgment payload: what is actually untested.
                        "uncovered_lines": _uncovered_snippets(root / fname, missing),
                    })
            except (json.JSONDecodeError, OSError, ValueError) as e:
                run.error = f"could not parse coverage report: {e}"
        elif code == 5:
            run.error = "pytest collected no tests"
        elif run.error is None and code not in (0, 1):
            run.error = f"pytest exited {code}: {err.strip()[:300] or out.strip()[-300:]}"

    METRICS.log_tool_call(
        tool="run_pytest_coverage", agent=None, args_summary=str(root),
        latency_ms=t["ms"], ok=run.error is None,
        result_summary=f"{run.total_percent:.0f}% covered, "
                       f"{run.tests_passed}p/{run.tests_failed}f",
        error=run.error,
    )
    return run
