"""Subprocess wrappers around the real static analysers: ``bandit`` and ``ruff``.

These are genuinely invoked binaries whose JSON output is parsed — not
reimplementations and not hardcoded results. Deliverable 1 turns on that being
true, so the raw stdout is preserved on every result and logged alongside the
agent's interpretation of it.

Both analysers are run with configuration isolation (``--isolated`` for ruff, an
explicit rule selection for both) so a fixture cannot influence its own review by
shipping a permissive config file — a small but real supply-chain concern.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import bandit as bandit_pkg
import ruff as ruff_pkg

from codeguard.obs.metrics import METRICS, timed


def analyser_versions() -> dict[str, str]:
    """Exact versions of the analysers backing a review.

    Recorded on every report because a finding is only reproducible against the
    tool that produced it: ruff changes rule behaviour between releases and
    bandit adds checks, so "clean under bandit" is meaningless without saying
    which bandit. ``ruff.find_ruff_bin()`` also pins the resolved binary rather
    than whatever happens to be first on PATH.
    """
    try:
        ruff_bin = ruff_pkg.find_ruff_bin()
    except Exception:  # noqa: BLE001
        ruff_bin = "ruff (not resolved)"
    return {
        "bandit": getattr(bandit_pkg, "__version__", "unknown"),
        "ruff_binary": str(ruff_bin),
        "python": sys.version.split()[0],
    }


# Style rules. E501 (long line) and E722 (bare except) are both included on
# purpose: StyleAgent must visibly rank them differently, which is the whole
# point of having an agent rather than piping the linter straight to a verdict.
RUFF_RULES = "E,W,F,B,SIM,C90"

TOOL_TIMEOUT_S = 120


@dataclass
class ToolRun:
    """Raw evidence of one analyser invocation."""

    tool: str
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    parsed: Any = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "command": " ".join(self.command),
            "exit_code": self.exit_code,
            "finding_count": len(self.findings),
            "findings": self.findings,
            "error": self.error,
            "analyser_versions": analyser_versions(),
            # Truncated: the agent needs to see real output, not a novel.
            "raw_stdout_excerpt": self.stdout[:2000],
            "raw_stderr_excerpt": self.stderr[:600],
        }


def _run(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=TOOL_TIMEOUT_S,
        cwd=str(cwd) if cwd else None,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def run_bandit(target: Path, root: Path | None = None) -> ToolRun:
    """Run bandit (security static analysis) over a file or directory."""
    cmd = [sys.executable, "-m", "bandit", "-f", "json", "-q"]
    if target.is_dir():
        cmd += ["-r"]
    cmd += [str(target)]

    with timed() as t:
        try:
            code, out, err = _run(cmd)
        except subprocess.TimeoutExpired:
            METRICS.log_tool_call(
                tool="run_bandit", agent=None, args_summary=str(target),
                latency_ms=TOOL_TIMEOUT_S * 1000, ok=False, error="timeout",
            )
            return ToolRun("bandit", cmd, -1, "", "", error="timeout")

    run = ToolRun("bandit", cmd, code, out, err)
    try:
        data = json.loads(out) if out.strip() else {}
        run.parsed = data
        for r in data.get("results", []):
            path = r.get("filename", "")
            if root:
                try:
                    path = str(Path(path).resolve().relative_to(root))
                except (ValueError, OSError):
                    pass
            run.findings.append({
                "rule_id": r.get("test_id"),
                "rule_name": r.get("test_name"),
                "file": path,
                "line": r.get("line_number"),
                "severity": (r.get("issue_severity") or "").lower(),
                "confidence": (r.get("issue_confidence") or "").lower(),
                "message": r.get("issue_text", ""),
                "code_excerpt": (r.get("code") or "").strip()[:300],
                "cwe": (r.get("issue_cwe") or {}).get("id"),
            })
    except json.JSONDecodeError as e:
        run.error = f"could not parse bandit JSON: {e}"

    METRICS.log_tool_call(
        tool="run_bandit", agent=None, args_summary=str(target),
        latency_ms=t["ms"], ok=run.error is None,
        result_summary=f"{len(run.findings)} issues", error=run.error,
    )
    return run


def run_ruff(target: Path, root: Path | None = None) -> ToolRun:
    """Run ruff (style/lint) over a file or directory."""
    cmd = [
        sys.executable, "-m", "ruff", "check",
        "--output-format", "json",
        "--isolated",          # ignore any config the PR might ship
        "--no-cache",
        "--select", RUFF_RULES,
        str(target),
    ]

    with timed() as t:
        try:
            code, out, err = _run(cmd)
        except subprocess.TimeoutExpired:
            METRICS.log_tool_call(
                tool="run_ruff", agent=None, args_summary=str(target),
                latency_ms=TOOL_TIMEOUT_S * 1000, ok=False, error="timeout",
            )
            return ToolRun("ruff", cmd, -1, "", "", error="timeout")

    run = ToolRun("ruff", cmd, code, out, err)
    try:
        data = json.loads(out) if out.strip() else []
        run.parsed = data
        for r in data:
            path = r.get("filename", "")
            if root:
                try:
                    path = str(Path(path).resolve().relative_to(root))
                except (ValueError, OSError):
                    pass
            run.findings.append({
                "rule_id": r.get("code"),
                "file": path,
                "line": (r.get("location") or {}).get("row"),
                "column": (r.get("location") or {}).get("column"),
                "message": r.get("message", ""),
                "fix_available": bool(r.get("fix")),
            })
    except json.JSONDecodeError as e:
        run.error = f"could not parse ruff JSON: {e}"

    METRICS.log_tool_call(
        tool="run_ruff", agent=None, args_summary=str(target),
        latency_ms=t["ms"], ok=run.error is None,
        result_summary=f"{len(run.findings)} violations", error=run.error,
    )
    return run
