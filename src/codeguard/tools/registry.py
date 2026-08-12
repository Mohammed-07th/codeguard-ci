"""Tool registry and the per-agent allow-list — least privilege for agents.

Every tool in the system is registered here exactly once, and every agent gets an
explicit allow-list. Enforcement is two-layered on purpose:

1. **Binding** — an agent is only ever shown the tools it is allowed to call, so
   the model cannot request what it cannot see.
2. **Dispatch** — :func:`dispatch` re-checks the allow-list before executing.
   Layer 1 alone would be defeated by a prompt-injected or confused model
   emitting a tool name it was never offered; layer 2 refuses it regardless.

That second check is what makes this RBAC rather than a naming convention, and
there is a test that proves a denied call actually raises.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from langchain_core.tools import StructuredTool

from codeguard.guardrails.redaction import redact
from codeguard.obs.metrics import METRICS, current_agent, timed
from codeguard.obs.tracing import span
from codeguard.tools import repo_tools
from codeguard.tools.sandbox import SandboxViolation, get_review_root, safe_resolve
from codeguard.tools.secret_scanner import scan_paths
from codeguard.tools.static_analysis import run_bandit as _bandit
from codeguard.tools.static_analysis import run_ruff as _ruff
from codeguard.tools.test_runner import run_pytest_coverage as _pytest_cov

SCANNABLE_SUFFIXES = {".py", ".txt", ".cfg", ".ini", ".toml", ".yaml", ".yml", ".json", ".md", ".env"}


class ToolAccessDenied(PermissionError):
    """Raised when an agent calls a tool outside its allow-list."""


# --- tool implementations (return dicts; the LLM-facing wrappers serialise) ----

def scan_secrets_impl(path: str = ".") -> dict[str, Any]:
    root = get_review_root()
    target = safe_resolve(path)
    if target.is_dir():
        files = [p for p in sorted(target.rglob("*"))
                 if p.is_file() and p.suffix in SCANNABLE_SUFFIXES]
    else:
        files = [target]
    return scan_paths(files, root=root).to_dict()


def run_bandit_impl(path: str = ".") -> dict[str, Any]:
    root = get_review_root()
    return _bandit(safe_resolve(path), root=root).to_dict()


def run_ruff_impl(path: str = ".") -> dict[str, Any]:
    root = get_review_root()
    return _ruff(safe_resolve(path), root=root).to_dict()


def run_pytest_coverage_impl() -> dict[str, Any]:
    return _pytest_cov(get_review_root()).to_dict()


# --- LLM-facing wrappers ------------------------------------------------------
# Explicit signatures and docstrings: these become the function-calling schema.

def _json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, default=str, indent=2)


def scan_secrets(path: str = ".") -> str:
    """Scan for hardcoded credentials and PII using pattern rules and Shannon entropy.

    All matches are masked before being returned; raw secret values are never
    exposed. Use this on a specific file, or on '.' for the whole PR.

    Args:
        path: File or directory relative to the repo root. Defaults to the whole PR.
    """
    return _json(scan_secrets_impl(path))


def run_bandit(path: str = ".") -> str:
    """Run the bandit security analyser and return its findings as JSON.

    Reports issue id, severity, confidence and the offending code excerpt.

    Args:
        path: File or directory relative to the repo root. Defaults to the whole PR.
    """
    return _json(run_bandit_impl(path))


def run_ruff(path: str = ".") -> str:
    """Run the ruff linter and return style violations as JSON.

    Args:
        path: File or directory relative to the repo root. Defaults to the whole PR.
    """
    return _json(run_ruff_impl(path))


def run_pytest_coverage() -> str:
    """Run the PR's test suite under coverage.

    Returns overall coverage, per-file coverage, and the SOURCE TEXT of uncovered
    lines so their risk can be judged rather than merely counted.
    """
    return _json(run_pytest_coverage_impl())


def read_file(path: str) -> str:
    """Read a file from the PR under review, with line numbers.

    Args:
        path: Path relative to the repo root, e.g. 'src/config.py'.
    """
    return _json(repo_tools.read_file(path))


def list_changed_files() -> str:
    """List every file changed by the pull request under review."""
    return _json(repo_tools.list_changed_files())


def get_diff() -> str:
    """Return the unified diff of the pull request under review."""
    return _json(repo_tools.get_diff())


@dataclass(frozen=True)
class RegisteredTool:
    name: str
    fn: Callable[..., str]
    description: str

    def as_langchain(self) -> StructuredTool:
        return StructuredTool.from_function(func=self.fn, name=self.name)


TOOLS: dict[str, RegisteredTool] = {
    t.name: t
    for t in (
        RegisteredTool("scan_secrets", scan_secrets, "regex + entropy credential scanner"),
        RegisteredTool("run_bandit", run_bandit, "bandit security static analysis"),
        RegisteredTool("run_ruff", run_ruff, "ruff style/lint analysis"),
        RegisteredTool("run_pytest_coverage", run_pytest_coverage, "pytest --cov test runner"),
        RegisteredTool("read_file", read_file, "read a file from the PR"),
        RegisteredTool("list_changed_files", list_changed_files, "list changed files"),
        RegisteredTool("get_diff", get_diff, "unified diff of the PR"),
    )
}


# --- the allow-list: least privilege, one row per agent -----------------------
# StyleAgent cannot read secrets. CoordinatorAgent cannot run analysers — it
# plans and delegates. The synthesizer touches no tools at all: it reasons only
# over Findings that other agents already placed in shared state.
AGENT_TOOLS: dict[str, tuple[str, ...]] = {
    "CoordinatorAgent": ("list_changed_files", "get_diff"),
    "SecurityAgent": ("scan_secrets", "run_bandit", "read_file"),
    "StyleAgent": ("run_ruff", "read_file"),
    "TestCoverageAgent": ("run_pytest_coverage", "read_file"),
    "ReviewSynthesizerAgent": (),
}


def allowed_tools(agent: str) -> tuple[str, ...]:
    if agent not in AGENT_TOOLS:
        raise ToolAccessDenied(f"Unknown agent {agent!r}; it has no tool allow-list.")
    return AGENT_TOOLS[agent]


def tools_for(agent: str) -> list[StructuredTool]:
    """LangChain tool objects this agent may be bound to (enforcement layer 1)."""
    return [TOOLS[name].as_langchain() for name in allowed_tools(agent)]


def dispatch(agent: str, tool_name: str, args: dict[str, Any] | None = None) -> str:
    """Execute a tool on behalf of an agent, enforcing the allow-list (layer 2).

    Raises:
        ToolAccessDenied: if ``tool_name`` is not in this agent's allow-list.
    """
    args = args or {}
    if tool_name not in allowed_tools(agent):
        METRICS.log_tool_call(
            tool=tool_name, agent=agent, args_summary=str(args)[:160],
            latency_ms=0.0, ok=False, error="ToolAccessDenied",
        )
        raise ToolAccessDenied(
            f"{agent} is not permitted to call {tool_name!r}. "
            f"Allowed: {', '.join(allowed_tools(agent)) or '(none)'}"
        )
    if tool_name not in TOOLS:
        raise ToolAccessDenied(f"Unknown tool {tool_name!r}.")

    with current_agent(agent), span(
        f"tool.{tool_name}", kind="TOOL", **{
            "tool.name": tool_name,
            "tool.agent": agent,
            "tool.args": str(args)[:200],
        }
    ) as sp:
        with timed() as t:
            try:
                out = TOOLS[tool_name].fn(**args)
                ok, err = True, None
            except (SandboxViolation, TypeError, ValueError) as e:
                out, ok, err = _json({"error": f"{type(e).__name__}: {e}"}), False, str(e)

        # DATA-PROTECTION GUARDRAIL. Every tool result crosses into the model
        # here, so redaction belongs here rather than in each tool. Running the
        # system proved why: read_file returned source verbatim and bandit
        # quoted the password inside its own issue_text, so a per-tool guarantee
        # already had two holes in it.
        redaction = redact(out, source=f"tool:{tool_name}")
        out = redaction.text
        if redaction.triggered:
            METRICS.log_guardrail(
                guardrail="output_redaction",
                triggered=True,
                detail=f"masked {redaction.masked_count} value(s) in {tool_name} output "
                       f"before it reached the model",
                matched_pattern=",".join(redaction.rules_triggered),
                excerpt=f"agent={agent} rules={redaction.rules_triggered}",
            )

        METRICS.log_tool_call(
            tool=tool_name, agent=agent, args_summary=str(args)[:160],
            latency_ms=t["ms"], ok=ok, result_summary=f"{len(out)} chars", error=err,
        )
        try:
            sp.set_attribute("tool.ok", ok)
            sp.set_attribute("tool.output_chars", len(out))
            sp.set_attribute("tool.redacted_values", redaction.masked_count)
        except Exception:  # noqa: BLE001 - tracing must never break a review
            pass
    return out


def roster() -> list[dict[str, Any]]:
    """Agent → tool allow-list, printed in the evidence notebook."""
    return [
        {"agent": a, "tool_count": len(ts), "tools": list(ts) or ["(none — reasons over state)"]}
        for a, ts in AGENT_TOOLS.items()
    ]
