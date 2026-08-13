"""Runtime dependency report — what is actually loaded, and at what version.

Served from ``/health`` and printed by the evidence notebook. Two reasons it
exists, both practical:

* **Operations.** "The review passed" is not reproducible without knowing which
  analysers and which orchestration version produced it. A health endpoint that
  reports the versions it is running is standard practice, and it is the first
  thing you want when a deployed reviewer starts disagreeing with a local one.
* **Provenance.** Several dependencies are used through an entry point rather
  than an ``import`` — ``uvicorn`` is the container command, ``pytest-cov`` is a
  plugin flag, ``nbconvert`` and ``ipykernel`` execute the notebook. Importing
  them here to report their versions makes the dependency set verifiable at
  runtime rather than taken on trust from ``requirements.txt``.

Note the gap between distribution names and import names: the distribution
``langgraph-checkpoint-sqlite`` installs the module ``langgraph.checkpoint.sqlite``,
and ``openinference-instrumentation-langchain`` installs
``openinference.instrumentation.langchain``. Both are listed with the module
path actually imported, so the mapping is explicit.
"""

from __future__ import annotations

import importlib
import importlib.metadata as md
import sys
from typing import Any

# (distribution name, module actually imported, what it does here)
DEPENDENCIES: list[tuple[str, str, str]] = [
    # --- orchestration ---
    ("langgraph", "langgraph.graph", "StateGraph, nodes, conditional edges"),
    ("langgraph-checkpoint-sqlite", "langgraph.checkpoint.sqlite",
     "SqliteSaver — checkpoints that survive a restart"),
    # --- model access ---
    ("langchain-core", "langchain_core.messages", "message types, tool binding"),
    ("langchain-openai", "langchain_openai", "ChatOpenAI against OpenRouter"),
    ("openai", "openai", "provider error types the retry layer matches on"),
    # --- contracts and resilience ---
    ("pydantic", "pydantic", "Finding/Verdict schemas, agent output validation"),
    ("pydantic-settings", "pydantic_settings", "settings loaded from .env"),
    ("python-dotenv", "dotenv", "loads .env inside the container"),
    ("tenacity", "tenacity", "exponential backoff on transient faults"),
    # --- the real analysers the agents shell out to ---
    ("bandit", "bandit", "security static analysis"),
    ("ruff", "ruff", "style/lint analysis"),
    ("pytest", "pytest", "runs the PR's own test suite"),
    ("pytest-cov", "pytest_cov", "coverage plugin, enabled per subprocess run"),
    ("coverage", "coverage", "coverage measurement behind pytest-cov"),
    # --- observability ---
    ("opentelemetry-sdk", "opentelemetry.sdk.trace", "TracerProvider, span processors"),
    ("opentelemetry-exporter-otlp", "opentelemetry.exporter.otlp.proto.http.trace_exporter",
     "OTLP export to the Phoenix collector"),
    ("openinference-instrumentation-langchain", "openinference.instrumentation.langchain",
     "LLM spans from LangChain callbacks"),
    # --- serving and storage ---
    ("fastapi", "fastapi", "webhook, review status, HITL resume"),
    ("uvicorn", "uvicorn", "ASGI server — the container command"),
    ("httpx", "httpx", "HTTP client used by the resilience tests"),
    ("boto3", "boto3", "S3-compatible report upload to MinIO"),
    # --- evidence ---
    ("nbformat", "nbformat", "builds the evidence notebook"),
    ("nbconvert", "nbconvert", "executes it and writes outputs back"),
    ("ipykernel", "ipykernel", "the kernel the notebook executes against"),
    ("rich", "rich", "renders the metrics summary tables"),
]


def dependency_report(verbose: bool = False) -> dict[str, Any]:
    """Import every declared dependency and report its version.

    Returns a summary plus, when ``verbose``, the per-package detail. Import
    failures are reported rather than raised: a missing optional dependency
    should surface in ``/health`` as a degraded component, not take the service
    down at request time.
    """
    packages: list[dict[str, Any]] = []
    for dist, module, purpose in DEPENDENCIES:
        entry: dict[str, Any] = {"distribution": dist, "module": module, "purpose": purpose}
        try:
            importlib.import_module(module)
            entry["imported"] = True
        except Exception as exc:  # noqa: BLE001 - reported, never fatal
            entry["imported"] = False
            entry["error"] = f"{type(exc).__name__}: {exc}"
        try:
            entry["version"] = md.version(dist)
        except md.PackageNotFoundError:
            entry["version"] = "unknown"
        packages.append(entry)

    missing = [p["distribution"] for p in packages if not p["imported"]]
    report: dict[str, Any] = {
        "python": sys.version.split()[0],
        "declared": len(packages),
        "importable": sum(1 for p in packages if p["imported"]),
        "missing": missing,
        "healthy": not missing,
    }
    if verbose:
        report["packages"] = packages
    return report


def print_report() -> dict[str, Any]:
    """Human-readable dependency table, used by the evidence notebook."""
    report = dependency_report(verbose=True)
    print(f"  python {report['python']} — {report['importable']}/{report['declared']} "
          f"declared dependencies imported successfully")
    print(f"  {'distribution':<42}{'version':<12}module actually imported")
    print("  " + "-" * 100)
    for p in report["packages"]:
        mark = "" if p["imported"] else "  <- IMPORT FAILED"
        print(f"  {p['distribution']:<42}{p['version']:<12}{p['module']}{mark}")
    if report["missing"]:
        print(f"\n  MISSING: {report['missing']}")
    return report
