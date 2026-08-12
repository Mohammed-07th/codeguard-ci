#!/usr/bin/env python
"""Qualify free OpenRouter models against what CodeGuard actually needs.

Deliverable 1 requires real function calling and Deliverable 3 requires Pydantic
structured output. Free models vary enormously on both, so model selection is
settled by measurement rather than by reputation.

Each candidate is scored on three capabilities:
  1. plain chat completion
  2. tool calling  — does it emit a well-formed tool_call for a bound tool?
  3. structured output — does it return a schema-valid Pydantic object?

    .venv/bin/python scripts/qualify_models.py
"""

from __future__ import annotations

import sys

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from codeguard.config import get_settings
from codeguard.llm.router import LLMRouter

CANDIDATES = [
    "openai/gpt-oss-20b:free",
    "nvidia/nemotron-3-super-120b-a12b:free",
    "google/gemma-4-31b-it:free",
    "nvidia/nemotron-3-nano-30b-a3b:free",
    "inclusionai/ling-3.0-tiny:free",
]


@tool
def scan_file_for_secrets(path: str) -> str:
    """Scan a source file for hardcoded credentials. Returns findings as text."""
    return f"scanned {path}"


class TriageResult(BaseModel):
    """Schema mirroring the shape the real agents must produce."""

    severity: str = Field(description="one of: info, low, medium, high, critical")
    is_false_positive: bool = Field(description="true if this is a test fixture, not a real secret")
    reason: str = Field(description="one sentence")


def check(router: LLMRouter, model: str) -> dict:
    res = {"model": model, "chat": False, "tools": False, "structured": False, "notes": []}

    # --- 1. plain chat ---
    try:
        r = router._build(model).invoke([HumanMessage(content="Reply with the single word: ok")])
        res["chat"] = bool((r.content or "").strip())
    except Exception as e:
        res["notes"].append(f"chat: {type(e).__name__}: {str(e)[:90]}")
        return res  # no point testing further

    # --- 2. tool calling ---
    try:
        bound = router._build(model).bind_tools([scan_file_for_secrets])
        r = bound.invoke([
            SystemMessage(content="You must use the provided tool. Do not answer directly."),
            HumanMessage(content="Scan the file src/settings.py for hardcoded secrets."),
        ])
        calls = getattr(r, "tool_calls", []) or []
        res["tools"] = bool(calls) and calls[0].get("name") == "scan_file_for_secrets"
        if not calls:
            res["notes"].append("tools: returned prose instead of a tool_call")
    except Exception as e:
        res["notes"].append(f"tools: {type(e).__name__}: {str(e)[:90]}")

    # --- 3. structured output ---
    try:
        s = router._build(model).with_structured_output(TriageResult)
        r = s.invoke([
            HumanMessage(
                content="A scanner flagged password='test123' inside tests/conftest.py. Triage it."
            )
        ])
        res["structured"] = isinstance(r, TriageResult)
    except Exception as e:
        res["notes"].append(f"structured: {type(e).__name__}: {str(e)[:90]}")

    return res


def main() -> int:
    get_settings().require_api_key()
    router = LLMRouter()

    print("=" * 92)
    print("FREE MODEL QUALIFICATION — chat / tool-calling / structured-output")
    print("=" * 92)
    print(f"{'model':<44} {'chat':>6} {'tools':>7} {'struct':>7}  notes")
    print("-" * 92)

    results = []
    for m in CANDIDATES:
        r = check(router, m)
        results.append(r)
        print(
            f"{m:<44} {'OK' if r['chat'] else '--':>6} "
            f"{'OK' if r['tools'] else '--':>7} {'OK' if r['structured'] else '--':>7}"
            f"  {'; '.join(r['notes'])[:110]}"
        )

    print("-" * 92)
    fully = [r["model"] for r in results if r["chat"] and r["tools"] and r["structured"]]
    print(f"\nFully capable (all three): {len(fully)}")
    for m in fully:
        print(f"   {m}")

    if len(fully) >= 2:
        print(f"\nRECOMMENDED primary : {fully[0]}")
        print(f"RECOMMENDED fallback: {fully[1]}   (must differ from primary to prove failover)")
    elif len(fully) == 1:
        print(f"\nOnly one fully-capable free model: {fully[0]} — fallback needs a second source.")
    else:
        print("\nNo free model passed all three checks.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
