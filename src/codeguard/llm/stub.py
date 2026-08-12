"""A deterministic stand-in for :class:`~codeguard.llm.router.LLMRouter`.

Two reasons this exists, both practical:

* **Quota.** The project runs on free-tier models with real rate limits. Debugging
  a graph by re-running it fifty times against a live provider is not viable.
* **Test determinism.** Graph and routing tests must assert on exact behaviour.
  A test that depends on what a 20B model felt like saying is not a test.

The stub honours the same ``invoke()`` contract as the real router, including
tool calls and structured output, so agents cannot tell the difference. It is a
development and testing aid — every number in ``evidence/`` comes from the real
router, and the stub is never used to produce graded output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from langchain_core.messages import AIMessage
from pydantic import BaseModel

from codeguard.config import TaskComplexity
from codeguard.llm.router import LLMResult


@dataclass
class StubResponse:
    """One scripted model reply."""

    content: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    parsed: BaseModel | None = None
    raise_error: Exception | None = None

    def to_message(self) -> AIMessage:
        calls = [
            {
                "name": c["name"],
                "args": c.get("args", {}),
                "id": c.get("id", f"stub_call_{i}"),
                "type": "tool_call",
            }
            for i, c in enumerate(self.tool_calls)
        ]
        return AIMessage(
            content=self.content,
            tool_calls=calls,
            response_metadata={"model_name": "stub/deterministic"},
            usage_metadata={"input_tokens": 100, "output_tokens": 20, "total_tokens": 120},
        )


class StubRouter:
    """Replays scripted responses keyed by the caller's ``tag``."""

    def __init__(
        self,
        script: dict[str, list[StubResponse]] | None = None,
        default: StubResponse | None = None,
    ) -> None:
        self.script = {k: list(v) for k, v in (script or {}).items()}
        self.default = default or StubResponse(content="(stub: nothing further to do)")
        self.calls: list[dict[str, Any]] = []
        self._total_cost = 0.0

    # --- LLMRouter-compatible surface --------------------------------------

    def pick_model(self, complexity: TaskComplexity | str) -> str:
        c = TaskComplexity(complexity) if isinstance(complexity, str) else complexity
        return "stub/large" if c is TaskComplexity.COMPLEX else "stub/small"

    def fallback_for(self, model: str) -> str:
        return "stub/fallback"

    def invoke(
        self,
        messages: Sequence[Any] | str,
        *,
        tag: str,
        complexity: TaskComplexity | str = TaskComplexity.STANDARD,
        tools: Sequence[Any] | None = None,
        structured_output: Any | None = None,
        **kwargs: Any,
    ) -> LLMResult:
        self.calls.append({"tag": tag, "complexity": str(complexity), "tools": bool(tools)})

        queue = self.script.get(tag)
        response = queue.pop(0) if queue else self.default
        if response.raise_error is not None:
            raise response.raise_error

        parsed = response.parsed
        if structured_output is not None and parsed is None:
            # Nothing scripted: hand back an empty-but-valid instance where the
            # schema allows it, so a test that does not care about the report
            # body does not have to script one.
            try:
                parsed = structured_output()
            except Exception:  # noqa: BLE001 - required fields; leave it None
                parsed = None

        return LLMResult(
            message=response.to_message(),
            parsed=parsed,
            requested_model=self.pick_model(complexity),
            actual_model="stub/deterministic",
            input_tokens=100,
            output_tokens=20,
            cost_usd=0.0,
            shadow_cost_usd=0.00007,
            price_known=True,
            latency_ms=1.0,
            attempts=1,
            fallback_used=False,
        )

    @property
    def total_cost_usd(self) -> float:
        return self._total_cost

    def reset_cost(self) -> None:
        self._total_cost = 0.0
