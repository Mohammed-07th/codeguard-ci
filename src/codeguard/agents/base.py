"""The ReAct loop: **Thought → Action → Observation**, repeated until the agent concludes.

This is the reasoning pattern named by Deliverable 1, implemented rather than
described. Each iteration:

* **Thought** — the model states, in prose, why it is about to do something.
* **Action** — it emits a real OpenAI-style function call, dispatched through the
  registry so the per-agent allow-list is enforced on the way out.
* **Observation** — the tool's actual output is fed back as a ``ToolMessage``.

The accumulated Thought/Action/Observation lines are the agent's **short-term
memory**: they live in the ``scratchpad`` channel of graph state and are carried
across steps, so step 4 can reason about what step 1 observed.

The loop ends when the model stops requesting tools, or when ``max_react_steps``
is hit — bounded, because an unbounded agent loop is a production incident. A
final call then converts the accumulated evidence into a schema-valid report.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Sequence

from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from pydantic import BaseModel

from codeguard.config import TaskComplexity, get_settings
from codeguard.guardrails.validation import validate_or_repair
from codeguard.llm.router import LLMRouter, get_router
from codeguard.tools.registry import ToolAccessDenied, dispatch, tools_for

# Tool output fed back to the model is truncated: free-tier context is limited
# and a 40KB coverage report would crowd out the reasoning.
MAX_OBSERVATION_CHARS = 2500


@dataclass
class ReActStep:
    step: int
    thought: str
    action: str | None = None
    action_args: dict[str, Any] = field(default_factory=dict)
    observation: str = ""
    denied: bool = False


@dataclass
class AgentRun:
    """Everything one agent produced, for state and for the evidence notebook."""

    agent: str
    report: BaseModel | None
    steps: list[ReActStep] = field(default_factory=list)
    scratchpad: list[str] = field(default_factory=list)
    raw_observations: list[dict[str, Any]] = field(default_factory=list)
    llm_calls: int = 0
    tool_calls: int = 0
    cost_usd: float = 0.0
    error: str | None = None


class ReActAgent:
    """Base class for every role-specialised agent.

    Subclasses differ in exactly three ways, which is what makes them distinct
    agents rather than one prompt wearing hats: a **system prompt** defining the
    role, a **tool allow-list** (looked up by agent name in the registry), and an
    **output schema** they must satisfy.
    """

    name: str = "ReActAgent"
    system_prompt: str = ""
    output_schema: type[BaseModel]
    complexity: TaskComplexity = TaskComplexity.STANDARD
    final_instruction: str = "Produce your final structured report now."

    def __init__(
        self,
        router: LLMRouter | None = None,
        max_steps: int | None = None,
        verbose: bool = True,
    ) -> None:
        self.settings = get_settings()
        self.router = router or get_router()
        self.max_steps = max_steps or self.settings.max_react_steps
        self.verbose = verbose

    # --- the loop ----------------------------------------------------------

    def run(self, task: str, prior_scratchpad: Sequence[str] = ()) -> AgentRun:
        """Execute the ReAct loop for one task and return a validated report."""
        run = AgentRun(agent=self.name, report=None)
        tools = tools_for(self.name)

        messages: list[BaseMessage] = [
            SystemMessage(content=self.system_prompt),
            HumanMessage(content=self._build_task(task, prior_scratchpad)),
        ]

        self._say(f"\n{'=' * 76}\n[{self.name}] ReAct loop — tools: "
                  f"{[t.name for t in tools] or '(none)'}\n{'=' * 76}")

        for step in range(1, self.max_steps + 1):
            try:
                result = self.router.invoke(
                    messages,
                    tag=f"{self.name}.react",
                    complexity=self.complexity,
                    tools=tools or None,
                )
            except Exception as exc:  # noqa: BLE001
                # A provider fault mid-loop must degrade this ONE agent, not take
                # down the whole review. Found the hard way: an upstream 429
                # during the loop propagated out of run() and killed the graph
                # after it had already completed a full iteration of real work.
                run.error = f"{type(exc).__name__}: {exc}"
                self._log(run, f"[{self.name}] LLM unavailable at step {step}: "
                               f"{str(exc)[:160]} — concluding with what it has")
                break
            run.llm_calls += 1
            run.cost_usd += result.cost_usd
            ai: AIMessage = result.message

            thought = (ai.content or "").strip() or "(no explicit thought emitted)"
            record = ReActStep(step=step, thought=thought)
            self._log(run, f"[{self.name}] step {step} | Thought: {thought[:400]}")

            calls = getattr(ai, "tool_calls", None) or []
            if not calls:
                run.steps.append(record)
                self._log(run, f"[{self.name}] step {step} | No further actions — concluding.")
                break

            messages.append(ai)
            for call in calls:
                tool_name = call.get("name", "")
                args = call.get("args", {}) or {}
                record.action, record.action_args = tool_name, args
                self._log(run, f"[{self.name}] step {step} | Action: {tool_name}({json.dumps(args)})")

                observation, denied = self._invoke_tool(tool_name, args)
                record.observation, record.denied = observation, denied
                run.tool_calls += 1
                run.raw_observations.append(
                    {"step": step, "tool": tool_name, "args": args,
                     "denied": denied, "raw_output": observation}
                )
                self._log(
                    run,
                    f"[{self.name}] step {step} | Observation: "
                    f"{observation[:MAX_OBSERVATION_CHARS][:600]}"
                    + (" …[truncated]" if len(observation) > 600 else ""),
                )
                messages.append(
                    ToolMessage(
                        content=observation[:MAX_OBSERVATION_CHARS],
                        tool_call_id=call.get("id") or tool_name,
                    )
                )
            run.steps.append(record)
        else:
            self._log(run, f"[{self.name}] step budget ({self.max_steps}) exhausted — concluding.")

        # --- convert accumulated evidence into a schema-valid report --------
        if run.error:  # loop already failed; do not spend another call on it
            return run
        messages.append(HumanMessage(content=self.final_instruction))
        try:
            run.report = self._final_report(messages, run)
        except Exception as exc:  # noqa: BLE001 - recorded, graph decides what to do
            run.error = f"{type(exc).__name__}: {exc}"
            self._log(run, f"[{self.name}] FAILED to produce a valid report: {run.error}")
        return run

    # --- helpers -----------------------------------------------------------

    def _invoke_tool(self, tool_name: str, args: dict[str, Any]) -> tuple[str, bool]:
        """Dispatch through the registry so the allow-list is enforced.

        A denial is fed back to the model as an observation rather than raised:
        the agent should learn it may not do that and continue, and the refusal
        is recorded in metrics either way.
        """
        try:
            return dispatch(self.name, tool_name, args), False
        except ToolAccessDenied as e:
            return json.dumps({"error": "ToolAccessDenied", "detail": str(e)}), True
        except Exception as e:  # noqa: BLE001 - a broken tool must not kill the review
            return json.dumps({"error": type(e).__name__, "detail": str(e)}), False

    def _final_report(self, messages: list[BaseMessage], run: AgentRun) -> BaseModel:
        result = self.router.invoke(
            messages,
            tag=f"{self.name}.final",
            complexity=self.complexity,
            structured_output=self.output_schema,
        )
        run.llm_calls += 1
        run.cost_usd += result.cost_usd

        def repair(instruction: str) -> Any:
            retry = self.router.invoke(
                [*messages, HumanMessage(content=instruction)],
                tag=f"{self.name}.final.repair",
                complexity=self.complexity,
                structured_output=self.output_schema,
            )
            run.llm_calls += 1
            run.cost_usd += retry.cost_usd
            return retry.parsed

        return validate_or_repair(
            self.output_schema, result.parsed, repair, agent=self.name
        )

    def _build_task(self, task: str, prior: Sequence[str]) -> str:
        """Prepend short-term memory so the agent can reason over earlier steps."""
        if not prior:
            return task
        memory = "\n".join(prior[-40:])
        return (
            f"{task}\n\n"
            f"--- Shared scratchpad from earlier steps in this review ---\n{memory}\n"
        )

    def _log(self, run: AgentRun, line: str) -> None:
        run.scratchpad.append(line)
        self._say(line)

    def _say(self, line: str) -> None:
        if self.verbose:
            print(line, flush=True)
