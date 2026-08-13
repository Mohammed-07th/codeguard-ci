# Architecture

CodeGuard CI is a **graph-orchestrated multi-agent system**. This document uses the course
vocabulary deliberately — *state*, *nodes*, *edges*, *agents*, *tools* — and points at the code
that implements each.

---

## 1. State

`ReviewState` ([`src/codeguard/state.py`](../src/codeguard/state.py)) is a typed `TypedDict`
threaded through every node. It is a **genuinely shared object**, not a message passed along a
chain: each node returns only the channels it changed, and LangGraph merges those updates through
the channel reducers.

```python
class ReviewState(TypedDict, total=False):
    pr_id: str
    diff: str
    workdir_path: str                                   # the working copy, never the fixture
    plan: list[str]
    delegated_agents: list[str]
    scratchpad:        Annotated[list[str],   operator.add]   # ReAct short-term memory
    findings:          Annotated[list[Finding], operator.add] # agents append here
    guardrail_events:  Annotated[list[dict],  operator.add]
    cost_usd:          Annotated[float,       operator.add]
    verdict: Verdict | None
    iteration: int
    hitl_decision: str | None
```

### Why the reducers matter

`security_agent`, `style_agent` and `coverage_agent` execute **in the same superstep**. All three
write `findings`, `scratchpad` and `cost_usd` concurrently. Without `operator.add` on those
channels the last writer would win and two agents' work would vanish. The reducers are what make
the parallel fan-out safe.

### The consequence the reducers create

Because `findings` is append-only, a remediation re-scan *appends* to the previous iteration's
findings — a naive count could only ever rise. So each `Finding` carries an `iteration` stamped
**by the graph, never by the model**, and routing reads only the current iteration via
`current_findings(state)`. The full history stays in state, which is what lets the evidence show
the progression rather than just the endpoint.

---

## 2. Nodes

Implemented in [`src/codeguard/graph/nodes.py`](../src/codeguard/graph/nodes.py), assembled in
[`build.py`](../src/codeguard/graph/build.py).

| Node | Responsibility |
|---|---|
| `ingest_pr` | Load the PR; **redact secrets and PII before any other node, prompt or span sees state** |
| `guardrail_input` | Prompt-injection detection on PR text; second redaction pass |
| `blocked` | Terminal for a failed guardrail — still writes an audit report |
| `coordinator` | Ordered plan + the delegation decision |
| `security_agent` | Credentials and vulnerabilities; triage; writes the fix |
| `style_agent` | Lint hits ranked by real consequence |
| `coverage_agent` | Whether the *specific* uncovered lines carry risk |
| `synthesizer` | Conflict resolution across agents; the verdict |
| `remediation_loop` | Bookkeeping for a repair pass |
| `apply_fix` | Rewrites the working copy so the next scan sees different bytes |
| `hitl_approval` | `interrupt()` — pauses the graph for a human |
| `apply_decision` | Folds the human's decision into the verdict |
| `finalize` / `persist_report` | Terminal; writes the report to disk and object storage |

Every node is wrapped in an OpenTelemetry span, so the trace waterfall shows the graph's real
shape. The one exception is `hitl_approval`: `interrupt()` suspends the graph by unwinding the
stack, and an enclosing span would record that control-flow signal as an error.

---

## 3. Edges

Three decision points, in [`src/codeguard/graph/edges.py`](../src/codeguard/graph/edges.py).

### `route_after_guardrail` → `blocked` | `coordinator`
A blocked PR never reaches the coordinator, so its text never reaches a model. The evidence for
that claim is `llm_calls: 0` on a blocked review, not an assertion about intent.

### `fan_out_to_specialists` → **a list of nodes**
Returning a list is what makes the coordinator's delegation *real*: a docs-only PR that it judged
not to need coverage analysis genuinely does not execute that node. `security_agent` is force-added
regardless — security review is not optional on a PR that reached this point.

### `route_after_synthesis` → `hitl_approval` | `remediation_loop` | `finalize`
The conditional edge Deliverable 2 turns on:

```
any genuine CRITICAL finding                            -> hitl_approval
HIGH findings, iteration < MAX_ITER, at least one fix    -> remediation_loop
otherwise                                                -> finalize
```

---

## 4. The remediation loop

```
synthesizer → remediation_loop → apply_fix → {security_agent, style_agent} → synthesizer
```

`apply_fix` substitutes each blocking finding's `suggested_fix` into the file **in `workdir/`**,
preserving indentation. Fixtures are never mutated, so the demo is repeatable. The next iteration
re-runs the real analysers against the patched bytes.

`coverage_agent` is deliberately excluded from the loop-back: a one-line substitution cannot change
which branches the test suite exercises.

**Termination is guaranteed three independent ways** — findings clear, `iteration >= MAX_ITER`, or
no remaining finding carries an applicable fix. The third matters: without it, an unfixable HIGH
finding would loop to the ceiling re-deriving the same answer. A parametrised test sweeps
iterations 0–5 and asserts routing never escapes the bound.

Measured, from the executed notebook:

```
iter  total  blocking   FP  decision
   0      9         5    1  BLOCK_MERGE
   1      4         0    1  REQUEST_CHANGES
blocking: 5 -> 0    terminated because: findings_clear
patched: ['src/config.py:8', 'src/config.py:15', 'src/settlement.py:22']
```

All three specialists contributed at iteration 0 (security 4, style 3, coverage 2).
Captured against real models in `evidence/live_review_pr_with_secret.log`.

---

## 5. Agents

Coordination strategy: **centralised coordinator with hierarchical delegation**.

Agents differ in exactly three ways, which is what makes them distinct agents rather than one
prompt wearing hats: a **system prompt**, a **tool allow-list**, and an **output schema**.

| Agent | Tools | Schema | Judgment the tool cannot provide |
|---|---|---|---|
| `CoordinatorAgent` | `list_changed_files`, `get_diff` | `ReviewPlan` | Which specialists are needed, and why any were skipped |
| `SecurityAgent` | `scan_secrets`, `run_bandit`, `read_file` | `AgentReport` | True vs false positive; exploitability here; writes the fix |
| `StyleAgent` | `run_ruff`, `read_file` | `AgentReport` | Derives its **own** severity — a bare `except:` in a fee path is not a long line |
| `TestCoverageAgent` | `run_pytest_coverage`, `read_file` | `AgentReport` | Whether the *specific* uncovered lines carry risk |
| `ReviewSynthesizerAgent` | **none** | `SynthesisResult` → `Verdict` | Resolves disagreement between agents; dedupes; final verdict |

The synthesizer holding no tools is the point: Deliverable 3 asks that agents communicate through
structured messages, and it never sees another agent's prose — only `Finding` objects from state.

### The ReAct loop

[`agents/base.py`](../src/codeguard/agents/base.py) implements **Thought → Action → Observation**:
the model states its reasoning, emits a real function call, and the tool's actual output is fed
back as a `ToolMessage`. Accumulated lines become the `scratchpad` channel — genuine short-term
memory carried across steps. The loop is bounded by `max_react_steps`, because an unbounded agent
loop is a production incident.

### A safety floor on synthesis

The model chooses freely between `APPROVE` and `REQUEST_CHANGES`, but it **cannot approve over an
untriaged critical finding**. On a free-tier model, an occasional malformed judgment must not be
able to wave through an RCE. Every override is logged as `SAFETY FLOOR` rather than applied
silently, and findings the raising agent triaged as false positives correctly do not trigger it.

---

## 6. Tools

Seven tools, all invoking real binaries or scanning real files
([`src/codeguard/tools/`](../src/codeguard/tools/)):

| Tool | Implementation |
|---|---|
| `scan_secrets` | Named credential patterns **+ Shannon entropy**; masks at the point of detection |
| `run_bandit` | `subprocess` → `bandit -f json`, parsed |
| `run_ruff` | `subprocess` → `ruff check --output-format json --isolated` |
| `run_pytest_coverage` | `subprocess` → `pytest --cov`; returns the **source text** of uncovered lines |
| `read_file` / `list_changed_files` / `get_diff` | Repository access, sandboxed |

Analyser versions are recorded on every report: "clean under bandit" means nothing without saying
*which* bandit.

Two access controls, both with tests proving they refuse:

* **Path sandbox** — tool paths resolve inside the review root; traversal and absolute paths are
  rejected *after* resolution, so a symlink cannot smuggle a path past the check.
* **Per-agent allow-list** — enforced at binding *and again* at dispatch, because a prompt-injected
  model could emit a tool name it was never offered.

---

## 7. Cross-cutting concerns

### Model routing and resilience
[`llm/router.py`](../src/codeguard/llm/router.py) maps task complexity onto a model, then layers
two independent mechanisms: `.with_fallbacks()` (a *model* failed → try another) inside
`tenacity` retry (a *transport* fault → try again). A 429 is deliberately excluded from the retry
set — the fallback handles rate limits, and retrying would just wait. `fallback_for()` never
returns the model that just failed, which matters because the synthesis model and the configured
fallback are the same model here.

### Cost metering
Cost is computed from token counts reported by the provider, never estimated. Because this project
runs on free models, real cost is `$0.00` and a **shadow cost** — the same measured tokens priced
at `gpt-4o-mini` rates — is reported alongside, always labelled as a projection.

### Observability
Spans come from three sources: OpenInference's LangChain instrumentor (LLM calls), `dispatch`
(tool calls), and a wrapper around each node. Structured JSONL metrics record model, tokens, cost,
latency, and — added after a real incident — *why* a fallback engaged.

### Persistence
`SqliteSaver` over a file, constructed from a raw connection rather than `from_conn_string`, which
is a context manager and would close the database as soon as the block exits. `check_same_thread=False`
is required because the parallel fan-out writes checkpoints from worker threads.

---

## 8. What would change in production

| Concern | Here | Production |
|---|---|---|
| Checkpointer | SQLite file | Postgres (`langgraph-checkpoint-postgres`); one constructor call |
| Model | Free tier, ~50 req/day | A paid tier; routing already selects per complexity |
| Injection detection | Pattern-based, 85% measured | Pattern filter **plus** an LLM classifier for paraphrase attacks |
| `apply_fix` | Line substitution | Real patch application, proposed as a PR rather than applied |
| Artifact storage | MinIO container | S3 — two environment variables, no code change |
| PR source | Fixtures and webhook payloads | A GitHub App posting inline review comments |
