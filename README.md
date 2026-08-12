# CodeGuard CI

**An agentic code-review and secrets-scanning system for CI pipelines.**

A pull request arrives at a webhook. A coordinator agent plans the review and delegates in parallel to
three role-specialised agents — security, style, and test-coverage — each of which calls *real* static
analysis tools (`bandit`, `ruff`, `pytest --cov`, and an entropy-based secret scanner) and then reasons
over the raw output to add judgment the tool cannot provide. A synthesizer resolves conflicts between
the agents and issues a verdict: `APPROVE`, `REQUEST_CHANGES`, or `BLOCK_MERGE`. Critical findings pause
the graph at a human-in-the-loop approval node.

The whole run is guarded (prompt-injection detection on PR text, secret redaction before any text reaches
the LLM), traced, cost-metered, checkpointed to SQLite, and served from FastAPI inside Docker Compose.

> **Status: under construction.** This README is a Phase-0 skeleton. Architecture summary, the graph
> diagram, the module table, the run instructions, and the rubric-mapping table land in Phase 10.

---

## The problem

Pull-request review is a security bottleneck. Human reviewers miss hardcoded credentials, and a leaked
key in a merged commit is permanent — rotating it is the only remedy. Plain linters catch syntax but
have no judgment: they cannot tell a real AWS key from a test fixture, and they flag a long line with
the same urgency as a bare `except:` swallowing errors in a payment path. CodeGuard CI puts a reasoning
layer on top of real tools so the *triage* is automated, not just the scanning.

The adversarial surface is native to the domain: a malicious PR whose description instructs the
automated reviewer to approve it is a realistic attack, and blocking it is a demonstrated guardrail
rather than a contrived one.

---

## Quick start

```bash
cp .env.example .env    # then paste your OPENROUTER_API_KEY into .env
uv venv --python 3.11
uv pip install -r requirements.txt
```

Full run instructions, environment variables, and Docker Compose topology: Phase 10.

---

## Repository layout

| Path | What lives there |
|------|------------------|
| `src/codeguard/agents/` | ReAct loop and the five role-specialised agents |
| `src/codeguard/tools/` | Real tool wrappers + per-agent allow-list (RBAC) |
| `src/codeguard/graph/` | LangGraph nodes, conditional edges, `StateGraph` assembly |
| `src/codeguard/guardrails/` | Input injection detection, output redaction, schema validation |
| `src/codeguard/obs/` | Phoenix tracing and structured cost/latency metrics |
| `src/codeguard/api/` | FastAPI webhook, health, and resume endpoints |
| `fixtures/` | Four PR fixtures: clean, secret-bearing, injection attack, critical |
| `evidence/` | Captured logs from real runs — the graded evidence |
| `notebooks/` | Executed evidence notebook, one section per rubric deliverable |
| `docs/` | Architecture, threat model, graph diagram, presentation outline |

---

## Attribution

Completed under the **Advanced Agentic AI Systems Engineering** advanced training program,
SDAIA Academy — June 2026 cohort.

SDAIA Academy on GitHub: https://github.com/SDAIAAcademy

Completed individually; all six deliverables implemented by a single contributor.
