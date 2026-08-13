#!/usr/bin/env python
"""Generate notebooks/capstone_evidence.ipynb.

The notebook is built from this script rather than hand-edited so it can be
regenerated deterministically and reviewed as source. Execute it with:

    .venv/bin/jupyter nbconvert --execute --inplace notebooks/capstone_evidence.ipynb
"""

from __future__ import annotations

from pathlib import Path

import nbformat as nbf

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "notebooks" / "capstone_evidence.ipynb"

nb = nbf.v4.new_notebook()
cells: list = []


def md(text: str) -> None:
    cells.append(nbf.v4.new_markdown_cell(text.strip("\n")))


def code(src: str) -> None:
    cells.append(nbf.v4.new_code_cell(src.strip("\n")))


# =============================================================================
md("""
# CodeGuard CI — Capstone Evidence

**Agentic code-review and secrets-scanning for CI pipelines.**

Completed under the *Advanced Agentic AI Systems Engineering* advanced training
programme, SDAIA Academy — cohort of 9–13 August 2026 (5-day advanced capstone, on-site, 30 training hours).
Completed individually; all six deliverables implemented by a single contributor.

---

### How to read this notebook

One section per rubric deliverable. Each ends with a printed
`✅ Deliverable N evidence captured` line.

Cells are one of two kinds, and each says which it is:

* **LIVE** — executes now, in this notebook. Every tool (`bandit`, `ruff`,
  `pytest`, the secret scanner) runs as a real subprocess against the real
  fixtures. Where an LLM is not the thing under test, a deterministic stub
  stands in for it so the cell is reproducible and costs no rate-limited quota;
  the tools and the graph are real regardless.
* **CAPTURED** — replays output recorded from a run against **real models**,
  stored under `evidence/`. Used where the evidence *is* the model's behaviour.

This split is deliberate and is stated at each cell. The project runs on
free-tier models capped at 50 requests/day, which is roughly one and a half
full reviews — so live model calls are spent on evidence that needs them, and
nothing else.
""")

code("""
# --- setup (LIVE) ---
import json, os, sys, subprocess, textwrap
from pathlib import Path

ROOT = Path.cwd().parent if Path.cwd().name == "notebooks" else Path.cwd()
sys.path.insert(0, str(ROOT / "src"))
os.chdir(ROOT)

from codeguard.config import get_settings, MODEL_PRICES
S = get_settings()
EV = ROOT / "evidence"

def captured(name, head=None, grep=None, tail=None):
    \"\"\"Replay a captured evidence file.\"\"\"
    p = EV / name
    if not p.exists():
        print(f"  [missing] evidence/{name} — run scripts/run_demo.sh"); return ""
    text = p.read_text(errors="replace")
    lines = text.splitlines()
    if grep:
        lines = [l for l in lines if any(g in l for g in grep)]
    if head:  lines = lines[:head]
    if tail:  lines = lines[-tail:]
    print("\\n".join(lines))
    return text

def rule(title):
    print("=" * 78); print(title); print("=" * 78)

print(f"repo          : {ROOT}")
print(f"python        : {sys.version.split()[0]}")
print(f"primary model : {S.primary_model}")
print(f"fallback      : {S.fallback_model}")
print(f"synthesis     : {S.synthesis_model}")
print(f"MAX_ITER      : {S.max_iter}   guardrails: {S.guardrails_enabled}")
print(f"evidence dir  : {len(list(EV.glob('*')))} artifacts")
""")

# ============================== DELIVERABLE 1 ================================
md("""
---
## Deliverable 1 — Agentic Reasoning & Tool Use  (15 pts)

**ReAct**: Thought → Action → Observation, looped, bounded, with real
OpenAI-style function calling over seven real tools. Short-term memory is the
`scratchpad` channel of graph state, carried across steps.

The claim that matters here is that the agent adds **judgment the tool cannot
provide** — so the raw tool output and the agent's interpretation of it are
shown side by side.
""")

code("""
# --- LIVE: the seven real tools and the per-agent allow-list ---
from codeguard.tools.registry import TOOLS, roster

rule("TOOL REGISTRY — every tool shells out to a real binary or scans real files")
for name, t in TOOLS.items():
    print(f"  {name:<24}{t.description}")

print()
rule("PER-AGENT ALLOW-LIST (RBAC) — least privilege")
print(f"  {'agent':<26}{'n':>3}  tools")
print("  " + "-" * 70)
for r in roster():
    print(f"  {r['agent']:<26}{r['tool_count']:>3}  {', '.join(r['tools'])}")
""")

code("""
# --- LIVE: a real tool executing right now, against a real fixture ---
from codeguard.tools import repo_tools
from codeguard.tools.registry import run_bandit_impl, scan_secrets_impl
from codeguard.tools.sandbox import review_root

pr = repo_tools.load_pull_request(S.fixtures_dir / "pr_with_secret")
with review_root(pr.root), repo_tools.pr_context(pr):
    scan = scan_secrets_impl(".")
    band = run_bandit_impl(".")

rule("RAW TOOL OUTPUT — no agent involved, no triage, everything at full severity")
print(f"  secret_scanner: {scan['hit_count']} hits across {len(scan['scanned_files'])} files")
for h in scan["hits"]:
    print(f"    {h['rule_id']:<20}{h['file']}:{h['line']:<4} "
          f"hint={h['severity_hint']:<9}in_test_path={h['in_test_path']}  {h['masked_match']}")
print(f"\\n  bandit: {band['finding_count']} issues   (subprocess: {band['command'].split()[-1]})")
for f in band["findings"][:5]:
    print(f"    {f['rule_id']:<7}{f['severity']:<9}{f['file']}:{f['line']}  {f['message'][:46]}")
print(f"\\n  analyser provenance: {band['analyser_versions']}")
""")

code("""
# --- CAPTURED: the ReAct trace from a run against real models ---
rule("ReAct LOOP — Thought / Action / Observation  (real LLM, real function calls)")
captured("phase3_security_agent.log",
         grep=["step 1 |", "step 2 |", "step 3 |", "ReAct loop"], head=18)
""")

code("""
# --- CAPTURED: the judgment layer, which is the whole point ---
rule("AGENT JUDGMENT vs RAW TOOL OUTPUT")
captured("phase3_security_agent.log", grep=["AGENT JUDGMENT", "  high ", "  medium ",
                                            "  low ", "fix:", "triage:", "YES"], head=22)
print()
rule("VERIFICATION (from that captured run)")
captured("phase3_security_agent.log", grep=["[PASS]", "[FAIL]"])
print()
print("Note the fourth finding: both the scanner AND bandit flagged")
print("tests/conftest.py at full severity. The AGENT downgraded it, with a written")
print("reason. No tool in the stack can make that call.")
print()
print("✅ Deliverable 1 evidence captured")
""")

# ============================== DELIVERABLE 2 ================================
md("""
---
## Deliverable 2 — Graph-Based Orchestration  (20 pts)

A LangGraph `StateGraph` over a typed `ReviewState`, compiled with a file-backed
`SqliteSaver`. Parallel fan-out to three specialists, fan-in at the synthesizer,
a three-way **conditional edge**, and a **remediation loop that changes code on
disk** and re-scans it.

The diagram is rendered *from the compiled graph*, so it cannot drift from the
implementation.
""")

code("""
# --- LIVE: the graph, rendered from the compiled object ---
from IPython.display import Image, display
from codeguard.graph.build import build_graph, make_checkpointer, prepare_initial_state
from codeguard.llm.stub import scripted_review_router

graph = build_graph(router=scripted_review_router(), checkpointer=make_checkpointer(),
                    verbose=False)
g = graph.get_graph()
print(f"nodes: {len(g.nodes)}   edges: {len(g.edges)}   checkpointer: "
      f"{type(graph.checkpointer).__name__}")
display(Image(filename="docs/graph.png"))
""")

code("""
# --- LIVE: the remediation loop, with the REAL scanner counting findings ---
# The LLM is stubbed; bandit, ruff, pytest and the secret scanner all execute
# for real, and apply_fix genuinely rewrites files in workdir/. The finding
# counts below are therefore measured, not scripted.
import time
from codeguard.obs.metrics import run_context

thread = f"nb-remediation-{int(time.time())}"
state = prepare_initial_state(S.fixtures_dir / "pr_with_secret", workdir_name=thread)
with run_context(thread_id=thread, pr_id=state["pr_id"]):
    final = graph.invoke(state, {"configurable": {"thread_id": thread},
                                 "recursion_limit": 60})

rule("STATE AFTER EACH NODE (scratchpad is the shared, appended state channel)")
for line in final["scratchpad"][:4] + ["   ..."] + final["scratchpad"][-4:]:
    print("  " + str(line)[:110])

print()
rule("REMEDIATION LOOP — findings per iteration")
print(f"  {'iter':>4}  {'total':>6}  {'blocking':>9}  {'triaged FP':>11}  decision")
print("  " + "-" * 62)
for h in final["iteration_history"]:
    print(f"  {h['iteration']:>4}  {h['findings_total']:>6}  {h['findings_blocking']:>9}"
          f"  {h['false_positives']:>11}  {h['decision']}")
counts = [h["findings_blocking"] for h in final["iteration_history"]]
print(f"\\n  blocking findings across iterations: {' -> '.join(map(str, counts))}")
print(f"  strictly decreasing: {all(b < a for a, b in zip(counts, counts[1:]))}")
print(f"  files patched      : {final['patched_files']}")
""")

code("""
# --- LIVE: the loop is provably bounded ---
from codeguard.graph.edges import loop_should_terminate, route_after_synthesis
from codeguard.state import Finding, Severity, new_state

done, why = loop_should_terminate(final)
rule("TERMINATION")
print(f"  terminated: {done}   because: {why}")
print(f"  iterations run: {final['iteration']} (MAX_ITER={S.max_iter})")

def probe(sev, iteration, fix="X = os.environ['X']", fp=False):
    st = new_state("PR-T", "t", "d", ["src/config.py"], "d", workdir_path="/tmp")
    st.update(iteration=iteration, findings=[Finding(
        agent="SecurityAgent", category="secret", severity=sev, file="src/config.py",
        line=8, message="m", suggested_fix=fix, is_false_positive=fp, iteration=iteration)])
    return route_after_synthesis(st)

print()
print(f"  {'scenario':<46}route")
print("  " + "-" * 66)
for label, args in [
    ("critical finding", (Severity.CRITICAL, 0, "f", False)),
    ("critical, but agent triaged it a false positive", (Severity.CRITICAL, 0, "f", True)),
    ("high finding, iteration 0", (Severity.HIGH, 0, "f", False)),
    (f"high finding, iteration {S.max_iter} (at ceiling)", (Severity.HIGH, S.max_iter, "f", False)),
    ("high finding with no applicable fix", (Severity.HIGH, 0, None, False)),
    ("low finding only", (Severity.LOW, 0, "f", False)),
]:
    print(f"  {label:<46}{probe(*args)}")
print()
print("✅ Deliverable 2 evidence captured")
""")

# ============================== DELIVERABLE 3 ================================
md("""
---
## Deliverable 3 — Multi-Agent & Role Specialisation  (20 pts)

Five named agents. They differ in exactly three ways — **system prompt**,
**tool allow-list**, **output schema** — which is what makes them distinct
agents rather than one prompt wearing hats.

Coordination strategy: **centralised coordinator with hierarchical delegation**.
Agents communicate *only* through structured Pydantic `Finding` objects written
into shared state. No agent ever reads another agent's prose.
""")

code("""
# --- LIVE: the agent roster ---
from codeguard.agents.coordinator import CoordinatorAgent
from codeguard.agents.coverage_agent import TestCoverageAgent
from codeguard.agents.security_agent import SecurityAgent
from codeguard.agents.style_agent import StyleAgent
from codeguard.agents.synthesizer import ReviewSynthesizerAgent
from codeguard.tools.registry import allowed_tools

rule("AGENT ROSTER — role, tools, output schema, judgment layer")
rows = [
    (CoordinatorAgent, "plans and decides WHICH specialists are needed"),
    (SecurityAgent,    "triages true vs false positive; writes the fix"),
    (StyleAgent,       "derives its OWN severity from what the code does"),
    (TestCoverageAgent,"judges which uncovered lines carry risk"),
]
for cls, judgment in rows:
    print(f"\\n  {cls.name}")
    print(f"    complexity : {cls.complexity.value}")
    print(f"    tools      : {', '.join(allowed_tools(cls.name)) or '(none)'}")
    print(f"    schema     : {cls.output_schema.__name__}")
    print(f"    judgment   : {judgment}")
print(f"\\n  {ReviewSynthesizerAgent.name}")
print(f"    complexity : {ReviewSynthesizerAgent.complexity.value}")
print(f"    tools      : (none — reasons only over Findings in shared state)")
print(f"    schema     : SynthesisResult -> Verdict")
print(f"    judgment   : resolves conflicts BETWEEN agents; dedupes; final verdict")
""")

code("""
# --- LIVE: the structured messages agents actually exchange ---
from codeguard.state import current_findings

# Show EVERY iteration, not just the last. Routing deliberately looks only at the
# current iteration, but that view hides the fan-out: by the final pass the
# specialists whose findings were already repaired have nothing left to report.
rule("FINDINGS IN SHARED STATE, TAGGED BY THE AGENT THAT PRODUCED THEM")
per_iter = {}
for f in final["findings"]:
    per_iter.setdefault(f.iteration, {}).setdefault(f.agent, []).append(f)

for it in sorted(per_iter):
    agents = per_iter[it]
    total = sum(len(v) for v in agents.values())
    print(f"\\n  ── iteration {it} — {len(agents)} agents contributed {total} findings ──")
    for agent, fs in sorted(agents.items()):
        print(f"    {agent}  ({len(fs)})")
        for f in fs:
            fp = "  [TRIAGED FALSE POSITIVE]" if f.is_false_positive else ""
            print(f"      {f.severity.value:<9}{f.category:<10}{f.file}:{f.line}  "
                  f"{f.message[:42]}{fp}")

contributors = sorted({f.agent for f in final["findings"]})
print(f"\\n  distinct agents that produced findings: {len(contributors)} -> {contributors}")
print("  Each ran its own tools, applied its own severity rubric, and wrote into the")
print("  same shared state channel concurrently — which is what the operator.add")
print("  reducer on `findings` exists to make safe.")
""")

code("""
# --- LIVE: what one agent actually transmits to the next ---
rule("ONE FINDING AS TRANSMITTED — a Pydantic object, never free text")
sample = next(f for f in final["findings"] if f.suggested_fix)
print(textwrap.indent(json.dumps(sample.model_dump(mode="json"), indent=2)[:900], "  "))
print()
rule("SEVERITY IS DERIVED BY THE AGENT, NOT COPIED FROM THE TOOL")
style = [f for f in final["findings"] if f.agent == "StyleAgent"]
for f in sorted(style, key=lambda x: x.file + str(x.line)):
    print(f"  {f.severity.value:<9}{f.message[:78]}")
print("\\n  ruff reported all of these at one flat severity. The agent separated the")
print("  bare except in the fee path from the long line — same linter, different risk.")
""")

code("""
# --- CAPTURED: the same thing against REAL models, all three specialists ---
rule("LIVE MULTI-AGENT REVIEW — real models, pr_with_secret")
captured("live_review_pr_with_secret.log",
         grep=["iteration 0: ", "iteration 1: ", "] iteration", "blocking findings across",
               "strictly decreasing", "terminated because", "patched files",
               "VERDICT:", "llm_calls", "elapsed"], head=20)
print()
rule("THE SYNTHESIZER ADJUDICATING BETWEEN AGENTS (real models)")
captured("live_review_pr_with_secret.log", grep=["SecurityAgent identified"], head=3)
print()
print("  It names three agents, weighs their differing positions, and explicitly")
print("  declines to re-promote the finding SecurityAgent triaged. That is the")
print("  conflict resolution Deliverable 3 asks for, on real models.")
""")

code("""
# --- LIVE: conflict resolution, and the safety floor ---
rule("SYNTHESIS — the verdict, referencing the contributing agents")
v = final["verdict"]
print(f"  decision : {v.decision}")
print(f"  blocking : {len(v.blocking_findings)} finding(s)")
print(f"  rationale:")
print(textwrap.indent(textwrap.fill(v.rationale, 88), "    "))
print()
print("  Agents that contributed: " + ", ".join(contributors))
print("  A triaged false positive does NOT block the merge — the synthesizer")
print("  respects the raising agent's downgrade rather than re-promoting it.")
print()
print("✅ Deliverable 3 evidence captured")
""")

# ============================== DELIVERABLE 4 ================================
md("""
---
## Deliverable 4 — Security, Guardrails & Observability  (20 pts)

* **Input guardrail** — prompt-injection detection on attacker-controlled PR
  text, running *before any of it reaches a model*.
* **Output/data guardrail** — secrets and PII masked before they can enter a
  prompt, a log or a span; plus Pydantic schema validation with a repair retry.
* **Observability** — OpenTelemetry spans, structured JSONL metrics, and a cost
  model driven by measured token counts.

Every claim below is paired with its negative case: guardrail on *and* off,
attacks blocked *and* benign PRs allowed through.
""")

code("""
# --- LIVE: the attack, blocked before a single token reaches a model ---
from codeguard.guardrails.injection import check_and_log, detect_injection
from codeguard.tools.repo_tools import load_pull_request

atk = load_pull_request(S.fixtures_dir / "pr_injection")
sources = {"pr_title": atk.title, "pr_description": atk.description, "diff": atk.diff}
verdict = detect_injection(sources)

rule("INPUT GUARDRAIL — pr_injection")
print(f"  blocked      : {verdict.blocked}")
print(f"  rules matched: {len(verdict.rule_ids)} -> {', '.join(verdict.rule_ids)}")
print(f"  total matches: {len(verdict.matches)}")
print()
for m in verdict.matches[:5]:
    print(f"  {m['rule_id']}")
    print(f"    in {m['source']}: {m['excerpt'][:96]}")
""")

code("""
# --- LIVE: the A/B that proves the GUARDRAIL is doing the work, not luck ---
rule("GUARDRAIL ON vs OFF — same payload, same detector")
on  = check_and_log(sources, enabled=True)
off = check_and_log(sources, enabled=False)
print(f"  {'':<26}{'blocked?':<12}{'matches detected'}")
print("  " + "-" * 60)
print(f"  {'guardrails ENABLED':<26}{str(on.blocked):<12}{len(on.matches)}")
print(f"  {'guardrails DISABLED':<26}{str(off.blocked):<12}{len(off.matches)}")
print()
print("  With the guardrail off the payload is still DETECTED and logged — it is")
print("  simply not acted on. So the A/B isolates enforcement from detection, and")
print("  the run below shows what reaches the graph in each case.")
print()
rule("END TO END THROUGH THE GRAPH (captured, guardrails enabled)")
captured("phase5_injection_blocked.log",
         grep=["DETECTED", "routing to blocked", "VERDICT:", "status:"], head=8)
""")

code("""
# --- LIVE: adversarial block rate, with the false-positive rate beside it ---
res = subprocess.run([sys.executable, "scripts/adversarial_check.py"],
                     capture_output=True, text=True)
print("\\n".join(res.stdout.splitlines()[2:]))
""")

code("""
# --- LIVE: the grep proof. Zero raw secrets in anything sent or recorded. ---
from codeguard.guardrails.redaction import assert_clean

RAW = ["AKIA3XQ7MZPLK2VNWR4T", "Hunter2!Settlement", "ahmed.alqahtani@example-bank.com.sa"]

rule("REDACTION PROOF — grep the record of what was actually transmitted")
print("  These three secrets are present in the fixture on disk:")
fixture_src = (S.fixtures_dir / "pr_with_secret" / "files" / "src" / "config.py").read_text()
for s in RAW:
    print(f"    {'FOUND' if s in fixture_src else 'missing':<8} {s}")

print("\\n  And in every artifact the system produced:")
print(f"  {'artifact':<30}{'size':>12}   raw secrets found")
print("  " + "-" * 68)
ok = True
for name, why in [("prompts.jsonl", "exact text sent to the model"),
                  ("traces.jsonl",  "every exported span"),
                  ("metrics.jsonl", "structured monitoring")]:
    p = EV / name
    if not p.exists():
        print(f"  {name:<30}{'(missing)':>12}"); continue
    text = p.read_text(errors="replace")
    leaked = assert_clean(text, RAW)
    ok = ok and not leaked
    print(f"  {name:<30}{len(text):>12,}   {leaked if leaked else 'NONE'}   ({why})")
print(f"\\n  All artifacts clean: {ok}")
""")

code("""
# --- LIVE: structured monitoring and the measured cost model ---
from codeguard.obs.metrics import METRICS, print_summary

rule("RUN SUMMARY — every number measured, none estimated")
summary = print_summary(METRICS.read(), title="all recorded runs (real models)")
print()
print(f"  Real cost is $0.00 because the project runs on free-tier models.")
print(f"  Shadow cost — the SAME measured token counts priced at gpt-4o-mini rates —")
print(f"  is ${summary['shadow_cost_usd']:.6f}. Reported as a projection, never as spend.")
print()
print("  price table used for costing:")
for m, (pin, pout) in MODEL_PRICES.items():
    print(f"    {m:<44}${pin:>6.3f} in / ${pout:>6.3f} out  per 1M tokens")
""")

code("""
# --- LIVE: the trace waterfall, regenerated from exported spans ---
from codeguard.obs.tracing import read_spans, render_waterfall

spans = read_spans()
rule(f"DISTRIBUTED TRACE — {len(spans)} spans exported")
print(render_waterfall(spans))
print()
print("  The three specialist spans start at the same offset and overlap: that is")
print("  the parallel fan-out as measured behaviour. The synthesizer begins only")
print("  after the last of them finishes — the fan-in.")
print()
print("✅ Deliverable 4 evidence captured")
""")

# ============================== DELIVERABLE 5 ================================
md("""
---
## Deliverable 5 — Production Readiness  (20 pts)

* **Persistence** — `SqliteSaver`, proven by killing a running review with
  `SIGKILL` and resuming it in a different process.
* **Human-in-the-loop** — `interrupt()` pauses the graph; `Command(resume=...)`
  delivers the decision. Both approve *and* reject are shown.
* **Cloud** — Docker Compose: FastAPI app + MinIO + Phoenix.
* **Resilience** — model fallback, retry with backoff, a cost cap.
""")

code("""
# --- CAPTURED: kill the process mid-review, resume in a fresh one ---
rule("CHECKPOINT DURABILITY ACROSS A PROCESS BOUNDARY")
captured("phase6_persistence_proof.log",
         grep=["worker pid", "SIGKILL", "checkpoints on disk", "resumer pid",
               "pr_id", "status", "scratchpad_lines", "next_nodes", "[PASS]", "[FAIL]"])
""")

code("""
# --- CAPTURED: HITL — the pause, and BOTH decisions from one checkpoint ---
rule("HUMAN-IN-THE-LOOP")
captured("phase6_hitl_both_paths.log",
         grep=["PAUSED", "proposed verdict", "options", "critical ", "halted at",
               "hitl_decision", "FINAL VERDICT", "approve ", "reject ", "[PASS]"])
""")

code("""
# --- LIVE: resilience, including the negative case ---
rule("MODEL FALLBACK — measured, from real runs")
rows = [r for r in METRICS.read() if r.get("kind") == "llm"]
fb   = [r for r in rows if r.get("fallback_used")]
real = [r for r in fb if r.get("fallback_reason") and "Simulated" not in str(r["fallback_reason"])]
print(f"  total LLM calls recorded : {len(rows)}")
print(f"  failover engaged         : {len(fb)}")
print(f"  with an upstream cause   : {len(real)}")
if real:
    r = real[-1]
    print(f"\\n  requested : {r['requested_model']}")
    print(f"  answered  : {r['actual_model']}")
    print(f"  cause     : {' '.join(str(r['fallback_reason']).split())[:150]}")
print()
print("  This failover was NOT forced — it is genuine upstream rate limiting that")
print("  hit the project during development. The graph degraded rather than failing.")
print()
rule("FORCED FAILURE — a synthetic 429 injected into the primary, captured live")
captured("phase7_observability.log",
         grep=["(b) FORCED", "requested :", "answered  :", "fallback  :", "response  :"],
         tail=6)
print()
print("  The rubric asks for a fallback firing on a SIMULATED failure, not only a")
print("  real one. A genuine openai.RateLimitError (HTTP 429) is injected into the")
print("  primary; the fallback model answers. Note the two directions: here the")
print("  primary is the large model and the small one answers, because")
print("  fallback_for() never returns the model that just failed.")
print()
rule("THE SAME MECHANISM, TESTED DETERMINISTICALLY (incl. the negative cases)")
res = subprocess.run([sys.executable, "-m", "pytest", "tests/test_resilience.py", "-v",
                      "-p", "no:phoenix", "-o", "addopts="],
                     capture_output=True, text=True)
print("\\n".join(l for l in res.stdout.splitlines() if "::" in l or "passed" in l))
""")

code("""
# --- CAPTURED + LIVE: the deployed stack ---
rule("DOCKER COMPOSE — app + minio + phoenix")
captured("phase8_docker_stack.log", head=60)
""")

code("""
# --- LIVE: is the stack up right now? ---
import urllib.request, urllib.error
rule("LIVE CHECK (only meaningful while `docker compose up -d` is running)")
try:
    with urllib.request.urlopen("http://localhost:8000/health", timeout=3) as r:
        h = json.loads(r.read())
    print(f"  GET /health -> HTTP {r.status}")
    print(f"    artifact_store reachable: {h['components']['artifact_store']['reachable']}")
    print(f"    checkpointer present    : {h['components']['checkpointer']['present']}")
    with urllib.request.urlopen("http://localhost:8000/reports", timeout=3) as r2:
        rep = json.loads(r2.read())
    print(f"  GET /reports -> {len(rep['objects'])} artifact(s) in MinIO")
    for o in rep["objects"][:5]:
        print(f"    {o['uri']}  {o['size']} bytes")
except (urllib.error.URLError, OSError) as e:
    print(f"  stack not running ({type(e).__name__}) — see the captured output above")
print()
print("✅ Deliverable 5 evidence captured")
""")

# ============================== DELIVERABLE 6 ================================
md("""
---
## Deliverable 6 — Documentation & Evidence  (5 pts)

* [`README.md`](../README.md) — problem, architecture, run instructions, rubric map
* [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) — nodes, edges, state, agents, tools
* [`docs/SECURITY.md`](../docs/SECURITY.md) — threat model, guardrail design, measured limits
* [`docs/presentation_outline.md`](../docs/presentation_outline.md) — architectural review
""")

code("""
# --- LIVE: self-assessment against the rubric ---
rule("SELF-ASSESSMENT — deliverable -> implementation -> evidence")
GRADE = [
    ("1. Agentic Reasoning & Tool Use", 15,
     "agents/base.py (ReAct), tools/ (7 real tools)",
     "phase3_security_agent.log; notebook §1"),
    ("2. Graph-Based Orchestration", 20,
     "graph/build.py, nodes.py, edges.py",
     "docs/graph.png; notebook §2; 27 graph tests"),
    ("3. Multi-Agent & Role Specialisation", 20,
     "agents/{coordinator,security,style,coverage,synthesizer}.py",
     "notebook §3; findings tagged by agent"),
    ("4. Security, Guardrails & Observability", 20,
     "guardrails/{injection,redaction,validation}.py, obs/",
     "phase5_adversarial.log; grep proof; traces.jsonl"),
    ("5. Production Readiness", 20,
     "graph/resume.py, api/main.py, storage/, Dockerfile",
     "phase6_*.log; phase8_docker_stack.log"),
    ("6. Documentation & Evidence", 5,
     "README, docs/, this notebook",
     "this notebook, executed with outputs"),
]
print(f"  {'deliverable':<42}{'pts':>4}  evidence")
print("  " + "-" * 92)
for name, pts, impl, ev in GRADE:
    print(f"  {name:<42}{pts:>4}  {ev}")
    print(f"  {'':<46}  code: {impl}")
print(f"\\n  total points available: {sum(p for _, p, _, _ in GRADE)}")

res = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q",
                      "-p", "no:phoenix", "-o", "addopts="],
                     capture_output=True, text=True)
print(f"\\n  test suite: {res.stdout.strip().splitlines()[-1]}")
print(f"  commits   : {subprocess.run(['git','rev-list','--count','HEAD'], capture_output=True, text=True).stdout.strip()}")
print()
print("✅ Deliverable 6 evidence captured")
""")

md("""
---
## Honest limitations

Stated plainly, because they are the questions an evaluator would ask anyway.

1. **Injection detection is pattern-based and has known bypasses.** Measured
   block rate is **11/13 (85%)** with **0/3 false positives**. Two attacks get
   through and are kept in the adversarial set rather than quietly removed:
   `A11` (semantic paraphrase — carries no trigger vocabulary at all, which is
   the fundamental limit of pattern matching) and `A12` (rot13 — chasing
   individual encodings is whack-a-mole). The real mitigation for both is
   architectural: an injected agent still cannot read outside the path sandbox
   or call a tool its allow-list does not grant.

2. **The SQLite checkpointer would not survive a multi-replica deployment.**
   One writer, one file. Postgres is the production swap; the checkpointer is a
   single constructor call in `graph/build.py`.

3. **Free-tier models constrain the evidence.** 50 requests/day is roughly one
   and a half full reviews, so model-dependent evidence is captured rather than
   re-run on every notebook execution. This is disclosed at each cell. It also
   produced genuinely useful evidence: a real upstream 429 storm, handled by the
   fallback, rather than a simulated one.

4. **Agent judgment quality tracks model quality.** SecurityAgent's triage is
   good; StyleAgent's severity reasoning is thinner than a frontier model would
   produce. The *mechanism* — role separation, structured exchange, judgment
   beyond the tool — is what is demonstrated here.

5. **`apply_fix` does line substitution, not real patch semantics.** Sufficient
   to prove the loop changes code and the finding count genuinely falls; a
   production version would apply a proper diff.

### With two more weeks

Postgres checkpointer and a multi-replica deployment; an LLM-based second-stage
injection classifier behind the pattern filter to close the semantic-paraphrase
gap; per-repository policy so severity thresholds are configurable rather than
hardcoded; and a real GitHub App integration posting findings as inline review
comments.
""")

nb["cells"] = cells
nb["metadata"] = {
    "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
    "language_info": {"name": "python", "version": "3.11"},
}
OUT.parent.mkdir(parents=True, exist_ok=True)
nbf.write(nb, OUT)
print(f"wrote {OUT.relative_to(ROOT)} — {len(cells)} cells "
      f"({sum(1 for c in cells if c.cell_type == 'code')} code)")
