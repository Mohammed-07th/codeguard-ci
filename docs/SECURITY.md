# Threat model and guardrail design

An automated reviewer occupies an unusual position: it reads **attacker-controlled text** and then
makes a decision that gates a merge. This document states what it defends against, what it does
not, and what was measured rather than assumed.

---

## 1. Trust boundary

Everything in a pull request is untrusted: title, description, diff, file contents, and code
comments. All of it is written by whoever opened the PR.

```
UNTRUSTED                        │  TRUSTED
─────────────────────────────────┼──────────────────────────────────
PR title, description, diff      │  agent system prompts
file contents in the working copy│  the tool allow-list
                                 │  routing rules, severity thresholds
```

The system is deliberately arranged so that crossing this boundary requires passing a control:
PR text passes the injection detector, tool output passes redaction, and file access passes the
path sandbox.

---

## 2. Threats and controls

### T1 — Prompt injection: the PR tells the reviewer to approve it

The headline attack. `fixtures/pr_injection/` carries it in two places at once: the PR description
(a forged `SYSTEM:` turn plus a direct instruction override) and a code comment addressed to the
automated reviewer.

**Control.** `guardrails/injection.py` scans PR text **before any of it reaches a model**. On a hit
the graph routes to `blocked`, which never reaches the coordinator. Detection is layered across
instruction override, authority spoofing, tool suppression, verdict steering, and text addressed to
the reviewer, plus Arabic-language equivalents. Evasion handling folds Unicode homoglyphs (NFKC),
strips zero-width characters, and decodes base64 blobs before scanning.

**Evidence.** The blocked review reports `llm_calls: 0` — not "the model refused", but *no model
was consulted*. See `evidence/phase5_injection_blocked.log`.

**Measured, on a 13-variant adversarial set with benign controls:**

| | Result |
|---|---|
| Attack block rate | **11/13 (85%)** |
| False-positive rate | **0/3 (0%)** |

The false-positive rate is reported alongside deliberately. A guardrail that blocks everything
scores 100% on block rate and is worthless; only the pair is meaningful.

### T2 — Credential exfiltration through the model, the logs, or the trace

A scanner that finds a secret and then forwards it to a third-party API has moved the leak, not
stopped it.

**Control.** Redaction runs at **three** choke points:

1. `ingest_pr` — PR text is masked before any node, prompt or span sees state.
2. `registry.dispatch` — every tool result is masked on its way to the model, so a new tool
   inherits the protection by default.
3. Span export — masked again on the way out, because spans from OpenInference record whole
   runnable inputs that we do not construct.

**Evidence.** `guardrails.redaction.assert_clean` greps the record of what was actually
transmitted:

```
prompts.jsonl   321,910 chars   raw secrets: NONE
traces.jsonl    611,539 chars   raw secrets: NONE
metrics.jsonl   167,899 chars   raw secrets: NONE
```

**This control was built in response to real leaks, twice.** Masking inside the scanner alone was
not sufficient: `read_file` returned source verbatim, and `bandit` quoted the password inside its
own `issue_text`. Later, raw keys were found in `traces.jsonl` because redaction ran one node too
late and OpenInference had already recorded the raw state. Both were found by grepping artifacts,
not by reading code — which is the argument for the grep being part of the test suite.

### T3 — Path traversal via a tool argument

Tool paths are chosen by an LLM operating on attacker-controlled input. `read_file("../../.env")`
would exfiltrate the API key through the agent's own findings.

**Control.** `tools/sandbox.py` resolves every path against a review root and rejects anything
outside it. Resolution happens *before* the containment check, so a symlink cannot smuggle a path
past it. Webhook payloads get the same treatment: a `files` key escaping the working directory is
rejected as an attack, not a mistake.

### T4 — Privilege escalation between agents

A prompt-injected agent may emit a tool name it was never offered.

**Control.** The per-agent allow-list is enforced **twice**: at binding, so the model only sees its
own tools, and again at `dispatch`, which refuses regardless of what the model asked for. Layer one
alone would be defeated by a model emitting an unoffered name. `StyleAgent` cannot read secrets;
`ReviewSynthesizerAgent` holds no tools at all.

### T5 — Executing attacker code

**Control.** The agents run *static analysers over* the PR. They never execute code from it. The
one exception is deliberate and bounded: `run_pytest_coverage` runs the PR's own test suite, in a
subprocess, with plugin autoloading disabled so the run cannot inherit the analysis environment's
plugins. In a production deployment that step belongs in a disposable sandbox.

### T6 — A malformed model response approving a merge

Free-tier models produce invalid or nonsensical structured output more often than frontier models.

**Control.** Pydantic schema validation with one repair retry, then failure — an agent that cannot
produce its schema twice is recorded as degraded rather than allowed to invent findings. Above
that, the synthesizer has a **safety floor**: it may not approve over an untriaged critical
finding, and every override is logged rather than applied silently. An unrecognised human resume
decision **fails closed** to `BLOCK_MERGE`; only an explicit approval approves.

### T7 — Denial of wallet

An agent loop with no bound is a billing incident.

**Control.** `max_react_steps` bounds each agent, `MAX_ITER` bounds the remediation loop, and a
per-run USD cost cap aborts a runaway. All three are tested.

---

## 3. What this does **not** defend against

Stated plainly, because these are the real gaps.

1. **Semantic paraphrase injection.** Variant `A11` conveys the same instruction with no trigger
   vocabulary at all — role framing and false reassurance. This is the fundamental limit of pattern
   matching, not a tuning gap. Closing it needs a second-stage LLM classifier.
2. **Arbitrary encodings.** `A12` is rot13. base64 is decoded; rot13, base32 and hex are not.
   Adding decoders one at a time is whack-a-mole, and the honest mitigation is architectural: an
   agent that *is* successfully injected still cannot read outside the sandbox or call a tool it was
   not granted.
3. **A malicious dependency in the PR.** Nothing here inspects `requirements.txt` for typosquats or
   malicious packages.
4. **Multi-turn or cross-PR attacks.** Each review is independent; there is no memory an attacker
   could poison across pull requests.
5. **The reviewer's own supply chain.** `bandit` and `ruff` are trusted. A compromised release of
   either would compromise the review.

---

## 4. Secrets handling in this repository

* `.env` is git-ignored; `.env.example` documents every variable with no real values.
* The API key never enters a prompt, a log, a span, or the container image.
* Every credential in `fixtures/` is **synthetic** and authenticates to nothing. The disclaimer
  lives in `fixtures/README.md` and each `pr.json`, deliberately **not** inside the scanned files —
  a comment saying "this is only a test key" next to the key would hand SecurityAgent the triage
  answer and hollow out the demo.
* `.dockerignore` keeps `.env` out of the build context.

Verify with:

```bash
git ls-files | grep -E '\.env$|\.sqlite$'          # expect no output
git log -p | grep -c 'sk-or-v1-[A-Za-z0-9]\{20,\}' # expect 0
```
