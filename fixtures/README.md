# PR fixtures

Five synthetic pull requests that drive every path through the review graph.

| Fixture | What it exercises | Expected route |
|---------|-------------------|----------------|
| `pr_clean/` | Benign change, tested, no findings | `finalize` → `APPROVE` |
| `pr_with_secret/` | Hardcoded credentials + PII, and one deliberate false positive | `remediation_loop` → findings decrease → `finalize` |
| `pr_injection/` | Prompt-injection payload in the PR description and in a code comment | `blocked` (input guardrail) |
| `pr_critical/` | Committed private key, `eval()` on user input, TLS verification disabled | `hitl_approval` (human decides) |
| `pr_docs_only/` | Documentation only — no executable code | `finalize` → `APPROVE`, with TestCoverageAgent **skipped** |

## Every credential in here is synthetic

The keys, passwords, tokens and personal details in these fixtures are **fabricated
test data**. They authenticate to nothing and identify no one. They exist so the
scanner has something real-shaped to match against.

That disclaimer lives here and in each `pr.json`'s `notes` field — deliberately
**not** inside the files themselves. The agents read the files; a comment saying
"this is only a test key" sitting next to the key would hand SecurityAgent the
triage answer for free and make the judgment demo meaningless.

## The docs-only fixture proves delegation is real

`fan_out_to_specialists` returns a *list* of nodes, so the coordinator's decision
changes which nodes execute rather than merely being logged. `pr_docs_only/` is what
turns that from a claim into evidence: there is nothing executable in it, so there is
no coverage to measure and no logic to lint, and a competent coordinator should skip
TestCoverageAgent and say why.

It also exercises the far edge of the secret scanner. The README names
`AWS_ACCESS_KEY_ID` and `DB_PASSWORD` **without values** — a detector that fires on a
variable name would flag a documentation page as a credential leak. It reports zero.

## The deliberate false positive

`pr_with_secret/files/tests/conftest.py` contains `password = "test123"`. Both the
secret scanner and bandit flag it, exactly as they should — neither can tell a
test fixture from a production credential.

SecurityAgent is expected to **downgrade it**, with a written reason referencing
the file's path and role. That single captured downgrade is the clearest proof
that the agent adds judgment the tool cannot, which is what Deliverable 3 asks for.

## Layout

    <fixture>/
        pr.json      PR metadata: id, title, description, changed_files, notes
        files/       the file tree the PR produces

`files/` is a real tree because the analysers are real — `bandit` and `pytest`
need something to open. The remediation loop copies it into `workdir/` before
patching, so fixtures stay pristine and the demo is repeatable.
