# PR fixtures

Four synthetic pull requests that drive every path through the review graph.

| Fixture | What it exercises | Expected route |
|---------|-------------------|----------------|
| `pr_clean/` | Benign change, tested, no findings | `finalize` → `APPROVE` |
| `pr_with_secret/` | Hardcoded credentials + PII, and one deliberate false positive | `remediation_loop` → findings decrease → `finalize` |
| `pr_injection/` | Prompt-injection payload in the PR description and in a code comment | `blocked` (input guardrail) |
| `pr_critical/` | Committed private key, `eval()` on user input, TLS verification disabled | `hitl_approval` (human decides) |

## Every credential in here is synthetic

The keys, passwords, tokens and personal details in these fixtures are **fabricated
test data**. They authenticate to nothing and identify no one. They exist so the
scanner has something real-shaped to match against.

That disclaimer lives here and in each `pr.json`'s `notes` field — deliberately
**not** inside the files themselves. The agents read the files; a comment saying
"this is only a test key" sitting next to the key would hand SecurityAgent the
triage answer for free and make the judgment demo meaningless.

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
