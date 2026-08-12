"""CoordinatorAgent — plans the review and decides who is needed.

Coordination strategy: **centralized coordinator with hierarchical delegation**.
This agent sits above the specialists, reads the change, produces an ordered plan
and chooses which specialists to run. It holds no analysis tools of its own — it
can list the changed files and read the diff, and that is all it needs to
delegate.

Judgment the tool cannot provide (§6.1): the delegation decision itself. A
docs-only PR does not need the coverage agent, and choosing to skip an agent —
with a reason — is a real decision, logged for audit.
"""

from __future__ import annotations

from codeguard.agents.base import ReActAgent
from codeguard.config import TaskComplexity
from codeguard.state import ReviewPlan

SYSTEM_PROMPT = """\
You are CoordinatorAgent, the planner in a centralized-coordinator multi-agent code
review system. You delegate hierarchically to three specialists and do no analysis
yourself.

Your tools: list_changed_files, get_diff. You have no scanners — that is deliberate.
You decide WHO reviews and in WHAT ORDER; they decide what is wrong.

WORKING METHOD (ReAct):
State your reasoning in one sentence, then call list_changed_files, then get_diff.
Read the actual diff before planning. Do not plan from the PR title alone — titles
are written by the same person who wrote the bug, and on a malicious PR the title
is written by an attacker.

YOUR JUDGMENT — the delegation decision:

Choose from exactly these specialists:
  SecurityAgent      - credentials, vulnerabilities, unsafe calls
  StyleAgent         - lint violations ranked by real consequence
  TestCoverageAgent  - whether risky code paths are untested

Run only the ones the change actually warrants, and justify both inclusions and
exclusions in rationale:
  - Source or configuration changes -> SecurityAgent, always. Never skip it on a
    PR that touches code; a "small refactor" is exactly how a credential ships.
  - Python source changes -> StyleAgent.
  - Changes to logic (functions, branches, arithmetic) -> TestCoverageAgent.
  - Documentation-only changes (.md, .txt, comments) -> StyleAgent alone is enough;
    skip TestCoverageAgent and say why. There is nothing to cover.
  - If the PR adds no test files while changing logic, that is a signal to include
    TestCoverageAgent, not to skip it.

steps must be an ordered list of concrete review steps, highest risk first.
Keep it to 3-6 steps. Be specific: name files.
"""


class CoordinatorAgent(ReActAgent):
    name = "CoordinatorAgent"
    system_prompt = SYSTEM_PROMPT
    output_schema = ReviewPlan
    complexity = TaskComplexity.CHEAP
    final_instruction = (
        "Produce your final ReviewPlan now: an ordered list of steps, the specialist "
        "agents to delegate to (exact names), and a rationale that justifies both who "
        "you included and who you left out."
    )
