"""Tests for the tool layer: detection correctness and both access controls."""

from __future__ import annotations

import json

import pytest

from codeguard.config import get_settings
from codeguard.tools import repo_tools
from codeguard.tools.registry import (
    AGENT_TOOLS,
    ToolAccessDenied,
    dispatch,
    scan_secrets_impl,
)
from codeguard.tools.sandbox import SandboxViolation, review_root
from codeguard.tools.secret_scanner import mask, scan_text, shannon_entropy

FIXTURES = get_settings().fixtures_dir


@pytest.fixture()
def secret_pr():
    pr = repo_tools.load_pull_request(FIXTURES / "pr_with_secret")
    with review_root(pr.root), repo_tools.pr_context(pr):
        yield pr


# --- entropy + masking --------------------------------------------------------

def test_shannon_entropy_separates_random_from_repetitive():
    assert shannon_entropy("aaaaaaaaaaaaaaaa") < 1.0
    assert shannon_entropy("xK9$mQ2vLp8wR4nT") > 3.5


def test_mask_never_reveals_the_secret():
    secret = "AKIA3XQ7MZPLK2VNWR4T"
    masked = mask(secret)
    assert secret not in masked
    assert masked.startswith("AKIA")
    assert "len=20" in masked


def test_mask_handles_short_values():
    assert mask("ab") == "**"


# --- pattern detection --------------------------------------------------------

def test_detects_password_inside_underscored_identifier():
    """`_` is a word character, so a naive \\b before 'password' misses DB_PASSWORD."""
    hits = scan_text('DB_PASSWORD = "Hunter2!Settlement"', "src/config.py")
    assert [h.rule_id for h in hits] == ["HARDCODED_PASSWORD"]


@pytest.mark.parametrize(
    "line,expected",
    [
        ('AWS_ACCESS_KEY_ID = "AKIA3XQ7MZPLK2VNWR4T"', "AWS_ACCESS_KEY"),
        ('EMAIL = "ahmed@example-bank.com.sa"', "EMAIL"),
        ('TOKEN = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"', "GITHUB_TOKEN"),
        ("-----BEGIN RSA PRIVATE KEY-----", "PRIVATE_KEY"),
    ],
)
def test_named_patterns_fire(line, expected):
    assert expected in {h.rule_id for h in scan_text(line, "src/x.py")}


def test_entropy_detector_catches_unnamed_credential():
    hits = scan_text('SESSION_TOKEN = "xK9mQ2vLp8wR4nT6yB1zC3dE5fG7hJ0k"', "src/x.py")
    assert any(h.detector == "entropy" for h in hits)


def test_clean_code_produces_no_hits():
    assert scan_text("def add(a, b):\n    return a + b\n", "src/math.py") == []


def test_test_paths_are_flagged_but_not_auto_dismissed():
    """The scanner records the hint; only the agent may downgrade it."""
    hits = scan_text('TEST_DB_PASSWORD = "test123"', "tests/conftest.py")
    assert len(hits) == 1
    assert hits[0].in_test_path is True
    assert hits[0].severity_hint == "high"  # still reported at full severity


def test_scan_output_contains_no_raw_secret(secret_pr):
    blob = json.dumps(scan_secrets_impl("."))
    for raw in ("AKIA3XQ7MZPLK2VNWR4T", "Hunter2!Settlement",
                "ahmed.alqahtani@example-bank.com.sa"):
        assert raw not in blob


# --- security control 1: the path sandbox ------------------------------------

@pytest.mark.parametrize("path", ["../../.env", "/etc/passwd", "../../../../etc/hosts"])
def test_sandbox_refuses_paths_outside_the_review_root(secret_pr, path):
    with pytest.raises(SandboxViolation):
        repo_tools.read_file(path)


def test_sandbox_allows_paths_inside_the_review_root(secret_pr):
    assert repo_tools.read_file("src/config.py")["line_count"] > 0


def test_tools_refuse_to_run_without_a_review_root():
    with pytest.raises(SandboxViolation):
        repo_tools.read_file("src/config.py")


# --- security control 2: the per-agent allow-list -----------------------------

def test_allowed_tool_call_succeeds(secret_pr):
    assert json.loads(dispatch("SecurityAgent", "scan_secrets", {"path": "."}))["hit_count"] > 0


@pytest.mark.parametrize(
    "agent,tool",
    [
        ("StyleAgent", "scan_secrets"),
        ("CoordinatorAgent", "run_bandit"),
        ("TestCoverageAgent", "run_ruff"),
        ("ReviewSynthesizerAgent", "read_file"),
    ],
)
def test_rbac_denies_tools_outside_the_allow_list(secret_pr, agent, tool):
    with pytest.raises(ToolAccessDenied):
        dispatch(agent, tool, {"path": "."})


def test_unknown_agent_has_no_privileges(secret_pr):
    with pytest.raises(ToolAccessDenied):
        dispatch("RogueAgent", "read_file", {"path": "src/config.py"})


def test_synthesizer_holds_no_tools():
    """It resolves conflicts over Findings in shared state; it needs no filesystem."""
    assert AGENT_TOOLS["ReviewSynthesizerAgent"] == ()
