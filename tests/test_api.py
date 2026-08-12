"""FastAPI surface tests — the deployed contract, without Docker.

Uses ``TestClient``, so the whole request path runs in-process: no daemon, no
container, no model call. The router is stubbed through the injection seam in
``api.main``.
"""

from __future__ import annotations

import sqlite3

import pytest
from fastapi.testclient import TestClient
from langgraph.checkpoint.sqlite import SqliteSaver

from codeguard.api import main as api
from codeguard.llm.stub import scripted_critical_router, scripted_review_router


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """A client whose checkpoints and LLM are isolated from everything else."""
    db = tmp_path / "checkpoints.sqlite"
    conn = sqlite3.connect(str(db), check_same_thread=False)
    monkeypatch.setattr(api, "make_checkpointer", lambda *a, **k: SqliteSaver(conn))
    monkeypatch.setattr(api, "ROUTER_FACTORY", scripted_review_router)
    api._RUNS.clear()
    with TestClient(api.app) as c:
        yield c
    conn.close()


# --- health -------------------------------------------------------------------

def test_health_returns_200(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_health_reports_each_component(client):
    body = client.get("/health").json()
    comps = body["components"]
    assert {"checkpointer", "artifact_store", "tracing", "models"} <= set(comps)
    assert comps["models"]["primary"]
    # Object storage is optional; health must not claim it is up when it is not.
    assert isinstance(comps["artifact_store"]["reachable"], bool)


def test_health_stays_ok_when_object_storage_is_down(client, monkeypatch):
    """A working deployment must not be pulled from rotation over an optional dep."""
    monkeypatch.setattr(api.artifacts, "is_available", lambda *a, **k: False)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["components"]["artifact_store"]["reachable"] is False


# --- webhook ------------------------------------------------------------------

def test_webhook_accepts_and_returns_a_thread_id(client):
    r = client.post("/webhook/pr", json={"fixture": "pr_clean"})
    assert r.status_code == 202
    body = r.json()
    assert body["thread_id"].startswith("pr-pr_clean-")
    assert body["state"] == "accepted"
    assert body["resume"].endswith("/resume")


def test_synchronous_review_completes_and_returns_findings(client):
    r = client.post("/webhook/pr?wait=true", json={"fixture": "pr_with_secret"})
    assert r.status_code == 202
    body = r.json()
    assert body["state"] == "complete"
    assert body["checkpoint"]["pr_id"] == "PR-1042"
    assert body["checkpoint"]["verdict"] in {"APPROVE", "REQUEST_CHANGES", "BLOCK_MERGE"}
    assert body["metrics"]["tool_calls"] > 0


def test_injection_pr_is_blocked_through_the_api(client):
    """The guardrail applies to remote input, which is where it matters most."""
    r = client.post("/webhook/pr?wait=true", json={"fixture": "pr_injection"})
    body = r.json()
    assert body["checkpoint"]["status"] == "blocked"
    assert body["checkpoint"]["verdict"] == "BLOCK_MERGE"


def test_inline_pr_without_id_is_rejected(client):
    r = client.post("/webhook/pr?wait=true", json={"title": "no id"})
    assert r.json()["state"] == "failed"
    assert "pr_id is required" in r.json()["error"]


def test_path_traversal_in_the_payload_is_refused(client):
    """The webhook body is remote input; a path escaping the workdir is an attack."""
    r = client.post("/webhook/pr?wait=true", json={
        "pr_id": "PR-EVIL",
        "files": {"../../../../tmp/pwned.py": "print('owned')"},
    })
    assert r.json()["state"] == "failed"
    assert "escapes the working directory" in r.json()["error"]


def test_unknown_thread_returns_404(client):
    assert client.get("/review/does-not-exist").status_code == 404


# --- human-in-the-loop over HTTP ----------------------------------------------

@pytest.fixture()
def paused(client, monkeypatch):
    monkeypatch.setattr(api, "ROUTER_FACTORY", scripted_critical_router)
    r = client.post("/webhook/pr?wait=true", json={"fixture": "pr_critical"})
    return r.json()["thread_id"]


def test_critical_pr_pauses_and_reports_awaiting_human(client, paused):
    body = client.get(f"/review/{paused}").json()
    assert body["awaiting_human"] is True
    assert body["approval_request"]["options"] == ["approve", "reject"]
    assert len(body["approval_request"]["blocking_findings"]) == 3


@pytest.mark.parametrize(
    "decision,expected", [("approve", "APPROVE"), ("reject", "BLOCK_MERGE")]
)
def test_resume_over_http_decides_the_review(client, paused, decision, expected):
    r = client.post(f"/review/{paused}/resume",
                    json={"decision": decision, "reason": "via API"})
    assert r.status_code == 200
    assert r.json()["decision"] == expected
    assert r.json()["hitl_decision"] == decision
    # And it is no longer waiting.
    assert client.get(f"/review/{paused}").json()["awaiting_human"] is False


def test_resuming_a_review_that_is_not_paused_is_a_conflict(client):
    client.post("/webhook/pr?wait=true", json={"fixture": "pr_clean"})
    thread = next(iter(api._RUNS))
    r = client.post(f"/review/{thread}/resume", json={"decision": "approve"})
    assert r.status_code == 409


def test_resume_rejects_an_invalid_decision(client, paused):
    """The schema is the gate: only approve/reject reach the graph."""
    r = client.post(f"/review/{paused}/resume", json={"decision": "maybe"})
    assert r.status_code == 422


# --- artifacts ----------------------------------------------------------------

def test_reports_endpoint_degrades_when_storage_is_down(client, monkeypatch):
    monkeypatch.setattr(api.artifacts, "is_available", lambda *a, **k: False)
    monkeypatch.setattr(api.artifacts, "list_reports", lambda *a, **k: [])
    body = client.get("/reports").json()
    assert body["reachable"] is False
    assert body["objects"] == []


def test_openapi_schema_documents_every_endpoint(client):
    paths = client.get("/openapi.json").json()["paths"]
    for p in ("/health", "/webhook/pr", "/review/{thread_id}",
              "/review/{thread_id}/resume", "/reports"):
        assert p in paths
