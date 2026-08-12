"""Resilience: model fallback and retry, proven without the network.

The router layers two independent mechanisms and they must not be confused:

* ``.with_fallbacks()`` — inner. A *model* failed; try a different model.
* ``tenacity`` — outer. A *transport* fault; try the same call again.

A 429 is deliberately excluded from the retry set: the fallback handles rate
limits, and retrying would just wait for the same limit.
"""

from __future__ import annotations

import httpx
import openai
import pytest
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.runnables import RunnableLambda

from codeguard.llm.router import LLMRouter, _simulated_rate_limit
from codeguard.obs.metrics import METRICS, run_context


def _ok_message(model: str = "fallback/model"):
    """A runnable standing in for a healthy provider."""
    return RunnableLambda(lambda _: AIMessage(
        content="fallback answered",
        response_metadata={"model_name": model},
        usage_metadata={"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
    ))


def _raises(exc: Exception):
    def _boom(_):
        raise exc
    return RunnableLambda(_boom)


@pytest.fixture()
def router(monkeypatch):
    """A router whose model construction is replaced, but whose routing is real."""
    r = LLMRouter()
    monkeypatch.setattr(r, "_prepare", lambda model, *a, **k: _ok_message(model))
    return r


# --- the simulated fault itself -----------------------------------------------

def test_simulated_rate_limit_raises_a_genuine_429():
    """The forced failure must be a real provider exception, not a stand-in."""
    with pytest.raises(openai.RateLimitError) as exc:
        _simulated_rate_limit(None)
    assert exc.value.response.status_code == 429


# --- fallback -----------------------------------------------------------------

def test_forced_primary_failure_is_absorbed_by_the_fallback(router):
    with run_context("t-forced-429", "PROBE"):
        result = router.invoke(
            [HumanMessage(content="hi")], tag="test.forced", force_primary_error=True
        )
    assert result.message.content == "fallback answered"
    assert result.fallback_used is True
    assert result.actual_model != result.requested_model


def test_fallback_reason_records_why_the_primary_failed(router):
    """Monitoring must explain a fallback storm, not just count it."""
    with run_context("t-reason", "PROBE"):
        router.invoke([HumanMessage(content="hi")], tag="test.reason",
                      force_primary_error=True)
    row = [r for r in METRICS.read("t-reason") if r["kind"] == "llm"][-1]
    assert row["fallback_used"] is True
    assert "RateLimitError" in (row["fallback_reason"] or "")


def test_healthy_primary_does_not_engage_the_fallback(router):
    """The negative case: with the primary up, no failover should be recorded."""
    with run_context("t-healthy", "PROBE"):
        result = router.invoke([HumanMessage(content="hi")], tag="test.healthy")
    assert result.fallback_used is False
    assert result.actual_model == result.requested_model


def test_fallback_target_is_never_the_model_that_just_failed(router):
    """Synthesis and the configured fallback are the same model here."""
    assert router.fallback_for(router.settings.fallback_model) == router.settings.primary_model
    assert router.fallback_for(router.settings.primary_model) == router.settings.fallback_model


def test_failure_of_both_models_propagates(monkeypatch):
    """Silent success on total outage would be worse than an error."""
    r = LLMRouter()
    err = openai.RateLimitError(
        "both down",
        response=httpx.Response(429, request=httpx.Request("POST", "https://x")),
        body=None,
    )
    monkeypatch.setattr(r, "_prepare", lambda model, *a, **k: _raises(err))
    with run_context("t-bothdown", "PROBE"), pytest.raises(openai.RateLimitError):
        r.invoke([HumanMessage(content="hi")], tag="test.bothdown")
    row = [x for x in METRICS.read("t-bothdown") if x["kind"] == "llm"][-1]
    assert row["ok"] is False


# --- retry --------------------------------------------------------------------

def test_transient_transport_fault_is_retried(monkeypatch):
    """A connection error is retried; the call ultimately succeeds."""
    r = LLMRouter()
    calls = {"n": 0}

    def flaky(_):
        calls["n"] += 1
        if calls["n"] < 2:
            raise openai.APIConnectionError(request=httpx.Request("POST", "https://x"))
        return AIMessage(content="recovered",
                         response_metadata={"model_name": "primary/model"},
                         usage_metadata={"input_tokens": 1, "output_tokens": 1,
                                         "total_tokens": 2})

    monkeypatch.setattr(r, "_prepare", lambda model, *a, **k: RunnableLambda(flaky))
    with run_context("t-retry", "PROBE"):
        result = r.invoke([HumanMessage(content="hi")], tag="test.retry",
                          with_fallback=False)
    assert result.message.content == "recovered"
    assert result.attempts >= 2


def test_rate_limits_are_not_retried(monkeypatch):
    """429 belongs to the fallback layer; retrying would just wait for the same limit."""
    r = LLMRouter()
    calls = {"n": 0}

    def always_429(_):
        calls["n"] += 1
        raise openai.RateLimitError(
            "limited",
            response=httpx.Response(429, request=httpx.Request("POST", "https://x")),
            body=None,
        )

    monkeypatch.setattr(r, "_prepare", lambda model, *a, **k: RunnableLambda(always_429))
    with run_context("t-no-retry", "PROBE"), pytest.raises(openai.RateLimitError):
        r.invoke([HumanMessage(content="hi")], tag="test.noretry", with_fallback=False)
    assert calls["n"] == 1, f"429 was retried {calls['n']} times; it should not be"


# --- cost cap -----------------------------------------------------------------

def test_cost_cap_aborts_a_runaway_run(monkeypatch):
    """An unbounded agent loop must not be able to spend without limit."""
    from codeguard.llm.router import CostCapExceeded

    r = LLMRouter()
    monkeypatch.setattr(r, "_prepare", lambda model, *a, **k: RunnableLambda(
        lambda _: AIMessage(
            content="x", response_metadata={"model_name": "openai/gpt-4o"},
            usage_metadata={"input_tokens": 1_000_000, "output_tokens": 1_000_000,
                            "total_tokens": 2_000_000})))
    r.settings.cost_cap_usd = 1.0
    with run_context("t-cap", "PROBE"), pytest.raises(CostCapExceeded):
        r.invoke([HumanMessage(content="hi")], tag="test.cap", with_fallback=False)
