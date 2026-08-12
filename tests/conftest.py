"""Test isolation.

Metrics, prompt logs and traces are *evidence artifacts*: the numbers in
``evidence/`` are meant to describe real reviews. A test run writing into the
same files corrupts that — it already happened once, when a simulated 429 from
tests/test_resilience.py was picked up and reported as genuine upstream rate
limiting in the observability evidence.

Every test therefore writes to a temporary directory instead.
"""

from __future__ import annotations

import pytest

from codeguard.obs import metrics as metrics_mod
from codeguard.obs import tracing as tracing_mod


@pytest.fixture(autouse=True)
def isolate_evidence(tmp_path, monkeypatch):
    """Redirect every artifact sink at a per-test temp directory."""
    monkeypatch.setattr(metrics_mod.METRICS, "path", tmp_path / "metrics.jsonl")
    monkeypatch.setattr(metrics_mod.PROMPTS, "path", tmp_path / "prompts.jsonl")
    # Spans are exported by a provider installed once per process; point the
    # file exporter at the temp dir so trace evidence is not appended to either.
    for proc in getattr(tracing_mod._provider, "_active_span_processor", None). \
            __dict__.get("_span_processors", ()) if tracing_mod._provider else ():
        exporter = getattr(proc, "span_exporter", None)
        if isinstance(exporter, tracing_mod.JsonlSpanExporter):
            monkeypatch.setattr(exporter, "path", tmp_path / "traces.jsonl")
    yield
