"""Distributed tracing: OpenTelemetry spans for every LLM call, tool call and node.

Deliverable 4 asks for tracing that captures tool calls, latency and failures.
Three span sources feed one trace per review:

* **LLM spans** from ``openinference-instrumentation-langchain``, which hooks
  LangChain's callback system and records prompts, models and token usage.
* **Tool spans** emitted by ``registry.dispatch`` — every analyser invocation.
* **Node spans** emitted around each graph node, so the waterfall shows the
  actual shape of the review: the three specialists overlapping in the fan-out,
  then the synthesizer serialising behind them.

A note on Phoenix. The ``arize-phoenix`` Python package cannot be imported on
Python 3.11 in this environment — ``phoenix.otel.register`` and
``px.launch_app`` both raise ``ValueError: mutable default <class
'mappingproxy'> for field boolean_names``, an upstream dataclass bug (the same
one that breaks its pytest plugin). That is a library defect, not a
configuration mistake, and it is not worth monkeypatching.

It does not cost us the tracing story: Phoenix is an OTLP collector, so we speak
OTLP to it over HTTP and run the Phoenix *server* as a container instead of
importing its client. Spans are additionally written to ``evidence/traces.jsonl``
by a local exporter, so the trace evidence is durable and inspectable whether or
not a collector is listening.
"""

from __future__ import annotations

import json
import logging
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Sequence

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)

from codeguard.config import PROJECT_ROOT, get_settings

log = logging.getLogger(__name__)

SERVICE_NAME = "codeguard-ci"
_provider: TracerProvider | None = None
_lock = threading.Lock()


class JsonlSpanExporter(SpanExporter):
    """Writes finished spans to a JSONL file.

    Exists so trace evidence survives without a collector: an evaluator can read
    ``evidence/traces.jsonl`` directly, and the notebook renders the waterfall
    from it rather than depending on a running Phoenix instance.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        p = Path(path) if path else PROJECT_ROOT / "evidence" / "traces.jsonl"
        self.path = p if p.is_absolute() else PROJECT_ROOT / p
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        from codeguard.guardrails.redaction import redact_text

        rows = []
        for s in spans:
            ctx = s.get_span_context()
            rows.append({
                "trace_id": format(ctx.trace_id, "032x"),
                "span_id": format(ctx.span_id, "016x"),
                "parent_span_id": format(s.parent.span_id, "016x") if s.parent else None,
                "name": s.name,
                "start_time_ns": s.start_time,
                "end_time_ns": s.end_time,
                "duration_ms": round((s.end_time - s.start_time) / 1e6, 2)
                if s.end_time and s.start_time else None,
                "status": s.status.status_code.name if s.status else None,
                # Defence in depth. Spans from OpenInference record whole
                # runnable inputs and outputs, including state we do not
                # construct, so redaction is applied again on the way out
                # rather than trusting that nothing upstream leaked.
                "attributes": {
                    k: (redact_text(v, source=f"span:{s.name}") if isinstance(v, str)
                        else _jsonable(v))
                    for k, v in (s.attributes or {}).items()
                },
            })
        try:
            with self._lock, self.path.open("a", encoding="utf-8") as fh:
                for r in rows:
                    fh.write(json.dumps(r, default=str) + "\n")
        except OSError:
            return SpanExportResult.FAILURE
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:  # pragma: no cover - lifecycle hook
        return None


def _jsonable(v: Any) -> Any:
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    return str(v)


def _collector_reachable(endpoint: str, timeout: float = 0.4) -> bool:
    """Is a collector actually listening?

    Checked up front because ``BatchSpanProcessor`` retries with backoff and logs
    a stack trace per attempt when nothing is there. Phoenix is optional — it
    runs as a container and is frequently down during local work — so an absent
    collector should be silent, not noisy. File export is unaffected either way.
    """
    import socket
    from urllib.parse import urlparse

    parsed = urlparse(endpoint if "//" in endpoint else f"http://{endpoint}")
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        log.info("no OTLP collector at %s:%s; spans go to file only", host, port)
        return False


def setup_tracing(
    endpoint: str | None = None,
    *,
    to_file: bool = True,
    instrument_langchain: bool = True,
) -> TracerProvider:
    """Install the tracer provider. Idempotent — safe to call from any entrypoint."""
    global _provider
    with _lock:
        if _provider is not None:
            return _provider

        settings = get_settings()
        provider = TracerProvider(
            resource=Resource.create({
                "service.name": SERVICE_NAME,
                "service.version": "0.1.0",
            })
        )

        if to_file:
            # Simple (not batched) so spans land on disk even if the process is
            # killed — which the persistence proof does on purpose.
            provider.add_span_processor(SimpleSpanProcessor(JsonlSpanExporter()))

        if settings.phoenix_enabled and _collector_reachable(
            endpoint or settings.phoenix_collector_endpoint
        ):
            url = endpoint or f"{settings.phoenix_collector_endpoint.rstrip('/')}/v1/traces"
            try:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                    OTLPSpanExporter,
                )

                provider.add_span_processor(
                    BatchSpanProcessor(OTLPSpanExporter(endpoint=url, timeout=5))
                )
                log.info("OTLP span export enabled -> %s", url)
            except Exception as exc:  # noqa: BLE001 - collector is optional
                log.warning("OTLP exporter unavailable (%s); file export still active", exc)

        trace.set_tracer_provider(provider)

        if instrument_langchain:
            try:
                from openinference.instrumentation.langchain import LangChainInstrumentor

                LangChainInstrumentor().instrument(tracer_provider=provider)
                log.info("LangChain instrumented via OpenInference")
            except Exception as exc:  # noqa: BLE001
                log.warning("LangChain instrumentation unavailable: %s", exc)

        _provider = provider
        return provider


def get_tracer(name: str = SERVICE_NAME):
    return trace.get_tracer(name)


@contextmanager
def span(name: str, kind: str = "CHAIN", **attributes: Any) -> Iterator[Any]:
    """Emit one span. ``kind`` follows OpenInference conventions so Phoenix renders it."""
    tracer = get_tracer()
    with tracer.start_as_current_span(name) as sp:
        try:
            sp.set_attribute("openinference.span.kind", kind)
            for k, v in attributes.items():
                if v is not None:
                    sp.set_attribute(k, _jsonable(v))
        except Exception:  # noqa: BLE001 - tracing must never break the review
            pass
        try:
            yield sp
        except Exception as exc:
            try:
                sp.set_attribute("error.type", type(exc).__name__)
                sp.set_attribute("error.message", str(exc)[:300])
                sp.set_status(trace.Status(trace.StatusCode.ERROR, str(exc)[:300]))
            except Exception:  # noqa: BLE001
                pass
            raise


def flush_tracing(timeout_ms: int = 5000) -> None:
    """Force pending spans out before the process exits."""
    if _provider is not None:
        try:
            _provider.force_flush(timeout_millis=timeout_ms)
        except Exception:  # noqa: BLE001
            pass


def read_spans(path: Path | str | None = None) -> list[dict[str, Any]]:
    """Read back the exported spans — used by the evidence notebook."""
    p = Path(path) if path else PROJECT_ROOT / "evidence" / "traces.jsonl"
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def render_waterfall(spans: list[dict[str, Any]], trace_id: str | None = None) -> str:
    """Render a text waterfall from exported spans.

    The notebook shows this next to the Phoenix screenshot; unlike the
    screenshot it regenerates from data on every run, so it cannot go stale.
    """
    if not spans:
        return "(no spans recorded)"
    if trace_id is None:
        trace_id = max(
            {s["trace_id"] for s in spans},
            key=lambda t: sum(1 for s in spans if s["trace_id"] == t),
        )
    rows = sorted(
        (s for s in spans if s["trace_id"] == trace_id),
        key=lambda s: s.get("start_time_ns") or 0,
    )
    if not rows:
        return "(no spans for that trace)"

    t0 = rows[0]["start_time_ns"]
    span_end = max((r.get("end_time_ns") or t0) for r in rows)
    total = max(span_end - t0, 1)
    width = 46

    depth: dict[str, int] = {}
    for r in rows:
        parent = r.get("parent_span_id")
        depth[r["span_id"]] = depth.get(parent, -1) + 1 if parent in depth else 0

    lines = [f"trace {trace_id}  —  {len(rows)} spans, {total / 1e6:.0f} ms total", ""]
    for r in rows:
        start = ((r["start_time_ns"] - t0) / total) * width
        dur = (((r.get("end_time_ns") or r["start_time_ns"]) - r["start_time_ns"]) / total) * width
        bar = " " * int(start) + "█" * max(1, int(dur))
        label = "  " * depth.get(r["span_id"], 0) + r["name"]
        err = "  ERROR" if r.get("status") == "ERROR" else ""
        lines.append(f"  {label:<38}{bar:<{width + 2}}{r.get('duration_ms', 0):>8.0f}ms{err}")
    return "\n".join(lines)
