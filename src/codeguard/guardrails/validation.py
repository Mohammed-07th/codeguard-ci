"""Output guardrail: schema enforcement with a repair retry.

Every agent must return a schema-valid Pydantic object. Free-tier models are
noticeably worse at this than frontier models, so a single malformed reply must
not take down a review.

On a validation failure the model is shown *its own invalid output and the
specific error*, then asked once to repair it. One retry only: if a model cannot
produce the schema twice, the correct behaviour is to fail loudly and let the
graph record a degraded agent rather than to invent findings.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, TypeVar

from pydantic import BaseModel, ValidationError

from codeguard.obs.metrics import METRICS

log = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class SchemaValidationFailed(RuntimeError):
    """Raised when an agent could not produce schema-valid output, even after repair."""


def validate_or_repair(
    schema: type[T],
    first_attempt: Any,
    repair_fn: Callable[[str], Any],
    *,
    agent: str,
) -> T:
    """Return a schema-valid object, retrying once with the validation error.

    Args:
        schema: The Pydantic model the agent must produce.
        first_attempt: Whatever the model returned (parsed object, dict, or None).
        repair_fn: Called with a corrective instruction; returns a second attempt.
        agent: Agent name, for the metrics row.

    Raises:
        SchemaValidationFailed: if both attempts are invalid.
    """
    ok, err = _coerce(schema, first_attempt)
    if ok is not None:
        return ok

    METRICS.log_guardrail(
        guardrail="output_schema_validation",
        triggered=True,
        detail=f"{agent}: first attempt invalid, requesting repair",
        matched_pattern=schema.__name__,
        excerpt=str(err)[:300],
    )
    log.warning("%s produced invalid %s, repairing: %s", agent, schema.__name__, err)

    instruction = (
        f"Your previous response did not match the required {schema.__name__} schema.\n"
        f"Validation error:\n{err}\n\n"
        "Return a corrected response that matches the schema exactly. "
        "Do not add commentary or explanation outside the structured fields."
    )
    second, err2 = _coerce(schema, repair_fn(instruction))
    if second is not None:
        METRICS.log_guardrail(
            guardrail="output_schema_validation",
            triggered=True,
            detail=f"{agent}: repair succeeded",
            matched_pattern=schema.__name__,
        )
        return second

    METRICS.log_guardrail(
        guardrail="output_schema_validation",
        triggered=True,
        detail=f"{agent}: repair FAILED, agent degraded",
        matched_pattern=schema.__name__,
        excerpt=str(err2)[:300],
    )
    raise SchemaValidationFailed(
        f"{agent} could not produce a valid {schema.__name__} after one repair "
        f"attempt. First error: {err}. Second error: {err2}"
    )


def _coerce(schema: type[T], value: Any) -> tuple[T | None, str | None]:
    """Try to turn ``value`` into ``schema``. Returns ``(obj, None)`` or ``(None, error)``."""
    if value is None:
        return None, "model returned no parsed output"
    if isinstance(value, schema):
        return value, None
    try:
        if isinstance(value, dict):
            return schema.model_validate(value), None
        if isinstance(value, str):
            return schema.model_validate_json(value), None
        return schema.model_validate(value), None
    except ValidationError as e:
        return None, _summarise(e)
    except (TypeError, ValueError) as e:
        return None, f"{type(e).__name__}: {e}"


def _summarise(exc: ValidationError, limit: int = 6) -> str:
    """Compact, model-readable rendering of a Pydantic validation error."""
    lines = []
    for err in exc.errors()[:limit]:
        loc = ".".join(str(p) for p in err.get("loc", ())) or "<root>"
        lines.append(f"  - {loc}: {err.get('msg')}")
    extra = len(exc.errors()) - limit
    if extra > 0:
        lines.append(f"  - ... and {extra} more")
    return "\n".join(lines)
