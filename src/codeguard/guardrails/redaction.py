"""Data-protection guardrail: mask secrets and PII **before** text reaches the LLM.

Deliverable 4 requires that raw credentials never enter a prompt or a trace. The
secret scanner masks its own output, but that is not sufficient on its own, and
running the system proved it: two other paths carried raw values to the model.

* ``read_file`` returned source verbatim — including the AWS key on line 8.
* ``bandit`` quoted the password back inside its own ``issue_text`` and ``code``
  fields, so even a security tool leaked it.

Masking inside each tool would therefore be a guarantee that holds until someone
adds the next tool. Instead redaction is applied at the single choke point every
tool result passes through on its way to the model — ``registry.dispatch`` — plus
on attacker-controlled PR text. A new tool inherits the protection by default.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from codeguard.tools.secret_scanner import (
    _ASSIGNMENT,
    _PATTERNS,
    ENTROPY_MIN_LENGTH,
    ENTROPY_THRESHOLD,
    mask,
    shannon_entropy,
)

# Values that are never worth masking: masking them would mangle ordinary code
# without protecting anything.
_SAFE_VALUES = {"true", "false", "none", "null", "test", "example", "changeme"}
_MIN_MASKABLE_LEN = 4


@dataclass
class RedactionResult:
    text: str
    masked_count: int = 0
    rules_triggered: list[str] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def triggered(self) -> bool:
        return self.masked_count > 0


def _collect(text: str) -> list[tuple[str, str]]:
    """Find every secret-like value in ``text`` as ``(rule_id, raw_value)``."""
    found: list[tuple[str, str]] = []
    for rule_id, _name, pattern, _sev, _cat in _PATTERNS:
        for m in pattern.finditer(text):
            raw = m.group(1) if m.groups() else m.group(0)
            if raw and len(raw) >= _MIN_MASKABLE_LEN and raw.lower() not in _SAFE_VALUES:
                found.append((rule_id, raw))

    for m in _ASSIGNMENT.finditer(text):
        value = m.group(2)
        if (
            len(value) >= ENTROPY_MIN_LENGTH
            and shannon_entropy(value) >= ENTROPY_THRESHOLD
            and value.lower() not in _SAFE_VALUES
        ):
            found.append(("HIGH_ENTROPY_STRING", value))
    return found


def redact(text: str, *, source: str = "") -> RedactionResult:
    """Replace every detected secret or piece of PII with an irreversible mask.

    Masks are substituted for *every* occurrence of a value, not just the one the
    pattern matched, so a credential repeated in a diff and an error message is
    covered by a single detection.
    """
    if not text:
        return RedactionResult(text=text)

    # Tool results arrive JSON-serialised, where a source line reads
    # `DB_PASSWORD = \"Hunter2!Settlement\"`. Patterns anchored on a quote
    # character do not match an escaped quote, so detection also runs over a
    # quote-normalised copy. Replacement still happens on the original text —
    # the secret value itself appears literally in both.
    found = _collect(text)
    normalised = text.replace('\\"', '"').replace("\\'", "'")
    if normalised != text:
        found += _collect(normalised)
    if not found:
        return RedactionResult(text=text)

    out = text
    seen: set[str] = set()
    rules: list[str] = []
    events: list[dict[str, Any]] = []
    count = 0

    # Longest first: masking a substring before its container would corrupt the
    # longer match and leave part of the secret visible.
    for rule_id, raw in sorted(found, key=lambda p: len(p[1]), reverse=True):
        if raw in seen or raw not in out:
            continue
        seen.add(raw)
        replacement = mask(raw)
        occurrences = out.count(raw)
        out = out.replace(raw, replacement)
        count += occurrences
        if rule_id not in rules:
            rules.append(rule_id)
        events.append({
            "rule_id": rule_id,
            "occurrences": occurrences,
            "masked_as": replacement,
            "source": source,
        })

    return RedactionResult(text=out, masked_count=count, rules_triggered=rules, events=events)


def redact_text(text: str, *, source: str = "") -> str:
    """Convenience wrapper returning only the redacted string."""
    return redact(text, source=source).text


def assert_clean(text: str, secrets: list[str]) -> list[str]:
    """Return any of ``secrets`` still present in ``text``.

    Used by the evidence notebook to prove, by grep, that no raw secret reached
    the model. An empty list is the proof.
    """
    return [s for s in secrets if s and s in text]
