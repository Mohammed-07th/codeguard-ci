"""Input guardrail: prompt-injection detection on attacker-controlled PR text.

The threat is native to the domain rather than contrived. A pull request's title,
description and code comments are written by whoever opened the PR — including an
attacker — and they are fed to a model that decides whether to approve the merge.
A PR that instructs the reviewer to approve it is the obvious attack.

The guardrail runs **before any PR text reaches the LLM**. On a hit the review is
routed to ``blocked`` and never reaches the coordinator, so the payload is never
put in front of a model at all. Detection is layered:

* **instruction-override patterns** — "ignore all previous instructions"
* **authority spoofing** — fake ``SYSTEM:`` turns, forged sign-off claims
* **tool suppression** — text telling the reviewer not to run a scanner
* **verdict steering** — text dictating the output verdict

Known limitation, stated plainly because it is the honest position: this is
pattern-based, and pattern-based detection has bypasses. It is a filter, not a
proof. The measured block rate against an adversarial set is reported in
``docs/SECURITY.md`` rather than a claim of completeness.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from codeguard.obs.metrics import METRICS

# (rule_id, description, pattern)
INJECTION_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("INSTRUCTION_OVERRIDE", "Attempts to discard prior instructions",
     re.compile(r"(?i)\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b"
                r"(?:all\s+)?(?:previous|prior|earlier|above|system|initial)\b"
                r"[^.\n]{0,20}\b(?:instruction|prompt|rule|direction|message)")),
    # Higher recall, lower precision: a 200-character window that spans newlines,
    # to catch a payload deliberately interleaved with filler across lines. Kept
    # as its own rule rather than widening the one above, so the precision
    # tradeoff is visible in the audit log rather than hidden inside a quantifier.
    # Measured at 0 false positives on the benign controls, but that set is small
    # (3 samples) and does not license a general claim of precision.
    ("INSTRUCTION_OVERRIDE_SPANNING", "Instruction override split across lines",
     re.compile(r"(?i)\b(?:ignore|disregard|forget|override)\b[\s\S]{0,200}?\b"
                r"(?:all\s+)?(?:previous|prior|earlier|above)\b[\s\S]{0,60}?"
                r"\b(?:instruction|prompt|rule|direction)")),
    ("SYSTEM_SPOOF", "Forges a system or developer turn",
     re.compile(r"(?im)^\s*(?:#{0,3}\s*)?(?:system|developer|assistant)\s*:\s*\S")),
    ("ROLE_REASSIGNMENT", "Tries to reassign the model's role or mode",
     re.compile(r"(?i)\byou\s+are\s+now\b|\bnew\s+instructions?\b|"
                r"\b(?:maintenance|debug|developer|god)\s+mode\b|"
                r"\bact\s+as\s+(?:a\s+)?(?:different|new)\b")),
    ("TOOL_SUPPRESSION", "Tells the reviewer not to run its tools",
     re.compile(r"(?i)\b(?:do\s+not|don't|never|skip|avoid|refrain\s+from)\b"
                r"[^.\n]{0,50}\b(?:run|call|invoke|use|execute)\b[^.\n]{0,40}"
                r"(?:scanner|scan|tool|bandit|ruff|analysis|check|test)")),
    ("VERDICT_STEERING", "Dictates the review outcome",
     re.compile(r"(?i)(?:\b(?:output|return|respond\s+with|reply\s+with|give)\b"
                r"[^.\n]{0,40}\b(?:verdict\s+)?(?:APPROVE|BLOCK_MERGE|REQUEST_CHANGES)\b"
                r"|\bverdict\s*[:=]?\s*approve\b)")),
    ("FORGED_APPROVAL", "Claims a human or team already signed off",
     re.compile(r"(?i)(?:\b(?:pre-?approved|already\s+(?:approved|reviewed|signed)|"
                r"signed\s+off|whitelisted|exempt)\b[^.\n]{0,60}"
                r"(?:by\s+)?(?:the\s+)?(?:security|ciso|team|management|admin|compliance)"
                r"|\b(?:security\s+team|ciso)\b[^.\n]{0,40}\b(?:approved|signed\s+off))")),
    ("REVIEWER_ADDRESS", "Text addressed to the automated reviewer itself",
     re.compile(r"(?i)\b(?:note|message|instruction)s?\s+(?:for|to)\s+the\s+"
                r"(?:automated\s+)?(?:reviewer|ai|agent|bot|llm|assistant)")),
    ("SECURITY_BYPASS", "Asserts that security review is unnecessary",
     re.compile(r"(?i)\bsecurity\s+(?:analysis|review|scan|check)\b[^.\n]{0,30}"
                r"\b(?:is\s+)?(?:not\s+required|unnecessary|not\s+needed|can\s+be\s+skipped)")),
    # Arabic-language injection. PR text is attacker-controlled and carries no
    # obligation to be in English; an English-only filter is trivially bypassed
    # by writing the same instruction in another language.
    ("INSTRUCTION_OVERRIDE_AR", "Instruction override written in Arabic",
     re.compile(r"(?:تجاهل|تجاهلي|أهمل|انس)\s*(?:جميع|كل|كافة)?\s*"
                r"(?:التعليمات|الأوامر|التوجيهات)")),
    ("FORGED_APPROVAL_AR", "Claims prior sign-off, written in Arabic",
     re.compile(r"(?:تمت\s*)?الموافق[ةه]\s*(?:على)?[^.\n]{0,40}"
                r"(?:مسبق(?:اً|ا)|من\s*قبل\s*فريق|الأمن)")),
    ("TOOL_SUPPRESSION_AR", "Tells the reviewer not to run its tools, in Arabic",
     re.compile(r"لا\s*(?:تقم\s*ب)?(?:تشغيل|تفحص|تستخدم|تنفذ)[^.\n]{0,40}"
                r"(?:الفحص|الأدوات|أدوات|الماسح)")),
    ("VERDICT_STEERING_AR", "Dictates the verdict, in Arabic",
     re.compile(r"(?:أصدر|اصدر|أعط|اعط)\s*(?:الحكم|القرار)[^.\n]{0,30}"
                r"(?:بالموافقة|بالقبول)")),
]

# Blobs worth decoding before scanning. Base64 is the common wrapper for a
# payload an attacker wants a pattern matcher to skip over.
_B64_BLOB = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")


@dataclass
class InjectionVerdict:
    blocked: bool = False
    matches: list[dict[str, Any]] = field(default_factory=list)
    scanned_sources: list[str] = field(default_factory=list)

    @property
    def rule_ids(self) -> list[str]:
        return sorted({m["rule_id"] for m in self.matches})

    def to_event(self) -> dict[str, Any]:
        return {
            "guardrail": "prompt_injection",
            "blocked": self.blocked,
            "rule_ids": self.rule_ids,
            "match_count": len(self.matches),
            "matches": self.matches,
            "scanned_sources": self.scanned_sources,
        }


class InjectionBlocked(RuntimeError):
    """Raised when PR text carries a prompt-injection payload."""

    def __init__(self, verdict: InjectionVerdict) -> None:
        super().__init__(
            f"Prompt injection detected ({', '.join(verdict.rule_ids)}); "
            f"{len(verdict.matches)} match(es). PR text was not sent to the model."
        )
        self.verdict = verdict


def normalise(text: str) -> str:
    """Fold obfuscation that would otherwise slip past a literal pattern match.

    Unicode homoglyphs and zero-width characters are a standard evasion: "ignore"
    written with a Cyrillic 'о' is a different byte string but the same
    instruction to a model. NFKC folds most homoglyphs; zero-width characters are
    stripped; runs of whitespace are collapsed.
    """
    if not text:
        return ""
    folded = unicodedata.normalize("NFKC", text)
    folded = re.sub(r"[​-‏‪-‮﻿­]", "", folded)
    return re.sub(r"[ \t]+", " ", folded)


def _excerpt(text: str, start: int, end: int, width: int = 90) -> str:
    lo = max(0, start - width // 3)
    hi = min(len(text), end + width // 3)
    return ("…" if lo > 0 else "") + text[lo:hi].replace("\n", " ⏎ ") + ("…" if hi < len(text) else "")


def decode_embedded_blobs(text: str) -> list[tuple[str, str]]:
    """Decode base64 blobs so a wrapped payload is scanned as text.

    Returns ``(blob_prefix, decoded_text)`` for anything that decodes to
    plausible text. Undecodable or binary results are dropped, so ordinary
    hashes and keys — which decode to noise — cost nothing but a check.
    """
    out: list[tuple[str, str]] = []
    for m in _B64_BLOB.finditer(text):
        blob = m.group(0)
        padded = blob + "=" * (-len(blob) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        printable = sum(c.isprintable() or c.isspace() for c in decoded)
        if decoded.strip() and printable / max(len(decoded), 1) > 0.9:
            out.append((blob[:24], decoded))
    return out


def detect_injection(sources: dict[str, str]) -> InjectionVerdict:
    """Scan named text sources for injection payloads.

    Args:
        sources: ``{"pr_title": ..., "pr_description": ..., "diff": ...}``.
    """
    verdict = InjectionVerdict(scanned_sources=[k for k, v in sources.items() if v])

    def _scan(text: str, source_name: str, via: str = "") -> None:
        for rule_id, description, pattern in INJECTION_PATTERNS:
            for m in pattern.finditer(text):
                verdict.matches.append({
                    "rule_id": rule_id + ("_ENCODED" if via else ""),
                    "description": description + (f" (recovered from {via})" if via else ""),
                    "source": source_name,
                    "matched_text": m.group(0)[:120],
                    # Excerpt is for the audit log; it is deliberately short and
                    # is never fed back to a model.
                    "excerpt": _excerpt(text, m.start(), m.end()),
                })

    for source_name, raw in sources.items():
        if not raw:
            continue
        text = normalise(raw)
        _scan(text, source_name)
        for prefix, decoded in decode_embedded_blobs(text):
            _scan(normalise(decoded), source_name, via=f"base64 blob '{prefix}…'")

    verdict.blocked = bool(verdict.matches)
    return verdict


def check_and_log(sources: dict[str, str], *, enabled: bool = True) -> InjectionVerdict:
    """Run detection and record the outcome in metrics.

    When ``enabled`` is False the scan still runs and is still logged, but the
    verdict is forced to not-blocked. That is what makes the A/B evidence honest:
    the guardrail-off run shows exactly what *would* have been caught.
    """
    verdict = detect_injection(sources)
    detected = verdict.blocked
    if not enabled:
        verdict.blocked = False

    METRICS.log_guardrail(
        guardrail="prompt_injection",
        triggered=detected,
        detail=(
            f"{len(verdict.matches)} match(es) across {verdict.scanned_sources}"
            + ("" if enabled else "  [GUARDRAIL DISABLED — not blocking]")
        ),
        matched_pattern=",".join(verdict.rule_ids),
        excerpt=verdict.matches[0]["excerpt"][:200] if verdict.matches else "",
    )
    return verdict
