"""Custom secret scanner: named credential patterns plus Shannon-entropy detection.

Two detectors, because either alone misses real leaks:

* **Pattern rules** catch credentials with a recognisable shape (``AKIA...``,
  ``ghp_...``, PEM blocks). High precision, zero recall on anything novel.
* **Entropy analysis** catches the rest. A random 32-character string assigned to
  something called ``token`` is suspicious regardless of issuer, and Shannon
  entropy is what separates ``"aaaaaaaaaaaa"`` from ``"xK9$mQ2vLp8wR4nT"``.

Every match is **masked at the point of detection**. The raw secret never leaves
this module, so it cannot reach a prompt, a log, a trace, or a finding. That is
what makes the Deliverable-4 grep proof possible.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# --- what counts as a secret -------------------------------------------------
# (rule_id, human name, compiled pattern, severity hint, category)
_PATTERNS: list[tuple[str, str, re.Pattern[str], str, str]] = [
    ("AWS_ACCESS_KEY", "AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical", "secret"),
    ("AWS_SECRET_KEY", "AWS secret access key",
     re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"), "critical", "secret"),
    ("GITHUB_TOKEN", "GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "critical", "secret"),
    ("SLACK_TOKEN", "Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "high", "secret"),
    ("PRIVATE_KEY", "Private key block",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "critical", "secret"),
    ("JWT", "JSON Web Token",
     re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "high", "secret"),
    # The optional `(?:[A-Za-z0-9_]*_)?` prefix is load-bearing: `_` is a word
    # character, so a plain \b before "password" cannot match inside an
    # identifier like DB_PASSWORD or TEST_DB_PASSWORD — which is exactly how
    # credentials are named in practice.
    ("HARDCODED_PASSWORD", "Hardcoded password",
     re.compile(r"(?i)\b(?:[A-Za-z0-9]+[_-])*(?:password|passwd|pwd)[A-Za-z0-9_]*"
                r"\s*[:=]\s*['\"]([^'\"\s]{4,})['\"]"),
     "high", "secret"),
    ("GENERIC_API_KEY", "Hardcoded API key/token",
     re.compile(r"(?i)\b(?:[A-Za-z0-9]+[_-])*"
                r"(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key)"
                r"[A-Za-z0-9_]*\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"),
     "high", "secret"),
    # --- PII, protected by the same redaction path ---
    ("EMAIL", "Email address (PII)",
     re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "medium", "secret"),
    ("IBAN", "IBAN (financial PII)",
     re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b"), "high", "secret"),
    ("SA_NATIONAL_ID", "Saudi national ID (PII)",
     re.compile(r"(?<![\d.])[12]\d{9}(?![\d.])"), "high", "secret"),
]

# Assignments worth entropy-testing even when no named pattern matches.
_ASSIGNMENT = re.compile(
    r"(?i)\b([A-Za-z_][A-Za-z0-9_]*(?:key|token|secret|password|passwd|pwd|credential|auth)[A-Za-z0-9_]*)"
    r"\s*[:=]\s*['\"]([^'\"\s]{16,})['\"]"
)

ENTROPY_THRESHOLD = 4.0
ENTROPY_MIN_LENGTH = 20

# Files whose secrets are conventionally non-production. Not auto-dismissed here —
# the scanner only records the hint, and SecurityAgent makes the triage call.
_TEST_PATH_HINTS = ("test", "tests", "conftest", "fixture", "fixtures", "example", "sample", "mock")


def shannon_entropy(s: str) -> float:
    """Bits of entropy per character. Random secrets score high, English prose low."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def mask(secret: str, keep: int = 4) -> str:
    """Irreversibly mask a secret, keeping a short prefix so findings stay actionable."""
    if not secret:
        return ""
    if len(secret) <= keep:
        return "*" * len(secret)
    return f"{secret[:keep]}{'*' * min(len(secret) - keep, 16)}(len={len(secret)})"


@dataclass
class SecretHit:
    rule_id: str
    rule_name: str
    file: str
    line: int
    masked_match: str
    severity_hint: str
    entropy: float = 0.0
    in_test_path: bool = False
    line_excerpt: str = ""          # already masked
    detector: str = "pattern"       # "pattern" | "entropy"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "file": self.file,
            "line": self.line,
            "masked_match": self.masked_match,
            "severity_hint": self.severity_hint,
            "entropy": round(self.entropy, 2),
            "in_test_path": self.in_test_path,
            "line_excerpt": self.line_excerpt,
            "detector": self.detector,
        }


@dataclass
class ScanResult:
    scanned_files: list[str] = field(default_factory=list)
    hits: list[SecretHit] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "secret_scanner",
            "scanned_files": self.scanned_files,
            "hit_count": len(self.hits),
            "hits": [h.to_dict() for h in self.hits],
            "errors": self.errors,
        }


def _mask_line(line: str, secrets: list[str]) -> str:
    """Return the source line with every detected secret replaced by its mask."""
    out = line.strip()
    for s in sorted(set(secrets), key=len, reverse=True):
        if s:
            out = out.replace(s, mask(s))
    return out[:200]


def _is_test_path(path: str) -> bool:
    low = path.lower()
    return any(h in low for h in _TEST_PATH_HINTS)


def scan_text(text: str, filename: str = "<text>") -> list[SecretHit]:
    """Scan an in-memory blob (a diff, a PR description) for secrets and PII."""
    hits: list[SecretHit] = []
    in_test = _is_test_path(filename)

    for lineno, line in enumerate(text.splitlines(), start=1):
        matched_secrets: list[str] = []
        line_hits: list[SecretHit] = []

        for rule_id, rule_name, pattern, sev, _cat in _PATTERNS:
            for m in pattern.finditer(line):
                raw = m.group(1) if m.groups() else m.group(0)
                matched_secrets.append(raw)
                line_hits.append(
                    SecretHit(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        file=filename,
                        line=lineno,
                        masked_match=mask(raw),
                        severity_hint=sev,
                        entropy=shannon_entropy(raw),
                        in_test_path=in_test,
                        detector="pattern",
                    )
                )

        # Entropy pass: only for assignments no named rule already claimed.
        for m in _ASSIGNMENT.finditer(line):
            var_name, value = m.group(1), m.group(2)
            if value in matched_secrets:
                continue
            ent = shannon_entropy(value)
            if ent >= ENTROPY_THRESHOLD and len(value) >= ENTROPY_MIN_LENGTH:
                matched_secrets.append(value)
                line_hits.append(
                    SecretHit(
                        rule_id="HIGH_ENTROPY_STRING",
                        rule_name=f"High-entropy value assigned to {var_name!r}",
                        file=filename,
                        line=lineno,
                        masked_match=mask(value),
                        severity_hint="high",
                        entropy=ent,
                        in_test_path=in_test,
                        detector="entropy",
                    )
                )

        if line_hits:
            excerpt = _mask_line(line, matched_secrets)
            for h in line_hits:
                h.line_excerpt = excerpt
            hits.extend(line_hits)

    return hits


def scan_paths(paths: list[Path], root: Path | None = None) -> ScanResult:
    """Scan files on disk. Paths are expected to be pre-validated by the sandbox."""
    result = ScanResult()
    for p in paths:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError) as e:
            result.errors.append(f"{p}: {type(e).__name__}: {e}")
            continue
        name = str(p.relative_to(root)) if root and root in p.parents else str(p)
        result.scanned_files.append(name)
        result.hits.extend(scan_text(text, filename=name))
    return result
