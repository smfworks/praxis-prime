"""Redaction before a memory write.

Secrets are stripped by default. Broader PII patterns run when
``memory.redact`` is ``pii``, or when HIPAA, FERPA, or GDPR is monitor or
enforce. Retention windows for those dials are technical defaults from
ARCHITECTURE §17, not legal advice. Dials that are off add no rule.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?i)\b(?:api[_-]?key|token|secret|password|authorization)\b\s*[:=]\s*\S+"
    ),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}"),
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
    ),
)

_PII_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    re.compile(
        r"\b(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}\b"
    ),
)

_HIPAA_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bMRN\s*[:=#]?\s*[A-Z0-9-]{4,}"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
)

_FERPA_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bstudent\s*id\s*[:=#]?\s*\S+"),
)

_DIAL_REDACT = ("hipaa", "ferpa", "gdpr")
_REDACT_MODES = {"off", "secrets", "pii"}


def normalize_redact_mode(value: str) -> str:
    mode = value.strip().lower()
    if mode not in _REDACT_MODES:
        return "secrets"
    return mode


def redact_text(text: str, *, mode: str, dials: Mapping[str, str]) -> str:
    """Return ``text`` with the active patterns replaced by ``[redacted]``."""
    patterns: list[re.Pattern[str]] = []
    effective = normalize_redact_mode(mode)
    dial_on = {
        dial_id: dials.get(dial_id, "off") in {"monitor", "enforce"}
        for dial_id in _DIAL_REDACT
    }
    if effective == "off" and not any(dial_on.values()):
        return text
    if effective in {"secrets", "pii"}:
        patterns.extend(_SECRET_PATTERNS)
    if effective == "pii" or any(dial_on.values()):
        patterns.extend(_PII_PATTERNS)
    if dial_on["hipaa"]:
        patterns.extend(_HIPAA_PATTERNS)
    if dial_on["ferpa"]:
        patterns.extend(_FERPA_PATTERNS)
    cleaned = text
    for pattern in patterns:
        cleaned = pattern.sub("[redacted]", cleaned)
    return cleaned


def retention_days(
    tier: str,
    dials: Mapping[str, str],
    *,
    episodic_ttl_days: int,
) -> int | None:
    """Shortest enforce-mode window, or the episodic default.

    Monitor does not expire rows. Enforce uses the strictest (smallest)
    day count among the dials that name one. Profile and semantic rows
    expire only when an enforce dial sets a window.
    """
    limits: list[int] = []
    if tier == "episodic":
        limits.append(episodic_ttl_days)
    if dials.get("gdpr") == "enforce":
        limits.append(30)
    if dials.get("ferpa") == "enforce":
        limits.append(365)
    if dials.get("hipaa") == "enforce":
        limits.append(2190)
    if not limits:
        return None
    return min(limits)
