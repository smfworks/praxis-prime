"""Tier 0: deterministic rules.

Numbers, dates, allow/deny lists, and compliance-dial detectors decide here.
A dial rule runs only when that dial is ``monitor`` or ``enforce``. Dials
default to off, so these detectors stay quiet until a person turns one on.

Detectors are technical filters, not legal conclusions.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from praxis_prime.compliance.detectors import luhn_ok, ssn_parts_ok
from praxis_prime.compliance.evaluate import feed_tier0
from praxis_prime.compliance.packs import bundled_packs
from praxis_prime.decide.schema import Question

_COUNT = re.compile(
    r"(?i)\bhow many times does (?:the word |the phrase )?['\"]?([A-Za-z0-9_-]+)['\"]?"
)
_COUNT_OF = re.compile(r"(?i)\bcount (?:the )?(?:word |occurrences of )?['\"]?([A-Za-z0-9_-]+)")
_DATE_QUESTION = re.compile(r"(?i)\b(?:what|which) date\b")
_ISO_DATE = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")
_DENY_LABELS = {"deny", "no", "false", "block", "unsafe", "reject"}
_ALLOW_LABELS = {"allow", "yes", "true", "approve", "safe"}


@dataclass(frozen=True, slots=True)
class RuleHit:
    label: str
    confidence: float
    probabilities: dict[str, float]
    rationale: str


def evaluate_rules(
    question: Question,
    state: str,
    *,
    dials: Mapping[str, str],
    deny: tuple[str, ...],
    allow: tuple[str, ...],
) -> RuleHit | None:
    """Return a decisive hit, or None when no rule applies."""
    dial_hit = _dial_hit(question, state, dials)
    if dial_hit is not None:
        return dial_hit
    listed = _list_hit(question, state, deny=deny, allow=allow)
    if listed is not None:
        return listed
    counted = _count_hit(question, state)
    if counted is not None:
        return counted
    dated = _date_hit(question, state)
    if dated is not None:
        return dated
    return None


def _dial_hit(
    question: Question,
    state: str,
    dials: Mapping[str, str],
) -> RuleHit | None:
    if _on(dials, "pci") and _has_pan(state):
        hit = _pick(question, ("pci", "payment_card", "card", "pci_dss"), positive=True)
        if hit is not None:
            return RuleHit(hit, 1.0, _certain(question, hit), "PCI dial: payment-card number")
    if _on(dials, "hipaa") and _has_ssn(state):
        hit = _pick(question, ("phi", "hipaa", "medical"), positive=True)
        if hit is not None:
            return RuleHit(hit, 1.0, _certain(question, hit), "HIPAA dial: SSN-shaped identifier")
    if _on(dials, "state_nc") and _has_ssn(state):
        hit = _pick(question, ("nc_pii", "ncpii", "state_nc"), positive=True)
        if hit is not None:
            return RuleHit(
                hit,
                1.0,
                _certain(question, hit),
                "NC dial: SSN-shaped identifier (technical filter, not legal advice)",
            )
    for data_class, rationale in feed_tier0(state, dials, bundled_packs()):
        names = _CLASS_NAMES.get(data_class)
        if names is None:
            continue
        hit = _pick(question, names, positive=True)
        if hit is not None:
            return RuleHit(hit, 1.0, _certain(question, hit), rationale)
    return None


_CLASS_NAMES: dict[str, tuple[str, ...]] = {
    "PHI": ("phi", "hipaa", "medical"),
    "NC_PII": ("nc_pii", "ncpii", "state_nc"),
    "NC_SSN": ("nc_pii", "ncpii", "state_nc"),
    "PCI": ("pci", "payment_card", "card", "pci_dss"),
    "EDUCATION_RECORD": ("education_record", "ferpa", "student"),
    "CHILD_DATA": ("child", "coppa", "under_13"),
    "SPECIAL_CATEGORY": ("special_category", "gdpr", "sensitive"),
    "US_PII": ("us_pii", "personal_information", "pii"),
}


def _list_hit(
    question: Question,
    state: str,
    *,
    deny: tuple[str, ...],
    allow: tuple[str, ...],
) -> RuleHit | None:
    lowered = state.lower()
    if any(phrase.lower() in lowered for phrase in deny if phrase.strip()):
        label = _named(question, _DENY_LABELS)
        if label is None and question.type == "noul" and _about_permission(question):
            label = "false"
        if label is not None:
            return RuleHit(label, 1.0, _certain(question, label), "deny list matched the state")
    if any(phrase.lower() in lowered for phrase in allow if phrase.strip()):
        label = _named(question, _ALLOW_LABELS)
        if label is None and question.type == "noul" and _about_permission(question):
            label = "true"
        if label is not None:
            return RuleHit(label, 0.95, _certain(question, label), "allow list matched the state")
    return None


def _count_hit(question: Question, state: str) -> RuleHit | None:
    match = _COUNT.search(question.instructions) or _COUNT_OF.search(question.instructions)
    if match is None:
        return None
    word = match.group(1)
    count = len(re.findall(rf"(?i)\b{re.escape(word)}\b", state))
    label = _match_option(question, str(count))
    if label is None:
        return None
    return RuleHit(
        label,
        1.0,
        _certain(question, label),
        f"counted {count} occurrence(s) of {word}",
    )


def _date_hit(question: Question, state: str) -> RuleHit | None:
    if _DATE_QUESTION.search(question.instructions) is None:
        return None
    found = _ISO_DATE.findall(state)
    if len(found) != 1:
        return None
    label = _match_option(question, found[0])
    if label is None:
        return None
    return RuleHit(label, 1.0, _certain(question, label), "parsed an ISO date from the state")


def _pick(question: Question, names: tuple[str, ...], *, positive: bool) -> str | None:
    blob = _blob(question)
    if not any(name in blob for name in names) and question.type != "noul":
        return None
    if question.type == "noul":
        if not any(name in blob for name in names):
            return None
        return "true" if positive else "false"
    for option in question.options:
        if option.lower().replace("-", "_") in names or option.lower() in names:
            return option
    return None


def _named(question: Question, names: set[str]) -> str | None:
    for option in question.options:
        if option.lower() in names:
            return option
    return None


def _match_option(question: Question, wanted: str) -> str | None:
    for option in question.options:
        if option == wanted:
            return option
    return None


def _certain(question: Question, label: str) -> dict[str, float]:
    probabilities = dict.fromkeys(question.options, 0.0)
    if label not in probabilities:
        probabilities[label] = 1.0
        return probabilities
    probabilities[label] = 1.0
    return probabilities


def _about_permission(question: Question) -> bool:
    blob = _blob(question)
    return any(word in blob for word in ("safe", "allow", "approve", "proceed", "permit"))


def _blob(question: Question) -> str:
    parts = [question.instructions.lower(), *[option.lower() for option in question.options]]
    parts.extend(value.lower() for value in question.criteria.values())
    return " ".join(parts)


def _on(dials: Mapping[str, str], dial_id: str) -> bool:
    return dials.get(dial_id, "off") in {"monitor", "enforce"}


_PAN = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_SSN = re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b")


def _has_pan(state: str) -> bool:
    for match in _PAN.finditer(state):
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            return True
    return False


def _has_ssn(state: str) -> bool:
    for area, group, serial in _SSN.findall(state):
        if ssn_parts_ok(area, group, serial):
            return True
    return False
