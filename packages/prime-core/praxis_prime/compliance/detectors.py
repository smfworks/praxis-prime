"""Checksum and context detectors for compliance packs.

These are technical filters. A match is not a legal conclusion that a
statute applies. Invalid SSNs and numbers that fail the Luhn check are
rejected so ordinary digit strings do not become findings.

ARCHITECTURE §7.4 (T0) and §17.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_PHONE = re.compile(
    r"\b(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}\b"
)
_SSN = re.compile(r"(?<!\d)(\d{3})[-\s](\d{2})[-\s](\d{4})(?!\d)")
_NPI = re.compile(r"(?<!\d)(\d{10})(?!\d)")
_PAN = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_MRN = re.compile(
    r"(?i)\b(?:mrn|medical record(?:\s+number)?)\s*[:=#]?\s*([A-Z0-9\-]*\d[A-Z0-9\-]{3,})\b"
)
_DATE = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b|\b(\d{1,2}/\d{1,2}/\d{4})\b")
_DOB_WORD = re.compile(r"(?i)\b(?:d\.?o\.?b\.?|date of birth|birth date|born on|born)\b")
_AGE = re.compile(
    r"(?i)\b(?:age|aged)\s*[:=]?\s*(\d{1,2})\b|\b(\d{1,2})\s+years?\s+old\b"
)
_UNDER_13 = re.compile(r"(?i)\bunder[\s-]*13\b|\b(?:child|children|minor)\s+under\s+13\b")
_NAME = re.compile(r"\b[A-Z][a-z]{1,20}\s+[A-Z][a-z]{1,20}\b")
_ACCOUNT = re.compile(r"(?<!\d)(\d{8,17})(?!\d)")


@dataclass(frozen=True, slots=True)
class DetectorSpec:
    id: str
    kind: str
    data_classes: tuple[str, ...]
    context: tuple[str, ...] = ()
    pattern: str = ""
    terms: tuple[str, ...] = ()
    window: int = 96


@dataclass(frozen=True, slots=True)
class Hit:
    detector_id: str
    data_class: str
    kind: str
    start: int
    end: int


def luhn_ok(number: str) -> bool:
    """Return True when ``number`` passes the Luhn check."""
    if not number.isdigit() or len(number) < 2:
        return False
    total = 0
    double = False
    for character in reversed(number):
        digit = int(character)
        if double:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
        double = not double
    return total % 10 == 0


def ssn_parts_ok(area: str, group: str, serial: str) -> bool:
    """Structural SSN filter. Area 000, 666, and 900–999 are rejected."""
    if len(area) != 3 or len(group) != 2 or len(serial) != 4:
        return False
    if not (area.isdigit() and group.isdigit() and serial.isdigit()):
        return False
    if area == "000" or area == "666" or area.startswith("9"):
        return False
    if group == "00" or serial == "0000":
        return False
    return True


def npi_ok(number: str) -> bool:
    """CMS NPI check: Luhn over the 80840 prefix plus the 10-digit NPI."""
    if len(number) != 10 or not number.isdigit():
        return False
    return luhn_ok("80840" + number)


def detect(text: str, specs: Sequence[DetectorSpec]) -> list[Hit]:
    """Find pack hits in ``text``. The matched substring is not returned."""
    if not text or not specs:
        return []
    found: list[Hit] = []
    for spec in specs:
        spans = _spans(text, spec)
        for start, end in spans:
            if not _context_ok(text, start, end, spec):
                continue
            for data_class in spec.data_classes:
                found.append(
                    Hit(
                        detector_id=spec.id,
                        data_class=data_class,
                        kind=spec.kind,
                        start=start,
                        end=end,
                    )
                )
    return found


def redact_spans(text: str, spans: Sequence[tuple[int, int, str]]) -> str:
    """Replace spans. ``mask`` hides the span. ``last4`` keeps four digits."""
    if not spans or not text:
        return text
    chosen: list[tuple[int, int, str]] = []
    for start, end, style in sorted(spans, key=lambda item: (item[0], item[1])):
        if start < 0 or end > len(text) or start >= end:
            continue
        if chosen and start < chosen[-1][1]:
            prev_start, prev_end, prev_style = chosen[-1]
            style = "mask" if "mask" in {style, prev_style} else style
            chosen[-1] = (prev_start, max(prev_end, end), style)
            continue
        chosen.append((start, end, style))
    pieces: list[str] = []
    cursor = 0
    for start, end, style in chosen:
        pieces.append(text[cursor:start])
        pieces.append(_replacement(text[start:end], style))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def _replacement(token: str, style: str) -> str:
    if style == "last4":
        digits = re.sub(r"\D", "", token)
        if len(digits) >= 4:
            return f"***{digits[-4:]}"
    return "[redacted]"


def _spans(text: str, spec: DetectorSpec) -> list[tuple[int, int]]:
    kind = spec.kind
    if kind == "ssn":
        return [
            (match.start(), match.end())
            for match in _SSN.finditer(text)
            if ssn_parts_ok(match.group(1), match.group(2), match.group(3))
        ]
    if kind == "npi":
        return [
            (match.start(), match.end())
            for match in _NPI.finditer(text)
            if npi_ok(match.group(1))
        ]
    if kind == "luhn":
        return _luhn_spans(text)
    if kind == "mrn":
        return [(match.start(), match.end()) for match in _MRN.finditer(text)]
    if kind == "dob":
        return _dob_spans(text)
    if kind == "email":
        return [(match.start(), match.end()) for match in _EMAIL.finditer(text)]
    if kind == "phone":
        return [(match.start(), match.end()) for match in _PHONE.finditer(text)]
    if kind == "named_email":
        return _named_contact_spans(text, _EMAIL)
    if kind == "named_phone":
        return _named_contact_spans(text, _PHONE)
    if kind == "age_under_13":
        return _child_spans(text)
    if kind == "account":
        return [(match.start(), match.end()) for match in _ACCOUNT.finditer(text)]
    if kind == "phrase":
        return _phrase_spans(text, spec.terms or _terms_from_pattern(spec.pattern))
    if kind == "regex":
        return _regex_spans(text, spec.pattern)
    return []


def _luhn_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for match in _PAN.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            spans.append((match.start(), match.end()))
    return spans


def _dob_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for match in _DATE.finditer(text):
        token = match.group(1) or match.group(2) or ""
        if not _real_date(token):
            continue
        if not _near(text, match.start(), match.end(), _DOB_WORD):
            continue
        spans.append((match.start(), match.end()))
    return spans


def _child_spans(text: str) -> list[tuple[int, int]]:
    spans = [(match.start(), match.end()) for match in _UNDER_13.finditer(text)]
    for match in _AGE.finditer(text):
        raw = match.group(1) or match.group(2) or ""
        if raw.isdigit() and int(raw) < 13:
            spans.append((match.start(), match.end()))
    return spans


def _named_contact_spans(text: str, pattern: re.Pattern[str]) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for match in pattern.finditer(text):
        if _near(text, match.start(), match.end(), _NAME):
            spans.append((match.start(), match.end()))
    return spans


def _phrase_spans(text: str, terms: Iterable[str]) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for term in terms:
        cleaned = term.strip()
        if not cleaned:
            continue
        for match in re.finditer(re.escape(cleaned), text, flags=re.IGNORECASE):
            spans.append((match.start(), match.end()))
    return spans


def _regex_spans(text: str, pattern: str) -> list[tuple[int, int]]:
    if not pattern.strip():
        return []
    try:
        compiled = re.compile(pattern)
    except re.error:
        return []
    return [(match.start(), match.end()) for match in compiled.finditer(text)]


def _terms_from_pattern(pattern: str) -> tuple[str, ...]:
    if not pattern.strip():
        return ()
    return tuple(part.strip() for part in pattern.split("|") if part.strip())


def _context_ok(text: str, start: int, end: int, spec: DetectorSpec) -> bool:
    if not spec.context:
        return True
    left = max(0, start - spec.window)
    right = min(len(text), end + spec.window)
    window = text[left:right].casefold()
    return any(term.casefold() in window for term in spec.context if term.strip())


def _near(text: str, start: int, end: int, pattern: re.Pattern[str], window: int = 48) -> bool:
    left = max(0, start - window)
    right = min(len(text), end + window)
    return pattern.search(text[left:right]) is not None


def _real_date(token: str) -> bool:
    for fmt in ("%Y-%m-%d", "%m/%d/%Y"):
        try:
            datetime.strptime(token, fmt)
        except ValueError:
            continue
        else:
            return True
    return False
