"""Visible form of text that came from the daemon or the user.

Rich markup is not the only way a terminal string becomes an instruction.
OSC, CSI, C1, bidi overrides, and other invisible characters are written as
ordinary text before a UI shows them.
"""

from __future__ import annotations

import unicodedata

_NEWLINE = "⏎"
_MARKS_PER_BASE = 2

# Letters and marks that take no visible space and are not category Cf.
_HANGUL_FILLER = frozenset({0x115F, 0x1160, 0x3164, 0xFFA0})
_ALWAYS = frozenset({0x034F, 0x061C, 0x200E, 0x200F}) | frozenset(range(0x2061, 0x2065))


def sanitize(text: object, *, newlines: bool = True) -> str:
    """Return ``text`` with controls and invisible characters made visible.

    ``\\n`` stays a newline when ``newlines`` is true. Otherwise it becomes
    ``⏎``. ESC, other C0 controls, DEL, and C1 (U+0080–U+009F) become
    ``\\xHH``. Format characters, bidi controls, zero-width characters,
    hangul fillers, variation selectors, tags, and lone surrogates become
    ``<U+XXXX>``. At most two combining marks stay on a base character.
    """
    raw = text if isinstance(text, str) else str(text)
    parts: list[str] = []
    marks = 0
    for char in raw:
        code = ord(char)
        if char == "\n" or code in {0x2028, 0x2029}:
            parts.append("\n" if newlines else _NEWLINE)
            marks = 0
            continue
        if code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            parts.append(f"\\x{code:02x}")
            marks = 0
            continue
        if _invisible(code):
            parts.append(_escape(code))
            marks = 0
            continue
        if unicodedata.category(char).startswith("M"):
            if marks >= _MARKS_PER_BASE:
                parts.append(_escape(code))
                continue
            marks += 1
            parts.append(char)
            continue
        parts.append(char)
        marks = 0
    return "".join(parts)


def has_raw_control(text: str) -> bool:
    """True when ``text`` still contains ESC, another C0 control, DEL, or C1."""
    for char in text:
        code = ord(char)
        if code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            if char != "\n":
                return True
    return False


def _invisible(code: int) -> bool:
    if code in _HANGUL_FILLER or code in _ALWAYS:
        return True
    if 0xFE00 <= code <= 0xFE0F or 0xE0100 <= code <= 0xE01EF:
        return True
    if 0xE0000 <= code <= 0xE007F or 0xD800 <= code <= 0xDFFF:
        return True
    return unicodedata.category(chr(code)) == "Cf"


def _escape(code: int) -> str:
    return f"<U+{code:04X}>"
