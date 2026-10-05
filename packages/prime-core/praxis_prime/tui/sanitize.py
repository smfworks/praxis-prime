"""Visible form of text that came from the daemon or the user.

Rich markup is not the only way a terminal string becomes an instruction.
OSC, CSI, C1, and bidi overrides are turned into ordinary characters before
either the full-screen UI or ``--plain`` writes them.
"""

from __future__ import annotations

# Bidi overrides, embeddings, and isolates. These reorder neighbouring text.
_BIDI = frozenset(range(0x202A, 0x202F)) | frozenset(range(0x2066, 0x206A))
# Characters that take no width and can hide a later span.
_ZERO_WIDTH = frozenset({0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x00AD})
_NEWLINE = "⏎"


def sanitize(text: object, *, newlines: bool = True) -> str:
    """Return ``text`` with controls visible and hiding characters removed.

    ``\\n`` stays a newline when ``newlines`` is true. Otherwise it becomes
    ``⏎``. ESC, other C0 controls, DEL, and C1 (U+0080–U+009F) become
    ``\\xHH`` so the bytes written out contain no raw ESC or C1.
    """
    raw = text if isinstance(text, str) else str(text)
    parts: list[str] = []
    for char in raw:
        code = ord(char)
        if code in _BIDI or code in _ZERO_WIDTH:
            continue
        if char == "\n" or code in {0x2028, 0x2029}:
            parts.append("\n" if newlines else _NEWLINE)
            continue
        if code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            parts.append(f"\\x{code:02x}")
            continue
        parts.append(char)
    return "".join(parts)


def has_raw_control(text: str) -> bool:
    """True when ``text`` still contains ESC, another C0 control, DEL, or C1."""
    for char in text:
        code = ord(char)
        if code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            if char != "\n":
                return True
    return False
