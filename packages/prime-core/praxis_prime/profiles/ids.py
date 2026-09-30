"""Profile ids used in paths and URLs.

An id is a single path segment. ``..``, slashes, and absolute paths are
rejected before anything joins them onto a directory.
"""

from __future__ import annotations

import re

_PROFILE_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_USERNAME = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")


def profile_id(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    if _PROFILE_ID.fullmatch(value):
        return value
    return None


def username(value: object) -> str | None:
    """Return a stored username, or None. Input is casefolded."""
    if not isinstance(value, str):
        return None
    text = value.strip().casefold()
    if _USERNAME.fullmatch(text):
        return text
    return None
