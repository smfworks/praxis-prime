"""Stat helpers that fail closed on permission errors.

Python 3.14 makes ``Path.is_file``, ``is_dir``, ``is_symlink``, and ``exists``
return False on any ``OSError`` instead of raising. A permission error then
looks like "not a file" or "not a symlink", and a check that trusted that
answer can read a path it should have refused. These helpers use
``os.lstat`` / ``os.stat`` and ``stat.S_IS*`` so the caller can tell a
missing path from one it is not allowed to classify.
"""

from __future__ import annotations

import os
import stat
from enum import StrEnum
from pathlib import Path


class StatKind(StrEnum):
    MISSING = "missing"
    UNREADABLE = "unreadable"
    SYMLINK = "symlink"
    FILE = "file"
    DIR = "dir"
    OTHER = "other"


def lstat_kind(path: Path) -> StatKind:
    """Classify ``path`` without following a symlink."""
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return StatKind.MISSING
    except OSError:
        return StatKind.UNREADABLE
    return _kind(mode)


def stat_kind(path: Path) -> StatKind:
    """Classify the file ``path`` names, following a final symlink.

    An unreadable symlink, or a directory along the way that cannot be
    searched, is ``UNREADABLE`` rather than ``MISSING``.
    """
    try:
        mode = os.stat(path, follow_symlinks=True).st_mode
    except FileNotFoundError:
        return StatKind.MISSING
    except OSError:
        return StatKind.UNREADABLE
    return _kind(mode)


def _kind(mode: int) -> StatKind:
    if stat.S_ISLNK(mode):
        return StatKind.SYMLINK
    if stat.S_ISREG(mode):
        return StatKind.FILE
    if stat.S_ISDIR(mode):
        return StatKind.DIR
    return StatKind.OTHER
