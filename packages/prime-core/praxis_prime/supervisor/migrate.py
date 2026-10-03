"""One-time marker for the worker split.

M1a already moved a single-user ``prime.db`` into ``profiles/default``.
This step does not move databases again and does not copy grants into a
worker. A second call sees the marker and returns without writing.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

_VERSION = 1


def marker_path(data_root: Path) -> Path:
    return Path(data_root) / "supervisor" / "m1c.json"


def migrate_install(data_root: Path) -> bool:
    """Write the M1c marker once. Return True only on the first call."""
    path = marker_path(data_root)
    if _already(path):
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    body = {
        "version": _VERSION,
        "grants": "not-restored",
        "applied_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    _write(path, json.dumps(body, sort_keys=True) + "\n")
    return True


def _already(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return False
    return isinstance(loaded, dict) and loaded.get("version") == _VERSION


def _write(path: Path, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, text.encode())
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
