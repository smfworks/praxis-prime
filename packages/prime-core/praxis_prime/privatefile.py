"""Create files that stay mode 0600.

Accounts, sessions, and profile memory live in these files. The mode is
set again after SQLite creates its WAL sidecars.

ARCHITECTURE §22 and §25.
"""

from __future__ import annotations

import os
from pathlib import Path


def tighten_file(path: Path) -> None:
    """Force ``path`` and any SQLite sidecar to mode 0600."""
    if path.exists():
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(f"{path}{suffix}")
        if sidecar.exists():
            try:
                os.chmod(sidecar, 0o600)
            except OSError:
                pass


def tighten_dir(path: Path) -> None:
    """Force a directory to mode 0700."""
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def touch_private(path: Path) -> None:
    """Create ``path`` if needed and leave it mode 0600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tighten_dir(path.parent)
    flags = os.O_RDWR | os.O_CREAT
    descriptor = os.open(path, flags, 0o600)
    os.close(descriptor)
    tighten_file(path)
