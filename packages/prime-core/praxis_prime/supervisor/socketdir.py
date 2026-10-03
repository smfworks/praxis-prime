"""Private directories for supervisor and worker sockets.

The directory is mode 0700 and owned by this user. ``mkdir(exist_ok=True)``
is not used: that inherits the umask and does not check the owner.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path


def ensure_private_dir(path: Path) -> None:
    """Create ``path`` as 0700, or refuse a directory this user does not own.

    A symlink is refused. An existing directory with a different mode is
    tightened when this user owns it, then checked again.
    """
    candidate = Path(path)
    try:
        info = os.lstat(candidate)
    except FileNotFoundError:
        info = None
    if info is not None:
        _require_private_dir(candidate)
        return
    parent = candidate.parent
    if parent != candidate:
        try:
            os.lstat(parent)
        except FileNotFoundError:
            ensure_private_dir(parent)
    try:
        os.mkdir(candidate, 0o700)
    except FileExistsError:
        pass
    _require_private_dir(candidate)


def _require_private_dir(path: Path) -> None:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise OSError(f"refusing socket directory {path}")
    if info.st_uid != os.getuid():
        raise OSError(f"refusing socket directory {path}")
    if stat.S_IMODE(info.st_mode) == 0o700:
        return
    os.chmod(path, 0o700)
    info = os.lstat(path)
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise OSError(f"refusing socket directory {path}")
