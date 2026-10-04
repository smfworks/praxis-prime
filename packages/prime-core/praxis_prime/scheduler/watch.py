"""File-change triggers.

inotify is used when the kernel provides it. Otherwise each check stats
the path. A token is the file size and mtime, or a hash of a directory's
immediate children, so a missed change is still visible on the next start.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import struct
from pathlib import Path

_IN_NONBLOCK = 0x00000800
_IN_CLOEXEC = 0x00080000
_MASK = 0x2 | 0x4 | 0x8 | 0x40 | 0x80 | 0x100 | 0x200
_HEADER = struct.Struct("iIII")
# A noisy directory must not grow this set without bound. Past the cap the
# watcher forgets individual paths and the next observe stats instead.
_DIRTY_CAP = 1024


def file_token(path: Path) -> str:
    if not path.exists():
        return "missing"
    if path.is_file():
        stat = path.stat()
        return f"f:{stat.st_mtime_ns}:{stat.st_size}"
    if path.is_dir():
        parts: list[str] = []
        try:
            children = sorted(path.iterdir(), key=lambda item: item.name)[:500]
        except OSError:
            return "unreadable"
        for child in children:
            try:
                stat = child.stat()
            except OSError:
                continue
            parts.append(f"{child.name}:{stat.st_mtime_ns}:{stat.st_size}")
        digest = hashlib.sha256("\n".join(parts).encode()).hexdigest()[:16]
        return f"d:{digest}"
    return "other"


class DirectoryWatcher:
    """One inotify fd, or a polling fallback."""

    def __init__(self) -> None:
        self.backend = "poll"
        self._fd: int | None = None
        self._wd_path: dict[int, Path] = {}
        self._armed: set[str] = set()
        self._dirty: set[str] = set()
        self._watched: set[str] = set()
        self._reconciled: set[str] = set()
        self._overflow = False
        self._libc: ctypes.CDLL | None = None
        fd, libc = _open_inotify()
        if fd is not None and libc is not None:
            self._fd = fd
            self._libc = libc
            self.backend = "inotify"

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def arm(self, path: Path) -> None:
        if self._fd is None or self._libc is None:
            return
        watch_dir = path if path.is_dir() else path.parent
        key = str(watch_dir)
        if key in self._armed or not watch_dir.is_dir():
            return
        encoded = os.fsencode(watch_dir)
        wd = self._libc.inotify_add_watch(self._fd, encoded, _MASK)
        if wd < 0:
            return
        self._armed.add(key)
        self._wd_path[int(wd)] = watch_dir

    def observe(self, path: Path, previous: str, *, startup: bool) -> tuple[bool, str]:
        """Return whether ``path`` changed, and the token to store."""
        self.arm(path)
        self._drain()
        key = str(path)
        self._watched.add(key)
        force = self._overflow
        if (
            self.backend == "inotify"
            and not startup
            and not force
            and previous
            and previous != "missing"
            and key not in self._dirty
        ):
            return False, previous
        token = file_token(path)
        self._dirty.discard(key)
        if force:
            self._reconciled.add(key)
            if self._watched <= self._reconciled:
                self._overflow = False
                self._reconciled.clear()
        return token != previous, token

    def _drain(self) -> None:
        if self._fd is None:
            return
        while True:
            try:
                raw = os.read(self._fd, 4096)
            except BlockingIOError:
                return
            except OSError:
                return
            if not raw:
                return
            for event_path in _parse(raw, self._wd_path):
                self._mark_dirty(str(event_path))

    def _mark_dirty(self, key: str) -> None:
        if self._overflow:
            return
        if len(self._dirty) >= _DIRTY_CAP:
            self._overflow = True
            self._dirty.clear()
            self._reconciled.clear()
            return
        self._dirty.add(key)


def _open_inotify() -> tuple[int | None, ctypes.CDLL | None]:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if not hasattr(libc, "inotify_init1"):
            return None, None
        libc.inotify_init1.argtypes = [ctypes.c_int]
        libc.inotify_init1.restype = ctypes.c_int
        libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        libc.inotify_add_watch.restype = ctypes.c_int
        fd = libc.inotify_init1(_IN_NONBLOCK | _IN_CLOEXEC)
    except (OSError, AttributeError):
        return None, None
    if fd < 0:
        return None, None
    return int(fd), libc


def _parse(raw: bytes, wd_path: dict[int, Path]) -> list[Path]:
    found: list[Path] = []
    offset = 0
    while offset + _HEADER.size <= len(raw):
        wd, _mask, _cookie, length = _HEADER.unpack_from(raw, offset)
        offset += _HEADER.size
        name = b""
        if length:
            name = raw[offset : offset + length].split(b"\x00", 1)[0]
            offset += length
        directory = wd_path.get(wd)
        if directory is None:
            continue
        if name:
            found.append(directory / name.decode("utf-8", "replace"))
        else:
            found.append(directory)
    return found
