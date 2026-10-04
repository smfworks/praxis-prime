"""File-change triggers.

inotify is used when the kernel provides it. Otherwise each check stats
the path. A token is the file size and mtime, or a hash of a directory's
immediate children, so a missed change is still visible on the next start.

A watched directory is armed again after it is deleted or replaced. Every
check still stats the path: an empty inotify queue is not proof the file
is unchanged.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import struct
from pathlib import Path
from typing import NamedTuple

_IN_NONBLOCK = 0x00000800
_IN_CLOEXEC = 0x00080000
# Modify, attrib, close-write, moved-from, moved-to, create, delete,
# delete-self, move-self. IN_IGNORED and IN_Q_OVERFLOW are kernel output
# and are not request bits.
_IN_MODIFY = 0x2
_IN_ATTRIB = 0x4
_IN_CLOSE_WRITE = 0x8
_IN_MOVED_FROM = 0x40
_IN_MOVED_TO = 0x80
_IN_CREATE = 0x100
_IN_DELETE = 0x200
_IN_DELETE_SELF = 0x400
_IN_MOVE_SELF = 0x800
_IN_Q_OVERFLOW = 0x4000
_IN_IGNORED = 0x8000
_MASK = (
    _IN_MODIFY
    | _IN_ATTRIB
    | _IN_CLOSE_WRITE
    | _IN_MOVED_FROM
    | _IN_MOVED_TO
    | _IN_CREATE
    | _IN_DELETE
    | _IN_DELETE_SELF
    | _IN_MOVE_SELF
)
_SELF_GONE = _IN_DELETE_SELF | _IN_MOVE_SELF | _IN_IGNORED
_CHILD_SWAP = _IN_DELETE | _IN_MOVED_FROM | _IN_CREATE | _IN_MOVED_TO
_HEADER = struct.Struct("iIII")
# A noisy directory must not grow this set without bound. Past the cap the
# watcher forgets individual paths and the next observe stats instead.
_DIRTY_CAP = 1024


class _Event(NamedTuple):
    wd: int
    mask: int
    path: Path | None
    name: str


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
        if self.backend != "inotify" or self._fd is None or self._libc is None:
            return
        watch_dir = path if path.is_dir() else path.parent
        self._add_watch(watch_dir)
        parent = watch_dir.parent
        if parent != watch_dir:
            self._add_watch(parent)

    def observe(self, path: Path, previous: str, *, startup: bool) -> tuple[bool, str]:
        """Return whether ``path`` changed, and the token to store.

        ``startup`` is the scheduler's first tick. The directory watch is
        re-armed when it has gone away, and the path is statted on every
        call. A matching token is not a change.
        """
        del startup
        self.arm(path)
        self._drain()
        # A delete in the queue drops the watch. Arm the path that is there now.
        self.arm(path)
        key = str(path)
        self._watched.add(key)
        token = file_token(path)
        self._dirty.discard(key)
        if self._overflow:
            self._reconciled.add(key)
            if self._watched <= self._reconciled:
                self._overflow = False
                self._reconciled.clear()
        return token != previous, token

    def _add_watch(self, watch_dir: Path) -> None:
        if self._fd is None or self._libc is None:
            return
        key = str(watch_dir)
        if key in self._armed or not watch_dir.is_dir():
            return
        encoded = os.fsencode(watch_dir)
        wd = self._libc.inotify_add_watch(self._fd, encoded, _MASK)
        if wd < 0:
            return
        self._armed.add(key)
        self._wd_path[int(wd)] = watch_dir

    def _drain(self) -> None:
        if self.backend != "inotify" or self._fd is None:
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
            for event in _parse(raw, self._wd_path):
                self._apply(event)

    def _apply(self, event: _Event) -> None:
        if event.wd < 0 or event.mask & _IN_Q_OVERFLOW:
            self._overflow = True
            self._dirty.clear()
            self._reconciled.clear()
            return
        if event.path is None:
            return
        key = str(event.path)
        if event.mask & _SELF_GONE:
            self._drop_wd(event.wd)
            self._mark_tree(key)
            return
        self._mark_tree(key)
        # A new directory at this path is a new inode. Forget the old watch.
        if event.name and event.mask & _CHILD_SWAP:
            self._drop_path(key)

    def _drop_wd(self, wd: int) -> None:
        path = self._wd_path.pop(wd, None)
        if path is None:
            return
        key = str(path)
        if not any(str(other) == key for other in self._wd_path.values()):
            self._armed.discard(key)

    def _drop_path(self, key: str) -> None:
        stale = [wd for wd, path in self._wd_path.items() if str(path) == key]
        for wd in stale:
            self._wd_path.pop(wd, None)
            self._rm_watch(wd)
        self._armed.discard(key)

    def _rm_watch(self, wd: int) -> None:
        if self._fd is None or self._libc is None:
            return
        rm_watch = getattr(self._libc, "inotify_rm_watch", None)
        if rm_watch is None:
            return
        rm_watch(self._fd, wd)

    def _mark_tree(self, key: str) -> None:
        self._mark_dirty(key)
        prefix = key + os.sep
        for watched in list(self._watched):
            if watched == key or watched.startswith(prefix):
                self._mark_dirty(watched)

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
        if hasattr(libc, "inotify_rm_watch"):
            libc.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
            libc.inotify_rm_watch.restype = ctypes.c_int
        fd = libc.inotify_init1(_IN_NONBLOCK | _IN_CLOEXEC)
    except (OSError, AttributeError):
        return None, None
    if fd < 0:
        return None, None
    return int(fd), libc


def _parse(raw: bytes, wd_path: dict[int, Path]) -> list[_Event]:
    found: list[_Event] = []
    offset = 0
    while offset + _HEADER.size <= len(raw):
        wd, mask, _cookie, length = _HEADER.unpack_from(raw, offset)
        offset += _HEADER.size
        name = ""
        if length:
            raw_name = raw[offset : offset + length].split(b"\x00", 1)[0]
            offset += length
            name = raw_name.decode("utf-8", "replace")
        if wd < 0 or mask & _IN_Q_OVERFLOW:
            found.append(_Event(wd, mask, None, name))
            continue
        directory = wd_path.get(wd)
        if directory is None:
            continue
        path = directory / name if name else directory
        found.append(_Event(wd, mask, path, name))
    return found
