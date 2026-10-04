"""File-change triggers.

inotify is used when the kernel provides it. Otherwise each check stats
the path. A token is the file size and mtime, or a hash of a directory's
immediate children, so a missed change is still visible on the next start.

A watched directory is armed again after it is deleted or replaced. Every
check still stats the path. An empty queue is not proof the file is
unchanged. A dirty flag or a queue overflow means the caller should stat
again. It is not itself a change to the file. Only watched paths and their
parent directories are recorded as dirty.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import struct
import threading
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
# A noisy directory must not grow this set without bound. Only watched
# paths and their parents are recorded. Past the cap the watcher forgets
# individual paths and the next observe stats instead.
_DIRTY_CAP = 1024


class _Event(NamedTuple):
    wd: int
    mask: int
    path: Path | None
    name: str


class WatchObservation(NamedTuple):
    """One check of a path.

    ``token_changed`` is a new stat token. ``dirty`` and ``overflowed`` mean
    the kernel reported activity, so the caller should stat again. A file
    routine fires only when the token changes. The Omarchy adapter also
    re-reads its cache when the watch is dirty or the queue overflowed.
    """

    token_changed: bool
    dirty: bool
    overflowed: bool
    token: str


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
        self._lock = threading.RLock()
        fd, libc = _open_inotify()
        if fd is not None and libc is not None:
            self._fd = fd
            self._libc = libc
            self.backend = "inotify"

    def close(self) -> None:
        with self._lock:
            if self._fd is None:
                return
            os.close(self._fd)
            self._fd = None
            self._libc = None

    def arm(self, path: Path) -> None:
        with self._lock:
            if self.backend != "inotify" or self._fd is None or self._libc is None:
                return
            watch_dir = path if path.is_dir() else path.parent
            self._add_watch(watch_dir)
            parent = watch_dir.parent
            if parent != watch_dir:
                self._add_watch(parent)

    def observe(self, path: Path, previous: str, *, startup: bool) -> WatchObservation:
        """Stat ``path`` and report the token, dirtiness, and overflow.

        ``startup`` is the scheduler's first tick. The directory watch is
        re-armed when it has gone away, and the path is statted on every
        call. The dirty flag for this path is cleared. A queue overflow
        stays set until every watched path has been checked.
        """
        del startup
        with self._lock:
            key = str(path)
            # Register before draining so this path, not an unrelated name,
            # is what a queued event can mark dirty.
            self._watched.add(key)
            self.arm(path)
            self._drain()
            # A delete in the queue drops the watch. Arm the path that is there now.
            self.arm(path)
            token = file_token(path)
            dirty = key in self._dirty
            overflowed = self._overflow
            self._dirty.discard(key)
            if self._overflow:
                self._reconciled.add(key)
                if self._watched <= self._reconciled:
                    self._overflow = False
                    self._reconciled.clear()
            self._repair_map()
            return WatchObservation(
                token_changed=token != previous,
                dirty=dirty,
                overflowed=overflowed,
                token=token,
            )

    def _add_watch(self, watch_dir: Path) -> None:
        if self._fd is None or self._libc is None:
            return
        if not watch_dir.is_dir():
            return
        key = str(watch_dir)
        existing = [wd for wd, path in self._wd_path.items() if str(path) == key]
        # One path keeps one wd. A second wd is the drift left by a replace.
        if len(existing) == 1:
            self._armed.add(key)
            return
        for wd in existing:
            self._wd_path.pop(wd, None)
            self._rm_watch(wd)
        self._armed.discard(key)
        encoded = os.fsencode(watch_dir)
        wd = self._libc.inotify_add_watch(self._fd, encoded, _MASK)
        if wd < 0:
            return
        self._bind_watch(int(wd), watch_dir)

    def _bind_watch(self, wd: int, watch_dir: Path) -> None:
        key = str(watch_dir)
        previous = self._wd_path.get(wd)
        if previous is not None and str(previous) != key:
            old_key = str(previous)
            others = [
                other
                for other, path in self._wd_path.items()
                if other != wd and str(path) == old_key
            ]
            if not others:
                self._armed.discard(old_key)
        for old, path in list(self._wd_path.items()):
            if old != wd and str(path) == key:
                self._wd_path.pop(old, None)
                self._rm_watch(old)
        self._wd_path[wd] = watch_dir
        self._armed.add(key)

    def _repair_map(self) -> None:
        """Drop a second wd for one path, and make ``_armed`` match the map."""
        kept: dict[str, int] = {}
        extras: list[int] = []
        for wd, path in self._wd_path.items():
            key = str(path)
            if key in kept:
                extras.append(kept[key])
            kept[key] = wd
        for wd in extras:
            self._wd_path.pop(wd, None)
            self._rm_watch(wd)
        self._armed.clear()
        self._armed.update(kept)

    def _drain(self) -> None:
        with self._lock:
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
        with self._lock:
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
        # MOVE_SELF leaves the kernel watch on the inode. Delete may already
        # have dropped it, which returns EINVAL.
        self._rm_watch(wd)
        key = str(path)
        if not any(str(other) == key for other in self._wd_path.values()):
            self._armed.discard(key)

    def _drop_path(self, key: str) -> None:
        with self._lock:
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
        if rm_watch(self._fd, int(wd)) >= 0:
            return
        if ctypes.get_errno() == errno.EINVAL:
            return

    def _mark_tree(self, key: str) -> None:
        with self._lock:
            self._mark_dirty(key)
            prefix = key + os.sep
            for watched in list(self._watched):
                if watched == key or watched.startswith(prefix):
                    self._mark_dirty(watched)

    def _is_relevant(self, key: str) -> bool:
        if key in self._watched:
            return True
        prefix = key + os.sep
        return any(watched.startswith(prefix) for watched in self._watched)

    def _mark_dirty(self, key: str) -> None:
        with self._lock:
            if self._overflow:
                return
            # Unrelated names in a watched directory are not recorded, so
            # they cannot fill the cap and force every routine to stat.
            if not self._is_relevant(key):
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
