"""Caps and deadlines for calls this process makes to another program.

An upstream body over 4 MiB is refused. A call that passes its deadline
is refused. Redirects are refused. The same rules cover model providers
and the Telegram connector.
"""

from __future__ import annotations

import time
import urllib.request
from collections.abc import Iterator

MAX_UPSTREAM_BYTES = 4 * 1024 * 1024


class RedirectRefused(Exception):
    """The peer answered with a redirect. The redirect was not followed."""

    def __init__(self, code: int) -> None:
        self.code = code
        super().__init__(f"redirect refused ({code})")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        del req, fp, msg, headers, newurl
        raise RedirectRefused(int(code))


def build_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_NoRedirect)


def _read_some(response: object, size: int = 65536) -> bytes:
    """Return the next short read. Prefer one underlying read, not a full buffer."""
    read1 = getattr(response, "read1", None)
    if callable(read1):
        block = read1(size)
    else:
        readinto = getattr(response, "readinto", None)
        if callable(readinto):
            buf = bytearray(size)
            count = readinto(buf)
            if not isinstance(count, int):
                raise TypeError("upstream body must be bytes")
            block = bytes(buf[:count])
        else:
            reader = getattr(response, "read", None)
            if not callable(reader):
                raise TypeError("upstream body must be bytes")
            block = reader(size)
    if isinstance(block, bytearray):
        block = bytes(block)
    if not isinstance(block, bytes):
        raise TypeError("upstream body must be bytes")
    return block


def read_bounded(
    response: object,
    *,
    limit: int = MAX_UPSTREAM_BYTES,
    deadline: float,
) -> bytes:
    """Read ``response`` until EOF, the cap, or the deadline."""
    chunks: list[bytes] = []
    total = 0
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError("upstream deadline exceeded")
        try:
            block = _read_some(response)
        except TimeoutError as exc:
            raise TimeoutError("upstream deadline exceeded") from exc
        if not block:
            break
        total += len(block)
        if total > limit:
            raise ValueError("upstream body exceeds 4MB")
        chunks.append(block)
    return b"".join(chunks)


def iter_bounded(
    response: object,
    *,
    limit: int | None = None,
) -> Iterator[bytes]:
    """Yield lines as bytes arrive. Stop when the body passes the cap.

    ``read1`` (or ``readinto``) returns a short read, so a token is not held
    until 64 KiB is buffered or the peer closes. The socket timeout is the
    idle deadline: a quiet peer fails the call, and a slow peer that keeps
    sending does not. A peer that closes while unread data is still queued
    can reset the connection. That reset is an ``OSError``. The cap counts
    every chunk, including a body that has no newlines.
    """
    if limit is None:
        limit = MAX_UPSTREAM_BYTES
    total = 0
    pending = b""
    while True:
        try:
            block = _read_some(response)
        except TimeoutError as exc:
            raise TimeoutError("upstream deadline exceeded") from exc
        if not block:
            break
        pending += block
        while True:
            split = pending.find(b"\n")
            if split < 0:
                break
            line = pending[: split + 1]
            pending = pending[split + 1 :]
            total += len(line)
            if total > limit:
                raise ValueError("upstream body exceeds 4MB")
            yield line
        if total + len(pending) > limit:
            raise ValueError("upstream body exceeds 4MB")
    if pending:
        total += len(pending)
        if total > limit:
            raise ValueError("upstream body exceeds 4MB")
        yield pending
