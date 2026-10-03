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


def read_bounded(
    response: object,
    *,
    limit: int = MAX_UPSTREAM_BYTES,
    deadline: float,
) -> bytes:
    """Read ``response`` until EOF, the cap, or the deadline."""
    chunks: list[bytes] = []
    total = 0
    reader = response.read
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError("upstream deadline exceeded")
        block = reader(65536)
        if not block:
            break
        if not isinstance(block, bytes):
            raise TypeError("upstream body must be bytes")
        total += len(block)
        if total > limit:
            raise ValueError("upstream body exceeds 4MB")
        chunks.append(block)
    return b"".join(chunks)


def iter_bounded(
    response: object,
    *,
    limit: int | None = None,
    deadline: float,
) -> Iterator[bytes]:
    """Yield lines from ``response``. Stop on the cap or the deadline.

    Blocks come from ``read`` in 64 KiB pieces. A body with no newlines
    still counts toward the cap, so one long line is not one multi-megabyte
    ``readline``. Python 3.13 raises ``ConnectionResetError`` from that read
    when the peer closes a response this large.
    """
    if limit is None:
        limit = MAX_UPSTREAM_BYTES
    reader = getattr(response, "read", None)
    if not callable(reader):
        yield read_bounded(response, limit=limit, deadline=deadline)
        return
    total = 0
    pending = b""
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError("upstream deadline exceeded")
        try:
            block = reader(65536)
        except TimeoutError as exc:
            raise TimeoutError("upstream deadline exceeded") from exc
        if time.monotonic() > deadline:
            raise TimeoutError("upstream deadline exceeded")
        if not block:
            break
        if not isinstance(block, bytes):
            raise TypeError("upstream body must be bytes")
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
