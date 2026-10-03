"""Length-prefixed JSON frames on a Unix socket.

Messages are capped at 4 MiB, the same ceiling as an upstream body.
A frame that is not a JSON object is rejected. Callers authenticate
before any other method; this module only moves bytes.
"""

from __future__ import annotations

import json
import socket
import struct
from collections.abc import Mapping

MAX_MESSAGE = 4 * 1024 * 1024
_HEADER = 4


class IpcError(RuntimeError):
    """The peer closed or sent a frame this process will not accept."""


def send_message(sock: socket.socket, payload: Mapping[str, object]) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_MESSAGE:
        raise IpcError("ipc message exceeds 4MB")
    sock.sendall(struct.pack("!I", len(body)) + body)


def recv_message(sock: socket.socket) -> dict[str, object]:
    raw_len = _read_exact(sock, _HEADER)
    (size,) = struct.unpack("!I", raw_len)
    if size <= 0 or size > MAX_MESSAGE:
        raise IpcError("ipc message exceeds 4MB")
    raw = _read_exact(sock, size)
    try:
        loaded = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise IpcError("ipc message is not JSON") from exc
    if not isinstance(loaded, dict):
        raise IpcError("ipc message must be an object")
    return loaded


def _read_exact(sock: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        try:
            block = sock.recv(remaining)
        except TimeoutError as exc:
            raise IpcError("ipc timed out") from exc
        except OSError as exc:
            raise IpcError("ipc connection closed") from exc
        if not block:
            raise IpcError("ipc connection closed")
        chunks.append(block)
        remaining -= len(block)
    return b"".join(chunks)


# Methods a worker may call on the supervisor. Anything else is refused.
WORKER_METHODS = frozenset({"grant.check", "event"})

# Methods the supervisor may call on a worker.
SUPERVISOR_METHODS = frozenset(
    {
        "health",
        "shutdown",
        "status",
        "chat",
        "approvals.list",
        "approvals.get",
        "approvals.decide",
        "approvals.deny_all",
        "session.drop",
        "session.owner",
        "model.set",
        "routine.fire",
        "revoke",
        "memory.remember",
        "memory.list",
        "events.pull",
    }
)

# Event kinds a worker may emit. The supervisor stamps the profile.
EVENT_KINDS = frozenset({"approval", "audit", "routine"})
