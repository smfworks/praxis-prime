"""Gateway frame constants and the loopback listen rule.

One JSON frame shape is used on WebSocket. HTTP carries the same payloads
for health, status, and approvals (ARCHITECTURE §4).

The listen address is loopback only. A public bind is refused before the
socket is created.
"""

from __future__ import annotations

import hmac
from contextvars import ContextVar

PROTOCOL_VERSION = 1
DEFAULT_LISTEN = "127.0.0.1:18790"
ROLES = frozenset({"operator", "viewer", "channel", "node", "agent"})
OPERATOR_ONLY = frozenset({"approvals.decide", "model.set", "session.drop"})
CHAT_ROLES = frozenset({"operator", "channel"})

request_id_var: ContextVar[str | None] = ContextVar("praxis_prime_request_id", default=None)


class ListenError(ValueError):
    """The requested bind address is not loopback."""


def parse_listen(value: str) -> tuple[str, int]:
    """Return ``(127.0.0.1, port)``. Anything else is an error.

    ``localhost`` is accepted and rewritten to ``127.0.0.1`` without DNS.
    Port ``0`` lets the OS pick a port (tests).
    """
    text = value.strip()
    if text.startswith("["):
        raise ListenError("refusing non-loopback listen address; the gateway stays on 127.0.0.1")
    host, sep, port_text = text.rpartition(":")
    if not sep or not host:
        raise ListenError(f"listen address must look like 127.0.0.1:18790, got {value!r}")
    if host == "localhost":
        host = "127.0.0.1"
    if host != "127.0.0.1":
        raise ListenError(
            f"refusing non-loopback listen address {host}; the gateway stays on 127.0.0.1"
        )
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ListenError(f"invalid listen port in {value!r}") from exc
    if port < 0 or port > 65535:
        raise ListenError(f"invalid listen port in {value!r}")
    return host, port


def secrets_equal(left: str, right: str) -> bool:
    """Constant-time compare. Empty values never match."""
    if not left or not right:
        return False
    left_b = left.encode()
    right_b = right.encode()
    if len(left_b) != len(right_b):
        return False
    return hmac.compare_digest(left_b, right_b)
