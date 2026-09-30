"""Host and Origin allowlist for the loopback gateway.

A browser can be pointed at a public name that rebinds to 127.0.0.1.
The gateway only accepts the names it actually bound: ``127.0.0.1`` and
``localhost``. The check does not resolve DNS. A non-loopback listen
address is still refused in ``parse_listen`` before the socket exists.

docs/blueprint-addendum-2026-09.md §4.2.
"""

from __future__ import annotations

_ALLOWED = frozenset({"127.0.0.1", "localhost"})


def host_origin_denial(
    headers: dict[str, str],
    *,
    bound_port: int,
) -> tuple[int, str, str] | None:
    """Return ``(status, code, message)`` when the request must be refused."""
    if headers.get("x-duplicate-host") == "1":
        return 400, "bad_request", "duplicate host header"
    raw_host = headers.get("host", "")
    if not raw_host:
        return 400, "bad_request", "host header is required"
    parsed = _split_host(raw_host)
    if parsed is None:
        return 403, "forbidden", "host is not allowed"
    host, port = parsed
    if host not in _ALLOWED:
        return 403, "forbidden", "host is not allowed"
    if port is not None and port != bound_port:
        return 403, "forbidden", "host is not allowed"
    origin = headers.get("origin", "")
    if origin and not _origin_ok(origin, bound_port):
        return 403, "forbidden", "origin is not allowed"
    return None


def _origin_ok(origin: str, bound_port: int) -> bool:
    if origin == "null" or "\\" in origin:
        return False
    if any(ord(char) < 33 for char in origin):
        return False
    if origin.startswith("https://"):
        rest = origin[len("https://") :]
    elif origin.startswith("http://"):
        rest = origin[len("http://") :]
    else:
        return False
    if not rest or any(char in rest for char in "/?#"):
        return False
    parsed = _split_host(rest)
    if parsed is None:
        return False
    host, port = parsed
    if host not in _ALLOWED:
        return False
    if port is not None and port != bound_port:
        return False
    return True


def _split_host(value: str) -> tuple[str, int | None] | None:
    if not value or len(value) > 253:
        return None
    if any(ord(char) < 33 or char in "@\\/?#\"'[]" for char in value):
        return None
    if value.count(":") > 1:
        return None
    port: int | None = None
    host = value
    if ":" in value:
        host, port_text = value.rsplit(":", 1)
        if not port_text.isdigit():
            return None
        port = int(port_text)
        if port > 65535:
            return None
    if not host or host.endswith(".") or ":" in host:
        return None
    return host.casefold(), port
