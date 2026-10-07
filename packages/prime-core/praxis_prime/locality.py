"""Classify a provider base URL as local, lan, or cloud.

A successful lookup is not cached. A positive cache would keep a name's old
addresses after DNS changes and widen the rebinding window. Callers that
enforce routing classify again at request time; see
``compliance.providers.filter_chain``.

Lookups are single-flight: one resolver call per host is in flight at a
time, and concurrent callers wait on it. A failed, empty, or timed-out
lookup is remembered for ``NEGATIVE_TTL`` seconds and answers ``cloud``
straight away (fail closed), so a dead resolver does not stall every
request or pile up threads stuck in ``getaddrinfo``.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from collections.abc import Callable, Sequence
from typing import Literal
from urllib.parse import urlsplit

Locality = Literal["local", "lan", "cloud"]
Resolver = Callable[[str], Sequence[str]]

_RANK = {"local": 0, "lan": 1, "cloud": 2}

# Seconds a failed, empty, or timed-out lookup keeps answering cloud.
NEGATIVE_TTL = 10.0

# Explicit ranges. Do not use ``ipaddress`` ``is_private`` or ``is_global``
# for the lan decision: Python marks documentation and benchmark ranges
# (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 198.18.0.0/15, and others)
# as private.
_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_ULA = ipaddress.ip_network("fc00::/7")
_LINK_LOCAL_V4 = ipaddress.ip_network("169.254.0.0/16")
_LINK_LOCAL_V6 = ipaddress.ip_network("fe80::/10")
_SIXTO4 = ipaddress.ip_network("2002::/16")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def host_of(base_url: str) -> str:
    """Hostname of a base URL, or "" when there is none.

    A missing scheme is treated as ``http://``. Bracketed IPv6, userinfo,
    and ports are handled by ``urlsplit``. The result is lowercase, without
    a trailing dot or an IPv6 zone id (``fe80::1%eth0``).
    """
    text = base_url.strip()
    if not text:
        return ""
    if "://" not in text:
        text = "http://" + text
    try:
        host = urlsplit(text).hostname or ""
    except ValueError:
        return ""
    host = host.lower().rstrip(".")
    if "%" in host:
        host = host.split("%", 1)[0]
    return host


def classify_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address | str) -> Locality:
    """Classify one IP address. A string may include a zone id or brackets."""
    address = _parse_address(ip)
    if isinstance(address, ipaddress.IPv6Address):
        mapped = address.ipv4_mapped
        if mapped is not None:
            return classify_address(mapped)
        # 6to4, NAT64, and IPv4-compatible addresses leave through a
        # translator. Fail closed. ``::`` and ``::1`` stay IPv6.
        if address in _SIXTO4 or address in _NAT64 or _ipv4_compatible(address):
            return "cloud"
    if address.is_loopback:
        return "local"
    # Unspecified is local. The kernel delivers a connect to 0.0.0.0 or ::
    # to this host, and OLLAMA_HOST=0.0.0.0:11434 is a common bind string.
    if address.is_unspecified:
        return "local"
    if address.version == 4 and (any(address in net for net in _RFC1918) or address in _CGNAT):
        return "lan"
    if address.version == 6 and address in _ULA:
        return "lan"
    # Link-local is never trusted as on-prem. 169.254.0.0/16 includes the
    # metadata address 169.254.169.254, and the probe already refuses it.
    if address.version == 4 and address in _LINK_LOCAL_V4:
        return "cloud"
    if address.version == 6 and address in _LINK_LOCAL_V6:
        return "cloud"
    return "cloud"


def classify_host(
    host: str,
    *,
    resolver: Resolver | None = None,
    timeout: float = 2.0,
) -> Locality:
    """Classify a host. Names use every resolved address.

    An empty host is cloud. Bare ``localhost`` is local and is not resolved.
    A name ending in ``.localhost`` is resolved, because a stock glibc
    resolver can send it to DNS; it is local only when every address is
    loopback, and cloud otherwise. An IP literal uses ``classify_address``.
    Any other name is resolved. The result is the most remote class: cloud
    beats lan, and lan beats local, so one public address makes the host
    cloud and a mix of loopback and lan is lan. A timeout, any resolver
    error, or no addresses is cloud.
    """
    text = host.strip().lower().rstrip(".")
    if text.startswith("[") and text.endswith("]") and len(text) >= 2:
        text = text[1:-1].strip()
    if "%" in text:
        text = text.split("%", 1)[0]
    if not text:
        return "cloud"
    if text == "localhost":
        return "local"
    try:
        return classify_address(text)
    except ValueError:
        pass
    lookup = resolve_host if resolver is None else resolver
    found = _lookup(lookup, text, timeout)
    if not found:
        return "cloud"
    if text.endswith(".localhost"):
        return "local" if all(_is_loopback(item) for item in found) else "cloud"
    classes: list[Locality] = []
    for item in found:
        try:
            classes.append(classify_address(item))
        except ValueError:
            return "cloud"
    if not classes:
        return "cloud"
    return max(classes, key=lambda item: _RANK[item])


def locality(
    base_url: str,
    *,
    resolver: Resolver | None = None,
    timeout: float = 2.0,
) -> Locality:
    """Classify the host of a base URL. See ``classify_host``."""
    return classify_host(host_of(base_url), resolver=resolver, timeout=timeout)


def resolve_host(host: str) -> list[str]:
    """Every A and AAAA address for ``host``. Tests may monkeypatch this.

    ``classify_host`` runs the lookup in a daemon thread and stops waiting
    at ``timeout``. This function itself does not time out.
    """
    found: list[str] = []
    for info in socket.getaddrinfo(host, None):
        sockaddr = info[4]
        if not sockaddr:
            continue
        address = str(sockaddr[0]).split("%", 1)[0]
        if address and address not in found:
            found.append(address)
    return found


def _parse_address(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if isinstance(ip, str):
        text = ip.strip().lower().rstrip(".")
        if text.startswith("[") and text.endswith("]") and len(text) >= 2:
            text = text[1:-1].strip()
        if "%" in text:
            text = text.split("%", 1)[0]
        return ipaddress.ip_address(text)
    return ip


def _ipv4_compatible(address: ipaddress.IPv6Address) -> bool:
    """True for ``::a.b.c.d``. ``::`` and ``::1`` are not this form."""
    if address.is_unspecified or address.is_loopback:
        return False
    return int(address) >> 32 == 0


def _is_loopback(item: str) -> bool:
    try:
        address = _parse_address(item)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback


class _Pending:
    __slots__ = ("done", "error", "result")

    def __init__(self) -> None:
        self.done = threading.Event()
        self.result: list[str] = []
        self.error: BaseException | None = None


_LOCK = threading.Lock()
_INFLIGHT: dict[tuple[int, str], _Pending] = {}
_NEGATIVE: dict[tuple[int, str], float] = {}


def clear_cache() -> None:
    """Forget in-flight bookkeeping and negative entries. For tests."""
    with _LOCK:
        _INFLIGHT.clear()
        _NEGATIVE.clear()


def _lookup(resolver: Resolver, host: str, timeout: float) -> list[str]:
    """Addresses for ``host``, or [] when the lookup failed or timed out.

    One resolver call per (resolver, host) runs at a time. Other callers
    wait on it, each for at most its own ``timeout``. A failure, an empty
    answer, or a timeout is remembered for ``NEGATIVE_TTL`` seconds.
    """
    key = (id(resolver), host)
    now = time.monotonic()
    start = False
    with _LOCK:
        expiry = _NEGATIVE.get(key)
        if expiry is not None:
            if expiry > now:
                return []
            del _NEGATIVE[key]
        pending = _INFLIGHT.get(key)
        if pending is None:
            pending = _Pending()
            _INFLIGHT[key] = pending
            start = True
    if start:
        worker = threading.Thread(
            target=_run,
            args=(resolver, host, key, pending),
            name="praxis-locality",
            daemon=True,
        )
        worker.start()
    if not pending.done.wait(timeout if timeout > 0 else 0):
        with _LOCK:
            _NEGATIVE[key] = time.monotonic() + NEGATIVE_TTL
        return []
    if pending.error is not None:
        return []
    return list(pending.result)


def _run(resolver: Resolver, host: str, key: tuple[int, str], pending: _Pending) -> None:
    try:
        pending.result = [str(item) for item in resolver(host)]
    except Exception as exc:  # any resolver failure fails closed
        pending.error = exc
    failed = pending.error is not None or not pending.result
    with _LOCK:
        # Only the current lookup for this key updates the shared state.
        # After ``clear_cache`` a late finisher just wakes its own waiters.
        if _INFLIGHT.get(key) is pending:
            del _INFLIGHT[key]
            if failed:
                _NEGATIVE[key] = time.monotonic() + NEGATIVE_TTL
            else:
                _NEGATIVE.pop(key, None)
    pending.done.set()
