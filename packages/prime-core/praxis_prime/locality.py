"""Classify a provider base URL as local, lan, or cloud.

The result is not cached. A cache would keep a name's old addresses after
DNS changes and widen the rebinding window. Callers that enforce routing
classify again at request time; see ``compliance.providers.filter_chain``.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from collections.abc import Callable, Sequence
from typing import Literal
from urllib.parse import urlsplit

Locality = Literal["local", "lan", "cloud"]
Resolver = Callable[[str], Sequence[str]]

_RANK = {"local": 0, "lan": 1, "cloud": 2}

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

    An empty host is cloud. ``localhost`` and names ending in ``.localhost``
    are local and are not resolved (RFC 6761). An IP literal uses
    ``classify_address``. Any other name is resolved. The result is the most
    remote class: cloud beats lan, and lan beats local, so one public
    address makes the host cloud and a mix of loopback and lan is lan.
    A timeout, any resolver error, or no addresses is cloud.
    """
    text = host.strip().lower().rstrip(".")
    if text.startswith("[") and text.endswith("]") and len(text) >= 2:
        text = text[1:-1].strip()
    if "%" in text:
        text = text.split("%", 1)[0]
    if not text:
        return "cloud"
    if text == "localhost" or text.endswith(".localhost"):
        return "local"
    try:
        return classify_address(text)
    except ValueError:
        pass
    lookup = resolve_host if resolver is None else resolver
    try:
        found = _invoke(lookup, text, timeout)
    except Exception:  # any resolver failure fails closed
        return "cloud"
    if not found:
        return "cloud"
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


def _invoke(resolver: Resolver, host: str, timeout: float) -> list[str]:
    """Run ``resolver`` in a daemon thread. A timeout yields no addresses."""
    box: list[list[str] | BaseException] = []

    def run() -> None:
        try:
            box.append([str(item) for item in resolver(host)])
        except Exception as exc:  # handed back to the caller thread
            box.append(exc)

    worker = threading.Thread(target=run, name="praxis-locality", daemon=True)
    worker.start()
    worker.join(timeout if timeout > 0 else 0)
    if worker.is_alive() or not box:
        return []
    result = box[0]
    if isinstance(result, BaseException):
        raise result
    return result
