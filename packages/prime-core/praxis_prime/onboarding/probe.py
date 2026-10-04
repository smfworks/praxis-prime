"""Bounded probes. No redirects, short deadlines, size caps. No credential URLs.

Metadata and link-local addresses are refused after resolution. Loopback,
RFC1918, ULA, and carrier-grade NAT stay allowed for Ollama, a LAN host,
and Tailscale. ``100.100.100.200`` and ``fd00:ec2::254`` are the exceptions
inside those ranges. The connection uses the address that was checked.
TLS still verifies the URL hostname and sends that name as SNI.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from praxis_prime.gateway.protocol import secrets_equal

PROBE_LIMIT = 256 * 1024
TEST_LIMIT = 1024 * 1024
PROBE_TIMEOUT = 5.0
_METADATA_NAMES = frozenset({"metadata.google.internal", "metadata.goog"})
_THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_ALIBABA = ipaddress.ip_address("100.100.100.200")
_EC2_METADATA = ipaddress.ip_address("fd00:ec2::254")
_BROADCAST = ipaddress.ip_address("255.255.255.255")


class ProbeError(Exception):
    """The probe refused the URL or the peer."""

    def __init__(self, message: str, *, fingerprint: str = "") -> None:
        self.fingerprint = fingerprint
        super().__init__(message)


@dataclass
class FetchResult:
    status: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)
    fingerprint: str = ""


def fetch(
    method: str,
    url: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = PROBE_TIMEOUT,
    limit: int = PROBE_LIMIT,
    pin: str = "",
    capture_fingerprint: bool = False,
) -> FetchResult:
    """One request. Redirects are refused. A pin is a SHA-256 of the peer cert."""
    parts, pinned = _prepare(url)
    deadline = time.monotonic() + timeout
    try:
        return _exchange(
            method,
            parts,
            body=body,
            headers=headers or {},
            timeout=timeout,
            limit=limit,
            pin=pin.strip().lower(),
            capture_fingerprint=capture_fingerprint,
            deadline=deadline,
            unverified=bool(pin),
            pinned=pinned,
        )
    except ProbeError:
        raise
    except ssl.SSLError as exc:
        if parts.scheme != "https" or not capture_fingerprint:
            raise ProbeError(f"TLS verification failed ({exc})") from exc
        fingerprint = _fingerprint_only(parts, timeout, pinned)
        raise ProbeError(
            "certificate is not trusted; the fingerprint was not used as trust",
            fingerprint=fingerprint,
        ) from exc
    except TimeoutError as exc:
        raise ProbeError("probe timed out") from exc
    except OSError as exc:
        raise ProbeError(f"probe failed ({exc})") from exc


def _prepare(url: str) -> tuple[urlsplit, str]:
    parts = _validate_url(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    addresses = _resolve(host, port)
    for address in addresses:
        if _address_blocked(address):
            raise ProbeError("that address is not allowed")
    return parts, addresses[0]


def _validate_url(url: str) -> urlsplit:
    parts = urlsplit(url.strip())
    if parts.scheme not in {"http", "https"}:
        raise ProbeError("only http and https URLs are allowed")
    if parts.username or parts.password:
        raise ProbeError("credentials in the URL are not allowed")
    host = (parts.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise ProbeError("the URL needs a host")
    if host in _METADATA_NAMES:
        raise ProbeError("metadata addresses are not allowed")
    return parts


def _resolve(host: str, port: int) -> list[str]:
    """Addresses for ``host``. Numeric forms are normalized here. Tests replace this."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ProbeError(f"probe failed ({exc})") from exc
    found: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        address = str(sockaddr[0]).split("%", 1)[0]
        if address and address not in found:
            found.append(address)
    if not found:
        raise ProbeError("the URL did not resolve")
    return found


def _address_blocked(text: str) -> bool:
    parsed = _parse_ip(text)
    if parsed is None:
        return True
    return _blocked_ip(_canonical(parsed))


def _parse_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    bare = text.split("%", 1)[0].strip()
    try:
        return ipaddress.ip_address(bare)
    except ValueError:
        return None


def _canonical(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Unwrap IPv4-mapped and well-known NAT64 (``64:ff9b::/96``) addresses."""
    if isinstance(address, ipaddress.IPv6Address):
        mapped = address.ipv4_mapped
        if mapped is not None:
            return mapped
        if address in _NAT64:
            return ipaddress.IPv4Address(address.packed[-4:])
    return address


def _blocked_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if address.is_multicast or address.is_unspecified or address.is_link_local:
        return True
    if address in {_BROADCAST, _ALIBABA, _EC2_METADATA}:
        return True
    return address.version == 4 and address in _THIS_NETWORK


def _exchange(
    method: str,
    parts,
    *,
    body: bytes | None,
    headers: dict[str, str],
    timeout: float,
    limit: int,
    pin: str,
    capture_fingerprint: bool,
    deadline: float,
    unverified: bool,
    pinned: str,
) -> FetchResult:
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    connection = _connection(
        parts.scheme,
        host,
        port,
        timeout,
        unverified=unverified,
        pinned=pinned,
    )
    try:
        connection.connect()
        fingerprint = ""
        if parts.scheme == "https" and (pin or capture_fingerprint):
            fingerprint = _peer_fingerprint(connection.sock)
            if pin and not secrets_equal(pin, fingerprint):
                raise ProbeError("TLS fingerprint does not match", fingerprint=fingerprint)
            if capture_fingerprint and not pin:
                raise ProbeError(
                    "certificate is not trusted; the fingerprint was not used as trust",
                    fingerprint=fingerprint,
                )
        if time.monotonic() > deadline:
            raise ProbeError("probe timed out")
        connection.request(method.upper(), path, body=body, headers=headers)
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise ProbeError(f"redirect refused ({response.status})")
        payload = _read_capped(response, limit, deadline)
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        return FetchResult(response.status, payload, response_headers, fingerprint)
    finally:
        connection.close()


def _fingerprint_only(parts, timeout: float, pinned: str) -> str:
    host = parts.hostname or ""
    port = parts.port or 443
    connection = _connection(parts.scheme, host, port, timeout, unverified=True, pinned=pinned)
    try:
        connection.connect()
        return _peer_fingerprint(connection.sock)
    except (OSError, ProbeError, ssl.SSLError):
        return ""
    finally:
        connection.close()


class _BoundConnection(http.client.HTTPConnection):
    """Connect to the checked address. TLS keeps the URL host for SNI and verify."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        timeout: float,
        pinned: str,
        context: ssl.SSLContext | None,
    ) -> None:
        super().__init__(host, port, timeout=timeout)
        self._pinned = pinned
        self._context = context

    def connect(self) -> None:
        raw = socket.create_connection((self._pinned, self.port), self.timeout)
        if self._context is None:
            self.sock = raw
            return
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def _connection(
    scheme: str,
    host: str,
    port: int,
    timeout: float,
    *,
    unverified: bool,
    pinned: str,
) -> _BoundConnection:
    context = None
    if scheme == "https":
        context = ssl._create_unverified_context() if unverified else ssl.create_default_context()
    return _BoundConnection(host, port, timeout=timeout, pinned=pinned, context=context)


def _peer_fingerprint(sock: socket.socket | None) -> str:
    if sock is None:
        raise ProbeError("TLS peer certificate is missing")
    der = sock.getpeercert(binary_form=True)
    if not der:
        raise ProbeError("TLS peer certificate is missing")
    return hashlib.sha256(der).hexdigest()


def _read_capped(response: http.client.HTTPResponse, limit: int, deadline: float) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        if time.monotonic() > deadline:
            raise ProbeError("probe timed out")
        block = response.read(8192)
        if not block:
            break
        total += len(block)
        if total > limit:
            raise ProbeError("probe response is too large")
        chunks.append(block)
    return b"".join(chunks)


def parse_json(body: bytes) -> dict[str, object]:
    try:
        loaded = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProbeError("the server did not return JSON") from exc
    if not isinstance(loaded, dict):
        raise ProbeError("the server did not return a JSON object")
    return loaded
