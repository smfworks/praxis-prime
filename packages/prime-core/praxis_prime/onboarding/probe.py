"""Bounded probes. No redirects, short deadlines, size caps. No credential URLs."""

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
_METADATA = "169.254.169.254"


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
    parts = _validate_url(url)
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
        )
    except ProbeError:
        raise
    except ssl.SSLError as exc:
        if parts.scheme != "https" or not capture_fingerprint:
            raise ProbeError(f"TLS verification failed ({exc})") from exc
        fingerprint = _fingerprint_only(parts, timeout)
        raise ProbeError(
            "certificate is not trusted; the fingerprint was not used as trust",
            fingerprint=fingerprint,
        ) from exc
    except TimeoutError as exc:
        raise ProbeError("probe timed out") from exc
    except OSError as exc:
        raise ProbeError(f"probe failed ({exc})") from exc


def _validate_url(url: str) -> urlsplit:
    parts = urlsplit(url.strip())
    if parts.scheme not in {"http", "https"}:
        raise ProbeError("only http and https URLs are allowed")
    if parts.username or parts.password:
        raise ProbeError("credentials in the URL are not allowed")
    host = (parts.hostname or "").strip().lower()
    if not host:
        raise ProbeError("the URL needs a host")
    if host in {_METADATA, "metadata.google.internal"}:
        raise ProbeError("metadata addresses are not allowed")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and str(address) == _METADATA:
        raise ProbeError("metadata addresses are not allowed")
    return parts


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
) -> FetchResult:
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    connection = _connection(parts.scheme, host, port, timeout, unverified=unverified)
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


def _fingerprint_only(parts, timeout: float) -> str:
    host = parts.hostname or ""
    port = parts.port or 443
    connection = _connection(parts.scheme, host, port, timeout, unverified=True)
    try:
        connection.connect()
        return _peer_fingerprint(connection.sock)
    except (OSError, ProbeError, ssl.SSLError):
        return ""
    finally:
        connection.close()


def _connection(
    scheme: str,
    host: str,
    port: int,
    timeout: float,
    *,
    unverified: bool,
) -> http.client.HTTPConnection:
    if scheme == "https":
        context = ssl._create_unverified_context() if unverified else ssl.create_default_context()
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    return http.client.HTTPConnection(host, port, timeout=timeout)


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
