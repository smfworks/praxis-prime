"""Metadata aliases are refused after a mocked resolve, then the connection is pinned."""

from __future__ import annotations

import socket
import ssl

import pytest

from praxis_prime.onboarding.probe import ProbeError, fetch

_BLOCKED = [
    ("http://2852039166/latest/meta-data/", ["169.254.169.254"]),
    ("http://0251.0376.0251.0376/", ["169.254.169.254"]),
    ("http://0xa9fea9fe/", ["169.254.169.254"]),
    ("http://169.254.169.254./", ["169.254.169.254"]),
    ("http://[::ffff:169.254.169.254]/", ["::ffff:169.254.169.254"]),
    ("http://metadata.attacker.example/latest/", ["169.254.169.254"]),
    ("http://169.254.170.2/", ["169.254.170.2"]),
    ("http://[fd00:ec2::254]/", ["fd00:ec2::254"]),
    ("http://100.100.100.200/", ["100.100.100.200"]),
    ("http://[fe80::1]/", ["fe80::1"]),
    ("http://[64:ff9b::a9fe:a9fe]/", ["64:ff9b::a9fe:a9fe"]),
    ("http://0.1.2.3/", ["0.1.2.3"]),
    ("http://0.0.0.0/", ["0.0.0.0"]),
    ("http://[::]/", ["::"]),
    ("http://224.0.0.1/", ["224.0.0.1"]),
    ("http://255.255.255.255/", ["255.255.255.255"]),
    ("http://metadata.google.internal/", ["203.0.113.5"]),
    ("http://metadata.goog./", ["203.0.113.5"]),
]

_ALLOWED = [
    ("http://127.0.0.1:9/v1/models", ["127.0.0.1"], ("127.0.0.1", 9)),
    ("http://[::1]:9/v1/models", ["::1"], ("::1", 9)),
    ("http://10.1.2.3/v1/models", ["10.1.2.3"], ("10.1.2.3", 80)),
    ("http://192.168.1.5/v1/models", ["192.168.1.5"], ("192.168.1.5", 80)),
    ("http://172.16.0.4/v1/models", ["172.16.0.4"], ("172.16.0.4", 80)),
    ("http://[fd00::1]/v1/models", ["fd00::1"], ("fd00::1", 80)),
    ("http://100.64.0.1/v1/models", ["100.64.0.1"], ("100.64.0.1", 80)),
]


@pytest.mark.parametrize(("url", "answers"), _BLOCKED)
def test_metadata_aliases_do_not_connect(
    monkeypatch: pytest.MonkeyPatch,
    url: str,
    answers: list[str],
) -> None:
    monkeypatch.setattr(
        "praxis_prime.onboarding.probe._resolve",
        lambda _host, _port: list(answers),
    )

    def connect(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("blocked address was connected")

    monkeypatch.setattr(socket, "create_connection", connect)
    with pytest.raises(ProbeError, match="not allowed"):
        fetch("GET", url, timeout=0.2)


def test_one_blocked_address_refuses_the_whole_set(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "praxis_prime.onboarding.probe._resolve",
        lambda _host, _port: ["10.1.2.3", "169.254.169.254"],
    )

    def connect(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("mixed result was connected")

    monkeypatch.setattr(socket, "create_connection", connect)
    with pytest.raises(ProbeError, match="not allowed"):
        fetch("GET", "http://mixed.example/v1/models", timeout=0.2)


@pytest.mark.parametrize(("url", "answers", "pinned"), _ALLOWED)
def test_allowed_ranges_pin_the_checked_address(
    monkeypatch: pytest.MonkeyPatch,
    url: str,
    answers: list[str],
    pinned: tuple[str, int],
):
    monkeypatch.setattr(
        "praxis_prime.onboarding.probe._resolve",
        lambda _host, _port: list(answers),
    )
    seen: list[tuple[object, ...]] = []

    def connect(address: tuple[object, ...], timeout: float | None = None) -> None:
        del timeout
        seen.append(address)
        raise OSError("stopped")

    monkeypatch.setattr(socket, "create_connection", connect)
    with pytest.raises(ProbeError, match="stopped"):
        fetch("GET", url, timeout=0.2)
    assert seen == [pinned]


def test_https_sni_is_the_hostname_not_the_pinned_address(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "praxis_prime.onboarding.probe._resolve",
        lambda _host, _port: ["127.0.0.1"],
    )
    seen: dict[str, object] = {}

    class _Sock:
        def close(self) -> None:
            return None

    def connect(address: tuple[object, ...], timeout: float | None = None) -> _Sock:
        del timeout
        seen["address"] = address
        return _Sock()

    def wrap(
        self: object,
        sock: object,
        server_hostname: str | None = None,
        **kwargs: object,
    ) -> None:
        del self, sock, kwargs
        seen["sni"] = server_hostname
        raise ssl.SSLError("stopped")

    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
    with pytest.raises(ProbeError, match="TLS verification failed"):
        fetch("GET", "https://ollama.local/v1/models", timeout=0.2)
    assert seen["address"] == ("127.0.0.1", 443)
    assert seen["sni"] == "ollama.local"
