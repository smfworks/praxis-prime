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
    ("http://[::169.254.169.254]/", ["::169.254.169.254"]),
    ("http://[2002:a9fe:a9fe::]/", ["2002:a9fe:a9fe::"]),
    ("http://[::0.1.2.3]/", ["::0.1.2.3"]),
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
    ("http://[::127.0.0.1]:9/v1/models", ["::127.0.0.1"], ("::127.0.0.1", 9)),
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


def test_probe_tries_each_allowed_address(monkeypatch: pytest.MonkeyPatch):
    from praxis_prime.onboarding.probe import FetchResult

    monkeypatch.setattr(
        "praxis_prime.onboarding.probe._resolve",
        lambda _host, _port: ["::1", "127.0.0.1"],
    )
    tried: list[str] = []

    def exchange(*_args: object, **kwargs: object) -> FetchResult:
        pinned = str(kwargs["pinned"])
        tried.append(pinned)
        if pinned == "::1":
            raise OSError("refused")
        return FetchResult(200, b"{}")

    monkeypatch.setattr("praxis_prime.onboarding.probe._exchange", exchange)
    result = fetch("GET", "http://localhost/v1/models", timeout=1)
    assert result.status == 200
    assert tried == ["::1", "127.0.0.1"]


def test_probe_does_not_fail_over_a_redirect(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "praxis_prime.onboarding.probe._resolve",
        lambda _host, _port: ["::1", "127.0.0.1"],
    )
    tried: list[str] = []

    def exchange(*_args: object, **kwargs: object) -> None:
        tried.append(str(kwargs["pinned"]))
        raise ProbeError("redirect refused (302)")

    monkeypatch.setattr("praxis_prime.onboarding.probe._exchange", exchange)
    with pytest.raises(ProbeError, match="redirect refused"):
        fetch("GET", "http://localhost/v1/models", timeout=1)
    assert tried == ["::1"]


def test_probe_stops_when_the_deadline_is_spent(monkeypatch: pytest.MonkeyPatch):
    import time

    monkeypatch.setattr(
        "praxis_prime.onboarding.probe._resolve",
        lambda _host, _port: ["::1", "127.0.0.1"],
    )
    tried: list[str] = []

    def exchange(*_args: object, **kwargs: object) -> None:
        tried.append(str(kwargs["pinned"]))
        time.sleep(0.3)
        raise TimeoutError("slow")

    monkeypatch.setattr("praxis_prime.onboarding.probe._exchange", exchange)
    with pytest.raises(ProbeError, match="timed out"):
        fetch("GET", "http://localhost/v1/models", timeout=0.2)
    assert tried == ["::1"]
