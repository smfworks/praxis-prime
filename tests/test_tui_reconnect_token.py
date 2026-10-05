"""Reconnect reads gateway.token again after a rotation."""

from __future__ import annotations

import asyncio
import os
import socket
import tempfile
import threading
from pathlib import Path

import pytest
from tests.test_tui_app import _submit, _until
from tests.test_tui_round2 import _live_app, _status, _UnixGateway

from praxis_prime.gateway.auth import rotate_token
from praxis_prime.gateway.client import GatewayClient
from praxis_prime.gateway.discover import discover, gateway_paths, write_discovery
from praxis_prime.tui.gateway import TuiGateway
from praxis_prime.tui.plain import run_plain
from praxis_prime.tui.sessions import SessionBook


class _Health:
    """Loopback GET /health for discover()."""

    def __init__(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        self.port = int(sock.getsockname()[1])
        sock.listen(8)
        sock.settimeout(0.2)
        self._sock = sock
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, name="tui-health", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(2)

    def _serve(self) -> None:
        body = b'{"ok": true}'
        response = (
            b"HTTP/1.1 200 OK\r\nContent-Length: "
            + str(len(body)).encode("ascii")
            + b"\r\nConnection: close\r\n\r\n"
            + body
        )
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                conn.settimeout(0.5)
                conn.recv(4096)
                conn.sendall(response)
            except OSError:
                pass
            finally:
                conn.close()


class _RotatingDaemon:
    """A unix gateway whose token file can be rotated out from under the client."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        runtime = tmp_path / "xdg"
        runtime.mkdir()
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
        self.path = tmp_path / "g.sock"
        if len(str(self.path)) > 100:
            self.path = Path(tempfile.mkdtemp(prefix="pptui")) / "g.sock"
        self.old = "token-before-rotation"
        self.server = _UnixGateway(self.path, token=self.old)
        self.health = _Health()
        self.server.start(drop_chat=True)
        self._write_token(self.old)
        write_discovery(
            env=None,
            pid=os.getpid(),
            port=self.health.port,
            socket_path=str(self.path),
            version="test",
            started_at="2026-01-01T00:00:00Z",
        )

    def connect(self) -> TuiGateway:
        endpoint = discover()
        assert endpoint is not None
        assert endpoint.token == self.old
        assert endpoint.socket_path == str(self.path)
        return TuiGateway.connect(endpoint, profile="default", discover=discover)

    def rotate_and_restart(self) -> str:
        _info, token_path = gateway_paths()
        rotate_token(token_path)
        new = token_path.read_text(encoding="utf-8").strip()
        assert new and new != self.old
        self.server.token = new
        self.server.restart()
        found = discover()
        assert found is not None and found.token == new
        return new

    def close(self) -> None:
        self.server.stop()
        self.health.stop()
        if self.path.exists():
            self.path.unlink()

    def _write_token(self, token: str) -> None:
        _info, token_path = gateway_paths()
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(token + "\n", encoding="utf-8")
        os.chmod(token_path, 0o600)


def test_tui_reconnects_after_the_token_rotates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    daemon = _RotatingDaemon(tmp_path, monkeypatch)
    gateway: TuiGateway | None = None
    try:
        gateway = daemon.connect()
        first = gateway.frames.client
        assert isinstance(first, GatewayClient)
        app = _live_app(gateway)

        async def run() -> None:
            async with app.run_test(size=(100, 30)) as pilot:
                await _until(pilot, lambda: app.booted)
                await _submit(pilot, app, "hi")
                await _wait(pilot, lambda: "disconnected" in _status(app))
                assert first.closed
                daemon.rotate_and_restart()
                await _wait(
                    pilot,
                    lambda: gateway.connected and "disconnected" not in _status(app),
                )
                renewed = gateway.frames.client
                assert isinstance(renewed, GatewayClient)
                assert renewed is not first
                assert not renewed.closed
                await _submit(pilot, app, "ping")
                await _wait(pilot, lambda: "pong" in app.transcript_text())

        asyncio.run(run())
    finally:
        if gateway is not None:
            gateway.close()
        daemon.close()
    assert daemon.server.tokens[0] == daemon.old
    assert daemon.server.tokens[-1] != daemon.old
    assert set(daemon.server.clients) == {"tui"}


def test_plain_reconnects_after_the_token_rotates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    daemon = _RotatingDaemon(tmp_path, monkeypatch)
    gateway: TuiGateway | None = None
    try:
        gateway = daemon.connect()
        lines = iter(["hi", "ping", "/quit"])

        def read_line() -> str:
            try:
                line = next(lines)
            except StopIteration as exc:
                raise EOFError from exc
            if line == "ping":
                daemon.rotate_and_restart()
            return line

        out: list[str] = []
        code = run_plain(
            gateway=gateway,
            sessions=SessionBook(),
            read_line=read_line,
            write=out.append,
            port=daemon.health.port,
        )
    finally:
        if gateway is not None:
            gateway.close()
        daemon.close()
    text = "".join(out)
    assert code == 0
    assert "prime: pong" in text
    assert daemon.server.tokens[0] == daemon.old
    assert daemon.server.tokens[-1] != daemon.old
    assert set(daemon.server.clients) == {"tui"}


async def _wait(pilot: object, pred) -> None:
    for _ in range(400):
        if pred():
            return
        await pilot.pause(0.05)  # type: ignore[attr-defined]
    raise AssertionError("timed out waiting for the TUI")
