"""Round-2 terminal fixes: confirm, scroll, reconnect, and visible text."""

from __future__ import annotations

import asyncio
import io
import json
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest
from tests.test_tui_app import _app, _confirm, _submit, _until
from tests.test_tui_gateway import FakeFrames, FakeHttp
from tests.test_tui_review import CARD, OSC52
from textual.geometry import Region
from textual.widgets import Button, Static

from praxis_prime.gateway.client import Endpoint, GatewayClient, GatewayError
from praxis_prime.gateway.ws import (
    ByteBuffer,
    WebSocketConnection,
    _headers,
    server_upgrade_response,
)
from praxis_prime.sanitize import sanitize
from praxis_prime.tui import _write_stdout, run_tui
from praxis_prime.tui.app import ConfirmDecision, HelpScreen
from praxis_prime.tui.cards import render_card
from praxis_prime.tui.gateway import TuiGateway
from praxis_prime.tui.plain import run_plain
from praxis_prime.tui.sanitize import sanitize as tui_sanitize
from praxis_prime.tui.sessions import SessionBook

_INVISIBLE = (
    0x00AD,
    0x034F,
    0x061C,
    0x115F,
    0x1160,
    0x200B,
    0x200C,
    0x200D,
    0x200E,
    0x200F,
    0x202A,
    0x202B,
    0x202C,
    0x202D,
    0x202E,
    0x2060,
    0x2061,
    0x2062,
    0x2063,
    0x2064,
    0x2066,
    0x2067,
    0x2068,
    0x2069,
    0x3164,
    0xFE00,
    0xFE0F,
    0xFEFF,
    0xFFA0,
    0xE0100,
    0xE01EF,
    0xE0001,
    0xE007F,
    0xD800,
    0xDFFF,
)


def test_sanitiser_escapes_each_invisible_class() -> None:
    assert sanitize is tui_sanitize
    for code in _INVISIBLE:
        shown = sanitize(f"A{chr(code)}B")
        assert chr(code) not in shown, hex(code)
        assert f"<U+{code:04X}>" in shown
        assert shown.startswith("A") and shown.endswith("B")
        assert sanitize(shown) == shown
    marks = sanitize("e" + "\u0301" * 4)
    assert marks == "e\u0301\u0301<U+0301><U+0301>"
    grapheme = sanitize("e\u034f\u0301\u0301")
    assert grapheme == "e<U+034F>\u0301\u0301"
    variation = sanitize("e\ufe0f\u0301\u0301\u0301")
    assert variation == "e<U+FE0F>\u0301\u0301<U+0301>"


def test_stdout_write_escapes_a_lone_surrogate(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = io.BytesIO()

    class _Out:
        buffer = captured

        def write(self, text: str) -> None:
            raise AssertionError(text)

        def flush(self) -> None:
            return

    monkeypatch.setattr(sys, "stdout", _Out())
    _write_stdout("hi\ud800")
    assert captured.getvalue() == b"hi\\ud800"


def test_connect_error_is_sanitised(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def discover() -> Endpoint:
        return Endpoint("127.0.0.1", 1, "tok")

    def boom(endpoint: Endpoint, *, profile: str = "", discover: object = None) -> TuiGateway:
        del endpoint, profile, discover
        raise GatewayError("nope\x1b]0;owned\x07")

    monkeypatch.setattr("praxis_prime.tui.TuiGateway.connect", boom)
    code = run_tui(plain=True, discover=discover)
    assert code == 1
    err = capsys.readouterr().err
    assert "\x1b" not in err
    assert "\\x1b" in err
    assert "owned" in err


def test_decision_failed_releases_the_latch() -> None:
    app, _gateway = _app(FakeFrames())
    app._latched.update({"ap1", "ap2"})
    app._apply_event(
        "",
        {
            "kind": "decision_failed",
            "approval_id": "ap1",
            "phase": "error",
            "detail": "decision ap1: connection closed",
        },
    )
    assert "ap1" not in app._latched
    assert "ap2" in app._latched
    assert "decision ap1: connection closed" in app.timeline_text()


def test_plain_flushes_text_before_the_approval_card() -> None:
    frames = FakeFrames()

    def script(text, session_id, on_event, decider, timeout, profile):
        del text, session_id, decider, timeout, profile
        on_event({"kind": "text", "text": "before the card"})
        on_event({"kind": "approval", "approval": dict(CARD)})
        return {"type": "result", "ok": True, "payload": {"sessionId": "s1", "text": ""}}

    frames.chat_impl = script
    out: list[str] = []
    lines = iter(["hello", "/quit"])
    code = run_plain(
        gateway=TuiGateway(frames, FakeHttp(), profile="default"),
        sessions=SessionBook(),
        read_line=_reader(lines),
        write=out.append,
        port=18790,
    )
    text = "".join(out)
    assert code == 0
    assert text.index("prime: before the card") < text.index("Approval needed")


def test_plain_reconnects_before_the_next_send() -> None:
    frames = FakeFrames()

    def script(text, session_id, on_event, decider, timeout, profile):
        del text, session_id, on_event, decider, timeout, profile
        raise GatewayError("connection closed")

    frames.chat_impl = script
    gateway = TuiGateway(frames, FakeHttp(), profile="default")
    fresh = FakeFrames()
    gateway._connector = lambda: (fresh, FakeHttp())
    out: list[str] = []
    code = run_plain(
        gateway=gateway,
        sessions=SessionBook(),
        read_line=_reader(iter(["hello", "again", "/quit"])),
        write=out.append,
        port=18790,
    )
    text = "".join(out)
    assert code == 0
    assert "error: connection closed" in text
    assert "disconnected, retrying" not in text
    assert fresh.chats and fresh.chats[0]["text"] == "again"
    assert "prime: ok" in text


def test_plain_says_retrying_when_the_reconnect_fails() -> None:
    frames = FakeFrames()

    def script(text, session_id, on_event, decider, timeout, profile):
        del text, session_id, on_event, decider, timeout, profile
        raise GatewayError("broken pipe")

    frames.chat_impl = script
    gateway = TuiGateway(frames, FakeHttp(), profile="default")

    def connector():
        raise OSError("down")

    gateway._connector = connector
    out: list[str] = []
    code = run_plain(
        gateway=gateway,
        sessions=SessionBook(),
        read_line=_reader(iter(["hello", "again", "/quit"])),
        write=out.append,
        port=18790,
    )
    text = "".join(out)
    assert code == 0
    assert "disconnected, retrying" in text
    assert frames.chats and len(frames.chats) == 1


def test_typing_and_edit_keys_do_not_decide() -> None:
    frames = FakeFrames()
    frames.approvals = [dict(CARD)]
    app, _gateway = _app(frames)

    async def run() -> None:
        async with app.run_test(size=(110, 36)) as pilot:
            await _until(pilot, lambda: app.approval_ids() == ["ap1"])
            await pilot.press("f3")
            await _until(pilot, lambda: app.focused is not None and app.focused.id == "approvals")
            for key in ("t", "h", "i", "s", "space", "i", "s"):
                await pilot.press(key)
            await pilot.press("ctrl+u")
            for key in ("d", "r", "a", "f", "t"):
                await pilot.press(key)
            await pilot.press("ctrl+x")
            await pilot.pause(0.2)
            if len(app.screen_stack) > 1:
                await pilot.press("escape")
                await pilot.pause()
            assert frames.decisions == []
            assert len(app.screen_stack) == 1
            await pilot.pause(0.85)
            await pilot.press("f3")
            await pilot.press("a")
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause(0.1)
            assert frames.decisions == []
            assert len(app.screen_stack) == 1
            await _confirm(pilot, "a")
            await _until(pilot, lambda: len(frames.decisions) == 1)

    asyncio.run(run())
    assert frames.decisions == [("ap1", "allow_once", "default")]


def test_question_mark_opens_help_from_the_list() -> None:
    app, _gateway = _app(FakeFrames())

    async def run() -> None:
        async with app.run_test(size=(100, 30)) as pilot:
            await _until(pilot, lambda: app.booted)
            await pilot.press("f3")
            await pilot.pause()
            await pilot.press("question_mark")
            await pilot.pause()
            assert isinstance(app.screen, HelpScreen)

    asyncio.run(run())


def test_approval_id_controls_are_escaped_in_the_list() -> None:
    frames = FakeFrames()
    evil = "ap" + OSC52 + "\x1b]0;owned\x07" + "\x1b]2;title\x07"
    item = dict(CARD)
    item["id"] = evil
    frames.approvals = [item]
    app, _gateway = _app(frames)

    async def run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await _until(pilot, lambda: app.approval_ids() == [evil])
            approvals = app.query_one("#approvals")
            prompt = str(approvals.get_option(evil).prompt)
            painted = "".join(approvals.render_line(y).text for y in range(approvals.size.height))
            assert "\x1b" not in prompt
            assert "\x1b" not in painted
            assert "\\x1b" in prompt
            assert "owned" in prompt
            assert app._selected_id == evil

    asyncio.run(run())


def test_poll_does_not_reset_card_scroll() -> None:
    frames = FakeFrames()
    item = dict(CARD)
    item["summary"] = ("ls -la " * 40) + "rm -rf ~/scratch"
    frames.approvals = [item]
    app, _gateway = _app(frames)

    async def run() -> None:
        async with app.run_test(size=(90, 28)) as pilot:
            await _until(pilot, lambda: app.approval_ids() == ["ap1"])
            scroller = app.query_one("#card-scroll")
            await pilot.press("f3")
            await pilot.pause()
            if scroller.max_scroll_y <= 0:
                scroller.styles.max_height = 4
                await pilot.pause()
            assert scroller.max_scroll_y > 0
            await pilot.press("pagedown")
            await pilot.pause()
            assert scroller.scroll_y > 0
            mark = scroller.scroll_y
            furthest = scroller.furthest
            app._set_approvals([dict(item)])
            await pilot.pause()
            app._poll_approvals()
            await pilot.pause(0.4)
            assert scroller.scroll_y == mark
            assert scroller.furthest == furthest

    asyncio.run(run())


def test_truncated_card_needs_the_full_text_paged() -> None:
    frames = FakeFrames()
    item = dict(CARD)
    item["summary"] = "A" * 4000
    frames.approvals = [item]
    app, _gateway = _app(frames)
    marker = f"...{4000 - 300} more"

    async def run() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            await _until(pilot, lambda: app.approval_ids() == ["ap1"])
            card = str(app.query_one("#card", Static).content)
            assert marker in card
            assert "Press v for the full text." in card
            assert "A" * 4000 not in card
            assert marker not in render_card(item, full=True)
            await pilot.press("f3")
            await pilot.pause()
            await pilot.press("end")
            await pilot.pause()
            await pilot.press("a")
            await pilot.pause(0.2)
            assert frames.decisions == []
            shown = " ".join(app.timeline_text().split())
            assert "Press v and page through the full text before deciding." in shown
            assert len(app.screen_stack) == 1
            await pilot.press("v")
            await pilot.pause()
            full = app.screen.query_one("#full-scroll")
            full.styles.height = 4
            full.styles.min_height = 4
            full.styles.max_height = 4
            await pilot.pause()
            assert full.max_scroll_y > 1
            assert not full.gate_met()
            await pilot.press("end")
            await pilot.pause()
            assert not full.gate_met()
            await pilot.press("home")
            await pilot.pause()
            for _ in range(40):
                if full.gate_met():
                    break
                await pilot.press("pagedown")
                await pilot.pause()
            assert full.gate_met()
            await pilot.press("escape")
            await pilot.pause()
            await _confirm(pilot, "a")
            await _until(pilot, lambda: len(frames.decisions) == 1)

    asyncio.run(run())
    assert frames.decisions == [("ap1", "allow_once", "default")]


@pytest.mark.parametrize("size", [(80, 24), (60, 20)])
def test_confirm_dialog_keeps_kind_and_buttons_on_screen(size: tuple[int, int]) -> None:
    app, _gateway = _app(FakeFrames())

    async def run() -> None:
        async with app.run_test(size=size) as pilot:
            await _until(pilot, lambda: app.booted)
            app.push_screen(
                ConfirmDecision(
                    approval_id="ap-9",
                    tool="shell",
                    action="Z" * 500,
                    decision="allow_once",
                    scope="",
                )
            )
            await pilot.pause()
            body = app.screen.query_one("#confirm-body")
            text_widget = app.screen.query_one("#confirm-text", Static)
            lines = [text_widget.render_line(y).text for y in range(text_widget.size.height)]
            visible = "\n".join(lines)
            assert "Approve once" in visible
            assert "Id: ap-9" in visible
            assert "Tool: shell" in visible
            assert visible.index("Approve once") < visible.index("Id:")
            assert visible.index("Id:") < visible.index("Tool:")
            bounds = Region(0, 0, app.size.width, app.size.height)
            assert bounds.contains_region(body.region)
            for needle in ("Approve once", "Id: ap-9", "Tool: shell"):
                index = next(i for i, line in enumerate(lines) if needle in line)
                y = text_widget.region.y + index
                assert body.region.y <= y < body.region.bottom
                assert 0 <= y < app.size.height
            text = str(text_widget.content)
            assert "Z" * 200 in text
            assert "Z" * 201 not in text
            assert "...300 more" in text
            for button_id in ("cancel", "confirm"):
                button = app.screen.query_one(f"#{button_id}", Button)
                assert button.region.width > 0 and button.region.height > 0
                assert bounds.contains_region(button.region)

    asyncio.run(run())


def test_streaming_append_stays_within_a_few_seconds() -> None:
    app, _gateway = _app(FakeFrames())
    chunk = "y" * 95

    async def run() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            await _until(pilot, lambda: app.booted)
            started = time.perf_counter()
            for _ in range(2000):
                app._apply_event("", {"kind": "text", "text": chunk})
            elapsed = time.perf_counter() - started
            assert elapsed < 4.0
            assert len(app.transcript_text()) > 100_000
            await pilot.pause(0.2)

    asyncio.run(run())


def test_real_client_reconnects_after_the_socket_is_killed(tmp_path: Path) -> None:
    path = tmp_path / "g.sock"
    if len(str(path)) > 100:
        path = Path(tempfile.mkdtemp(prefix="pptui")) / "g.sock"
    server = _UnixGateway(path)
    server.start(drop_chat=True)
    gateway: TuiGateway | None = None
    try:
        endpoint = Endpoint("127.0.0.1", 1, "test-token", socket_path=str(path))
        gateway = TuiGateway.connect(endpoint, profile="default")
        first = gateway.frames.client
        assert isinstance(first, GatewayClient)
        app = _live_app(gateway)

        async def run() -> None:
            async with app.run_test(size=(100, 30)) as pilot:
                await _until(pilot, lambda: app.booted)
                await _submit(pilot, app, "hi")
                await _wait_longer(pilot, lambda: "disconnected" in _status(app))
                assert first.closed
                server.restart()
                await _wait_longer(
                    pilot,
                    lambda: gateway.connected and "disconnected" not in _status(app),
                )
                await _submit(pilot, app, "ping")
                await _wait_longer(pilot, lambda: "pong" in app.transcript_text())

        asyncio.run(run())
    finally:
        if gateway is not None:
            gateway.close()
        server.stop()
        if path.exists():
            path.unlink()
    assert server.clients
    assert set(server.clients) == {"tui"}
    assert set(server.tokens) == {"test-token"}


def _reader(lines):
    stream = iter(lines)

    def read_line() -> str:
        try:
            return next(stream)
        except StopIteration as exc:
            raise EOFError from exc

    return read_line


def _status(app: object) -> str:
    return str(app.query_one("#status", Static).content)  # type: ignore[attr-defined]


def _live_app(gateway: TuiGateway):
    from praxis_prime.tui.app import PraxisApp

    return PraxisApp(gateway, profile="default")


async def _wait_longer(pilot: object, pred) -> None:
    for _ in range(160):
        if pred():
            return
        await pilot.pause(0.05)  # type: ignore[attr-defined]
    raise AssertionError("timed out waiting for the TUI")


class _UnixGateway:
    """A unix-socket gateway. The first chat dies the way kill -9 does."""

    def __init__(self, path: Path, token: str = "test-token") -> None:
        self.path = path
        self.token = token
        self.clients: list[str] = []
        self.tokens: list[str] = []
        self.dropped = threading.Event()
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def start(self, *, drop_chat: bool) -> None:
        self._ready.clear()
        if self.path.exists():
            self.path.unlink()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.path))
        listener.listen(4)
        listener.settimeout(0.2)
        self._listener = listener
        self._thread = threading.Thread(
            target=self._serve,
            args=(listener, drop_chat),
            name="tui-unix-gateway",
            daemon=True,
        )
        self._thread.start()
        assert self._ready.wait(2)

    def restart(self) -> None:
        self.stop()
        self._stop.clear()
        self.start(drop_chat=False)

    def stop(self) -> None:
        self._stop.set()
        listener = self._listener
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        thread = self._thread
        if thread is not None:
            thread.join(2)

    def _serve(self, listener: socket.socket, drop_chat: bool) -> None:
        self._ready.set()
        try:
            while not self._stop.is_set():
                try:
                    conn, _addr = listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    return
                try:
                    self._speak(conn, drop_chat)
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass
                if drop_chat and self.dropped.is_set():
                    return
        finally:
            try:
                listener.close()
            except OSError:
                pass

    def _speak(self, conn: socket.socket, drop_chat: bool) -> None:
        conn.settimeout(5)
        try:
            buffer = ByteBuffer(conn)
            raw = buffer.read_until(b"\r\n\r\n", 16384)
            headers = _headers(raw)
            if headers.get("authorization") != f"Bearer {self.token}":
                conn.sendall(b"HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n")
                return
            conn.sendall(server_upgrade_response(headers.get("sec-websocket-key", "")))
            ws = WebSocketConnection(conn, buffer, client=False)
            while not self._stop.is_set():
                text = ws.recv_text()
                if not text:
                    return
                frame = json.loads(text)
                if isinstance(frame, dict) and self._reply(ws, conn, frame, drop_chat):
                    return
        except (OSError, ConnectionError, ValueError, json.JSONDecodeError, RuntimeError):
            return

    def _reply(
        self,
        ws: WebSocketConnection,
        conn: socket.socket,
        frame: dict[str, object],
        drop_chat: bool,
    ) -> bool:
        kind = str(frame.get("type") or "")
        frame_id = str(frame.get("id") or "")
        payload = frame.get("payload")
        body = payload if isinstance(payload, dict) else {}
        if kind == "connect":
            self.clients.append(str(body.get("client") or ""))
            self.tokens.append(str(body.get("token") or ""))
            if body.get("token") != self.token:
                self._send(ws, frame_id, "error", {"message": "refused"})
                return True
            self._send(ws, frame_id, "hello", {})
            return False
        if kind == "approvals.list":
            self._send(ws, frame_id, "result", {"approvals": []})
            return False
        if kind == "chat.send":
            if drop_chat:
                self.dropped.set()
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                return True
            self._send(ws, frame_id, "result", {"sessionId": "s1", "text": "pong"})
            return False
        self._send(ws, frame_id, "result", {})
        return False

    def _send(
        self,
        ws: WebSocketConnection,
        frame_id: str,
        kind: str,
        payload: dict[str, object],
    ) -> None:
        ws.send_text(
            json.dumps(
                {
                    "type": kind,
                    "id": frame_id,
                    "ok": kind != "error",
                    "payload": payload,
                }
            )
        )
