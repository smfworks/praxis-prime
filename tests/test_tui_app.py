"""Textual pilot tests and the plain-text transcript. The gateway is fake."""

from __future__ import annotations

import asyncio
import time

import pytest
from tests.test_tui_gateway import FakeFrames, FakeHttp
from textual.color import Color
from textual.widgets import Input, Static

from praxis_prime.cli import main
from praxis_prime.gateway.client import Endpoint, GatewayClient, GatewayError
from praxis_prime.tui import run_tui
from praxis_prime.tui.app import PraxisApp
from praxis_prime.tui.gateway import TuiGateway
from praxis_prime.tui.plain import run_plain
from praxis_prime.tui.sessions import SessionBook

CARD = {
    "id": "ap1",
    "tool": "shell",
    "risk": "high",
    "summary": "rm tmp",
    "reason": "write",
    "sandboxed": False,
}


def _app(
    frames: FakeFrames,
    *,
    status: dict[str, object] | None = None,
    session: str = "",
    profile: str = "default",
) -> tuple[PraxisApp, TuiGateway]:
    http = FakeHttp(status=status)
    gateway = TuiGateway(frames, http, profile=profile, port=18790)
    return PraxisApp(gateway, profile=profile, session=session), gateway


async def _until(pilot: object, pred) -> None:
    for _ in range(80):
        if pred():
            return
        await pilot.pause(0.05)  # type: ignore[attr-defined]
    raise AssertionError("timed out waiting for the TUI")


async def _confirm(pilot: object, key: str) -> None:
    """Open the dialog, wait out the arming delay, then Tab to Confirm and Enter."""
    await pilot.press(key)  # type: ignore[attr-defined]
    await pilot.pause(0.85)  # type: ignore[attr-defined]
    await pilot.press("tab")  # type: ignore[attr-defined]
    await pilot.press("enter")  # type: ignore[attr-defined]


async def _submit(pilot: object, app: PraxisApp, text: str) -> None:
    composer = app.query_one("#composer", Input)
    composer.focus()
    await pilot.pause()  # type: ignore[attr-defined]
    composer.value = text
    await pilot.press("enter")  # type: ignore[attr-defined]


def test_chat_send_renders_the_stream() -> None:
    frames = FakeFrames()

    def script(text, session_id, on_event, decider, timeout, profile):
        del text, session_id, decider, timeout, profile
        on_event({"kind": "text", "text": "Hello "})
        on_event({"kind": "text", "text": "there"})
        on_event({"kind": "tool", "phase": "start", "name": "files", "detail": "list"})
        return {
            "type": "result",
            "ok": True,
            "payload": {"sessionId": "s1", "text": "Hello there"},
        }

    frames.chat_impl = script
    app, _gateway = _app(frames)

    async def run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await _until(pilot, lambda: app.booted)
            await _submit(pilot, app, "hi")
            await _until(pilot, lambda: "Hello there" in app.transcript_text())
            assert "Hello there" in app.transcript_text()
            assert "files" in app.timeline_text()

            def painted() -> bool:
                body = app.query_one("#transcript-body")
                kinds = [set(child.classes) for child in body.children]
                has_you = any("you" in item for item in kinds)
                has_prime = any("prime" in item for item in kinds)
                return has_you and has_prime

            await _until(pilot, painted)

    asyncio.run(run())
    assert "you: hi" in app.transcript_text()
    assert "prime: Hello there" in app.transcript_text()
    assert "files" in app.timeline_text()
    assert frames.chats[0]["text"] == "hi"
    assert frames.chats[0]["profile"] == "default"
    assert frames.decisions == []


def test_approval_approve_reaches_the_gateway() -> None:
    _decision_pilot("a", "allow_once")


def test_approval_deny_reaches_the_gateway() -> None:
    _decision_pilot("d", "deny")


def _decision_pilot(key: str, decision: str) -> None:
    frames = FakeFrames()
    card = dict(CARD)

    def script(text, session_id, on_event, decider, timeout, profile):
        del text, session_id, timeout
        on_event({"kind": "text", "text": "working"})
        on_event({"kind": "approval", "approval": card})
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            answer = decider(card)
            if answer:
                frames.decide("ap1", answer, profile or "")
                break
            time.sleep(0.02)
        else:
            raise AssertionError("the pane did not decide")
        on_event({"kind": "text", "text": " done"})
        return {
            "type": "result",
            "ok": True,
            "payload": {"sessionId": "s1", "text": "working done"},
        }

    frames.chat_impl = script
    app, _gateway = _app(frames)

    async def run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await _until(pilot, lambda: app.booted)
            await _submit(pilot, app, "go")
            await _until(pilot, lambda: "ap1" in app.approval_ids())
            await pilot.press("f3")
            await _until(pilot, lambda: app.focused is not None and app.focused.id == "approvals")
            await _confirm(pilot, key)
            await _until(pilot, lambda: "working done" in app.transcript_text())

    asyncio.run(run())
    assert frames.decisions == [("ap1", decision, "default")]


def test_enter_on_an_approval_does_not_decide() -> None:
    frames = FakeFrames()
    frames.approvals = [dict(CARD)]
    app, _gateway = _app(frames)

    async def run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await _until(pilot, lambda: app.approval_ids() == ["ap1"])
            await pilot.press("f3")
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause(0.2)
            card = str(app.query_one("#card", Static).content)
            assert "Approval needed" in card
            assert "rm tmp" in card

    asyncio.run(run())
    assert frames.decisions == []


def test_session_switch_selects_the_next_turn() -> None:
    frames = FakeFrames()

    def script(text, session_id, on_event, decider, timeout, profile):
        del decider, timeout, profile
        sid = session_id or f"s{len(frames.chats)}"
        on_event({"kind": "text", "text": f"reply {text}"})
        return {
            "type": "result",
            "ok": True,
            "payload": {"sessionId": sid, "text": f"reply {text}"},
        }

    frames.chat_impl = script
    app, _gateway = _app(frames)

    async def run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await _until(pilot, lambda: app.booted)
            await _submit(pilot, app, "one")
            await _until(pilot, lambda: "reply one" in app.transcript_text())
            await pilot.press("f4")
            await pilot.pause()
            await pilot.press("n")
            await pilot.pause()
            await _submit(pilot, app, "two")
            await _until(pilot, lambda: "reply two" in app.transcript_text())
            await pilot.press("f4")
            await pilot.pause()
            await pilot.press("up")
            await pilot.press("enter")
            await pilot.pause()
            assert "you: two" not in app.transcript_text()
            assert "you: one" in app.transcript_text()
            await _submit(pilot, app, "three")
            await _until(pilot, lambda: len(frames.chats) == 3)

    asyncio.run(run())
    assert [item["session_id"] for item in frames.chats] == [None, None, "s1"]
    assert "you: three" in app.transcript_text()
    assert "you: two" not in app.transcript_text()


def test_unconfigured_daemon_blocks_chat_and_names_setup() -> None:
    frames = FakeFrames()
    app, _gateway = _app(
        frames,
        status={
            "inferenceReady": False,
            "missing": [{"id": "no provider chosen"}],
            "provider": "",
        },
    )

    async def run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await _until(pilot, lambda: app.booted)
            banner = str(app.query_one("#banner", Static).content)
            assert "No model provider is configured" in banner
            assert "praxis-prime setup" in banner
            await _submit(pilot, app, "hi")
            await pilot.pause(0.2)

    asyncio.run(run())
    assert frames.chats == []


def _rgb(color: object) -> tuple[int, int, int] | None:
    if color is None or getattr(color, "is_default", False):
        return None
    trip = getattr(color, "triplet", None)
    if trip is None:
        return None
    return (trip.red, trip.green, trip.blue)


def _filtered_pairs(
    app: PraxisApp,
) -> list[tuple[tuple[int, int, int] | None, tuple[int, int, int] | None]]:
    # The screen compositor stays blank in headless tests. The status line is
    # what the driver would filter on the way to the terminal.
    strip = app.query_one("#status").render_line(0)
    segments = [(text, style, control) for text, style, control in strip]
    background = app.screen.styles.background
    if not isinstance(background, Color):
        background = Color.parse("#000000")
    for filt in app.get_line_filters():
        segments = filt.apply(list(segments), background)
    pairs = []
    for text, style, _control in segments:
        if not text or not str(text).strip():
            continue
        fg = None if style is None else style.color
        bg = None if style is None else style.bgcolor
        pairs.append((_rgb(fg), _rgb(bg)))
    return pairs


def test_no_color_does_not_paint_black_on_black(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("COLORFGBG", raising=False)
    app, _gateway = _app(FakeFrames())

    async def run() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            await _until(pilot, lambda: app.booted)
            pairs = _filtered_pairs(app)
            explicit = [(fg, bg) for fg, bg in pairs if fg is not None and bg is not None]
            assert explicit
            for fg, bg in explicit:
                assert fg != bg

    asyncio.run(run())


def test_plain_transcript_approves_and_denies() -> None:
    frames = FakeFrames()
    second = dict(CARD)
    second["id"] = "ap2"
    frames.approvals = [dict(CARD), second]

    def script(text, session_id, on_event, decider, timeout, profile):
        del text, session_id, timeout
        on_event({"kind": "text", "text": "streamed"})
        on_event({"kind": "approval", "approval": dict(CARD)})
        on_event({"kind": "tool", "phase": "start", "name": "files", "detail": "list"})
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            answer = decider(dict(CARD))
            if answer:
                frames.decide("ap1", answer, profile or "")
                break
            time.sleep(0.01)
        else:
            raise AssertionError("plain mode did not approve")
        on_event({"kind": "text", "text": " tail"})
        return {
            "type": "result",
            "ok": True,
            "payload": {"sessionId": "s1", "text": "streamed tail"},
        }

    frames.chat_impl = script
    gateway = TuiGateway(frames, FakeHttp(), profile="default", port=18790)
    lines = iter(["hello", "/approve ap1", "/deny ap2", "/sessions", "/timeline", "/quit"])

    def read_line() -> str:
        try:
            return next(lines)
        except StopIteration as exc:
            raise EOFError from exc

    out: list[str] = []
    code = run_plain(
        gateway=gateway,
        sessions=SessionBook(),
        read_line=read_line,
        write=out.append,
        port=18790,
    )
    text = "".join(out)
    assert code == 0
    assert "you: hello" in text
    user_at = text.index("you: hello")
    assert text.index("prime: streamed") < text.index("Approval needed", user_at)
    assert "prime:  tail" in text
    assert text.count("prime:") == 2
    assert "Approval needed" in text
    assert "rm tmp" in text
    assert "decision allow_once ap1" in text
    assert "decision deny ap2" in text
    assert "s1" in text
    assert "timeline: tool files" in text or "files" in text
    assert "┌" not in text
    assert "│" not in text
    assert "\x1b[" not in text
    assert ("ap1", "allow_once", "default") in frames.decisions
    assert ("ap2", "deny", "default") in frames.decisions
    kinds = [item[1] for item in frames.decisions]
    assert kinds.count("allow_once") == 1
    assert kinds.count("deny") == 1


def test_tui_help_lists_plain(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["tui", "--help"])
    assert caught.value.code == 0
    assert "--plain" in capsys.readouterr().out


def test_tui_exits_when_the_daemon_is_not_running(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("praxis_prime.gateway.discover.discover", lambda: None)
    assert main(["tui"]) == 1
    err = capsys.readouterr().err
    assert "praxis-primed is not running." in err
    assert "praxis-prime daemon start" in err
    assert "praxis-prime setup" in err
    assert "http://127.0.0.1:18790/" in err


def test_tui_connect_failure_is_not_a_setup_message(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    endpoint = Endpoint("127.0.0.1", 9, "token-value")
    monkeypatch.setattr("praxis_prime.gateway.discover.discover", lambda: endpoint)

    def connect(ep: Endpoint, **kwargs: object) -> GatewayClient:
        del ep
        assert kwargs.get("client") == "tui"
        raise GatewayError("stopped")

    monkeypatch.setattr(GatewayClient, "connect", staticmethod(connect))
    assert main(["tui", "--plain"]) == 1
    err = capsys.readouterr().err
    assert "stopped" in err
    assert "not running" not in err


def test_fullscreen_without_textual_prints_the_install_hint(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from praxis_prime.tui import _INSTALL_HINT

    _frames, http = FakeFrames(), FakeHttp()
    gateway = TuiGateway(_frames, http, profile="default", port=18790)

    def connect(endpoint: Endpoint, **kwargs: object) -> TuiGateway:
        del endpoint, kwargs
        return gateway

    def missing() -> type[PraxisApp]:
        raise ImportError("textual")

    monkeypatch.setattr(TuiGateway, "connect", staticmethod(connect))
    monkeypatch.setattr("praxis_prime.tui._load_app", missing)
    code = run_tui(discover=lambda: Endpoint("127.0.0.1", 18790, "token-value"))
    assert code == 1
    assert capsys.readouterr().err == _INSTALL_HINT


def test_plain_does_not_load_the_fullscreen_app(monkeypatch: pytest.MonkeyPatch) -> None:
    frames, http = FakeFrames(), FakeHttp()
    gateway = TuiGateway(frames, http, profile="default", port=18790)
    loaded = False

    def connect(endpoint: Endpoint, **kwargs: object) -> TuiGateway:
        del endpoint, kwargs
        return gateway

    def missing() -> type[PraxisApp]:
        nonlocal loaded
        loaded = True
        raise ImportError("textual")

    monkeypatch.setattr(TuiGateway, "connect", staticmethod(connect))
    monkeypatch.setattr("praxis_prime.tui._load_app", missing)
    lines = iter(["/quit"])
    code = run_tui(
        plain=True,
        discover=lambda: Endpoint("127.0.0.1", 18790, "token-value"),
        read_line=lambda: next(lines),
        write=lambda _text: None,
    )
    assert code == 0
    assert loaded is False
