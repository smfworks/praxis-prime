"""Review fixes for the terminal: injection, the card that is decided, and colour."""

from __future__ import annotations

import asyncio
import json
import queue
import threading
import time

import pytest
from tests.test_tui_app import _app, _submit, _until
from tests.test_tui_gateway import FakeFrames, FakeHttp
from textual.widgets import Input, Static

from praxis_prime.approvals.card import format_approval_card
from praxis_prime.gateway.client import GatewayClient, GatewayError
from praxis_prime.themes.color import contrast_ratio
from praxis_prime.tui.app import HELP, HelpScreen, PraxisApp
from praxis_prime.tui.cards import render_card, scope_label
from praxis_prime.tui.gateway import TuiGateway
from praxis_prime.tui.palette import fallback_palette
from praxis_prime.tui.plain import run_plain
from praxis_prime.tui.sanitize import has_raw_control, sanitize
from praxis_prime.tui.sessions import SessionBook
from praxis_prime.tui.theme_map import theme_for

OSC52 = "\x1b]52;c;eA==\x07"
OSC8 = "\x1b]8;;http://evil.example\x07click\x1b]8;;\x07"
CSI_CLEAR = "\x1b[2J\x1b[H"
C1_CSI = "\x9b2J"
ERASE_LINE = "\x1b[2K\r\x1b[1A"
BIDI = "safe\u202ehidden\u200b\u2066"
EVIL = OSC52 + OSC8 + CSI_CLEAR + C1_CSI + BIDI

CARD = {
    "id": "ap1",
    "tool": "shell",
    "risk": "high",
    "summary": "rm tmp",
    "reason": "write",
    "sandboxed": False,
    "sessionId": "sess-9",
    "requester": "ada",
}


def _assert_visible(text: str) -> None:
    assert "\x1b" not in text
    assert b"\x1b" not in text.encode("utf-8")
    assert not has_raw_control(text)
    assert "\u202e" not in text
    assert "\u200b" not in text
    assert "\u2066" not in text


def test_sanitiser_shows_osc_csi_c1_and_drops_bidi() -> None:
    shown = sanitize(EVIL + ERASE_LINE)
    _assert_visible(shown)
    assert "\\x1b" in shown
    assert "\\x9b" in shown
    assert "\\x0d" in shown
    assert "\\x07" in shown
    assert "safe" in sanitize(BIDI)
    assert "hidden" in sanitize(BIDI)
    again = sanitize(shown)
    assert again == shown


def test_card_flattens_newlines_and_keeps_the_hidden_command() -> None:
    summary = "ls -la" + ("\n" * 12) + "rm -rf ~/scratch"
    item = dict(CARD)
    item["summary"] = summary
    item["reason"] = "because\nit matters"
    text = render_card(item)
    _assert_visible(text)
    action = next(line for line in text.splitlines() if line.startswith("Action:"))
    assert "ls -la" in action
    assert "rm -rf ~/scratch" in action
    assert "⏎" in action
    assert "\n" not in action
    assert text.index("Approval needed:") < text.index("Risk:")
    assert text.index("Risk:") < text.index("Sandbox:")
    assert text.index("Sandbox:") < text.index("Action:")
    assert text.index("Action:") < text.index("Why:")
    assert "HOST:" in text
    assert "Session: sess-9" in text
    assert "Requester: ada" in text
    assert "Always allow in session sess-9" in text
    assert "ctrl+y" in text and "ctrl+u" in text and "ctrl+x" in text
    assert "/approve ap1" in text
    assert "A text reply cannot approve this." in text
    erased = dict(CARD)
    erased["summary"] = "ls -la" + ERASE_LINE + "rm -rf ~/"
    erased_text = render_card(erased)
    _assert_visible(erased_text)
    erased_action = next(line for line in erased_text.splitlines() if line.startswith("Action:"))
    assert "ls -la" in erased_action
    assert "rm -rf ~/" in erased_action
    assert "\\x1b" in erased_action


def test_shared_card_sanitises_dynamic_fields() -> None:
    item = dict(CARD)
    item["summary"] = "ls -la" + ERASE_LINE + "rm -rf ~/"
    item["reason"] = "line\n" + BIDI
    text = format_approval_card(item)
    _assert_visible(text)
    assert "rm -rf ~/" in text
    assert "A chat message cannot approve this." in text
    assert "Use Approve, Deny, or Always this session." in text
    assert "read-only" in format_approval_card({"mount": "read-only", "sandboxed": True})


def test_empty_session_names_the_daemon_process() -> None:
    assert scope_label({"sessionId": ""}) == "Always allow for this daemon process"
    assert "session sess-9" in scope_label(CARD)
    assert "this daemon process" in HELP
    assert "ctrl+y" in HELP
    assert "/approve <id>" in HELP


def test_focused_row_contrast_is_at_least_3_to_1() -> None:
    palette = fallback_palette("dark")
    theme = theme_for(palette)
    generated = theme.to_color_system().generate()
    focus = generated["block-cursor-background"]
    blur = generated["block-cursor-blurred-background"]
    pane = generated["surface"]
    assert contrast_ratio(focus, pane) >= 3.0
    assert focus.lower() != blur.lower()
    assert contrast_ratio(generated["block-cursor-foreground"], focus) >= 3.0
    assert contrast_ratio(generated["block-cursor-blurred-foreground"], blur) >= 3.0


def test_palette_switch_changes_the_rendered_background(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    app, _gateway = _app(FakeFrames())

    async def run() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            await _until(pilot, lambda: app.booted)
            app._apply_palette(fallback_palette("dark"))
            await pilot.pause()
            dark = _background(app)
            dark_name = app.theme
            app._apply_palette(fallback_palette("light"))
            await pilot.pause()
            light = _background(app)
            assert dark is not None and light is not None
            assert dark != light
            assert app.theme != dark_name

    asyncio.run(run())


def test_focused_list_has_a_border_and_a_distinct_row() -> None:
    frames = FakeFrames()
    frames.approvals = [dict(CARD)]
    app, _gateway = _app(frames)

    async def run() -> None:
        async with app.run_test(size=(100, 32)) as pilot:
            await _until(pilot, lambda: app.approval_ids() == ["ap1"])
            approvals = app.query_one("#approvals")
            approvals.focus()
            await pilot.pause()
            assert "solid" in str(approvals.styles.border).lower()
            labels = [
                binding.description
                for _ns, binding, _on, _tip in app.screen.active_bindings.values()
            ]
            assert "Help" in labels
            focus_bg = _option_background(approvals, "ap1")
            pane = approvals.styles.background
            pane_rgb = (pane.r, pane.g, pane.b)
            assert _contrast_rgb(focus_bg, pane_rgb) >= 3.0
            composer = app.query_one("#composer")
            composer.focus()
            await pilot.pause()
            blur_bg = _option_background(approvals, "ap1")
            assert focus_bg != blur_bg

    asyncio.run(run())


def test_highlight_follows_the_card_and_confirm_decides_that_id() -> None:
    frames = FakeFrames()
    first = dict(CARD)
    second = dict(CARD)
    second["id"] = "apB"
    second["summary"] = "rm -rf ~/"
    third = dict(CARD)
    third["id"] = "apC"
    third["summary"] = "other"
    frames.approvals = [first, second, third]
    app, _gateway = _app(frames)

    async def run() -> None:
        async with app.run_test(size=(110, 36)) as pilot:
            await _until(pilot, lambda: app.approval_ids() == ["ap1", "apB", "apC"])
            await pilot.press("f3")
            await pilot.pause()
            assert "rm tmp" in str(app.query_one("#card", Static).content)
            await pilot.press("down")
            await pilot.pause()
            card = str(app.query_one("#card", Static).content)
            assert "apB" in card
            assert "rm -rf ~/" in card
            await pilot.press("a")
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause(0.2)
            assert frames.decisions == []
            await pilot.press("a")
            await pilot.pause()
            await pilot.press("ctrl+y")
            await _until(pilot, lambda: len(frames.decisions) == 1)

    asyncio.run(run())
    assert frames.decisions == [("apB", "allow_once", "default")]


def test_new_approval_does_not_steal_the_highlighted_card() -> None:
    frames = FakeFrames()
    first = dict(CARD)
    second = dict(CARD)
    second["id"] = "apB"
    second["summary"] = "rm -rf ~/"
    frames.approvals = [first]
    started = threading.Event()

    def script(text, session_id, on_event, decider, timeout, profile):
        del text, session_id, timeout, profile
        started.set()
        on_event({"kind": "approval", "approval": second})
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            decider(second)
            if any(item[0] == "ap1" for item in frames.decisions):
                break
            time.sleep(0.02)
        else:
            raise AssertionError("highlighted card was not decided")
        return {"type": "result", "ok": True, "payload": {"sessionId": "s1", "text": "done"}}

    frames.chat_impl = script
    app, _gateway = _app(frames)

    async def run() -> None:
        async with app.run_test(size=(110, 36)) as pilot:
            await _until(pilot, lambda: app.approval_ids() == ["ap1"])
            await _submit(pilot, app, "go")
            assert started.wait(2)
            await _until(pilot, lambda: "apB" in app.approval_ids())
            card = str(app.query_one("#card", Static).content)
            assert "ap1" in card
            assert "rm -rf ~/" not in card
            await pilot.press("f3")
            await pilot.pause()
            await pilot.press("a")
            await pilot.pause()
            await pilot.press("ctrl+y")
            await _until(pilot, lambda: "done" in app.transcript_text())

    asyncio.run(run())
    assert ("ap1", "allow_once", "default") in frames.decisions
    assert not any(item[0] == "apB" for item in frames.decisions)


def test_highlight_stays_on_the_same_id_when_an_earlier_card_leaves() -> None:
    frames = FakeFrames()
    cards = []
    for approval_id, summary in (("apA", "one"), ("apB", "two"), ("apC", "three")):
        item = dict(CARD)
        item["id"] = approval_id
        item["summary"] = summary
        cards.append(item)
    frames.approvals = cards
    app, _gateway = _app(frames)

    async def run() -> None:
        async with app.run_test(size=(110, 36)) as pilot:
            await _until(pilot, lambda: app.approval_ids() == ["apA", "apB", "apC"])
            await pilot.press("f3")
            await pilot.pause()
            await pilot.press("down")
            await pilot.pause()
            assert app._selected_id == "apB"
            app._set_approvals(cards[1:])
            await pilot.pause()
            assert app._selected_id == "apB"
            assert "two" in str(app.query_one("#card", Static).content)
            app._set_approvals(cards[2:])
            await pilot.pause()
            assert app._selected_id is None
            await pilot.press("a")
            await pilot.pause(0.2)
            assert frames.decisions == []

    asyncio.run(run())


def test_held_key_and_typed_prose_do_not_decide() -> None:
    frames = FakeFrames()
    frames.approvals = [dict(CARD), {**CARD, "id": "apB"}, {**CARD, "id": "apC"}]
    app, _gateway = _app(frames)

    async def run() -> None:
        async with app.run_test(size=(110, 36)) as pilot:
            await _until(pilot, lambda: len(app.approval_ids()) == 3)
            await pilot.press("f3")
            await pilot.pause()
            for _ in range(5):
                await pilot.press("a")
            await pilot.pause(0.2)
            assert frames.decisions == []
            await pilot.press("ctrl+y")
            await _until(pilot, lambda: len(frames.decisions) == 1)
            for _ in range(4):
                await pilot.press("a")
                await pilot.press("ctrl+y")
            await pilot.pause(0.3)
            assert len(frames.decisions) == 1
            for key in ("y", "e", "s", "space", "d", "o", "space", "i", "t"):
                await pilot.press(key)
            await pilot.pause(0.3)

    asyncio.run(run())
    assert frames.decisions == [("ap1", "allow_once", "default")]


def test_long_card_blocks_a_decision_until_it_is_scrolled() -> None:
    frames = FakeFrames()
    item = dict(CARD)
    item["summary"] = ("ls -la " * 40) + "rm -rf ~/scratch"
    frames.approvals = [item]
    app, _gateway = _app(frames)

    async def run() -> None:
        async with app.run_test(size=(90, 28)) as pilot:
            await _until(pilot, lambda: app.approval_ids() == ["ap1"])
            card = str(app.query_one("#card", Static).content)
            assert "rm -rf ~/scratch" in card
            assert "⏎" not in card or "rm -rf ~/scratch" in card
            scroller = app.query_one("#card-scroll")
            await pilot.press("f3")
            await pilot.pause()
            if scroller.max_scroll_y <= 0:
                scroller.styles.max_height = 4
                await pilot.pause()
            assert scroller.max_scroll_y > 0
            await pilot.press("a")
            await pilot.pause(0.2)
            assert frames.decisions == []
            assert "Scroll the approval card" in app.timeline_text()
            scroller.scroll_end(animate=False)
            await pilot.pause()
            await pilot.press("a")
            await pilot.pause()
            await pilot.press("ctrl+y")
            await _until(pilot, lambda: len(frames.decisions) == 1)

    asyncio.run(run())
    assert frames.decisions == [("ap1", "allow_once", "default")]


def test_server_text_is_sanitised_in_both_modes() -> None:
    frames = FakeFrames()

    def script(text, session_id, on_event, decider, timeout, profile):
        del text, session_id, decider, timeout, profile
        on_event({"kind": "text", "text": EVIL})
        on_event({"kind": "tool", "phase": "start", "name": EVIL, "detail": ERASE_LINE})
        return {"type": "result", "ok": True, "payload": {"sessionId": "s1", "text": EVIL}}

    frames.chat_impl = script
    app, gateway = _app(frames)

    async def run() -> None:
        async with app.run_test(size=(100, 30)) as pilot:
            await _until(pilot, lambda: app.booted)
            await _submit(pilot, app, "hi")
            await _until(pilot, lambda: "\\x1b" in app.transcript_text())

    asyncio.run(run())
    _assert_visible(app.transcript_text())
    _assert_visible(app.timeline_text())
    assert "\\x1b" in app.transcript_text()
    assert "\\x9b" in app.transcript_text()

    plain_frames = FakeFrames()
    plain_frames.chat_impl = script
    plain = TuiGateway(plain_frames, FakeHttp(), profile="default")
    out: list[str] = []
    lines = iter(["hello", "/quit"])

    def read_line() -> str:
        try:
            return next(lines)
        except StopIteration as exc:
            raise EOFError from exc

    code = run_plain(
        gateway=plain,
        sessions=SessionBook(),
        read_line=read_line,
        write=out.append,
        port=18790,
    )
    text = "".join(out)
    assert code == 0
    _assert_visible(text)
    assert "prime: " in text
    assert text.count("prime:") == 1
    assert "\\x1b" in text
    del gateway


def test_plain_quit_does_not_read_another_line() -> None:
    calls = {"n": 0}

    def read_line() -> str:
        calls["n"] += 1
        if calls["n"] > 1:
            raise AssertionError("quit waited for another line")
        return "/quit"

    code = run_plain(
        gateway=TuiGateway(FakeFrames(), FakeHttp(), profile="default"),
        sessions=SessionBook(),
        read_line=read_line,
        write=lambda _text: None,
        port=18790,
    )
    assert code == 0
    assert calls["n"] == 1


def test_new_during_a_busy_draft_keeps_the_line() -> None:
    frames = FakeFrames()
    started = threading.Event()
    release = threading.Event()

    def script(text, session_id, on_event, decider, timeout, profile):
        del text, session_id, on_event, decider, timeout, profile
        started.set()
        assert release.wait(4)
        return {"type": "result", "ok": True, "payload": {"sessionId": "s9", "text": "later"}}

    frames.chat_impl = script
    app, _gateway = _app(frames)

    async def run() -> None:
        async with app.run_test(size=(100, 30)) as pilot:
            await _until(pilot, lambda: app.booted)
            await _submit(pilot, app, "keep this line")
            assert started.wait(2)
            await pilot.press("ctrl+n")
            await pilot.pause()
            release.set()
            await _until(pilot, lambda: not app._busy)

    asyncio.run(run())
    blob = "\n".join(app.sessions.text(key) for key in app.sessions.transcripts)
    assert "you: keep this line" in blob


def test_pre_tool_assistant_text_is_kept() -> None:
    frames = FakeFrames()

    def script(text, session_id, on_event, decider, timeout, profile):
        del text, session_id, decider, timeout, profile
        on_event({"kind": "text", "text": "before the tool"})
        on_event({"kind": "tool", "phase": "start", "name": "shell", "detail": "ls"})
        return {
            "type": "result",
            "ok": True,
            "payload": {"sessionId": "s1", "text": "after the tool"},
        }

    frames.chat_impl = script
    app, _gateway = _app(frames)

    async def run() -> None:
        async with app.run_test(size=(100, 30)) as pilot:
            await _until(pilot, lambda: app.booted)
            await _submit(pilot, app, "go")
            await _until(pilot, lambda: "after the tool" in app.transcript_text())

    asyncio.run(run())
    text = app.transcript_text()
    assert "prime: before the tool" in text
    assert "prime: after the tool" in text


def test_help_opens_from_the_composer() -> None:
    app, _gateway = _app(FakeFrames())

    async def run() -> None:
        async with app.run_test(size=(100, 30)) as pilot:
            await _until(pilot, lambda: app.booted)
            app.query_one("#composer", Input).focus()
            await pilot.pause()
            await pilot.press("ctrl+question_mark")
            await pilot.pause()
            assert isinstance(app.screen, HelpScreen)

    asyncio.run(run())


def test_dead_socket_clears_busy_and_reconnects() -> None:
    frames = FakeFrames()

    def script(text, session_id, on_event, decider, timeout, profile):
        del text, session_id, on_event, decider, timeout, profile
        raise OSError("dead")

    frames.chat_impl = script
    app, gateway = _app(frames)
    replaced = FakeFrames()

    def connector():
        return replaced, FakeHttp()

    gateway._connector = connector
    gateway._next_try = 0

    async def run() -> None:
        async with app.run_test(size=(100, 30)) as pilot:
            await _until(pilot, lambda: app.booted)
            await _submit(pilot, app, "hi")
            await _until(pilot, lambda: not app._busy and "disconnected" in app.timeline_text())
            await _until(pilot, lambda: gateway.connected and gateway.frames is replaced)

    asyncio.run(run())
    assert app._busy is False


def test_a_blank_line_separates_turns() -> None:
    book = SessionBook()
    book.append("s", "you: one")
    book.append("s", "prime: a")
    book.append("s", "you: two")
    assert book.text("s").split("\n") == ["you: one", "prime: a", "", "you: two"]


def test_session_title_stays_on_one_line() -> None:
    book = SessionBook()
    book.note_user("title\nwith a second line " + ("x" * 80))
    book.pin_draft()
    _session_id, title = book.rows()[0]
    assert "\n" not in title
    assert len(title) <= 60


def test_chat_reports_a_rejected_decision_and_a_dead_send() -> None:
    socket = _ScriptedSocket()
    client = GatewayClient(socket)
    events: list[dict[str, object]] = []
    try:
        result = client.chat(
            "hi",
            on_event=events.append,
            decider=lambda _pending: "deny",
            timeout=3,
        )
    finally:
        client.close()
    assert result["payload"]["text"] == "done"
    assert any(
        item.get("phase") == "error" and "nope" in str(item.get("detail")) for item in events
    )

    dead = _DeadSocket()
    client = GatewayClient(dead)
    try:
        with pytest.raises(GatewayError, match="disconnected"):
            client.chat("hi", timeout=2)
    finally:
        client.close()


def test_timeline_caps_and_indents_wrapped_lines() -> None:
    app, _gateway = _app(FakeFrames())

    async def run() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            await _until(pilot, lambda: app.booted)
            for index in range(520):
                app._timeline_add(f"event {index} " + ("word " * 20))
            assert len(app._timeline) == 500
            assert "event 0 " not in app.timeline_text()
            assert "\n  " in app.timeline_text()

    asyncio.run(run())


class _ScriptedSocket:
    def __init__(self) -> None:
        self.inbound: queue.Queue[str | None] = queue.Queue()
        self._chat_id = ""

    def send_text(self, text: str) -> None:
        frame = json.loads(text)
        if frame["type"] == "chat.send":
            self._chat_id = frame["id"]
            self.inbound.put(
                json.dumps(
                    {
                        "type": "event",
                        "id": frame["id"],
                        "payload": {"kind": "approval", "approval": {"id": "ap"}},
                    }
                )
            )
            return
        if frame["type"] == "approvals.decide":
            self.inbound.put(
                json.dumps(
                    {
                        "type": "error",
                        "id": frame["id"],
                        "ok": False,
                        "payload": {"message": "nope"},
                    }
                )
            )
            self.inbound.put(
                json.dumps(
                    {
                        "type": "result",
                        "id": self._chat_id,
                        "ok": True,
                        "payload": {"text": "done", "sessionId": "s"},
                    }
                )
            )

    def recv_text(self) -> str | None:
        item = self.inbound.get(timeout=3)
        return item

    def close(self) -> None:
        self.inbound.put(None)


class _DeadSocket:
    def __init__(self) -> None:
        self.inbound: queue.Queue[str | None] = queue.Queue()

    def send_text(self, text: str) -> None:
        del text
        raise OSError("broken pipe")

    def recv_text(self) -> str | None:
        return self.inbound.get(timeout=2)

    def close(self) -> None:
        self.inbound.put(None)


def _contrast_rgb(color: tuple[int, int, int], other: tuple[int, int, int]) -> float:
    left = "#{:02x}{:02x}{:02x}".format(*color)
    right = "#{:02x}{:02x}{:02x}".format(*other)
    return contrast_ratio(left, right)


def _option_background(widget: object, needle: str) -> tuple[int, int, int]:
    for y in range(widget.size.height):  # type: ignore[attr-defined]
        line = widget.render_line(y)  # type: ignore[attr-defined]
        if needle not in line.text:
            continue
        for segment in line:
            bgcolor = segment.style.bgcolor if segment.style is not None else None
            trip = None if bgcolor is None else bgcolor.triplet
            if needle in segment.text and trip is not None:
                return (trip.red, trip.green, trip.blue)
    raise AssertionError(f"{needle} was not painted")


def _background(app: PraxisApp) -> tuple[int, int, int] | None:
    strip = app.screen.render_line(0)
    for _text, style, _control in strip:
        if style is None or style.bgcolor is None or style.bgcolor.is_default:
            continue
        trip = style.bgcolor.triplet
        if trip is not None:
            return (trip.red, trip.green, trip.blue)
    return None
