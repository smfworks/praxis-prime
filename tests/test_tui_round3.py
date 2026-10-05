"""Round-3 terminal fixes: hidden approval text and the confirm dialog."""

from __future__ import annotations

import asyncio

from tests.test_tui_app import _app, _confirm, _until
from tests.test_tui_gateway import FakeFrames
from tests.test_tui_review import CARD
from textual.widgets import Static

from praxis_prime.tui.app import ConfirmDecision
from praxis_prime.tui.cards import approval_digest, render_card


def test_hidden_tail_change_does_not_satisfy_the_read_gate() -> None:
    prefix = "A" * 300
    first = dict(CARD)
    first["summary"] = prefix + " rm -rf /safe-cmd"
    second = dict(CARD)
    second["summary"] = prefix + " rm -rf /evil-cmd"
    assert render_card(first) == render_card(second)
    assert "rm -rf /evil-cmd" not in render_card(first)
    assert approval_digest(first) != approval_digest(second)
    frames = FakeFrames()
    frames.approvals = [first]
    app, _gateway = _app(frames)

    async def run() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            await _until(pilot, lambda: app.approval_ids() == ["ap1"])
            await pilot.press("f3")
            await pilot.pause()
            await _page_full(pilot, app, "rm -rf /safe-cmd")
            assert app._full_read_key == ("ap1", approval_digest(first))
            await _replace(pilot, app, frames, second)
            await pilot.pause()
            assert app._full_read_key is None
            assert "rm -rf /evil-cmd" not in str(app.query_one("#card", Static).content)
            await pilot.press("f3")
            await pilot.press("a")
            await pilot.pause(0.85)
            await pilot.press("tab")
            await pilot.press("enter")
            await pilot.pause(0.2)
            assert frames.decisions == []
            assert len(app.screen_stack) == 1
            shown = " ".join(app.timeline_text().split())
            assert "Press v and page through the full text before deciding." in shown
            await pilot.press("f3")
            await _page_full(pilot, app, "rm -rf /evil-cmd")
            await _confirm(pilot, "a")
            await _until(pilot, lambda: len(frames.decisions) == 1)

    asyncio.run(run())
    assert frames.decisions == [("ap1", "allow_once", "default")]


def test_confirm_closes_when_the_approval_changes_behind_it() -> None:
    prefix = "B" * 300
    first = dict(CARD)
    first["summary"] = prefix + " keep-it"
    second = dict(CARD)
    second["summary"] = prefix + " destroy"
    assert render_card(first) == render_card(second)
    frames = FakeFrames()
    frames.approvals = [first]
    app, _gateway = _app(frames)

    async def run() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
            await _until(pilot, lambda: app.approval_ids() == ["ap1"])
            await pilot.press("f3")
            await pilot.pause()
            await _page_full(pilot, app, " keep")
            await pilot.press("a")
            await pilot.pause()
            assert len(app.screen_stack) > 1
            await _replace(pilot, app, frames, second)
            await pilot.pause()
            assert len(app.screen_stack) == 1
            assert frames.decisions == []
            shown = " ".join(app.timeline_text().split())
            assert "The approval changed. Read it again before deciding." in shown
            await pilot.press("a")
            await pilot.pause(0.2)
            assert frames.decisions == []
            assert len(app.screen_stack) == 1

    asyncio.run(run())


def test_cancel_closes_immediately_and_confirm_waits() -> None:
    frames = FakeFrames()
    frames.approvals = [dict(CARD)]
    app, _gateway = _app(frames)

    async def run() -> None:
        async with app.run_test(size=(100, 30)) as pilot:
            await _until(pilot, lambda: app.approval_ids() == ["ap1"])
            await pilot.press("f3")
            await pilot.pause()
            await pilot.press("a")
            await pilot.pause()
            assert app.focused is not None and app.focused.id == "cancel"
            await pilot.press("enter")
            await pilot.pause(0.1)
            assert frames.decisions == []
            assert len(app.screen_stack) == 1
            await pilot.press("a")
            await pilot.pause()
            await pilot.press("tab")
            assert app.focused is not None and app.focused.id == "confirm"
            await pilot.press("enter")
            await pilot.pause(0.1)
            assert frames.decisions == []
            assert len(app.screen_stack) > 1
            await pilot.pause(0.85)
            await pilot.press("enter")
            await _until(pilot, lambda: len(frames.decisions) == 1)

    asyncio.run(run())
    assert frames.decisions == [("ap1", "allow_once", "default")]


def test_confirm_tab_order_skips_the_body() -> None:
    app, _gateway = _app(FakeFrames())

    async def run() -> None:
        async with app.run_test(size=(80, 24)) as pilot:
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
            assert body.can_focus is False
            ids = [widget.id for widget in app.screen.focus_chain]
            assert "confirm-body" not in ids
            assert "confirm-text" not in ids
            seen: list[str | None] = []
            for _ in range(4):
                seen.append(None if app.focused is None else app.focused.id)
                await pilot.press("tab")
            assert seen == ["cancel", "confirm", "cancel", "confirm"]
            body.styles.height = 4
            body.styles.min_height = 4
            body.styles.max_height = 4
            await pilot.pause()
            assert body.max_scroll_y > 0
            await pilot.press("pagedown")
            await pilot.pause()
            assert body.scroll_y > 0
            assert app.focused is not None and app.focused.id == "cancel"

    asyncio.run(run())


async def _replace(pilot: object, app: object, frames: FakeFrames, item: dict[str, object]) -> None:
    """Stop the approval poll, then install one card. A late poll must not restore the old text."""
    for timer in list(getattr(app, "_timers", ())):
        timer.stop()
    await pilot.pause(0.3)  # type: ignore[attr-defined]
    frames.approvals = [item]
    app._set_approvals([dict(item)])  # type: ignore[attr-defined]


async def _page_full(pilot: object, app: object, needle: str) -> None:
    await pilot.press("v")  # type: ignore[attr-defined]
    await pilot.pause()  # type: ignore[attr-defined]
    text = str(app.screen.query_one("#full-text", Static).content)  # type: ignore[attr-defined]
    assert needle in text
    full = app.screen.query_one("#full-scroll")  # type: ignore[attr-defined]
    full.styles.height = 4
    full.styles.min_height = 4
    full.styles.max_height = 4
    await pilot.pause()  # type: ignore[attr-defined]
    assert full.max_scroll_y > 1
    assert not full.gate_met()
    await pilot.press("end")  # type: ignore[attr-defined]
    await pilot.pause()  # type: ignore[attr-defined]
    assert not full.gate_met()
    await pilot.press("home")  # type: ignore[attr-defined]
    await pilot.pause()  # type: ignore[attr-defined]
    for _ in range(40):
        if full.gate_met():
            break
        await pilot.press("pagedown")  # type: ignore[attr-defined]
        await pilot.pause()  # type: ignore[attr-defined]
    assert full.gate_met()
    await pilot.press("escape")  # type: ignore[attr-defined]
    await pilot.pause()  # type: ignore[attr-defined]
