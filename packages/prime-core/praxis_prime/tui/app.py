"""Full-screen Praxis Prime terminal. A gateway client, keyboard first."""

from __future__ import annotations

import time

from textual import events, on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Input, OptionList, Static
from textual.widgets._option_list import Option

from praxis_prime.gateway.client import GatewayError
from praxis_prime.sanitize import sanitize
from praxis_prime.tui.cards import ACTION_LIMIT, card_truncated, clip, render_card, scope_label
from praxis_prime.tui.gateway import Readiness, TuiGateway
from praxis_prime.tui.palette import Palette, fallback_palette, palette_from_http, resolve_mode
from praxis_prime.tui.sessions import SessionBook
from praxis_prime.tui.theme_map import theme_for

_TIMELINE_CAP = 500
_DECIDE_GAP = 0.12
_ARM_DELAY = 0.75
_STREAM_INTERVAL = 1 / 30

HELP = "\n".join(
    (
        "Praxis Prime",
        "",
        "F1 help    F2 timeline    F3 approvals    F4 sessions",
        "Ctrl+F focuses the composer. Enter there sends.",
        "Nothing is approved for you.",
        "Approvals, when that pane is focused:",
        "  a  approve once     s  always allow     d  deny",
        "  Each opens a dialog on Cancel. Tab to Confirm, then Enter.",
        "  Those keys do nothing in the middle of typing.",
        "  Enter on a row shows the card and does not decide.",
        "  v  shows the full text. Page to the end when the card was cut.",
        "  End and Home do not count as reading the card.",
        "  Always allow uses the approval's session, or this daemon process",
        "  when that session is empty.",
        "Sessions: Enter switches, n starts a new one, ctrl+n from anywhere.",
        "? help on a list    F1 help from anywhere    ctrl+q quit",
        "Plain commands: /approve <id>  /session-approve <id>  /deny <id>",
        "",
        "This visit's sessions stay on this screen. The daemon has no session list.",
    )
)


class HelpScreen(ModalScreen[None]):
    """Key chart. Escape closes it."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("question_mark", "dismiss", "Close"),
    ]
    DEFAULT_CSS = """
    HelpScreen {
        align: center middle;
    }
    HelpScreen > Static {
        width: 72;
        height: auto;
        padding: 1 2;
        background: $surface;
        color: $text;
        border: solid $border;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(HELP, markup=False)


class ConfirmDecision(ModalScreen[bool]):
    """Name the approval. Cancel is focused. Confirm is a button."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("a", "noop", show=False),
        Binding("s", "noop", show=False),
        Binding("d", "noop", show=False),
    ]
    DEFAULT_CSS = """
    ConfirmDecision {
        layout: vertical;
        overflow: hidden;
        height: 100%;
        max-height: 100%;
    }
    #confirm-box {
        width: 100%;
        max-width: 100%;
        height: 100%;
        max-height: 100%;
        background: $surface;
        color: $text;
        border: solid $accent;
    }
    #confirm-body {
        height: 1fr;
        padding: 0 1;
    }
    #confirm-text {
        width: 100%;
        height: auto;
    }
    #confirm-actions {
        dock: bottom;
        height: 3;
        align: right middle;
        padding: 0 1;
        background: $surface;
    }
    """

    def __init__(
        self,
        approval_id: str,
        tool: str,
        action: str,
        decision: str,
        scope: str,
    ) -> None:
        super().__init__()
        self.approval_id = approval_id
        self.tool = tool
        self.action = action
        self.decision = decision
        self.scope = scope
        self._opened_at = 0.0

    def compose(self) -> ComposeResult:
        verb = {
            "allow_once": "Approve once",
            "allow_session": "Always allow",
            "deny": "Deny",
        }.get(self.decision, "Decide")
        lines = [
            verb,
            f"Id: {self.approval_id}",
            f"Tool: {self.tool}",
            f"Action: {clip(self.action, ACTION_LIMIT)}",
        ]
        if self.decision == "allow_session":
            lines.append(self.scope)
        lines.append("Cancel is selected. Tab to Confirm, then press Enter.")
        with Vertical(id="confirm-box"):
            with VerticalScroll(id="confirm-body"):
                yield Static("\n".join(lines), id="confirm-text", markup=False)
            with Horizontal(id="confirm-actions"):
                yield Button("Cancel", id="cancel", variant="primary")
                yield Button("Confirm", id="confirm", variant="success")

    def on_mount(self) -> None:
        self._opened_at = time.monotonic()
        self.query_one("#cancel", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if time.monotonic() - self._opened_at < _ARM_DELAY:
            return
        self.dismiss(event.button.id == "confirm")

    def action_cancel(self) -> None:
        self.dismiss(False)

    def action_noop(self) -> None:
        return


class SessionSwitch(Message):
    """Enter on a session row."""

    def __init__(self, option_id: str) -> None:
        super().__init__()
        self.option_id = option_id


class SessionNew(Message):
    """n on the session list, or ctrl+n."""


class ApprovalShown(Message):
    """Enter on a card. Not a decision."""

    def __init__(self, approval_id: str) -> None:
        super().__init__()
        self.approval_id = approval_id


class ApprovalDecide(Message):
    """a, s, or d on the focused approval. Opens a confirm dialog."""

    def __init__(self, approval_id: str, decision: str) -> None:
        super().__init__()
        self.approval_id = approval_id
        self.decision = decision


class ApprovalView(Message):
    """v on the focused approval. Opens the full sanitised text."""

    def __init__(self, approval_id: str) -> None:
        super().__init__()
        self.approval_id = approval_id


class SessionList(OptionList):
    """Sessions opened in this visit. Enter switches. n starts a draft."""

    BINDINGS = [Binding("n", "new_session", "New", show=False)]

    def __init__(self, id: str | None = None) -> None:
        super().__init__(id=id, compact=True, markup=False)

    def action_select(self) -> None:
        option = self.highlighted_option
        if option is None:
            return
        self.post_message(SessionSwitch(str(option.id or "")))

    def action_new_session(self) -> None:
        self.post_message(SessionNew())


class ApprovalList(OptionList):
    """Pending cards. a / s / d ask for confirmation. Enter only reveals the card."""

    BINDINGS = [
        Binding("a", "allow_once", "Approve"),
        Binding("s", "allow_session", "Session"),
        Binding("d", "deny", "Deny"),
        Binding("v", "view_full", "Full text", show=False),
        Binding("pagedown", "scroll_card", show=False),
        Binding("pageup", "scroll_card_up", show=False),
        Binding("end", "scroll_card_end", show=False),
        Binding("home", "scroll_card_home", show=False),
    ]

    def __init__(self, id: str | None = None) -> None:
        super().__init__(id=id, compact=True, markup=False)
        self._last_printable_at = 0.0

    def on_key(self, event: events.Key) -> None:
        char = event.character
        if char and char.isprintable() and char not in "asd":
            self._last_printable_at = time.monotonic()

    def action_select(self) -> None:
        option = self.highlighted_option
        if option is None or not option.id:
            return
        self.post_message(ApprovalShown(str(option.id)))

    def action_allow_once(self) -> None:
        self._emit("allow_once")

    def action_allow_session(self) -> None:
        self._emit("allow_session")

    def action_deny(self) -> None:
        self._emit("deny")

    def action_view_full(self) -> None:
        option = self.highlighted_option
        if option is None or not option.id:
            return
        self.post_message(ApprovalView(str(option.id)))

    def action_scroll_card(self) -> None:
        self._card().scroll_page_down(animate=False)

    def action_scroll_card_up(self) -> None:
        self._card().scroll_page_up(animate=False)

    def action_scroll_card_end(self) -> None:
        self._card().scroll_end(animate=False)

    def action_scroll_card_home(self) -> None:
        self._card().scroll_home(animate=False)

    def _card(self) -> GatedScroll:
        return self.app.query_one("#card-scroll", GatedScroll)

    def _emit(self, decision: str) -> None:
        if time.monotonic() - self._last_printable_at < _ARM_DELAY:
            return
        option = self.highlighted_option
        if option is None or not option.id:
            return
        self.post_message(ApprovalDecide(str(option.id), decision))


class GatedScroll(VerticalScroll):
    """Furthest position reached by a line, a page, or the mouse.

    Home and End jump. They do not move that mark, so they cannot satisfy
    the approval gate.
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.furthest = 0.0
        self._jumping = False

    def scroll_end(self, **kwargs: object) -> None:
        self._jump(to_end=True, **kwargs)

    def scroll_home(self, **kwargs: object) -> None:
        self._jump(to_end=False, **kwargs)

    def _jump(self, *, to_end: bool, **kwargs: object) -> None:
        animate = bool(kwargs.get("animate", True))
        immediate = bool(kwargs.get("immediate", False))
        x_axis = bool(kwargs.get("x_axis", True))
        y_axis = bool(kwargs.get("y_axis", True))
        rest = {
            key: value
            for key, value in kwargs.items()
            if key not in {"animate", "immediate", "x_axis", "y_axis"}
        }

        def go() -> None:
            target = self.max_scroll_y if to_end else 0
            self._jumping = True
            try:
                super(GatedScroll, self)._scroll_to(
                    0 if x_axis else None,
                    target if y_axis else None,
                    animate=animate,
                    release_anchor=False,
                    **rest,  # type: ignore[arg-type]
                )
            finally:
                self._jumping = False

        if immediate:
            go()
        else:
            self.call_after_refresh(go)

    def _scroll_to(self, x: float | None = None, y: float | None = None, **kwargs: object) -> bool:
        old = self.scroll_y
        jumping = self._jumping
        changed = super()._scroll_to(x, y, **kwargs)  # type: ignore[arg-type]
        if jumping or y is None:
            return changed
        page = self.scrollable_content_region.height
        if page <= 0:
            page = self.size.height or 1
        if abs(self.scroll_y - old) > page + 1:
            return changed
        if self.scroll_y > self.furthest:
            self.furthest = float(self.scroll_y)
        return changed

    def gate_met(self) -> bool:
        if self.max_scroll_y <= 0:
            return True
        return self.furthest >= self.max_scroll_y - 1


class FullTextScreen(ModalScreen[bool]):
    """The sanitised card with nothing cut off. Escape closes it."""

    BINDINGS = [
        Binding("escape", "close_full", "Close"),
        Binding("v", "close_full", show=False),
        Binding("pagedown", "page_down", show=False),
        Binding("pageup", "page_up", show=False),
        Binding("end", "jump_end", show=False),
        Binding("home", "jump_home", show=False),
    ]
    DEFAULT_CSS = """
    FullTextScreen {
        background: $background;
    }
    #full-scroll {
        height: 1fr;
        padding: 0 1;
    }
    #full-text {
        height: auto;
        width: 100%;
    }
    """

    def __init__(self, text: str) -> None:
        super().__init__()
        self._text = text

    def compose(self) -> ComposeResult:
        with GatedScroll(id="full-scroll"):
            yield Static(self._text, id="full-text", markup=False)

    def action_close_full(self) -> None:
        self.dismiss(self.query_one("#full-scroll", GatedScroll).gate_met())

    def action_page_down(self) -> None:
        self.query_one("#full-scroll", GatedScroll).scroll_page_down(animate=False)

    def action_page_up(self) -> None:
        self.query_one("#full-scroll", GatedScroll).scroll_page_up(animate=False)

    def action_jump_end(self) -> None:
        self.query_one("#full-scroll", GatedScroll).scroll_end(animate=False)

    def action_jump_home(self) -> None:
        self.query_one("#full-scroll", GatedScroll).scroll_home(animate=False)


class PraxisApp(App[None]):
    """Chat, timeline, approvals, and sessions. All of them stay on screen."""

    ENABLE_COMMAND_PALETTE = False
    TITLE = "Praxis Prime"
    CSS = """
    Screen {
        layout: vertical;
        background: $background;
        color: $text;
    }
    #status {
        height: 1;
        padding: 0 1;
        background: $surface;
        color: $text-muted;
    }
    #banner {
        display: none;
        height: auto;
        padding: 0 1;
        background: $surface;
        color: $warning;
    }
    #banner.show {
        display: block;
    }
    #body {
        layout: horizontal;
        height: 1fr;
    }
    #sessions {
        width: 28;
        height: 1fr;
        border-right: solid $border;
        padding: 0 1;
    }
    #center {
        layout: vertical;
        width: 1fr;
        height: 1fr;
    }
    #transcript {
        height: 1fr;
        padding: 0 1;
        background: $background;
    }
    #transcript-body {
        height: auto;
        width: 100%;
    }
    #transcript-body Static {
        height: auto;
        width: 100%;
    }
    .you {
        color: $accent;
        text-style: bold;
    }
    .prime {
        color: $text;
    }
    .gap {
        height: 1;
        color: $text-muted;
    }
    #composer {
        height: 3;
        margin: 0 1;
    }
    #side {
        layout: vertical;
        width: 46;
        height: 1fr;
        border-left: solid $border;
    }
    #timeline-label {
        height: 1;
        padding: 0 1;
        color: $text-muted;
    }
    #timeline {
        height: 1fr;
        padding: 0 1;
    }
    #card-scroll {
        height: auto;
        max-height: 20;
        min-height: 6;
        padding: 0 1;
        background: $surface;
    }
    #card {
        height: auto;
        width: 100%;
    }
    #approvals {
        height: 8;
        padding: 0 1;
    }
    SessionList.-textual-compact:focus,
    ApprovalList.-textual-compact:focus {
        border: solid $accent !important;
    }
    #timeline:focus, #transcript:focus, #composer:focus {
        border: solid $accent;
    }
    SessionList > .option-list--option-highlighted,
    ApprovalList > .option-list--option-highlighted {
        background: $block-cursor-blurred-background !important;
        color: $block-cursor-blurred-foreground !important;
    }
    SessionList:focus > .option-list--option-highlighted,
    ApprovalList:focus > .option-list--option-highlighted {
        background: $block-cursor-background !important;
        color: $block-cursor-foreground !important;
        text-style: bold;
    }
    Footer {
        background: $footer-background;
        color: $footer-foreground;
    }
    """
    BINDINGS = [
        Binding("f1", "help", "Help", priority=True),
        Binding("ctrl+f", "focus_chat", "Chat", priority=True),
        Binding("f2", "focus_timeline", "Timeline"),
        Binding("f3", "focus_approvals", "Approvals"),
        Binding("f4", "focus_sessions", "Sessions"),
        Binding("question_mark", "help", "Help", show=False),
        Binding("ctrl+n", "new_session", "New"),
        Binding("ctrl+q", "quit", "Quit"),
    ]

    def __init__(
        self,
        gateway: TuiGateway,
        *,
        profile: str = "",
        session: str = "",
    ) -> None:
        super().__init__()
        self.gateway = gateway
        self.profile = profile
        self.sessions = SessionBook(session)
        self._timeline: list[str] = []
        self._approvals: list[dict[str, object]] = []
        self._approval_ids: list[str] = []
        self._selected_id: str | None = None
        self._latched: set[str] = set()
        self._last_decide_at = 0.0
        self._card_key: tuple[str, str] | None = None
        self._truncated_id: str | None = None
        self._full_read_id: str | None = None
        self._transcript_timer: object | None = None
        self._transcript_dirty = False
        self._shown_lines: list[str] | None = None
        self._palette: Palette | None = None
        self._can_chat = False
        self._blocked = ""
        self._booted = False
        self._busy = False

    def compose(self) -> ComposeResult:
        yield Static("", id="status", markup=False)
        yield Static("", id="banner", markup=False)
        with Horizontal(id="body"):
            yield SessionList(id="sessions")
            with Vertical(id="center"):
                with VerticalScroll(id="transcript"):
                    yield Vertical(id="transcript-body")
                yield Input(placeholder="Message", id="composer")
            with Vertical(id="side"):
                yield Static("Timeline", id="timeline-label", markup=False)
                with VerticalScroll(id="timeline"):
                    yield Static("", id="timeline-body", markup=False)
                with GatedScroll(id="card-scroll"):
                    yield Static("", id="card", markup=False)
                yield ApprovalList(id="approvals")
        yield Footer()

    def on_mount(self) -> None:
        self._apply_palette(fallback_palette(resolve_mode("system")))
        self._render_sessions()
        self._sync_transcript(force=True)
        self.query_one("#composer", Input).focus()
        self.run_worker(self._bootstrap, thread=True, group="boot", exit_on_error=False)
        self.set_interval(1.0, self._poll_approvals)
        self.set_interval(2.0, self._poll_theme)

    def action_focus_chat(self) -> None:
        self.query_one("#composer", Input).focus()

    def action_focus_timeline(self) -> None:
        self.query_one("#timeline").focus()

    def action_focus_approvals(self) -> None:
        self.query_one("#approvals", ApprovalList).focus()

    def action_focus_sessions(self) -> None:
        self.query_one("#sessions", SessionList).focus()

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_new_session(self) -> None:
        self._new_session()

    def action_quit(self) -> None:
        self.gateway.close()
        self.exit()

    def transcript_text(self) -> str:
        return self.sessions.text()

    def timeline_text(self) -> str:
        return "\n".join(self._timeline)

    def approval_ids(self) -> list[str]:
        return list(self._approval_ids)

    @property
    def booted(self) -> bool:
        return self._booted

    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text:
            event.input.clear()
            return
        if not self._booted:
            return
        if self._busy:
            return
        if not self._can_chat:
            self._set_banner(self._blocked)
            return
        event.input.clear()
        self._send(text)

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if event.option_list.id != "approvals":
            return
        option_id = str(event.option_id or "")
        self._selected_id = option_id or None
        self._show_card(self._find_approval(option_id) if option_id else None)

    @on(SessionSwitch)
    def _on_session_switch(self, event: SessionSwitch) -> None:
        session_id = "" if event.option_id in {"", "draft"} else event.option_id
        self.sessions.switch(session_id)
        self._render_sessions()
        self._sync_transcript(force=True)
        self._render_status()

    @on(SessionNew)
    def _on_session_new(self, event: SessionNew) -> None:
        del event
        self._new_session()

    @on(ApprovalShown)
    def _on_approval_shown(self, event: ApprovalShown) -> None:
        self._selected_id = event.approval_id
        self._show_card(self._find_approval(event.approval_id))

    @on(ApprovalDecide)
    def _on_approval_decide(self, event: ApprovalDecide) -> None:
        now = time.monotonic()
        if now - self._last_decide_at < _DECIDE_GAP:
            return
        if len(self.screen_stack) > 1:
            return
        approval_id = event.approval_id
        if not approval_id or approval_id in self._latched:
            return
        if self._selected_id != approval_id:
            return
        if self._truncated_id == approval_id:
            if self._full_read_id != approval_id:
                self._timeline_add("Press v and page through the full text before deciding.")
                return
        elif not self._card_at_end():
            self._timeline_add("Scroll the approval card to the end before deciding.")
            return
        self._last_decide_at = now
        item = self._find_approval(approval_id) or {}
        dialog = ConfirmDecision(
            approval_id=sanitize(approval_id, newlines=False),
            tool=sanitize(item.get("tool") or "", newlines=False),
            action=sanitize(item.get("summary") or "", newlines=False),
            decision=event.decision,
            scope=scope_label(item),
        )

        def done(confirmed: bool | None) -> None:
            if not confirmed or approval_id in self._latched:
                return
            if self._find_approval(approval_id) is None:
                return
            self._latched.add(approval_id)
            self._send_decision(approval_id, event.decision)

        self.push_screen(dialog, done)

    @on(ApprovalView)
    def _on_approval_view(self, event: ApprovalView) -> None:
        if len(self.screen_stack) > 1:
            return
        item = self._find_approval(event.approval_id)
        if item is None:
            return
        self._selected_id = event.approval_id

        def done(met: bool | None) -> None:
            if met and self._truncated_id == event.approval_id:
                self._full_read_id = event.approval_id

        self.push_screen(FullTextScreen(render_card(item, full=True)), done)

    def _new_session(self) -> None:
        self.sessions.new()
        self._render_sessions()
        self._sync_transcript(force=True)
        self._render_status()
        self.query_one("#composer", Input).focus()

    def _send(self, text: str) -> None:
        shown = sanitize(text)
        self.sessions.note_user(shown)
        if self.sessions.current == "":
            target = self.sessions.pin_draft()
        else:
            target = self.sessions.current
        self.sessions.append(target, f"you: {shown}")
        self._sync_transcript(force=True)
        self._render_sessions()
        self._busy = True
        self._render_status()

        def work() -> None:
            def on_event(payload: dict[str, object]) -> None:
                self.call_from_thread(self._apply_event, target, payload)

            try:
                result = self.gateway.chat(
                    shown,
                    session_id=self.sessions.wire_id(target),
                    on_event=on_event,
                    profile=self.profile,
                )
            except GatewayError as exc:
                self.call_from_thread(self._chat_failed, target, str(exc))
                return
            except OSError as exc:
                self.gateway.note_down()
                self.call_from_thread(self._chat_failed, target, f"disconnected: {exc}")
                return
            self.call_from_thread(self._chat_finished, target, result)

        self.run_worker(work, thread=True, group="chat", exclusive=True, exit_on_error=False)

    def _apply_event(self, session_id: str, payload: dict[str, object]) -> None:
        kind = str(payload.get("kind") or "")
        if kind == "text":
            chunk = sanitize(payload.get("text") or "")
            if chunk:
                self.sessions.add_assistant_chunk(session_id, chunk)
                if self.sessions.current == session_id:
                    self._schedule_transcript()
            return
        if kind == "decision_failed":
            failed_id = str(payload.get("approval_id") or "")
            if failed_id:
                self._latched.discard(failed_id)
            detail = str(payload.get("detail") or "")
            if detail:
                self._timeline_add(detail)
            return
        if kind == "tool":
            self.sessions.seal_assistant(session_id)
            self._timeline_add(_span("tool", payload))
            return
        if kind == "status":
            self._timeline_add(_span("status", payload))
            return
        if kind == "turn":
            phase = sanitize(payload.get("phase", ""), newlines=False)
            self._timeline_add(f"turn {phase}".strip())
            return
        if kind == "approval":
            approval = payload.get("approval")
            if isinstance(approval, dict):
                self.sessions.seal_assistant(session_id)
                self._upsert_approval(approval)
                approval_id = sanitize(approval.get("id", ""), newlines=False)
                self._timeline_add(f"approval {approval_id}")

    def _chat_finished(self, target: str, result: dict[str, object]) -> None:
        self._busy = False
        payload = result.get("payload")
        body = payload if isinstance(payload, dict) else {}
        final = sanitize(body.get("text") or "", newlines=False)
        self.sessions.finish_assistant(target, final)
        error = body.get("error")
        if error:
            self.sessions.append(target, f"error: {sanitize(error)}")
        session_id = str(body.get("sessionId") or "")
        if session_id:
            self.sessions.rename(target, session_id)
        self._sync_transcript(force=True)
        self._render_sessions()
        self._render_status()

    def _chat_failed(self, target: str, message: str) -> None:
        self._busy = False
        visible = sanitize(message)
        self.sessions.append(target, f"error: {visible}")
        self._timeline_add(f"error: {visible}")
        self._sync_transcript(force=True)
        self._render_status()

    def _decision_failed(self, approval_id: str, message: str) -> None:
        self._latched.discard(approval_id)
        self._timeline_add(f"error: {sanitize(message)}")

    def _send_decision(self, approval_id: str, decision: str) -> None:
        def work() -> None:
            try:
                state = self.gateway.decide(approval_id, decision)
            except (GatewayError, ValueError, OSError) as exc:
                self.call_from_thread(self._decision_failed, approval_id, str(exc))
                return
            self.call_from_thread(
                self._timeline_add,
                f"decision {decision} {approval_id} ({state})",
            )

        self.run_worker(work, thread=True, group="decide", exit_on_error=False)

    def _bootstrap(self) -> None:
        try:
            palette = palette_from_http(self.gateway.http, self.profile)
            readiness = self.gateway.readiness()
            try:
                approvals: list[dict[str, object]] | None = self.gateway.list_approvals()
            except GatewayError:
                approvals = None
        except Exception as exc:
            self.call_from_thread(self._boot_failed, str(exc))
            return
        self.call_from_thread(self._booted_ok, palette, readiness, approvals)

    def _booted_ok(
        self,
        palette: object,
        readiness: Readiness,
        approvals: list[dict[str, object]] | None,
    ) -> None:
        if isinstance(palette, Palette):
            self._apply_palette(palette)
        self._can_chat = readiness.ready
        self._blocked = readiness.message
        self._booted = True
        if readiness.message and not readiness.ready:
            self._set_banner(readiness.message)
        if approvals is not None:
            self._set_approvals(approvals)
        self._render_status()

    def _boot_failed(self, message: str) -> None:
        self._can_chat = True
        self._booted = True
        self._timeline_add(f"error: {sanitize(message)}")
        self._render_status()

    def _poll_approvals(self) -> None:
        try:
            self.query_one("#card")
        except NoMatches:
            return
        if not self.gateway.connected:
            self.run_worker(
                self._reconnect,
                thread=True,
                group="reconnect",
                exclusive=True,
                exit_on_error=False,
            )
            return
        if self._busy or self.gateway.in_chat:
            return
        self.run_worker(
            self._load_approvals,
            thread=True,
            group="approvals",
            exclusive=True,
            exit_on_error=False,
        )

    def _reconnect(self) -> None:
        self.gateway.try_reconnect()
        self.call_from_thread(self._render_status)

    def _load_approvals(self) -> None:
        try:
            items = self.gateway.list_approvals()
        except GatewayError:
            return
        self.call_from_thread(self._set_approvals, items)

    def _poll_theme(self) -> None:
        palette = self._palette
        if palette is None:
            return
        if palette.theme_id != "omarchy.live" and palette.requested != "omarchy":
            return
        self.run_worker(
            self._reload_theme,
            thread=True,
            group="theme",
            exclusive=True,
            exit_on_error=False,
        )

    def _reload_theme(self) -> None:
        current = self._palette
        palette = palette_from_http(self.gateway.http, self.profile)
        if current is not None and palette.package_hash == current.package_hash:
            if palette.theme_id == current.theme_id and palette.mode == current.mode:
                return
        self.call_from_thread(self._apply_palette, palette)

    def _apply_palette(self, palette: object) -> None:
        if not isinstance(palette, Palette):
            return
        self._palette = palette
        mapped = theme_for(palette)
        self.register_theme(mapped)
        if self.theme != mapped.name:
            self.theme = mapped.name
        else:
            self.refresh_css()
        self._render_status()

    def _set_banner(self, message: str) -> None:
        banner = self.query_one("#banner", Static)
        banner.update(sanitize(message))
        if message:
            banner.add_class("show")
        else:
            banner.remove_class("show")

    def _render_status(self) -> None:
        try:
            widget = self.query_one("#status", Static)
        except Exception:
            return
        session = self.sessions.current or "new"
        theme_id = self._palette.theme_id if self._palette is not None else "smf.praxis"
        mode = self._palette.mode if self._palette is not None else ""
        profile = self.profile or "profile"
        if not self.gateway.connected:
            flag = "  disconnected, retrying"
        elif self._busy:
            flag = "  busy"
        else:
            flag = ""
        widget.update(sanitize(f"Praxis Prime  {profile}  {session}  {theme_id} {mode}{flag}"))

    def _schedule_transcript(self) -> None:
        """Coalesce streaming updates to about 30 frames a second."""
        self._transcript_dirty = True
        if self._transcript_timer is not None:
            return
        self._transcript_timer = self.set_timer(_STREAM_INTERVAL, self._flush_transcript)

    def _flush_transcript(self) -> None:
        self._transcript_timer = None
        if not self._transcript_dirty:
            return
        self._transcript_dirty = False
        self._sync_transcript()

    def _sync_transcript(self, *, force: bool = False) -> None:
        if force:
            self._transcript_dirty = False
        try:
            body = self.query_one("#transcript-body", Vertical)
        except NoMatches:
            return
        lines = list(self.sessions.transcripts.get(self.sessions.current, []))
        shown = self._shown_lines
        if not force and shown == lines:
            return
        mounted = list(body.children)
        if (
            not force
            and shown is not None
            and lines
            and len(shown) == len(lines)
            and shown[:-1] == lines[:-1]
            and len(mounted) == len(lines)
        ):
            mounted[-1].update(lines[-1] or " ")
            mounted[-1].set_classes(_line_class(lines[-1]))
            self._shown_lines = lines
            return
        if (
            not force
            and shown is not None
            and lines[: len(shown)] == shown
            and len(mounted) == len(shown)
        ):
            for line in lines[len(shown) :]:
                body.mount(_line_widget(line))
            self._shown_lines = lines
            self.query_one("#transcript", VerticalScroll).scroll_end(animate=False)
            return
        body.remove_children()
        for line in lines:
            body.mount(_line_widget(line))
        self._shown_lines = lines
        if lines:
            self.query_one("#transcript", VerticalScroll).scroll_end(animate=False)

    def _render_sessions(self) -> None:
        widget = self.query_one("#sessions", SessionList)
        rows = self.sessions.rows()
        widget.clear_options()
        current_index = 0
        for index, (session_id, title) in enumerate(rows):
            option_id = session_id or "draft"
            mark = ">" if session_id == self.sessions.current else " "
            widget.add_option(Option(_session_label(mark, title, session_id), id=option_id))
            if session_id == self.sessions.current:
                current_index = index
        if widget.option_count:
            widget.highlighted = current_index

    def _set_approvals(self, items: list[dict[str, object]]) -> None:
        try:
            widget = self.query_one("#approvals", ApprovalList)
        except NoMatches:
            return
        cleaned = [item for item in items if item.get("id")]
        ids = [str(item.get("id") or "") for item in cleaned]
        self._latched.intersection_update(ids)
        if ids == self._approval_ids and all(
            render_card(old) == render_card(new)
            for old, new in zip(self._approvals, cleaned, strict=True)
        ):
            self._approvals = cleaned
            return
        selected = self._selected_id
        previous = list(self._approval_ids)
        self._approvals = cleaned
        widget.clear_options()
        for item in cleaned:
            approval_id = str(item.get("id") or "")
            risk = sanitize(item.get("risk") or "", newlines=False)
            tool = sanitize(item.get("tool") or "", newlines=False)
            label_id = sanitize(approval_id, newlines=False)
            widget.add_option(Option(f"{risk}  {tool}  {label_id}", id=approval_id))
        self._approval_ids = ids
        if selected and selected in ids:
            widget.highlighted = ids.index(selected)
            self._selected_id = selected
            self._show_card(self._find_approval(selected))
            return
        if not previous and ids:
            widget.highlighted = 0
            self._selected_id = ids[0]
            self._show_card(cleaned[0])
            return
        widget.highlighted = None
        self._selected_id = None
        self._show_card(None)

    def _upsert_approval(self, item: dict[str, object]) -> None:
        approval_id = str(item.get("id") or "")
        if not approval_id:
            return
        replaced = False
        updated: list[dict[str, object]] = []
        for existing in self._approvals:
            if str(existing.get("id") or "") == approval_id:
                updated.append(item)
                replaced = True
            else:
                updated.append(existing)
        if not replaced:
            updated.append(item)
        self._set_approvals(updated)

    def _find_approval(self, approval_id: str) -> dict[str, object] | None:
        for item in self._approvals:
            if str(item.get("id") or "") == approval_id:
                return item
        return None

    def _show_card(self, item: dict[str, object] | None) -> None:
        try:
            widget = self.query_one("#card", Static)
            scroller = self.query_one("#card-scroll", GatedScroll)
        except NoMatches:
            return
        if not item:
            if self._card_key is None:
                return
            widget.update("")
            self._card_key = None
            self._truncated_id = None
            self._full_read_id = None
            scroller.furthest = 0.0
            return
        approval_id = str(item.get("id") or "")
        text = render_card(item)
        key = (approval_id, text)
        if key == self._card_key:
            return
        widget.update(text)
        scroller.furthest = 0.0
        scroller.scroll_home(animate=False)
        self._card_key = key
        self._truncated_id = approval_id if card_truncated(item) else None
        self._full_read_id = None

    def _card_at_end(self) -> bool:
        try:
            scroller = self.query_one("#card-scroll", GatedScroll)
        except NoMatches:
            return False
        return scroller.gate_met()

    def _timeline_add(self, line: str) -> None:
        self._timeline.append(_hanging(sanitize(line)))
        if len(self._timeline) > _TIMELINE_CAP:
            self._timeline = self._timeline[-_TIMELINE_CAP:]
        try:
            self.query_one("#timeline-body", Static).update("\n".join(self._timeline))
        except Exception:
            return


def _span(kind: str, payload: dict[str, object]) -> str:
    name = sanitize(payload.get("name") or "", newlines=False)
    phase = sanitize(payload.get("phase") or "", newlines=False)
    detail = sanitize(payload.get("detail") or "", newlines=False)
    return f"{kind} {name} {phase} {detail}".strip()


def _line_class(line: str) -> str:
    if line == "":
        return "gap"
    if line.startswith("you:"):
        return "you"
    if line.startswith("prime:"):
        return "prime"
    return "note"


def _line_widget(line: str) -> Static:
    shown = line if line else " "
    return Static(shown, markup=False, classes=_line_class(line))


def _static_text(widget: object) -> str:
    text = str(getattr(widget, "content", ""))
    classes = getattr(widget, "classes", ())
    if "gap" in classes:
        return ""
    return text


def _session_label(mark: str, title: str, session_id: str) -> str:
    ident = sanitize(session_id or "draft", newlines=False)
    if len(ident) > 8:
        ident = ident[:8]
    clean = sanitize(title, newlines=False)
    if len(clean) > 14:
        clean = clean[:13] + "…"
    return f"{mark} {clean}  {ident}"


def _hanging(text: str, width: int = 36) -> str:
    blocks = [_wrap_one(block, width) for block in text.split("\n")]
    return "\n".join(blocks)


def _wrap_one(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    lines: list[str] = []
    rest = text
    first = True
    while rest:
        limit = width if first else max(1, width - 2)
        if len(rest) <= limit:
            lines.append(rest if first else f"  {rest}")
            break
        cut = rest.rfind(" ", 0, limit + 1)
        if cut <= 0:
            cut = limit
        chunk = rest[:cut].rstrip()
        rest = rest[cut:].lstrip()
        lines.append(chunk if first else f"  {chunk}")
        first = False
    return "\n".join(lines)
