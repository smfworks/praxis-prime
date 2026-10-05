"""Full-screen Praxis Prime terminal. A gateway client, keyboard first."""

from __future__ import annotations

import os

from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Footer, Input, OptionList, Static
from textual.widgets._option_list import Option

from praxis_prime.approvals.card import format_approval_card
from praxis_prime.gateway.client import GatewayError
from praxis_prime.tui.gateway import Readiness, TuiGateway
from praxis_prime.tui.palette import fallback_palette, palette_from_http, resolve_mode
from praxis_prime.tui.sessions import SessionBook
from praxis_prime.tui.theme_map import theme_for

HELP = "\n".join(
    (
        "Praxis Prime",
        "",
        "F1 chat    F2 timeline    F3 approvals    F4 sessions",
        "Enter in the composer sends. Nothing is approved for you.",
        "Approvals, when that pane is focused:",
        "  a  approve once",
        "  s  approve for this session",
        "  d  deny",
        "  Enter shows the card and does not decide.",
        "Sessions: Enter switches, n starts a new one, ctrl+n from anywhere.",
        "? help    ctrl+q quit",
        "",
        "This visit's sessions stay on this screen. The daemon has no session list.",
    )
)


class HelpScreen(ModalScreen[None]):
    """Key chart. Escape or ? closes it."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("question_mark", "dismiss", "Close"),
    ]
    DEFAULT_CSS = """
    HelpScreen {
        align: center middle;
    }
    HelpScreen > Static {
        width: 68;
        height: auto;
        padding: 1 2;
        background: $surface;
        color: $text;
        border: solid $border;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(HELP, markup=False)


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
    """a, s, or d on the focused approval."""

    def __init__(self, approval_id: str, decision: str) -> None:
        super().__init__()
        self.approval_id = approval_id
        self.decision = decision


class SessionList(OptionList):
    """Sessions opened in this visit. Enter switches. n starts a draft."""

    BINDINGS = [Binding("n", "new_session", "New", show=False)]

    def __init__(self, id: str | None = None) -> None:
        super().__init__(id=id, compact=True, markup=False)

    def action_select(self) -> None:
        option = self.highlighted_option
        if option is None:
            return
        self.post_message(SessionSwitch(option.id or ""))

    def action_new_session(self) -> None:
        self.post_message(SessionNew())


class ApprovalList(OptionList):
    """Pending cards. a / s / d decide. Enter only reveals the card."""

    BINDINGS = [
        Binding("a", "allow_once", "Approve"),
        Binding("s", "allow_session", "Session"),
        Binding("d", "deny", "Deny"),
    ]

    def __init__(self, id: str | None = None) -> None:
        super().__init__(id=id, compact=True, markup=False)

    def action_select(self) -> None:
        option = self.highlighted_option
        if option is None or not option.id:
            return
        self.post_message(ApprovalShown(option.id))

    def action_allow_once(self) -> None:
        self._emit("allow_once")

    def action_allow_session(self) -> None:
        self._emit("allow_session")

    def action_deny(self) -> None:
        self._emit("deny")

    def _emit(self, decision: str) -> None:
        option = self.highlighted_option
        if option is None or not option.id:
            return
        self.post_message(ApprovalDecide(option.id, decision))


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
    }
    #composer {
        height: 3;
        margin: 0 1;
    }
    #side {
        layout: vertical;
        width: 42;
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
        max-height: 12;
        padding: 0 1;
        background: $surface;
    }
    #approvals {
        height: 8;
        padding: 0 1;
    }
    Footer {
        background: $footer-background;
        color: $footer-foreground;
    }
    """
    BINDINGS = [
        Binding("f1", "focus_chat", "Chat"),
        Binding("f2", "focus_timeline", "Timeline"),
        Binding("f3", "focus_approvals", "Approvals"),
        Binding("f4", "focus_sessions", "Sessions"),
        Binding("question_mark", "help", "Help"),
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
        self._palette = None
        self._can_chat = False
        self._blocked = ""
        self._booted = False
        self._busy = False
        self._no_color = os.environ.get("NO_COLOR") is not None

    def compose(self) -> ComposeResult:
        yield Static("", id="status", markup=False)
        yield Static("", id="banner", markup=False)
        with Horizontal(id="body"):
            yield SessionList(id="sessions")
            with Vertical(id="center"):
                with VerticalScroll(id="transcript"):
                    yield Static("", id="transcript-body", markup=False)
                yield Input(placeholder="Message", id="composer")
            with Vertical(id="side"):
                yield Static("Timeline", id="timeline-label", markup=False)
                with VerticalScroll(id="timeline"):
                    yield Static("", id="timeline-body", markup=False)
                with VerticalScroll(id="card-scroll"):
                    yield Static("", id="card", markup=False)
                yield ApprovalList(id="approvals")
        yield Footer()

    def on_mount(self) -> None:
        self._apply_palette(fallback_palette(resolve_mode("system")))
        self._render_sessions()
        self._render_transcript()
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

    @on(SessionSwitch)
    def _on_session_switch(self, event: SessionSwitch) -> None:
        session_id = "" if event.option_id in {"", "draft"} else event.option_id
        self.sessions.switch(session_id)
        self._render_sessions()
        self._render_transcript()
        self._render_status()

    @on(SessionNew)
    def _on_session_new(self, event: SessionNew) -> None:
        del event
        self._new_session()

    @on(ApprovalShown)
    def _on_approval_shown(self, event: ApprovalShown) -> None:
        self._show_card(self._find_approval(event.approval_id))

    @on(ApprovalDecide)
    def _on_approval_decide(self, event: ApprovalDecide) -> None:
        approval_id = event.approval_id
        decision = event.decision

        def work() -> None:
            try:
                state = self.gateway.decide(approval_id, decision)
            except (GatewayError, ValueError) as exc:
                self.call_from_thread(self._timeline_add, f"error: {exc}")
                return
            self.call_from_thread(
                self._timeline_add,
                f"decision {decision} {approval_id} ({state})",
            )

        self.run_worker(work, thread=True, group="decide", exit_on_error=False)

    def _new_session(self) -> None:
        self.sessions.new()
        self._render_sessions()
        self._render_transcript()
        self._render_status()
        self.query_one("#composer", Input).focus()

    def _send(self, text: str) -> None:
        self.sessions.note_user(text)
        target = self.sessions.current
        self.sessions.append(target, f"you: {text}")
        self._render_transcript()
        self._busy = True
        self._render_status()

        def work() -> None:
            def on_event(payload: dict[str, object]) -> None:
                self.call_from_thread(self._apply_event, target, payload)

            try:
                result = self.gateway.chat(
                    text,
                    session_id=target or None,
                    on_event=on_event,
                    profile=self.profile,
                )
            except GatewayError as exc:
                self.call_from_thread(self._chat_failed, target, str(exc))
                return
            self.call_from_thread(self._chat_finished, target, result)

        self.run_worker(work, thread=True, group="chat", exclusive=True, exit_on_error=False)

    def _apply_event(self, session_id: str, payload: dict[str, object]) -> None:
        kind = str(payload.get("kind") or "")
        if kind == "text":
            chunk = str(payload.get("text") or "")
            if chunk:
                current = self.sessions.last_with_prefix(session_id, "prime: ")
                self.sessions.replace_last(session_id, "prime: ", f"prime: {current}{chunk}")
                if self.sessions.current == session_id:
                    self._render_transcript()
            return
        if kind == "tool":
            self._timeline_add(_span("tool", payload))
            return
        if kind == "status":
            self._timeline_add(_span("status", payload))
            return
        if kind == "turn":
            self._timeline_add(f"turn {payload.get('phase', '')}".strip())
            return
        if kind == "approval":
            approval = payload.get("approval")
            if isinstance(approval, dict):
                self._upsert_approval(approval)
                self._timeline_add(f"approval {approval.get('id', '')}")

    def _chat_finished(self, target: str, result: dict[str, object]) -> None:
        self._busy = False
        payload = result.get("payload")
        body = payload if isinstance(payload, dict) else {}
        final = str(body.get("text") or "")
        streamed = self.sessions.last_with_prefix(target, "prime: ")
        if final and final != streamed:
            if streamed:
                self.sessions.replace_last(target, "prime: ", f"prime: {final}")
            else:
                self.sessions.append(target, f"prime: {final}")
        error = body.get("error")
        if error:
            self.sessions.append(target, f"error: {error}")
        session_id = str(body.get("sessionId") or "")
        if session_id and target == "":
            self.sessions.adopt(session_id)
        elif session_id and session_id != target:
            self.sessions.switch(session_id)
        self._render_transcript()
        self._render_sessions()
        self._render_status()

    def _chat_failed(self, target: str, message: str) -> None:
        self._busy = False
        self.sessions.append(target, f"error: {message}")
        self._timeline_add(f"error: {message}")
        self._render_transcript()
        self._render_status()

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
        from praxis_prime.tui.palette import Palette

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
        self._timeline_add(f"error: {message}")
        self._render_status()

    def _poll_approvals(self) -> None:
        if self._busy or self.gateway.in_chat:
            return
        self.run_worker(
            self._load_approvals,
            thread=True,
            group="approvals",
            exclusive=True,
            exit_on_error=False,
        )

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
        from praxis_prime.tui.palette import Palette

        if not isinstance(palette, Palette):
            return
        self._palette = palette
        mapped = theme_for(palette, no_color=self._no_color)
        if isinstance(mapped, str):
            self.theme = mapped
        else:
            self.register_theme(mapped)
            self.theme = mapped.name
        self._render_status()

    def _set_banner(self, message: str) -> None:
        banner = self.query_one("#banner", Static)
        banner.update(message)
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
        busy = "  busy" if self._busy else ""
        widget.update(f"Praxis Prime  {profile}  {session}  {theme_id} {mode}{busy}")

    def _render_transcript(self) -> None:
        self.query_one("#transcript-body", Static).update(self.sessions.text())

    def _render_sessions(self) -> None:
        widget = self.query_one("#sessions", SessionList)
        rows = self.sessions.rows()
        widget.clear_options()
        current_index = 0
        for index, (session_id, title) in enumerate(rows):
            option_id = session_id or "draft"
            mark = ">" if session_id == self.sessions.current else " "
            short = session_id[:8] if session_id else "draft"
            widget.add_option(Option(f"{mark} {title}  {short}", id=option_id))
            if session_id == self.sessions.current:
                current_index = index
        if widget.option_count:
            widget.highlighted = current_index

    def _set_approvals(self, items: list[dict[str, object]]) -> None:
        ids = [str(item.get("id") or "") for item in items if item.get("id")]
        self._approvals = [item for item in items if item.get("id")]
        if ids == self._approval_ids:
            return
        widget = self.query_one("#approvals", ApprovalList)
        previous = widget.highlighted
        widget.clear_options()
        for item in self._approvals:
            approval_id = str(item.get("id") or "")
            label = f"{item.get('risk', '')}  {item.get('tool', '')}  {approval_id}"
            widget.add_option(Option(label, id=approval_id))
        self._approval_ids = ids
        if not widget.option_count:
            self._show_card(None)
            return
        index = 0 if previous is None else min(previous, widget.option_count - 1)
        widget.highlighted = index
        self._show_card(self._approvals[index])

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
        self._show_card(item)

    def _find_approval(self, approval_id: str) -> dict[str, object] | None:
        for item in self._approvals:
            if str(item.get("id") or "") == approval_id:
                return item
        return None

    def _show_card(self, item: dict[str, object] | None) -> None:
        widget = self.query_one("#card", Static)
        if not item:
            widget.update("")
            return
        widget.update(format_approval_card(item))

    def _timeline_add(self, line: str) -> None:
        self._timeline.append(line)
        try:
            self.query_one("#timeline-body", Static).update("\n".join(self._timeline))
        except Exception:
            return


def _span(kind: str, payload: dict[str, object]) -> str:
    name = str(payload.get("name") or "")
    phase = str(payload.get("phase") or "")
    detail = str(payload.get("detail") or "")
    return f"{kind} {name} {phase} {detail}".strip()
