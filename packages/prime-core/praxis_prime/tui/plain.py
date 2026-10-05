"""Linear transcript for screen readers.

No full-screen layout, no box drawing, and no colour. Assistant text is
buffered to a newline or the end of the turn, and the ``prime:`` prefix is
printed once per line. ``/approve``, ``/session-approve``, and ``/deny`` are
the only decision commands. An empty line decides nothing.
"""

from __future__ import annotations

import queue
import threading
from collections.abc import Callable

from praxis_prime.gateway.client import GatewayError
from praxis_prime.sanitize import sanitize
from praxis_prime.tui.cards import render_card
from praxis_prime.tui.gateway import TuiGateway
from praxis_prime.tui.sessions import SessionBook

ReadLine = Callable[[], str]
Write = Callable[[str], None]

HELP = "\n".join(
    (
        "Commands:",
        "  /help",
        "  /quit",
        "  /sessions",
        "  /session <id>",
        "  /new",
        "  /approvals",
        "  /timeline",
        "  /approve <id>             allow once",
        "  /session-approve <id>     allow for that approval's session",
        "                            (this daemon process, when the session is empty)",
        "  /deny <id>",
        "Any other line is a chat message.",
        "Nothing is approved unless you send one of those commands.",
    )
)


def run_plain(
    *,
    gateway: TuiGateway,
    sessions: SessionBook,
    read_line: ReadLine,
    write: Write,
    port: int,
) -> int:
    """Read commands until ``/quit`` or end of input. Returns a process code."""
    del port  # the gateway already carries the wizard port in its readiness text
    incoming = _Incoming(read_line)
    timeline: list[str] = []
    readiness = gateway.readiness()
    write("Praxis Prime. Type /help for commands.\n")
    if not readiness.ready and readiness.message:
        write(sanitize(readiness.message) + "\n")
    _announce(gateway, write)

    def drain() -> None:
        incoming.drain_decisions(gateway, write)

    gateway.set_wait_hook(drain)
    try:
        while True:
            write("> ")
            line = incoming.next_line()
            if line is None:
                return 0
            done = _handle(
                line,
                gateway,
                sessions,
                timeline,
                readiness.ready,
                readiness.message,
                write,
            )
            if done:
                return 0
    finally:
        gateway.set_wait_hook(None)
        incoming.close()


def decision_of(line: str) -> tuple[str, str] | None:
    """``(approval id, decision)`` when ``line`` is an explicit decision command."""
    parts = line.strip().split()
    if len(parts) != 2:
        return None
    command, approval_id = parts
    if command == "/approve":
        return approval_id, "allow_once"
    if command == "/session-approve":
        return approval_id, "allow_session"
    if command == "/deny":
        return approval_id, "deny"
    return None


def _handle(
    line: str,
    gateway: TuiGateway,
    sessions: SessionBook,
    timeline: list[str],
    ready: bool,
    blocked: str,
    write: Write,
) -> bool:
    """Run one command. Return True when the session should end."""
    text = line.strip()
    if not text:
        return False
    if text in {"/quit", "/exit"}:
        return True
    if text == "/help":
        write(HELP + "\n")
        return False
    if text == "/sessions":
        _write_sessions(sessions, write)
        return False
    if text == "/new":
        sessions.new()
        write("session new\n")
        return False
    if text == "/approvals":
        _announce(gateway, write)
        return False
    if text == "/timeline":
        if not timeline:
            write("timeline empty\n")
            return False
        for item in timeline[-500:]:
            write(item + "\n")
        return False
    if text.startswith("/session "):
        session_id = text.split(maxsplit=1)[1].strip()
        if not session_id:
            write("usage: /session <id>\n")
            return False
        sessions.switch(session_id)
        write(f"session {sanitize(session_id, newlines=False)}\n")
        shown = sessions.text()
        if shown:
            write(shown + "\n")
        return False
    parsed = decision_of(text)
    if parsed is not None:
        _apply_decision(gateway, parsed[0], parsed[1], write)
        return False
    if text.startswith("/"):
        write("Unknown command. Type /help.\n")
        return False
    if not ready:
        write(sanitize(blocked or "Chat is not available.") + "\n")
        return False
    if not _ensure_connected(gateway, write):
        return False
    _send(gateway, sessions, timeline, text, write)
    return False


def _send(
    gateway: TuiGateway,
    sessions: SessionBook,
    timeline: list[str],
    text: str,
    write: Write,
) -> None:
    shown = sanitize(text)
    sessions.note_user(shown)
    if sessions.current == "":
        target = sessions.pin_draft()
    else:
        target = sessions.current
    sessions.append(target, f"you: {shown}")
    write(f"you: {shown}\n")
    buffer = _PrimeBuffer(write)

    def on_event(payload: dict[str, object]) -> None:
        kind = str(payload.get("kind") or "")
        if kind == "text":
            buffer.add(str(payload.get("text") or ""))
            return
        if kind == "decision_failed":
            buffer.flush()
            write(sanitize(payload.get("detail") or "decision failed") + "\n")
            return
        if kind == "approval":
            buffer.flush()
            approval = payload.get("approval")
            if isinstance(approval, dict):
                _write_card(approval, write)
                approval_id = sanitize(approval.get("id", ""), newlines=False)
                timeline.append(f"timeline: approval {approval_id}")
            return
        if kind == "tool":
            buffer.flush()
        if kind in {"tool", "status"}:
            line = _span(kind, payload)
            timeline.append(line)
            write(line + "\n")
            return
        if kind == "turn":
            line = f"timeline: turn {sanitize(payload.get('phase', ''), newlines=False)}".strip()
            timeline.append(line)
        if len(timeline) > 500:
            del timeline[:-500]

    try:
        result = gateway.chat(
            shown,
            session_id=sessions.wire_id(target),
            on_event=on_event,
        )
    except GatewayError as exc:
        write(f"error: {sanitize(exc)}\n")
        return
    payload = result.get("payload")
    body = payload if isinstance(payload, dict) else {}
    session_id = str(body.get("sessionId") or "")
    final = sanitize(body.get("text") or "", newlines=False)
    buffer.finish(final)
    for line in buffer.lines:
        sessions.append(target, f"prime: {line}")
    error = body.get("error")
    if error:
        visible = sanitize(error)
        write(f"error: {visible}\n")
        sessions.append(target, f"error: {visible}")
    if session_id:
        sessions.rename(target, session_id)
        write(f"session {sanitize(session_id, newlines=False)}\n")


def _announce(gateway: TuiGateway, write: Write) -> None:
    if not _ensure_connected(gateway, write):
        return
    try:
        items = gateway.list_approvals()
    except GatewayError as exc:
        write(f"error: {sanitize(exc)}\n")
        return
    if not items:
        write("no pending approvals\n")
        return
    for item in items:
        _write_card(item, write)


def _write_card(item: dict[str, object], write: Write) -> None:
    write(render_card(item) + "\n")


def _ensure_connected(gateway: TuiGateway, write: Write) -> bool:
    """Reconnect with the gateway backoff before the next send."""
    if gateway.connected:
        return True
    if gateway.try_reconnect():
        return True
    write("disconnected, retrying\n")
    return False


def _apply_decision(gateway: TuiGateway, approval_id: str, decision: str, write: Write) -> None:
    if not _ensure_connected(gateway, write):
        return
    try:
        state = gateway.decide(approval_id, decision)
    except (GatewayError, ValueError) as exc:
        write(f"error: {sanitize(exc)}\n")
        return
    write(f"decision {decision} {sanitize(approval_id, newlines=False)} ({state})\n")


def _write_sessions(sessions: SessionBook, write: Write) -> None:
    rows = sessions.rows()
    if not rows:
        write("no sessions\n")
        return
    for session_id, title in rows:
        mark = "*" if session_id == sessions.current else " "
        label = session_id or "new"
        write(f"{mark} {sanitize(label, newlines=False)}  {sanitize(title, newlines=False)}\n")


def _span(kind: str, payload: dict[str, object]) -> str:
    name = sanitize(payload.get("name") or "", newlines=False)
    phase = sanitize(payload.get("phase") or "", newlines=False)
    detail = sanitize(payload.get("detail") or "", newlines=False)
    return f"timeline: {kind} {name} {phase} {detail}".strip()


class _PrimeBuffer:
    """One ``prime:`` line per newline, and one more at the end of the turn."""

    def __init__(self, write: Write) -> None:
        self._write = write
        self._buf = ""
        self.lines: list[str] = []

    def add(self, chunk: str) -> None:
        self._buf += sanitize(chunk)
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            self._emit(line)

    def flush(self) -> None:
        """Print text that arrived before a tool or an approval card."""
        if self._buf:
            self._emit(self._buf)
            self._buf = ""

    def finish(self, final: str) -> None:
        if self._buf:
            self._emit(self._buf)
            self._buf = ""
        if not final:
            return
        if self.lines and final == "".join(self.lines):
            return
        if self.lines and final == self.lines[-1]:
            return
        if not self.lines:
            self._emit(final)

    def _emit(self, line: str) -> None:
        visible = sanitize(line, newlines=False)
        self.lines.append(visible)
        self._write(f"prime: {visible}\n")


class _Incoming:
    """Background reader. Decision lines can arrive while a turn blocks.

    ``/quit`` is queued and the thread returns, so a real tty does not sit
    in a second ``input()`` after the command.
    """

    def __init__(self, read_line: ReadLine) -> None:
        self._read_line = read_line
        self._queue: queue.Queue[str | None] = queue.Queue()
        self._buffer: list[str | None] = []
        self._closed = False
        self._thread = threading.Thread(target=self._run, name="praxis-tui-plain", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._closed = True

    def next_line(self) -> str | None:
        if self._buffer:
            return self._buffer.pop(0)
        return self._queue.get()

    def drain_decisions(self, gateway: TuiGateway, write: Write) -> None:
        while True:
            try:
                line = self._queue.get_nowait()
            except queue.Empty:
                return
            if line is None:
                self._buffer.append(None)
                continue
            parsed = decision_of(line)
            if parsed is None:
                self._buffer.append(line)
                continue
            _apply_decision(gateway, parsed[0], parsed[1], write)

    def _run(self) -> None:
        while not self._closed:
            try:
                line = self._read_line()
            except EOFError:
                self._queue.put(None)
                return
            self._queue.put(line)
            if isinstance(line, str) and line.strip() in {"/quit", "/exit"}:
                return
