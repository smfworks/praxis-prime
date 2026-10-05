"""Linear transcript for screen readers.

No full-screen layout, no box drawing, and no colour. New assistant text
and approval cards are plain lines. ``/approve``, ``/session-approve``, and
``/deny`` are the only decision commands. An empty line decides nothing.
"""

from __future__ import annotations

import queue
import threading
from collections.abc import Callable

from praxis_prime.approvals.card import format_approval_card
from praxis_prime.gateway.client import GatewayError
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
        "  /session-approve <id>     allow for this session",
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
        write(readiness.message + "\n")
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
        for item in timeline:
            write(item + "\n")
        return False
    if text.startswith("/session "):
        session_id = text.split(maxsplit=1)[1].strip()
        if not session_id:
            write("usage: /session <id>\n")
            return False
        sessions.switch(session_id)
        write(f"session {session_id}\n")
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
        write((blocked or "Chat is not available.") + "\n")
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
    sessions.note_user(text)
    target = sessions.current
    sessions.append(target, f"you: {text}")
    write(f"you: {text}\n")
    assistant = ""

    def on_event(payload: dict[str, object]) -> None:
        nonlocal assistant
        kind = str(payload.get("kind") or "")
        if kind == "text":
            chunk = str(payload.get("text") or "")
            if not chunk:
                return
            assistant += chunk
            write(f"prime: {chunk}\n")
            return
        if kind == "approval":
            approval = payload.get("approval")
            if isinstance(approval, dict):
                _write_card(approval, write)
                timeline.append(f"timeline: approval {approval.get('id', '')}")
            return
        if kind == "tool":
            line = _span("tool", payload)
            timeline.append(line)
            write(line + "\n")
            return
        if kind == "status":
            line = _span("status", payload)
            timeline.append(line)
            write(line + "\n")
            return
        if kind == "turn":
            line = f"timeline: turn {payload.get('phase', '')}".strip()
            timeline.append(line)

    try:
        result = gateway.chat(text, session_id=target or None, on_event=on_event)
    except GatewayError as exc:
        write(f"error: {exc}\n")
        return
    payload = result.get("payload")
    body = payload if isinstance(payload, dict) else {}
    session_id = str(body.get("sessionId") or "")
    final = str(body.get("text") or "")
    if assistant:
        sessions.append(target, f"prime: {assistant}")
    elif final:
        sessions.append(target, f"prime: {final}")
        write(f"prime: {final}\n")
    error = body.get("error")
    if error:
        write(f"error: {error}\n")
        sessions.append(target, f"error: {error}")
    if session_id:
        if target == "":
            sessions.adopt(session_id)
        elif session_id != target:
            sessions.switch(session_id)
        write(f"session {session_id}\n")


def _announce(gateway: TuiGateway, write: Write) -> None:
    try:
        items = gateway.list_approvals()
    except GatewayError as exc:
        write(f"error: {exc}\n")
        return
    if not items:
        write("no pending approvals\n")
        return
    for item in items:
        _write_card(item, write)


def _write_card(item: dict[str, object], write: Write) -> None:
    write(format_approval_card(item) + "\n")
    approval_id = str(item.get("id") or "")
    if approval_id:
        write(
            f"Commands: /approve {approval_id}  "
            f"/session-approve {approval_id}  /deny {approval_id}\n"
        )


def _apply_decision(gateway: TuiGateway, approval_id: str, decision: str, write: Write) -> None:
    try:
        state = gateway.decide(approval_id, decision)
    except (GatewayError, ValueError) as exc:
        write(f"error: {exc}\n")
        return
    write(f"decision {decision} {approval_id} ({state})\n")


def _write_sessions(sessions: SessionBook, write: Write) -> None:
    rows = sessions.rows()
    if not rows:
        write("no sessions\n")
        return
    for session_id, title in rows:
        mark = "*" if session_id == sessions.current else " "
        label = session_id or "new"
        write(f"{mark} {label}  {title}\n")


def _span(kind: str, payload: dict[str, object]) -> str:
    name = str(payload.get("name") or "")
    phase = str(payload.get("phase") or "")
    detail = str(payload.get("detail") or "")
    return f"timeline: {kind} {name} {phase} {detail}".strip()


class _Incoming:
    """Background reader. Decision lines can arrive while a turn blocks."""

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
