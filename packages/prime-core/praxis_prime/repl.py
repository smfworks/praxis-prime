"""Terminal chat and one-shot ask.

Streaming text, a tool timeline, and inline approvals. Ctrl-C during a turn
cancels that turn. Ctrl-D leaves the chat.
"""

from __future__ import annotations

import select
import sys
from collections.abc import Callable
from pathlib import Path

from praxis_prime import __version__
from praxis_prime.approvals.card import format_approval_card
from praxis_prime.approvals.gate import ApprovalDecision, ApprovalRequest
from praxis_prime.gateway.client import GatewayClient, GatewayError
from praxis_prime.loop.control import TurnControl
from praxis_prime.loop.events import StatusEvent, TurnEnded
from praxis_prime.router.types import TextDelta
from praxis_prime.runtime import Runtime

ReadLine = Callable[[str], str]
Write = Callable[[str], None]

HELP = """\
/help                 show this help
/model                show the active model and fallbacks
/model <spec>         switch model, for example /model ollama:qwen3:8b
/clear                start a fresh session
/code <task>          coding mode: worktree, diff, then accept, discard, or keep
/quit                 leave the chat

Ctrl-C                cancel the current turn
Ctrl-D                leave the chat

Approvals, when a tool needs one:
  y or yes            allow once
  n or no             deny
  a or always         allow this exact action for the rest of the session
"""


class Renderer:
    """Print assistant text and the plan → check → act timeline."""

    def __init__(self, write: Write, *, color: bool) -> None:
        self.write = write
        self.color = color
        self._in_text = False

    def event(self, event: object) -> None:
        if isinstance(event, TextDelta):
            if not self._in_text:
                self.write("\n" + _paint("praxis", "36", self.color) + "\n")
                self._in_text = True
            self.write(event.text)
            return
        if self._in_text:
            self.write("\n")
            self._in_text = False
        if isinstance(event, StatusEvent):
            self.write(format_status(event, color=self.color) + "\n")
        elif isinstance(event, TurnEnded) and event.cancelled:
            self.write(_paint("  (turn cancelled)", "33", self.color) + "\n")

    def close_text(self) -> None:
        if self._in_text:
            self.write("\n")
            self._in_text = False


def format_status(event: StatusEvent, *, color: bool) -> str:
    label = {"plan": "plan", "check": "check", "act": "act", "result": "result"}.get(
        event.phase,
        event.phase,
    )
    tone = {"plan": "2", "check": "33", "act": "36", "result": "32"}.get(event.phase, "2")
    if "denied" in event.detail or "deny" in event.detail:
        tone = "31"
    return "  " + _paint(f"{label:<6}", tone, color) + " " + event.detail


def format_approval(request: ApprovalRequest, *, color: bool) -> str:
    lines = [
        "",
        _paint("approval needed", "33", color),
        f"  tool:    {request.tool}",
        f"  risk:    {request.risk.value}",
        f"  why:     {request.reason}",
        f"  sandbox: {'bubblewrap' if request.sandboxed else 'host (no bubblewrap)'}",
        f"  action:  {request.summary}",
    ]
    if request.mount:
        lines.append(f"  mount:   {request.mount}")
    lines.extend(
        [
            "  y once    n deny    a always for this session",
            "",
        ]
    )
    return "\n".join(lines)


def terminal_approver(
    read_line: ReadLine,
    write: Write,
    *,
    color: bool,
) -> Callable[[ApprovalRequest], ApprovalDecision]:
    def approve(request: ApprovalRequest) -> ApprovalDecision:
        write(format_approval(request, color=color))
        while True:
            try:
                answer = read_line("allow? [y/n/a] ").strip().lower()
            except EOFError:
                write("\n")
                return ApprovalDecision.DENY
            if answer in {"y", "yes"}:
                return ApprovalDecision.ALLOW_ONCE
            if answer in {"n", "no", ""}:
                return ApprovalDecision.DENY
            if answer in {"a", "always", "always-for-session"}:
                return ApprovalDecision.ALLOW_SESSION
            write("Answer y, n, or a.\n")

    return approve


def noninteractive_approver(write: Write) -> Callable[[ApprovalRequest], ApprovalDecision]:
    def approve(request: ApprovalRequest) -> ApprovalDecision:
        write(
            f"denied {request.tool} ({request.risk.value}): {request.reason}. "
            "No interactive approval is available.\n"
        )
        return ApprovalDecision.DENY

    return approve


def run_repl(
    runtime: Runtime,
    *,
    read_line: ReadLine,
    write: Write,
    session_id: str | None = None,
    color: bool = False,
) -> int:
    try:
        active_id, loop = runtime.open_loop(session_id)
    except LookupError as exc:
        write(f"praxis-prime chat: {exc}\n")
        return 1
    write(_banner(runtime.router.primary.spec(), active_id))
    while True:
        try:
            line = read_line("you> ")
        except EOFError:
            write("\n")
            return 0
        except KeyboardInterrupt:
            write("\n")
            return 0
        command = line.strip()
        if not command:
            continue
        if command in {"/quit", "/exit"}:
            return 0
        if command == "/help":
            write(HELP)
            continue
        if command == "/model":
            chain = ", ".join(ref.spec() for ref in runtime.router.chain)
            write(f"model {runtime.router.primary.spec()}\nfallbacks {chain}\n")
            continue
        if command.startswith("/model "):
            spec = command.split(None, 1)[1].strip()
            try:
                chosen = runtime.set_model(spec)
            except ValueError as exc:
                write(f"{exc}\n")
                continue
            runtime.store.set_model(active_id, chosen)
            write(f"model {chosen}\n")
            continue
        if command == "/clear":
            runtime.gate.clear()
            active_id, loop = runtime.open_loop(None)
            write(f"new session {active_id}\n")
            continue
        if command == "/code" or command.startswith("/code "):
            _run_code_command(command, runtime, read_line=read_line, write=write, color=color)
            continue
        if command.startswith("/"):
            write("Unknown command. Type /help.\n")
            continue
        control = TurnControl()
        renderer = Renderer(write, color=color)
        try:
            for event in loop.run_turn(command, control):
                renderer.event(event)
        except KeyboardInterrupt:
            control.cancel()
            renderer.close_text()
            write("\n  (turn cancelled)\n")
            continue
        renderer.close_text()
        write("\n")
    return 0


def run_ask(
    prompt: str,
    runtime: Runtime,
    *,
    write_out: Write,
    write_err: Write,
    session_id: str | None = None,
    color: bool = False,
) -> int:
    try:
        active_id, loop = runtime.open_loop(session_id)
    except LookupError as exc:
        write_err(f"praxis-prime ask: {exc}\n")
        return 1
    write_err(f"session {active_id}\n")
    control = TurnControl()
    error: str | None = None
    cancelled = False
    try:
        for event in loop.run_turn(prompt, control):
            if isinstance(event, TextDelta):
                write_out(event.text)
            elif isinstance(event, StatusEvent):
                write_err(format_status(event, color=color) + "\n")
            elif isinstance(event, TurnEnded):
                error = event.error
                cancelled = event.cancelled
    except KeyboardInterrupt:
        write_err("\n(turn cancelled)\n")
        return 130
    write_out("\n")
    if cancelled:
        write_err("(turn cancelled)\n")
        return 130
    if error:
        return 1
    return 0


def _run_code_command(
    command: str,
    runtime: Runtime,
    *,
    read_line: ReadLine,
    write: Write,
    color: bool,
) -> None:
    """``/code <task>`` runs in a worktree and then asks accept, discard, or keep."""
    del color
    task = command[5:].strip()
    if not task:
        write(
            "Usage: /code <task>\n"
            "The task runs on a prime/<slug> branch. "
            "Your checkout is unchanged until you accept.\n"
        )
        return
    from praxis_prime.coding.session import run_coding_task
    from praxis_prime.coding.worktree import CodingError

    try:
        run_coding_task(
            task,
            runtime,
            read_line=read_line,
            write=write,
            interactive=True,
        )
    except CodingError as exc:
        write(f"praxis-prime code: {exc}\n")


def stdout_writer(stream: object | None = None) -> Write:
    target = sys.stdout if stream is None else stream

    def write(text: str) -> None:
        target.write(text)
        target.flush()

    return write


def _banner(model: str, session_id: str) -> str:
    return (
        f"Praxis Prime {__version__}\n"
        f"model {model}\n"
        f"session {session_id}\n"
        "Type /help for commands. Ctrl-C cancels a turn. Ctrl-D exits.\n\n"
    )


def _paint(text: str, code: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"\033[{code}m{text}\033[0m"


def run_remote_repl(
    client: GatewayClient,
    *,
    read_line: ReadLine,
    write: Write,
    color: bool = False,
    interactive: bool = False,
) -> int:
    """Chat through a running daemon. Approvals can be answered here or elsewhere."""
    try:
        body = client.status()
    except GatewayError as exc:
        write(f"praxis-prime chat: {exc}\n")
        return 1
    model = str(body.get("model", ""))
    write(_banner(model, "daemon"))
    session_id: str | None = None
    while True:
        try:
            line = read_line("you> ")
        except EOFError:
            write("\n")
            return 0
        except KeyboardInterrupt:
            write("\n")
            return 0
        command = line.strip()
        if not command:
            continue
        if command in {"/quit", "/exit"}:
            return 0
        if command == "/help":
            write(HELP)
            continue
        if command == "/model":
            try:
                current = client.status()
            except GatewayError as exc:
                write(f"{exc}\n")
                continue
            write(f"model {current.get('model', '')}\n")
            continue
        if command.startswith("/model "):
            spec = command.split(None, 1)[1].strip()
            try:
                chosen = client.set_model(spec)
            except GatewayError as exc:
                write(f"{exc}\n")
                continue
            write(f"model {chosen}\n")
            continue
        if command == "/clear":
            if session_id:
                try:
                    client.drop_session(session_id)
                except GatewayError as exc:
                    write(f"{exc}\n")
            session_id = None
            write("new session\n")
            continue
        if command == "/code" or command.startswith("/code "):
            write("coding mode runs in this process so the worktree stays on this machine.\n")
            from praxis_prime.runtime import build_runtime

            local = build_runtime(
                approver=terminal_approver(read_line, write, color=color),
                cwd=Path.cwd(),
            )
            try:
                _run_code_command(command, local, read_line=read_line, write=write, color=color)
            finally:
                local.close()
            continue
        if command.startswith("/"):
            write("Unknown command. Type /help.\n")
            continue
        decider = tty_decider(write) if interactive else None
        try:
            result = client.chat(
                command,
                session_id=session_id,
                on_event=lambda payload: _render_remote(payload, write, color=color),
                decider=decider,
            )
        except KeyboardInterrupt:
            write("\n  (interrupt)\n")
            continue
        except GatewayError as exc:
            write(f"{exc}\n")
            continue
        payload = result.get("payload")
        if isinstance(payload, dict) and isinstance(payload.get("sessionId"), str):
            session_id = payload["sessionId"]
        write("\n")


def run_remote_ask(
    client: GatewayClient,
    prompt: str,
    *,
    write_out: Write,
    write_err: Write,
    color: bool = False,
    decider: Callable[[dict[str, object]], str | None] | None = None,
    session_id: str | None = None,
) -> int:
    try:
        result = client.chat(
            prompt,
            session_id=session_id,
            on_event=lambda payload: _render_remote_ask(payload, write_out, write_err, color=color),
            decider=decider,
        )
    except KeyboardInterrupt:
        write_err("\n(turn cancelled)\n")
        return 130
    except GatewayError as exc:
        write_err(f"{exc}\n")
        return 1
    write_out("\n")
    payload = result.get("payload")
    if isinstance(payload, dict):
        if payload.get("cancelled"):
            write_err("(turn cancelled)\n")
            return 130
        if payload.get("error"):
            write_err(str(payload["error"]) + "\n")
            return 1
    return 0


def tty_decider(write: Write) -> Callable[[dict[str, object]], str | None]:
    """Non-blocking y/n/a prompt. Returns None until the user answers."""
    state = {"id": "", "prompted": False}

    def decide(approval: dict[str, object]) -> str | None:
        approval_id = str(approval.get("id", ""))
        if state["id"] != approval_id:
            state["id"] = approval_id
            state["prompted"] = False
        if not state["prompted"]:
            write("allow? [y/n/a] ")
            state["prompted"] = True
        if not _stdin_ready():
            return None
        try:
            answer = sys.stdin.readline()
        except KeyboardInterrupt:
            return "deny"
        return _parse_allow(answer.strip().lower(), write)

    return decide


def _parse_allow(answer: str, write: Write) -> str | None:
    if answer in {"y", "yes"}:
        return "allow_once"
    if answer in {"a", "always", "always-for-session"}:
        return "allow_session"
    if answer in {"n", "no", ""}:
        return "deny"
    write("Answer y, n, or a.\n")
    return None


def _stdin_ready() -> bool:
    if sys.stdin.closed:
        return False
    try:
        ready, _, _ = select.select([sys.stdin], [], [], 0)
    except (OSError, ValueError):
        return False
    return bool(ready)


def _render_remote(payload: dict[str, object], write: Write, *, color: bool) -> None:
    kind = payload.get("kind")
    if kind == "text":
        write(str(payload.get("text", "")))
        return
    if kind == "status":
        event = StatusEvent(str(payload.get("phase", "")), str(payload.get("detail", "")))
        write(format_status(event, color=color) + "\n")
        return
    if kind == "approval":
        approval = payload.get("approval")
        if isinstance(approval, dict):
            write("\n" + format_approval_card(approval) + "\n")


def _render_remote_ask(
    payload: dict[str, object],
    write_out: Write,
    write_err: Write,
    *,
    color: bool,
) -> None:
    kind = payload.get("kind")
    if kind == "text":
        write_out(str(payload.get("text", "")))
        return
    if kind == "status":
        event = StatusEvent(str(payload.get("phase", "")), str(payload.get("detail", "")))
        write_err(format_status(event, color=color) + "\n")
        return
    if kind == "approval":
        approval = payload.get("approval")
        if isinstance(approval, dict):
            write_err(format_approval_card(approval) + "\n")
