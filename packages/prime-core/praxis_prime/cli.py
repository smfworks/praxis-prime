"""Command line interface for Praxis Prime.

Console scripts: ``praxis-prime`` and the alias ``pprime``.

``chat`` and ``ask`` attach to a running ``praxis-primed`` when one is
healthy, and run the agent loop in this process otherwise. ``--local``
always stays in this process.

ARCHITECTURE §24 and §33.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from praxis_prime import __version__
from praxis_prime.config import describe_write, resolve_config_dir, write_default_config
from praxis_prime.doctor import format_report, report_exit_code, run_system_doctor


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        print(f"praxis-prime {__version__}")
        return 0
    if args.command == "doctor":
        checks = run_system_doctor()
        sys.stdout.write(format_report(checks))
        return report_exit_code(checks)
    if args.command == "config":
        return _config_command(args.config_dir, force=args.force)
    if args.command == "chat":
        return _chat_command(args)
    if args.command == "ask":
        return _ask_command(args)
    if args.command == "daemon":
        return _daemon_command(args)
    if args.command == "service":
        return _service_command(args)
    if args.command == "approvals":
        return _approvals_command(args)
    if args.command == "telegram":
        return _telegram_command(args)
    if args.command == "code":
        return _code_command(args)
    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="praxis-prime",
        description="Praxis Prime, a local-first autonomous AI agent for Linux (pre-alpha).",
    )
    parser.add_argument("--version", action="store_true", help="Print the version and exit.")
    commands = parser.add_subparsers(dest="command")

    commands.add_parser(
        "doctor",
        help="Check Python, OS (Ubuntu, Arch, or Omarchy), Wayland vs X11, and Ollama.",
    )

    config = commands.add_parser(
        "config",
        help="Write the default XDG config. Every compliance dial is off.",
    )
    config.add_argument(
        "--force",
        action="store_true",
        help="Overwrite config.toml and policy/profile.toml if they already exist.",
    )
    config.add_argument(
        "--config-dir",
        help=(
            "Directory to write. Defaults to $XDG_CONFIG_HOME/praxis-prime "
            "or ~/.config/praxis-prime."
        ),
    )

    chat = commands.add_parser(
        "chat",
        help="Interactive terminal chat with streaming, tools, and approvals.",
    )
    _add_runtime_args(chat)

    ask = commands.add_parser(
        "ask",
        help="Ask one question, print the answer, and exit.",
    )
    ask.add_argument("prompt", nargs="+", help="The question to ask.")
    _add_runtime_args(ask)

    daemon = commands.add_parser("daemon", help="Start, stop, or inspect praxis-primed.")
    daemon_commands = daemon.add_subparsers(dest="daemon_command")
    daemon_commands.add_parser("start", help="Start the daemon in the background.")
    daemon_commands.add_parser("stop", help="Ask the daemon to shut down.")
    daemon_commands.add_parser("status", help="Show whether the daemon is healthy.")
    logs = daemon_commands.add_parser("logs", help="Print recent daemon log lines.")
    logs.add_argument("--lines", type=int, default=80, help="How many lines to print.")

    service = commands.add_parser(
        "service",
        help="Install or remove the systemd --user unit (Ubuntu and Arch/Omarchy).",
    )
    service_commands = service.add_subparsers(dest="service_command")
    service_commands.add_parser("install", help="Write, enable, and start praxis-prime.service.")
    service_commands.add_parser("uninstall", help="Disable and remove praxis-prime.service.")

    approvals = commands.add_parser("approvals", help="List or decide pending approvals.")
    approval_commands = approvals.add_subparsers(dest="approvals_command")
    approval_commands.add_parser("list", help="List approvals waiting on the daemon.")
    approve = approval_commands.add_parser("approve", help="Allow a pending approval.")
    approve.add_argument("approval_id")
    approve.add_argument(
        "--session",
        action="store_true",
        help="Allow this action for the rest of its session.",
    )
    deny = approval_commands.add_parser("deny", help="Deny a pending approval.")
    deny.add_argument("approval_id")

    code = commands.add_parser(
        "code",
        help="Run a coding task in a git worktree. Your checkout is unchanged until you accept.",
    )
    code.add_argument("task", nargs="+", help="What the coding agent should do.")
    code.add_argument("--repo", help="Git repository. Defaults to the current directory.")
    code.add_argument("--accept", action="store_true", help="Merge the task branch locally.")
    code.add_argument("--discard", action="store_true", help="Delete the task branch.")
    code.add_argument("--keep", action="store_true", help="Leave the task branch. Do not merge it.")
    _add_runtime_args(code)

    telegram = commands.add_parser("telegram", help="Pair the Telegram bot with your chat.")
    telegram_commands = telegram.add_subparsers(dest="telegram_command")
    telegram_commands.add_parser(
        "pair",
        help="Print a one-time code. Send it to the bot as /pair CODE.",
    )
    return parser


def _add_runtime_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--model", help="Model spec, for example ollama:qwen3:8b.")
    parser.add_argument("--session", help="Resume a session id from the local database.")
    parser.add_argument(
        "--config-dir",
        help="Config directory. Defaults to the XDG config path.",
    )
    parser.add_argument(
        "--data-dir",
        help="Data directory for prime.db. Defaults to the XDG data path.",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Run in this process even when a daemon is already running.",
    )


def _chat_command(args: argparse.Namespace) -> int:
    from praxis_prime.repl import run_remote_repl, run_repl, stdout_writer, terminal_approver
    from praxis_prime.runtime import build_runtime

    color = _use_color(sys.stdout)
    writer = stdout_writer()
    endpoint = _endpoint_for(args)
    if endpoint is not None:
        from praxis_prime.gateway.client import GatewayClient, GatewayError

        print(
            f"attached to praxis-primed at {endpoint.host}:{endpoint.port}",
            file=sys.stderr,
        )
        try:
            client = GatewayClient.connect(endpoint)
        except (OSError, GatewayError, TimeoutError) as exc:
            print(f"praxis-prime chat: {exc}", file=sys.stderr)
            return 1
        try:
            return run_remote_repl(
                client,
                read_line=input,
                write=writer,
                color=color,
                interactive=sys.stdin.isatty(),
            )
        finally:
            client.close()
    approver = terminal_approver(input, writer, color=color)
    try:
        runtime = _runtime_from_args(args, approver, build_runtime)
    except (ValueError, OSError) as exc:
        print(f"praxis-prime chat: {exc}", file=sys.stderr)
        return 2
    try:
        return run_repl(
            runtime,
            read_line=input,
            write=writer,
            session_id=args.session,
            color=color,
        )
    finally:
        runtime.close()


def _ask_command(args: argparse.Namespace) -> int:
    from praxis_prime.repl import (
        noninteractive_approver,
        run_ask,
        run_remote_ask,
        stdout_writer,
        terminal_approver,
        tty_decider,
    )
    from praxis_prime.runtime import build_runtime

    prompt = " ".join(args.prompt).strip()
    if not prompt:
        print("praxis-prime ask: prompt is empty", file=sys.stderr)
        return 2
    err = stdout_writer(sys.stderr)
    color = _use_color(sys.stderr)
    endpoint = _endpoint_for(args)
    if endpoint is not None:
        from praxis_prime.gateway.client import GatewayClient, GatewayError

        print(
            f"attached to praxis-primed at {endpoint.host}:{endpoint.port}",
            file=sys.stderr,
        )
        try:
            client = GatewayClient.connect(endpoint)
        except (OSError, GatewayError, TimeoutError) as exc:
            print(f"praxis-prime ask: {exc}", file=sys.stderr)
            return 1
        try:
            decider = tty_decider(err) if sys.stdin.isatty() else None
            return run_remote_ask(
                client,
                prompt,
                write_out=stdout_writer(),
                write_err=err,
                color=color,
                decider=decider,
                session_id=args.session,
            )
        finally:
            client.close()
    if sys.stdin.isatty():
        approver = terminal_approver(input, err, color=color)
    else:
        approver = noninteractive_approver(err)
    try:
        runtime = _runtime_from_args(args, approver, build_runtime)
    except (ValueError, OSError) as exc:
        print(f"praxis-prime ask: {exc}", file=sys.stderr)
        return 2
    try:
        return run_ask(
            prompt,
            runtime,
            write_out=stdout_writer(),
            write_err=err,
            session_id=args.session,
            color=color,
        )
    finally:
        runtime.close()


def _runtime_from_args(args: argparse.Namespace, approver: object, builder: object):
    config_path = None
    if args.config_dir:
        config_path = Path(args.config_dir) / "config.toml"
    data_path = None
    if args.data_dir:
        data_path = Path(args.data_dir) / "prime.db"
    build = builder
    return build(
        approver=approver,
        model=args.model,
        config_path=config_path,
        data_path=data_path,
        cwd=Path.cwd(),
    )


def _use_color(stream: object) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def _endpoint_for(args: argparse.Namespace):
    if getattr(args, "local", False) or args.config_dir or args.data_dir:
        return None
    from praxis_prime.gateway.discover import discover

    return discover()


def _daemon_command(args: argparse.Namespace) -> int:
    from praxis_prime.daemon import show_logs, start_detached, status, stop_running

    if args.daemon_command == "start":
        return start_detached()
    if args.daemon_command == "stop":
        return stop_running()
    if args.daemon_command == "status":
        return status()
    if args.daemon_command == "logs":
        count = args.lines if isinstance(args.lines, int) and args.lines > 0 else 80
        return show_logs(count)
    print("usage: praxis-prime daemon {start|stop|status|logs}", file=sys.stderr)
    return 2


def _service_command(args: argparse.Namespace) -> int:
    from praxis_prime.service import install, uninstall

    if args.service_command == "install":
        return install()
    if args.service_command == "uninstall":
        return uninstall()
    print("usage: praxis-prime service {install|uninstall}", file=sys.stderr)
    return 2


def _approvals_command(args: argparse.Namespace) -> int:
    from praxis_prime.approvals.card import format_approval_card
    from praxis_prime.gateway.client import GatewayClient, GatewayError
    from praxis_prime.gateway.discover import discover

    if args.approvals_command not in {"list", "approve", "deny"}:
        print("usage: praxis-prime approvals {list|approve|deny}", file=sys.stderr)
        return 2
    endpoint = discover()
    if endpoint is None:
        print("praxis-primed is not running", file=sys.stderr)
        return 1
    try:
        client = GatewayClient.connect(endpoint)
    except (OSError, GatewayError, TimeoutError) as exc:
        print(f"praxis-prime approvals: {exc}", file=sys.stderr)
        return 1
    try:
        if args.approvals_command == "list":
            items = client.list_approvals()
            if not items:
                print("no pending approvals")
                return 0
            for item in items:
                print(format_approval_card(item))
                print()
            return 0
        decision = "allow_session" if args.approvals_command == "approve" and args.session else ""
        if args.approvals_command == "approve" and not decision:
            decision = "allow_once"
        if args.approvals_command == "deny":
            decision = "deny"
        client.decide(args.approval_id, decision)
    except GatewayError as exc:
        print(f"praxis-prime approvals: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()
    print(f"{decision} {args.approval_id}")
    return 0


def _telegram_command(args: argparse.Namespace) -> int:
    from praxis_prime.channels.telegram import PairingStore
    from praxis_prime.paths import data_dir, state_dir

    if args.telegram_command != "pair":
        print("usage: praxis-prime telegram pair", file=sys.stderr)
        return 2
    store = PairingStore(
        state_dir() / "telegram-pairing.json",
        data_dir() / "telegram-owner.json",
    )
    code = store.issue()
    print("Send this to your Praxis Prime bot within 10 minutes:")
    print(f"/pair {code}")
    print("Only the chat that sends the code becomes the owner.")
    print("The code was not written to config.toml.")
    return 0


def _code_command(args: argparse.Namespace) -> int:
    from praxis_prime.coding.worktree import CodingError
    from praxis_prime.repl import noninteractive_approver, stdout_writer, terminal_approver
    from praxis_prime.runtime import build_runtime

    chosen = [name for name in ("accept", "discard", "keep") if getattr(args, name)]
    if len(chosen) > 1:
        print("praxis-prime code: choose only one of --accept, --discard, --keep", file=sys.stderr)
        return 2
    disposition = chosen[0] if chosen else None
    interactive = disposition is None and sys.stdin.isatty()
    err = stdout_writer(sys.stderr)
    out = stdout_writer()
    color = _use_color(sys.stdout)
    if sys.stdin.isatty():
        approver = terminal_approver(input, err, color=color)
    else:
        approver = noninteractive_approver(err)
    try:
        runtime = _runtime_from_args(args, approver, build_runtime)
    except (ValueError, OSError) as exc:
        print(f"praxis-prime code: {exc}", file=sys.stderr)
        return 2
    if args.repo:
        runtime.cwd = Path(args.repo)
    from praxis_prime.coding.session import run_coding_task

    try:
        result = run_coding_task(
            " ".join(args.task),
            runtime,
            repo=Path(args.repo) if args.repo else None,
            disposition=disposition,
            read_line=input,
            write=out,
            interactive=interactive,
            color=color,
        )
    except CodingError as exc:
        print(f"praxis-prime code: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n(interrupted)", file=sys.stderr)
        return 130
    finally:
        runtime.close()
    return 0 if result.ok else 1


def _config_command(explicit: str | None, *, force: bool) -> int:
    directory = resolve_config_dir(explicit)
    try:
        result = write_default_config(directory, force=force)
    except OSError as exc:
        print(f"praxis-prime config: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(describe_write(result))
    return 0
