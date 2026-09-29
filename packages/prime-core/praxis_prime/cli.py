"""Command line interface for Praxis Prime.

Console scripts: ``praxis-prime`` and the alias ``pprime``.

``chat`` and ``ask`` run the agent loop in this process. The daemon entry
point stays in ``praxis_prime.daemon`` and does not listen.

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


def _chat_command(args: argparse.Namespace) -> int:
    from praxis_prime.repl import run_repl, stdout_writer, terminal_approver
    from praxis_prime.runtime import build_runtime

    color = _use_color(sys.stdout)
    writer = stdout_writer()
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
        stdout_writer,
        terminal_approver,
    )
    from praxis_prime.runtime import build_runtime

    prompt = " ".join(args.prompt).strip()
    if not prompt:
        print("praxis-prime ask: prompt is empty", file=sys.stderr)
        return 2
    err = stdout_writer(sys.stderr)
    color = _use_color(sys.stderr)
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


def _config_command(explicit: str | None, *, force: bool) -> int:
    directory = resolve_config_dir(explicit)
    try:
        result = write_default_config(directory, force=force)
    except OSError as exc:
        print(f"praxis-prime config: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(describe_write(result))
    return 0
