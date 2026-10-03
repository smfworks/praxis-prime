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
from praxis_prime.accounts.cli import account_command, add_account_parser
from praxis_prime.accounts.oidc_cli import add_oidc_parser, oidc_command
from praxis_prime.compliance.cli import add_compliance_parsers, dispatch_compliance
from praxis_prime.config import describe_write, resolve_config_dir, write_default_config
from praxis_prime.doctor import format_report, report_exit_code, run_system_doctor
from praxis_prime.mcp.cli import add_mcp_parser, mcp_command
from praxis_prime.packs.cli import add_packs_parsers, dispatch_packs
from praxis_prime.profiles.cli import add_profile_parser, profile_command
from praxis_prime.state import MigrationInProgress
from praxis_prime.user_commands import add_user_commands, dispatch_user_command


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except MigrationInProgress as exc:
        print(f"praxis-prime: {exc}", file=sys.stderr)
        return 2


def _main(argv: list[str] | None = None) -> int:
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
    if args.command == "decide":
        return _decide_command(args)
    if args.command == "mcp":
        return mcp_command(args)
    if args.command == "account":
        return account_command(args)
    if args.command == "oidc":
        return oidc_command(args)
    if args.command == "profile":
        return profile_command(args)
    handled = dispatch_packs(args)
    if handled is not None:
        return handled
    handled = dispatch_compliance(args)
    if handled is not None:
        return handled
    handled = dispatch_user_command(args)
    if handled is not None:
        return handled
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
    daemon_commands.add_parser(
        "rotate-token",
        help="Replace the loopback bearer token. Restart praxis-primed to use it.",
    )
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
    approval_list = approval_commands.add_parser(
        "list",
        help="List approvals waiting on the daemon.",
    )
    _add_approval_profile(approval_list)
    approve = approval_commands.add_parser("approve", help="Allow a pending approval.")
    approve.add_argument("approval_id")
    approve.add_argument(
        "--session",
        action="store_true",
        help="Allow this action for the rest of its session.",
    )
    _add_approval_profile(approve)
    deny = approval_commands.add_parser("deny", help="Deny a pending approval.")
    deny.add_argument("approval_id")
    _add_approval_profile(deny)

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

    decide = commands.add_parser(
        "decide",
        help="Ask the local Decision Engine. Does not call a hosted service.",
    )
    decide.add_argument("rest", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)

    telegram = commands.add_parser("telegram", help="Pair the Telegram bot with your chat.")
    telegram_commands = telegram.add_subparsers(dest="telegram_command")
    telegram_commands.add_parser(
        "pair",
        help="Print a one-time code. Send it to the bot as /pair CODE.",
    )
    add_account_parser(commands)
    add_oidc_parser(commands)
    add_profile_parser(commands)
    add_mcp_parser(commands)
    add_packs_parsers(commands)
    add_compliance_parsers(commands)
    add_user_commands(commands)
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
    parser.add_argument(
        "--profile",
        help="Profile id. A running daemon routes the turn to that profile's worker.",
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
                profile=getattr(args, "profile", "") or "",
            )
        finally:
            client.close()
    approver = terminal_approver(input, writer, color=color)
    try:
        runtime = _runtime_from_args(args, approver, build_runtime)
    except (ValueError, OSError, MigrationInProgress) as exc:
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
                profile=getattr(args, "profile", "") or "",
            )
        finally:
            client.close()
    if sys.stdin.isatty():
        approver = terminal_approver(input, err, color=color)
    else:
        approver = noninteractive_approver(err)
    try:
        runtime = _runtime_from_args(args, approver, build_runtime)
    except (ValueError, OSError, MigrationInProgress) as exc:
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
        profile=getattr(args, "profile", None) or None,
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
    if args.daemon_command == "rotate-token":
        from praxis_prime.gateway.auth import rotate_token
        from praxis_prime.gateway.discover import gateway_paths

        rotate_token(gateway_paths()[1])
        print("Replaced the loopback bearer token. Restart praxis-primed to use it.")
        print("The token was not printed. It stays in the runtime directory, mode 0600.")
        return 0
    print("usage: praxis-prime daemon {start|stop|status|logs|rotate-token}", file=sys.stderr)
    return 2


def _service_command(args: argparse.Namespace) -> int:
    from praxis_prime.service import install, uninstall

    if args.service_command == "install":
        return install()
    if args.service_command == "uninstall":
        return uninstall()
    print("usage: praxis-prime service {install|uninstall}", file=sys.stderr)
    return 2


def _add_approval_profile(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--profile",
        default="",
        help="Profile id. Omit to list every card this account can see.",
    )


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
            items = client.list_approvals(profile=args.profile)
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
        client.decide(args.approval_id, decision, profile=args.profile)
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
    except (ValueError, OSError, MigrationInProgress) as exc:
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


def _decide_command(args: argparse.Namespace) -> int:
    parts = list(args.rest)
    if parts and parts[0] == "--":
        parts = parts[1:]
    if not parts or parts[0] not in {"report", "feedback"}:
        parts = ["ask", *parts]
    parser = _decide_parser()
    try:
        parsed = parser.parse_args(parts)
    except SystemExit as exc:
        code = exc.code
        return 2 if code is None else int(code)
    if parsed.action == "report":
        return _decide_report(parsed)
    if parsed.action == "feedback":
        return _decide_feedback(parsed)
    return _decide_ask(parsed)


def _decide_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="praxis-prime decide")
    commands = parser.add_subparsers(dest="action", required=True)
    ask = commands.add_parser("ask")
    ask.add_argument("question", nargs="+")
    ask.add_argument("--options", default="", help="Comma-separated choices. Omit for yes/no.")
    ask.add_argument("--state", default="", help="Untrusted text the question is about.")
    ask.add_argument("--max-tier", type=int, default=None, help="Highest tier, 0 through 4.")
    ask.add_argument("--explain", action="store_true", help="Print the tier trace.")
    ask.add_argument("--config-dir")
    ask.add_argument("--data-dir")
    report = commands.add_parser("report", help="Print a reliability report and fit a calibrator.")
    report.add_argument("--config-dir")
    report.add_argument("--data-dir")
    feedback = commands.add_parser("feedback", help="Record whether a decision was correct.")
    feedback.add_argument("decision_id")
    feedback.add_argument("--correct", action="store_true")
    feedback.add_argument("--incorrect", action="store_true")
    feedback.add_argument(
        "--label",
        default="",
        help="Gold label. Marks the prediction right or wrong.",
    )
    feedback.add_argument("--config-dir")
    feedback.add_argument("--data-dir")
    return parser


def _decide_ask(args: argparse.Namespace) -> int:
    from praxis_prime.decide.schema import DecideError, simple_request

    question = " ".join(args.question).strip()
    options = [part.strip() for part in args.options.split(",") if part.strip()]
    try:
        request = simple_request(
            question,
            options=options,
            state=args.state,
            max_tier=args.max_tier,
        )
    except DecideError as exc:
        print(f"praxis-prime decide: {exc}", file=sys.stderr)
        return 2
    try:
        runtime = _decide_runtime(args)
    except (OSError, ValueError) as exc:
        print(f"praxis-prime decide: {exc}", file=sys.stderr)
        return 2
    try:
        response = runtime.engine.decide(request)
    except DecideError as exc:
        print(f"praxis-prime decide: {exc}", file=sys.stderr)
        return 2
    finally:
        runtime.close()
    answer = response.answers["q"]
    print(
        f"{answer.label}  tier T{answer.tier}  "
        f"confidence {answer.confidence:.2f}  id {response.decision_id}"
    )
    if args.explain:
        for line in answer.trace:
            print(line)
    if answer.escalate:
        print("escalate: true")
    return 0


def _decide_report(args: argparse.Namespace) -> int:
    from praxis_prime.decide.engine import fit_report

    try:
        runtime = _decide_runtime(args)
    except (OSError, ValueError) as exc:
        print(f"praxis-prime decide: {exc}", file=sys.stderr)
        return 2
    try:
        sys.stdout.write(fit_report(runtime.engine))
    finally:
        runtime.close()
    return 0


def _decide_feedback(args: argparse.Namespace) -> int:
    if args.correct and args.incorrect:
        print("praxis-prime decide: pass only one of --correct and --incorrect", file=sys.stderr)
        return 2
    if not args.correct and not args.incorrect and not args.label:
        print(
            "praxis-prime decide: pass --correct, --incorrect, or --label",
            file=sys.stderr,
        )
        return 2
    try:
        runtime = _decide_runtime(args)
    except (OSError, ValueError) as exc:
        print(f"praxis-prime decide: {exc}", file=sys.stderr)
        return 2
    try:
        correct = True if args.correct else False if args.incorrect else None
        changed = runtime.engine.labels.feedback(
            args.decision_id,
            correct=correct,
            gold=args.label or None,
        )
    finally:
        runtime.close()
    if changed == 0:
        print(f"praxis-prime decide: no decision {args.decision_id}", file=sys.stderr)
        return 2
    print(f"recorded feedback for {args.decision_id}")
    return 0


def _decide_runtime(args: argparse.Namespace):
    from praxis_prime.runtime import build_runtime

    config_path = Path(args.config_dir) / "config.toml" if args.config_dir else None
    data_path = Path(args.data_dir) / "prime.db" if args.data_dir else None
    return build_runtime(
        env=os.environ,
        config_path=config_path,
        data_path=data_path,
        cwd=Path.cwd(),
    )


def _config_command(explicit: str | None, *, force: bool) -> int:
    directory = resolve_config_dir(explicit)
    try:
        result = write_default_config(directory, force=force)
    except OSError as exc:
        print(f"praxis-prime config: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(describe_write(result))
    return 0
