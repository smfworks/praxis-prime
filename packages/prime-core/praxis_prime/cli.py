"""Command line interface for Praxis Prime.

Console scripts: ``praxis-prime`` and the alias ``pprime``.

TODO: ARCHITECTURE §24 and §33. Typer can replace argparse when the command
surface grows. The daemon entry point lives in ``praxis_prime.daemon``.
"""

from __future__ import annotations

import argparse
import sys

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
    return parser


def _config_command(explicit: str | None, *, force: bool) -> int:
    directory = resolve_config_dir(explicit)
    try:
        result = write_default_config(directory, force=force)
    except OSError as exc:
        print(f"praxis-prime config: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(describe_write(result))
    return 0
