"""``praxis-prime omarchy`` and the ``pprime`` alias.

Both console scripts call ``praxis_prime.cli:main``.
"""

from __future__ import annotations

import argparse
import sys

from praxis_prime.omarchy.install import install_omarchy, status_command, uninstall_omarchy


def add_omarchy_parser(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    omarchy = commands.add_parser(
        "omarchy",
        help="Install the Omarchy theme template and the Super+Alt+A keybind.",
    )
    sub = omarchy.add_subparsers(dest="omarchy_command")
    sub.add_parser(
        "status",
        help="Show detection, the template, the rendered file, and the keybind. Writes nothing.",
    )
    install = sub.add_parser(
        "install",
        help="Write the theme template and the keybind. Asks before each change.",
    )
    _add_install_flags(install, profile=True)
    remove = sub.add_parser(
        "uninstall",
        help="Remove the template and the keybind this command wrote.",
    )
    _add_install_flags(remove, profile=False)


def omarchy_command(args: argparse.Namespace) -> int:
    command = getattr(args, "omarchy_command", None)
    if command == "status":
        return status_command()
    if command == "install":
        return install_omarchy(
            theme=bool(args.theme),
            keybind=bool(args.keybind),
            yes=bool(args.yes),
            dry_run=bool(args.dry_run),
            profile=str(args.profile or ""),
            force=bool(args.force),
        )
    if command == "uninstall":
        return uninstall_omarchy(
            theme=bool(args.theme),
            keybind=bool(args.keybind),
            yes=bool(args.yes),
            dry_run=bool(args.dry_run),
            force=bool(args.force),
        )
    print("usage: praxis-prime omarchy {status|install|uninstall}", file=sys.stderr)
    return 2


def _add_install_flags(parser: argparse.ArgumentParser, *, profile: bool) -> None:
    parser.add_argument("--theme", action="store_true", help="Only the theme template.")
    parser.add_argument("--keybind", action="store_true", help="Only the keybind.")
    parser.add_argument("--yes", action="store_true", help="Apply without asking.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the steps and diffs. Write nothing.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Overwrite a different template, follow a symlink, or write bindings.lua "
            "when Omarchy was not detected."
        ),
    )
    if profile:
        parser.add_argument(
            "--profile",
            help="Select omarchy for this profile, the same as `theme set omarchy`.",
        )
