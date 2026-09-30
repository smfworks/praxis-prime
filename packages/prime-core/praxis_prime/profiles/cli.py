"""``praxis-prime profile`` commands.

docs/blueprint-addendum-2026-09.md §6.3.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from praxis_prime.accounts.db import AccountError, AccountStore
from praxis_prime.accounts.roles import PROFILE_ROLES
from praxis_prime.paths import data_dir
from praxis_prime.profiles.home import create_profile, list_profiles


def add_profile_parser(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    profile = commands.add_parser("profile", help="Create profiles and assign members.")
    sub = profile.add_subparsers(dest="profile_command")
    create = sub.add_parser("create", help="Create an empty profile directory.")
    create.add_argument("name")
    create.add_argument("--display-name", default="")
    create.add_argument("--data-dir")
    listing = sub.add_parser("list", help="List profile ids.")
    listing.add_argument("--data-dir")
    assign = sub.add_parser("assign", help="Grant an account a role on a profile.")
    assign.add_argument("name")
    assign.add_argument("--account", required=True)
    assign.add_argument("--role", required=True, choices=PROFILE_ROLES)
    assign.add_argument("--data-dir")


def profile_command(args: argparse.Namespace) -> int:
    command = getattr(args, "profile_command", None)
    if command == "create":
        return _create(args)
    if command == "list":
        return _list(args)
    if command == "assign":
        return _assign(args)
    print("usage: praxis-prime profile {create|list|assign}", file=sys.stderr)
    return 2


def _create(args: argparse.Namespace) -> int:
    try:
        home = create_profile(_data(args), args.name, display_name=args.display_name)
    except ValueError as exc:
        print(f"praxis-prime profile: {exc}", file=sys.stderr)
        return 2
    print(f"created profile {home.profile_id}")
    return 0


def _list(args: argparse.Namespace) -> int:
    names = list_profiles(_data(args))
    if not names:
        print("no profiles")
        return 0
    for name in names:
        print(name)
    return 0


def _assign(args: argparse.Namespace) -> int:
    root = _data(args)
    if args.name not in list_profiles(root):
        print(f"praxis-prime profile: no profile {args.name}", file=sys.stderr)
        return 2
    store = AccountStore(root / "accounts.db")
    account = store.get_username(args.account)
    if account is None:
        print("praxis-prime profile: no such account", file=sys.stderr)
        return 2
    try:
        store.set_membership(account.id, args.name, args.role)
    except AccountError as exc:
        print(f"praxis-prime profile: {exc}", file=sys.stderr)
        return 2
    print(f"assigned {account.username} as {args.role} on {args.name}")
    return 0


def _data(args: argparse.Namespace) -> Path:
    explicit = getattr(args, "data_dir", None)
    if explicit:
        return Path(explicit)
    return data_dir()
