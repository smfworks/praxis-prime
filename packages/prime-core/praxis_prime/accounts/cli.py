"""``praxis-prime account`` commands.

``create`` on an empty database is the first-run owner bootstrap. It also
migrates single-user state into the ``default`` profile. Passwords are read
from stdin, never from an argument.

docs/blueprint-addendum-2026-09.md §6.2 and §6.3.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from praxis_prime.accounts.db import Account, AccountError, AccountStore
from praxis_prime.accounts.roles import SERVER_ROLES
from praxis_prime.audit.log import AuditLog
from praxis_prime.paths import config_dir, data_dir
from praxis_prime.profiles.migrate import MigrationBusy, daemon_is_running, migrate_single_user
from praxis_prime.state import StateDB
from praxis_prime.statfile import StatKind, lstat_kind


def add_account_parser(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    account = commands.add_parser("account", help="Create and inspect local accounts.")
    sub = account.add_subparsers(dest="account_command")
    create = sub.add_parser("create", help="Create an account. The first one is the owner.")
    create.add_argument("username")
    create.add_argument("--display-name", default="", help="Name shown in the audit log.")
    create.add_argument("--role", default="operator", choices=SERVER_ROLES)
    create.add_argument("--email", default="")
    create.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read one password line from stdin. It is not a command argument.",
    )
    _add_dirs(create)
    listing = sub.add_parser("list", help="List accounts. Password hashes are not printed.")
    _add_dirs(listing)
    passwd = sub.add_parser("passwd", help="Set a new password and clear a lockout.")
    passwd.add_argument("username")
    passwd.add_argument("--password-stdin", action="store_true")
    _add_dirs(passwd)
    transfer = sub.add_parser(
        "transfer-owner",
        help="Hand the owner role to an existing admin. The previous owner becomes admin.",
    )
    transfer.add_argument("username")
    _add_dirs(transfer)
    disable = sub.add_parser("disable", help="Disable an account and revoke its sessions.")
    disable.add_argument("username")
    _add_dirs(disable)
    role = sub.add_parser("role", help="Change a server role and revoke that account's sessions.")
    role.add_argument("username")
    role.add_argument(
        "--role",
        required=True,
        choices=tuple(item for item in SERVER_ROLES if item != "owner"),
    )
    _add_dirs(role)


def account_command(args: argparse.Namespace) -> int:
    command = getattr(args, "account_command", None)
    if command == "create":
        return _create(args)
    if command == "list":
        return _list(args)
    if command == "passwd":
        return _passwd(args)
    if command == "transfer-owner":
        return _transfer_owner(args)
    if command == "disable":
        return _disable(args)
    if command == "role":
        return _set_role(args)
    print(
        "usage: praxis-prime account {create|list|passwd|transfer-owner|disable|role}",
        file=sys.stderr,
    )
    return 2


def _create(args: argparse.Namespace) -> int:
    password = _read_password(args, confirm=True)
    if password is None:
        return 2
    store = _store(args)
    try:
        if not store.has_accounts():
            if daemon_is_running():
                print(
                    "praxis-prime account: stop praxis-primed before the first account",
                    file=sys.stderr,
                )
                return 2
            account = store.create_account(
                username_text=args.username,
                password=password,
                display_name=args.display_name or args.username,
                role="owner",
                email=args.email,
            )
            result = migrate_single_user(
                _data(args),
                _config(args),
                owner_account=account.id,
            )
            store.set_membership(account.id, result.profile_id, "owner")
            print(f"created owner {account.username} ({account.id})")
            print(f"profile {result.profile_id}")
            if result.backup:
                print(f"backup {result.backup}")
            return 0
        account = store.create_account(
            username_text=args.username,
            password=password,
            display_name=args.display_name or args.username,
            role=args.role,
            email=args.email,
        )
    except MigrationBusy as exc:
        print(f"praxis-prime account: {exc}", file=sys.stderr)
        return 2
    except AccountError as exc:
        print(f"praxis-prime account: {exc}", file=sys.stderr)
        return 2
    print(f"created {account.role} {account.username} ({account.id})")
    return 0


def _list(args: argparse.Namespace) -> int:
    accounts = _store(args).list_accounts()
    if not accounts:
        print("no accounts")
        return 0
    for account in accounts:
        print(f"{account.id}  {account.username}  {account.role}  {account.status}")
    return 0


def _passwd(args: argparse.Namespace) -> int:
    password = _read_password(args, confirm=True)
    if password is None:
        return 2
    try:
        account = _store(args).set_password(args.username, password)
    except AccountError as exc:
        print(f"praxis-prime account: {exc}", file=sys.stderr)
        return 2
    print(f"updated password for {account.username}")
    return 0


def _disable(args: argparse.Namespace) -> int:
    try:
        account = _store(args).disable_account(args.username)
    except AccountError as exc:
        print(f"praxis-prime account: {exc}", file=sys.stderr)
        return 2
    print(f"disabled {account.username}")
    return 0


def _set_role(args: argparse.Namespace) -> int:
    try:
        account = _store(args).set_server_role(args.username, args.role)
    except AccountError as exc:
        print(f"praxis-prime account: {exc}", file=sys.stderr)
        return 2
    print(f"{account.username} is now {account.role}")
    return 0


def _transfer_owner(args: argparse.Namespace) -> int:
    store = _store(args)
    try:
        former, current = store.transfer_owner(args.username)
    except AccountError as exc:
        print(f"praxis-prime account: {exc}", file=sys.stderr)
        return 2
    finally:
        store.close()
    _audit_transfer(_data(args), former, current)
    print(f"owner is now {current.username} ({current.id})")
    print(f"previous owner {former.username} is admin")
    return 0


def _audit_transfer(root: Path, former: Account, current: Account) -> None:
    """Append one hash-chained event. No password or token is included."""
    profile_db = root / "profiles" / "default" / "prime.db"
    kind = lstat_kind(profile_db)
    if kind in {StatKind.SYMLINK, StatKind.UNREADABLE}:
        print(
            "praxis-prime account: profile database cannot be opened for the audit event",
            file=sys.stderr,
        )
        return
    if kind is StatKind.FILE:
        path = profile_db
        profile = "default"
    else:
        path = root / "prime.db"
        profile = ""
        legacy = lstat_kind(path)
        if legacy in {StatKind.SYMLINK, StatKind.UNREADABLE}:
            print(
                "praxis-prime account: state database cannot be opened for the audit event",
                file=sys.stderr,
            )
            return
    db = StateDB(path)
    try:
        AuditLog(db).append(
            session_id=None,
            kind="auth.owner_transfer",
            summary="owner transferred",
            payload={
                "from_account": former.id,
                "from_username": former.username,
                "to_account": current.id,
                "to_username": current.username,
            },
            actor_account=former.id,
            profile=profile,
        )
    finally:
        db.close()


def _read_password(args: argparse.Namespace, *, confirm: bool) -> str | None:
    if args.password_stdin:
        line = sys.stdin.readline()
        if line.endswith("\n"):
            line = line[:-1]
        if line.endswith("\r"):
            line = line[:-1]
        return line
    if not sys.stdin.isatty():
        print(
            "praxis-prime account: pass --password-stdin or run in a terminal",
            file=sys.stderr,
        )
        return None
    first = getpass.getpass("Password: ")
    if confirm:
        second = getpass.getpass("Repeat password: ")
        if first != second:
            print("praxis-prime account: passwords did not match", file=sys.stderr)
            return None
    return first


def _store(args: argparse.Namespace) -> AccountStore:
    return AccountStore(_data(args) / "accounts.db")


def _data(args: argparse.Namespace) -> Path:
    explicit = getattr(args, "data_dir", None)
    if explicit:
        return Path(explicit)
    return data_dir()


def _config(args: argparse.Namespace) -> Path:
    explicit = getattr(args, "config_dir", None)
    if explicit:
        return Path(explicit)
    return config_dir()


def _add_dirs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--data-dir", help="Data directory. Defaults to the XDG data path.")
    parser.add_argument("--config-dir", help="Config directory. Defaults to the XDG config path.")
