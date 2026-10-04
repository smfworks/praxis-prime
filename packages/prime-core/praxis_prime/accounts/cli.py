"""``praxis-prime account`` commands.

``create`` on an empty database is the first-run owner bootstrap. It also
migrates single-user state into the ``default`` profile. Passwords are read
from stdin, never from an argument.

``totp`` and ``passkey`` write ``accounts.db`` as the local OS user, the
same trust as ``passwd``. Each of those commands appends an audit event
and does not record the secret. ``totp disable`` asks for the password
only. The HTTP disable route requires a step-up instead. Passkey
enrollment itself is the daemon HTTP ceremony and requires a step-up
there; this CLI can only list and remove credentials.

docs/blueprint-addendum-2026-09.md §4.3, §6.2, and §6.3.
"""

from __future__ import annotations

import argparse
import getpass
import sqlite3
import sys
from pathlib import Path

from praxis_prime.accounts.db import Account, AccountError, AccountStore
from praxis_prime.accounts.factors import FactorError, Factors
from praxis_prime.accounts.roles import SERVER_ROLES
from praxis_prime.audit.log import AuditLog
from praxis_prime.paths import config_dir, data_dir
from praxis_prime.profiles.migrate import MigrationBusy, migrate_single_user, migrate_under_lock
from praxis_prime.state import DatabaseBusy, StateDB
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
    factors = sub.add_parser("factors", help="Show TOTP and passkeys. Secrets are not printed.")
    factors.add_argument("username")
    _add_dirs(factors)
    totp = sub.add_parser("totp", help="Enroll, confirm, or disable TOTP on this machine.")
    totp_commands = totp.add_subparsers(dest="totp_command")
    enroll = totp_commands.add_parser(
        "enroll",
        help="Start TOTP. Prints the secret and recovery codes once.",
    )
    enroll.add_argument("username")
    _add_dirs(enroll)
    confirm = totp_commands.add_parser("confirm", help="Confirm TOTP with one code from stdin.")
    confirm.add_argument("username")
    _add_dirs(confirm)
    disable = totp_commands.add_parser("disable", help="Turn TOTP off. Reads the password.")
    disable.add_argument("username")
    disable.add_argument("--password-stdin", action="store_true")
    _add_dirs(disable)
    passkey = sub.add_parser("passkey", help="List or remove a passkey.")
    passkey_commands = passkey.add_subparsers(dest="passkey_command")
    listed = passkey_commands.add_parser(
        "list",
        help="List passkey ids. Public keys are not printed.",
    )
    listed.add_argument("username")
    _add_dirs(listed)
    removed = passkey_commands.add_parser("remove", help="Remove one passkey by its id.")
    removed.add_argument("username")
    removed.add_argument("credential_id")
    _add_dirs(removed)


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
    if command == "factors":
        return _factors(args)
    if command == "totp":
        return _totp(args)
    if command == "passkey":
        return _passkey(args)
    print(
        "usage: praxis-prime account "
        "{create|list|passwd|transfer-owner|disable|role|factors|totp|passkey}",
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
            return _create_owner(args, store, password)
        from praxis_prime.onboarding.token import invalidate_first_run_token

        invalidate_first_run_token(_config(args))
        account = store.create_account(
            username_text=args.username,
            password=password,
            display_name=args.display_name or args.username,
            role=args.role,
            email=args.email,
        )
    except AccountError as exc:
        print(f"praxis-prime account: {exc}", file=sys.stderr)
        return 2
    print(f"created {account.role} {account.username} ({account.id})")
    return 0


def _create_owner(args: argparse.Namespace, store: AccountStore, password: str) -> int:
    """Migrate first. A failure before the marker does not leave an owner behind."""
    account: Account | None = None
    try:
        result = migrate_under_lock(_data(args), _config(args), owner_account="")
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
            daemon_running=lambda: False,
        )
        store.set_membership(account.id, result.profile_id, "owner")
    except MigrationBusy as exc:
        print(f"praxis-prime account: {exc}", file=sys.stderr)
        return 2
    except (AccountError, OSError) as exc:
        if account is not None:
            try:
                store.discard_account(account.id)
            except AccountError:
                pass
        print(f"praxis-prime account: {exc}", file=sys.stderr)
        return 2
    from praxis_prime.onboarding.token import invalidate_first_run_token

    invalidate_first_run_token(_config(args))
    print(f"created owner {account.username} ({account.id})")
    print(f"profile {result.profile_id}")
    if result.backup:
        print(f"backup {result.backup}")
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
    store = _store(args)
    try:
        existing = store.get_username(args.username)
        removed = 0
        if existing is not None:
            keys = Factors(store).summary(existing.id).get("passkeys")
            removed = len(keys) if isinstance(keys, list) else 0
        account = store.set_password(args.username, password)
    except AccountError as exc:
        print(f"praxis-prime account: {exc}", file=sys.stderr)
        return 2
    _audit_account(
        _data(args),
        account,
        "password changed",
        {"method": "password", "passkeys_revoked": removed},
    )
    print(f"updated password for {account.username}")
    return 0


def _factors(args: argparse.Namespace) -> int:
    store = _store(args)
    account = store.get_username(args.username)
    if account is None:
        print("praxis-prime account: no such account", file=sys.stderr)
        return 2
    summary = Factors(store).summary(account.id)
    totp = "on" if summary["totp"] else "pending" if summary["totpPending"] else "off"
    print(f"{account.username}  totp={totp}  recovery={summary['recoveryCodesRemaining']}")
    passkeys = summary["passkeys"]
    if not isinstance(passkeys, list) or not passkeys:
        print("passkeys none")
        return 0
    for item in passkeys:
        if not isinstance(item, dict):
            continue
        print(f"passkey {item.get('id', '')}  {item.get('name', '')}")
    return 0


def _totp(args: argparse.Namespace) -> int:
    command = getattr(args, "totp_command", None)
    if command == "enroll":
        return _totp_enroll(args)
    if command == "confirm":
        return _totp_confirm(args)
    if command == "disable":
        return _totp_disable(args)
    print("usage: praxis-prime account totp {enroll|confirm|disable}", file=sys.stderr)
    return 2


def _totp_enroll(args: argparse.Namespace) -> int:
    store = _store(args)
    account = store.get_username(args.username)
    if account is None:
        print("praxis-prime account: no such account", file=sys.stderr)
        return 2
    try:
        enrollment = Factors(store).begin_totp(account.id)
    except FactorError as exc:
        print(f"praxis-prime account: {exc}", file=sys.stderr)
        return 2
    _audit_account(
        _data(args),
        account,
        "totp enrollment started",
        {"method": "totp"},
    )
    print(f"totp pending for {account.username}")
    print(f"secret {enrollment.secret}")
    print(f"otpauth {enrollment.otpauth_uri}")
    print("recovery codes (shown once):")
    for code in enrollment.recovery_codes:
        print(code)
    print("confirm with: praxis-prime account totp confirm " + account.username)
    return 0


def _totp_confirm(args: argparse.Namespace) -> int:
    line = sys.stdin.readline()
    if line.endswith("\n"):
        line = line[:-1]
    if line.endswith("\r"):
        line = line[:-1]
    store = _store(args)
    account = store.get_username(args.username)
    if account is None:
        print("praxis-prime account: no such account", file=sys.stderr)
        return 2
    try:
        Factors(store).confirm_totp(account.id, line)
    except FactorError as exc:
        print(f"praxis-prime account: {exc}", file=sys.stderr)
        return 2
    _audit_account(_data(args), account, "totp confirmed", {"method": "totp"})
    print(f"totp on for {account.username}")
    return 0


def _totp_disable(args: argparse.Namespace) -> int:
    password = _read_password(args, confirm=False)
    if password is None:
        return 2
    store = _store(args)
    try:
        account = Factors(store).disable_totp(args.username, password)
    except FactorError as exc:
        print(f"praxis-prime account: {exc}", file=sys.stderr)
        return 2
    _audit_account(_data(args), account, "totp disabled", {"method": "totp"})
    print(f"totp off for {account.username}")
    return 0


def _passkey(args: argparse.Namespace) -> int:
    command = getattr(args, "passkey_command", None)
    if command not in {"list", "remove"}:
        print("usage: praxis-prime account passkey {list|remove}", file=sys.stderr)
        return 2
    store = _store(args)
    account = store.get_username(args.username)
    if account is None:
        print("praxis-prime account: no such account", file=sys.stderr)
        return 2
    factors = Factors(store)
    if command == "list":
        summary = factors.summary(account.id)
        passkeys = summary["passkeys"]
        if not isinstance(passkeys, list) or not passkeys:
            print("no passkeys")
            return 0
        for item in passkeys:
            if isinstance(item, dict):
                print(f"{item.get('id', '')}  {item.get('name', '')}")
        return 0
    if command == "remove":
        try:
            factors.remove_passkey(account.id, args.credential_id)
        except FactorError as exc:
            print(f"praxis-prime account: {exc}", file=sys.stderr)
            return 2
        _audit_account(
            _data(args),
            account,
            "passkey removed",
            {"method": "passkey"},
        )
        print(f"removed passkey for {account.username}")
        return 0
    print("usage: praxis-prime account passkey {list|remove}", file=sys.stderr)
    return 2


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


def _audit_account(
    root: Path,
    account: Account,
    summary: str,
    payload: dict[str, object],
) -> None:
    """Append one hash-chained event. Callers must not put secrets in ``payload``."""
    path, profile = _audit_target(root)
    if path is None:
        return
    stamped = {"username": account.username, **payload}
    try:
        db = StateDB(path)
    except (OSError, sqlite3.Error, DatabaseBusy, ValueError) as exc:
        print(f"praxis-prime account: audit event was not written ({exc})", file=sys.stderr)
        return
    try:
        AuditLog(db).append(
            session_id=None,
            kind="auth.mfa",
            summary=summary,
            payload=stamped,
            actor_account=account.id,
            profile=profile,
        )
    except (OSError, sqlite3.Error) as exc:
        print(f"praxis-prime account: audit event was not written ({exc})", file=sys.stderr)
    finally:
        db.close()


def _audit_target(root: Path) -> tuple[Path, str] | None:
    """Return ``(prime.db, profile)`` for a CLI audit event, or None."""
    profile_db = root / "profiles" / "default" / "prime.db"
    kind = lstat_kind(profile_db)
    if kind in {StatKind.SYMLINK, StatKind.UNREADABLE}:
        print(
            "praxis-prime account: profile database cannot be opened for the audit event",
            file=sys.stderr,
        )
        return None
    if kind is StatKind.FILE:
        return profile_db, "default"
    path = root / "prime.db"
    legacy = lstat_kind(path)
    if legacy in {StatKind.SYMLINK, StatKind.UNREADABLE}:
        print(
            "praxis-prime account: state database cannot be opened for the audit event",
            file=sys.stderr,
        )
        return None
    return path, ""


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
