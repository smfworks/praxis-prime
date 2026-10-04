"""Create the first owner the same way from the CLI and the web wizard.

The move into ``profiles/default`` happens before the account is kept.
A failure after the insert discards the account. The caller writes the
audit row and only then deletes the first-run token.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from praxis_prime.accounts.db import Account, AccountError, AccountStore
from praxis_prime.profiles.home import list_profiles
from praxis_prime.profiles.migrate import (
    _read_marker,
    _write_marker,
    migrate_single_user,
    migrate_under_lock,
    migration_marker,
)


@dataclass(frozen=True, slots=True)
class OwnerCreated:
    account: Account
    profile_id: str
    backup: str
    profiles_existed: bool


def create_owner_account(
    store: AccountStore,
    data_root: Path,
    config_dir: Path,
    *,
    username: str,
    password: str,
    display_name: str = "",
    email: str = "",
    daemon_running: Callable[[], bool] | None = None,
) -> OwnerCreated:
    """Migrate, insert the owner, stamp the marker, and record membership.

    ``daemon_running`` defaults to the published-daemon check. The HTTP
    path passes a function that returns false after this process has
    released ``prime.db``. A lock that is still held raises ``MigrationBusy``.
    """
    existed = bool(list_profiles(data_root))
    account: Account | None = None
    try:
        result = migrate_under_lock(
            data_root,
            config_dir,
            owner_account="",
            daemon_running=daemon_running,
        )
        account = store.create_account(
            username_text=username,
            password=password,
            display_name=display_name or username,
            role="owner",
            email=email,
        )
        result = migrate_single_user(
            data_root,
            config_dir,
            owner_account=account.id,
            daemon_running=lambda: False,
        )
        store.set_membership(account.id, result.profile_id, "owner")
    except (AccountError, OSError, sqlite3.Error, RuntimeError, ValueError):
        if account is not None:
            try:
                store.discard_account(account.id)
            except AccountError:
                pass
        raise
    return OwnerCreated(
        account=account,
        profile_id=result.profile_id,
        backup=result.backup,
        profiles_existed=existed,
    )


def clear_discarded_owner(data_root: Path, account_id: str) -> None:
    """Drop an owner id from the marker when that account was not kept."""
    marker = migration_marker(data_root)
    if not marker.is_file():
        return
    recorded = _read_marker(marker)
    if recorded.owner_account != account_id:
        return
    _write_marker(marker, recorded.profile_id, recorded.backup, "")
