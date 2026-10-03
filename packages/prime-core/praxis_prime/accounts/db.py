"""``accounts.db``: accounts, memberships, sessions, and WebSocket tickets.

The file is SQLite in WAL mode, created mode 0600. Session cookies and
WebSocket tickets are stored only as SHA-256 hashes. The CSRF token is
stored so a same-origin client can read it back; it is useless without
the session cookie. Passwords are stored only as argon2id hashes.
Passkey public keys, encrypted TOTP seeds, and recovery-code hashes live
in this same file so the existing account-data denylist covers them.

docs/blueprint-addendum-2026-09.md §4.3 and §6.3.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from praxis_prime.accounts.passwords import (
    dummy_verify,
    hash_password,
    password_ok,
    verify_password,
)
from praxis_prime.accounts.roles import PROFILE_ROLES, SERVER_ROLES, profile_role, server_role
from praxis_prime.privatefile import tighten_file, touch_private
from praxis_prime.profiles.ids import profile_id, username

SESSION_TTL_SECONDS = 12 * 60 * 60
TICKET_TTL_SECONDS = 30
LOCK_AFTER_FAILURES = 5
LOCK_SECONDS = 15 * 60
# argon2id uses about 19 MiB per verify. This caps how many run at once.
LOGIN_CONCURRENCY = 4
# Distinct usernames each take a lock. Drop the oldest ones that nobody
# has pinned and that are not held. A pin covers the window between
# lookup and acquire, so eviction cannot hand two threads different locks
# for the same name.
_NAME_LOCK_CAP = 256
_COOKIE = "pp_session"


class _NameLock:
    """One username lock plus how many callers have reserved it."""

    __slots__ = ("holders", "lock")

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.holders = 0


@dataclass(frozen=True, slots=True)
class Account:
    id: str
    username: str
    display_name: str
    email: str
    role: str
    status: str
    created_at: str

    def public(self) -> dict[str, object]:
        return {
            "id": self.id,
            "username": self.username,
            "displayName": self.display_name,
            "email": self.email,
            "role": self.role,
            "status": self.status,
            "createdAt": self.created_at,
        }


@dataclass(frozen=True, slots=True)
class Session:
    id: str
    account_id: str
    username: str
    role: str
    csrf_token: str
    expires_at: str


@dataclass(frozen=True, slots=True)
class IssuedSession:
    account: Account
    session_id: str
    token: str
    csrf_token: str
    max_age: int


@dataclass(frozen=True, slots=True)
class Ticket:
    account_id: str
    username: str
    role: str
    profile_id: str
    session_id: str = ""


class AccountError(ValueError):
    """A rejected account or membership change. No secret is included."""


class AccountStore:
    """One process-wide connection. Methods take a lock."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        touch_private(self.path)
        previous = os.umask(0o077)
        try:
            self.conn = sqlite3.connect(self.path, check_same_thread=False)
        finally:
            os.umask(previous)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self._lock = threading.Lock()
        self._login_slots = threading.BoundedSemaphore(LOGIN_CONCURRENCY)
        self._name_locks: dict[str, _NameLock] = {}
        self._name_guard = threading.Lock()
        self._migrate()
        tighten_file(self.path)

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    def has_accounts(self) -> bool:
        with self._lock:
            row = self.conn.execute("SELECT 1 FROM accounts LIMIT 1").fetchone()
        return row is not None

    def count_accounts(self) -> int:
        with self._lock:
            row = self.conn.execute("SELECT COUNT(*) AS n FROM accounts").fetchone()
        return int(row["n"]) if row is not None else 0

    def create_account(
        self,
        *,
        username_text: str,
        password: str,
        display_name: str,
        role: str = "operator",
        email: str = "",
    ) -> Account:
        """Insert an account. The first account is forced to ``owner``."""
        name = username(username_text)
        if name is None:
            raise AccountError("username must be 1 to 64 characters: a-z, 0-9, . _ -")
        problem = password_ok(password)
        if problem:
            raise AccountError(problem)
        shown = _display_name(display_name or name)
        mail = _email(email)
        chosen = server_role(role)
        if chosen is None:
            raise AccountError("role must be owner, admin, operator, viewer, or auditor")
        encoded = hash_password(password)
        now = _now()
        account_id = _new_id("acc")
        with self._lock:
            existing = self.conn.execute("SELECT COUNT(*) AS n FROM accounts").fetchone()
            count = int(existing["n"]) if existing is not None else 0
            if count == 0:
                chosen = "owner"
            elif chosen == "owner":
                raise AccountError("an owner account already exists")
            if chosen not in SERVER_ROLES:
                raise AccountError("role must be owner, admin, operator, viewer, or auditor")
            try:
                self.conn.execute(
                    """
                    INSERT INTO accounts (
                        id, username, display_name, email, password_hash, role,
                        status, created_at, updated_at, failed_logins, locked_until
                    ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, 0, '')
                    """,
                    (account_id, name, shown, mail, encoded, chosen, now, now),
                )
                self.conn.commit()
            except sqlite3.IntegrityError as exc:
                raise AccountError(f"account {name} already exists") from exc
            tighten_file(self.path)
        return Account(account_id, name, shown, mail, chosen, "active", now)

    def discard_account(self, account_id: str) -> None:
        """Delete one account and its sessions. Rolls back a failed first create."""
        if not account_id.startswith("acc_"):
            raise AccountError("no such account")
        with self._lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                self.conn.execute(
                    "DELETE FROM ws_tickets WHERE account_id = ?",
                    (account_id,),
                )
                self.conn.execute(
                    "DELETE FROM sessions WHERE account_id = ?",
                    (account_id,),
                )
                self.conn.execute(
                    "DELETE FROM memberships WHERE account_id = ?",
                    (account_id,),
                )
                self.conn.execute(
                    "DELETE FROM mfa_tokens WHERE account_id = ?",
                    (account_id,),
                )
                self.conn.execute(
                    "DELETE FROM step_up WHERE account_id = ?",
                    (account_id,),
                )
                self.conn.execute(
                    "DELETE FROM recovery_codes WHERE account_id = ?",
                    (account_id,),
                )
                self.conn.execute("DELETE FROM totp WHERE account_id = ?", (account_id,))
                self.conn.execute(
                    "DELETE FROM passkeys WHERE account_id = ?",
                    (account_id,),
                )
                self.conn.execute(
                    "DELETE FROM webauthn_challenges WHERE account_id = ?",
                    (account_id,),
                )
                self.conn.execute(
                    "DELETE FROM oidc_identities WHERE account_id = ?",
                    (account_id,),
                )
                self.conn.execute(
                    "DELETE FROM oidc_transactions WHERE account_id = ?",
                    (account_id,),
                )
                deleted = self.conn.execute(
                    "DELETE FROM accounts WHERE id = ?",
                    (account_id,),
                )
                if deleted.rowcount != 1:
                    raise AccountError("no such account")
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise

    def list_accounts(self) -> list[Account]:
        with self._lock:
            rows = self.conn.execute(
                """
                SELECT id, username, display_name, email, role, status, created_at
                FROM accounts ORDER BY username
                """
            ).fetchall()
        return [_account(row) for row in rows]

    def get_id(self, account_id: str) -> Account | None:
        if not account_id.startswith("acc_"):
            return None
        with self._lock:
            row = self.conn.execute(
                """
                SELECT id, username, display_name, email, role, status, created_at
                FROM accounts WHERE id = ?
                """,
                (account_id,),
            ).fetchone()
        if row is None:
            return None
        return _account(row)

    def get_username(self, username_text: str) -> Account | None:
        name = username(username_text)
        if name is None:
            return None
        with self._lock:
            row = self._account_row(name)
        if row is None:
            return None
        return _account(row)

    def owner(self) -> Account | None:
        with self._lock:
            row = self.conn.execute(
                """
                SELECT id, username, display_name, email, role, status, created_at
                FROM accounts WHERE role = 'owner' ORDER BY created_at LIMIT 1
                """
            ).fetchone()
        if row is None:
            return None
        return _account(row)

    def transfer_owner(self, username_text: str) -> tuple[Account, Account]:
        """Hand ownership to an existing admin. The previous owner becomes admin.

        There is still one owner. The change is one transaction.
        """
        name = username(username_text)
        if name is None:
            raise AccountError("no such account")
        now = _now()
        with self._lock:
            owner_row = self.conn.execute(
                """
                SELECT id FROM accounts
                WHERE role = 'owner' ORDER BY created_at LIMIT 1
                """
            ).fetchone()
            target = self._account_row(name)
            if owner_row is None:
                raise AccountError("no owner account")
            if target is None or str(target["status"]) != "active":
                raise AccountError("no such account")
            if str(target["role"]) != "admin":
                raise AccountError("the new owner must already be an admin")
            if str(target["id"]) == str(owner_row["id"]):
                raise AccountError("that account is already the owner")
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                self.conn.execute(
                    """
                    UPDATE accounts SET role = 'admin', updated_at = ?
                    WHERE id = ? AND role = 'owner'
                    """,
                    (now, owner_row["id"]),
                )
                cursor = self.conn.execute(
                    """
                    UPDATE accounts SET role = 'owner', updated_at = ?
                    WHERE id = ? AND role = 'admin'
                    """,
                    (now, target["id"]),
                )
                if cursor.rowcount != 1:
                    raise AccountError("could not transfer ownership")
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise
            former = self.conn.execute(
                """
                SELECT id, username, display_name, email, role, status, created_at
                FROM accounts WHERE id = ?
                """,
                (owner_row["id"],),
            ).fetchone()
            current = self._account_row(name)
        if former is None or current is None:
            raise AccountError("could not transfer ownership")
        return _account(former), _account(current)

    def set_password(self, username_text: str, password: str) -> Account:
        name = username(username_text)
        if name is None:
            raise AccountError("no such account")
        problem = password_ok(password)
        if problem:
            raise AccountError(problem)
        encoded = hash_password(password)
        now = _now()
        with self._lock:
            row = self._account_row(name)
            if row is None:
                raise AccountError("no such account")
            self.conn.execute(
                """
                UPDATE accounts
                SET password_hash = ?, updated_at = ?, failed_logins = 0,
                    second_factor_failures = 0, locked_until = ''
                WHERE id = ?
                """,
                (encoded, now, row["id"]),
            )
            # A passkey enrolled from a stolen session must not survive the
            # reset. Step-up tokens from that session die with it too.
            self.conn.execute("DELETE FROM passkeys WHERE account_id = ?", (row["id"],))
            self.conn.execute("DELETE FROM step_up WHERE account_id = ?", (row["id"],))
            self.conn.execute(
                """
                UPDATE webauthn_challenges SET used = 1
                WHERE account_id = ? AND used = 0
                """,
                (row["id"],),
            )
            self._revoke_credentials(str(row["id"]))
            self.conn.commit()
            tighten_file(self.path)
            fresh = self._account_row(name)
        if fresh is None:
            raise AccountError("no such account")
        return _account(fresh)

    def note_second_factor_failure(self, account_id: str) -> None:
        """Count a TOTP, recovery, or passkey failure toward the same lockout."""
        with self._lock:
            self._note_second_factor_failure(account_id)

    def clear_failures(self, account_id: str) -> None:
        """Reset password and second-factor counters after a full sign-in."""
        with self._lock:
            self._clear_failure_counters(account_id)
            self.conn.commit()

    def account_is_locked(self, account_id: str) -> bool:
        with self._lock:
            row = self.conn.execute(
                "SELECT locked_until, status FROM accounts WHERE id = ?",
                (account_id,),
            ).fetchone()
        if row is None or str(row["status"]) != "active":
            return False
        return _is_locked(str(row["locked_until"]))

    def disable_account(self, username_text: str) -> Account:
        """Disable an account and revoke its sessions and tickets.

        The owner cannot be disabled. Transfer ownership first.
        """
        name = username(username_text)
        if name is None:
            raise AccountError("no such account")
        now = _now()
        with self._lock:
            row = self._account_row(name)
            if row is None:
                raise AccountError("no such account")
            if str(row["role"]) == "owner":
                raise AccountError("the owner cannot be disabled; transfer ownership first")
            self.conn.execute(
                "UPDATE accounts SET status = 'disabled', updated_at = ? WHERE id = ?",
                (now, row["id"]),
            )
            self._revoke_credentials(str(row["id"]))
            self.conn.commit()
            fresh = self._account_row(name)
        if fresh is None:
            raise AccountError("no such account")
        return _account(fresh)

    def set_server_role(self, username_text: str, role: str) -> Account:
        """Change a server role. Revokes sessions and tickets.

        Owner is only changed by ``transfer_owner``. Becoming an auditor
        forces every membership to viewer.
        """
        name = username(username_text)
        chosen = server_role(role)
        if name is None:
            raise AccountError("no such account")
        if chosen is None or chosen == "owner":
            raise AccountError("role must be admin, operator, viewer, or auditor")
        now = _now()
        with self._lock:
            row = self._account_row(name)
            if row is None:
                raise AccountError("no such account")
            if str(row["role"]) == "owner":
                raise AccountError("use transfer-owner to change the owner")
            self.conn.execute(
                "UPDATE accounts SET role = ?, updated_at = ? WHERE id = ?",
                (chosen, now, row["id"]),
            )
            if chosen == "auditor":
                self.conn.execute(
                    """
                    UPDATE memberships SET profile_role = 'viewer'
                    WHERE account_id = ?
                    """,
                    (row["id"],),
                )
            self._revoke_credentials(str(row["id"]))
            self.conn.commit()
            fresh = self._account_row(name)
        if fresh is None:
            raise AccountError("no such account")
        return _account(fresh)

    def authenticate(self, username_text: str, password: str) -> Account | None:
        """Return the account, or None. Does not reveal which check failed.

        The lockout counter is held across argon2, so a burst of guesses
        cannot all pass the "not locked" check. argon2 itself runs outside
        the SQLite lock, under a process-wide concurrency cap.
        """
        name = username(username_text)
        presented = password if isinstance(password, str) else ""
        if name is None:
            self._verify_bounded("", presented)
            return None
        with self._account_gate(name):
            with self._lock:
                row = self._account_row(name)
                if row is None:
                    encoded = ""
                    account: Account | None = None
                    locked = False
                    active = False
                    account_id = ""
                else:
                    encoded = str(row["password_hash"])
                    account = _account(row)
                    locked = _is_locked(str(row["locked_until"]))
                    active = str(row["status"]) == "active"
                    account_id = str(row["id"])
            if account is None or locked or not active:
                self._verify_bounded(encoded if account is not None else "", presented)
                return None
            if not self._verify_bounded(encoded, presented):
                with self._lock:
                    fresh = self.conn.execute(
                        "SELECT failed_logins FROM accounts WHERE id = ?",
                        (account_id,),
                    ).fetchone()
                    previous = int(fresh["failed_logins"]) if fresh is not None else 0
                    self._record_failure(account_id, previous)
                return None
            with self._lock:
                self.conn.execute(
                    """
                    UPDATE accounts
                    SET failed_logins = 0, locked_until = '', updated_at = ?
                    WHERE id = ?
                    """,
                    (_now(), account_id),
                )
                self.conn.commit()
                tighten_file(self.path)
            return account

    def set_membership(self, account_id: str, profile: str, role: str) -> None:
        if not account_id.startswith("acc_"):
            raise AccountError("no such account")
        checked = profile_id(profile)
        if checked is None:
            raise AccountError("invalid profile id")
        chosen = profile_role(role)
        if chosen is None or chosen not in PROFILE_ROLES:
            raise AccountError("profile role must be owner, operator, or viewer")
        now = _now()
        with self._lock:
            found = self.conn.execute(
                "SELECT id, role FROM accounts WHERE id = ?",
                (account_id,),
            ).fetchone()
            if found is None:
                raise AccountError("no such account")
            if str(found["role"]) == "auditor" and chosen != "viewer":
                raise AccountError("an auditor membership is viewer")
            self.conn.execute(
                """
                INSERT INTO memberships (account_id, profile_id, profile_role, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT (account_id, profile_id)
                DO UPDATE SET profile_role = excluded.profile_role
                """,
                (account_id, checked, chosen, now),
            )
            self.conn.commit()

    def remove_membership(self, account_id: str, profile: str) -> bool:
        if not account_id.startswith("acc_"):
            raise AccountError("no such account")
        checked = profile_id(profile)
        if checked is None:
            raise AccountError("invalid profile id")
        with self._lock:
            cursor = self.conn.execute(
                "DELETE FROM memberships WHERE account_id = ? AND profile_id = ?",
                (account_id, checked),
            )
            self.conn.commit()
        return cursor.rowcount > 0

    def membership(self, account_id: str, profile: str) -> str | None:
        with self._lock:
            row = self.conn.execute(
                """
                SELECT profile_role FROM memberships
                WHERE account_id = ? AND profile_id = ?
                """,
                (account_id, profile),
            ).fetchone()
        if row is None:
            return None
        return str(row["profile_role"])

    def list_memberships(self) -> list[dict[str, str]]:
        """Profile grants. No secrets. Used by the admin directory."""
        with self._lock:
            rows = self.conn.execute(
                """
                SELECT account_id, profile_id, profile_role
                FROM memberships
                ORDER BY profile_id, account_id
                """
            ).fetchall()
        return [
            {
                "accountId": str(row["account_id"]),
                "profileId": str(row["profile_id"]),
                "role": str(row["profile_role"]),
            }
            for row in rows
        ]

    def profile_ids_for(self, account_id: str) -> tuple[str, ...]:
        with self._lock:
            rows = self.conn.execute(
                """
                SELECT profile_id FROM memberships
                WHERE account_id = ? ORDER BY profile_id
                """,
                (account_id,),
            ).fetchall()
        return tuple(str(row["profile_id"]) for row in rows)

    def open_session(self, account: Account, *, ttl: int = SESSION_TTL_SECONDS) -> IssuedSession:
        raw = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        session_id = _new_id("ses")
        now = datetime.now(UTC)
        expires = (now + timedelta(seconds=max(ttl, 0))).isoformat(timespec="seconds")
        created = now.isoformat(timespec="seconds")
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO sessions (
                    id, account_id, token_hash, csrf_token, created_at,
                    expires_at, last_seen_at, revoked
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (session_id, account.id, _hash(raw), csrf, created, expires, created),
            )
            self.conn.commit()
            tighten_file(self.path)
        return IssuedSession(account, session_id, raw, csrf, max(ttl, 0))

    def session_from_token(self, token: str) -> Session | None:
        if not token or len(token) > 256:
            return None
        digest = _hash(token)
        now = _now()
        with self._lock:
            row = self.conn.execute(
                """
                SELECT s.id, s.account_id, s.csrf_token, s.expires_at, s.revoked,
                       a.username, a.role, a.status
                FROM sessions AS s
                JOIN accounts AS a ON a.id = s.account_id
                WHERE s.token_hash = ?
                """,
                (digest,),
            ).fetchone()
            if row is None or int(row["revoked"]) or str(row["status"]) != "active":
                return None
            if str(row["expires_at"]) <= now:
                return None
            self.conn.execute(
                "UPDATE sessions SET last_seen_at = ? WHERE id = ?",
                (now, row["id"]),
            )
            self.conn.commit()
        return Session(
            id=str(row["id"]),
            account_id=str(row["account_id"]),
            username=str(row["username"]),
            role=str(row["role"]),
            csrf_token=str(row["csrf_token"]),
            expires_at=str(row["expires_at"]),
        )

    def revoke_token(self, token: str) -> bool:
        if not token:
            return False
        with self._lock:
            row = self.conn.execute(
                "SELECT id, account_id FROM sessions WHERE token_hash = ?",
                (_hash(token),),
            ).fetchone()
            cursor = self.conn.execute(
                "UPDATE sessions SET revoked = 1 WHERE token_hash = ? AND revoked = 0",
                (_hash(token),),
            )
            if row is not None:
                self.conn.execute(
                    "DELETE FROM step_up WHERE account_id = ? AND session_id = ?",
                    (row["account_id"], row["id"]),
                )
                self.conn.execute(
                    "DELETE FROM oidc_transactions WHERE session_id = ?",
                    (row["id"],),
                )
            self.conn.commit()
        return cursor.rowcount > 0

    def session_is_live(self, session_id: str) -> bool:
        """True when this login session is unrevoked, unexpired, and active."""
        if not session_id or len(session_id) > 80:
            return False
        now = _now()
        with self._lock:
            row = self.conn.execute(
                """
                SELECT s.revoked, s.expires_at, a.status
                FROM sessions AS s
                JOIN accounts AS a ON a.id = s.account_id
                WHERE s.id = ?
                """,
                (session_id,),
            ).fetchone()
        if row is None or int(row["revoked"]) or str(row["status"]) != "active":
            return False
        return str(row["expires_at"]) > now

    def csrf_matches(self, session: Session, presented: str) -> bool:
        if not presented or len(presented) > 256 or not session.csrf_token:
            return False
        return hmac.compare_digest(session.csrf_token, presented)

    def issue_ticket(
        self,
        account: Account,
        *,
        profile: str = "",
        session_id: str = "",
        ttl: int = TICKET_TTL_SECONDS,
    ) -> str:
        checked = ""
        if profile:
            found = profile_id(profile)
            if found is None:
                raise AccountError("invalid profile id")
            checked = found
        raw = secrets.token_urlsafe(32)
        now = datetime.now(UTC)
        expires = (now + timedelta(seconds=max(ttl, 0))).isoformat(timespec="seconds")
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO ws_tickets (
                    id, account_id, token_hash, profile_id, session_id,
                    created_at, expires_at, used
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    _new_id("wst"),
                    account.id,
                    _hash(raw),
                    checked,
                    session_id,
                    now.isoformat(timespec="seconds"),
                    expires,
                ),
            )
            self.conn.commit()
            tighten_file(self.path)
        return raw

    def consume_ticket(self, token: str) -> Ticket | None:
        """Return the ticket once. A second call, or an expired ticket, is None."""
        if not token or len(token) > 256:
            return None
        digest = _hash(token)
        now = _now()
        with self._lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                row = self.conn.execute(
                    """
                    SELECT t.id, t.account_id, t.profile_id, t.session_id,
                           t.expires_at, t.used, a.username, a.role, a.status
                    FROM ws_tickets AS t
                    JOIN accounts AS a ON a.id = t.account_id
                    WHERE t.token_hash = ?
                    """,
                    (digest,),
                ).fetchone()
                if row is None or int(row["used"]) or str(row["expires_at"]) <= now:
                    self.conn.rollback()
                    return None
                if str(row["status"]) != "active":
                    self.conn.rollback()
                    return None
                bound = str(row["session_id"])
                if bound and not self._session_row_live(bound, now):
                    self.conn.execute(
                        "UPDATE ws_tickets SET used = 1 WHERE id = ? AND used = 0",
                        (row["id"],),
                    )
                    self.conn.commit()
                    return None
                cursor = self.conn.execute(
                    "UPDATE ws_tickets SET used = 1 WHERE id = ? AND used = 0",
                    (row["id"],),
                )
                if cursor.rowcount != 1:
                    self.conn.rollback()
                    return None
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise
        return Ticket(
            account_id=str(row["account_id"]),
            username=str(row["username"]),
            role=str(row["role"]),
            profile_id=str(row["profile_id"]),
            session_id=str(row["session_id"]),
        )

    def _migrate(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                email TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (
                    role IN ('owner', 'admin', 'operator', 'viewer', 'auditor')
                ),
                status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                failed_logins INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS memberships (
                account_id TEXT NOT NULL REFERENCES accounts(id),
                profile_id TEXT NOT NULL,
                profile_role TEXT NOT NULL CHECK (
                    profile_role IN ('owner', 'operator', 'viewer')
                ),
                created_at TEXT NOT NULL,
                PRIMARY KEY (account_id, profile_id)
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(id),
                token_hash TEXT NOT NULL UNIQUE,
                csrf_token TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS ws_tickets (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(id),
                token_hash TEXT NOT NULL UNIQUE,
                profile_id TEXT NOT NULL DEFAULT '',
                session_id TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS auth_meta (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS totp (
                account_id TEXT PRIMARY KEY REFERENCES accounts(id),
                secret_enc BLOB NOT NULL,
                confirmed INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                confirmed_at TEXT NOT NULL DEFAULT '',
                last_step INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS recovery_codes (
                code_hash TEXT PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(id),
                created_at TEXT NOT NULL,
                used_at TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS passkeys (
                credential_id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(id),
                public_key BLOB NOT NULL,
                sign_count INTEGER NOT NULL DEFAULT 0,
                rp_id TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT 'passkey',
                created_at TEXT NOT NULL,
                last_used_at TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS webauthn_challenges (
                challenge BLOB PRIMARY KEY,
                account_id TEXT NOT NULL DEFAULT '',
                kind TEXT NOT NULL CHECK (kind IN ('register', 'authenticate')),
                rp_id TEXT NOT NULL,
                origin TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                session_id TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS webauthn_spent (
                challenge BLOB PRIMARY KEY,
                expires_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS mfa_tokens (
                token_hash TEXT PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(id),
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                pending_role TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS step_up (
                token_hash TEXT PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(id),
                session_id TEXT NOT NULL DEFAULT '',
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS oidc_providers (
                id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                issuer TEXT NOT NULL UNIQUE,
                client_id TEXT NOT NULL,
                secret_key TEXT NOT NULL,
                scopes TEXT NOT NULL,
                email_allowlist TEXT NOT NULL DEFAULT '[]',
                role_claim TEXT NOT NULL DEFAULT '',
                role_map TEXT NOT NULL DEFAULT '{}',
                dev_loopback INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                preset TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS oidc_identities (
                issuer TEXT NOT NULL,
                subject TEXT NOT NULL,
                account_id TEXT NOT NULL REFERENCES accounts(id),
                provider_id TEXT NOT NULL,
                email TEXT NOT NULL DEFAULT '',
                linked_at TEXT NOT NULL,
                PRIMARY KEY (issuer, subject)
            );

            CREATE UNIQUE INDEX IF NOT EXISTS oidc_identity_account_issuer
                ON oidc_identities(account_id, issuer);

            CREATE TABLE IF NOT EXISTS oidc_transactions (
                state_hash TEXT PRIMARY KEY,
                binding_hash TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                nonce_hash TEXT NOT NULL,
                verifier TEXT NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ('login', 'link')),
                account_id TEXT NOT NULL DEFAULT '',
                session_id TEXT NOT NULL DEFAULT '',
                redirect_uri TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                client_key TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS oidc_spent (
                nonce_hash TEXT PRIMARY KEY,
                expires_at TEXT NOT NULL
            );
            """
        )
        self._ensure_column("ws_tickets", "session_id", "session_id TEXT NOT NULL DEFAULT ''")
        self._ensure_column(
            "webauthn_challenges",
            "session_id",
            "session_id TEXT NOT NULL DEFAULT ''",
        )
        self._ensure_column(
            "accounts",
            "second_factor_failures",
            "second_factor_failures INTEGER NOT NULL DEFAULT 0",
        )
        self._ensure_column(
            "mfa_tokens",
            "pending_role",
            "pending_role TEXT NOT NULL DEFAULT ''",
        )
        self._ensure_column(
            "oidc_transactions",
            "client_key",
            "client_key TEXT NOT NULL DEFAULT ''",
        )
        # Rows written before the verifier moved to process memory still hold
        # it. Clear the column on every open so a leftover value does not stay
        # in the database.
        self.conn.execute("UPDATE oidc_transactions SET verifier = '' WHERE verifier != ''")
        self.conn.commit()
        tighten_file(self.path)

    def _account_row(self, name: str) -> sqlite3.Row | None:
        return self.conn.execute(
            """
            SELECT id, username, display_name, email, role, status, created_at,
                   password_hash, failed_logins, locked_until
            FROM accounts WHERE username = ?
            """,
            (name,),
        ).fetchone()

    def _record_failure(self, account_id: str, previous: int) -> None:
        extra = self.conn.execute(
            "SELECT second_factor_failures FROM accounts WHERE id = ?",
            (account_id,),
        ).fetchone()
        second = int(extra["second_factor_failures"]) if extra is not None else 0
        failed = previous + 1
        locked = ""
        if failed + second >= LOCK_AFTER_FAILURES:
            locked = (datetime.now(UTC) + timedelta(seconds=LOCK_SECONDS)).isoformat(
                timespec="seconds"
            )
        self.conn.execute(
            """
            UPDATE accounts
            SET failed_logins = ?, locked_until = ?, updated_at = ?
            WHERE id = ?
            """,
            (failed, locked, _now(), account_id),
        )
        self.conn.commit()

    def _note_second_factor_failure(self, account_id: str) -> None:
        """Caller holds ``_lock``. Commits, including any pending challenge burn."""
        row = self.conn.execute(
            """
            SELECT failed_logins, second_factor_failures, locked_until
            FROM accounts WHERE id = ?
            """,
            (account_id,),
        ).fetchone()
        if row is None or _is_locked(str(row["locked_until"])):
            self.conn.commit()
            return
        second = int(row["second_factor_failures"]) + 1
        locked = ""
        if int(row["failed_logins"]) + second >= LOCK_AFTER_FAILURES:
            locked = (datetime.now(UTC) + timedelta(seconds=LOCK_SECONDS)).isoformat(
                timespec="seconds"
            )
        self.conn.execute(
            """
            UPDATE accounts
            SET second_factor_failures = ?, locked_until = ?, updated_at = ?
            WHERE id = ?
            """,
            (second, locked, _now(), account_id),
        )
        self.conn.commit()

    def _clear_failure_counters(self, account_id: str) -> None:
        self.conn.execute(
            """
            UPDATE accounts
            SET failed_logins = 0, second_factor_failures = 0, locked_until = '', updated_at = ?
            WHERE id = ?
            """,
            (_now(), account_id),
        )

    def _ensure_column(self, table: str, column: str, declaration: str) -> None:
        """Add a column. A concurrent first open may add it first.

        Six processes opening an M1a database all see ``second_factor_failures``
        missing, and all issue ``ALTER TABLE``. SQLite accepts one and raises
        ``duplicate column name`` for the rest. That error means the column
        is present.
        """
        rows = self.conn.execute(f"PRAGMA table_info({table})").fetchall()
        names = {str(row[1]) for row in rows}
        if column in names:
            return
        try:
            self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {declaration}")
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc).lower():
                raise

    @contextmanager
    def _account_gate(self, name: str) -> Iterator[None]:
        """Serialize one username. The lock is pinned before it is acquired.

        Eviction used to drop a lock that had been returned but not yet
        acquired, or that a waiter had released and not yet re-acquired.
        Those callers then took a new lock and the username was no longer
        serialized. The holder count is incremented under the guard before
        ``acquire``, and eviction skips any lock that is pinned or held.
        """
        entry = self._pin_name_lock(name)
        try:
            with entry.lock:
                yield
        finally:
            self._unpin_name_lock(name)

    def _pin_name_lock(self, name: str) -> _NameLock:
        with self._name_guard:
            entry = self._name_locks.pop(name, None)
            if entry is None:
                entry = _NameLock()
            entry.holders += 1
            self._name_locks[name] = entry
            self._evict_name_locks()
            return entry

    def _unpin_name_lock(self, name: str) -> None:
        with self._name_guard:
            entry = self._name_locks.get(name)
            if entry is not None and entry.holders > 0:
                entry.holders -= 1

    def _evict_name_locks(self) -> None:
        """Caller holds ``_name_guard``."""
        overflow = len(self._name_locks) - _NAME_LOCK_CAP
        if overflow <= 0:
            return
        for old_name, old in list(self._name_locks.items()):
            if overflow <= 0:
                break
            if old.holders > 0 or old.lock.locked():
                continue
            del self._name_locks[old_name]
            overflow -= 1

    def _verify_bounded(self, encoded: str, presented: str) -> bool:
        with self._login_slots:
            if not encoded:
                dummy_verify(presented)
                return False
            return verify_password(encoded, presented)

    def _revoke_credentials(self, account_id: str) -> None:
        """Mark sessions revoked and unused tickets spent. Caller commits."""
        self.conn.execute(
            "UPDATE sessions SET revoked = 1 WHERE account_id = ? AND revoked = 0",
            (account_id,),
        )
        self.conn.execute(
            "UPDATE ws_tickets SET used = 1 WHERE account_id = ? AND used = 0",
            (account_id,),
        )
        self.conn.execute(
            "UPDATE mfa_tokens SET used = 1 WHERE account_id = ? AND used = 0",
            (account_id,),
        )
        self.conn.execute(
            "DELETE FROM oidc_transactions WHERE account_id = ?",
            (account_id,),
        )

    def _session_row_live(self, session_id: str, now: str) -> bool:
        row = self.conn.execute(
            """
            SELECT revoked, expires_at FROM sessions WHERE id = ?
            """,
            (session_id,),
        ).fetchone()
        if row is None or int(row["revoked"]):
            return False
        return str(row["expires_at"]) > now


def cookie_value(header: str, name: str = _COOKIE) -> str:
    """Return one cookie value. The header is not logged by this function."""
    if not header or len(header) > 4096:
        return ""
    prefix = f"{name}="
    for part in header.split(";"):
        item = part.strip()
        if item.startswith(prefix):
            value = item[len(prefix) :]
            if len(value) > 256 or any(ch in value for ch in " \r\n;"):
                return ""
            return value
    return ""


def session_cookie(token: str, *, max_age: int) -> str:
    """HttpOnly, Secure, SameSite=Strict session cookie."""
    if max_age <= 0 or not token:
        return f"{_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
    if any(ch in token for ch in " \r\n;"):
        raise AccountError("session token cannot be stored in a cookie")
    return (
        f"{_COOKIE}={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={max_age}"
    )


def _account(row: Mapping[str, object]) -> Account:
    role = str(row["role"])
    if role not in SERVER_ROLES:
        role = "viewer"
    return Account(
        id=str(row["id"]),
        username=str(row["username"]),
        display_name=str(row["display_name"]),
        email=str(row["email"]),
        role=role,
        status=str(row["status"]),
        created_at=str(row["created_at"]),
    )


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _is_locked(until: str) -> bool:
    return bool(until) and until > _now()


def _display_name(value: str) -> str:
    text = " ".join(value.replace("\r", " ").replace("\n", " ").split())
    if not text:
        raise AccountError("display name is empty")
    if len(text) > 80:
        raise AccountError("display name is too long")
    return text


def _email(value: str) -> str:
    text = value.strip()
    if not text:
        return ""
    if len(text) > 254 or any(ch.isspace() for ch in text) or text.count("@") != 1:
        raise AccountError("email must be a single address")
    return text

