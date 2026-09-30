"""``accounts.db``: accounts, memberships, sessions, and WebSocket tickets.

The file is SQLite in WAL mode, created mode 0600. Session cookies and
WebSocket tickets are stored only as SHA-256 hashes. The CSRF token is
stored so a same-origin client can read it back; it is useless without
the session cookie. Passwords are stored only as argon2id hashes.

docs/blueprint-addendum-2026-09.md §4.3 and §6.3.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
from collections.abc import Mapping
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
_COOKIE = "pp_session"


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
        self._lock = threading.Lock()
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

    def list_accounts(self) -> list[Account]:
        with self._lock:
            rows = self.conn.execute(
                """
                SELECT id, username, display_name, email, role, status, created_at
                FROM accounts ORDER BY username
                """
            ).fetchall()
        return [_account(row) for row in rows]

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
                SET password_hash = ?, updated_at = ?, failed_logins = 0, locked_until = ''
                WHERE id = ?
                """,
                (encoded, now, row["id"]),
            )
            self.conn.commit()
            tighten_file(self.path)
            fresh = self._account_row(name)
        if fresh is None:
            raise AccountError("no such account")
        return _account(fresh)

    def authenticate(self, username_text: str, password: str) -> Account | None:
        """Return the account, or None. Does not reveal which check failed.

        The argon2 compare runs outside the database lock.
        """
        name = username(username_text)
        presented = password if isinstance(password, str) else ""
        if name is None:
            dummy_verify(presented)
            return None
        with self._lock:
            row = self._account_row(name)
            if row is None:
                encoded = ""
                account: Account | None = None
                locked = False
                active = False
                account_id = ""
                failed = 0
            else:
                encoded = str(row["password_hash"])
                account = _account(row)
                locked = _is_locked(str(row["locked_until"]))
                active = str(row["status"]) == "active"
                account_id = str(row["id"])
                failed = int(row["failed_logins"])
        if account is None:
            dummy_verify(presented)
            return None
        if locked:
            dummy_verify(presented)
            return None
        if not active or not verify_password(encoded, presented):
            if active:
                with self._lock:
                    fresh = self.conn.execute(
                        "SELECT failed_logins FROM accounts WHERE id = ?",
                        (account_id,),
                    ).fetchone()
                    previous = int(fresh["failed_logins"]) if fresh is not None else failed
                    self._record_failure(account_id, previous)
            else:
                verify_password(encoded, presented)
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
            cursor = self.conn.execute(
                "UPDATE sessions SET revoked = 1 WHERE token_hash = ? AND revoked = 0",
                (_hash(token),),
            )
            self.conn.commit()
        return cursor.rowcount > 0

    def csrf_matches(self, session: Session, presented: str) -> bool:
        if not presented or len(presented) > 256 or not session.csrf_token:
            return False
        return hmac.compare_digest(session.csrf_token, presented)

    def issue_ticket(
        self,
        account: Account,
        *,
        profile: str = "",
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
                    id, account_id, token_hash, profile_id, created_at, expires_at, used
                ) VALUES (?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    _new_id("wst"),
                    account.id,
                    _hash(raw),
                    checked,
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
                    SELECT t.id, t.account_id, t.profile_id, t.expires_at, t.used,
                           a.username, a.role, a.status
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
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            );
            """
        )
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
        failed = previous + 1
        locked = ""
        if failed >= LOCK_AFTER_FAILURES:
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

