"""Append-only audit log with a SHA-256 hash chain.

Tool calls and approvals are recorded here. Payloads should already be
redacted by the caller. This is the MVP chain: no daily signature yet.

ARCHITECTURE §18.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

from praxis_prime.state import StateDB

_GENESIS = "0" * 64
_AUTH_FAIL_WINDOW = 60.0
_AUTH_FAIL_GLOBAL = 8
_AUTH_FAIL_SUMMARY = 8

# Set for the duration of one request or turn. Empty falls back to the
# values bound on the AuditLog (the profile the runtime opened).
actor_account_var: ContextVar[str] = ContextVar("praxis_prime_actor_account", default="")
profile_var: ContextVar[str] = ContextVar("praxis_prime_profile", default="")


class AuditLog:
    def __init__(self, db: StateDB) -> None:
        self.db = db
        self.actor_account = ""
        self.profile = ""
        self._lock = threading.RLock()
        self._fail_user: dict[str, float] = {}
        self._fail_at: list[float] = []
        self._suppressed: dict[tuple[str, str], int] = {}
        self._timer: threading.Timer | None = None
        # A second connection. Chat writes hold transactions on ``db.conn``,
        # and ``BEGIN IMMEDIATE`` on that same connection raises.
        self._conn = sqlite3.connect(self.db.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("PRAGMA foreign_keys=ON")

    def close(self) -> None:
        """Flush a partial auth.fail summary, then close the connection."""
        with self._lock:
            self._cancel_timer()
            if self._conn is not None and self._suppressed:
                try:
                    self._write_summary()
                except sqlite3.Error:
                    pass
            conn = self._conn
            self._conn = None
        if conn is not None:
            conn.close()

    def bind(self, *, actor_account: str = "", profile: str = "") -> None:
        """Default actor and profile stamped on later events."""
        self.actor_account = actor_account
        self.profile = profile

    def append(
        self,
        *,
        session_id: str | None,
        kind: str,
        summary: str,
        payload: dict[str, Any],
        actor_account: str | None = None,
        profile: str | None = None,
    ) -> str:
        account = self._actor(actor_account)
        profile_id = self._profile(profile)
        stamped = dict(payload)
        if not isinstance(stamped.get("actor_account"), str):
            stamped["actor_account"] = account
        if not isinstance(stamped.get("profile"), str):
            stamped["profile"] = profile_id
        column_account = str(stamped["actor_account"])
        column_profile = str(stamped["profile"])
        payload_json = json.dumps(stamped, sort_keys=True, separators=(",", ":"))
        with self._lock:
            if kind == "auth.fail" and not self._permit_auth_fail(stamped):
                self._note_suppressed(stamped)
                if self._should_summarize():
                    self._write_summary()
                return self.last_hash()
            return self._insert(
                session_id,
                kind,
                summary,
                payload_json,
                column_account,
                column_profile,
            )

    def _insert(
        self,
        session_id: str | None,
        kind: str,
        summary: str,
        payload_json: str,
        column_account: str,
        column_profile: str,
    ) -> str:
        conn = self._require()
        conn.execute("BEGIN IMMEDIATE")
        try:
            prev = self.last_hash()
            digest = hashlib.sha256(f"{prev}\n{payload_json}".encode()).hexdigest()
            conn.execute(
                """
                INSERT INTO audit_events (
                    session_id, created_at, kind, summary, payload_json,
                    prev_hash, hash, actor_account, profile
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    datetime.now(UTC).isoformat(),
                    kind,
                    summary,
                    payload_json,
                    prev,
                    digest,
                    column_account,
                    column_profile,
                ),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        return digest

    def _require(self) -> sqlite3.Connection:
        if self._conn is None:
            raise sqlite3.ProgrammingError("audit log is closed")
        return self._conn

    def _permit_auth_fail(self, payload: dict[str, Any]) -> bool:
        """At most one auth.fail per username per minute, and a global cap."""
        now = time.monotonic()
        name = payload.get("username")
        key = name.casefold() if isinstance(name, str) else ""
        if len(key) > 64:
            key = key[:64]
        self._fail_at = [stamp for stamp in self._fail_at if now - stamp < _AUTH_FAIL_WINDOW]
        if len(self._fail_at) >= _AUTH_FAIL_GLOBAL:
            return False
        last = self._fail_user.get(key, 0.0)
        if key and now - last < _AUTH_FAIL_WINDOW:
            return False
        self._fail_user[key] = now
        self._fail_at.append(now)
        if len(self._fail_user) > 256:
            stale = [
                item
                for item, stamp in self._fail_user.items()
                if now - stamp >= _AUTH_FAIL_WINDOW
            ]
            for item in stale:
                del self._fail_user[item]
        return True

    def _note_suppressed(self, payload: dict[str, Any]) -> None:
        name = payload.get("username")
        ip = payload.get("ip")
        user = name.casefold()[:64] if isinstance(name, str) else ""
        host = ip[:64] if isinstance(ip, str) else ""
        key = (user, host)
        self._suppressed[key] = self._suppressed.get(key, 0) + 1
        self._arm_timer()

    def _arm_timer(self) -> None:
        """Write a short burst even when the process stays up past the window."""
        if self._timer is not None:
            return
        timer = threading.Timer(_AUTH_FAIL_WINDOW, self._flush_due)
        timer.daemon = True
        self._timer = timer
        timer.start()

    def _flush_due(self) -> None:
        with self._lock:
            self._timer = None
            if self._conn is None or not self._suppressed:
                return
            try:
                self._write_summary()
            except sqlite3.Error:
                return

    def _cancel_timer(self) -> None:
        timer = self._timer
        self._timer = None
        if timer is not None:
            timer.cancel()

    def _should_summarize(self) -> bool:
        if not self._suppressed:
            return False
        if len(self._suppressed) > 64:
            return True
        return sum(self._suppressed.values()) >= _AUTH_FAIL_SUMMARY

    def _write_summary(self) -> None:
        """One chained row so a throttled brute-force burst stays visible."""
        if not self._suppressed:
            return
        counts = [
            {"username": name, "ip": ip, "count": count}
            for (name, ip), count in sorted(self._suppressed.items())
        ]
        total = sum(item["count"] for item in counts)
        stamped = {
            "actor_account": "",
            "counts": counts,
            "profile": "",
            "suppressed": total,
        }
        payload_json = json.dumps(stamped, sort_keys=True, separators=(",", ":"))
        self._insert(
            None,
            "auth.fail.summary",
            "suppressed login failures",
            payload_json,
            "",
            "",
        )
        self._suppressed.clear()

    def _actor(self, explicit: str | None) -> str:
        if explicit is not None:
            return explicit
        current = actor_account_var.get()
        return current or self.actor_account

    def _profile(self, explicit: str | None) -> str:
        if explicit is not None:
            return explicit
        current = profile_var.get()
        return current or self.profile

    def last_id(self) -> int | None:
        with self._lock:
            row = self._require().execute(
                "SELECT id FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        return int(row["id"])

    def last_hash(self) -> str:
        with self._lock:
            row = self._require().execute(
                "SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return _GENESIS
        return str(row["hash"])

    def verify(self) -> bool:
        prev = _GENESIS
        with self._lock:
            rows = self._require().execute(
                "SELECT payload_json, prev_hash, hash FROM audit_events ORDER BY id"
            ).fetchall()
        for row in rows:
            if row["prev_hash"] != prev:
                return False
            expect = hashlib.sha256(f"{prev}\n{row['payload_json']}".encode()).hexdigest()
            if row["hash"] != expect:
                return False
            prev = str(row["hash"])
        return True

    def for_session(self, session_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return self._for_session(session_id)

    def _for_session(self, session_id: str) -> list[dict[str, Any]]:
        rows = self._require().execute(
            """
            SELECT kind, summary, payload_json, hash, actor_account, profile
            FROM audit_events
            WHERE session_id = ?
            ORDER BY id
            """,
            (session_id,),
        ).fetchall()
        events = []
        for row in rows:
            events.append(
                {
                    "kind": row["kind"],
                    "summary": row["summary"],
                    "payload": json.loads(row["payload_json"]),
                    "hash": row["hash"],
                    "actor_account": str(row["actor_account"] or ""),
                    "profile": str(row["profile"] or ""),
                }
            )
        return events
