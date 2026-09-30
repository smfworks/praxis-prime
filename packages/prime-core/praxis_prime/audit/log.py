"""Append-only audit log with a SHA-256 hash chain.

Tool calls and approvals are recorded here. Payloads should already be
redacted by the caller. This is the MVP chain: no daily signature yet.

ARCHITECTURE §18.
"""

from __future__ import annotations

import hashlib
import json
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

from praxis_prime.state import StateDB

_GENESIS = "0" * 64

# Set for the duration of one request or turn. Empty falls back to the
# values bound on the AuditLog (the profile the runtime opened).
actor_account_var: ContextVar[str] = ContextVar("praxis_prime_actor_account", default="")
profile_var: ContextVar[str] = ContextVar("praxis_prime_profile", default="")


class AuditLog:
    def __init__(self, db: StateDB) -> None:
        self.db = db
        self.actor_account = ""
        self.profile = ""

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
        stamped.setdefault("actor_account", account)
        stamped.setdefault("profile", profile_id)
        payload_json = json.dumps(stamped, sort_keys=True, separators=(",", ":"))
        prev = self.last_hash()
        digest = hashlib.sha256(f"{prev}\n{payload_json}".encode()).hexdigest()
        self.db.conn.execute(
            """
            INSERT INTO audit_events (
                session_id, created_at, kind, summary, payload_json, prev_hash, hash,
                actor_account, profile
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
                account,
                profile_id,
            ),
        )
        self.db.conn.commit()
        return digest

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
        row = self.db.conn.execute(
            "SELECT id FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        return int(row["id"])

    def last_hash(self) -> str:
        row = self.db.conn.execute(
            "SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return _GENESIS
        return str(row["hash"])

    def verify(self) -> bool:
        prev = _GENESIS
        rows = self.db.conn.execute(
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
        rows = self.db.conn.execute(
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
