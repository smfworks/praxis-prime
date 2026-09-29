"""Append-only audit log with a SHA-256 hash chain.

Tool calls and approvals are recorded here. Payloads should already be
redacted by the caller. This is the MVP chain: no daily signature yet.

ARCHITECTURE §18.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from praxis_prime.state import StateDB

_GENESIS = "0" * 64


class AuditLog:
    def __init__(self, db: StateDB) -> None:
        self.db = db

    def append(
        self,
        *,
        session_id: str | None,
        kind: str,
        summary: str,
        payload: dict[str, Any],
    ) -> str:
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        prev = self.last_hash()
        digest = hashlib.sha256(f"{prev}\n{payload_json}".encode()).hexdigest()
        self.db.conn.execute(
            """
            INSERT INTO audit_events
                (session_id, created_at, kind, summary, payload_json, prev_hash, hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (session_id, datetime.now(UTC).isoformat(), kind, summary, payload_json, prev, digest),
        )
        self.db.conn.commit()
        return digest

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
            SELECT kind, summary, payload_json, hash
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
                }
            )
        return events
