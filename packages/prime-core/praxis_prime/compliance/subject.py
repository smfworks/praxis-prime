"""Data-subject export and erase.

The match is a case-insensitive substring of stored text. The audit row
stores a short hash of the subject, not the subject itself.

This is starter machinery for a GDPR-style request. It is not legal advice
and it does not decide a lawful basis.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from praxis_prime.audit.log import AuditLog
from praxis_prime.state import StateDB


def export_subject(db: StateDB, subject: str, *, lawful_basis_note: str = "") -> dict[str, Any]:
    needle = _needle(subject)
    memory = _rows(
        db,
        """
        SELECT id, tier, scope, content, source, session_id, channel, created_at
        FROM memory_entries
        WHERE instr(lower(content), ?) > 0
        ORDER BY created_at, id
        """,
        needle,
    )
    messages = _rows(
        db,
        """
        SELECT id, session_id, role, content, created_at
        FROM messages
        WHERE instr(lower(content), ?) > 0
        ORDER BY id
        """,
        needle,
    )
    return {
        "subject_hash": _subject_hash(subject),
        "lawful_basis_note": lawful_basis_note,
        "disclaimer": "Starter export. Not legal advice. Confirm the request before relying on it.",
        "memory": memory,
        "messages": messages,
    }


def erase_subject(db: StateDB, subject: str, *, audit: AuditLog | None = None) -> dict[str, int]:
    needle = _needle(subject)
    memory = db.conn.execute(
        "DELETE FROM memory_entries WHERE instr(lower(content), ?) > 0",
        (needle,),
    )
    messages = db.conn.execute(
        "DELETE FROM messages WHERE instr(lower(content), ?) > 0",
        (needle,),
    )
    db.conn.commit()
    result = {
        "memory_deleted": int(memory.rowcount),
        "messages_deleted": int(messages.rowcount),
    }
    if audit is not None:
        audit.append(
            session_id=None,
            kind="retention",
            summary="data-subject erase",
            payload={
                "action": "erase",
                "subject_hash": _subject_hash(subject),
                **result,
            },
        )
    return result


def _rows(db: StateDB, sql: str, needle: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for row in db.conn.execute(sql, (needle,)).fetchall():
        found.append({key: row[key] for key in row.keys()})
    return found


def _needle(subject: str) -> str:
    cleaned = subject.strip().lower()
    if not cleaned:
        raise ValueError("subject is empty")
    return cleaned


def _subject_hash(subject: str) -> str:
    return hashlib.sha256(subject.strip().lower().encode()).hexdigest()[:16]


def dumps_export(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"
