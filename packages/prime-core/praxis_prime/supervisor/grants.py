"""Session grants stored in the profile database.

A grant is checked again on every tool call. Revoking it writes
``revoked = 1``. The next start loads only rows that are still valid,
so a restart cannot bring a revoked grant back.

``migrate_grants`` runs once. A second start sees ``grants-v1`` and
does not read the legacy file again.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from praxis_prime.state import StateDB

_MIGRATION = "grants-v1"


def ensure_schema(db: StateDB) -> None:
    db.conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS session_grants (
            account_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            grant_key TEXT NOT NULL,
            profile_id TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (account_id, session_id, grant_key)
        );
        CREATE TABLE IF NOT EXISTS schema_migrations (
            name TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        );
        """
    )
    db.conn.commit()


def migration_applied(db: StateDB) -> bool:
    ensure_schema(db)
    row = db.conn.execute(
        "SELECT name FROM schema_migrations WHERE name = ?",
        (_MIGRATION,),
    ).fetchone()
    return row is not None


def migrate_grants(db: StateDB, legacy_path: Path | None = None) -> bool:
    """Apply ``grants-v1`` once.

    Returns True the first time and False after that. Active entries in
    a legacy file are not copied. Revoked entries are stored as revoked
    so a later load cannot treat them as live.
    """
    ensure_schema(db)
    if migration_applied(db):
        return False
    if legacy_path is not None and legacy_path.is_file():
        _import_revoked(db, legacy_path)
    db.conn.execute(
        "INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)",
        (_MIGRATION, datetime.now(UTC).isoformat(timespec="seconds")),
    )
    db.conn.commit()
    return True


def _import_revoked(db: StateDB, path: Path) -> None:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return
    if not isinstance(loaded, dict):
        return
    revoked = loaded.get("revoked", [])
    if not isinstance(revoked, list):
        return
    for item in revoked:
        if not isinstance(item, str) or item.count(":") < 2:
            continue
        account, session, key = item.split(":", 2)
        if not account or not session or not key:
            continue
        db.conn.execute(
            """
            INSERT INTO session_grants (
                account_id, session_id, grant_key, profile_id, revoked
            ) VALUES (?, ?, ?, '', 1)
            ON CONFLICT (account_id, session_id, grant_key)
            DO UPDATE SET revoked = 1
            """,
            (account, session, key),
        )


def save_grant(
    db: StateDB,
    *,
    account_id: str,
    session_id: str,
    grant_key: str,
    profile_id: str,
) -> None:
    if not account_id or not session_id or not grant_key:
        return
    ensure_schema(db)
    db.conn.execute(
        """
        INSERT INTO session_grants (
            account_id, session_id, grant_key, profile_id, revoked
        ) VALUES (?, ?, ?, ?, 0)
        ON CONFLICT (account_id, session_id, grant_key)
        DO UPDATE SET revoked = 0, profile_id = excluded.profile_id
        """,
        (account_id, session_id, grant_key, profile_id),
    )
    db.conn.commit()


def revoke_grant(
    db: StateDB,
    *,
    account_id: str,
    session_id: str,
    grant_key: str,
) -> None:
    ensure_schema(db)
    db.conn.execute(
        """
        UPDATE session_grants SET revoked = 1
        WHERE account_id = ? AND session_id = ? AND grant_key = ?
        """,
        (account_id, session_id, grant_key),
    )
    db.conn.commit()


def load_live_grants(db: StateDB) -> list[tuple[str, str, str]]:
    """Rows that are not revoked: account, session, grant key."""
    ensure_schema(db)
    rows = db.conn.execute(
        """
        SELECT account_id, session_id, grant_key FROM session_grants
        WHERE revoked = 0
        ORDER BY account_id, session_id, grant_key
        """
    ).fetchall()
    return [(str(row[0]), str(row[1]), str(row[2])) for row in rows]


def is_revoked(db: StateDB, *, account_id: str, session_id: str, grant_key: str) -> bool:
    ensure_schema(db)
    row = db.conn.execute(
        """
        SELECT revoked FROM session_grants
        WHERE account_id = ? AND session_id = ? AND grant_key = ?
        """,
        (account_id, session_id, grant_key),
    ).fetchone()
    return row is not None and int(row[0]) == 1
