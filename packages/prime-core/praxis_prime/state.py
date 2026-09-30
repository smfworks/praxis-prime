"""SQLite state file under the XDG data directory.

Sessions and the audit log share ``prime.db``. The daemon is the writer
when it is running. ``check_same_thread`` is off because the daemon
serializes every use of this connection on one lock.

TODO: ARCHITECTURE §10 and §18. FTS5, sqlite-vec, and a separate ``audit.db``
are later work. This module is the MVP store.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from pathlib import Path

from praxis_prime.paths import data_dir

DB_FILENAME = "prime.db"


def default_db_path(env: Mapping[str, str] | None = None) -> Path:
    return data_dir(env) / DB_FILENAME


class StateDB:
    """One WAL connection and the schema for sessions plus the audit chain."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    def _migrate(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                model TEXT NOT NULL,
                title TEXT NOT NULL DEFAULT '',
                preamble TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                tool_call_id TEXT,
                tool_calls_json TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS messages_session_idx
                ON messages(session_id, id);

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                created_at TEXT NOT NULL,
                kind TEXT NOT NULL,
                summary TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
