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
                hash TEXT NOT NULL,
                actor_account TEXT NOT NULL DEFAULT '',
                profile TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS memory_entries (
                id TEXT PRIMARY KEY,
                tier TEXT NOT NULL,
                scope TEXT NOT NULL,
                content TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                source TEXT NOT NULL,
                session_id TEXT NOT NULL DEFAULT '',
                channel TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                expires_at TEXT NOT NULL DEFAULT '',
                embedding_json TEXT NOT NULL DEFAULT ''
            );

            CREATE UNIQUE INDEX IF NOT EXISTS memory_dedupe
                ON memory_entries(tier, scope, content_hash);

            CREATE INDEX IF NOT EXISTS memory_session_idx
                ON memory_entries(tier, session_id);

            CREATE TABLE IF NOT EXISTS routines (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                prompt TEXT NOT NULL,
                trigger_kind TEXT NOT NULL,
                trigger_expr TEXT NOT NULL,
                timezone TEXT NOT NULL,
                missed_policy TEXT NOT NULL,
                min_interval_seconds INTEGER NOT NULL,
                max_iterations INTEGER NOT NULL,
                max_usd REAL,
                skill TEXT NOT NULL DEFAULT '',
                deliver TEXT NOT NULL DEFAULT 'none',
                paused INTEGER NOT NULL DEFAULT 0,
                scope TEXT NOT NULL DEFAULT 'global',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                next_fire_at TEXT NOT NULL DEFAULT '',
                last_fire_at TEXT NOT NULL DEFAULT '',
                watch_token TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS routine_runs (
                id TEXT PRIMARY KEY,
                routine_id TEXT NOT NULL,
                session_id TEXT NOT NULL DEFAULT '',
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                outcome TEXT NOT NULL,
                summary TEXT NOT NULL DEFAULT '',
                trigger TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS routine_runs_idx
                ON routine_runs(routine_id, started_at);

            CREATE TABLE IF NOT EXISTS breach_records (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                pack TEXT NOT NULL,
                summary TEXT NOT NULL,
                affected_count INTEGER NOT NULL,
                status TEXT NOT NULL,
                notice_draft TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS dial_positions (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                positions_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        self._ensure_column(
            "audit_events",
            "actor_account",
            "actor_account TEXT NOT NULL DEFAULT ''",
        )
        self._ensure_column(
            "audit_events",
            "profile",
            "profile TEXT NOT NULL DEFAULT ''",
        )
        self._ensure_column(
            "sessions",
            "owner_account",
            "owner_account TEXT NOT NULL DEFAULT ''",
        )
        self._ensure_column(
            "sessions",
            "owner_profile",
            "owner_profile TEXT NOT NULL DEFAULT ''",
        )
        self.conn.commit()

    def _ensure_column(self, table: str, column: str, declaration: str) -> None:
        rows = self.conn.execute(f"PRAGMA table_info({table})").fetchall()
        names = {str(row[1]) for row in rows}
        if column not in names:
            self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {declaration}")

    def close(self) -> None:
        self.conn.close()
