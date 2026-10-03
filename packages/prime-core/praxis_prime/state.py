"""SQLite state file under the XDG data directory.

Sessions and the audit log share ``prime.db``. Chat writes use this
connection. The audit log opens its own connection so a chat transaction
cannot nest inside an audit ``BEGIN IMMEDIATE``. ``check_same_thread`` is
off because the daemon uses the connection from more than one thread.

TODO: ARCHITECTURE §10 and §18. FTS5, sqlite-vec, and a separate ``audit.db``
are later work. This module is the MVP store.
"""

from __future__ import annotations

import fcntl
import os
import sqlite3
from collections.abc import Mapping
from pathlib import Path

from praxis_prime.paths import data_dir

DB_FILENAME = "prime.db"


class DatabaseBusy(RuntimeError):
    """Another process holds the shared lock on this database."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.lock_path = db_lock_path(self.db_path)
        super().__init__(
            f"{self.db_path.name} is open in another process ({self.lock_path}). "
            "Stop praxis-primed and any local chat before migrating. "
            "--force does not override an open database."
        )


class MigrationInProgress(RuntimeError):
    """An opener refused to wait on, or recreate, a database mid-migration."""

    def __init__(self, detail: str = "migration in progress") -> None:
        super().__init__(detail)


def db_lock_path(path: Path) -> Path:
    """Sidecar flock held for as long as ``path`` is open."""
    return Path(f"{path}.lock")


_LOCK_ATTEMPTS = 8


def _open_lock_fd(db_path: Path) -> int:
    lock = db_lock_path(db_path)
    lock.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(lock, flags, 0o600)


def _open_dir_fd(directory: Path) -> int:
    directory.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    return os.open(directory, flags)


def _fd_is_path(fd: int, path: Path) -> bool:
    """True when ``fd`` still names the inode at ``path``."""
    try:
        held = os.fstat(fd)
        current = os.lstat(path)
    except OSError:
        return False
    return (held.st_dev, held.st_ino) == (current.st_dev, current.st_ino)


def _close_fd(fd: int) -> None:
    if fd < 0:
        return
    try:
        os.close(fd)
    except OSError:
        pass


def _acquire_db_lock(db_path: Path, *, exclusive: bool) -> list[int]:
    """Lock the sidecar and its parent directory. Caller closes both fds.

    The flock is on the sidecar's inode. Replacing that file with
    unlink and create would let a new opener lock a different inode and
    migration would no longer see the holder. The opener retries until
    ``fstat`` matches ``lstat`` of the path, and both sides flock the
    parent directory so a replacement cannot drop the migration lock
    while a holder remains.

    A shared opener takes the file descriptor first and the directory
    lock only after ``_open_lock_fd`` returns. An exclusive opener takes
    the directory first. Two shared locks do not block each other.
    """
    lock = db_lock_path(db_path)
    mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    flag = mode | fcntl.LOCK_NB
    for _attempt in range(_LOCK_ATTEMPTS):
        file_fd = -1
        dir_fd = -1
        try:
            if exclusive:
                dir_fd = _open_dir_fd(lock.parent)
                fcntl.flock(dir_fd, flag)
                file_fd = _open_lock_fd(db_path)
                fcntl.flock(file_fd, flag)
            else:
                file_fd = _open_lock_fd(db_path)
                dir_fd = _open_dir_fd(lock.parent)
                fcntl.flock(dir_fd, flag)
                fcntl.flock(file_fd, flag)
        except BlockingIOError:
            _close_fd(file_fd)
            _close_fd(dir_fd)
            if exclusive:
                raise DatabaseBusy(db_path) from None
            raise MigrationInProgress("migration in progress") from None
        except OSError:
            _close_fd(file_fd)
            _close_fd(dir_fd)
            raise
        if _fd_is_path(file_fd, lock):
            return [dir_fd, file_fd]
        _close_fd(file_fd)
        _close_fd(dir_fd)
    raise MigrationInProgress("database lock changed while opening")


def acquire_exclusive_db_locks(paths: list[Path]) -> list[int]:
    """Non-blocking exclusive locks. The caller closes every returned fd.

    A shared lock from ``StateDB`` in another process makes this raise
    ``DatabaseBusy`` and drops any locks already taken. Each database
    contributes its parent-directory fd and its sidecar fd.
    """
    held: list[int] = []
    try:
        for db_path in paths:
            held.extend(_acquire_db_lock(db_path, exclusive=True))
    except Exception:
        release_db_locks(held)
        raise
    return held


def release_db_locks(fds: list[int]) -> None:
    for fd in fds:
        if fd < 0:
            continue
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass


def refuse_misplaced_database(path: Path) -> None:
    """Refuse ``<account-root>/profiles/prime.db``, or an illegal profile id.

    ``--data-dir <data>/profiles`` would otherwise create
    ``profiles/prime.db`` beside the real profile folders. A data directory
    that is itself named ``profiles``, and is not that folder inside an
    account root, is a normal data directory. A folder such as
    ``profiles/Bad_Name`` is not a profile id and must not open without
    profile scoping.
    """
    candidate = Path(path)
    if candidate.name != DB_FILENAME:
        return
    parent = candidate.parent
    if parent.name == "profiles" and _profiles_tree_inside_account_root(parent):
        raise ValueError(
            "refusing to use a profiles directory as the data directory; "
            "pass the account data root"
        )
    if parent.parent.name != "profiles":
        return
    from praxis_prime.profiles.ids import profile_id

    if profile_id(parent.name) is None:
        raise ValueError(f"invalid profile id {parent.name!r}")


def _profiles_tree_inside_account_root(profiles_dir: Path) -> bool:
    """True when ``profiles_dir`` is the profile tree of an account root.

    A directory that is merely named ``profiles`` is not that tree. The
    default XDG data directory counts even before it holds files, and so
    does a parent that already has account data or profile folders.
    """
    account = profiles_dir.parent
    try:
        if account.resolve() == Path(data_dir()).resolve():
            return True
    except (OSError, RuntimeError, ValueError):
        return True
    for name in ("accounts.db", "audit.db", "backups", "SOUL.md", "prime.db"):
        if _path_exists(account / name):
            return True
    try:
        children = list(profiles_dir.iterdir())
    except OSError:
        return True
    from praxis_prime.profiles.ids import profile_id

    return any(child.is_dir() and profile_id(child.name) is not None for child in children)


def _path_exists(path: Path) -> bool:
    try:
        os.lstat(path)
    except OSError:
        return False
    return True


def default_db_path(env: Mapping[str, str] | None = None) -> Path:
    """Pre-migration path ``<data>/prime.db``.

    Openers use ``resolve_runtime_layout``. After the marker exists, that
    opens ``profiles/default/prime.db`` instead of this file.
    """
    return data_dir(env) / DB_FILENAME


def data_root_for_database(path: Path) -> Path:
    """Data directory that owns ``path``.

    Profile files live at ``<root>/profiles/<id>/prime.db``. Every other
    database is treated as the legacy file directly under its parent.
    """
    candidate = Path(path)
    if candidate.name == DB_FILENAME and candidate.parent.parent.name == "profiles":
        return candidate.parent.parent.parent
    return candidate.parent


def refuse_if_migrating(path: Path) -> None:
    """CLI and daemon openers call this before they create a database file."""
    from praxis_prime.profiles.migrate import migration_in_progress

    root = data_root_for_database(path)
    if migration_in_progress(root):
        raise MigrationInProgress("migration in progress")
    if _legacy_path_closed(path, root):
        moved = root / "profiles" / "default" / DB_FILENAME
        raise MigrationInProgress(f"this database moved to {moved} after migration")


def _legacy_path_closed(path: Path, root: Path) -> bool:
    """True when ``path`` is the pre-move ``prime.db`` and the marker exists.

    Opening it would create a fresh empty file beside the database that
    already moved under ``profiles/default``.
    """
    if Path(path) != Path(root) / DB_FILENAME:
        return False
    from praxis_prime.profiles.home import migration_marker
    from praxis_prime.statfile import StatKind, lstat_kind

    return lstat_kind(migration_marker(root)) is StatKind.FILE


class StateDB:
    """One WAL connection and the schema for sessions plus the audit chain.

    The process holds a shared flock on ``<path>.lock`` and on the parent
    directory until ``close``. The lock is non-blocking: an exclusive
    migration lock fails the open with ``migration in progress`` instead
    of waiting and then creating a new file at a path chosen before the
    move. Migration takes that file exclusively and refuses when it is held.

    ``allow_during_migration`` is only for ``create_profile`` while the
    move itself is creating ``profiles/default/prime.db``. Callers other
    than that move leave it false.
    """

    def __init__(self, path: Path, *, allow_during_migration: bool = False) -> None:
        self.path = Path(path)
        self._lock_fds: list[int] = []
        from praxis_prime.supervisor.confine import refuse_worker_path

        refuse_worker_path(self.path)
        refuse_misplaced_database(self.path)
        if not allow_during_migration:
            refuse_if_migrating(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_fds = _acquire_db_lock(self.path, exclusive=False)
        conn: sqlite3.Connection | None = None
        try:
            if not allow_during_migration:
                refuse_if_migrating(self.path)
            conn = sqlite3.connect(self.path, check_same_thread=False)
            self.conn = conn
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.execute("PRAGMA busy_timeout=5000")
            self._migrate()
        except Exception:
            if conn is not None:
                conn.close()
            self._release_lock()
            raise

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
        self._release_lock()

    def _release_lock(self) -> None:
        fds = self._lock_fds
        self._lock_fds = []
        release_db_locks(fds)
