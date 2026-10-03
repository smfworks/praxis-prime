"""One lease per routine run.

A crashed worker leaves the lease in place. After it expires the next
start may retry once. A second expiry does not start another run, and a
live lease blocks a second runner.
"""

from __future__ import annotations

from collections.abc import Callable

from praxis_prime.state import StateDB

Clock = Callable[[], float]
_LEASE_SECONDS = 30.0


def ensure_schema(db: StateDB) -> None:
    db.conn.execute(
        """
        CREATE TABLE IF NOT EXISTS routine_leases (
            routine_id TEXT PRIMARY KEY,
            owner TEXT NOT NULL,
            lease_until REAL NOT NULL,
            attempts INTEGER NOT NULL
        )
        """
    )
    db.conn.commit()


class LeaseStore:
    """SQLite leases. ``clock`` returns seconds, so tests can move time."""

    def __init__(self, db: StateDB, *, clock: Clock, ttl: float = _LEASE_SECONDS) -> None:
        self.db = db
        self.clock = clock
        self.ttl = ttl
        ensure_schema(db)

    def acquire(self, routine_id: str, owner: str) -> str:
        """Return ``run``, ``retry``, or ``skip``.

        ``skip`` means another runner holds the lease, or the one allowed
        retry already happened.
        """
        now = self.clock()
        row = self.db.conn.execute(
            "SELECT owner, lease_until, attempts FROM routine_leases WHERE routine_id = ?",
            (routine_id,),
        ).fetchone()
        if row is None:
            self._write(routine_id, owner, now + self.ttl, 0)
            return "run"
        held_by = str(row[0])
        until = float(row[1])
        attempts = int(row[2])
        if until > now and held_by != owner:
            return "skip"
        if until > now and held_by == owner:
            return "run"
        if attempts >= 1:
            return "skip"
        self._write(routine_id, owner, now + self.ttl, 1)
        return "retry"

    def release(self, routine_id: str) -> None:
        """Drop the lease after a clean finish so the next schedule is fresh."""
        self.db.conn.execute(
            "DELETE FROM routine_leases WHERE routine_id = ?",
            (routine_id,),
        )
        self.db.conn.commit()

    def _write(self, routine_id: str, owner: str, until: float, attempts: int) -> None:
        self.db.conn.execute(
            """
            INSERT INTO routine_leases (routine_id, owner, lease_until, attempts)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (routine_id) DO UPDATE SET
                owner = excluded.owner,
                lease_until = excluded.lease_until,
                attempts = excluded.attempts
            """,
            (routine_id, owner, until, attempts),
        )
        self.db.conn.commit()
