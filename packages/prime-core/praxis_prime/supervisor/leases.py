"""One lease per routine run.

A crashed worker leaves the lease in place. After it expires the next
start may retry once. A second expiry does not start another run, and a
live lease blocks a second runner. The worker renews a lease it still
holds so a run longer than the interval is not treated as finished.

``acquire`` takes ``BEGIN IMMEDIATE`` so two runners cannot both observe
an empty row and both insert. The clock is read inside that transaction.
The token returned with ``run`` or ``retry`` is checked on ``renew`` and
``release``.
"""

from __future__ import annotations

import secrets
import threading
from collections.abc import Callable

from praxis_prime.state import StateDB

Clock = Callable[[], float]
_LEASE_SECONDS = 30.0
# Two processes can sample the clock a few milliseconds apart. That is not
# a reboot. A backwards monotonic clock still clears this slack.
_CLOCK_SKEW_SECONDS = 1.0


def _lease_expired(until: float, now: float, ttl: float) -> bool:
    """True when ``until`` has passed, or the clock jumped backwards.

    The sample is taken inside ``BEGIN IMMEDIATE``. A waiter whose clock is
    only ``_CLOCK_SKEW_SECONDS`` behind the holder still sees a live lease.
    """
    return until <= now or until > now + ttl + _CLOCK_SKEW_SECONDS


def ensure_schema(db: StateDB) -> None:
    db.conn.execute(
        """
        CREATE TABLE IF NOT EXISTS routine_leases (
            routine_id TEXT PRIMARY KEY,
            owner TEXT NOT NULL,
            lease_until REAL NOT NULL,
            attempts INTEGER NOT NULL,
            token TEXT NOT NULL DEFAULT ''
        )
        """
    )
    columns = {str(row[1]) for row in db.conn.execute("PRAGMA table_info(routine_leases)")}
    if "token" not in columns:
        db.conn.execute(
            "ALTER TABLE routine_leases ADD COLUMN token TEXT NOT NULL DEFAULT ''"
        )
    db.conn.commit()


class LeaseStore:
    """SQLite leases. ``clock`` returns seconds, so tests can move time."""

    def __init__(self, db: StateDB, *, clock: Clock, ttl: float = _LEASE_SECONDS) -> None:
        self.db = db
        self.clock = clock
        self.ttl = ttl
        self._lock = threading.Lock()
        ensure_schema(db)

    def acquire(self, routine_id: str, owner: str) -> tuple[str, str]:
        """Return ``(decision, token)``.

        ``decision`` is ``run``, ``retry``, or ``skip``. ``token`` is empty
        when the decision is ``skip``. ``skip`` means the lease is still
        live, including for this owner, or the one allowed retry already
        happened.
        """
        with self._lock:
            return self._acquire(routine_id, owner)

    def _acquire(self, routine_id: str, owner: str) -> tuple[str, str]:
        token = secrets.token_hex(16)
        self.db.conn.execute("BEGIN IMMEDIATE")
        try:
            now = self.clock()
            row = self.db.conn.execute(
                """
                SELECT owner, lease_until, attempts, token
                FROM routine_leases WHERE routine_id = ?
                """,
                (routine_id,),
            ).fetchone()
            if row is None:
                self._write(routine_id, owner, now + self.ttl, 0, token)
                self.db.conn.commit()
                return "run", token
            until = float(row[1])
            attempts = int(row[2])
            # A lease that ends further ahead than a fresh one, past a small
            # skew, is a clock that moved backwards (a monotonic value stored
            # across a reboot). Treat it as expired so the one retry still
            # happens. A waiter a millisecond behind does not.
            expired = _lease_expired(until, now, self.ttl)
            if not expired or attempts >= 1:
                self.db.conn.rollback()
                return "skip", ""
            self._write(routine_id, owner, now + self.ttl, 1, token)
            self.db.conn.commit()
            return "retry", token
        except Exception:
            self.db.conn.rollback()
            raise

    def renew(self, routine_id: str, owner: str, token: str) -> bool:
        """Extend a lease this owner still holds. Return False when it was lost.

        ``attempts`` is left as it is. A missing row, a different owner, a
        different token, an expiry, or a lease that ends further ahead than
        a fresh one is not extended.
        """
        with self._lock:
            return self._renew(routine_id, owner, token)

    def _renew(self, routine_id: str, owner: str, token: str) -> bool:
        if not token:
            return False
        self.db.conn.execute("BEGIN IMMEDIATE")
        try:
            now = self.clock()
            row = self.db.conn.execute(
                """
                SELECT owner, lease_until, attempts, token
                FROM routine_leases WHERE routine_id = ?
                """,
                (routine_id,),
            ).fetchone()
            if row is None or str(row[0]) != owner or str(row[3]) != token:
                self.db.conn.rollback()
                return False
            until = float(row[1])
            if _lease_expired(until, now, self.ttl):
                self.db.conn.rollback()
                return False
            updated = self.db.conn.execute(
                """
                UPDATE routine_leases
                SET lease_until = ?
                WHERE routine_id = ? AND owner = ? AND token = ?
                """,
                (now + self.ttl, routine_id, owner, token),
            )
            if updated.rowcount != 1:
                self.db.conn.rollback()
                return False
            self.db.conn.commit()
            return True
        except Exception:
            self.db.conn.rollback()
            raise

    def release(self, routine_id: str, owner: str, token: str) -> bool:
        """Drop the lease after a clean finish. A wrong token leaves it."""
        with self._lock:
            return self._release(routine_id, owner, token)

    def _release(self, routine_id: str, owner: str, token: str) -> bool:
        if not token:
            return False
        self.db.conn.execute("BEGIN IMMEDIATE")
        try:
            deleted = self.db.conn.execute(
                """
                DELETE FROM routine_leases
                WHERE routine_id = ? AND owner = ? AND token = ?
                """,
                (routine_id, owner, token),
            )
            if deleted.rowcount != 1:
                self.db.conn.rollback()
                return False
            self.db.conn.commit()
            return True
        except Exception:
            self.db.conn.rollback()
            raise

    def _write(
        self,
        routine_id: str,
        owner: str,
        until: float,
        attempts: int,
        token: str,
    ) -> None:
        self.db.conn.execute(
            """
            INSERT INTO routine_leases (routine_id, owner, lease_until, attempts, token)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (routine_id) DO UPDATE SET
                owner = excluded.owner,
                lease_until = excluded.lease_until,
                attempts = excluded.attempts,
                token = excluded.token
            """,
            (routine_id, owner, until, attempts, token),
        )
