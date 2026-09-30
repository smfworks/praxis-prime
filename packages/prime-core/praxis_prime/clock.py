"""UTC timestamps shared by routines and memory.

Callers pass a ``now`` function in tests so cron, decay, and retention do
not depend on the wall clock.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

Now = Callable[[], datetime]


def utcnow() -> datetime:
    return datetime.now(UTC)


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def dump_time(value: datetime) -> str:
    return as_utc(value).isoformat()


def load_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return as_utc(parsed)
