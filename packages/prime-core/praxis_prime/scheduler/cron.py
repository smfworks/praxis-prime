"""Cron and interval triggers in the user's timezone.

Five fields, ``minute hour day-of-month month day-of-week``, plus
``@every``. The smallest gap is one minute. Day-of-month and day-of-week
combine the way Vixie cron does: when both are restricted, either match
is enough.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from praxis_prime.clock import as_utc

_MIN_SECONDS = 60
_DOW = {
    "sun": 0,
    "mon": 1,
    "tue": 2,
    "wed": 3,
    "thu": 4,
    "fri": 5,
    "sat": 6,
}
_MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class ScheduleError(ValueError):
    """The trigger expression is not usable."""


@dataclass(frozen=True, slots=True)
class CronExpr:
    minutes: frozenset[int]
    hours: frozenset[int]
    days: frozenset[int]
    months: frozenset[int]
    weekdays: frozenset[int]
    day_any: bool
    weekday_any: bool

    def matches(self, local: datetime) -> bool:
        if local.minute not in self.minutes or local.hour not in self.hours:
            return False
        if local.month not in self.months:
            return False
        day_ok = local.day in self.days
        weekday = (local.weekday() + 1) % 7
        weekday_ok = weekday in self.weekdays
        if self.day_any and self.weekday_any:
            return True
        if self.day_any:
            return weekday_ok
        if self.weekday_any:
            return day_ok
        return day_ok or weekday_ok


def timezone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ScheduleError(f"unknown timezone {name}") from exc


def parse_every(expr: str) -> int:
    """Return seconds for ``15m`` or ``@every 15m``. Rejects gaps under a minute."""
    text = expr.strip().lower()
    if text.startswith("@every"):
        text = text[len("@every") :].strip()
    if not text:
        raise ScheduleError("@every needs a duration such as 15m")
    unit = text[-1]
    number = text[:-1].strip()
    if unit not in _UNITS or not number.isdigit():
        raise ScheduleError(f"duration {expr!r} must look like 15m, 1h, or 1d")
    seconds = int(number) * _UNITS[unit]
    if seconds < _MIN_SECONDS:
        raise ScheduleError("minimum interval is 1 minute")
    return seconds


def parse_cron(expr: str) -> CronExpr:
    fields = expr.split()
    if len(fields) != 5:
        raise ScheduleError(
            f"cron {expr!r} needs 5 fields: minute hour day-of-month month day-of-week"
        )
    minutes, minute_any = _field(fields[0], 0, 59, None)
    hours, _hour_any = _field(fields[1], 0, 23, None)
    days, day_any = _field(fields[2], 1, 31, None)
    months, _month_any = _field(fields[3], 1, 12, _MONTHS)
    weekdays, weekday_any = _field(fields[4], 0, 6, _DOW, dow=True)
    del minute_any
    return CronExpr(
        minutes=minutes,
        hours=hours,
        days=days,
        months=months,
        weekdays=weekdays,
        day_any=day_any,
        weekday_any=weekday_any,
    )


def next_cron(expr: str, after: datetime, tz: ZoneInfo) -> datetime:
    """Next fire strictly after ``after``, returned in UTC."""
    schedule = parse_cron(expr)
    local = as_utc(after).astimezone(tz)
    candidate = local.replace(second=0, microsecond=0) + timedelta(minutes=1)
    for _ in range(366 * 24 * 60):
        if schedule.matches(candidate):
            return candidate.astimezone(UTC)
        candidate += timedelta(minutes=1)
    raise ScheduleError(f"cron {expr!r} has no match within a year")


def next_interval(after: datetime, seconds: int, anchor: datetime) -> datetime:
    """Next boundary of ``seconds`` strictly after ``after``, from ``anchor``."""
    if seconds < _MIN_SECONDS:
        raise ScheduleError("minimum interval is 1 minute")
    start = as_utc(anchor)
    moment = as_utc(after)
    if moment < start:
        return start
    elapsed = (moment - start).total_seconds()
    steps = int(elapsed // seconds) + 1
    return start + timedelta(seconds=steps * seconds)


def _field(
    expr: str,
    low: int,
    high: int,
    names: dict[str, int] | None,
    *,
    dow: bool = False,
) -> tuple[frozenset[int], bool]:
    text = expr.strip().lower()
    if text in {"*", "?"}:
        return frozenset(range(low, high + 1)), True
    values: set[int] = set()
    for part in text.split(","):
        piece = part.strip()
        if not piece:
            raise ScheduleError(f"empty cron field in {expr!r}")
        step = 1
        base = piece
        if "/" in piece:
            base, step_text = piece.split("/", 1)
            if not step_text.isdigit() or int(step_text) < 1:
                raise ScheduleError(f"bad step in {expr!r}")
            step = int(step_text)
        if base in {"*", "?"}:
            start, end = low, high
        elif "-" in base:
            left, right = base.split("-", 1)
            start = _number(left, low, high, names, dow=dow)
            end = _number(right, low, high, names, dow=dow)
            if end < start:
                raise ScheduleError(f"reversed range in {expr!r}")
        else:
            start = end = _number(base, low, high, names, dow=dow)
        for value in range(start, end + 1, step):
            if low <= value <= high:
                values.add(value)
    if not values:
        raise ScheduleError(f"cron field {expr!r} matched nothing")
    return frozenset(values), False


def _number(
    token: str,
    low: int,
    high: int,
    names: dict[str, int] | None,
    *,
    dow: bool,
) -> int:
    key = token.strip().lower()
    if names and key in names:
        return names[key]
    if not key.isdigit():
        raise ScheduleError(f"bad cron value {token!r}")
    value = int(key)
    if dow and value == 7:
        value = 0
    if value < low or value > high:
        raise ScheduleError(f"cron value {token!r} is outside {low}-{high}")
    return value
