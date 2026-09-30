"""Cron and interval parsing. Times are fixed; nothing calls a model."""

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from praxis_prime.scheduler.cron import (
    ScheduleError,
    next_cron,
    next_interval,
    parse_cron,
    parse_every,
    timezone,
)

_NY = ZoneInfo("America/New_York")


def test_next_cron_uses_the_local_timezone():
    winter = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
    assert next_cron("0 8 * * *", winter, _NY) == datetime(2026, 1, 15, 13, 0, tzinfo=UTC)

    summer = datetime(2026, 7, 15, 12, 0, tzinfo=UTC)
    assert next_cron("0 8 * * *", summer, _NY) == datetime(2026, 7, 16, 12, 0, tzinfo=UTC)


def test_weekday_cron_lands_on_the_next_matching_morning():
    after = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
    nxt = next_cron("0 9 * * 1", after, _NY)
    assert nxt == datetime(2026, 10, 5, 13, 0, tzinfo=UTC)
    local = nxt.astimezone(_NY)
    assert local.weekday() == 0
    assert local.hour == 9


def test_names_sunday_seven_and_vixie_or():
    named = parse_cron("0 9 * jan mon")
    assert named.hours == frozenset({9})
    assert named.months == frozenset({1})
    assert named.weekdays == frozenset({1})
    assert 0 in parse_cron("0 0 * * 7").weekdays
    assert 0 in parse_cron("0 0 * * sun").weekdays

    either = parse_cron("0 0 1 * 1")
    thursday = datetime(2026, 1, 1, 0, 0, tzinfo=_NY)
    monday = datetime(2026, 1, 5, 0, 0, tzinfo=_NY)
    friday = datetime(2026, 1, 2, 0, 0, tzinfo=_NY)
    assert either.matches(thursday)
    assert either.matches(monday)
    assert not either.matches(friday)


def test_interval_is_exclusive_of_the_boundary_and_rejects_sub_minute():
    anchor = datetime(2026, 1, 1, tzinfo=UTC)
    on_boundary = anchor + timedelta(minutes=15)
    assert next_interval(on_boundary, 15 * 60, anchor) == anchor + timedelta(minutes=30)
    assert parse_every("@every 15m") == 900
    assert parse_every("1h") == 3600
    with pytest.raises(ScheduleError):
        parse_every("30s")
    with pytest.raises(ScheduleError):
        parse_cron("0 8 * *")
    with pytest.raises(ScheduleError):
        timezone("Not/AZone")
