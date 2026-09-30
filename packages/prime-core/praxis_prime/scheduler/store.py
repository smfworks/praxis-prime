"""SQLite routines and run history.

ARCHITECTURE §11. Each routine is a prompt plus a trigger, a missed-run
policy, a budget, and an optional skill and delivery target.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from praxis_prime.clock import Now, dump_time, load_time, utcnow
from praxis_prime.scheduler.cron import (
    ScheduleError,
    next_cron,
    next_interval,
    parse_cron,
    parse_every,
    timezone,
)
from praxis_prime.state import StateDB

_MISSED = {"skip", "once"}
_KINDS = {"cron", "interval", "file", "webhook"}


@dataclass(frozen=True, slots=True)
class Routine:
    id: str
    name: str
    prompt: str
    trigger_kind: str
    trigger_expr: str
    timezone_name: str
    missed_policy: str
    min_interval_seconds: int
    max_iterations: int
    max_usd: float | None
    skill: str
    deliver: str
    paused: bool
    scope: str
    created_at: str
    updated_at: str
    next_fire_at: str
    last_fire_at: str
    watch_token: str

    def public(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "prompt": self.prompt,
            "trigger": self.trigger_kind,
            "expr": self.trigger_expr,
            "timezone": self.timezone_name,
            "missed": self.missed_policy,
            "min_interval_seconds": self.min_interval_seconds,
            "max_iterations": self.max_iterations,
            "max_usd": self.max_usd,
            "skill": self.skill,
            "deliver": self.deliver,
            "paused": self.paused,
            "scope": self.scope,
            "next_fire_at": self.next_fire_at,
            "last_fire_at": self.last_fire_at,
        }


@dataclass(frozen=True, slots=True)
class RoutineRun:
    id: str
    routine_id: str
    session_id: str
    started_at: str
    finished_at: str
    outcome: str
    summary: str
    trigger: str

    def public(self) -> dict[str, object]:
        return {
            "id": self.id,
            "routine_id": self.routine_id,
            "session_id": self.session_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "outcome": self.outcome,
            "summary": self.summary,
            "trigger": self.trigger,
        }


class RoutineStore:
    def __init__(self, db: StateDB, *, clock: Now | None = None) -> None:
        self.db = db
        self.clock = clock or utcnow

    def add(self, **fields: object) -> Routine:
        kind = str(fields["trigger_kind"])
        expr = str(fields["trigger_expr"])
        tz_name = str(fields.get("timezone_name") or "UTC")
        if kind not in _KINDS:
            raise ScheduleError(f"unknown trigger {kind}")
        missed = str(fields.get("missed_policy") or "skip")
        if missed not in _MISSED:
            raise ScheduleError("missed policy must be skip or once")
        minimum = int(fields.get("min_interval_seconds") or 60)
        if minimum < 60:
            raise ScheduleError("minimum interval is 1 minute")
        self._validate(kind, expr, tz_name)
        now = dump_time(self.clock())
        routine_id = f"rt_{uuid.uuid4().hex[:8]}"
        max_usd = fields.get("max_usd")
        usd = float(max_usd) if isinstance(max_usd, int | float) else None
        next_fire = ""
        if kind in {"cron", "interval"}:
            next_fire = dump_time(self.next_fire_at(kind, expr, tz_name, self.clock(), now))
        self.db.conn.execute(
            """
            INSERT INTO routines (
                id, name, prompt, trigger_kind, trigger_expr, timezone, missed_policy,
                min_interval_seconds, max_iterations, max_usd, skill, deliver, paused,
                scope, created_at, updated_at, next_fire_at, last_fire_at, watch_token
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, '', ?)
            """,
            (
                routine_id,
                str(fields.get("name") or "routine"),
                str(fields["prompt"]),
                kind,
                expr,
                tz_name,
                missed,
                minimum,
                int(fields.get("max_iterations") or 20),
                usd,
                str(fields.get("skill") or ""),
                str(fields.get("deliver") or "none"),
                str(fields.get("scope") or "global"),
                now,
                now,
                next_fire,
                str(fields.get("watch_token") or ""),
            ),
        )
        self.db.conn.commit()
        return self.get(routine_id)

    def get(self, routine_id: str) -> Routine:
        row = self.db.conn.execute(
            "SELECT * FROM routines WHERE id = ?",
            (routine_id,),
        ).fetchone()
        if row is None:
            raise LookupError(f"no routine {routine_id}")
        return _routine(row)

    def list_routines(self) -> list[Routine]:
        rows = self.db.conn.execute(
            "SELECT * FROM routines ORDER BY name, id"
        ).fetchall()
        return [_routine(row) for row in rows]

    def update(self, routine_id: str, **fields: object) -> Routine:
        current = self.get(routine_id)
        kind = str(fields.get("trigger_kind") or current.trigger_kind)
        expr = str(fields.get("trigger_expr") or current.trigger_expr)
        tz_name = str(fields.get("timezone_name") or current.timezone_name)
        missed = str(fields.get("missed_policy") or current.missed_policy)
        if missed not in _MISSED:
            raise ScheduleError("missed policy must be skip or once")
        self._validate(kind, expr, tz_name)
        now_dt = self.clock()
        now = dump_time(now_dt)
        next_fire = current.next_fire_at
        trigger_changed = (
            kind != current.trigger_kind
            or expr != current.trigger_expr
            or tz_name != current.timezone_name
        )
        if kind in {"cron", "interval"} and trigger_changed:
            upcoming = self.next_fire_at(kind, expr, tz_name, now_dt, current.created_at)
            next_fire = dump_time(upcoming)
        if kind in {"file", "webhook"}:
            next_fire = ""
        max_usd = fields["max_usd"] if "max_usd" in fields else current.max_usd
        usd = float(max_usd) if isinstance(max_usd, int | float) else None
        self.db.conn.execute(
            """
            UPDATE routines SET
                name = ?, prompt = ?, trigger_kind = ?, trigger_expr = ?, timezone = ?,
                missed_policy = ?, max_iterations = ?, max_usd = ?, skill = ?, deliver = ?,
                scope = ?, updated_at = ?, next_fire_at = ?, watch_token = ?
            WHERE id = ?
            """,
            (
                str(fields.get("name") or current.name),
                str(fields.get("prompt") or current.prompt),
                kind,
                expr,
                tz_name,
                missed,
                int(fields.get("max_iterations") or current.max_iterations),
                usd,
                str(fields.get("skill") if "skill" in fields else current.skill),
                str(fields.get("deliver") or current.deliver),
                str(fields.get("scope") or current.scope),
                now,
                next_fire,
                str(fields.get("watch_token") if "watch_token" in fields else current.watch_token),
                routine_id,
            ),
        )
        self.db.conn.commit()
        return self.get(routine_id)

    def set_paused(self, routine_id: str, paused: bool) -> Routine:
        self.get(routine_id)
        self.db.conn.execute(
            "UPDATE routines SET paused = ?, updated_at = ? WHERE id = ?",
            (1 if paused else 0, dump_time(self.clock()), routine_id),
        )
        self.db.conn.commit()
        return self.get(routine_id)

    def delete(self, routine_id: str) -> None:
        self.get(routine_id)
        self.db.conn.execute("DELETE FROM routines WHERE id = ?", (routine_id,))
        self.db.conn.commit()

    def add_run(self, run: RoutineRun) -> None:
        self.db.conn.execute(
            """
            INSERT INTO routine_runs (
                id, routine_id, session_id, started_at, finished_at, outcome, summary, trigger
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run.id,
                run.routine_id,
                run.session_id,
                run.started_at,
                run.finished_at,
                run.outcome,
                run.summary,
                run.trigger,
            ),
        )
        self.db.conn.commit()

    def history(self, routine_id: str = "", *, limit: int = 20) -> list[RoutineRun]:
        if routine_id:
            rows = self.db.conn.execute(
                """
                SELECT * FROM routine_runs WHERE routine_id = ?
                ORDER BY started_at DESC, id DESC LIMIT ?
                """,
                (routine_id, limit),
            ).fetchall()
        else:
            rows = self.db.conn.execute(
                "SELECT * FROM routine_runs ORDER BY started_at DESC, id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [_run(row) for row in rows]

    def mark_fired(
        self,
        routine: Routine,
        now: datetime,
        *,
        watch_token: str | None = None,
    ) -> None:
        nxt = ""
        if routine.trigger_kind in {"cron", "interval"}:
            nxt = dump_time(
                self.next_fire_at(
                    routine.trigger_kind,
                    routine.trigger_expr,
                    routine.timezone_name,
                    now,
                    routine.created_at,
                )
            )
        token = routine.watch_token if watch_token is None else watch_token
        self.db.conn.execute(
            """
            UPDATE routines
            SET last_fire_at = ?, next_fire_at = ?, watch_token = ?, updated_at = ?
            WHERE id = ?
            """,
            (dump_time(now), nxt, token, dump_time(now), routine.id),
        )
        self.db.conn.commit()

    def mark_skipped(
        self,
        routine: Routine,
        now: datetime,
        *,
        watch_token: str | None = None,
    ) -> None:
        nxt = ""
        if routine.trigger_kind in {"cron", "interval"}:
            nxt = dump_time(
                self.next_fire_at(
                    routine.trigger_kind,
                    routine.trigger_expr,
                    routine.timezone_name,
                    now,
                    routine.created_at,
                )
            )
        token = routine.watch_token if watch_token is None else watch_token
        self.db.conn.execute(
            """
            UPDATE routines
            SET next_fire_at = ?, watch_token = ?, updated_at = ?
            WHERE id = ?
            """,
            (nxt, token, dump_time(now), routine.id),
        )
        self.db.conn.commit()

    def next_fire_at(
        self,
        kind: str,
        expr: str,
        tz_name: str,
        after: datetime,
        anchor: str,
    ) -> datetime:
        if kind == "interval" or expr.strip().lower().startswith("@every"):
            return next_interval(after, parse_every(expr), load_time(anchor))
        return next_cron(expr, after, timezone(tz_name))

    def _validate(self, kind: str, expr: str, tz_name: str) -> None:
        if kind == "cron":
            if expr.strip().lower().startswith("@every"):
                parse_every(expr)
                return
            parse_cron(expr)
            timezone(tz_name)
            return
        if kind == "interval":
            parse_every(expr)
            return
        if kind == "file" and not expr.strip():
            raise ScheduleError("file watch needs a path")
        if kind == "webhook":
            return
        timezone(tz_name)


def schedule_decision(routine: Routine, now: datetime) -> str:
    """Return ``wait``, ``run``, or ``skip`` for a cron or interval routine."""
    if routine.paused or routine.trigger_kind not in {"cron", "interval"}:
        return "wait"
    if not routine.next_fire_at:
        return "wait"
    due = load_time(routine.next_fire_at)
    if now < due:
        return "wait"
    late = (now - due).total_seconds()
    grace = max(60, routine.min_interval_seconds)
    if late <= grace:
        return "run"
    if routine.missed_policy == "skip":
        return "skip"
    return "run"


def too_soon(routine: Routine, now: datetime) -> bool:
    if not routine.last_fire_at:
        return False
    elapsed = (now - load_time(routine.last_fire_at)).total_seconds()
    return elapsed < routine.min_interval_seconds


def _routine(row: object) -> Routine:
    usd = row["max_usd"]
    return Routine(
        id=str(row["id"]),
        name=str(row["name"]),
        prompt=str(row["prompt"]),
        trigger_kind=str(row["trigger_kind"]),
        trigger_expr=str(row["trigger_expr"]),
        timezone_name=str(row["timezone"]),
        missed_policy=str(row["missed_policy"]),
        min_interval_seconds=int(row["min_interval_seconds"]),
        max_iterations=int(row["max_iterations"]),
        max_usd=float(usd) if usd is not None else None,
        skill=str(row["skill"] or ""),
        deliver=str(row["deliver"] or "none"),
        paused=bool(row["paused"]),
        scope=str(row["scope"] or "global"),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
        next_fire_at=str(row["next_fire_at"] or ""),
        last_fire_at=str(row["last_fire_at"] or ""),
        watch_token=str(row["watch_token"] or ""),
    )


def _run(row: object) -> RoutineRun:
    return RoutineRun(
        id=str(row["id"]),
        routine_id=str(row["routine_id"]),
        session_id=str(row["session_id"] or ""),
        started_at=str(row["started_at"]),
        finished_at=str(row["finished_at"]),
        outcome=str(row["outcome"]),
        summary=str(row["summary"] or ""),
        trigger=str(row["trigger"]),
    )
