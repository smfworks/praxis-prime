"""Scheduler loop inside praxis-primed.

Cron and interval routines catch up with the missed-run policy. File watches
use inotify when the kernel has it. Webhooks call :meth:`fire_http`.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from praxis_prime.audit.log import AuditLog
from praxis_prime.clock import Now, dump_time, utcnow
from praxis_prime.memory.tiers import MemoryStore
from praxis_prime.runtime import Runtime
from praxis_prime.scheduler.runner import Deliver, execute_routine
from praxis_prime.scheduler.store import (
    Routine,
    RoutineRun,
    RoutineStore,
    schedule_decision,
    too_soon,
)
from praxis_prime.scheduler.watch import DirectoryWatcher

Runner = Callable[[Routine, str], RoutineRun]


class RoutineScheduler:
    def __init__(
        self,
        store: RoutineStore,
        runner: Runner,
        *,
        watcher: DirectoryWatcher | None = None,
        clock: Now | None = None,
        audit: AuditLog | None = None,
        memory: MemoryStore | None = None,
        logger: object | None = None,
        lane: threading.Lock | None = None,
    ) -> None:
        self.store = store
        self.runner = runner
        self.watcher = watcher or DirectoryWatcher()
        self.clock = clock or utcnow
        self.audit = audit
        self.memory = memory
        self.logger = logger
        self._lane = lane
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._saw_tick = False
        self._lock = threading.Lock()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="praxis-routines", daemon=True)
        self._thread.start()

    def request_stop(self) -> None:
        self._stop.set()

    def join(self, timeout: float = 5) -> None:
        if self._thread is not None:
            self._thread.join(timeout)
            self._thread = None
        self.watcher.close()

    def tick(self, now: datetime | None = None) -> list[str]:
        if self._stop.is_set():
            return []
        return self._on_lane(lambda: self._tick(now or self.clock()))

    def fire_http(self, routine_id: str) -> tuple[int, dict[str, object]]:
        return self._on_lane(lambda: self._fire(routine_id))

    def _on_lane(self, body: Callable[[], list[str] | tuple[int, dict[str, object]]]):
        if self._lane is None:
            with self._lock:
                return body()
        with self._lane:
            with self._lock:
                return body()

    def _fire(self, routine_id: str) -> tuple[int, dict[str, object]]:
        try:
            routine = self.store.get(routine_id)
        except LookupError:
            return 404, _error("not_found", f"no routine {routine_id}")
        if routine.paused:
            return 409, _error("paused", "routine is paused")
        moment = self.clock()
        if too_soon(routine, moment):
            return 429, _error("too_soon", "minimum interval is 1 minute")
        run = self.runner(routine, "webhook")
        self.store.mark_fired(routine, moment)
        return 200, {"ok": True, "run": run.public()}

    def _tick(self, moment: datetime) -> list[str]:
        notes: list[str] = []
        if self.memory is not None:
            try:
                self.memory.apply_retention()
            except Exception:
                self._warn()
        startup = not self._saw_tick
        self._saw_tick = True
        for routine in self.store.list_routines():
            if routine.paused:
                continue
            try:
                if routine.trigger_kind in {"cron", "interval"}:
                    notes.extend(self._scheduled(routine, moment))
                elif routine.trigger_kind == "file":
                    notes.extend(self._file(routine, moment, startup=startup))
            except Exception:
                self._warn()
        return notes

    def _scheduled(self, routine: Routine, moment: datetime) -> list[str]:
        decision = schedule_decision(routine, moment)
        if decision == "wait":
            return []
        if decision == "skip":
            self._skip(routine, moment, "schedule")
            return [f"skip {routine.id}"]
        if too_soon(routine, moment):
            return []
        self.runner(routine, "schedule")
        self.store.mark_fired(routine, moment)
        return [f"run {routine.id}"]

    def _file(self, routine: Routine, moment: datetime, *, startup: bool) -> list[str]:
        path = Path(routine.trigger_expr)
        changed, token = self.watcher.observe(path, routine.watch_token, startup=startup)
        if not changed:
            return []
        missed = _stale(path, moment, routine.min_interval_seconds)
        if missed and routine.missed_policy == "skip":
            self._skip(routine, moment, "file", watch_token=token)
            return [f"skip {routine.id}"]
        if too_soon(routine, moment):
            return []
        self.runner(routine, "file")
        self.store.mark_fired(routine, moment, watch_token=token)
        return [f"run {routine.id}"]

    def _skip(
        self,
        routine: Routine,
        moment: datetime,
        trigger: str,
        *,
        watch_token: str | None = None,
    ) -> None:
        self.store.mark_skipped(routine, moment, watch_token=watch_token)
        run = RoutineRun(
            id=f"rn_{uuid.uuid4().hex[:8]}",
            routine_id=routine.id,
            session_id="",
            started_at=dump_time(moment),
            finished_at=dump_time(moment),
            outcome="skipped",
            summary="missed run skipped",
            trigger=trigger,
        )
        self.store.add_run(run)
        if self.audit is not None:
            self.audit.append(
                session_id=None,
                kind="routine_run",
                summary=f"{routine.name} skipped",
                payload={
                    "routine_id": routine.id,
                    "run_id": run.id,
                    "trigger": trigger,
                    "outcome": "skipped",
                    "skill": routine.skill,
                },
            )

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                self._warn()
            if self._stop.wait(5):
                return

    def _warn(self) -> None:
        warning = getattr(self.logger, "warning", None)
        if warning is not None:
            warning("routine_tick_failed")


def scheduler_for(
    runtime: Runtime,
    *,
    deliver: Deliver | None = None,
    usd_per_iteration: float = 0.0,
    logger: object | None = None,
    lane: threading.Lock | None = None,
) -> RoutineScheduler:
    store = RoutineStore(runtime.db)

    def runner(routine: Routine, trigger: str) -> RoutineRun:
        # Read the database at fire time. Web owner creation swaps
        # ``runtime.db`` onto ``profiles/default`` without restarting.
        database = runtime.db
        if database is None:
            raise RuntimeError("profile database is closed")
        return execute_routine(
            runtime,
            routine,
            trigger=trigger,
            store=RoutineStore(database),
            deliver=deliver,
            usd_per_iteration=usd_per_iteration,
        )

    return RoutineScheduler(
        store,
        runner,
        audit=runtime.audit,
        memory=runtime.memory,
        logger=logger,
        lane=lane,
    )


def _stale(path: Path, now: datetime, minimum: int) -> bool:
    if not path.exists():
        return True
    age = now.timestamp() - path.stat().st_mtime
    return age > max(60, minimum)


def _error(code: str, message: str) -> dict[str, object]:
    return {"ok": False, "error": {"code": code, "message": message}}
