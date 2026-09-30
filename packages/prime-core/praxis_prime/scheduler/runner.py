"""Run one routine as an ordinary agent session.

Always-ask actions use the same approval gate as chat. A headless run with
nobody answering denies when the gate times out. The run is one audit event.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable

from praxis_prime.clock import dump_time, utcnow
from praxis_prime.loop.events import StatusEvent, TurnEnded
from praxis_prime.memory.redact import redact_text
from praxis_prime.memory.tiers import memory_channel
from praxis_prime.runtime import Runtime
from praxis_prime.scheduler.store import Routine, RoutineRun, RoutineStore

Deliver = Callable[[str], None]


def _channel(scope: str) -> str:
    if scope.startswith("channel:"):
        return scope.split(":", 1)[1]
    return ""


def execute_routine(
    runtime: Runtime,
    routine: Routine,
    *,
    trigger: str,
    store: RoutineStore,
    deliver: Deliver | None = None,
    usd_per_iteration: float = 0.0,
) -> RoutineRun:
    started = dump_time(utcnow())
    session_id = ""
    summary = ""
    outcome = "error"
    try:
        allowed = routine.max_iterations
        if routine.max_usd is not None and usd_per_iteration > 0:
            allowed = min(allowed, int(routine.max_usd / usd_per_iteration))
        if allowed < 1:
            outcome = "budget"
            summary = "stopped before the model call; budget is below one iteration"
        else:
            session_id, loop = runtime.open_loop(skill=routine.skill, scope=routine.scope)
            loop.max_iterations = allowed
            denied = False
            error: str | None = None
            text = ""
            token = memory_channel.set(_channel(routine.scope))
            try:
                for event in loop.run_turn(routine.prompt):
                    if isinstance(event, StatusEvent) and event.detail.endswith("approval denied"):
                        denied = True
                    elif isinstance(event, TurnEnded):
                        text = event.text
                        error = event.error
            finally:
                memory_channel.reset(token)
            summary = redact_text(text, mode="secrets", dials=runtime.settings.dials)
            summary = " ".join(summary.split())[:500]
            if error == "max_iterations":
                outcome = "budget"
            elif denied:
                outcome = "denied"
            elif error:
                outcome = "error"
                summary = summary or error
            else:
                outcome = "ok"
            if routine.deliver == "telegram" and deliver is not None and summary:
                deliver(summary[:4000])
    except Exception as exc:
        outcome = "error"
        summary = type(exc).__name__
    finished = dump_time(utcnow())
    run = RoutineRun(
        id=f"rn_{uuid.uuid4().hex[:8]}",
        routine_id=routine.id,
        session_id=session_id,
        started_at=started,
        finished_at=finished,
        outcome=outcome,
        summary=summary,
        trigger=trigger,
    )
    store.add_run(run)
    runtime.audit.append(
        session_id=session_id or None,
        kind="routine_run",
        summary=f"{routine.name} {outcome}",
        payload={
            "routine_id": routine.id,
            "run_id": run.id,
            "trigger": trigger,
            "outcome": outcome,
            "skill": routine.skill,
        },
    )
    return run
