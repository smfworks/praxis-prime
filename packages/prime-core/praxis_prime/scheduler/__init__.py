"""Routines, cron, intervals, file watches, and webhooks.

ARCHITECTURE §11. ``praxis-primed`` runs due routines. Each run is an
agent session. Always-ask actions still wait on the approval queue.

``RoutineScheduler`` is loaded on attribute access so importing this
package does not pull the runtime in before the agent loop is ready.
"""

from praxis_prime.scheduler.store import RoutineStore

__all__ = ["RoutineScheduler", "RoutineStore"]


def __getattr__(name: str) -> object:
    if name == "RoutineScheduler":
        from praxis_prime.scheduler.service import RoutineScheduler

        return RoutineScheduler
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
