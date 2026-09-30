"""Cancel and steer a running turn.

OpenClaw queue modes include steer (inject into the running turn) and
interrupt (cancel). The terminal UI uses cancel. Callers can also steer.
"""

from __future__ import annotations

from threading import Lock


class TurnControl:
    """Thread-safe flags for one turn.

    ``cancel`` stops the turn before the next model or tool step.
    ``steer`` queues text that the loop appends as a user message before
    the next model call.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._cancelled = False
        self._steer: list[str] = []

    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True

    @property
    def cancelled(self) -> bool:
        with self._lock:
            return self._cancelled

    def steer(self, text: str) -> None:
        cleaned = text.strip()
        if not cleaned:
            return
        with self._lock:
            self._steer.append(cleaned)

    def drain_steer(self) -> list[str]:
        with self._lock:
            queued = list(self._steer)
            self._steer.clear()
            return queued
