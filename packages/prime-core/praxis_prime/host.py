"""Kernel host.

One lock serializes turns so the SQLite connection and the approval gate
stay on a single logical lane (ARCHITECTURE §3.1, §4). Channel text is
wrapped as untrusted data before the model sees it.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from praxis_prime import __version__
from praxis_prime.approvals.queue import ApprovalQueue
from praxis_prime.channels.trust import untrusted_channel_message
from praxis_prime.loop.events import StatusEvent, TurnEnded
from praxis_prime.router.types import TextDelta
from praxis_prime.runtime import Runtime

EventCallback = Callable[[dict[str, object]], None]


@dataclass(frozen=True, slots=True)
class TurnResult:
    session_id: str
    text: str
    error: str | None
    cancelled: bool


class Host:
    """The daemon's handle on the in-process agent runtime."""

    def __init__(self, runtime: Runtime, queue: ApprovalQueue) -> None:
        self.runtime = runtime
        self.queue = queue
        self.started_at = time.time()
        self._lock = threading.RLock()
        self._closed = False
        self.runtime.gate.approver = queue.authorize

    def chat(
        self,
        text: str,
        *,
        session_id: str | None = None,
        untrusted: bool = False,
        source: str = "channel",
        on_event: EventCallback | None = None,
    ) -> TurnResult:
        with self._lock:
            if self._closed:
                raise RuntimeError("daemon is shut down")
            body = untrusted_channel_message(text, source=source) if untrusted else text
            active_id, loop = self.runtime.open_loop(session_id)
            final = ""
            error: str | None = None
            cancelled = False
            for event in loop.run_turn(body):
                payload = event_payload(event)
                if on_event is not None:
                    on_event(payload)
                if isinstance(event, TextDelta):
                    final += event.text
                elif isinstance(event, TurnEnded):
                    final = event.text or final
                    error = event.error
                    cancelled = event.cancelled
            return TurnResult(
                session_id=active_id,
                text=final,
                error=error,
                cancelled=cancelled,
            )

    def set_model(self, spec: str) -> str:
        with self._lock:
            if self._closed:
                raise RuntimeError("daemon is shut down")
            return self.runtime.set_model(spec)

    def drop_session(self, session_id: str | None) -> None:
        with self._lock:
            if session_id:
                self.runtime.gate.clear(session_id)

    def status(self) -> dict[str, object]:
        with self._lock:
            model = "" if self._closed else self.runtime.router.primary.spec()
            mode = "" if self._closed else self.runtime.settings.mode
        return {
            "service": "praxis-primed",
            "version": __version__,
            "model": model,
            "mode": mode,
            "pendingApprovals": len(self.queue.list_pending()),
            "uptimeSeconds": int(time.time() - self.started_at),
        }

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self.runtime.close()


def event_payload(event: object) -> dict[str, object]:
    if isinstance(event, TextDelta):
        return {"kind": "text", "text": event.text}
    if isinstance(event, StatusEvent):
        return {"kind": "status", "phase": event.phase, "detail": event.detail}
    if isinstance(event, TurnEnded):
        return {
            "kind": "turn",
            "text": event.text,
            "cancelled": event.cancelled,
            "error": event.error,
        }
    return {"kind": "status", "phase": "plan", "detail": ""}
