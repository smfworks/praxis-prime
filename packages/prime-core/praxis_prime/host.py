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
from praxis_prime.approvals.gate import approval_account_id
from praxis_prime.approvals.queue import ApprovalQueue
from praxis_prime.channels.trust import untrusted_channel_message
from praxis_prime.loop.control import TurnControl
from praxis_prime.loop.events import StatusEvent, ToolSpan, TurnEnded
from praxis_prime.memory.tiers import memory_channel
from praxis_prime.profiles.ids import profile_id
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
        self._control: TurnControl | None = None
        self._active_account = ""
        self.runtime.gate.approver = queue.authorize

    def chat(
        self,
        text: str,
        *,
        session_id: str | None = None,
        untrusted: bool = False,
        source: str = "channel",
        channel: str = "",
        on_event: EventCallback | None = None,
        owner_account: str = "",
        owner_profile: str = "",
    ) -> TurnResult:
        with self._lock:
            if self._closed:
                raise RuntimeError("daemon is shut down")
            body = untrusted_channel_message(text, source=source) if untrusted else text
            active_id, loop = self.runtime.open_loop(
                session_id,
                channel=channel,
                owner_account=owner_account,
                owner_profile=owner_profile,
            )
            final = ""
            error: str | None = None
            cancelled = False
            control = TurnControl()
            self._control = control
            self._active_account = owner_account
            token = memory_channel.set(channel)
            account_token = approval_account_id.set(owner_account)
            try:
                for event in loop.run_turn(body, control):
                    payload = event_payload(event)
                    if on_event is not None:
                        on_event(payload)
                    if isinstance(event, TextDelta):
                        final += event.text
                    elif isinstance(event, TurnEnded):
                        final = event.text or final
                        error = event.error
                        cancelled = event.cancelled
            finally:
                self._control = None
                self._active_account = ""
                approval_account_id.reset(account_token)
                memory_channel.reset(token)
            return TurnResult(
                session_id=active_id,
                text=final,
                error=error,
                cancelled=cancelled,
            )

    def set_model(self, spec: str, *, profile: str = "") -> str:
        self._require_this_profile(profile)
        with self._lock:
            if self._closed:
                raise RuntimeError("daemon is shut down")
            return self.runtime.set_model(spec)

    def drop_session(self, session_id: str | None, *, account_id: str = "") -> None:
        with self._lock:
            if not session_id:
                return
            if account_id:
                found = self.runtime.store.owner(session_id)
                if found is None:
                    raise LookupError(f"no session {session_id}")
                owner_account, owner_profile = found
                if owner_account != account_id:
                    raise PermissionError("session belongs to another account")
                runtime_profile = self.runtime.profile_id
                if owner_profile and runtime_profile and owner_profile != runtime_profile:
                    raise PermissionError("session belongs to another account")
                self.runtime.gate.clear(session_id, account_id=account_id)
                return
            self.runtime.gate.clear(session_id)

    def active_account(self) -> str:
        return self._active_account

    def cancel_turn(self, *, actor: str) -> bool:
        """Stop the running turn. Returns False when nothing is running."""
        control = self._control
        if control is None:
            return False
        control.cancel()
        self.queue.deny_all(actor=actor)
        return True

    def list_memory(self, profile: str = "") -> list[dict[str, object]]:
        self._require_this_profile(profile)
        from praxis_prime.catalog import memory_rows

        return memory_rows(self.runtime.memory)

    def list_skills(self, profile: str = "") -> list[dict[str, object]]:
        self._require_this_profile(profile)
        from praxis_prime.catalog import skill_rows

        return skill_rows(self.runtime.skills)

    def list_routines(self, profile: str = "") -> list[dict[str, object]]:
        self._require_this_profile(profile)
        from praxis_prime.catalog import routine_rows
        from praxis_prime.scheduler.store import RoutineStore

        return routine_rows(RoutineStore(self.runtime.db))

    def _require_this_profile(self, profile: str) -> None:
        """Refuse a catalog read for a profile this process did not open.

        An empty name means this process. Chat and approve use the same
        rule in the gateway before they get here.
        """
        requested = profile.strip()
        if not requested:
            return
        named = profile_id(requested)
        bound = profile_id(self.runtime.profile_id) if self.runtime.profile_id else None
        if named is None or bound is None or named != bound:
            raise PermissionError("this daemon runs a different profile")

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
    if isinstance(event, ToolSpan):
        return {
            "kind": "tool",
            "phase": event.phase,
            "toolCallId": event.tool_call_id,
            "name": event.name,
            "detail": event.detail,
        }
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
