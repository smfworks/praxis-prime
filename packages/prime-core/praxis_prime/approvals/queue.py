"""Pending-approval queue.

The agent thread blocks in :meth:`ApprovalQueue.authorize` until an operator
decides or the TTL elapses. A timeout denies the action. Decisions are
single-use. Chat text is not a way in; callers pass an explicit decision.
"""

from __future__ import annotations

import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from praxis_prime.approvals.gate import (
    ApprovalDecision,
    ApprovalRequest,
    approval_actor,
    approval_session_id,
)

Notify = Callable[[dict[str, object]], None]
_ID = re.compile(r"ap_[0-9a-f]{8}")
_SECRET_KEY = re.compile(r"(?i)(api[_-]?key|token|secret|password|authorization)")


@dataclass
class _Item:
    id: str
    request: ApprovalRequest
    session_id: str | None
    created_at: float
    expires_at: float
    state: str
    actor: str
    decision: ApprovalDecision | None
    event: threading.Event
    profile_id: str = ""

    def public(self) -> dict[str, object]:
        return {
            "id": self.id,
            "tool": self.request.tool,
            "risk": self.request.risk.value,
            "reason": self.request.reason,
            "summary": self.request.summary,
            "arguments": redact_arguments(self.request.arguments),
            "sandboxed": self.request.sandboxed,
            "mount": self.request.mount,
            "sessionId": self.session_id,
            "profileId": self.profile_id,
            "state": self.state,
            "actor": self.actor,
            "expiresAt": datetime.fromtimestamp(self.expires_at, UTC).isoformat(),
        }


class ApprovalQueue:
    """In-memory queue. The daemon is the only process that decides."""

    def __init__(
        self,
        *,
        ttl: float = 900,
        on_pending: Notify | None = None,
        on_resolved: Notify | None = None,
    ) -> None:
        self.ttl = ttl
        self.on_pending = on_pending
        self.on_resolved = on_resolved
        self.profile_id = ""
        self._items: dict[str, _Item] = {}
        self._lock = threading.Lock()

    def authorize(self, request: ApprovalRequest) -> ApprovalDecision:
        """Block until a decision arrives. Timeout and errors deny."""
        now = time.time()
        item = _Item(
            id=_new_id(),
            request=request,
            session_id=approval_session_id.get(),
            created_at=now,
            expires_at=now + self.ttl,
            state="pending",
            actor="",
            decision=None,
            event=threading.Event(),
            profile_id=self.profile_id,
        )
        with self._lock:
            self._items[item.id] = item
        snapshot = item.public()
        self._notify(self.on_pending, snapshot)
        item.event.wait(self.ttl)
        with self._lock:
            if item.state == "pending":
                item.state = "expired"
                item.decision = ApprovalDecision.DENY
                item.actor = "timeout"
            decision = item.decision or ApprovalDecision.DENY
            actor = item.actor
            snapshot = item.public()
        approval_actor.set(actor or "timeout")
        self._notify(self.on_resolved, snapshot)
        if decision in {ApprovalDecision.ALLOW_ONCE, ApprovalDecision.ALLOW_SESSION}:
            return decision
        return ApprovalDecision.DENY

    def list_pending(self) -> list[dict[str, object]]:
        with self._lock:
            pending = [item.public() for item in self._items.values() if item.state == "pending"]
        pending.sort(key=lambda item: str(item["id"]))
        return pending

    def decide(
        self,
        approval_id: str,
        decision: ApprovalDecision,
        *,
        actor: str,
    ) -> dict[str, object]:
        """Record one decision. A second call for the same id fails."""
        if not _ID.fullmatch(approval_id):
            raise LookupError(f"unknown approval {approval_id}")
        if decision not in {
            ApprovalDecision.ALLOW_ONCE,
            ApprovalDecision.ALLOW_SESSION,
            ApprovalDecision.DENY,
        }:
            raise ValueError("decision must be allow_once, allow_session, or deny")
        with self._lock:
            item = self._items.get(approval_id)
            if item is None or item.state != "pending":
                raise LookupError(f"approval {approval_id} is not pending")
            item.state = decision.value
            item.decision = decision
            item.actor = actor
            item.event.set()
            return item.public()

    def deny_all(self, *, actor: str) -> None:
        """Unblock every waiter. Used on shutdown."""
        with self._lock:
            pending = [item for item in self._items.values() if item.state == "pending"]
            for item in pending:
                item.state = "deny"
                item.decision = ApprovalDecision.DENY
                item.actor = actor
                item.event.set()

    def get(self, approval_id: str) -> dict[str, object] | None:
        with self._lock:
            item = self._items.get(approval_id)
            if item is None:
                return None
            return item.public()

    def _notify(self, callback: Notify | None, snapshot: dict[str, object]) -> None:
        if callback is None:
            return
        try:
            callback(snapshot)
        except Exception:
            return


def parse_decision(value: object) -> ApprovalDecision:
    if not isinstance(value, str):
        raise ValueError("decision must be allow_once, allow_session, or deny")
    try:
        decision = ApprovalDecision(value)
    except ValueError as exc:
        raise ValueError("decision must be allow_once, allow_session, or deny") from exc
    if decision not in {
        ApprovalDecision.ALLOW_ONCE,
        ApprovalDecision.ALLOW_SESSION,
        ApprovalDecision.DENY,
    }:
        raise ValueError("decision must be allow_once, allow_session, or deny")
    return decision


def redact_arguments(arguments: Mapping[str, object]) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    for key, value in arguments.items():
        name = str(key)
        if _SECRET_KEY.search(name):
            cleaned[name] = "[redacted]"
        else:
            text = " ".join(str(value).split())
            cleaned[name] = text if len(text) <= 180 else text[:179] + "…"
    return cleaned


def _new_id() -> str:
    return "ap_" + secrets.token_hex(4)
