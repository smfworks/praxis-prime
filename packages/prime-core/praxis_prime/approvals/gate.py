"""Approval gate for consequential actions.

A tool runs only after ``allow``, an allow-once reply, or a grant stored
for this session. Denied and unanswered requests do not run the tool.
"""

from __future__ import annotations

from collections.abc import Mapping
from contextvars import ContextVar
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from praxis_prime.tools.registry import Risk

# Set by the agent loop for the duration of one authorize() call.
approval_session_id: ContextVar[str | None] = ContextVar(
    "praxis_prime_approval_session",
    default=None,
)
approval_account_id: ContextVar[str] = ContextVar(
    "praxis_prime_approval_account",
    default="",
)
approval_actor: ContextVar[str] = ContextVar("praxis_prime_approval_actor", default="")


class ApprovalDecision(StrEnum):
    ALLOW_ONCE = "allow_once"
    ALLOW_SESSION = "allow_session"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """What the person is asked to approve. This is the action, not a hint."""

    tool: str
    risk: Risk
    reason: str
    summary: str
    arguments: Mapping[str, object]
    grant_key: str
    sandboxed: bool
    mount: str = ""


class Approver(Protocol):
    def __call__(self, request: ApprovalRequest) -> ApprovalDecision:
        """Return a decision. Raising is treated as deny by the gate."""


class ApprovalGate:
    """Session grants plus a required human approver for new asks."""

    def __init__(self, approver: Approver | None = None) -> None:
        self.approver = approver
        self._grants: set[str] = set()
        self._session_grants: dict[str, set[str]] = {}

    def clear(self, session_id: str | None = None, *, account_id: str = "") -> None:
        """Drop session grants. With no id, drop every grant this process holds.

        Grants are keyed by account and session. Clearing one account's
        session does not drop another account's grant for that id.
        """
        if session_id is None:
            self._grants.clear()
            self._session_grants.clear()
            return
        self._session_grants.pop(_grant_bucket(session_id, account_id), None)

    def _bucket(self, session_id: str | None) -> set[str]:
        key = _grant_bucket(session_id, approval_account_id.get())
        if not key:
            return self._grants
        return self._session_grants.setdefault(key, set())

    def authorize(self, request: ApprovalRequest) -> ApprovalDecision:
        grants = self._bucket(approval_session_id.get())
        if request.grant_key in grants:
            approval_actor.set("session-grant")
            return ApprovalDecision.ALLOW_SESSION
        if self.approver is None:
            approval_actor.set("")
            return ApprovalDecision.DENY
        approval_actor.set("")
        try:
            decision = self.approver(request)
        except Exception:
            approval_actor.set("error")
            return ApprovalDecision.DENY
        if decision == ApprovalDecision.ALLOW_SESSION:
            grants.add(request.grant_key)
            return decision
        if decision == ApprovalDecision.ALLOW_ONCE:
            return decision
        return ApprovalDecision.DENY


def _grant_bucket(session_id: str | None, account_id: str) -> str:
    if account_id and session_id:
        return f"{account_id}:{session_id}"
    return session_id or ""
