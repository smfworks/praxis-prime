"""Approval gate for consequential actions.

A tool runs only after ``allow``, an allow-once reply, or a grant stored
for this session. Denied and unanswered requests do not run the tool.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from praxis_prime.tools.registry import Risk


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


class Approver(Protocol):
    def __call__(self, request: ApprovalRequest) -> ApprovalDecision:
        """Return a decision. Raising is treated as deny by the gate."""


class ApprovalGate:
    """Session grants plus a required human approver for new asks."""

    def __init__(self, approver: Approver | None = None) -> None:
        self.approver = approver
        self._grants: set[str] = set()

    def clear(self) -> None:
        self._grants.clear()

    def authorize(self, request: ApprovalRequest) -> ApprovalDecision:
        if request.grant_key in self._grants:
            return ApprovalDecision.ALLOW_SESSION
        if self.approver is None:
            return ApprovalDecision.DENY
        try:
            decision = self.approver(request)
        except Exception:
            return ApprovalDecision.DENY
        if decision == ApprovalDecision.ALLOW_SESSION:
            self._grants.add(request.grant_key)
            return decision
        if decision == ApprovalDecision.ALLOW_ONCE:
            return decision
        return ApprovalDecision.DENY
