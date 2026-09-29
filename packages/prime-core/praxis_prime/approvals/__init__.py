"""Approval gate.

Consequential actions need a human. The gate records allow-once and
allow-for-this-session decisions. It does not approve anything by itself.

ARCHITECTURE §16.
"""

from praxis_prime.approvals.gate import (
    ApprovalDecision,
    ApprovalGate,
    ApprovalRequest,
    Approver,
)

__all__ = [
    "ApprovalDecision",
    "ApprovalGate",
    "ApprovalRequest",
    "Approver",
]
