"""Audit log.

Tool calls and approvals are appended to a SHA-256 hash chain in the
session database. Daily signatures and export formats are later work.

ARCHITECTURE §18.
"""

from praxis_prime.audit.log import AuditLog

__all__ = ["AuditLog"]
