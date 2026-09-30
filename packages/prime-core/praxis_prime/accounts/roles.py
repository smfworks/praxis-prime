"""Server roles and per-profile roles.

The server role and the profile role both have to allow an action. A
profile membership cannot loosen a server role.

docs/blueprint-addendum-2026-09.md §6.2.
"""

from __future__ import annotations

from typing import Literal

ServerRole = Literal["owner", "admin", "operator", "viewer", "auditor"]
ProfileRole = Literal["owner", "operator", "viewer"]

SERVER_ROLES: tuple[ServerRole, ...] = (
    "owner",
    "admin",
    "operator",
    "viewer",
    "auditor",
)
PROFILE_ROLES: tuple[ProfileRole, ...] = ("owner", "operator", "viewer")
MANAGE_ROLES = frozenset({"owner", "admin"})
APPROVE_SERVER_ROLES = frozenset({"owner", "admin", "operator"})
CHAT_SERVER_ROLES = frozenset({"owner", "admin", "operator"})
APPROVE_PROFILE_ROLES = frozenset({"owner", "operator"})
CHAT_PROFILE_ROLES = frozenset({"owner", "operator"})


def server_role(value: object) -> ServerRole | None:
    if isinstance(value, str) and value in SERVER_ROLES:
        return value  # type: ignore[return-value]
    return None


def profile_role(value: object) -> ProfileRole | None:
    if isinstance(value, str) and value in PROFILE_ROLES:
        return value  # type: ignore[return-value]
    return None


def can_approve(role: str, membership: str | None) -> bool:
    """True when both the server role and the profile role may approve.

    ``membership`` is None for an unscoped legacy approval. Owner and admin
    may decide those. A named profile still needs a membership check by
    the caller; pass that profile role here.
    """
    if role not in APPROVE_SERVER_ROLES:
        return False
    if membership is None:
        return role in MANAGE_ROLES or role == "operator"
    return membership in APPROVE_PROFILE_ROLES


def can_chat(role: str, membership: str | None) -> bool:
    """Viewers and auditors do not send chat. A profile viewer does not either."""
    if role not in CHAT_SERVER_ROLES:
        return False
    if membership is None:
        return True
    return membership in CHAT_PROFILE_ROLES


def sees_all_profiles(role: str) -> bool:
    """Owner and admin are not limited to memberships."""
    return role in MANAGE_ROLES
