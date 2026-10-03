"""Authentication and authorization for gateway routes.

A bearer token is the owner bootstrap credential and stays loopback-only
because the socket does. Cookie sessions need a CSRF header on every
mutating request. WebSocket tickets are single-use and short-lived.

When no account exists yet, the bearer token keeps today's operator
behavior so a single-user install does not change.

docs/blueprint-addendum-2026-09.md §4.3 and §6.2.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass

from praxis_prime.accounts.db import (
    AccountStore,
    cookie_value,
    session_cookie,
)
from praxis_prime.accounts.factors import Factors
from praxis_prime.accounts.roles import (
    APPROVE_SERVER_ROLES,
    CHAT_SERVER_ROLES,
    can_approve,
    can_chat,
    sees_all_profiles,
)
from praxis_prime.audit.log import AuditLog
from praxis_prime.gateway.auth import bearer_token, token_ok
from praxis_prime.gateway.protocol import ROLES
from praxis_prime.profiles.ids import profile_id

_SAFE = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass(frozen=True, slots=True)
class Principal:
    kind: str
    account_id: str
    username: str
    role: str
    session_token: str = ""
    session_id: str = ""


@dataclass(frozen=True, slots=True)
class Denial:
    status: int
    code: str
    message: str

    @property
    def ok(self) -> bool:
        return self.status == 0


_ALLOW = Denial(0, "", "")


def accounts_enforced(store: AccountStore | None) -> bool:
    return store is not None and store.has_accounts()


def authenticate_http(
    store: AccountStore | None,
    headers: dict[str, str],
    method: str,
    *,
    bootstrap_token: str,
    bearer_enabled: bool = True,
) -> Principal | Denial:
    """Identify the caller. CSRF failures are 403. Missing auth is 401.

    ``bearer_enabled`` matters only after an account exists. Until then the
    bearer token stays the operator credential, so a false flag cannot open
    the gateway or lock out the first-run install.
    """
    if not accounts_enforced(store):
        if not token_ok(bearer_token(headers), bootstrap_token):
            return Denial(401, "unauthorized", "Bearer token required")
        return Principal(kind="legacy", account_id="", username="", role="operator")
    assert store is not None
    cookie = cookie_value(headers.get("cookie", ""))
    if cookie:
        session = store.session_from_token(cookie)
        if session is None:
            return Denial(401, "unauthorized", "session expired or revoked")
        if method not in _SAFE and not store.csrf_matches(session, headers.get("x-csrf-token", "")):
            return Denial(403, "forbidden", "CSRF token missing or invalid")
        return Principal(
            kind="session",
            account_id=session.account_id,
            username=session.username,
            role=session.role,
            session_token=cookie,
            session_id=session.id,
        )
    if bearer_enabled and token_ok(bearer_token(headers), bootstrap_token):
        owner = store.owner()
        if owner is None or owner.status != "active":
            return Denial(401, "unauthorized", "authentication required")
        return Principal(
            kind="bootstrap",
            account_id=owner.id,
            username=owner.username,
            role="owner",
        )
    return Denial(401, "unauthorized", "authentication required")


# Chat, approval, routine fire, model.set, and session.drop. With one
# in-process runtime, these run only on the profile that process opened.
# The supervisor sets multi_profile so each call names its own worker.
_SCOPED_ACTIONS = frozenset({"chat", "approve"})


def authorize_action(
    store: AccountStore | None,
    principal: Principal,
    *,
    action: str,
    profile: str,
    profile_exists: Callable[[str], bool] | None = None,
    runtime_profile: str = "",
    multi_profile: bool = False,
) -> Denial:
    """Enforce the server role and membership.

    An empty profile is not a pass. A single-process daemon only runs the
    profile it opened. The supervisor accepts any profile the caller may
    use. Unscoped approvals (no profile on the card and none on this
    process) are owner/admin only.
    """
    if principal.kind == "legacy" or store is None or not accounts_enforced(store):
        return _ALLOW
    if action == "approve" and principal.role not in APPROVE_SERVER_ROLES:
        return Denial(403, "forbidden", "this role cannot approve")
    if action == "chat" and principal.role not in CHAT_SERVER_ROLES:
        return Denial(403, "forbidden", "this role cannot chat")
    if action == "admin" and not sees_all_profiles(principal.role):
        return Denial(403, "forbidden", "admin role required")
    if action == "audit" and principal.role not in {"owner", "admin", "auditor"}:
        return Denial(403, "forbidden", "audit role required")
    if action == "content" and principal.role == "auditor":
        return Denial(403, "forbidden", "auditor cannot read chat content")
    effective = profile
    if action in _SCOPED_ACTIONS:
        scoped = _scoped_profile(profile, runtime_profile, multi=multi_profile)
        if scoped.code == "unscoped" and action == "approve":
            if can_approve(principal.role, None):
                return _ALLOW
            return Denial(403, "forbidden", "unscoped approvals are owner or admin only")
        if scoped.code == "unscoped":
            return Denial(403, "forbidden", "a profile is required")
        if not scoped.ok:
            return scoped
        effective = scoped.message
    if not effective:
        return _ALLOW
    checked = profile_id(effective)
    if checked is None:
        return Denial(400, "bad_request", "invalid profile id")
    exists = True if profile_exists is None else profile_exists(checked)
    if not exists:
        return Denial(404, "not_found", "no such profile")
    if sees_all_profiles(principal.role):
        return _ALLOW
    membership = store.membership(principal.account_id, checked)
    if membership is None:
        return Denial(403, "forbidden", "not a member of this profile")
    if action == "approve" and not can_approve(principal.role, membership):
        return Denial(403, "forbidden", "this role cannot approve")
    if action == "chat" and not can_chat(principal.role, membership):
        return Denial(403, "forbidden", "this role cannot chat")
    if action == "content" and principal.role == "auditor":
        return Denial(403, "forbidden", "auditor cannot read chat content")
    return _ALLOW


def claim_protocol_role(principal: Principal, requested: str) -> str | Denial:
    """Cap the WebSocket role the client asked for."""
    if requested not in ROLES:
        return Denial(400, "bad_role", "unknown role")
    if principal.kind == "legacy":
        return requested
    if requested == "operator" and principal.role not in {"owner", "admin", "operator"}:
        return Denial(403, "forbidden", f"{principal.role} cannot claim operator")
    if requested == "channel" and not sees_all_profiles(principal.role):
        return Denial(403, "forbidden", "channel role is not available to this account")
    return requested


def login(
    store: AccountStore,
    body: bytes,
    audit: AuditLog | None,
    *,
    peer: str = "",
) -> tuple[int, dict[str, object], list[tuple[str, str]]]:
    """Check a password and open a session. The password is not logged."""
    try:
        parsed = json.loads(body.decode("utf-8") or "{}")
    except (UnicodeError, json.JSONDecodeError):
        return 400, _error("bad_request", "login body must be JSON"), []
    if not isinstance(parsed, dict):
        return 400, _error("bad_request", "login body must be an object"), []
    username_text = parsed.get("username", "")
    password = parsed.get("password", "")
    if not isinstance(username_text, str) or not isinstance(password, str):
        return 400, _error("bad_request", "username and password must be strings"), []
    account = store.authenticate(username_text, password)
    if account is None:
        if not _audit_or_unavailable(
            audit,
            "auth.fail",
            "login failed",
            {"username": _safe_name(username_text), "ip": _safe_ip(peer)},
        ):
            return 503, _error("unavailable", "audit log is busy"), []
        return 401, _error("unauthorized", "invalid username or password"), []
    factors = Factors(store)
    if factors.totp_active(account.id):
        # The password is only the first factor. Do not clear second-factor
        # failures here: a known password must not reset TOTP lockout.
        if not _audit_or_unavailable(
            audit,
            "auth.mfa",
            "second factor required",
            {
                "actor_account": account.id,
                "username": account.username,
                "role": account.role,
                "method": "password",
            },
        ):
            return 503, _error("unavailable", "audit log is busy; login was not completed"), []
        token = factors.issue_mfa(account.id)
        return 200, {
            "ok": True,
            "mfaRequired": True,
            "mfaToken": token,
            "methods": ["totp", "recovery"],
        }, []
    # Write the audit row before the session exists. A locked prime.db then
    # returns 503 and does not leave an orphan session.
    store.clear_failures(account.id)
    if not _audit_or_unavailable(
        audit,
        "auth.login",
        "login",
        {
            "actor_account": account.id,
            "username": account.username,
            "role": account.role,
            "method": "password",
        },
    ):
        return 503, _error("unavailable", "audit log is busy; login was not completed"), []
    issued = store.open_session(account)
    payload: dict[str, object] = {
        "ok": True,
        "account": account.public(),
        "csrfToken": issued.csrf_token,
    }
    return 200, payload, [("Set-Cookie", session_cookie(issued.token, max_age=issued.max_age))]


def logout(
    store: AccountStore,
    principal: Principal,
    audit: AuditLog | None,
) -> tuple[int, dict[str, object], list[tuple[str, str]]]:
    if principal.session_token:
        store.revoke_token(principal.session_token)
    _audit(
        audit,
        "auth.logout",
        "logout",
        {"actor_account": principal.account_id, "username": principal.username},
    )
    cleared = session_cookie("", max_age=0)
    return 200, {"ok": True}, [("Set-Cookie", cleared)]


def issue_ws_ticket(
    store: AccountStore,
    principal: Principal,
    profile: str,
) -> tuple[int, dict[str, object]]:
    if principal.kind not in {"session", "bootstrap"} or not principal.account_id:
        return 401, _error("unauthorized", "authentication required")
    account = store.get_username(principal.username)
    if account is None:
        return 401, _error("unauthorized", "authentication required")
    try:
        ticket = store.issue_ticket(
            account,
            profile=profile,
            session_id=principal.session_id,
        )
    except ValueError as exc:
        return 400, _error("bad_request", str(exc))
    return 200, {"ok": True, "ticket": ticket, "expiresIn": 30}


def principal_from_ticket(store: AccountStore, token: str) -> Principal | None:
    ticket = store.consume_ticket(token)
    if ticket is None:
        return None
    return Principal(
        kind="ticket",
        account_id=ticket.account_id,
        username=ticket.username,
        role=ticket.role,
        session_id=ticket.session_id,
    )


def _scoped_profile(requested: str, runtime_profile: str, *, multi: bool = False) -> Denial:
    """The profile this action may use, or a denial.

    ``message`` holds the profile id when ``code`` is empty. ``unscoped``
    means neither the caller nor this process named a profile. ``multi``
    is the supervisor: a named profile is not compared to one runtime.
    """
    raw = requested.strip()
    bound = runtime_profile.strip()
    if multi:
        if raw:
            named = profile_id(raw)
            if named is None:
                return Denial(400, "bad_request", "invalid profile id")
            return Denial(0, "", named)
        if bound:
            named = profile_id(bound)
            if named is None:
                return Denial(403, "forbidden", "invalid profile id")
            return Denial(0, "", named)
        return Denial(0, "unscoped", "")
    if raw:
        named = profile_id(raw)
        if named is None:
            return Denial(400, "bad_request", "invalid profile id")
        bound_id = profile_id(bound) if bound else None
        if bound_id is None or named != bound_id:
            return Denial(403, "forbidden", "this daemon runs a different profile")
        return Denial(0, "", named)
    if bound:
        named = profile_id(bound)
        if named is None:
            return Denial(403, "forbidden", "this daemon runs a different profile")
        return Denial(0, "", named)
    return Denial(0, "unscoped", "")


def _audit(audit: AuditLog | None, kind: str, summary: str, payload: dict[str, object]) -> None:
    if audit is None:
        return
    audit.append(session_id=None, kind=kind, summary=summary, payload=payload)


def _audit_or_unavailable(
    audit: AuditLog | None,
    kind: str,
    summary: str,
    payload: dict[str, object],
) -> bool:
    """False when ``prime.db`` stays locked past the audit busy timeout."""
    try:
        _audit(audit, kind, summary, payload)
    except sqlite3.OperationalError:
        return False
    return True


def _error(code: str, message: str) -> dict[str, object]:
    return {"ok": False, "error": {"code": code, "message": message}}


def _safe_name(value: str) -> str:
    text = value.strip().casefold()
    if len(text) > 64:
        return ""
    return text


def _safe_ip(value: str) -> str:
    text = value.strip()
    if not text or len(text) > 64:
        return ""
    allowed = "0123456789.:abcdefABCDEF%"
    if any(ch not in allowed for ch in text):
        return ""
    return text
