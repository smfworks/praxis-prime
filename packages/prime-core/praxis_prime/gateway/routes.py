"""Allowlist of gateway routes, and id agreement across path, body, and query.

A route that is not on the list is rejected. When the same id appears in
more than one of the path, the body, and the query, the values must match.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from urllib.parse import parse_qs

_APPROVAL = re.compile(r"^/v1/approvals/(ap_[0-9a-f]{8})$")
_ROUTINE = re.compile(r"^/v1/routines/(rt_[0-9a-f]{8})/fire$")
_PROFILE = re.compile(r"^/v1/profiles/([a-z][a-z0-9-]{0,63})$")

_EXACT = frozenset(
    {
        ("GET", "/health"),
        ("GET", "/status"),
        ("POST", "/v1/auth/login"),
        ("POST", "/v1/auth/login/totp"),
        ("GET", "/v1/auth/oidc/providers"),
        ("POST", "/v1/auth/oidc/login"),
        ("GET", "/v1/auth/oidc/callback"),
        ("GET", "/v1/auth/oidc/identities"),
        ("POST", "/v1/auth/oidc/link"),
        ("POST", "/v1/auth/oidc/unlink"),
        ("POST", "/v1/auth/logout"),
        ("GET", "/v1/auth/session"),
        ("POST", "/v1/auth/ws-ticket"),
        ("POST", "/v1/auth/passkey/options"),
        ("POST", "/v1/auth/passkey/verify"),
        ("POST", "/v1/auth/step-up"),
        ("POST", "/v1/auth/step-up/passkey/options"),
        ("POST", "/v1/auth/step-up/passkey/verify"),
        ("POST", "/v1/auth/totp/enroll"),
        ("POST", "/v1/auth/totp/confirm"),
        ("POST", "/v1/auth/totp/disable"),
        ("POST", "/v1/auth/recovery/regenerate"),
        ("GET", "/v1/auth/factors"),
        ("POST", "/v1/auth/passkey/register/options"),
        ("POST", "/v1/auth/passkey/register/verify"),
        ("POST", "/v1/auth/passkey/remove"),
        ("GET", "/"),
        ("GET", "/index.html"),
        ("GET", "/v1/profiles"),
        ("GET", "/v1/memory"),
        ("GET", "/v1/skills"),
        ("GET", "/v1/routines"),
        ("GET", "/v1/admin/directory"),
        ("GET", "/v1/approvals"),
        ("GET", "/v1/approvals/meta"),
        ("POST", "/v1/approvals"),
        ("POST", "/v1/decide"),
        ("POST", "/v1/systemone"),
        ("GET", "/v1/audit"),
        ("GET", "/v1/onboarding/status"),
        ("POST", "/v1/onboarding/detect"),
        ("POST", "/v1/onboarding/probe"),
        ("POST", "/v1/onboarding/test"),
        ("POST", "/v1/onboarding/save"),
        ("POST", "/v1/onboarding/owner"),
        ("POST", "/v1/onboarding/dials"),
        ("POST", "/v1/onboarding/oidc"),
        ("POST", "/v1/onboarding/telegram"),
        ("GET", "/v1/themes"),
        ("GET", "/v1/themes/active"),
        ("POST", "/v1/themes/preview"),
        ("POST", "/v1/themes/install"),
        ("POST", "/v1/themes/remove"),
        ("POST", "/v1/themes/lock"),
        ("POST", "/v1/themes/select"),
    }
)

_FRAME_TYPES = frozenset(
    {
        "connect",
        "ping",
        "status",
        "approvals.list",
        "approvals.decide",
        "chat.send",
        "model.set",
        "session.drop",
        "onboarding.status",
        "onboarding.detect",
        "onboarding.probe",
        "onboarding.test",
        "onboarding.save",
    }
)


def route_allowed(method: str, route: str) -> bool:
    """True when the SPA or a channel may call this route."""
    if (method, route) in _EXACT:
        return True
    if method == "GET" and route.startswith("/assets/") and _asset_name(route):
        return True
    if method == "POST" and _APPROVAL.fullmatch(route):
        return True
    if method == "POST" and _ROUTINE.fullmatch(route):
        return True
    if method == "GET" and _PROFILE.fullmatch(route):
        return True
    return False


def _asset_name(route: str) -> bool:
    name = route.removeprefix("/assets/")
    if not name or "/" in name or name.startswith("."):
        return False
    return all(char.isalnum() or char in "._-" for char in name) and len(name) <= 128


def frame_allowed(kind: str) -> bool:
    return kind in _FRAME_TYPES


def frame_session_ids_agree(frame: Mapping[str, object]) -> bool:
    """False when the frame and its payload name different sessions."""
    top = frame.get("sessionId")
    payload = frame.get("payload")
    inner = payload.get("sessionId") if isinstance(payload, dict) else None
    if isinstance(top, str) and top and isinstance(inner, str) and inner:
        return top == inner
    return True


def ids_agree(
    *,
    path_id: str = "",
    body: Mapping[str, object] | None = None,
    query: str = "",
    keys: tuple[str, ...] = ("id", "approvalId", "sessionId", "profile"),
) -> bool:
    """True when each id agrees with its other copies.

    ``profile`` and ``sessionId`` are different ids and may differ.
    When ``path_id`` is set, it is the resource id and must match every
    present copy of the keys the caller passed.
    """
    grouped: dict[str, list[str]] = {}

    def add(key: str, value: str) -> None:
        if value:
            grouped.setdefault(key, []).append(value)

    if body:
        for key in keys:
            raw = body.get(key)
            if isinstance(raw, str):
                add(key, raw)
    if query:
        parsed = parse_qs(query, keep_blank_values=False)
        for key in keys:
            for item in parsed.get(key, []):
                add(key, item)
    if path_id:
        for key in list(grouped):
            grouped[key].append(path_id)
    return all(len(set(values)) <= 1 for values in grouped.values())
