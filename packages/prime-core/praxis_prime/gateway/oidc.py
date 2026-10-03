"""HTTP adapter for OpenID Connect sign-in.

Public routes start a login and finish the provider redirect. Session
routes list, link, and unlink identities. Linking and unlinking need a
step-up. The browser only sees a generic error. The audit row has the
reason, and it does not contain tokens, codes, or the client secret.

An OIDC sign-in is one factor. It does not mint a step-up token. When
TOTP is confirmed, the callback sets ``pp_mfa`` and waits for
``POST /v1/auth/login/totp``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from urllib.parse import parse_qs

from praxis_prime.accounts.db import AccountStore, cookie_value
from praxis_prime.accounts.factors import Factors
from praxis_prime.accounts.oidc import (
    CLIENT_COOKIE,
    OIDC_COOKIE,
    TXN_TTL_SECONDS,
    OidcError,
    abandon,
    apply_mapped_role,
    begin,
    binding_cookie,
    client_binding,
    complete,
    get_provider,
    list_identities,
    loopback_redirect,
    mfa_cookie,
    public_providers,
    unlink,
    unlink_allowed,
)
from praxis_prime.accounts.oidc import (
    transaction_kind as _transaction,
)
from praxis_prime.audit.log import AuditLog
from praxis_prime.gateway.authz import (
    Principal,
    _audit_or_unavailable,
    _error,
    _safe_ip,
    _safe_name,
)
from praxis_prime.gateway.factors import _open_session
from praxis_prime.observe import JsonLogger

_Result = tuple[int, dict[str, object], list[tuple[str, str]]]
SIGN_IN = "Sign-in could not be completed."
CHANGE = "The change could not be completed."
_REASONS = frozenset(
    {
        "malformed",
        "alg_rejected",
        "bad_signature",
        "unknown_kid",
        "bad_issuer",
        "bad_audience",
        "bad_azp",
        "expired",
        "bad_time",
        "bad_nonce",
        "reused_nonce",
        "reused_state",
        "bad_state",
        "bad_binding",
        "missing_code",
        "missing_pkce",
        "missing_id_token",
        "not_linked",
        "email_unverified",
        "email_not_allowed",
        "email_ambiguous",
        "privileged_link",
        "issuer_taken",
        "identity_taken",
        "last_factor",
        "step_up",
        "provider_denied",
        "provider_http",
        "provider_unreachable",
        "redirect_refused",
        "url_rejected",
        "discovery_issuer",
        "discovery_endpoint",
        "response_too_large",
        "secret_missing",
        "unknown_provider",
        "bad_redirect",
        "locked",
        "disabled",
        "session_expired",
        "busy",
        "token_rejected",
        "rejected",
        "provider_exists",
        "bad_request",
        "link-started",
        "linked",
        "unlinked",
    }
)
_BLOCKED = frozenset(
    {
        "code",
        "token",
        "id_token",
        "access_token",
        "refresh_token",
        "client_secret",
        "nonce",
        "state",
        "verifier",
        "authorizationurl",
    }
)


def oidc_public(
    store: AccountStore | None,
    method: str,
    route: str,
    headers: dict[str, str],
    query: str,
    body: bytes,
    audit: AuditLog | None,
    logger: JsonLogger | None,
    *,
    port: int,
    peer: str,
) -> _Result | None:
    """Handle a route that does not need a session. None if this is not one."""
    if (method, route) not in {
        ("GET", "/v1/auth/oidc/providers"),
        ("POST", "/v1/auth/oidc/login"),
        ("GET", "/v1/auth/oidc/callback"),
    }:
        return None
    if store is None:
        return 503, _error("unavailable", "accounts are not configured"), []
    if method == "GET" and route == "/v1/auth/oidc/providers":
        # The login page calls this before the button, so a browser already
        # holds a signed pp_client when it starts sign-in.
        presented = cookie_value(headers.get("cookie", ""), CLIENT_COOKIE)
        _client, cookies = client_binding(store, presented)
        return 200, {"ok": True, "providers": public_providers(store)}, cookies
    if method == "POST" and route == "/v1/auth/oidc/login":
        return _start_login(store, headers, body, audit, logger, port=port, peer=peer)
    return _callback(store, headers, query, audit, logger, peer=peer)


def oidc_session(
    store: AccountStore,
    principal: Principal,
    method: str,
    route: str,
    headers: dict[str, str],
    body: bytes,
    audit: AuditLog | None,
    logger: JsonLogger | None,
    *,
    port: int,
    peer: str,
) -> _Result | None:
    """List, link, or unlink. The caller has already checked the session CSRF."""
    if (method, route) not in {
        ("GET", "/v1/auth/oidc/identities"),
        ("POST", "/v1/auth/oidc/link"),
        ("POST", "/v1/auth/oidc/unlink"),
    }:
        return None
    if principal.kind != "session" or not principal.session_id:
        return 401, _error("unauthorized", "authentication required"), []
    if method == "GET":
        return 200, {"ok": True, "identities": list_identities(store, principal.account_id)}, []
    if route.endswith("/link"):
        return _link(store, principal, headers, body, audit, logger, port=port, peer=peer)
    return _unlink(store, principal, body, audit, peer=peer)


def _start_login(
    store: AccountStore,
    headers: dict[str, str],
    body: bytes,
    audit: AuditLog | None,
    logger: JsonLogger | None,
    *,
    port: int,
    peer: str,
) -> _Result:
    parsed = _object(body)
    if parsed is None:
        return 400, _error("bad_request", "login body must be JSON"), []
    provider_id = parsed.get("provider", "")
    if not isinstance(provider_id, str):
        return 400, _error("bad_request", "provider must be a string"), []
    client, client_cookies = _browser_key(store, headers)
    try:
        redirect = loopback_redirect(headers.get("host", ""), port)
        url, binding = begin(
            store,
            provider_id=provider_id,
            redirect_uri=redirect,
            kind="login",
            client_key=client,
        )
    except OidcError as exc:
        status, payload, cookies = _posted_error(
            audit,
            exc,
            provider_id=_safe_provider(provider_id),
            peer=peer,
            message=SIGN_IN,
        )
        return status, payload, [*cookies, *client_cookies]
    del logger
    return 200, {"ok": True, "authorizationUrl": url}, [
        ("Set-Cookie", binding_cookie(binding, max_age=TXN_TTL_SECONDS)),
        *client_cookies,
    ]


def _callback(
    store: AccountStore,
    headers: dict[str, str],
    query: str,
    audit: AuditLog | None,
    logger: JsonLogger | None,
    *,
    peer: str,
) -> _Result:
    try:
        params = parse_qs(query, keep_blank_values=False, max_num_fields=16)
    except ValueError:
        params = {}
    state = _one(params, "state")
    kind, provider_id = _transaction(store, state) if state else ("", "")
    message = CHANGE if kind == "link" else SIGN_IN
    outcome = "error"
    if _one(params, "error"):
        if state:
            abandon(store, state)
        return _nav_error(
            audit,
            reason="provider_denied",
            provider_id=provider_id,
            peer=peer,
            message=message,
            outcome=outcome,
        )
    code = _one(params, "code")
    binding = cookie_value(headers.get("cookie", ""), OIDC_COOKIE)
    if not state or not code:
        if state:
            abandon(store, state)
        return _nav_error(
            audit,
            reason="missing_code" if state else "bad_state",
            provider_id=provider_id,
            peer=peer,
            message=message,
            outcome=outcome,
        )
    scrub: Callable[[str], None] | None = None if logger is None else logger.add_secret
    try:
        done = complete(store, state=state, binding=binding, code=code, scrub=scrub)
    except OidcError as exc:
        return _nav_error(
            audit,
            reason=exc.reason,
            provider_id=provider_id,
            peer=peer,
            message=message,
            outcome=outcome,
        )
    except Exception:
        return _nav_error(
            audit,
            reason="rejected",
            provider_id=provider_id,
            peer=peer,
            message=message,
            outcome=outcome,
        )
    if done.kind == "link":
        if not _record(
            audit,
            "auth.oidc",
            "oidc identity linked",
            {
                "actor_account": done.account.id,
                "username": done.account.username,
                "provider": done.provider_id,
                "action": "linked",
                "method": "oidc",
            },
        ):
            return 503, _error("unavailable", "audit log is busy"), _clear_binding()
        return 302, {"ok": True, "account": done.account.public()}, [
            *_clear_binding(),
            ("Location", "/?oidc=linked"),
        ]
    if Factors(store).totp_active(done.account.id):
        if not _record(
            audit,
            "auth.mfa",
            "second factor required",
            {
                "actor_account": done.account.id,
                "username": done.account.username,
                "role": done.account.role,
                "provider": done.provider_id,
                "method": "oidc",
            },
        ):
            return 503, _error("unavailable", "audit log is busy; login was not completed"), []
        token = Factors(store).issue_mfa(done.account.id, pending_role=done.mapped_role)
        return 302, {
            "ok": True,
            "mfaRequired": True,
            "methods": ["totp", "recovery"],
        }, [
            ("Set-Cookie", mfa_cookie(token)),
            *_clear_binding(),
            ("Location", "/?oidc=mfa"),
        ]
    account = apply_mapped_role(store, done.account, done.mapped_role)
    status, payload, cookies = _open_session(store, account, audit, method="oidc")
    if status != 200:
        return status, payload, cookies
    if "stepUpToken" in payload:
        payload.pop("stepUpToken", None)
    return 302, payload, [*cookies, *_clear_binding(), ("Location", "/?oidc=ok")]


def _link(
    store: AccountStore,
    principal: Principal,
    headers: dict[str, str],
    body: bytes,
    audit: AuditLog | None,
    logger: JsonLogger | None,
    *,
    port: int,
    peer: str,
) -> _Result:
    parsed = _object(body)
    if parsed is None:
        return 400, _error("bad_request", "body must be JSON"), []
    provider_id = parsed.get("provider", "")
    if not isinstance(provider_id, str):
        return 400, _error("bad_request", "provider must be a string"), []
    safe = _safe_provider(provider_id)
    try:
        redirect = loopback_redirect(headers.get("host", ""), port)
        if get_provider(store, provider_id) is None:
            raise OidcError("unknown_provider")
    except OidcError as exc:
        return _change_error(audit, principal, exc.reason, safe, peer)
    denied = _spend_step_up(store, principal, parsed)
    if denied is not None:
        _change_audit(audit, principal, "step_up", safe, peer)
        return denied
    try:
        url, binding = begin(
            store,
            provider_id=provider_id,
            redirect_uri=redirect,
            kind="link",
            account_id=principal.account_id,
            session_id=principal.session_id,
            client_key=principal.session_id,
        )
    except OidcError as exc:
        return _change_error(audit, principal, exc.reason, safe, peer)
    if not _change_audit(audit, principal, "link-started", safe, peer):
        return 503, _error("unavailable", "audit log is busy"), []
    del logger
    return 200, {"ok": True, "authorizationUrl": url}, [
        ("Set-Cookie", binding_cookie(binding, max_age=TXN_TTL_SECONDS)),
    ]


def _unlink(
    store: AccountStore,
    principal: Principal,
    body: bytes,
    audit: AuditLog | None,
    *,
    peer: str,
) -> _Result:
    parsed = _object(body)
    if parsed is None:
        return 400, _error("bad_request", "body must be JSON"), []
    issuer = parsed.get("issuer", "")
    subject = parsed.get("subject", "")
    if not isinstance(issuer, str) or not isinstance(subject, str):
        return 400, _error("bad_request", "issuer and subject must be strings"), []
    try:
        unlink_allowed(store, principal.account_id, issuer, subject)
    except OidcError as exc:
        return _change_error(audit, principal, exc.reason, "", peer, status=exc.status)
    denied = _spend_step_up(store, principal, parsed)
    if denied is not None:
        _change_audit(audit, principal, "step_up", "", peer)
        return denied
    try:
        unlink(store, principal.account_id, issuer, subject)
    except OidcError as exc:
        return _change_error(audit, principal, exc.reason, "", peer, status=exc.status)
    if not _change_audit(audit, principal, "unlinked", "", peer):
        return 503, _error("unavailable", "audit log is busy"), []
    return 200, {"ok": True}, []


def _spend_step_up(
    store: AccountStore,
    principal: Principal,
    parsed: dict[str, object],
) -> _Result | None:
    token = parsed.get("stepUpToken", "")
    if not isinstance(token, str):
        return 400, _error("bad_request", "step-up token must be a string"), []
    if Factors(store).step_up_valid(principal.account_id, token, principal.session_id):
        return None
    return 401, {"ok": False, "error": {"code": "oidc_error", "message": CHANGE}}, []


def _posted_error(
    audit: AuditLog | None,
    exc: OidcError,
    *,
    provider_id: str,
    peer: str,
    message: str,
) -> _Result:
    if not _fail(audit, reason=exc.reason, provider_id=provider_id, peer=peer, username=""):
        return 503, _error("unavailable", "audit log is busy"), []
    status = exc.status if exc.status in {400, 401, 409, 429} else 400
    if exc.reason == "last_factor":
        return 409, {"ok": False, "error": {"code": "last_factor", "message": CHANGE}}, []
    return status, {"ok": False, "error": {"code": "oidc_error", "message": message}}, []


def _nav_error(
    audit: AuditLog | None,
    *,
    reason: str,
    provider_id: str,
    peer: str,
    message: str,
    outcome: str,
) -> _Result:
    if not _fail(audit, reason=reason, provider_id=provider_id, peer=peer, username=""):
        return 503, _error("unavailable", "audit log is busy"), _clear_binding()
    return 302, {"ok": False, "error": {"code": "oidc_error", "message": message}}, [
        *_clear_binding(),
        ("Location", f"/?oidc={outcome}"),
    ]


def _change_error(
    audit: AuditLog | None,
    principal: Principal,
    reason: str,
    provider_id: str,
    peer: str,
    *,
    status: int = 400,
) -> _Result:
    if not _change_audit(audit, principal, reason, provider_id, peer):
        return 503, _error("unavailable", "audit log is busy"), []
    if reason == "last_factor":
        return 409, {"ok": False, "error": {"code": "last_factor", "message": CHANGE}}, []
    code_status = status if status in {400, 401, 409, 429} else 400
    return code_status, {"ok": False, "error": {"code": "oidc_error", "message": CHANGE}}, []


def _fail(
    audit: AuditLog | None,
    *,
    reason: str,
    provider_id: str,
    peer: str,
    username: str,
) -> bool:
    name = username or provider_id or "oidc"
    return _record(
        audit,
        "auth.fail",
        "oidc sign-in failed",
        {
            "method": "oidc",
            "reason": _reason(reason),
            "provider": provider_id,
            "username": _safe_name(name) or "oidc",
            "ip": _safe_ip(peer),
        },
    )


def _change_audit(
    audit: AuditLog | None,
    principal: Principal,
    reason: str,
    provider_id: str,
    peer: str,
) -> bool:
    return _record(
        audit,
        "auth.oidc",
        "oidc account change",
        {
            "actor_account": principal.account_id,
            "username": _safe_name(principal.username),
            "provider": provider_id,
            "action": _reason(reason),
            "method": "oidc",
            "ip": _safe_ip(peer),
        },
    )


def _record(
    audit: AuditLog | None,
    kind: str,
    summary: str,
    payload: dict[str, object],
) -> bool:
    return _audit_or_unavailable(audit, kind, summary, _scrub(payload))


def _scrub(payload: dict[str, object]) -> dict[str, object]:
    cleaned: dict[str, object] = {}
    for key, value in payload.items():
        if key.casefold() in _BLOCKED or not isinstance(value, str):
            continue
        if len(value) > 512 or "eyJ" in value:
            continue
        cleaned[key] = value
    return cleaned


def _reason(value: str) -> str:
    if value in _REASONS:
        return value
    return "rejected"


def _safe_provider(value: str) -> str:
    text = value.strip().casefold()
    if len(text) > 64 or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789-" for char in text):
        return ""
    return text


def _clear_binding() -> list[tuple[str, str]]:
    return [("Set-Cookie", binding_cookie("", max_age=0))]


def _browser_key(
    store: AccountStore, headers: dict[str, str]
) -> tuple[str, list[tuple[str, str]]]:
    """A verified pp_client id, or the anonymous bucket when the cookie fails."""
    presented = cookie_value(headers.get("cookie", ""), CLIENT_COOKIE)
    return client_binding(store, presented)


def _object(body: bytes) -> dict[str, object] | None:
    try:
        parsed = json.loads(body.decode("utf-8") or "{}")
    except (UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def _one(params: dict[str, list[str]], key: str) -> str:
    values = params.get(key, [])
    if len(values) != 1 or not isinstance(values[0], str):
        return ""
    if len(values[0]) > 2048:
        return ""
    return values[0]
