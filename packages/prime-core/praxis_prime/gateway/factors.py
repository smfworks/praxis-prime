"""HTTP ceremonies for passkeys and TOTP.

Unauthenticated routes are login's second step and passkey sign-in.
Enrollment requires a session (or the loopback owner bearer token) and,
for cookie sessions, the CSRF header the rest of the gateway already checks.

The bearer token and the Unix socket are not WebAuthn ceremonies. See
docs/SECURITY.md.

docs/blueprint-addendum-2026-09.md §4.3.
"""

from __future__ import annotations

import json

from praxis_prime.accounts.db import AccountStore
from praxis_prime.accounts.factors import FactorError, Factors
from praxis_prime.audit.log import AuditLog
from praxis_prime.gateway.authz import (
    Principal,
    _audit_or_unavailable,
    _error,
    _safe_ip,
    _safe_name,
    session_cookie,
)

_Result = tuple[int, dict[str, object], list[tuple[str, str]]]


def totp_login(
    store: AccountStore,
    body: bytes,
    audit: AuditLog | None,
    *,
    peer: str = "",
) -> _Result:
    parsed = _object(body)
    if parsed is None:
        return 400, _error("bad_request", "login body must be JSON"), []
    token = parsed.get("mfaToken", "")
    code = parsed.get("code", "")
    if not isinstance(token, str) or not isinstance(code, str):
        return 400, _error("bad_request", "mfa token and code must be strings"), []
    account = Factors(store).complete_mfa(token, code)
    if account is None:
        if not _audit_or_unavailable(
            audit,
            "auth.fail",
            "second factor failed",
            {"method": "totp", "ip": _safe_ip(peer)},
        ):
            return 503, _error("unavailable", "audit log is busy"), []
        return 401, _error("unauthorized", "invalid code"), []
    return _open_session(store, account, audit, method=_method_for(code))


def passkey_options(
    store: AccountStore,
    body: bytes,
    *,
    origin: str,
    port: int,
) -> _Result:
    parsed = _object(body)
    if parsed is None:
        return 400, _error("bad_request", "passkey body must be JSON"), []
    username = parsed.get("username", "")
    if not isinstance(username, str):
        return 400, _error("bad_request", "username must be a string"), []
    try:
        options = Factors(store).begin_authentication(
            username,
            origin_header=origin,
            port=port,
        )
    except FactorError as exc:
        return exc.status, _error(exc.code, str(exc)), []
    return 200, {"ok": True, "options": options}, []


def passkey_verify(
    store: AccountStore,
    body: bytes,
    audit: AuditLog | None,
    *,
    peer: str = "",
) -> _Result:
    parsed = _object(body)
    if parsed is None:
        return 400, _error("bad_request", "passkey body must be JSON"), []
    credential = parsed.get("credential")
    account = Factors(store).finish_authentication(credential)
    if account is None:
        if not _audit_or_unavailable(
            audit,
            "auth.fail",
            "passkey rejected",
            {"method": "passkey", "ip": _safe_ip(peer)},
        ):
            return 503, _error("unavailable", "audit log is busy"), []
        return 401, _error("unauthorized", "passkey was rejected"), []
    return _open_session(store, account, audit, method="passkey")


def authed_factor(
    store: AccountStore,
    principal: Principal,
    method: str,
    route: str,
    body: bytes,
    audit: AuditLog | None,
    *,
    origin: str,
    port: int,
) -> _Result | None:
    """Handle an enrollment route, or return None so another handler can."""
    if not principal.account_id:
        if (method, route) in _AUTHED:
            return 401, _error("unauthorized", "authentication required"), []
        return None
    handler = _AUTHED.get((method, route))
    if handler is None:
        return None
    try:
        return handler(store, principal, body, audit, origin=origin, port=port)
    except FactorError as exc:
        return exc.status, _error(exc.code, str(exc)), []


def _totp_enroll(
    store: AccountStore,
    principal: Principal,
    body: bytes,
    audit: AuditLog | None,
    *,
    origin: str,
    port: int,
) -> _Result:
    del body, origin, port
    enrollment = Factors(store).begin_totp(principal.account_id)
    if not _audit_factor(audit, principal, "auth.mfa", "totp enrollment started", "totp"):
        return 503, _error("unavailable", "audit log is busy"), []
    return 200, {
        "ok": True,
        "secret": enrollment.secret,
        "otpauthUri": enrollment.otpauth_uri,
        "recoveryCodes": list(enrollment.recovery_codes),
    }, []


def _totp_confirm(
    store: AccountStore,
    principal: Principal,
    body: bytes,
    audit: AuditLog | None,
    *,
    origin: str,
    port: int,
) -> _Result:
    del origin, port
    code = _code(body)
    if code is None:
        return 400, _error("bad_request", "code must be a string"), []
    Factors(store).confirm_totp(principal.account_id, code)
    if not _audit_factor(audit, principal, "auth.mfa", "totp confirmed", "totp"):
        return 503, _error("unavailable", "audit log is busy"), []
    return 200, {"ok": True, "totp": True}, []


def _totp_disable(
    store: AccountStore,
    principal: Principal,
    body: bytes,
    audit: AuditLog | None,
    *,
    origin: str,
    port: int,
) -> _Result:
    del origin, port
    parsed = _object(body)
    if parsed is None:
        return 400, _error("bad_request", "body must be JSON"), []
    password = parsed.get("password", "")
    if not isinstance(password, str):
        return 400, _error("bad_request", "password must be a string"), []
    Factors(store).disable_totp(principal.username, password)
    if not _audit_factor(audit, principal, "auth.mfa", "totp disabled", "totp"):
        return 503, _error("unavailable", "audit log is busy"), []
    return 200, {"ok": True, "totp": False}, []


def _recovery(
    store: AccountStore,
    principal: Principal,
    body: bytes,
    audit: AuditLog | None,
    *,
    origin: str,
    port: int,
) -> _Result:
    del origin, port
    code = _code(body)
    if code is None:
        return 400, _error("bad_request", "code must be a string"), []
    codes = Factors(store).regenerate_recovery(principal.account_id, code)
    if not _audit_factor(audit, principal, "auth.mfa", "recovery codes replaced", "recovery"):
        return 503, _error("unavailable", "audit log is busy"), []
    return 200, {"ok": True, "recoveryCodes": list(codes)}, []


def _factors_get(
    store: AccountStore,
    principal: Principal,
    body: bytes,
    audit: AuditLog | None,
    *,
    origin: str,
    port: int,
) -> _Result:
    del body, audit, origin, port
    return 200, {"ok": True, **Factors(store).summary(principal.account_id)}, []


def _register_options(
    store: AccountStore,
    principal: Principal,
    body: bytes,
    audit: AuditLog | None,
    *,
    origin: str,
    port: int,
) -> _Result:
    del body, audit
    account = store.get_id(principal.account_id)
    if account is None:
        return 401, _error("unauthorized", "authentication required"), []
    options = Factors(store).begin_registration(account, origin_header=origin, port=port)
    return 200, {"ok": True, "options": options}, []


def _register_verify(
    store: AccountStore,
    principal: Principal,
    body: bytes,
    audit: AuditLog | None,
    *,
    origin: str,
    port: int,
) -> _Result:
    del origin, port
    parsed = _object(body)
    if parsed is None:
        return 400, _error("bad_request", "passkey body must be JSON"), []
    credential = parsed.get("credential")
    name = parsed.get("name", "")
    if not isinstance(name, str):
        return 400, _error("bad_request", "name must be a string"), []
    account = store.get_id(principal.account_id)
    if account is None:
        return 401, _error("unauthorized", "authentication required"), []
    created = Factors(store).finish_registration(account, credential, name=name)
    if not _audit_factor(audit, principal, "auth.mfa", "passkey enrolled", "passkey"):
        return 503, _error("unavailable", "audit log is busy"), []
    return 200, {"ok": True, "passkey": created}, []


def _passkey_remove(
    store: AccountStore,
    principal: Principal,
    body: bytes,
    audit: AuditLog | None,
    *,
    origin: str,
    port: int,
) -> _Result:
    del origin, port
    parsed = _object(body)
    if parsed is None:
        return 400, _error("bad_request", "passkey body must be JSON"), []
    credential_id = parsed.get("credentialId", "")
    if not isinstance(credential_id, str):
        return 400, _error("bad_request", "credential id must be a string"), []
    Factors(store).remove_passkey(principal.account_id, credential_id)
    if not _audit_factor(audit, principal, "auth.mfa", "passkey removed", "passkey"):
        return 503, _error("unavailable", "audit log is busy"), []
    return 200, {"ok": True}, []


_AUTHED = {
    ("POST", "/v1/auth/totp/enroll"): _totp_enroll,
    ("POST", "/v1/auth/totp/confirm"): _totp_confirm,
    ("POST", "/v1/auth/totp/disable"): _totp_disable,
    ("POST", "/v1/auth/recovery/regenerate"): _recovery,
    ("GET", "/v1/auth/factors"): _factors_get,
    ("POST", "/v1/auth/passkey/register/options"): _register_options,
    ("POST", "/v1/auth/passkey/register/verify"): _register_verify,
    ("POST", "/v1/auth/passkey/remove"): _passkey_remove,
}


def _open_session(
    store: AccountStore,
    account: object,
    audit: AuditLog | None,
    *,
    method: str,
) -> _Result:
    from praxis_prime.accounts.db import Account

    if not isinstance(account, Account):
        return 401, _error("unauthorized", "invalid code"), []
    if not _audit_or_unavailable(
        audit,
        "auth.login",
        "login",
        {
            "actor_account": account.id,
            "username": account.username,
            "role": account.role,
            "method": method,
        },
    ):
        return 503, _error("unavailable", "audit log is busy; login was not completed"), []
    store.clear_failures(account.id)
    issued = store.open_session(account)
    payload: dict[str, object] = {
        "ok": True,
        "account": account.public(),
        "csrfToken": issued.csrf_token,
    }
    return 200, payload, [("Set-Cookie", session_cookie(issued.token, max_age=issued.max_age))]


def _audit_factor(
    audit: AuditLog | None,
    principal: Principal,
    kind: str,
    summary: str,
    method: str,
) -> bool:
    return _audit_or_unavailable(
        audit,
        kind,
        summary,
        {
            "actor_account": principal.account_id,
            "username": _safe_name(principal.username),
            "method": method,
        },
    )


def _method_for(code: str) -> str:
    cleaned = code.strip().replace(" ", "")
    if len(cleaned) == 6 and cleaned.isdigit():
        return "totp"
    return "recovery"


def _code(body: bytes) -> str | None:
    parsed = _object(body)
    if parsed is None:
        return None
    code = parsed.get("code", "")
    if not isinstance(code, str):
        return None
    return code


def _object(body: bytes) -> dict[str, object] | None:
    try:
        parsed = json.loads(body.decode("utf-8") or "{}")
    except (UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed
