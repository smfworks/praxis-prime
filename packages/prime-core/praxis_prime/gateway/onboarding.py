"""HTTP and WebSocket setup routes. First-run owner creation is HTTP only."""

from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
import threading
import time
from typing import Any

from praxis_prime.accounts.db import AccountError, session_cookie
from praxis_prime.accounts.factors import Factors
from praxis_prime.accounts.oidc import OidcError, add_provider, get_provider, secret_name
from praxis_prime.accounts.roles import sees_all_profiles
from praxis_prime.channels.secrets import secret_file, write_secret
from praxis_prime.channels.telegram import PairingStore
from praxis_prime.gateway.authz import Denial, authenticate_http
from praxis_prime.onboarding.record import inference_ready
from praxis_prime.onboarding.service import OnboardingError, OnboardingService, Selection
from praxis_prime.onboarding.token import HEADER_NAME, invalidate_first_run_token, token_matches
from praxis_prime.paths import state_dir

_WINDOW_SECONDS = 900.0
_FAILURE_LIMIT = 5
_OWNER_WAIT_SECONDS = 8.0
_OWNER_WAIT_STEP = 0.05
_LOOPBACK_PEERS = {"127.0.0.1", "::1"}
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class SetupFailures:
    """Wrong first-run tokens, counted per peer."""

    def __init__(self) -> None:
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def blocked(self, peer: str, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        with self._lock:
            return len(self._prune(peer, current)) >= _FAILURE_LIMIT

    def record(self, peer: str, now: float | None = None) -> bool:
        """Record one failure. True when the peer is now over the limit."""
        current = time.monotonic() if now is None else now
        with self._lock:
            hits = self._prune(peer, current)
            hits.append(current)
            self._hits[peer] = hits
            return len(hits) >= _FAILURE_LIMIT

    def _prune(self, peer: str, now: float) -> list[float]:
        hits = [item for item in self._hits.get(peer, []) if now - item < _WINDOW_SECONDS]
        self._hits[peer] = hits
        return hits


def handle_onboarding(
    server: Any,
    method: str,
    route: str,
    headers: dict[str, str],
    body: bytes,
    extras: list[tuple[str, str]],
    peer: str,
    query: str,
) -> tuple[int, dict[str, object]] | None:
    """Return a response, or None when this is not an onboarding route."""
    del query  # the setup token is never accepted from the query string
    if not route.startswith("/v1/onboarding/"):
        return None
    accounts = server.accounts
    if accounts is None:
        if method == "GET" and route == "/v1/onboarding/status":
            return 200, {"setupRequired": False}
        return 403, _error("forbidden", "Use `praxis-prime setup` from this computer.")
    owner_exists = accounts.has_accounts()
    if owner_exists and server.config_dir is not None:
        invalidate_first_run_token(server.config_dir)
    if method == "GET" and route == "/v1/onboarding/status":
        return _status(server, headers, method, owner_exists, peer)
    if not owner_exists:
        return _first_run(server, method, route, headers, body, extras, peer)
    principal = authenticate_http(
        accounts,
        headers,
        method,
        bootstrap_token=server.token,
        bearer_enabled=server.bearer_enabled,
    )
    if isinstance(principal, Denial) or not sees_all_profiles(principal.role):
        return 403, _error("forbidden", "only an owner or admin can change setup")
    return _dispatch(server, method, route, body, principal, extras)


def onboarding_payload(
    server: Any,
    kind: str,
    payload: dict[str, object],
    actor: str,
) -> dict[str, object]:
    """Authenticated owner/admin WebSocket calls. Owner creation is not here."""
    service = _service(server, actor)
    if kind == "onboarding.status":
        return _admin_status(server)
    if kind == "onboarding.detect":
        return service.detect()
    if kind == "onboarding.probe":
        url = str(payload.get("url", ""))
        pin = str(payload.get("tlsFingerprint", "") or "")
        return service.probe(url, pin=pin, capture_fingerprint=not pin)
    if kind == "onboarding.test":
        return service.test(
            provider=str(payload.get("provider", "")),
            model=str(payload.get("model", "")),
            base_url=str(payload.get("baseUrl", "") or ""),
            lane=str(payload.get("lane", "") or ""),
            api_key=str(payload.get("apiKey", "") or ""),
            pin=str(payload.get("tlsFingerprint", "") or ""),
        )
    if kind == "onboarding.save":
        return service.save(_selection(payload, actor))
    raise OnboardingError("unknown setup request", code="not_found")


def _status(
    server: Any,
    headers: dict[str, str],
    method: str,
    owner_exists: bool,
    peer: str,
) -> tuple[int, dict[str, object]]:
    if not owner_exists:
        presented = headers.get(HEADER_NAME, "").strip()
        if not presented:
            return 200, {"setupRequired": True}
        denied = _token_gate(server, headers, peer)
        if denied is not None:
            return denied
        return 200, _service(server, "").status(owner_exists=False)
    principal = authenticate_http(
        server.accounts,
        headers,
        method,
        bootstrap_token=server.token,
        bearer_enabled=server.bearer_enabled,
    )
    if isinstance(principal, Denial):
        return 200, {"setupRequired": False}
    if not sees_all_profiles(principal.role):
        ready = False
        if server.config_dir is not None:
            ready = inference_ready(server.config_dir, _service(server, "")._settings().model_spec)
        return 200, {"setupRequired": False, "inferenceReady": ready}
    return 200, _admin_status(server)


def _token_gate(
    server: Any,
    headers: dict[str, str],
    peer: str,
) -> tuple[int, dict[str, object]] | None:
    host = _host_name(headers.get("host", ""))
    if server.host != "127.0.0.1" or peer not in _LOOPBACK_PEERS or host not in _LOOPBACK_HOSTS:
        return 403, _error(
            "forbidden",
            "First-run setup from another machine is refused. Use `praxis-prime setup`.",
        )
    if server.config_dir is None:
        return 403, _error("forbidden", "Use `praxis-prime setup` from this computer.")
    presented = headers.get(HEADER_NAME, "").strip()
    if not presented:
        return 401, _error("unauthorized", "first-run token required")
    if token_matches(server.config_dir, presented):
        return None
    # ``peer`` is the socket address. X-Forwarded-For is not a peer.
    failures: SetupFailures = server.setup_failures
    if failures.blocked(peer) or failures.record(peer):
        return 429, _error("rate_limited", "too many setup attempts; wait and try again")
    return 401, _error("unauthorized", "first-run token was rejected")


def _admin_status(server: Any) -> dict[str, object]:
    return _service(server, "").status(owner_exists=server.accounts.has_accounts())


def _first_run(
    server: Any,
    method: str,
    route: str,
    headers: dict[str, str],
    body: bytes,
    extras: list[tuple[str, str]],
    peer: str,
) -> tuple[int, dict[str, object]]:
    denied = _token_gate(server, headers, peer)
    if denied is not None:
        return denied
    if server.accounts.has_accounts():
        invalidate_first_run_token(server.config_dir)
        return 409, _error("conflict", "an owner account already exists")
    return _dispatch(server, method, route, body, None, extras)


def _dispatch(
    server: Any,
    method: str,
    route: str,
    body: bytes,
    principal: Any,
    extras: list[tuple[str, str]],
) -> tuple[int, dict[str, object]]:
    if method != "POST":
        return 405, _error("method", "method not allowed")
    try:
        payload = _object(body)
    except OnboardingError as exc:
        return 400, _error(exc.code, str(exc))
    actor = "" if principal is None else str(getattr(principal, "account_id", "") or "")
    service = _service(server, actor)
    try:
        if route == "/v1/onboarding/owner":
            return _create_owner(server, payload, extras)
        if route == "/v1/onboarding/detect":
            return 200, service.detect()
        if route == "/v1/onboarding/probe":
            return 200, service.probe(
                str(payload.get("url", "")),
                pin=str(payload.get("tlsFingerprint", "") or ""),
                capture_fingerprint=not str(payload.get("tlsFingerprint", "") or ""),
            )
        if route == "/v1/onboarding/test":
            return 200, service.test(
                provider=str(payload.get("provider", "")),
                model=str(payload.get("model", "")),
                base_url=str(payload.get("baseUrl", "") or ""),
                lane=str(payload.get("lane", "") or ""),
                api_key=str(payload.get("apiKey", "") or ""),
                pin=str(payload.get("tlsFingerprint", "") or ""),
            )
        if route == "/v1/onboarding/save":
            _require_step_up(server, principal, payload)
            return 200, service.save(_selection(payload, actor))
        if route == "/v1/onboarding/dials":
            positions = payload.get("positions")
            if not isinstance(positions, dict):
                return 400, _error("bad_request", "positions must be an object")
            clean = {str(key): str(value) for key, value in positions.items()}
            return 200, {"ok": True, "dials": service.set_dials(clean, actor=actor)}
        if route == "/v1/onboarding/oidc":
            return _oidc(server, payload)
        if route == "/v1/onboarding/telegram":
            return _telegram(server)
    except OnboardingError as exc:
        status = {"usage": 400, "replace": 409, "allowlist": 403, "context": 422, "test": 422}.get(
            exc.code, 400
        )
        return status, _error(exc.code, str(exc))
    return 404, _error("not_found", "no such setup route")


def _create_owner(
    server: Any,
    payload: dict[str, object],
    extras: list[tuple[str, str]],
) -> tuple[int, dict[str, object]]:
    from praxis_prime.onboarding.owner import clear_discarded_owner, create_owner_account
    from praxis_prime.profiles.migrate import MigrationBusy

    username = payload.get("username", "")
    password = payload.get("password", "")
    display = payload.get("displayName", "")
    if not isinstance(username, str) or not isinstance(password, str):
        return 400, _error("bad_request", "username and password must be strings")
    if not isinstance(display, str):
        display = ""
    if server.data_root is None or server.config_dir is None:
        return 400, _error("bad_request", "data directory is not set")
    store = server.accounts
    _release_owned_database(server)
    try:
        created = create_owner_account(
            store,
            server.data_root,
            server.config_dir,
            username=username,
            password=password,
            display_name=display or username,
            daemon_running=lambda: False,
        )
    except MigrationBusy:
        if _wait_for_owner(store):
            invalidate_first_run_token(server.config_dir)
            return 409, _error("conflict", "an owner account already exists")
        return 503, _error(
            "unavailable",
            "prime.db is open, so this setup cannot move the existing data. "
            "Stop praxis-primed and run `praxis-prime setup`.",
        )
    except AccountError as exc:
        message = str(exc)
        if "already exists" in message:
            invalidate_first_run_token(server.config_dir)
            return 409, _error("conflict", message)
        return 400, _error("bad_request", message)
    except OSError as exc:
        return 503, _error("unavailable", str(exc))
    account = created.account
    try:
        _audit_owner_created(server.data_root, account)
    except (OSError, sqlite3.Error, RuntimeError, ValueError):
        try:
            clear_discarded_owner(server.data_root, account.id)
        except OSError:
            pass
        store.discard_account(account.id)
        return 503, _error("unavailable", "audit log is busy; the owner was not kept")
    invalidate_first_run_token(server.config_dir)
    issued = store.open_session(account)
    extras.append(("Set-Cookie", session_cookie(issued.token, max_age=issued.max_age)))
    return 201, {
        "ok": True,
        "account": account.public(),
        "csrfToken": issued.csrf_token,
        "restartRequired": not created.profiles_existed,
    }


def _wait_for_owner(store: Any) -> bool:
    """True when a peer finishes creating the owner while this call waits."""
    deadline = time.monotonic() + _OWNER_WAIT_SECONDS
    while time.monotonic() < deadline:
        if store.has_accounts():
            return True
        time.sleep(_OWNER_WAIT_STEP)
    return bool(store.has_accounts())


def _release_owned_database(server: Any) -> None:
    """Drop this process's flock on prime.db so the shared migration can move it."""
    runtime = getattr(getattr(server, "agent", None), "runtime", None)
    audit = getattr(server, "audit", None)
    db = getattr(runtime, "db", None) if runtime is not None else None
    if audit is not None:
        try:
            audit.close()
        except (OSError, sqlite3.Error, RuntimeError, ValueError):
            pass
        server.audit = None
        if runtime is not None and getattr(runtime, "audit", None) is audit:
            runtime.audit = None
        if db is None:
            db = getattr(audit, "db", None)
    if db is None:
        return
    try:
        db.close()
    except (OSError, sqlite3.Error, RuntimeError, ValueError):
        release = getattr(db, "_release_lock", None)
        if callable(release):
            try:
                release()
            except (OSError, sqlite3.Error, RuntimeError, ValueError):
                pass
    if runtime is not None:
        runtime.db = None


def _audit_owner_created(data_root: Any, account: Any) -> None:
    """Append the owner row where the profile reader looks after the move."""
    from praxis_prime.audit.log import AuditLog
    from praxis_prime.profiles.home import ProfileHome
    from praxis_prime.state import StateDB

    db = StateDB(ProfileHome(data_root, "default").db_path)
    log = AuditLog(db)
    try:
        log.append(
            session_id=None,
            kind="auth.login",
            summary="owner created from first-run setup",
            payload={
                "actor_account": account.id,
                "username": account.username,
                "role": account.role,
                "method": "setup",
                "profile": "default",
            },
            actor_account=account.id,
            profile="default",
        )
    finally:
        log.close()
        db.close()


def _require_step_up(server: Any, principal: Any, payload: dict[str, object]) -> None:
    api_key = str(payload.get("apiKey", "") or "")
    provider = str(payload.get("provider", "") or "").strip().lower()
    if not api_key or principal is None:
        return
    from praxis_prime.onboarding.service import KEY_NAMES, _secret_exists

    name = KEY_NAMES.get(provider, "")
    if not name or server.config_dir is None:
        return
    if not _secret_exists(server.config_dir, {}, name):
        return
    session_id = str(getattr(principal, "session_id", "") or "")
    token = str(payload.get("stepUpToken", "") or "")
    factors = Factors(server.accounts)
    spent = factors.step_up_valid(principal.account_id, token, session_id)
    if not session_id or not spent:
        raise OnboardingError(
            "replacing a provider key needs a step-up, or `praxis-prime setup --replace`",
            code="replace",
        )


def _oidc(server: Any, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
    provider_id = str(payload.get("providerId", "") or "")
    secret = str(payload.get("clientSecret", "") or "")
    if get_provider(server.accounts, provider_id) is not None:
        return 409, _error(
            "conflict",
            "that OIDC provider already exists; its secret was left in place",
        )
    if not secret:
        return 400, _error("bad_request", "client secret is required")
    name = secret_name(provider_id)
    if server.config_dir is None:
        return 400, _error("bad_request", "config directory is not set")
    write_secret(secret_file(server.config_dir), name, secret)
    try:
        add_provider(
            server.accounts,
            provider_id=provider_id,
            display_name=str(payload.get("displayName", "") or provider_id),
            issuer=str(payload.get("issuer", "") or ""),
            client_id=str(payload.get("clientId", "") or ""),
            secret_key=name,
            preset=str(payload.get("preset", "") or ""),
        )
    except OidcError as exc:
        return 400, _error("bad_request", str(exc))
    return 200, {"ok": True, "providerId": provider_id, "secretKey": name}


def _telegram(server: Any) -> tuple[int, dict[str, object]]:
    root = server.data_root
    if root is None:
        return 400, _error("bad_request", "data directory is not set")
    store = PairingStore(state_dir() / "telegram-pairing.json", root / "telegram-owner.json")
    code = store.issue()
    return 200, {"ok": True, "command": f"/pair {code}"}


def _selection(payload: dict[str, object], actor: str) -> Selection:
    return Selection(
        lane=str(payload.get("lane", "") or ""),
        provider=str(payload.get("provider", "") or ""),
        model=str(payload.get("model", "") or ""),
        utility_model=str(payload.get("utilityModel", "") or ""),
        vision_model=str(payload.get("visionModel", "") or ""),
        judge_model=str(payload.get("judgeModel", "") or ""),
        base_url=str(payload.get("baseUrl", "") or ""),
        api_key=str(payload.get("apiKey", "") or ""),
        tls_fingerprint=str(payload.get("tlsFingerprint", "") or ""),
        replace=payload.get("replace") is True,
        actor=actor,
    )


def _service(server: Any, actor: str) -> OnboardingService:
    def audit(kind: str, summary: str, payload: dict[str, object]) -> None:
        if server.audit is None:
            return
        stamped = dict(payload)
        if actor:
            stamped["actor_account"] = actor
        server.audit.append(
            session_id=None,
            kind=kind,
            summary=summary,
            payload=stamped,
            actor_account=actor,
        )

    return OnboardingService(
        config_dir=server.config_dir,
        data_dir=server.data_root,
        env=getattr(server, "onboarding_env", os.environ),
        fetcher=getattr(server, "onboarding_fetcher", None),
        hardware_runner=getattr(server, "onboarding_runner", None),
        audit=audit if server.audit is not None else None,
    )


def _object(body: bytes) -> dict[str, object]:
    if not body:
        return {}
    try:
        loaded = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OnboardingError("body must be JSON", code="bad_request") from exc
    if not isinstance(loaded, dict):
        raise OnboardingError("body must be a JSON object", code="bad_request")
    return loaded


def _error(code: str, message: str) -> dict[str, object]:
    return {"ok": False, "error": {"code": code, "message": message}}


def _host_name(value: str) -> str:
    """Hostname only. Bracketed loopback normalizes to ``::1`` or ``127.0.0.1``.

    The check parses the address. It does not resolve DNS.
    """
    text = value.strip().lower()
    if text.startswith("["):
        end = text.find("]")
        text = text[1:end] if end != -1 else text
    else:
        text = text.split(":", 1)[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return text
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_loopback:
        return "::1" if address.version == 6 else "127.0.0.1"
    return text
