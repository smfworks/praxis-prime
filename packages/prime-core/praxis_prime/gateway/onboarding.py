"""HTTP and WebSocket setup routes. First-run owner creation is HTTP only."""

from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
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
    if accounts.has_accounts() and _creation_active(server):
        return _await_peer_owner(server)
    owner_exists = accounts.has_accounts()
    if owner_exists and server.config_dir is not None and not _creation_active(server):
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
    principal: Any,
) -> dict[str, object]:
    """Authenticated owner/admin WebSocket calls. Owner creation is not here."""
    actor = "" if principal is None else str(getattr(principal, "account_id", "") or "")
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
        prepared, selection = _prepare_save(server, principal, payload)
        return _finish_save(server, prepared.save(selection))
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
        if _creation_active(server):
            return _await_peer_owner(server)
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
            prepared, selection = _prepare_save(server, principal, payload)
            return 200, _finish_save(server, prepared.save(selection))
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
    from praxis_prime.onboarding.owner import validate_owner_inputs

    username = payload.get("username", "")
    password = payload.get("password", "")
    display = payload.get("displayName", "")
    if not isinstance(username, str) or not isinstance(password, str):
        return 400, _error("bad_request", "username and password must be strings")
    if not isinstance(display, str):
        display = ""
    if server.data_root is None or server.config_dir is None:
        return 400, _error("bad_request", "data directory is not set")
    try:
        validate_owner_inputs(
            username=username,
            password=password,
            display_name=display or username,
        )
    except AccountError as exc:
        return 400, _error("bad_request", str(exc))
    if not _begin_owner_creation(server):
        return _await_peer_owner(server)
    try:
        return _create_owner_holding_gate(server, username, password, display, extras)
    finally:
        _end_owner_creation(server)


def _create_owner_holding_gate(
    server: Any,
    username: str,
    password: str,
    display: str,
    extras: list[tuple[str, str]],
) -> tuple[int, dict[str, object]]:
    from praxis_prime.onboarding.owner import clear_discarded_owner, create_owner_account
    from praxis_prime.profiles.migrate import MigrationBusy

    store = server.accounts
    if store.has_accounts():
        invalidate_first_run_token(server.config_dir)
        return 409, _error("conflict", "an owner account already exists")
    released = False
    try:
        if _holds_legacy_database(server):
            _release_owned_database(server)
            released = True
            server.restart_required = True
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
        _settle_database(server, released)
        if _wait_for_owner(store):
            return 409, _error("conflict", "an owner account already exists")
        return 503, _error(
            "unavailable",
            "prime.db is open, so this setup cannot move the existing data. "
            "Stop praxis-primed and run `praxis-prime setup`.",
        )
    except AccountError as exc:
        _settle_database(server, released)
        message = str(exc)
        if "already exists" in message and store.has_accounts():
            invalidate_first_run_token(server.config_dir)
            return 409, _error("conflict", message)
        return 400, _error("bad_request", message)
    except OSError as exc:
        _settle_database(server, released)
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
        _settle_database(server, released)
        return 503, _error("unavailable", "audit log is busy; the owner was not kept")
    invalidate_first_run_token(server.config_dir)
    if released:
        opened = _reopen_profile_database(server, actor=account.id)
        server.restart_required = not opened
    issued = store.open_session(account)
    extras.append(("Set-Cookie", session_cookie(issued.token, max_age=issued.max_age)))
    return 201, {
        "ok": True,
        "account": account.public(),
        "csrfToken": issued.csrf_token,
        "restartRequired": _process_needs_restart(server),
    }


def _wait_for_owner(store: Any) -> bool:
    """True when a peer finishes creating the owner while this call waits."""
    deadline = time.monotonic() + _OWNER_WAIT_SECONDS
    while time.monotonic() < deadline:
        if store.has_accounts():
            return True
        time.sleep(_OWNER_WAIT_STEP)
    return bool(store.has_accounts())


class _OwnerGate:
    """One in-process owner creation. Waiters must not delete the token."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.active = False
        self._done = threading.Condition(self._lock)


_GATE_INIT = threading.Lock()


def _owner_gate(server: Any) -> _OwnerGate:
    gate = getattr(server, "owner_gate", None)
    if isinstance(gate, _OwnerGate):
        return gate
    with _GATE_INIT:
        gate = getattr(server, "owner_gate", None)
        if not isinstance(gate, _OwnerGate):
            gate = _OwnerGate()
            server.owner_gate = gate
        return gate


def _creation_active(server: Any) -> bool:
    gate = getattr(server, "owner_gate", None)
    if not isinstance(gate, _OwnerGate):
        return False
    with gate._lock:
        return gate.active


def _begin_owner_creation(server: Any) -> bool:
    gate = _owner_gate(server)
    with gate._lock:
        if gate.active:
            return False
        gate.active = True
        return True


def _end_owner_creation(server: Any) -> None:
    gate = getattr(server, "owner_gate", None)
    if not isinstance(gate, _OwnerGate):
        return
    with gate._lock:
        gate.active = False
        gate._done.notify_all()


def _wait_until_idle(server: Any) -> bool:
    """True when no owner creation is in progress. False when the wait expires."""
    gate = _owner_gate(server)
    deadline = time.monotonic() + _OWNER_WAIT_SECONDS
    with gate._lock:
        while gate.active:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            gate._done.wait(remaining)
        return True


def _await_peer_owner(server: Any) -> tuple[int, dict[str, object]]:
    """Wait out an in-flight create. Do not burn the token if that create is discarded."""
    if not _wait_until_idle(server):
        return 503, _error("unavailable", "owner setup is still running; try again")
    if server.accounts.has_accounts():
        if server.config_dir is not None:
            invalidate_first_run_token(server.config_dir)
        return 409, _error("conflict", "an owner account already exists")
    return 503, _error("unavailable", "owner setup did not finish; try again")


def _holds_legacy_database(server: Any) -> bool:
    """True when this process has the single-user ``data/prime.db`` open.

    The multi-profile supervisor audit is a different file. Closing it
    would drop the worker supervisor's log, and that process does not
    hold the profile database the migration moves.
    """
    if getattr(server, "multi_profile", False) or server.data_root is None:
        return False
    runtime = getattr(getattr(server, "agent", None), "runtime", None)
    db = getattr(runtime, "db", None) if runtime is not None else None
    path = _database_path(db)
    if path is None:
        return False
    try:
        legacy = (Path(server.data_root) / "prime.db").resolve()
    except OSError:
        legacy = Path(server.data_root) / "prime.db"
    return path == legacy


def _database_path(db: Any) -> Path | None:
    raw = getattr(db, "path", None)
    if raw is None:
        raw = getattr(db, "db_path", None)
    if raw is None:
        return None
    try:
        return Path(raw).resolve()
    except OSError:
        return Path(raw)


def _settle_database(server: Any, released: bool) -> None:
    """Reopen after a failed create. A failed reopen asks for a restart."""
    if not released:
        return
    server.restart_required = not _restore_running_database(server)


def _reopen_profile_database(server: Any, *, actor: str = "") -> bool:
    if server.data_root is None:
        return False
    from praxis_prime.profiles.home import ProfileHome

    path = ProfileHome(server.data_root, "default").db_path
    try:
        return _install_runtime_database(server, path, "default", actor=actor)
    except (OSError, sqlite3.Error, RuntimeError, ValueError):
        return False


def _restore_running_database(server: Any) -> bool:
    """Open the profile database if the move finished, otherwise the legacy file."""
    runtime = getattr(getattr(server, "agent", None), "runtime", None)
    if runtime is None or server.data_root is None:
        return False
    from praxis_prime.profiles.home import ProfileHome

    root = Path(server.data_root)
    candidates = (
        (ProfileHome(root, "default").db_path, "default"),
        (root / "prime.db", ""),
    )
    for path, profile in candidates:
        if not path.is_file():
            continue
        try:
            if _install_runtime_database(server, path, profile):
                return True
        except (OSError, sqlite3.Error, RuntimeError, ValueError):
            continue
    return False


def _install_runtime_database(server: Any, path: Path, profile: str, *, actor: str = "") -> bool:
    """Point the running daemon at ``path``. False when this process has no runtime."""
    runtime = getattr(getattr(server, "agent", None), "runtime", None)
    if runtime is None:
        return False
    from praxis_prime.audit.log import AuditLog
    from praxis_prime.scheduler.store import RoutineStore
    from praxis_prime.state import StateDB

    db = StateDB(path)
    try:
        log = AuditLog(db)
    except (OSError, sqlite3.Error, RuntimeError, ValueError):
        db.close()
        raise
    log.bind(actor_account=actor, profile=profile)
    runtime.db = db
    runtime.audit = log
    runtime.profile_id = profile
    for name in ("store", "memory"):
        holder = getattr(runtime, name, None)
        if holder is not None and hasattr(holder, "db"):
            holder.db = db
    for holder in (
        getattr(runtime, "policy", None),
        getattr(runtime, "engine", None),
        getattr(runtime, "mcp", None),
        getattr(server, "decider", None),
    ):
        if holder is not None and hasattr(holder, "audit"):
            holder.audit = log
    server.audit = log
    scheduler = getattr(server, "scheduler", None)
    if scheduler is not None:
        scheduler.store = RoutineStore(db)
        scheduler.audit = log
        memory = getattr(runtime, "memory", None)
        if memory is not None:
            scheduler.memory = memory
    queue_obj = getattr(getattr(server, "agent", None), "queue", None)
    if queue_obj is not None and hasattr(queue_obj, "profile_id"):
        queue_obj.profile_id = profile
    return True


def _process_needs_restart(server: Any) -> bool:
    """True while this process is still single-user or its database is closed.

    A stub gateway with no runtime stays true. A daemon rebound to
    ``profiles/default`` with an open connection is false.
    """
    if getattr(server, "restart_required", False):
        return True
    if getattr(server, "multi_profile", False):
        return False
    runtime = getattr(getattr(server, "agent", None), "runtime", None)
    if runtime is None:
        return True
    profile = str(getattr(runtime, "profile_id", "") or "")
    db = getattr(runtime, "db", None)
    conn = getattr(db, "conn", None) if db is not None else None
    if not profile or conn is None:
        return True
    return False


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


def _finish_save(server: Any, result: dict[str, object]) -> dict[str, object]:
    """Reload the serving router after a save. Ask for a restart when that fails."""
    if result.get("ok") is not True:
        return result
    body = dict(result)
    body["restartRequired"] = not _refresh_serving_router(server)
    return body


def _refresh_serving_router(server: Any) -> bool:
    """True when the process that serves chat is using the saved provider."""
    runtime = getattr(getattr(server, "agent", None), "runtime", None)
    if runtime is not None and getattr(runtime, "router", None) is not None:
        return _reload_in_process(server, runtime)
    if not getattr(server, "multi_profile", False):
        return True
    return _reload_running_workers(server)


def _reload_in_process(server: Any, runtime: Any) -> bool:
    if server.config_dir is None:
        return False
    from praxis_prime.runtime import reload_serving_router

    env = getattr(server, "onboarding_env", None)
    if env is None:
        env = os.environ
    lock = getattr(getattr(server, "agent", None), "_lock", None)
    try:
        reload_serving_router(
            runtime,
            env=env,
            config_path=Path(server.config_dir) / "config.toml",
            lock=lock,
        )
    except (OSError, ValueError, RuntimeError, sqlite3.Error):
        return False
    return True


def _reload_running_workers(server: Any) -> bool:
    """Reload workers that are already up. An idle profile loads the file when it starts."""
    supervisor = getattr(server, "supervisor", None)
    if supervisor is None or not hasattr(supervisor, "running"):
        agent = getattr(server, "agent", None)
        supervisor = getattr(agent, "supervisor", None)
    if supervisor is None or not hasattr(supervisor, "running") or not hasattr(supervisor, "call"):
        return False
    try:
        names = list(supervisor.running())
    except (OSError, RuntimeError, ValueError):
        return False
    from praxis_prime.supervisor.ipc import IpcError
    from praxis_prime.supervisor.supervisor import WorkerUnavailable

    for name in names:
        try:
            supervisor.call(name, "runtime.reload", {}, timeout=10)
        except (WorkerUnavailable, IpcError, OSError, RuntimeError, ValueError):
            return False
    return True


_STEP_UP_MESSAGE = (
    "changing the provider, its endpoint, or its key needs a step-up, "
    "or `praxis-prime setup --replace`"
)


def _prepare_save(
    server: Any,
    principal: Any,
    payload: dict[str, object],
) -> tuple[OnboardingService, Selection]:
    """Shared HTTP and WebSocket save guard. The CLI calls ``save`` directly.

    ``replace`` is checked before the step-up token is spent, so a rejected
    replacement leaves the token in place.
    """
    actor = "" if principal is None else str(getattr(principal, "account_id", "") or "")
    service = _service(server, actor)
    selection = _selection(payload, actor)
    if service.requires_replace(selection) and not selection.replace:
        raise OnboardingError(
            "a provider is already configured; pass --replace to change it",
            code="replace",
        )
    if service.needs_step_up(selection):
        _spend_step_up(server, principal, payload)
    return service, selection


def _spend_step_up(server: Any, principal: Any, payload: dict[str, object]) -> None:
    session_id = str(getattr(principal, "session_id", "") or "")
    token = str(payload.get("stepUpToken", "") or "")
    account_id = str(getattr(principal, "account_id", "") or "")
    factors = Factors(server.accounts)
    spent = factors.step_up_valid(account_id, token, session_id) if account_id else False
    if not session_id or not spent:
        raise OnboardingError(_STEP_UP_MESSAGE, code="replace")


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
        actor=actor,
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
