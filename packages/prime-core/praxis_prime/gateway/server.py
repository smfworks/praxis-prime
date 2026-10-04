"""Loopback HTTP and WebSocket gateway.

Every client speaks the same JSON frames. HTTP exposes health (open), plus
status and approvals behind the bearer token. The socket is bound to
127.0.0.1 only, and peers that are not loopback are dropped.
"""

from __future__ import annotations

import json
import os
import queue
import re
import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs

from praxis_prime.accounts.db import AccountStore, cookie_value
from praxis_prime.accounts.oidc import CLIENT_COOKIE, client_binding
from praxis_prime.accounts.roles import sees_all_profiles
from praxis_prime.approvals.queue import ApprovalQueue, parse_decision
from praxis_prime.audit.log import AuditLog, actor_account_var, profile_var
from praxis_prime.decide.engine import DecisionEngine
from praxis_prime.decide.schema import DecideError
from praxis_prime.gateway.agui import TurnStream
from praxis_prime.gateway.auth import bearer_token, token_ok
from praxis_prime.gateway.authz import (
    Denial,
    Principal,
    accounts_enforced,
    authenticate_http,
    authorize_action,
    claim_protocol_role,
    issue_ws_ticket,
    login,
    logout,
    principal_from_ticket,
)
from praxis_prime.gateway.factors import authed_factor, passkey_options, passkey_verify, totp_login
from praxis_prime.gateway.guard import (
    body_size_denial,
    fetch_site_denial,
    host_origin_denial,
    mutation_type_denial,
)
from praxis_prime.gateway.oidc import oidc_public, oidc_session
from praxis_prime.gateway.onboarding import (
    SetupFailures,
    close_owned_gateway_audit,
    handle_onboarding,
    onboarding_payload,
)
from praxis_prime.gateway.protocol import (
    CHAT_ROLES,
    OPERATOR_ONLY,
    PROTOCOL_VERSION,
    request_id_var,
)
from praxis_prime.gateway.routes import (
    frame_allowed,
    frame_session_ids_agree,
    ids_agree,
    route_allowed,
)
from praxis_prime.gateway.themes import (
    MAX_THEME_BODY,
    active_response,
    handle_themes,
    load_theme_asset,
    theme_asset_headers,
    theme_asset_route,
    theme_upload,
    theme_zip_denial,
)
from praxis_prime.gateway.web import CSP, load_asset, static_route
from praxis_prime.gateway.ws import (
    ByteBuffer,
    WebSocketConnection,
    WebSocketError,
    server_upgrade_response,
)
from praxis_prime.host import Host, TurnResult
from praxis_prime.observe import JsonLogger
from praxis_prime.onboarding.service import OnboardingError
from praxis_prime.statfile import StatKind, lstat_kind

_APPROVAL_PATH = re.compile(r"^/v1/approvals/(ap_[0-9a-f]{8})$")
_ROUTINE_FIRE = re.compile(r"^/v1/routines/(rt_[0-9a-f]{8})/fire$")
_PROFILE_PATH = re.compile(r"^/v1/profiles/([a-z][a-z0-9-]{0,63})$")
RoutineFire = Callable[[str], tuple[int, dict[str, object]]]


class GatewayServer:
    """Accept loop for TCP and, when the path fits, the runtime Unix socket."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        token: str,
        agent: Host,
        approvals: ApprovalQueue,
        logger: JsonLogger | None = None,
        socket_path: str | None = None,
        decider: DecisionEngine | None = None,
        routine_fire: RoutineFire | None = None,
        accounts: AccountStore | None = None,
        audit: AuditLog | None = None,
        data_root: Path | None = None,
        bearer_enabled: bool = True,
        multi_profile: bool = False,
        config_dir: Path | None = None,
    ) -> None:
        self.host = host
        self._port = port
        self.token = token
        self.agent = agent
        self.approvals = approvals
        self.decider = decider
        self.routine_fire = routine_fire
        self.accounts = accounts
        self.audit = audit
        self.data_root = data_root
        self.bearer_enabled = bearer_enabled
        self.multi_profile = multi_profile
        self.config_dir = config_dir
        self.restart_required = False
        self.setup_in_progress = False
        self._owns_gateway_audit = False
        self.scheduler = None
        self.setup_failures = SetupFailures()
        self.logger = logger
        self.socket_path = socket_path
        self._stopped = threading.Event()
        self._listen: socket.socket | None = None
        self._unix: socket.socket | None = None
        self._threads: list[threading.Thread] = []
        self._conns: set[socket.socket] = set()
        self._conn_lock = threading.Lock()
        self._subs: list[_Subscriber] = []
        self._sub_lock = threading.Lock()
        self._idem: dict[tuple[str, str], dict[str, object]] = {}
        self._inflight: set[tuple[str, str]] = set()
        self._idem_lock = threading.Lock()
        self.bound_port = port

    def start(self) -> None:
        if self.host != "127.0.0.1":
            raise OSError("gateway refused to bind a non-loopback address")
        listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen.bind((self.host, self._port))
        listen.listen(16)
        listen.settimeout(0.5)
        self._listen = listen
        self.bound_port = listen.getsockname()[1]
        thread = threading.Thread(
            target=self._accept_loop,
            args=(listen, False),
            name="praxis-gateway",
            daemon=True,
        )
        thread.start()
        self._threads.append(thread)
        self._start_unix()

    def shutdown(self) -> None:
        self._stopped.set()
        for listen in (self._listen, self._unix):
            if listen is not None:
                try:
                    listen.close()
                except OSError:
                    pass
        with self._conn_lock:
            connections = list(self._conns)
        for conn in connections:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass
        for thread in self._threads:
            thread.join(timeout=2)
        if self.socket_path:
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass
        close_owned_gateway_audit(self)

    def _pause_message(self) -> str | None:
        """Why ordinary requests are paused, or None when the gateway is open.

        A restart blocks health. Setup-in-progress does not: ``/health`` stays ok.
        """
        if self.restart_required:
            return _RESTART_MESSAGE
        if self.setup_in_progress:
            return _SETUP_MESSAGE
        return None

    def publish(self, frame: dict[str, object]) -> None:
        """Fan out one event. Each socket is filtered by the principal it connected as.

        Unauthenticated sockets are not in this list. A disabled or revoked
        account is removed so a later event cannot reach it.
        """
        with self._sub_lock:
            subscribers = list(self._subs)
        drop: list[_Subscriber] = []
        for subscriber in subscribers:
            refreshed = self._recheck(subscriber.principal)
            if isinstance(refreshed, Denial):
                drop.append(subscriber)
                continue
            subscriber.principal = refreshed
            filtered = self._filter_broadcast(frame, refreshed)
            if filtered is not None:
                subscriber.outgoing.put(filtered)
        if not drop:
            return
        with self._sub_lock:
            for subscriber in drop:
                if subscriber in self._subs:
                    self._subs.remove(subscriber)
        for subscriber in drop:
            subscriber.outgoing.put(None)
            try:
                subscriber.conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _start_unix(self) -> None:
        if not self.socket_path:
            return
        if len(self.socket_path.encode()) > 100:
            if self.logger is not None:
                self.logger.warning("unix_socket_skipped", reason="path too long")
            self.socket_path = None
            return
        try:
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)
            unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            unix.bind(self.socket_path)
            os.chmod(self.socket_path, 0o600)
            unix.listen(16)
            unix.settimeout(0.5)
        except OSError as exc:
            if self.logger is not None:
                self.logger.warning("unix_socket_skipped", error=type(exc).__name__)
            self.socket_path = None
            return
        self._unix = unix
        thread = threading.Thread(
            target=self._accept_loop,
            args=(unix, True),
            name="praxis-gateway-unix",
            daemon=True,
        )
        thread.start()
        self._threads.append(thread)

    def _accept_loop(self, listen: socket.socket, unix: bool) -> None:
        while not self._stopped.is_set():
            try:
                conn, addr = listen.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stopped.is_set():
                    return
                continue
            if not unix and not _peer_is_loopback(addr):
                conn.close()
                if self.logger is not None:
                    self.logger.warning("rejected_peer")
                continue
            conn.settimeout(None)
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with self._conn_lock:
            self._conns.add(conn)
        try:
            buffer = ByteBuffer(conn)
            raw = buffer.read_until(b"\r\n\r\n", limit=16384)
            method, path, headers = _parse_head(raw)
            route_only = path.split("?", 1)[0]
            denied = host_origin_denial(headers, bound_port=self.bound_port)
            if denied is not None:
                status, code, message = denied
                _reject_theme_upload(
                    conn, buffer, method, route_only, headers, status, code, message
                )
                if self.logger is not None:
                    self.logger.warning("host_rejected", code=code)
                return
            # The provider redirect is a cross-site top-level GET. State,
            # PKCE, the nonce, and the pp_oidc cookie are the checks. Every
            # other route still refuses Sec-Fetch-Site: cross-site.
            if not (method == "GET" and route_only == "/v1/auth/oidc/callback"):
                site = fetch_site_denial(headers)
                if site is not None:
                    status, code, message = site
                    _reject_theme_upload(
                        conn, buffer, method, route_only, headers, status, code, message
                    )
                    return
            if static_route(method, route_only):
                self._static(conn, route_only)
                return
            if theme_asset_route(method, route_only):
                self._theme_asset(conn, route_only)
                return
            if theme_upload(method, route_only, headers):
                denial = theme_zip_denial(headers)
                if denial is not None:
                    status, code, message = denial
                    _write_http(conn, status, _error(code, message))
                    return
                length = int(headers.get("content-length", "0") or "0")
                body = buffer.read_exact(length) if length else b""
                extras = []
                status, payload = self._http(
                    method, path, headers, body, extras, _peer_host(conn)
                )
                _write_http(conn, status, payload, extras)
                return
            if headers.get("upgrade", "").lower() == "websocket":
                self._handle_ws(conn, buffer, headers, path)
                return
            sized = body_size_denial(headers)
            if sized is not None:
                status, code, message = sized
                _write_http(conn, status, _error(code, message))
                return
            typed = mutation_type_denial(method, headers)
            if typed is not None:
                status, code, message = typed
                _write_http(conn, status, _error(code, message))
                return
            length = _content_length(headers)
            body = buffer.read_exact(length) if length else b""
            extras: list[tuple[str, str]] = []
            status, payload = self._http(method, path, headers, body, extras, _peer_host(conn))
            _write_http(conn, status, payload, extras)
        except (ConnectionError, OSError, ValueError, WebSocketError):
            if self.logger is not None:
                self.logger.warning("connection_closed")
        finally:
            with self._conn_lock:
                self._conns.discard(conn)
            try:
                conn.close()
            except OSError:
                pass

    def _http(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        extras: list[tuple[str, str]],
        peer: str = "",
    ) -> tuple[int, dict[str, object]]:
        route, _, query = path.partition("?")
        if method == "GET" and route == "/health" and not self.restart_required:
            return 200, {"ok": True, "service": "praxis-primed"}
        paused = self._pause_message()
        if paused is not None:
            if paused == _SETUP_MESSAGE:
                extras.append(("Retry-After", "1"))
            return 503, _error("unavailable", paused)
        if not route_allowed(method, route):
            return 404, _error("not_allowed", "route is not on the allowlist")
        if method == "GET" and route == "/v1/themes/active":
            return active_response(
                accounts=self.accounts,
                headers=headers,
                query=query,
                data_root=self.data_root,
                token=self.token,
                bearer_enabled=self.bearer_enabled,
                profile_exists=self._profile_exists,
                runtime_profile=self._runtime_profile(),
                multi_profile=self.multi_profile,
            )
        if method == "POST" and route == "/v1/auth/login":
            if self.accounts is None:
                return 503, _error("unavailable", "accounts are not configured")
            status, payload, cookies = login(self.accounts, body, self.audit, peer=peer)
            extras.extend(cookies)
            if status != 200 and self.logger is not None:
                self.logger.warning("auth_fail")
            return status, payload
        public_oidc = oidc_public(
            self.accounts,
            method,
            route,
            headers,
            query,
            body,
            self.audit,
            self.logger,
            port=self.bound_port,
            peer=peer,
        )
        if public_oidc is not None:
            status, payload, cookies = public_oidc
            extras.extend(cookies)
            if status in {401, 403} and self.logger is not None:
                self.logger.warning("auth_fail")
            return status, payload
        public_factor = self._public_factor(method, route, headers, body, extras, peer)
        if public_factor is not None:
            return public_factor
        onboarding = handle_onboarding(
            self, method, route, headers, body, extras, peer, query
        )
        if onboarding is not None:
            return onboarding
        principal = authenticate_http(
            self.accounts,
            headers,
            method,
            bootstrap_token=self.token,
            bearer_enabled=self.bearer_enabled,
        )
        if isinstance(principal, Denial):
            if principal.status == 401 and self.logger is not None:
                self.logger.warning("http_unauthorized", path=route)
            # The SPA asks for the session before it shows the login form.
            if (
                principal.status == 401
                and method == "GET"
                and route == "/v1/auth/session"
                and self.accounts is not None
            ):
                extras.extend(_client_cookie(self.accounts, headers))
            return principal.status, _error(principal.code, principal.message)
        explicit_profile = headers.get("x-praxis-profile", "").strip()
        profile_name = explicit_profile
        named = _PROFILE_PATH.fullmatch(route)
        if named is not None:
            profile_name = named.group(1)
        if self.multi_profile and not profile_name:
            profile_name = self._implicit_profile()
        action = _http_action(method, route)
        # An omitted approvals list is not the implicit profile. Owner and
        # admin see every card; a member is filtered after this check.
        auth_profile = explicit_profile if action == "approval_list" else profile_name
        denial = authorize_action(
            self.accounts,
            principal,
            action=action,
            profile=auth_profile,
            profile_exists=self._profile_exists,
            runtime_profile=self._runtime_profile(),
            multi_profile=self.multi_profile,
        )
        if not denial.ok:
            return denial.status, _error(denial.code, denial.message)
        if query and not ids_agree(query=query, keys=("id", "approvalId", "profile", "sessionId")):
            return 400, _error("bad_request", "id does not match")
        actor_token = actor_account_var.set(principal.account_id)
        # A single-process daemon stamps its runtime profile. The header is a
        # routing hint for the supervisor and must not rewrite the audit row.
        stamped = profile_name if self.multi_profile else ""
        profile_token = profile_var.set(stamped or self._runtime_profile())
        try:
            return self._authed_http(
                method, route, headers, body, extras, principal, profile_name, query, peer
            )
        finally:
            actor_account_var.reset(actor_token)
            profile_var.reset(profile_token)

    def _authed_http(
        self,
        method: str,
        route: str,
        headers: dict[str, str],
        body: bytes,
        extras: list[tuple[str, str]],
        principal: Principal,
        profile_name: str,
        query: str = "",
        peer: str = "",
    ) -> tuple[int, dict[str, object]]:
        if self.accounts is not None:
            oidc_handled = oidc_session(
                self.accounts,
                principal,
                method,
                route,
                headers,
                body,
                self.audit,
                self.logger,
                port=self.bound_port,
                peer=peer,
            )
            if oidc_handled is not None:
                status, payload, cookies = oidc_handled
                extras.extend(cookies)
                return status, payload
            handled = authed_factor(
                self.accounts,
                principal,
                method,
                route,
                body,
                self.audit,
                origin=headers.get("origin", ""),
                port=self.bound_port,
            )
            if handled is not None:
                status, payload, cookies = handled
                extras.extend(cookies)
                return status, payload
        if method == "POST" and route == "/v1/auth/logout":
            if self.accounts is None:
                return 404, _error("not_found", "no such route")
            status, payload, cookies = logout(self.accounts, principal, self.audit)
            extras.extend(cookies)
            return status, payload
        if method == "GET" and route == "/v1/auth/session":
            body_out: dict[str, object] = {"ok": True, "account": _principal_public(principal)}
            if principal.kind == "session" and self.accounts is not None:
                session = self.accounts.session_from_token(principal.session_token)
                if session is not None:
                    body_out["csrfToken"] = session.csrf_token
            if self.accounts is not None:
                extras.extend(_client_cookie(self.accounts, headers))
            return 200, body_out
        themed = handle_themes(
            method=method,
            route=route,
            headers=headers,
            body=body,
            query=query,
            principal=principal,
            profile=profile_name,
            data_root=self.data_root,
            audit=self.audit,
            accounts=self.accounts,
        )
        if themed is not None:
            return themed
        if method == "GET" and route == "/v1/memory":
            return self._profile_catalog("list_memory", "entries", profile_name)
        if method == "GET" and route == "/v1/skills":
            return self._profile_catalog("list_skills", "skills", profile_name)
        if method == "GET" and route == "/v1/routines":
            return self._profile_catalog("list_routines", "routines", profile_name)
        if method == "GET" and route == "/v1/admin/directory":
            return self._admin_directory()
        if method == "POST" and route == "/v1/auth/ws-ticket":
            if self.accounts is None:
                return 404, _error("not_found", "no such route")
            status, payload = issue_ws_ticket(self.accounts, principal, profile_name)
            return status, payload
        if method == "GET" and route == "/v1/profiles":
            return 200, self._list_profiles(principal)
        named = _PROFILE_PATH.fullmatch(route)
        if method == "GET" and named is not None:
            role = ""
            if self.accounts is not None and principal.account_id:
                role = self.accounts.membership(principal.account_id, named.group(1)) or ""
            return 200, {"ok": True, "profile": {"id": named.group(1), "role": role}}
        if method == "GET" and route == "/status":
            return 200, {"ok": True, "status": self._status()}
        if method == "GET" and route == "/v1/approvals/meta":
            # The header the client sent. An omitted header is not the
            # implicit profile, or an owner would lose every other card.
            explicit = headers.get("x-praxis-profile", "").strip()
            foreign = self._foreign_runtime(explicit)
            if foreign is not None:
                return foreign.status, _error(foreign.code, foreign.message)
            rows = self._visible_meta(principal, profile=explicit)
            return 200, {"ok": True, "count": len(rows), "approvals": rows}
        if method == "GET" and route == "/v1/approvals":
            explicit = headers.get("x-praxis-profile", "").strip()
            foreign = self._foreign_runtime(explicit)
            if foreign is not None:
                return foreign.status, _error(foreign.code, foreign.message)
            return 200, {
                "ok": True,
                "approvals": self._visible_approvals(principal, profile=explicit),
            }
        match = _APPROVAL_PATH.fullmatch(route)
        if method == "POST" and match is not None:
            try:
                parsed = json.loads(body.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                return 400, _error("bad_request", "approval body must be JSON")
            if not isinstance(parsed, dict):
                return 400, _error("bad_request", "approval body must be an object")
            if not ids_agree(
                path_id=match.group(1),
                body=parsed,
                query=query,
                keys=("id", "approvalId"),
            ):
                return 400, _error("bad_request", "approval id does not match")
            existing = self.approvals.get(match.group(1))
            item_profile = _profile_of(existing)
            target = item_profile or profile_name
            if target:
                scoped = authorize_action(
                    self.accounts,
                    principal,
                    action="approve",
                    profile=target,
                    profile_exists=self._profile_exists,
                    runtime_profile=self._runtime_profile(),
                    multi_profile=self.multi_profile,
                )
                if not scoped.ok:
                    return scoped.status, _error(scoped.code, scoped.message)
            try:
                decision = parse_decision(parsed.get("decision"))
                actor = principal.account_id or "operator"
                item = self.approvals.decide(match.group(1), decision, actor=actor)
            except LookupError as exc:
                return 404, _error("not_found", str(exc))
            except ValueError as exc:
                return 400, _error("bad_request", str(exc))
            return 200, {
                "ok": True,
                "approval": self._hide_foreign_session(principal, item),
            }
        if method == "POST" and route in {"/v1/decide", "/v1/systemone"}:
            return self._http_decide(body)
        fired = _ROUTINE_FIRE.fullmatch(route)
        if method == "POST" and fired is not None:
            return self._http_routine(fired.group(1))
        return 404, _error("not_found", "no such route")

    def _public_factor(
        self,
        method: str,
        route: str,
        headers: dict[str, str],
        body: bytes,
        extras: list[tuple[str, str]],
        peer: str,
    ) -> tuple[int, dict[str, object]] | None:
        if method != "POST" or route not in {
            "/v1/auth/login/totp",
            "/v1/auth/passkey/options",
            "/v1/auth/passkey/verify",
        }:
            return None
        if self.accounts is None:
            return 503, _error("unavailable", "accounts are not configured")
        origin = headers.get("origin", "")
        if route == "/v1/auth/login/totp":
            status, payload, cookies = totp_login(
                self.accounts,
                body,
                self.audit,
                peer=peer,
                cookie_header=headers.get("cookie", ""),
            )
        elif route == "/v1/auth/passkey/options":
            status, payload, cookies = passkey_options(
                self.accounts,
                body,
                origin=origin,
                port=self.bound_port,
            )
        else:
            status, payload, cookies = passkey_verify(self.accounts, body, self.audit, peer=peer)
        extras.extend(cookies)
        if status == 401 and self.logger is not None:
            self.logger.warning("auth_fail")
        return status, payload

    def _static(self, conn: socket.socket, route: str) -> None:
        loaded = load_asset(route)
        if loaded is None:
            _write_http(conn, 404, _error("not_found", "web app is not installed"))
            return
        status, body, content_type = loaded
        if status != 200:
            _write_http(conn, 404, _error("not_found", "web app is not installed"))
            return
        cache = "no-store" if route in {"/", "/index.html"} else "public, max-age=3600"
        _write_bytes(
            conn,
            200,
            body,
            content_type,
            [
                ("Content-Security-Policy", CSP),
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "no-referrer"),
                ("Cache-Control", cache),
            ],
        )

    def _theme_asset(self, conn: socket.socket, route: str) -> None:
        loaded = load_theme_asset(self.data_root, route)
        if loaded is None:
            _write_http(conn, 404, _error("not_found", "theme asset is not available"))
            return
        body, content_type = loaded
        _write_bytes(conn, 200, body, content_type, theme_asset_headers())

    def _profile_catalog(
        self,
        method: str,
        key: str,
        profile: str,
    ) -> tuple[int, dict[str, object]]:
        if self.multi_profile and not profile:
            return 403, _error("forbidden", "a profile is required")
        fn = getattr(self.agent, method, None)
        if not callable(fn):
            return 404, _error("not_found", "no such route")
        from praxis_prime.supervisor.ipc import IpcError
        from praxis_prime.supervisor.supervisor import WorkerUnavailable

        try:
            rows = fn(profile)
        except PermissionError as exc:
            return 403, _error("forbidden", str(exc) or "this daemon runs a different profile")
        except (WorkerUnavailable, IpcError, OSError):
            return 503, _error("unavailable", "profile worker is unavailable")
        if not isinstance(rows, list):
            rows = []
        return 200, {"ok": True, "profile": profile, key: rows}

    def _admin_directory(self) -> tuple[int, dict[str, object]]:
        if self.accounts is None:
            return 404, _error("not_found", "accounts are not configured")
        accounts = [
            {
                "id": account.id,
                "username": account.username,
                "displayName": account.display_name,
                "role": account.role,
                "status": account.status,
            }
            for account in self.accounts.list_accounts()
        ]
        return 200, {
            "ok": True,
            "accounts": accounts,
            "memberships": self.accounts.list_memberships(),
        }

    def _http_routine(self, routine_id: str) -> tuple[int, dict[str, object]]:
        if self.routine_fire is None:
            return 404, _error("not_found", "routines are not running")
        try:
            status, payload = self.routine_fire(routine_id)
        except Exception:
            if self.logger is not None:
                self.logger.warning("routine_fire_failed")
            return 500, _error("error", "routine failed")
        return status, payload

    def _http_decide(self, body: bytes) -> tuple[int, dict[str, object]]:
        if self.decider is None:
            return 503, _error("unavailable", "decision engine is not configured")
        try:
            parsed = json.loads(body.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            return 400, _error("bad_request", "decide body must be JSON")
        if not isinstance(parsed, dict):
            return 400, _error("bad_request", "decide body must be an object")
        try:
            result = self.decider.decide(parsed)
        except DecideError as exc:
            return 400, _error("bad_request", str(exc))
        except Exception:
            if self.logger is not None:
                self.logger.warning("decide_failed")
            return 500, _error("error", "decision engine failed")
        return 200, result.to_wire()

    def _handle_ws(
        self,
        conn: socket.socket,
        buffer: ByteBuffer,
        headers: dict[str, str],
        path: str,
    ) -> None:
        key = headers.get("sec-websocket-key", "")
        if not key:
            _write_http(conn, 400, _error("bad_request", "missing websocket key"))
            return
        header_token = bearer_token(headers)
        ticket = _request_ticket(path, headers)
        if header_token and not token_ok(header_token, self.token) and not ticket:
            if self.logger is not None:
                self.logger.warning("ws_unauthorized")
            _write_http(conn, 401, _error("unauthorized", "Bearer token required"))
            return
        conn.sendall(server_upgrade_response(key))
        ws = WebSocketConnection(conn, buffer, client=False)
        outgoing: queue.Queue[dict[str, object] | None] = queue.Queue()
        writer = threading.Thread(target=_write_frames, args=(ws, outgoing), daemon=True)
        writer.start()
        role: str | None = None
        subscriber: _Subscriber | None = None
        try:
            first = _read_json(ws)
            connected = self._connect(first, header_token, outgoing, path, headers)
            if connected is None:
                return
            role, principal = connected
            subscriber = _Subscriber(outgoing, principal, conn)
            with self._sub_lock:
                self._subs.append(subscriber)
            while not self._stopped.is_set():
                frame = _read_json(ws)
                if frame is None:
                    return
                frame_id = str(frame.get("id", ""))
                refreshed = self._recheck(principal)
                if isinstance(refreshed, Denial):
                    outgoing.put(_frame_error(frame_id, refreshed.code, refreshed.message))
                    return
                principal = refreshed
                subscriber.principal = principal
                claimed = claim_protocol_role(principal, role)
                if isinstance(claimed, Denial):
                    outgoing.put(_frame_error(frame_id, claimed.code, claimed.message))
                    return
                role = claimed
                self._dispatch(frame, role, principal, outgoing)
        finally:
            with self._sub_lock:
                if subscriber is not None and subscriber in self._subs:
                    self._subs.remove(subscriber)
            outgoing.put(None)
            writer.join(timeout=1)

    def _connect(
        self,
        frame: dict[str, object] | None,
        header_token: str,
        outgoing: queue.Queue[dict[str, object] | None],
        path: str,
        headers: dict[str, str],
    ) -> tuple[str, Principal] | None:
        frame_id = "" if frame is None else str(frame.get("id", ""))
        paused = self._pause_message()
        if paused is not None:
            outgoing.put(_frame_error(frame_id, "unavailable", paused))
            return None
        if frame is None or frame.get("type") != "connect":
            frame_id = str((frame or {}).get("id", ""))
            outgoing.put(
                _frame_error(frame_id, "connect_required", "first frame must be connect")
            )
            return None
        payload = _payload(frame)
        frame_id = str(frame.get("id", ""))
        principal = self._ws_principal(payload, header_token, path, headers)
        if isinstance(principal, Denial):
            if self.logger is not None and principal.status == 401:
                self.logger.warning("ws_unauthorized")
            outgoing.put(_frame_error(frame_id, principal.code, principal.message))
            return None
        claimed = claim_protocol_role(principal, str(payload.get("role", "")))
        if isinstance(claimed, Denial):
            outgoing.put(_frame_error(frame_id, claimed.code, claimed.message))
            return None
        outgoing.put(
            {
                "type": "hello",
                "id": frame_id,
                "ok": True,
                "payload": {
                    "protocol": PROTOCOL_VERSION,
                    "version": self._status().get("version", ""),
                    "role": claimed,
                },
            }
        )
        return claimed, principal

    def _dispatch(
        self,
        frame: dict[str, object],
        role: str,
        principal: Principal,
        outgoing: queue.Queue[dict[str, object] | None],
    ) -> None:
        kind = str(frame.get("type", ""))
        frame_id = str(frame.get("id", ""))
        paused = self._pause_message()
        if paused is not None:
            outgoing.put(_frame_error(frame_id, "unavailable", paused))
            return
        if not frame_allowed(kind):
            outgoing.put(_frame_error(frame_id, "unknown_type", f"unknown frame {kind}"))
            return
        if not frame_session_ids_agree(frame):
            outgoing.put(_frame_error(frame_id, "bad_request", "session id does not match"))
            return
        explicit_profile = str(_payload(frame).get("profile", "") or "")
        profile_name = explicit_profile
        if self.multi_profile and not profile_name:
            profile_name = self._implicit_profile()
        frame_action = _frame_action(kind)
        auth_profile = explicit_profile if frame_action == "approval_list" else profile_name
        denial = authorize_action(
            self.accounts,
            principal,
            action=frame_action,
            profile=auth_profile,
            profile_exists=self._profile_exists,
            runtime_profile=self._runtime_profile(),
            multi_profile=self.multi_profile,
        )
        if not denial.ok:
            outgoing.put(_frame_error(frame_id, denial.code, denial.message))
            return
        if kind in OPERATOR_ONLY and role != "operator":
            outgoing.put(_frame_error(frame_id, "forbidden", f"{role} cannot {kind}"))
            return
        if kind == "chat.send" and role not in CHAT_ROLES:
            outgoing.put(_frame_error(frame_id, "forbidden", f"{role} cannot chat"))
            return
        idem = frame.get("idempotencyKey")
        key = idem if isinstance(idem, str) and idem else ""
        cached = self._cached(principal.account_id, key)
        if cached is not None:
            replay = dict(cached)
            replay["id"] = frame_id
            outgoing.put(replay)
            return
        if key and self._mark_inflight(principal.account_id, key):
            outgoing.put(_frame_error(frame_id, "in_progress", "duplicate request"))
            return
        try:
            if kind == "ping":
                outgoing.put({"type": "pong", "id": frame_id, "ok": True, "payload": {}})
            elif kind == "status":
                result = {"type": "result", "id": frame_id, "ok": True, "payload": self._status()}
                self._remember(principal.account_id, key, result)
                outgoing.put(result)
            elif kind == "approvals.list":
                foreign = self._foreign_runtime(explicit_profile)
                if foreign is not None:
                    outgoing.put(_frame_error(frame_id, foreign.code, foreign.message))
                    return
                result = {
                    "type": "result",
                    "id": frame_id,
                    "ok": True,
                    "payload": {
                        "approvals": self._visible_approvals(
                            principal, profile=explicit_profile
                        )
                    },
                }
                outgoing.put(result)
            elif kind == "approvals.decide":
                self._decide(frame, principal, outgoing)
            elif kind == "chat.send":
                self._chat(frame, principal, outgoing, key, profile_name)
            elif kind == "model.set":
                self._model(frame, outgoing, profile_name)
            elif kind.startswith("onboarding."):
                try:
                    payload = onboarding_payload(self, kind, _payload(frame), principal)
                except OnboardingError as exc:
                    outgoing.put(_frame_error(frame_id, exc.code, str(exc)))
                    return
                outgoing.put({"type": "result", "id": frame_id, "ok": True, "payload": payload})
            elif kind == "session.drop":
                session_id = frame.get("sessionId") or _payload(frame).get("sessionId")
                try:
                    self.agent.drop_session(
                        session_id if isinstance(session_id, str) else None,
                        account_id=principal.account_id,
                    )
                except PermissionError:
                    outgoing.put(
                        _frame_error(frame_id, "forbidden", "session belongs to another account")
                    )
                    return
                except LookupError:
                    outgoing.put(_frame_error(frame_id, "not_found", "no such session"))
                    return
                outgoing.put({"type": "result", "id": frame_id, "ok": True, "payload": {}})
            else:
                outgoing.put(_frame_error(frame_id, "unknown_type", f"unknown frame {kind}"))
        finally:
            if key and kind != "chat.send":
                self._clear_inflight(principal.account_id, key)

    def _decide(
        self,
        frame: dict[str, object],
        principal: Principal,
        outgoing: queue.Queue[dict[str, object] | None],
    ) -> None:
        frame_id = str(frame.get("id", ""))
        payload = _payload(frame)
        approval_id = str(payload.get("approvalId", ""))
        existing = self.approvals.get(approval_id)
        target = _profile_of(existing) or str(payload.get("profile", "") or "")
        if target:
            scoped = authorize_action(
                self.accounts,
                principal,
                action="approve",
                profile=target,
                profile_exists=self._profile_exists,
                runtime_profile=self._runtime_profile(),
                multi_profile=self.multi_profile,
            )
            if not scoped.ok:
                outgoing.put(_frame_error(frame_id, scoped.code, scoped.message))
                return
        try:
            decision = parse_decision(payload.get("decision"))
            actor = principal.account_id or "operator"
            item = self.approvals.decide(approval_id, decision, actor=actor)
        except LookupError as exc:
            outgoing.put(_frame_error(frame_id, "not_found", str(exc)))
            return
        except ValueError as exc:
            outgoing.put(_frame_error(frame_id, "bad_request", str(exc)))
            return
        visible = self._hide_foreign_session(principal, item)
        outgoing.put(
            {"type": "result", "id": frame_id, "ok": True, "payload": {"approval": visible}}
        )

    def _chat(
        self,
        frame: dict[str, object],
        principal: Principal,
        outgoing: queue.Queue[dict[str, object] | None],
        idem: str,
        profile_name: str = "",
    ) -> None:
        frame_id = str(frame.get("id", ""))
        payload = _payload(frame)
        text = payload.get("text")
        if not isinstance(text, str) or not text.strip():
            self._clear_inflight(principal.account_id, idem)
            outgoing.put(_frame_error(frame_id, "bad_request", "chat text is empty"))
            return
        session = frame.get("sessionId") or payload.get("sessionId")
        session_id = session if isinstance(session, str) and session else None
        account_id = principal.account_id
        routed = profile_name if self.multi_profile else ""
        runtime_profile = routed or self._runtime_profile()
        stream = TurnStream(thread_id=session_id or frame_id, run_id=frame_id)
        for agui in stream.start():
            outgoing.put(_agui_frame(frame_id, agui))

        def work() -> None:
            token = request_id_var.set(frame_id)
            actor_token = actor_account_var.set(account_id)
            profile_token = profile_var.set(runtime_profile)

            def on_event(event: dict[str, object]) -> None:
                outgoing.put({"type": "event", "id": frame_id, "payload": event})
                for agui in stream.feed(event):
                    outgoing.put(_agui_frame(frame_id, agui))

            try:
                result = self.agent.chat(
                    text,
                    session_id=session_id,
                    on_event=on_event,
                    owner_account=account_id,
                    owner_profile=runtime_profile,
                )
                for agui in stream.finish(error=result.error):
                    outgoing.put(_agui_frame(frame_id, agui))
                body = _turn_payload(result)
                done: dict[str, object] = {
                    "type": "result",
                    "id": frame_id,
                    "ok": result.error is None and not result.cancelled,
                    "payload": body,
                }
                self._remember(account_id, idem, done)
                outgoing.put(done)
            except PermissionError:
                for agui in stream.finish(error="session belongs to another account"):
                    outgoing.put(_agui_frame(frame_id, agui))
                outgoing.put(
                    _frame_error(frame_id, "forbidden", "session belongs to another account")
                )
            except LookupError:
                for agui in stream.finish(error="no such session"):
                    outgoing.put(_agui_frame(frame_id, agui))
                outgoing.put(_frame_error(frame_id, "not_found", "no such session"))
            except Exception as exc:
                for agui in stream.finish(error=type(exc).__name__):
                    outgoing.put(_agui_frame(frame_id, agui))
                outgoing.put(_frame_error(frame_id, "turn_failed", type(exc).__name__))
            finally:
                profile_var.reset(profile_token)
                actor_account_var.reset(actor_token)
                request_id_var.reset(token)
                self._clear_inflight(account_id, idem)

        threading.Thread(target=work, name="praxis-turn", daemon=True).start()

    def _model(
        self,
        frame: dict[str, object],
        outgoing: queue.Queue[dict[str, object] | None],
        profile_name: str = "",
    ) -> None:
        frame_id = str(frame.get("id", ""))
        spec = str(_payload(frame).get("spec", "")).strip()
        try:
            chosen = self.agent.set_model(spec, profile=profile_name)
        except PermissionError as exc:
            outgoing.put(_frame_error(frame_id, "forbidden", str(exc)))
            return
        except ValueError as exc:
            outgoing.put(_frame_error(frame_id, "bad_request", str(exc)))
            return
        outgoing.put({"type": "result", "id": frame_id, "ok": True, "payload": {"model": chosen}})

    def _status(self) -> dict[str, object]:
        body = self.agent.status()
        body["protocol"] = PROTOCOL_VERSION
        body["pid"] = os.getpid()
        body["listen"] = f"127.0.0.1:{self.bound_port}"
        if self.socket_path:
            body["socket"] = self.socket_path
        return body

    def _idem_key(self, account_id: str, key: str) -> tuple[str, str] | None:
        if not key:
            return None
        return (account_id, key)

    def _cached(self, account_id: str, key: str) -> dict[str, object] | None:
        scoped = self._idem_key(account_id, key)
        if scoped is None:
            return None
        with self._idem_lock:
            found = self._idem.get(scoped)
            return dict(found) if found is not None else None

    def _remember(self, account_id: str, key: str, frame: dict[str, object]) -> None:
        scoped = self._idem_key(account_id, key)
        if scoped is None:
            return
        stored = dict(frame)
        stored.pop("id", None)
        with self._idem_lock:
            self._idem[scoped] = stored
            while len(self._idem) > 256:
                self._idem.pop(next(iter(self._idem)))

    def _mark_inflight(self, account_id: str, key: str) -> bool:
        """Return True when this account's key is already running."""
        scoped = self._idem_key(account_id, key)
        if scoped is None:
            return False
        with self._idem_lock:
            if scoped in self._inflight:
                return True
            self._inflight.add(scoped)
            return False

    def _clear_inflight(self, account_id: str, key: str) -> None:
        scoped = self._idem_key(account_id, key)
        if scoped is None:
            return
        with self._idem_lock:
            self._inflight.discard(scoped)

    def _profile_exists(self, name: str) -> bool:
        if self.data_root is None:
            return False
        home = self.data_root / "profiles" / name
        # A symlink or a path we cannot stat still counts as present.
        # ``Path.is_file`` on Python 3.14 is False for both, and a 404
        # would hide a profile the caller is not allowed to ignore.
        for filename in ("profile.toml", "prime.db"):
            kind = lstat_kind(home / filename)
            if kind in {StatKind.FILE, StatKind.SYMLINK, StatKind.UNREADABLE}:
                return True
        return False

    def _runtime_profile(self) -> str:
        if self.multi_profile:
            return ""
        if self.audit is None:
            return ""
        return self.audit.profile

    def _implicit_profile(self) -> str:
        """The profile a client gets when it does not name one.

        ``default`` wins when it exists, so a migrated single-user install
        keeps working. Otherwise the only profile is used.
        """
        if self.data_root is None:
            return ""
        from praxis_prime.profiles.home import list_profiles

        names = list_profiles(self.data_root)
        if "default" in names:
            return "default"
        if len(names) == 1:
            return names[0]
        return ""

    def _list_profiles(self, principal: Principal) -> dict[str, object]:
        if self.data_root is None:
            return {"ok": True, "profiles": []}
        from praxis_prime.profiles.home import list_profiles

        names = list_profiles(self.data_root)
        if (
            accounts_enforced(self.accounts)
            and self.accounts is not None
            and principal.account_id
            and not sees_all_profiles(principal.role)
        ):
            allowed = set(self.accounts.profile_ids_for(principal.account_id))
            names = [name for name in names if name in allowed]
        return {"ok": True, "profiles": [{"id": name} for name in names]}

    def _filter_broadcast(
        self,
        frame: dict[str, object],
        principal: Principal,
    ) -> dict[str, object] | None:
        """Scope one published event. ``None`` means this socket gets nothing.

        Owner and admin see the card, including an unscoped one. A member sees
        only a card for a profile they belong to. An auditor sees meta fields
        and not arguments, text, or a session id. A non-member sees nothing.
        The same split applies to any other broadcast (transcript, status).
        """
        if not accounts_enforced(self.accounts):
            return frame
        payload = frame.get("payload")
        if isinstance(payload, dict) and payload.get("kind") == "approval":
            approval = payload.get("approval")
            if not isinstance(approval, dict):
                return None
            visible = self._approval_broadcast(principal, approval)
            if visible is None:
                return None
            cloned = dict(frame)
            cloned_payload = dict(payload)
            cloned_payload["approval"] = visible
            cloned["payload"] = cloned_payload
            return cloned
        return self._scoped_event(principal, frame)

    def _approval_broadcast(
        self,
        principal: Principal,
        item: dict[str, object],
    ) -> dict[str, object] | None:
        if principal.role == "auditor":
            if not principal.account_id:
                return None
            return _approval_meta(item)
        if sees_all_profiles(principal.role):
            return dict(self._hide_foreign_session(principal, item))
        if self.accounts is None or not principal.account_id:
            return None
        profile = item.get("profileId")
        if not isinstance(profile, str) or not profile:
            return None
        allowed = set(self.accounts.profile_ids_for(principal.account_id))
        if profile not in allowed:
            return None
        return dict(self._hide_foreign_session(principal, item))

    def _scoped_event(
        self,
        principal: Principal,
        frame: dict[str, object],
    ) -> dict[str, object] | None:
        """Non-approval broadcasts. Auditors get no body. Members need a profile."""
        if principal.role == "auditor" or not principal.account_id:
            return None
        if sees_all_profiles(principal.role):
            return frame
        if self.accounts is None:
            return None
        profile = _event_profile(frame)
        if not profile:
            return None
        allowed = set(self.accounts.profile_ids_for(principal.account_id))
        if profile not in allowed:
            return None
        return frame

    def _process_profile(self) -> str:
        stamped = getattr(self.approvals, "profile_id", "")
        return self._runtime_profile() or (stamped if isinstance(stamped, str) else "")

    def _foreign_runtime(self, profile: str) -> Denial | None:
        """A named profile that this process did not open.

        The supervisor has no single runtime, so a named profile is a worker.
        An empty name is the profile authorize_action already bound.
        """
        if self.multi_profile:
            return None
        requested = profile.strip()
        if not requested:
            return None
        from praxis_prime.profiles.ids import profile_id

        named = profile_id(requested)
        runtime = self._process_profile()
        bound = profile_id(runtime) if runtime else None
        if named is None or bound is None or named != bound:
            return Denial(403, "forbidden", "this daemon runs a different profile")
        return None

    def _visible_approvals(
        self,
        principal: Principal,
        *,
        profile: str = "",
    ) -> list[dict[str, object]]:
        items = self._approvals_for_profile(self.approvals.list_pending(), profile)
        if (
            accounts_enforced(self.accounts)
            and not sees_all_profiles(principal.role)
            and self.accounts is not None
            and principal.account_id
        ):
            allowed = set(self.accounts.profile_ids_for(principal.account_id))
            kept: list[dict[str, object]] = []
            for item in items:
                card_profile = item.get("profileId")
                if isinstance(card_profile, str) and card_profile in allowed:
                    kept.append(item)
            items = kept
        return [self._hide_foreign_session(principal, item) for item in items]

    def _visible_meta(
        self,
        principal: Principal,
        *,
        profile: str = "",
    ) -> list[dict[str, object]]:
        """Metadata for the caller's profiles. Auditors, owners, and admins see all."""
        named = profile.strip()
        if (
            not accounts_enforced(self.accounts)
            or principal.role in {"owner", "admin", "auditor"}
            or self.accounts is None
            or not principal.account_id
        ):
            if named:
                return self.approvals.list_meta(profiles=frozenset({named}))
            runtime = "" if self.multi_profile else self._process_profile()
            if runtime:
                return self.approvals.list_meta(profiles=frozenset({runtime, ""}))
            return self.approvals.list_meta()
        allowed = set(self.accounts.profile_ids_for(principal.account_id))
        if named:
            allowed &= {named}
        elif not self.multi_profile:
            runtime = self._process_profile()
            if runtime:
                allowed &= {runtime}
        return self.approvals.list_meta(profiles=frozenset(allowed))

    def _approvals_for_profile(
        self,
        items: list[dict[str, object]],
        profile: str,
    ) -> list[dict[str, object]]:
        """Keep cards for the profile this read was authorized to see.

        A named supervisor request is one worker. With no name, owners and
        members keep the cards their role already allows. A single-process
        daemon drops a card stamped for some other profile.
        """
        named = profile.strip()
        if named:
            return [item for item in items if item.get("profileId") == named]
        if self.multi_profile:
            return items
        runtime = self._process_profile()
        if not runtime:
            return items
        return [
            item for item in items if not item.get("profileId") or item.get("profileId") == runtime
        ]

    def _hide_foreign_session(
        self,
        principal: Principal,
        item: dict[str, object],
    ) -> dict[str, object]:
        session_id = item.get("sessionId")
        if not isinstance(session_id, str) or not session_id or not principal.account_id:
            return item
        try:
            owner = self.agent.runtime.store.owner(session_id)
        except Exception:
            owner = None
        if owner is not None and owner[0] == principal.account_id:
            return item
        hidden = dict(item)
        hidden["sessionId"] = ""
        return hidden

    def _recheck(self, principal: Principal) -> Principal | Denial:
        """Reload role, status, and the login session before the next frame."""
        if principal.kind == "legacy" or self.accounts is None or not principal.account_id:
            return principal
        account = self.accounts.get_id(principal.account_id)
        if account is None or account.status != "active":
            return Denial(401, "unauthorized", "session expired or revoked")
        if principal.session_id and not self.accounts.session_is_live(principal.session_id):
            return Denial(401, "unauthorized", "session expired or revoked")
        if account.role == principal.role and account.username == principal.username:
            return principal
        return Principal(
            kind=principal.kind,
            account_id=principal.account_id,
            username=account.username,
            role=account.role,
            session_token=principal.session_token,
            session_id=principal.session_id,
        )

    def _ws_principal(
        self,
        payload: dict[str, object],
        header_token: str,
        path: str,
        headers: dict[str, str],
    ) -> Principal | Denial:
        ticket = str(payload.get("ticket", "") or "") or _request_ticket(path, headers)
        if ticket and self.accounts is not None:
            found = principal_from_ticket(self.accounts, ticket)
            if found is None:
                return Denial(401, "unauthorized", "websocket ticket rejected")
            return found
        presented = str(payload.get("token", "") or "") or header_token
        if not accounts_enforced(self.accounts):
            if not token_ok(presented, self.token):
                return Denial(401, "unauthorized", "gateway token rejected")
            return Principal(kind="legacy", account_id="", username="", role="operator")
        if self.bearer_enabled and token_ok(presented, self.token) and self.accounts is not None:
            owner = self.accounts.owner()
            if owner is None or owner.status != "active":
                return Denial(401, "unauthorized", "gateway token rejected")
            return Principal(
                kind="bootstrap",
                account_id=owner.id,
                username=owner.username,
                role="owner",
            )
        return Denial(401, "unauthorized", "gateway token rejected")


@dataclass
class _Subscriber:
    outgoing: queue.Queue[dict[str, object] | None]
    principal: Principal
    conn: socket.socket


def _client_cookie(
    store: AccountStore, headers: dict[str, str]
) -> list[tuple[str, str]]:
    """Set a signed pp_client when this browser does not already have one."""
    presented = cookie_value(headers.get("cookie", ""), CLIENT_COOKIE)
    _client, cookies = client_binding(store, presented)
    return cookies


def _approval_meta(item: dict[str, object]) -> dict[str, object]:
    """The content-free fields from ``GET /v1/approvals/meta``. No text."""
    decision = item.get("decision")
    if not isinstance(decision, str) or not decision:
        state = item.get("state")
        decision = state if isinstance(state, str) and state else "pending"
    created = item.get("createdAt")
    return {
        "id": item.get("id", ""),
        "tool": item.get("tool", ""),
        "risk": item.get("risk", ""),
        "createdAt": created if isinstance(created, str) else "",
        "decision": decision,
    }


def _event_profile(frame: dict[str, object]) -> str:
    payload = frame.get("payload")
    if not isinstance(payload, dict):
        return ""
    for key in ("profileId", "profile"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
        nested = payload.get("approval")
        if isinstance(nested, dict):
            inner = nested.get(key)
            if isinstance(inner, str) and inner:
                return inner
    return ""


def _write_frames(
    ws: WebSocketConnection,
    outgoing: queue.Queue[dict[str, object] | None],
) -> None:
    while True:
        item = outgoing.get()
        if item is None:
            return
        try:
            ws.send_text(json.dumps(item))
        except (OSError, WebSocketError):
            return


def _read_json(ws: WebSocketConnection) -> dict[str, object] | None:
    try:
        text = ws.recv_text()
    except (OSError, WebSocketError, ConnectionError, UnicodeError):
        return None
    if text is None:
        return None
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        return {"type": "", "id": "", "payload": {}}
    if not isinstance(loaded, dict):
        return {"type": "", "id": "", "payload": {}}
    return loaded


def _parse_head(raw: bytes) -> tuple[str, str, dict[str, str]]:
    text = raw.decode("iso-8859-1", errors="replace")
    lines = text.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) < 2:
        raise ValueError("bad request line")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().lower()
        if key == "host" and "host" in headers:
            headers["x-duplicate-host"] = "1"
        headers[key] = value.strip()
    return parts[0].upper(), parts[1], headers


_THEME_POSTS = frozenset({"/v1/themes/install", "/v1/themes/preview"})


def _reject_theme_upload(
    conn: socket.socket,
    buffer: ByteBuffer,
    method: str,
    route: str,
    headers: dict[str, str],
    status: int,
    code: str,
    message: str,
) -> None:
    """Refuse the request, reading a theme upload body first.

    Origin and ``Sec-Fetch-Site: cross-site`` are decided before the body
    is read. Closing then, with the zip still in the socket buffer, resets
    the connection. The client sees a network error instead of the status.
    """
    if method == "POST" and route in _THEME_POSTS:
        _drain_declared_body(buffer, headers, MAX_THEME_BODY)
    _write_http(conn, status, _error(code, message))


def _drain_declared_body(buffer: ByteBuffer, headers: dict[str, str], limit: int) -> None:
    raw = headers.get("content-length", "")
    if not raw:
        return
    try:
        length = int(raw)
    except ValueError:
        return
    if length <= 0 or length > limit:
        return
    buffer.read_exact(length)


def _content_length(headers: dict[str, str]) -> int:
    raw = headers.get("content-length", "0") or "0"
    try:
        length = int(raw)
    except ValueError as exc:
        raise ValueError("bad content length") from exc
    if length < 0 or length > 1_000_000:
        raise ValueError("body too large")
    return length


def _write_http(
    conn: socket.socket,
    status: int,
    payload: dict[str, object],
    extras: list[tuple[str, str]] | None = None,
) -> None:
    reasons = {
        200: "OK",
        302: "Found",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        409: "Conflict",
        413: "Payload Too Large",
        415: "Unsupported Media Type",
        429: "Too Many Requests",
        500: "Error",
        503: "Unavailable",
    }
    body = json.dumps(payload).encode("utf-8")
    lines = [
        f"HTTP/1.1 {status} {reasons.get(status, 'Error')}",
        "Content-Type: application/json",
        f"Content-Length: {len(body)}",
        "Connection: close",
        "Cache-Control: no-store",
        "X-Content-Type-Options: nosniff",
    ]
    for name, value in extras or []:
        if "\r" in value or "\n" in value:
            continue
        lines.append(f"{name}: {value}")
    head = "\r\n".join(lines) + "\r\n\r\n"
    try:
        conn.sendall(head.encode("ascii") + body)
    except OSError:
        return


def _error(code: str, message: str) -> dict[str, object]:
    return {"ok": False, "error": {"code": code, "message": message}}


def _frame_error(frame_id: str, code: str, message: str) -> dict[str, object]:
    return {
        "type": "error",
        "id": frame_id,
        "ok": False,
        "payload": {"code": code, "message": message},
    }


def _payload(frame: dict[str, object]) -> dict[str, object]:
    payload = frame.get("payload")
    if isinstance(payload, dict):
        return payload
    return {}


def _turn_payload(result: TurnResult) -> dict[str, object]:
    return {
        "sessionId": result.session_id,
        "text": result.text,
        "error": result.error,
        "cancelled": result.cancelled,
    }


def _agui_frame(frame_id: str, event: dict[str, object]) -> dict[str, object]:
    return {"type": "event", "id": frame_id, "payload": {"kind": "agui", "agui": event}}


def _write_bytes(
    conn: socket.socket,
    status: int,
    body: bytes,
    content_type: str,
    extras: list[tuple[str, str]],
) -> None:
    lines = [
        f"HTTP/1.1 {status} OK",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    for name, value in extras:
        if "\r" in value or "\n" in value:
            continue
        lines.append(f"{name}: {value}")
    head = "\r\n".join(lines) + "\r\n\r\n"
    try:
        conn.sendall(head.encode("ascii") + body)
    except OSError:
        return


_RESTART_MESSAGE = "Restart praxis-primed to finish profile setup."
_SETUP_MESSAGE = "Setup is in progress. Retry shortly."


def _http_action(method: str, route: str) -> str:
    if method == "GET" and route in {"/v1/memory", "/v1/skills", "/v1/routines"}:
        return "content"
    if method == "GET" and route == "/v1/admin/directory":
        return "admin"
    if method == "POST" and (_APPROVAL_PATH.fullmatch(route) or route == "/v1/approvals"):
        return "approve"
    if method == "GET" and route == "/v1/approvals":
        return "approval_list"
    if method == "POST" and route in {"/v1/decide", "/v1/systemone"}:
        return "chat"
    if method == "POST" and _ROUTINE_FIRE.fullmatch(route):
        return "chat"
    if method == "GET" and route == "/v1/audit":
        return "audit"
    if method == "POST" and route in {
        "/v1/themes/install",
        "/v1/themes/preview",
        "/v1/themes/remove",
        "/v1/themes/lock",
    }:
        return "admin"
    return "read"


def _frame_action(kind: str) -> str:
    if kind.startswith("onboarding."):
        return "admin"
    if kind == "approvals.decide":
        return "approve"
    if kind in {"chat.send", "model.set", "session.drop"}:
        return "chat"
    if kind == "approvals.list":
        return "approval_list"
    return "read"


def _profile_of(item: dict[str, object] | None) -> str:
    if item is None:
        return ""
    raw = item.get("profileId", "")
    if isinstance(raw, str):
        return raw
    return ""


def _principal_public(principal: Principal) -> dict[str, object]:
    return {
        "id": principal.account_id,
        "username": principal.username,
        "role": principal.role,
        "kind": principal.kind,
    }


def _request_ticket(path: str, headers: dict[str, str]) -> str:
    header = headers.get("x-praxis-ticket", "").strip()
    if header:
        return header
    query = parse_qs(path.split("?", 1)[1] if "?" in path else "", keep_blank_values=False)
    values = query.get("ticket", [])
    if len(values) == 1:
        return values[0]
    return ""


def _peer_host(conn: socket.socket) -> str:
    try:
        addr = conn.getpeername()
    except OSError:
        return ""
    if not isinstance(addr, tuple) or not addr or not isinstance(addr[0], str):
        return ""
    host = addr[0]
    if len(host) > 64:
        return ""
    return host


def _peer_is_loopback(addr: object) -> bool:
    if not isinstance(addr, tuple) or not addr:
        return False
    host = addr[0]
    return isinstance(host, str) and (host == "127.0.0.1" or host.startswith("127."))
