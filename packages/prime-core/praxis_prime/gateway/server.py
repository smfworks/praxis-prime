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

from praxis_prime.approvals.queue import ApprovalQueue, parse_decision
from praxis_prime.decide.engine import DecisionEngine
from praxis_prime.decide.schema import DecideError
from praxis_prime.gateway.auth import bearer_token, token_ok
from praxis_prime.gateway.protocol import (
    CHAT_ROLES,
    OPERATOR_ONLY,
    PROTOCOL_VERSION,
    ROLES,
    request_id_var,
)
from praxis_prime.gateway.ws import (
    ByteBuffer,
    WebSocketConnection,
    WebSocketError,
    server_upgrade_response,
)
from praxis_prime.host import Host, TurnResult
from praxis_prime.observe import JsonLogger

_APPROVAL_PATH = re.compile(r"^/v1/approvals/(ap_[0-9a-f]{8})$")


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
    ) -> None:
        self.host = host
        self._port = port
        self.token = token
        self.agent = agent
        self.approvals = approvals
        self.decider = decider
        self.logger = logger
        self.socket_path = socket_path
        self._stopped = threading.Event()
        self._listen: socket.socket | None = None
        self._unix: socket.socket | None = None
        self._threads: list[threading.Thread] = []
        self._conns: set[socket.socket] = set()
        self._conn_lock = threading.Lock()
        self._subs: list[queue.Queue[dict[str, object] | None]] = []
        self._sub_lock = threading.Lock()
        self._idem: dict[str, dict[str, object]] = {}
        self._inflight: set[str] = set()
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

    def publish(self, frame: dict[str, object]) -> None:
        with self._sub_lock:
            subscribers = list(self._subs)
        for subscriber in subscribers:
            subscriber.put(frame)

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
            if headers.get("upgrade", "").lower() == "websocket":
                self._handle_ws(conn, buffer, headers)
                return
            length = _content_length(headers)
            body = buffer.read_exact(length) if length else b""
            status, payload = self._http(method, path, headers, body)
            _write_http(conn, status, payload)
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
    ) -> tuple[int, dict[str, object]]:
        route = path.split("?", 1)[0]
        if method == "GET" and route == "/health":
            return 200, {"ok": True, "service": "praxis-primed"}
        if not token_ok(bearer_token(headers), self.token):
            if self.logger is not None:
                self.logger.warning("http_unauthorized", path=route)
            return 401, _error("unauthorized", "Bearer token required")
        if method == "GET" and route == "/status":
            return 200, {"ok": True, "status": self._status()}
        if method == "GET" and route == "/v1/approvals":
            return 200, {"ok": True, "approvals": self.approvals.list_pending()}
        match = _APPROVAL_PATH.fullmatch(route)
        if method == "POST" and match is not None:
            try:
                parsed = json.loads(body.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                return 400, _error("bad_request", "approval body must be JSON")
            if not isinstance(parsed, dict):
                return 400, _error("bad_request", "approval body must be an object")
            try:
                decision = parse_decision(parsed.get("decision"))
                item = self.approvals.decide(match.group(1), decision, actor="operator")
            except LookupError as exc:
                return 404, _error("not_found", str(exc))
            except ValueError as exc:
                return 400, _error("bad_request", str(exc))
            return 200, {"ok": True, "approval": item}
        if method == "POST" and route in {"/v1/decide", "/v1/systemone"}:
            return self._http_decide(body)
        return 404, _error("not_found", "no such route")

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
    ) -> None:
        key = headers.get("sec-websocket-key", "")
        if not key:
            _write_http(conn, 400, _error("bad_request", "missing websocket key"))
            return
        header_token = bearer_token(headers)
        if header_token and not token_ok(header_token, self.token):
            if self.logger is not None:
                self.logger.warning("ws_unauthorized")
            _write_http(conn, 401, _error("unauthorized", "Bearer token required"))
            return
        conn.sendall(server_upgrade_response(key))
        ws = WebSocketConnection(conn, buffer, client=False)
        outgoing: queue.Queue[dict[str, object] | None] = queue.Queue()
        with self._sub_lock:
            self._subs.append(outgoing)
        writer = threading.Thread(target=_write_frames, args=(ws, outgoing), daemon=True)
        writer.start()
        role: str | None = None
        try:
            first = _read_json(ws)
            role = self._connect(first, header_token, outgoing)
            if role is None:
                return
            while not self._stopped.is_set():
                frame = _read_json(ws)
                if frame is None:
                    return
                self._dispatch(frame, role, outgoing)
        finally:
            with self._sub_lock:
                if outgoing in self._subs:
                    self._subs.remove(outgoing)
            outgoing.put(None)
            writer.join(timeout=1)

    def _connect(
        self,
        frame: dict[str, object] | None,
        header_token: str,
        outgoing: queue.Queue[dict[str, object] | None],
    ) -> str | None:
        if frame is None or frame.get("type") != "connect":
            frame_id = str((frame or {}).get("id", ""))
            outgoing.put(
                _frame_error(frame_id, "connect_required", "first frame must be connect")
            )
            return None
        payload = _payload(frame)
        presented = str(payload.get("token", "")) or header_token
        frame_id = str(frame.get("id", ""))
        if not token_ok(presented, self.token):
            if self.logger is not None:
                self.logger.warning("ws_unauthorized")
            outgoing.put(_frame_error(frame_id, "unauthorized", "gateway token rejected"))
            return None
        role = str(payload.get("role", ""))
        if role not in ROLES:
            outgoing.put(_frame_error(frame_id, "bad_role", "unknown role"))
            return None
        outgoing.put(
            {
                "type": "hello",
                "id": frame_id,
                "ok": True,
                "payload": {
                    "protocol": PROTOCOL_VERSION,
                    "version": self._status().get("version", ""),
                    "role": role,
                },
            }
        )
        return role

    def _dispatch(
        self,
        frame: dict[str, object],
        role: str,
        outgoing: queue.Queue[dict[str, object] | None],
    ) -> None:
        kind = str(frame.get("type", ""))
        frame_id = str(frame.get("id", ""))
        if kind in OPERATOR_ONLY and role != "operator":
            outgoing.put(_frame_error(frame_id, "forbidden", f"{role} cannot {kind}"))
            return
        if kind == "chat.send" and role not in CHAT_ROLES:
            outgoing.put(_frame_error(frame_id, "forbidden", f"{role} cannot chat"))
            return
        idem = frame.get("idempotencyKey")
        key = idem if isinstance(idem, str) and idem else ""
        cached = self._cached(key)
        if cached is not None:
            replay = dict(cached)
            replay["id"] = frame_id
            outgoing.put(replay)
            return
        if key and self._mark_inflight(key):
            outgoing.put(_frame_error(frame_id, "in_progress", "duplicate request"))
            return
        try:
            if kind == "ping":
                outgoing.put({"type": "pong", "id": frame_id, "ok": True, "payload": {}})
            elif kind == "status":
                result = {"type": "result", "id": frame_id, "ok": True, "payload": self._status()}
                self._remember(key, result)
                outgoing.put(result)
            elif kind == "approvals.list":
                result = {
                    "type": "result",
                    "id": frame_id,
                    "ok": True,
                    "payload": {"approvals": self.approvals.list_pending()},
                }
                outgoing.put(result)
            elif kind == "approvals.decide":
                self._decide(frame, outgoing)
            elif kind == "chat.send":
                self._chat(frame, outgoing, key)
            elif kind == "model.set":
                self._model(frame, outgoing)
            elif kind == "session.drop":
                session_id = frame.get("sessionId") or _payload(frame).get("sessionId")
                self.agent.drop_session(session_id if isinstance(session_id, str) else None)
                outgoing.put({"type": "result", "id": frame_id, "ok": True, "payload": {}})
            else:
                outgoing.put(_frame_error(frame_id, "unknown_type", f"unknown frame {kind}"))
        finally:
            if key and kind != "chat.send":
                self._clear_inflight(key)

    def _decide(
        self,
        frame: dict[str, object],
        outgoing: queue.Queue[dict[str, object] | None],
    ) -> None:
        frame_id = str(frame.get("id", ""))
        payload = _payload(frame)
        try:
            decision = parse_decision(payload.get("decision"))
            approval_id = str(payload.get("approvalId", ""))
            item = self.approvals.decide(approval_id, decision, actor="operator")
        except LookupError as exc:
            outgoing.put(_frame_error(frame_id, "not_found", str(exc)))
            return
        except ValueError as exc:
            outgoing.put(_frame_error(frame_id, "bad_request", str(exc)))
            return
        outgoing.put({"type": "result", "id": frame_id, "ok": True, "payload": {"approval": item}})

    def _chat(
        self,
        frame: dict[str, object],
        outgoing: queue.Queue[dict[str, object] | None],
        idem: str,
    ) -> None:
        frame_id = str(frame.get("id", ""))
        payload = _payload(frame)
        text = payload.get("text")
        if not isinstance(text, str) or not text.strip():
            self._clear_inflight(idem)
            outgoing.put(_frame_error(frame_id, "bad_request", "chat text is empty"))
            return
        session = frame.get("sessionId") or payload.get("sessionId")
        session_id = session if isinstance(session, str) and session else None

        def work() -> None:
            token = request_id_var.set(frame_id)

            def on_event(event: dict[str, object]) -> None:
                outgoing.put({"type": "event", "id": frame_id, "payload": event})

            try:
                result = self.agent.chat(text, session_id=session_id, on_event=on_event)
                body = _turn_payload(result)
                done: dict[str, object] = {
                    "type": "result",
                    "id": frame_id,
                    "ok": result.error is None and not result.cancelled,
                    "payload": body,
                }
                self._remember(idem, done)
                outgoing.put(done)
            except Exception as exc:
                outgoing.put(_frame_error(frame_id, "turn_failed", type(exc).__name__))
            finally:
                request_id_var.reset(token)
                self._clear_inflight(idem)

        threading.Thread(target=work, name="praxis-turn", daemon=True).start()

    def _model(
        self,
        frame: dict[str, object],
        outgoing: queue.Queue[dict[str, object] | None],
    ) -> None:
        frame_id = str(frame.get("id", ""))
        spec = str(_payload(frame).get("spec", "")).strip()
        try:
            chosen = self.agent.set_model(spec)
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

    def _cached(self, key: str) -> dict[str, object] | None:
        if not key:
            return None
        with self._idem_lock:
            found = self._idem.get(key)
            return dict(found) if found is not None else None

    def _remember(self, key: str, frame: dict[str, object]) -> None:
        if not key:
            return
        stored = dict(frame)
        stored.pop("id", None)
        with self._idem_lock:
            self._idem[key] = stored
            while len(self._idem) > 256:
                self._idem.pop(next(iter(self._idem)))

    def _mark_inflight(self, key: str) -> bool:
        """Return True when this key is already running."""
        with self._idem_lock:
            if key in self._inflight:
                return True
            self._inflight.add(key)
            return False

    def _clear_inflight(self, key: str) -> None:
        if not key:
            return
        with self._idem_lock:
            self._inflight.discard(key)


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
        headers[name.strip().lower()] = value.strip()
    return parts[0].upper(), parts[1], headers


def _content_length(headers: dict[str, str]) -> int:
    raw = headers.get("content-length", "0") or "0"
    try:
        length = int(raw)
    except ValueError as exc:
        raise ValueError("bad content length") from exc
    if length < 0 or length > 1_000_000:
        raise ValueError("body too large")
    return length


def _write_http(conn: socket.socket, status: int, payload: dict[str, object]) -> None:
    reasons = {
        200: "OK",
        400: "Bad Request",
        401: "Unauthorized",
        404: "Not Found",
        500: "Error",
        503: "Unavailable",
    }
    body = json.dumps(payload).encode("utf-8")
    head = (
        f"HTTP/1.1 {status} {reasons.get(status, 'Error')}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "Cache-Control: no-store\r\n"
        "\r\n"
    )
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


def _peer_is_loopback(addr: object) -> bool:
    if not isinstance(addr, tuple) or not addr:
        return False
    host = addr[0]
    return isinstance(host, str) and (host == "127.0.0.1" or host.startswith("127."))
