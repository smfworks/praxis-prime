"""Operator client for the local gateway.

Chat, status, and approvals all use the same WebSocket frames. The Unix
socket is preferred when the daemon published one; TCP loopback is the
fallback (ARCHITECTURE §3.1).
"""

from __future__ import annotations

import json
import os
import queue
import socket
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from praxis_prime import __version__
from praxis_prime.gateway.ws import WebSocketConnection, WebSocketError, client_handshake

EventHandler = Callable[[dict[str, object]], None]
Decider = Callable[[dict[str, object]], str | None]
Pulse = Callable[[], None]


class GatewayError(RuntimeError):
    """The daemon rejected a frame or the connection dropped."""


@dataclass(frozen=True, slots=True)
class Endpoint:
    host: str
    port: int
    token: str = field(repr=False)
    socket_path: str | None = None


class GatewayClient:
    """One operator session. Not safe for concurrent requests."""

    def __init__(self, ws: WebSocketConnection) -> None:
        self.ws = ws
        self._events: queue.Queue[dict[str, object]] = queue.Queue()
        self._waiters: dict[str, queue.Queue[dict[str, object]]] = {}
        self._closed = threading.Event()
        self._reader = threading.Thread(
            target=self._read_loop,
            name="praxis-gateway-client",
            daemon=True,
        )
        self._reader.start()

    @classmethod
    def connect(
        cls,
        endpoint: Endpoint,
        *,
        timeout: float = 5,
        role: str = "operator",
        client: str = "cli",
    ) -> GatewayClient:
        # The socket instance below reuses the name client.
        client_name = client
        sock = _connect_socket(endpoint, timeout=timeout)
        try:
            buffer = client_handshake(
                sock,
                host=endpoint.host,
                port=endpoint.port,
                token=endpoint.token,
            )
        except Exception:
            sock.close()
            raise
        client = cls(WebSocketConnection(sock, buffer, client=True))
        try:
            hello = client.request(
                "connect",
                {
                    "role": role,
                    "client": client_name,
                    "version": __version__,
                    "token": endpoint.token,
                    "capabilities": ["chat", "approvals"],
                },
                timeout=timeout,
            )
        except Exception:
            client.close()
            raise
        if hello.get("type") != "hello" or not hello.get("ok"):
            client.close()
            message = _message(hello)
            raise GatewayError(message or "gateway rejected the connection")
        return client

    def close(self) -> None:
        self._closed.set()
        try:
            self.ws.close()
        except OSError:
            return

    @property
    def closed(self) -> bool:
        """True once the reader has exited or a write has failed."""
        return self._closed.is_set()

    def status(self) -> dict[str, object]:
        frame = self.request("status", {})
        self._raise_if_error(frame)
        payload = frame.get("payload")
        return payload if isinstance(payload, dict) else {}

    def list_approvals(self, profile: str = "", timeout: float = 30) -> list[dict[str, object]]:
        payload: dict[str, object] = {}
        if profile:
            payload["profile"] = profile
        frame = self.request("approvals.list", payload, timeout=timeout)
        self._raise_if_error(frame)
        payload = frame.get("payload")
        if not isinstance(payload, dict):
            return []
        items = payload.get("approvals")
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
        return []

    def decide(self, approval_id: str, decision: str, profile: str = "") -> dict[str, object]:
        payload: dict[str, object] = {"approvalId": approval_id, "decision": decision}
        if profile:
            payload["profile"] = profile
        frame = self.request("approvals.decide", payload)
        self._raise_if_error(frame)
        payload = frame.get("payload")
        return payload if isinstance(payload, dict) else {}

    def set_model(self, spec: str, *, profile: str | None = None) -> str:
        payload: dict[str, object] = {"spec": spec}
        if profile:
            payload["profile"] = profile
        frame = self.request("model.set", payload)
        self._raise_if_error(frame)
        payload = frame.get("payload")
        if isinstance(payload, dict):
            return str(payload.get("model", spec))
        return spec

    def drop_session(self, session_id: str) -> None:
        frame = self.request("session.drop", {"sessionId": session_id}, session_id=session_id)
        self._raise_if_error(frame)

    def chat(
        self,
        text: str,
        *,
        session_id: str | None = None,
        on_event: EventHandler | None = None,
        decider: Decider | None = None,
        timeout: float | None = None,
        profile: str | None = None,
        pulse: Pulse | None = None,
    ) -> dict[str, object]:
        """Send one turn and return the result frame.

        ``decider`` is polled while an approval is pending. Return a decision
        string to answer it, or None to keep waiting. Telegram or another
        operator can decide first; this method returns when the turn ends.
        ``pulse`` runs on this thread each wait so another decision can be
        sent without waiting for the turn to finish. A rejected decision is
        reported through ``on_event`` and does not drop the turn.
        """
        frame_id = uuid.uuid4().hex
        box: queue.Queue[dict[str, object]] = queue.Queue(maxsize=1)
        self._waiters[frame_id] = box
        payload: dict[str, object] = {"text": text}
        if profile:
            payload["profile"] = profile
        body: dict[str, object] = {
            "type": "chat.send",
            "id": frame_id,
            "idempotencyKey": uuid.uuid4().hex,
            "payload": payload,
        }
        if session_id:
            body["sessionId"] = session_id
        try:
            self.ws.send_text(json.dumps(body))
        except OSError as exc:
            self._closed.set()
            self._waiters.pop(frame_id, None)
            raise GatewayError(f"disconnected: {exc}") from exc
        deadline = None if timeout is None else time.monotonic() + timeout
        pending: dict[str, object] | None = None
        try:
            while not self._closed.is_set():
                if pulse is not None:
                    pulse()
                if deadline is not None and time.monotonic() > deadline:
                    raise GatewayError("timed out waiting for the daemon")
                event = _get(self._events, 0.2)
                if event is not None and event.get("id") == frame_id:
                    payload = event.get("payload")
                    if isinstance(payload, dict):
                        if on_event is not None:
                            on_event(payload)
                        approval = payload.get("approval")
                        if payload.get("kind") == "approval" and isinstance(approval, dict):
                            pending = approval
                result = _get(box, 0)
                if result is not None:
                    _drain_frame(self._events, frame_id, on_event)
                    if result.get("type") == "error":
                        raise GatewayError(_message(result) or "turn failed")
                    return result
                if pending is not None and decider is not None:
                    decision = decider(pending)
                    if decision:
                        try:
                            self.decide(str(pending.get("id", "")), decision, profile or "")
                        except GatewayError as exc:
                            if on_event is not None:
                                on_event(
                                    {
                                        "kind": "status",
                                        "phase": "error",
                                        "detail": str(exc),
                                    }
                                )
                        pending = None
            raise GatewayError("gateway connection closed")
        finally:
            self._waiters.pop(frame_id, None)

    def request(
        self,
        kind: str,
        payload: dict[str, object],
        *,
        session_id: str | None = None,
        timeout: float = 30,
    ) -> dict[str, object]:
        frame_id = uuid.uuid4().hex
        box: queue.Queue[dict[str, object]] = queue.Queue(maxsize=1)
        self._waiters[frame_id] = box
        frame: dict[str, object] = {
            "type": kind,
            "id": frame_id,
            "idempotencyKey": uuid.uuid4().hex,
            "payload": payload,
        }
        if session_id:
            frame["sessionId"] = session_id
        try:
            self.ws.send_text(json.dumps(frame))
            result = box.get(timeout=timeout)
        except queue.Empty as exc:
            raise GatewayError(f"timed out waiting for {kind}") from exc
        except OSError as exc:
            self._closed.set()
            raise GatewayError(f"disconnected: {exc}") from exc
        finally:
            self._waiters.pop(frame_id, None)
        return result

    def _raise_if_error(self, frame: dict[str, object]) -> None:
        if frame.get("type") == "error" or frame.get("ok") is False:
            raise GatewayError(_message(frame) or "gateway request failed")

    def _read_loop(self) -> None:
        try:
            while not self._closed.is_set():
                try:
                    text = self.ws.recv_text()
                except (OSError, WebSocketError, ConnectionError, UnicodeError):
                    return
                if text is None:
                    return
                try:
                    loaded = json.loads(text)
                except json.JSONDecodeError:
                    continue
                if not isinstance(loaded, dict):
                    continue
                if loaded.get("type") == "event":
                    self._events.put(loaded)
                    continue
                frame_id = str(loaded.get("id", ""))
                box = self._waiters.get(frame_id)
                if box is not None:
                    box.put(loaded)
        finally:
            self._closed.set()
            self._fail_waiters("connection closed")

    def _fail_waiters(self, message: str) -> None:
        failure = {"type": "error", "ok": False, "payload": {"code": "closed", "message": message}}
        for box in list(self._waiters.values()):
            box.put(dict(failure))


def _connect_socket(endpoint: Endpoint, *, timeout: float) -> socket.socket:
    if endpoint.socket_path and os.path.exists(endpoint.socket_path):
        unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            unix.settimeout(timeout)
            unix.connect(endpoint.socket_path)
            unix.settimeout(None)
            return unix
        except OSError:
            unix.close()
    sock = socket.create_connection((endpoint.host, endpoint.port), timeout=timeout)
    sock.settimeout(None)
    return sock


def _drain_frame(
    events: queue.Queue[dict[str, object]],
    frame_id: str,
    on_event: EventHandler | None,
) -> None:
    """Apply events already read before the result frame is returned."""
    pending: list[dict[str, object]] = []
    while True:
        event = _get(events, 0)
        if event is None:
            break
        pending.append(event)
    for event in pending:
        if event.get("id") != frame_id:
            events.put(event)
            continue
        payload = event.get("payload")
        if on_event is not None and isinstance(payload, dict):
            on_event(payload)


def _get(box: queue.Queue[dict[str, object]], timeout: float) -> dict[str, object] | None:
    try:
        if timeout == 0:
            return box.get_nowait()
        return box.get(timeout=timeout)
    except queue.Empty:
        return None


def _message(frame: dict[str, object]) -> str:
    payload = frame.get("payload")
    if isinstance(payload, dict):
        message = payload.get("message")
        if isinstance(message, str):
            return message
    return ""
