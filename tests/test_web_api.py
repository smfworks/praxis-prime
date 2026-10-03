"""M1d gateway: request checks, the SPA shell, catalog routes, and web approvals."""

from __future__ import annotations

import json
import queue
import socket
import threading
import time
from pathlib import Path

from tests.fakes import ScriptedProvider
from tests.test_accounts import _login, _request

from praxis_prime.accounts.db import AccountStore
from praxis_prime.approvals.queue import ApprovalQueue
from praxis_prime.compliance.report import collect_events
from praxis_prime.gateway.agui import AGUI_TYPES
from praxis_prime.gateway.client import Endpoint, GatewayClient
from praxis_prime.gateway.server import GatewayServer
from praxis_prime.host import Host, TurnResult
from praxis_prime.observe import JsonLogger
from praxis_prime.profiles.home import create_profile
from praxis_prime.router.types import AssistantFinal, ToolCall
from praxis_prime.runtime import build_runtime
from praxis_prime.supervisor.routing import RoutingHost
from praxis_prime.tools.registry import Risk, Tool, ToolRegistry

_PASSWORD = "correct-horse"


def test_agui_schema_matches_the_event_names():
    path = Path(__file__).resolve().parents[1] / "protocol" / "agui.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    assert set(schema["properties"]["type"]["enum"]) == set(AGUI_TYPES)


def test_cross_site_non_json_and_oversized_bodies_are_refused(tmp_path: Path):
    server, host = _open(tmp_path)
    try:
        status, _headers, body = _raw(
            server.bound_port,
            "GET",
            "/health",
            extra={"Sec-Fetch-Site": "cross-site"},
        )
        assert status == 403
        assert body["error"]["code"] == "forbidden"

        status, _headers, body = _raw(
            server.bound_port,
            "POST",
            "/v1/auth/login",
            payload=b'{"username":"ada"}',
            extra={"Content-Type": "text/plain"},
        )
        assert status == 415
        assert body["error"]["code"] == "unsupported_media_type"

        status, _headers, body = _raw(
            server.bound_port,
            "POST",
            "/v1/auth/login",
            extra={"Content-Type": "application/json", "Content-Length": "1000001"},
        )
        assert status == 413
        assert body["error"]["code"] == "payload_too_large"
    finally:
        server.shutdown()
        host.close()


def test_static_shell_sends_a_strict_csp(tmp_path: Path, monkeypatch):
    ui = tmp_path / "ui"
    assets = ui / "assets"
    assets.mkdir(parents=True)
    (ui / "index.html").write_text(
        "<!doctype html><html><head><title>Praxis Prime</title></head>"
        '<body><script src="/assets/app.js"></script></body></html>',
        encoding="utf-8",
    )
    (assets / "app.js").write_text("export const ready = true;\n", encoding="utf-8")
    monkeypatch.setenv("PRAXIS_PRIME_UI_DIR", str(ui))
    server, host = _open(tmp_path)
    try:
        status, headers, raw = _raw_bytes(server.bound_port, "GET", "/")
        assert status == 200
        assert b"<script src=" in raw
        assert b"unsafe-inline" not in raw
        policy = headers.get("content-security-policy", "")
        assert "script-src 'self'" in policy
        assert "unsafe-inline" not in policy
        assert "unsafe-eval" not in policy
        status, headers, raw = _raw_bytes(server.bound_port, "GET", "/assets/app.js")
        assert status == 200
        assert raw.startswith(b"export const ready")
        assert "script-src 'self'" in headers.get("content-security-policy", "")
        status, _headers, body = _raw(server.bound_port, "GET", "/assets/../index.html")
        assert status == 404
        assert body["error"]["code"] == "not_allowed"
    finally:
        server.shutdown()
        host.close()


def test_session_reload_returns_the_csrf_token(tmp_path: Path):
    server, host, _runtime = _accounts(tmp_path)
    try:
        cookie, csrf, _body = _login(server.bound_port, "ada", _PASSWORD)
        status, _headers, body = _request(
            server.bound_port,
            "GET",
            "/v1/auth/session",
            cookie=cookie,
        )
        assert status == 200
        assert body["csrfToken"] == csrf
        assert "pp_session" not in json.dumps(body)
    finally:
        server.shutdown()
        host.close()


def test_catalog_is_limited_to_the_granted_profile(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    store = AccountStore(data / "accounts.db")
    ada = store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
    bea = store.create_account(
        username_text="bea",
        password=_PASSWORD,
        display_name="Bea",
        role="operator",
    )
    create_profile(data, "alpha")
    create_profile(data, "beta")
    store.set_membership(ada.id, "alpha", "owner")
    store.set_membership(bea.id, "beta", "operator")
    spy = _Spy()
    logger = JsonLogger(tmp_path / "daemon.log")
    server = GatewayServer(
        host="127.0.0.1",
        port=0,
        token="test-token",
        agent=spy,  # type: ignore[arg-type]
        approvals=ApprovalQueue(),
        logger=logger,
        accounts=store,
        data_root=data,
        multi_profile=True,
    )
    server.start()
    try:
        ada_cookie, ada_csrf, _ada = _login(server.bound_port, "ada", _PASSWORD)
        bea_cookie, bea_csrf, _bea = _login(server.bound_port, "bea", _PASSWORD)
        status, _headers, body = _request(
            server.bound_port,
            "GET",
            "/v1/memory",
            cookie=bea_cookie,
            csrf=bea_csrf,
            profile="alpha",
        )
        assert status == 403
        assert spy.calls == []
        status, _headers, body = _request(
            server.bound_port,
            "GET",
            "/v1/memory",
            cookie=bea_cookie,
            csrf=bea_csrf,
            profile="beta",
        )
        assert status == 200
        assert body["profile"] == "beta"
        assert spy.calls == [("list_memory", "beta")]
        status, _headers, body = _request(
            server.bound_port,
            "GET",
            "/v1/admin/directory",
            cookie=bea_cookie,
            csrf=bea_csrf,
        )
        assert status == 403
        status, _headers, body = _request(
            server.bound_port,
            "GET",
            "/v1/admin/directory",
            cookie=ada_cookie,
            csrf=ada_csrf,
        )
        assert status == 200
        names = {item["username"] for item in body["accounts"]}
        assert names == {"ada", "bea"}
        assert "email" not in json.dumps(body)
        assert {item["profileId"] for item in body["memberships"]} == {"alpha", "beta"}
    finally:
        server.shutdown()


def test_in_process_catalog_reads_that_runtime(tmp_path: Path):
    server, host, runtime = _accounts(tmp_path, owner_only=True)
    try:
        runtime.memory.remember("the kettle is blue")
        cookie, csrf, _body = _login(server.bound_port, "ada", _PASSWORD)
        status, _headers, body = _request(
            server.bound_port,
            "GET",
            "/v1/memory",
            cookie=cookie,
            csrf=csrf,
        )
        assert status == 200
        assert any(item["content"] == "the kettle is blue" for item in body["entries"])
        status, _headers, skills = _request(
            server.bound_port,
            "GET",
            "/v1/skills",
            cookie=cookie,
            csrf=csrf,
        )
        assert status == 200
        assert isinstance(skills["skills"], list)
        status, _headers, routines = _request(
            server.bound_port,
            "GET",
            "/v1/routines",
            cookie=cookie,
            csrf=csrf,
        )
        assert status == 200
        assert routines["routines"] == []
    finally:
        server.shutdown()
        host.close()


def test_web_approval_is_once_and_stays_on_that_account(tmp_path: Path):
    ran: list[str] = []
    replies = [
        AssistantFinal(
            content="",
            tool_calls=(ToolCall(id="c1", name="delete_file", arguments={"path": "secret"}),),
        ),
        AssistantFinal(content="deleted"),
    ]
    server, host, runtime = _accounts(
        tmp_path,
        replies=replies,
        registry=_delete_tool(ran),
        profile="default",
    )
    store = AccountStore(tmp_path / "data" / "accounts.db")
    store.create_account(
        username_text="otto",
        password=_PASSWORD,
        display_name="Otto",
        role="operator",
    )
    client = GatewayClient.connect(
        Endpoint("127.0.0.1", server.bound_port, "test-token"),
        timeout=2,
    )
    try:
        cookie, csrf, _body = _login(server.bound_port, "ada", _PASSWORD)
        otto_cookie, otto_csrf, _otto = _login(server.bound_port, "otto", _PASSWORD)
        holder: dict[str, object] = {}

        def chat() -> None:
            try:
                holder["result"] = client.chat("delete the secret", timeout=8)
            except Exception as exc:
                holder["error"] = exc

        worker = threading.Thread(target=chat)
        worker.start()
        approval_id = ""
        for _ in range(50):
            status, _headers, body = _request(
                server.bound_port,
                "GET",
                "/v1/approvals",
                cookie=cookie,
                csrf=csrf,
            )
            assert status == 200
            rows = body["approvals"]
            if rows:
                approval_id = str(rows[0]["id"])
                break
            time.sleep(0.05)
        assert approval_id
        assert ran == []
        denied, _headers, _body = _request(
            server.bound_port,
            "POST",
            f"/v1/approvals/{approval_id}",
            cookie=otto_cookie,
            csrf=otto_csrf,
            body_json={"decision": "allow_once", "id": approval_id},
        )
        assert denied == 403
        assert ran == []
        status, _headers, body = _request(
            server.bound_port,
            "POST",
            f"/v1/approvals/{approval_id}",
            cookie=cookie,
            csrf=csrf,
            body_json={"decision": "allow_once", "id": approval_id},
        )
        assert status == 200
        assert body["approval"]["state"] == "allow_once"
        missing, _headers, _body = _request(
            server.bound_port,
            "POST",
            f"/v1/approvals/{approval_id}",
            cookie=cookie,
            body_json={"decision": "deny", "id": approval_id},
        )
        assert missing == 403
        again, _headers, _body = _request(
            server.bound_port,
            "POST",
            f"/v1/approvals/{approval_id}",
            cookie=cookie,
            csrf=csrf,
            body_json={"decision": "deny", "id": approval_id},
        )
        assert again == 404
        worker.join(timeout=8)
        assert "error" not in holder
        assert ran == ["secret"]
        approvals = [item for item in collect_events(runtime.audit) if item["kind"] == "approval"]
        assert len(approvals) == 1
        assert approvals[0]["summary"] == "allow_once"
    finally:
        client.close()
        server.shutdown()
        host.close()


def test_chat_streams_agui_events_in_order(tmp_path: Path):
    ran: list[str] = []
    replies = [
        AssistantFinal(
            content="Looking.",
            tool_calls=(ToolCall(id="c1", name="echo", arguments={"text": "hi"}),),
        ),
        AssistantFinal(content=""),
    ]
    server, host = _open(tmp_path, replies=replies, registry=_echo_tool(ran))
    seen: list[str] = []
    client = GatewayClient.connect(
        Endpoint("127.0.0.1", server.bound_port, "test-token"),
        timeout=2,
    )
    try:

        def on_event(payload: dict[str, object]) -> None:
            agui = payload.get("agui")
            if isinstance(agui, dict) and isinstance(agui.get("type"), str):
                seen.append(str(agui["type"]))

        result = client.chat("hello", on_event=on_event, timeout=8)
        while True:
            try:
                event = client._events.get_nowait()
            except queue.Empty:
                break
            payload = event.get("payload")
            if isinstance(payload, dict):
                on_event(payload)
        wanted = [
            "RUN_STARTED",
            "TEXT_MESSAGE_CONTENT",
            "TOOL_CALL_START",
            "TOOL_CALL_ARGS",
            "TOOL_CALL_END",
            "TOOL_CALL_RESULT",
            "RUN_FINISHED",
        ]
        actual = [name for name in seen if name in set(wanted)]
        assert actual == wanted
        payload = result.get("payload")
        assert isinstance(payload, dict)
        assert "Looking." in str(payload.get("text"))
        assert ran == ["hi"]
    finally:
        client.close()
        server.shutdown()
        host.close()


def test_routing_host_forwards_events_while_chat_runs():
    class _Sup:
        def __init__(self) -> None:
            self.pending: list[dict[str, object]] = []
            self.lock = threading.Lock()

        def call(self, profile: str, method: str, params: object = None, timeout: float = 30):
            del params, timeout
            assert profile == "alpha"
            if method == "chat.events":
                with self.lock:
                    events = list(self.pending)
                    self.pending.clear()
                return {"events": events}
            if method == "chat":
                with self.lock:
                    self.pending.append({"kind": "text", "text": "Hi"})
                time.sleep(0.2)
                with self.lock:
                    self.pending.append({"kind": "text", "text": " there"})
                return {"sessionId": "s", "text": "Hi there", "error": None, "cancelled": False}
            raise AssertionError(method)

    host = RoutingHost(_Sup(), object(), object())  # type: ignore[arg-type]
    seen: list[str] = []
    result = host.chat(
        "hello",
        owner_profile="alpha",
        on_event=lambda event: seen.append(str(event["text"])),
    )
    assert result == TurnResult(session_id="s", text="Hi there", error=None, cancelled=False)
    assert seen == ["Hi", " there"]


class _Spy:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def list_memory(self, profile: str = "") -> list[dict[str, object]]:
        self.calls.append(("list_memory", profile))
        return [{"content": profile}]

    def list_skills(self, profile: str = "") -> list[dict[str, object]]:
        self.calls.append(("list_skills", profile))
        return []

    def list_routines(self, profile: str = "") -> list[dict[str, object]]:
        self.calls.append(("list_routines", profile))
        return []

    def status(self) -> dict[str, object]:
        return {
            "service": "praxis-primed",
            "version": "test",
            "model": "stub",
            "mode": "ask",
            "pendingApprovals": 0,
            "uptimeSeconds": 0,
        }

    def chat(self, text: str, **kwargs: object) -> TurnResult:
        del text, kwargs
        return TurnResult(session_id="s", text="ok", error=None, cancelled=False)

    def close(self) -> None:
        return None


def _open(
    tmp_path: Path,
    replies: list[AssistantFinal] | None = None,
    registry: ToolRegistry | None = None,
) -> tuple[GatewayServer, Host]:
    server, host, _runtime = _accounts(
        tmp_path,
        replies=replies,
        registry=registry,
        owner_only=True,
        with_account=False,
    )
    return server, host


def _accounts(
    tmp_path: Path,
    *,
    replies: list[AssistantFinal] | None = None,
    registry: ToolRegistry | None = None,
    owner_only: bool = False,
    with_account: bool = True,
    profile: str = "",
) -> tuple[GatewayServer, Host, object]:
    del owner_only
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    if profile:
        create_profile(data, profile)
    store = None
    if with_account:
        store = AccountStore(data / "accounts.db")
        ada = store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
        if profile:
            store.set_membership(ada.id, profile, "owner")
    runtime = build_runtime(
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=data / "prime.db",
        cwd=tmp_path,
        providers={"ollama": ScriptedProvider(replies or [AssistantFinal(content="ok")])},
        registry=registry,
        profile=profile or None,
    )
    queue = ApprovalQueue()
    queue.profile_id = runtime.profile_id
    host = Host(runtime, queue)
    logger = JsonLogger(tmp_path / "daemon.log")
    server = GatewayServer(
        host="127.0.0.1",
        port=0,
        token="test-token",
        agent=host,
        approvals=queue,
        logger=logger,
        accounts=store,
        audit=runtime.audit,
        data_root=data,
    )
    server.start()
    return server, host, runtime


def _echo_tool(ran: list[str]) -> ToolRegistry:
    def execute(arguments, context):
        del context
        ran.append(str(arguments.get("text")))
        return "echoed"

    registry = ToolRegistry()
    registry.register(
        Tool(
            name="echo",
            description="Echo text.",
            parameters={
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
            risk=Risk.READ,
            execute=execute,
        )
    )
    return registry


def _delete_tool(ran: list[str]) -> ToolRegistry:
    def execute(arguments, context):
        del context
        ran.append(str(arguments.get("path")))
        return "deleted"

    registry = ToolRegistry()
    registry.register(
        Tool(
            name="delete_file",
            description="Delete a file.",
            parameters={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            risk=Risk.DESTRUCTIVE,
            execute=execute,
        )
    )
    return registry


def _raw(
    port: int,
    method: str,
    path: str,
    *,
    payload: bytes = b"",
    extra: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], dict[str, object]]:
    status, headers, raw = _raw_bytes(port, method, path, payload=payload, extra=extra)
    parsed = json.loads(raw.decode("utf-8"))
    assert isinstance(parsed, dict)
    return status, headers, parsed


def _raw_bytes(
    port: int,
    method: str,
    path: str,
    *,
    payload: bytes = b"",
    extra: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    lines = [f"{method} {path} HTTP/1.1", "Host: 127.0.0.1", "Connection: close"]
    for name, value in (extra or {}).items():
        lines.append(f"{name}: {value}")
    if payload and not any(line.lower().startswith("content-length:") for line in lines):
        lines.append(f"Content-Length: {len(payload)}")
    raw_head = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        sock.sendall(raw_head + payload)
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    finally:
        sock.close()
    head, _, body = data.partition(b"\r\n\r\n")
    rows = head.decode("iso-8859-1").split("\r\n")
    status = int(rows[0].split(" ", 2)[1])
    headers: dict[str, str] = {}
    for line in rows[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return status, headers, body
