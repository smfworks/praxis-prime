"""Loopback gateway: auth, roles, and a destructive tool that waits for approval."""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from pathlib import Path

from tests.fakes import ScriptedProvider

from praxis_prime.approvals.queue import ApprovalQueue
from praxis_prime.gateway.client import Endpoint, GatewayClient, GatewayError
from praxis_prime.gateway.discover import discover, log_path, write_discovery
from praxis_prime.gateway.protocol import parse_listen, request_id_var
from praxis_prime.gateway.server import GatewayServer
from praxis_prime.host import Host
from praxis_prime.observe import JsonLogger
from praxis_prime.router.types import AssistantFinal, ToolCall
from praxis_prime.runtime import build_runtime
from praxis_prime.tools.registry import Risk, Tool, ToolRegistry


def test_parse_listen_stays_on_loopback():
    assert parse_listen("localhost:18790") == ("127.0.0.1", 18790)
    assert parse_listen("127.0.0.1:0") == ("127.0.0.1", 0)
    for value in ("0.0.0.0:18790", "[::]:18790", "192.168.1.2:18790"):
        try:
            parse_listen(value)
        except ValueError as exc:
            assert "loopback" in str(exc)
        else:
            raise AssertionError(f"{value} should be refused")


def test_health_is_open_and_other_routes_need_the_token(tmp_path: Path):
    server, host, _queue, _provider = _server(tmp_path, [AssistantFinal(content="ok")])
    try:
        status, body = _http(server.bound_port, "GET", "/health")
        assert status == 200
        assert body["ok"] is True
        assert body["service"] == "praxis-primed"

        status, body = _http(server.bound_port, "GET", "/status")
        assert status == 401
        assert body["ok"] is False

        status, _body = _http(server.bound_port, "GET", "/status", token="")
        assert status == 401
        status, _body = _http(server.bound_port, "GET", "/status", token="wrong-token")
        assert status == 401

        status, body = _http(server.bound_port, "GET", "/status", token="test-token")
        assert status == 200
        assert body["status"]["listen"].startswith("127.0.0.1:")
        status, body = _http(server.bound_port, "GET", "/v1/approvals", token="test-token")
        assert status == 200
        assert body["approvals"] == []
    finally:
        server.shutdown()
        host.close()
    log = (tmp_path / "daemon.log").read_text(encoding="utf-8")
    assert "test-token" not in log
    assert "http_unauthorized" in log


def test_websocket_rejects_a_missing_token_and_a_channel_decision(tmp_path: Path):
    server, host, _queue, _provider = _server(tmp_path, [AssistantFinal(content="ok")])
    try:
        bare = Endpoint("127.0.0.1", server.bound_port, "")
        try:
            GatewayClient.connect(bare, timeout=2)
            raise AssertionError("empty token must not connect")
        except GatewayError as exc:
            assert "token" in str(exc).lower() or "rejected" in str(exc).lower()

        bad = _ws_status(server.bound_port, "not-the-token")
        assert bad == 401

        channel = GatewayClient.connect(_endpoint(server), timeout=2, role="channel")
        try:
            try:
                channel.decide("ap_00000000", "deny")
                raise AssertionError("a channel must not decide approvals")
            except GatewayError as exc:
                assert "cannot" in str(exc)
        finally:
            channel.close()

        operator = GatewayClient.connect(_endpoint(server), timeout=2)
        try:
            body = operator.status()
            assert body["service"] == "praxis-primed"
        finally:
            operator.close()
    finally:
        server.shutdown()
        host.close()


def test_destructive_tool_does_not_run_until_the_operator_approves(tmp_path: Path):
    ran: list[str] = []
    registry = _delete_tool(ran)
    replies = [
        _tool_reply("delete_file", {"path": "secret"}),
        AssistantFinal(content="deleted"),
    ]
    server, host, _queue, _provider = _server(tmp_path, replies, registry=registry)
    client = GatewayClient.connect(_endpoint(server), timeout=2)
    try:
        seen = threading.Event()

        def decider(item: dict[str, object]) -> str:
            assert ran == []
            assert item["tool"] == "delete_file"
            assert item["risk"] == "DESTRUCTIVE"
            seen.set()
            return "allow_once"

        result = client.chat("delete the secret", decider=decider, timeout=8)
    finally:
        client.close()
        server.shutdown()
        host.close()
    assert seen.is_set()
    assert ran == ["secret"]
    payload = result.get("payload")
    assert isinstance(payload, dict)
    assert payload.get("text") == "deleted"


def test_destructive_tool_does_not_run_when_the_approval_times_out(tmp_path: Path):
    ran: list[str] = []
    registry = _delete_tool(ran)
    replies = [
        _tool_reply("delete_file", {"path": "secret"}),
        AssistantFinal(content="stopped"),
    ]
    server, host, _queue, _provider = _server(tmp_path, replies, registry=registry, ttl=0.3)
    client = GatewayClient.connect(_endpoint(server), timeout=2)
    try:
        result = client.chat("delete the secret", timeout=5)
    finally:
        client.close()
        server.shutdown()
        host.close()
    assert ran == []
    payload = result.get("payload")
    assert isinstance(payload, dict)
    assert payload.get("error") is None


def test_daemon_serve_shuts_down_and_does_not_log_the_token(tmp_path, monkeypatch):
    from praxis_prime.daemon import serve

    _isolate(tmp_path, monkeypatch)
    monkeypatch.setenv("PRAXIS_PRIME_APPROVAL_TTL", "30")
    ran: list[str] = []
    provider = ScriptedProvider(
        [
            _tool_reply("delete_file", {"path": "secret"}),
            AssistantFinal(content="should-not-finish-as-deleted"),
        ]
    )
    runtime_box: dict[str, object] = {}

    def builder(**kwargs):
        del kwargs
        runtime = build_runtime(
            model="ollama:qwen3:32b",
            env={},
            config_path=tmp_path / "missing.toml",
            data_path=tmp_path / "prime.db",
            cwd=tmp_path,
            providers={"ollama": provider},
            registry=_delete_tool(ran),
        )
        runtime_box["runtime"] = runtime
        return runtime

    monkeypatch.setattr("praxis_prime.daemon.build_runtime", builder)
    stop = threading.Event()
    outcome: dict[str, int] = {}

    def run() -> None:
        outcome["code"] = serve(stop=stop, listen="127.0.0.1:0")

    thread = threading.Thread(target=run)
    thread.start()
    endpoint = _wait_discover()
    assert endpoint is not None
    info_path = Path(os.environ["XDG_RUNTIME_DIR"]) / "praxis-prime" / "gateway.json"
    published = info_path.read_text(encoding="utf-8")
    assert endpoint.token not in published
    token_path = Path(os.environ["XDG_RUNTIME_DIR"]) / "praxis-prime" / "gateway.token"
    assert (token_path.stat().st_mode & 0o777) == 0o600

    client = GatewayClient.connect(endpoint, timeout=2)
    watcher = GatewayClient.connect(endpoint, timeout=2)
    chat_done = threading.Event()

    def chat() -> None:
        try:
            client.chat("delete the secret", timeout=8)
        except GatewayError:
            return
        finally:
            chat_done.set()

    worker = threading.Thread(target=chat)
    worker.start()
    pending = False
    for _ in range(50):
        if watcher.list_approvals():
            pending = True
            break
        time.sleep(0.05)
    assert pending
    assert ran == []
    stop.set()
    thread.join(timeout=8)
    worker.join(timeout=8)
    watcher.close()
    client.close()
    assert not thread.is_alive()
    assert outcome["code"] == 0
    assert ran == []
    assert chat_done.is_set()
    log = log_path().read_text(encoding="utf-8")
    assert endpoint.token not in log
    assert "shutdown" in log
    assert not info_path.exists()


def test_ask_attaches_and_local_stays_in_process(tmp_path, monkeypatch, capsys):
    from praxis_prime.cli import main

    _isolate(tmp_path, monkeypatch)
    server, host, _queue, _provider = _server(
        tmp_path / "gw",
        [AssistantFinal(content="from-daemon")],
    )
    try:
        token_path = Path(os.environ["XDG_RUNTIME_DIR"]) / "praxis-prime" / "gateway.token"
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text("test-token\n", encoding="utf-8")
        os.chmod(token_path, 0o600)
        write_discovery(
            env=os.environ,
            pid=os.getpid(),
            port=server.bound_port,
            socket_path=None,
            version="test",
            started_at="2026-09-30T00:00:00+00:00",
        )
        assert main(["ask", "say", "hi"]) == 0
        captured = capsys.readouterr()
        assert "from-daemon" in captured.out
        assert "attached to praxis-primed" in captured.err

        local_runtime = build_runtime(
            model="ollama:qwen3:32b",
            env={},
            config_path=tmp_path / "missing.toml",
            data_path=tmp_path / "local.db",
            cwd=tmp_path,
            providers={"ollama": ScriptedProvider([AssistantFinal(content="from-local")])},
        )

        def builder(**kwargs):
            del kwargs
            return local_runtime

        monkeypatch.setattr("praxis_prime.runtime.build_runtime", builder)
        assert main(["ask", "--local", "say", "hi"]) == 0
        captured = capsys.readouterr()
        assert "from-local" in captured.out
        assert "attached" not in captured.err
    finally:
        server.shutdown()
        host.close()


def test_cli_approvals_deny_a_pending_action(tmp_path, monkeypatch, capsys):
    from praxis_prime.approvals.gate import ApprovalDecision, ApprovalRequest
    from praxis_prime.cli import main

    _isolate(tmp_path, monkeypatch)
    server, host, queue, _provider = _server(tmp_path, [AssistantFinal(content="ok")])
    token_path = Path(os.environ["XDG_RUNTIME_DIR"]) / "praxis-prime" / "gateway.token"
    token_path.parent.mkdir(parents=True, exist_ok=True)
    token_path.write_text("test-token\n", encoding="utf-8")
    os.chmod(token_path, 0o600)
    write_discovery(
        env=os.environ,
        pid=os.getpid(),
        port=server.bound_port,
        socket_path=None,
        version="test",
        started_at="2026-09-30T00:00:00+00:00",
    )
    request = ApprovalRequest(
        tool="delete_file",
        risk=Risk.DESTRUCTIVE,
        reason="delete or overwrite",
        summary="path=secret",
        arguments={"path": "secret"},
        grant_key="delete_file:secret",
        sandboxed=False,
    )
    holder: dict[str, ApprovalDecision] = {}

    def block() -> None:
        holder["decision"] = queue.authorize(request)

    worker = threading.Thread(target=block)
    worker.start()
    approval_id = ""
    try:
        for _ in range(50):
            pending = queue.list_pending()
            if pending:
                approval_id = str(pending[0]["id"])
                break
            time.sleep(0.02)
        assert approval_id
        assert main(["approvals", "list"]) == 0
        listed = capsys.readouterr().out
        assert "Approval needed" in listed
        assert approval_id in listed
        assert "A chat message cannot approve this." in listed
        assert main(["approvals", "deny", approval_id]) == 0
        assert "deny" in capsys.readouterr().out
    finally:
        worker.join(timeout=3)
        server.shutdown()
        host.close()
    assert holder["decision"] == ApprovalDecision.DENY


def test_daemon_status_when_nothing_is_running(tmp_path, monkeypatch, capsys):
    from praxis_prime.cli import main

    _isolate(tmp_path, monkeypatch)
    assert main(["daemon", "status"]) == 1
    assert "not running" in capsys.readouterr().out


def _server(
    tmp_path: Path,
    replies: list[AssistantFinal],
    *,
    registry: ToolRegistry | None = None,
    ttl: float = 30,
) -> tuple[GatewayServer, Host, ApprovalQueue, ScriptedProvider]:
    provider = ScriptedProvider(replies)
    runtime = build_runtime(
        model="ollama:qwen3:32b",
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=tmp_path / "prime.db",
        cwd=tmp_path,
        providers={"ollama": provider},
        registry=registry,
    )
    queue = ApprovalQueue(ttl=ttl)
    host = Host(runtime, queue)
    logger = JsonLogger(tmp_path / "daemon.log")
    logger.add_secret("test-token")
    server = GatewayServer(
        host="127.0.0.1",
        port=0,
        token="test-token",
        agent=host,
        approvals=queue,
        logger=logger,
    )

    def on_pending(item: dict[str, object]) -> None:
        server.publish(
            {
                "type": "event",
                "id": request_id_var.get(),
                "payload": {"kind": "approval", "approval": item},
            }
        )

    queue.on_pending = on_pending
    server.start()
    return server, host, queue, provider


def _endpoint(server: GatewayServer) -> Endpoint:
    return Endpoint("127.0.0.1", server.bound_port, "test-token")


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


def _tool_reply(name: str, arguments: dict[str, object]) -> AssistantFinal:
    return AssistantFinal(
        content="",
        tool_calls=(ToolCall(id="c1", name=name, arguments=arguments),),
    )


def _http(
    port: int,
    method: str,
    path: str,
    *,
    token: str | None = None,
    body: dict[str, object] | None = None,
) -> tuple[int, dict[str, object]]:
    payload = b"" if body is None else json.dumps(body).encode("utf-8")
    headers = [
        f"{method} {path} HTTP/1.1",
        "Host: 127.0.0.1",
        "Connection: close",
    ]
    if token is not None:
        headers.append(f"Authorization: Bearer {token}")
    if payload:
        headers.append("Content-Type: application/json")
        headers.append(f"Content-Length: {len(payload)}")
    raw_head = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii")
    with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
        sock.settimeout(2)
        sock.sendall(raw_head + payload)
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    head, _, raw = data.partition(b"\r\n\r\n")
    status = int(head.split()[1])
    parsed = json.loads(raw.decode("utf-8"))
    assert isinstance(parsed, dict)
    return status, parsed


def _ws_status(port: int, token: str) -> int:
    key = "dGhlIHNhbXBsZSBub25jZQ=="
    request = (
        "GET /ws HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Authorization: Bearer {token}\r\n"
        "\r\n"
    )
    with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
        sock.settimeout(2)
        sock.sendall(request.encode("ascii"))
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    return int(data.split(b"\r\n", 1)[0].split()[1])


def _isolate(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("PRAXIS_PRIME_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("PRAXIS_PRIME_SECRETS_FILE", raising=False)
    monkeypatch.delenv("PRAXIS_PRIME_GATEWAY_LISTEN", raising=False)


def _wait_discover():
    for _ in range(50):
        endpoint = discover(timeout=0.2)
        if endpoint is not None:
            return endpoint
        time.sleep(0.05)
    return None
