"""Chat reaches the provider saved by the wizard, without a process restart."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from tests.test_onboarding_api import _call, _gateway, _running

from praxis_prime.accounts.db import AccountStore
from praxis_prime.approvals.queue import ApprovalQueue
from praxis_prime.gateway.authz import Principal
from praxis_prime.gateway.onboarding import onboarding_payload
from praxis_prime.gateway.server import GatewayServer
from praxis_prime.host import Host
from praxis_prime.onboarding.record import read_record, write_record
from praxis_prime.onboarding.token import ensure_first_run_token
from praxis_prime.router.types import ChatRequest, InferenceNotConfigured, canonical_spec
from praxis_prime.runtime import build_runtime
from praxis_prime.supervisor.ipc import IpcError

_PASSWORD = "correct-horse"
_MODEL = "wizard-model"
_PROVIDERS = (
    ("ollama", "local", ""),
    ("llamacpp", "local", ""),
    ("vllm", "local", ""),
    ("lmstudio", "local", ""),
    ("openai-compatible", "local", ""),
    ("openai-compatible", "cloud", "sk-hosted"),
)


class _ProviderServer(ThreadingHTTPServer):
    def __init__(self) -> None:
        self.hits: list[dict[str, object]] = []
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), _ProviderHandler)


class _ProviderHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        del fmt, args

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/api/tags":
            body = {"models": [{"name": _MODEL, "context_length": 32768}]}
        else:
            body = {"data": [{"id": _MODEL, "max_model_len": 32768}]}
        self._send(json.dumps(body).encode(), "application/json")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        path = self.path.split("?", 1)[0]
        hit = {
            "path": path,
            "model": str(payload.get("model", "")),
            "authorization": self.headers.get("Authorization", ""),
            "stream": payload.get("stream") is True,
        }
        server = self.server
        assert isinstance(server, _ProviderServer)
        with server.lock:
            server.hits.append(hit)
        if path == "/api/chat":
            line = json.dumps({"message": {"content": "from-provider"}, "done": True})
            self._send((line + "\n").encode(), "application/x-ndjson")
            return
        if payload.get("stream") is True:
            text = (
                'data: {"choices":[{"delta":{"content":"from-provider"}}]}\n\n'
                "data: [DONE]\n\n"
            )
            self._send(text.encode(), "text/event-stream")
            return
        if "tools" in payload:
            message: dict[str, object] = {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "c1",
                        "type": "function",
                        "function": {"name": "ping", "arguments": "{}"},
                    }
                ],
            }
        else:
            message = {"role": "assistant", "content": "ready"}
        self._send(json.dumps({"choices": [{"message": message}]}).encode(), "application/json")

    def _send(self, body: bytes, content_type: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextmanager
def _provider() -> Iterator[_ProviderServer]:
    server = _ProviderServer()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _post(
    gateway: GatewayServer,
    path: str,
    payload: dict[str, object],
    *,
    token: str = "",
    bearer: str = "",
) -> tuple[int, dict[str, Any]]:
    headers = {"host": "127.0.0.1", "content-type": "application/json"}
    if token:
        headers["x-praxis-setup-token"] = token
    if bearer:
        headers["authorization"] = f"Bearer {bearer}"
    status, body = gateway._http(
        "POST", path, headers, json.dumps(payload).encode(), [], "127.0.0.1"
    )
    assert isinstance(body, dict)
    return status, body


def _chat_hits(provider: _ProviderServer) -> list[dict[str, object]]:
    with provider.lock:
        return [dict(hit) for hit in provider.hits if hit["stream"] or hit["path"] == "/api/chat"]


def _expect_chat(host: Host, provider: _ProviderServer, *, api_key: str, provider_id: str) -> None:
    before = len(_chat_hits(provider))
    result = host.chat("ping")
    assert result.error is None, result.error
    assert "from-provider" in result.text
    fresh = _chat_hits(provider)[before:]
    assert fresh, "chat did not reach the configured provider"
    hit = fresh[-1]
    assert hit["model"] == _MODEL
    if provider_id == "ollama":
        assert hit["path"] == "/api/chat"
    else:
        assert hit["path"] == "/v1/chat/completions"
    if api_key:
        assert hit["authorization"] == f"Bearer {api_key}"
    else:
        assert hit["authorization"] == ""


def _alias_record(config: Path, provider: str) -> None:
    record = read_record(config)
    alias = f"{provider}:{_MODEL}"
    record["spec"] = alias
    roles = record.get("roles")
    if isinstance(roles, dict):
        for role in roles.values():
            if isinstance(role, dict) and "spec" in role:
                role["spec"] = alias
    write_record(config, record)


@pytest.mark.parametrize(("provider", "lane", "api_key"), _PROVIDERS)
def test_chat_reaches_the_saved_provider_before_and_after_restart(
    tmp_path: Path, provider: str, lane: str, api_key: str
) -> None:
    config = tmp_path / "config"
    data = tmp_path / "data"
    config.mkdir()
    data.mkdir()
    store = AccountStore(tmp_path / "accounts.db")
    with _provider() as upstream:
        base = f"http://127.0.0.1:{upstream.server_address[1]}"
        runtime = build_runtime(
            env={},
            config_path=config / "config.toml",
            data_path=data / "prime.db",
            cwd=tmp_path,
        )
        queue = ApprovalQueue()
        host = Host(runtime, queue)
        gateway = GatewayServer(
            host="127.0.0.1",
            port=0,
            token="loopback-bearer",
            agent=host,
            approvals=queue,
            accounts=store,
            audit=runtime.audit,
            data_root=data,
            config_dir=config,
            bearer_enabled=True,
        )
        gateway.onboarding_env = {}  # type: ignore[attr-defined]
        try:
            token = ensure_first_run_token(config)
            status, created = _post(
                gateway,
                "/v1/onboarding/owner",
                {"username": "ada", "password": _PASSWORD, "displayName": "Ada"},
                token=token,
            )
            assert status == 201, created
            assert created["restartRequired"] is False
            saved = {
                "lane": lane,
                "provider": provider,
                "model": _MODEL,
                "baseUrl": base,
            }
            if api_key:
                saved["apiKey"] = api_key
            status, body = _post(gateway, "/v1/onboarding/save", saved, bearer=gateway.token)
            assert status == 200, body
            assert body["inferenceReady"] is True
            assert body["restartRequired"] is False
            assert body["spec"] == f"{provider}:{_MODEL}"
            record = read_record(config)
            assert record["spec"] == canonical_spec(f"{provider}:{_MODEL}")
            assert record["provider"] == provider
            _expect_chat(host, upstream, api_key=api_key, provider_id=provider)
            _alias_record(config, provider)
        finally:
            gateway.shutdown()
            runtime.close()
        restarted = build_runtime(
            env={},
            config_path=config / "config.toml",
            data_path=data / "prime.db",
            cwd=tmp_path,
        )
        try:
            ready = canonical_spec(restarted.settings.model_spec)
            assert ready in restarted.settings.verified_specs
            assert restarted.settings.provider_ready() is True
            again = Host(restarted, ApprovalQueue())
            _expect_chat(again, upstream, api_key=api_key, provider_id=provider)
        finally:
            restarted.close()
    store.close()


def test_websocket_save_reloads_the_router(tmp_path: Path) -> None:
    config = tmp_path / "config"
    data = tmp_path / "data"
    config.mkdir()
    data.mkdir()
    store = AccountStore(tmp_path / "accounts.db")
    with _provider() as upstream:
        base = f"http://127.0.0.1:{upstream.server_address[1]}"
        runtime = build_runtime(
            env={},
            config_path=config / "config.toml",
            data_path=data / "prime.db",
            cwd=tmp_path,
        )
        queue = ApprovalQueue()
        host = Host(runtime, queue)
        gateway = GatewayServer(
            host="127.0.0.1",
            port=0,
            token="loopback-bearer",
            agent=host,
            approvals=queue,
            accounts=store,
            audit=runtime.audit,
            data_root=data,
            config_dir=config,
            bearer_enabled=True,
        )
        gateway.onboarding_env = {}  # type: ignore[attr-defined]
        try:
            token = ensure_first_run_token(config)
            status, created = _post(
                gateway,
                "/v1/onboarding/owner",
                {"username": "ada", "password": _PASSWORD, "displayName": "Ada"},
                token=token,
            )
            assert status == 201, created
            owner = store.owner()
            assert owner is not None
            principal = Principal(
                kind="session",
                account_id=owner.id,
                username=owner.username,
                role=owner.role,
            )
            saved = onboarding_payload(
                gateway,
                "onboarding.save",
                {
                    "lane": "local",
                    "provider": "llamacpp",
                    "model": _MODEL,
                    "baseUrl": base,
                },
                principal,
            )
            assert saved["ok"] is True
            assert saved["restartRequired"] is False
            _expect_chat(host, upstream, api_key="", provider_id="llamacpp")
        finally:
            gateway.shutdown()
            runtime.close()
    store.close()


def test_a_failed_router_reload_asks_for_a_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk")

    monkeypatch.setattr("praxis_prime.runtime.reload_serving_router", boom)
    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server, runtime = _running(tmp_path, store, config)
    try:
        token = ensure_first_run_token(config)
        status, body, _extras = _call(
            server,
            "POST",
            "/v1/onboarding/save",
            json.dumps(
                {
                    "lane": "local",
                    "provider": "llamacpp",
                    "model": "local-model",
                    "baseUrl": "http://127.0.0.1:9",
                }
            ).encode(),
            token=token,
        )
        assert status == 200, body
        assert body["restartRequired"] is True
        with pytest.raises(InferenceNotConfigured, match="No model provider"):
            list(runtime.router.iter_stream(ChatRequest(model="local-model", messages=())))
    finally:
        runtime.close()
        store.close()


def test_multi_profile_save_reloads_running_workers(tmp_path: Path) -> None:
    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    server.multi_profile = True

    class _Supervisor:
        def __init__(self) -> None:
            self.names: list[str] = []
            self.calls: list[tuple[str, str, float]] = []
            self.fail = False

        def running(self) -> list[str]:
            return list(self.names)

        def call(
            self,
            profile: str,
            method: str,
            params: dict[str, object] | None = None,
            *,
            timeout: float = 30,
        ) -> dict[str, object]:
            del params
            self.calls.append((profile, method, timeout))
            if self.fail:
                raise IpcError("router reload failed")
            return {"ok": True}

    supervisor = _Supervisor()
    server.supervisor = supervisor  # type: ignore[attr-defined]
    token = ensure_first_run_token(config)
    payload = {
        "lane": "local",
        "provider": "llamacpp",
        "model": "local-model",
        "baseUrl": "http://127.0.0.1:9",
    }
    status, body, _extras = _call(
        server, "POST", "/v1/onboarding/save", json.dumps(payload).encode(), token=token
    )
    assert status == 200, body
    assert body["restartRequired"] is False
    assert supervisor.calls == []
    supervisor.names = ["default"]
    payload["model"] = "other-model"
    payload["replace"] = True
    status, body, _extras = _call(
        server, "POST", "/v1/onboarding/save", json.dumps(payload).encode(), token=token
    )
    assert status == 200, body
    assert body["restartRequired"] is False
    assert supervisor.calls == [("default", "runtime.reload", 10)]
    supervisor.fail = True
    payload["model"] = "third-model"
    status, body, _extras = _call(
        server, "POST", "/v1/onboarding/save", json.dumps(payload).encode(), token=token
    )
    assert status == 200, body
    assert body["restartRequired"] is True
    store.close()
