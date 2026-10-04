"""Gateway first-run window: token, loopback peer, and a closed setup after an owner."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

import pytest

from praxis_prime.accounts.db import AccountStore
from praxis_prime.gateway.server import GatewayServer
from praxis_prime.onboarding.probe import FetchResult
from praxis_prime.onboarding.token import ensure_first_run_token, read_first_run_token

_PASSWORD = "correct-horse"


def _fetch(method: str, url: str, **kwargs: object) -> FetchResult:
    del method
    if url.endswith("/v1/models") or url.endswith("/api/tags"):
        body = {"data": [{"id": "local-model", "max_model_len": 32768}]}
        return FetchResult(200, json.dumps(body).encode("utf-8"))
    raw = kwargs.get("body") or b"{}"
    payload = json.loads(raw if isinstance(raw, (bytes, str)) else b"{}")
    tools = isinstance(payload, dict) and "tools" in payload
    message: dict[str, object]
    if tools:
        message = {"role": "assistant", "content": "", "tool_calls": [{"id": "c1"}]}
    else:
        message = {"role": "assistant", "content": "ready"}
    return FetchResult(200, json.dumps({"choices": [{"message": message}]}).encode("utf-8"))


def _gateway(
    tmp_path: Path,
    store: AccountStore | None,
    config: Path,
    *,
    host: str = "127.0.0.1",
) -> GatewayServer:
    config.mkdir(parents=True, exist_ok=True)
    server = GatewayServer(
        host=host,
        port=0,
        token="loopback-bearer",
        agent=None,  # type: ignore[arg-type]
        approvals=None,  # type: ignore[arg-type]
        accounts=store,
        config_dir=config,
        data_root=tmp_path / "data",
        bearer_enabled=True,
    )
    server.onboarding_fetcher = _fetch  # type: ignore[attr-defined]
    server.onboarding_env = {}  # type: ignore[attr-defined]
    server.onboarding_runner = lambda _argv: ""  # type: ignore[attr-defined]
    return server


def _call(
    server: GatewayServer,
    method: str,
    path: str,
    body: bytes = b"",
    *,
    token: str = "",
    peer: str = "127.0.0.1",
    host: str = "127.0.0.1",
    cookie: str = "",
    csrf: str = "",
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any], list[tuple[str, str]]]:
    headers = {"host": host, "content-type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    if token:
        headers["x-praxis-setup-token"] = token
    if cookie:
        headers["cookie"] = f"pp_session={cookie}"
    if csrf:
        headers["x-csrf-token"] = csrf
    extras: list[tuple[str, str]] = []
    status, payload = server._http(method, path, headers, body, extras, peer)
    return status, payload, extras


def _owner(name: str) -> bytes:
    return json.dumps({"username": name, "password": _PASSWORD, "displayName": name}).encode()


def _session(extras: list[tuple[str, str]]) -> str:
    for key, value in extras:
        if key == "Set-Cookie" and value.startswith("pp_session="):
            return value.split(";", 1)[0].split("=", 1)[1]
    return ""


def test_status_without_a_token_is_only_the_boolean(tmp_path: Path):
    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    ensure_first_run_token(config)
    status, body, _extras = _call(server, "GET", "/v1/onboarding/status")
    assert status == 200
    assert body == {"setupRequired": True}
    store.close()


def test_missing_token_is_not_rate_limited(tmp_path: Path):
    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    ensure_first_run_token(config)
    for _ in range(6):
        status, body, _extras = _call(server, "POST", "/v1/onboarding/owner", _owner("ada"))
        assert status == 401
        assert body["error"]["code"] == "unauthorized"
    assert store.count_accounts() == 0
    store.close()


def test_wrong_token_is_rate_limited_and_a_correct_token_is_not(tmp_path: Path):
    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    token = ensure_first_run_token(config)
    codes: list[int] = []
    for _ in range(6):
        status, _body, _extras = _call(
            server, "POST", "/v1/onboarding/owner", _owner("ada"), token="wrong-token"
        )
        codes.append(status)
    assert codes == [401, 401, 401, 401, 429, 429]
    status, body, _extras = _call(
        server, "POST", "/v1/onboarding/owner", _owner("ada"), token=token
    )
    assert status == 201
    assert body["account"]["username"] == "ada"
    assert store.count_accounts() == 1
    store.close()


def test_token_in_the_query_string_is_ignored(tmp_path: Path):
    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    token = ensure_first_run_token(config)
    for _ in range(5):
        status, _body, _extras = _call(
            server,
            "POST",
            f"/v1/onboarding/owner?setup={token}",
            _owner("ada"),
        )
        assert status == 401
    assert store.count_accounts() == 0
    status, body, _extras = _call(
        server, "POST", "/v1/onboarding/owner", _owner("ada"), token=token
    )
    assert status == 201
    assert body["account"]["username"] == "ada"
    assert _PASSWORD not in json.dumps(body)
    store.close()


def test_non_loopback_peer_and_host_are_refused(tmp_path: Path):
    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    token = ensure_first_run_token(config)
    status, body, _extras = _call(
        server,
        "POST",
        "/v1/onboarding/owner",
        _owner("ada"),
        token=token,
        peer="192.0.2.10",
    )
    assert status == 403
    assert "praxis-prime setup" in body["error"]["message"]
    status, _body, _extras = _call(
        server,
        "GET",
        "/v1/onboarding/status",
        token=token,
        host="evil.example",
    )
    assert status == 403
    server.host = "0.0.0.0"
    status, _body, _extras = _call(
        server, "POST", "/v1/onboarding/owner", _owner("ada"), token=token
    )
    assert status == 403
    assert store.count_accounts() == 0
    store.close()


def test_ipv6_loopback_host_with_a_port_is_accepted(tmp_path: Path):
    from praxis_prime.gateway.guard import host_origin_denial

    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    token = ensure_first_run_token(config)
    status, body, _extras = _call(
        server,
        "GET",
        "/v1/onboarding/status",
        token=token,
        peer="::1",
        host="[::1]:18790",
    )
    assert status == 200
    assert body["missing"][0]["id"] == "no owner account"
    assert host_origin_denial({"host": "[::1]:18790"}, bound_port=18790) is None
    assert host_origin_denial({"host": "[::1]"}, bound_port=18790) is None
    assert (
        host_origin_denial(
            {"host": "[::1]:18790", "origin": "http://[::1]:18790"},
            bound_port=18790,
        )
        is None
    )
    mapped = {"host": "[::ffff:127.0.0.1]:18790", "origin": "http://[::ffff:127.0.0.1]:18790"}
    assert host_origin_denial(mapped, bound_port=18790) is None
    assert host_origin_denial({"host": "[::1]:9"}, bound_port=18790) is not None
    assert host_origin_denial({"host": "[fe80::1]:18790"}, bound_port=18790) is not None
    store.close()


def test_forwarded_for_does_not_change_the_loopback_check(tmp_path: Path):
    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    token = ensure_first_run_token(config)
    status, body, _extras = _call(
        server,
        "GET",
        "/v1/onboarding/status",
        token=token,
        peer="192.0.2.10",
        extra_headers={"x-forwarded-for": "127.0.0.1"},
    )
    assert status == 403
    assert "praxis-prime setup" in body["error"]["message"]
    status, allowed, _extras = _call(
        server,
        "GET",
        "/v1/onboarding/status",
        token=token,
        peer="127.0.0.1",
        extra_headers={"x-forwarded-for": "192.0.2.10"},
    )
    assert status == 200
    assert allowed["missing"][0]["id"] == "no owner account"
    store.close()


def test_concurrent_owner_creation_keeps_one_and_burns_the_token(tmp_path: Path):
    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    token = ensure_first_run_token(config)
    results: list[int] = []
    barrier = threading.Barrier(2)

    def create(name: str) -> None:
        barrier.wait()
        status, _body, _extras = _call(
            server, "POST", "/v1/onboarding/owner", _owner(name), token=token
        )
        results.append(status)

    threads = [
        threading.Thread(target=create, args=("ada",)),
        threading.Thread(target=create, args=("bea",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(results) == [201, 409]
    assert store.count_accounts() == 1
    assert read_first_run_token(config) == ""
    status, body, _extras = _call(server, "POST", "/v1/onboarding/save", b"{}", token=token)
    assert status == 403
    assert body["error"]["code"] == "forbidden"
    status, quiet, _extras = _call(server, "GET", "/v1/onboarding/status")
    assert quiet == {"setupRequired": False}
    store.close()


def test_save_during_first_run_stores_the_key_outside_config(tmp_path: Path):
    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    token = ensure_first_run_token(config)
    payload = {
        "lane": "local",
        "provider": "llamacpp",
        "model": "local-model",
        "baseUrl": "http://127.0.0.1:9",
        "apiKey": "sk-local",
    }
    status, body, _extras = _call(
        server,
        "POST",
        "/v1/onboarding/save",
        json.dumps(payload).encode(),
        token=token,
        host="127.0.0.1:18790",
    )
    assert status == 200
    assert body["inferenceReady"] is True
    rendered = json.dumps(body) + (config / "config.toml").read_text(encoding="utf-8")
    assert "sk-local" not in rendered
    assert "sk-local" in (config / "secrets.env").read_text(encoding="utf-8")
    store.close()


def test_after_an_owner_mutations_require_an_admin(tmp_path: Path):
    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    token = ensure_first_run_token(config)
    status, body, extras = _call(server, "POST", "/v1/onboarding/owner", _owner("ada"), token=token)
    assert status == 201
    cookie = _session(extras)
    csrf = str(body["csrfToken"])
    status, found, _extras = _call(
        server, "POST", "/v1/onboarding/detect", b"{}", cookie=cookie, csrf=csrf
    )
    assert status == 200
    assert "servers" in found
    dumped = json.dumps(found)
    assert "sk-" not in dumped
    status, _body, _extras = _call(server, "POST", "/v1/onboarding/save", b"{}")
    assert status == 403
    operator = store.create_account(
        username_text="bea",
        password=_PASSWORD,
        display_name="Bea",
        role="operator",
    )
    issued = store.open_session(operator)
    status, limited, _extras = _call(
        server,
        "GET",
        "/v1/onboarding/status",
        cookie=issued.token,
        csrf=issued.csrf_token,
    )
    assert status == 200
    assert set(limited) == {"setupRequired", "inferenceReady"}
    status, _body, _extras = _call(
        server,
        "POST",
        "/v1/onboarding/save",
        b'{"lane":"skip"}',
        cookie=issued.token,
        csrf=issued.csrf_token,
    )
    assert status == 403
    store.close()


def test_legacy_mode_without_accounts_hides_setup(tmp_path: Path):
    server = _gateway(tmp_path, None, tmp_path / "config")
    status, body, _extras = _call(server, "GET", "/v1/onboarding/status")
    assert status == 200
    assert body == {"setupRequired": False}
    status, body, _extras = _call(server, "POST", "/v1/onboarding/detect", b"{}")
    assert status == 403


def _routine(data: Path, *, hold: bool = False):
    from praxis_prime.scheduler.store import RoutineStore
    from praxis_prime.state import StateDB

    data.mkdir(parents=True, exist_ok=True)
    db = StateDB(data / "prime.db")
    RoutineStore(db).add(
        name="morning",
        prompt="keep-this-routine",
        trigger_kind="interval",
        trigger_expr="5m",
    )
    if hold:
        return db
    db.close()
    return None


def _profile_rows(data: Path, sql: str) -> list[Any]:
    from praxis_prime.state import StateDB

    db = StateDB(data / "profiles" / "default" / "prime.db")
    try:
        return list(db.conn.execute(sql).fetchall())
    finally:
        db.close()


def test_web_owner_on_a_fresh_install_migrates_and_audits_the_profile(tmp_path: Path):
    from praxis_prime.state import MigrationInProgress, StateDB

    config = tmp_path / "config"
    data = tmp_path / "data"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    token = ensure_first_run_token(config)
    status, body, _extras = _call(
        server, "POST", "/v1/onboarding/owner", _owner("ada"), token=token
    )
    assert status == 201, body
    assert body["restartRequired"] is True
    assert read_first_run_token(config) == ""
    marker = json.loads((data / "profiles" / ".migration.json").read_text(encoding="utf-8"))
    assert marker["profile"] == "default"
    assert marker["owner_account"] == body["account"]["id"]
    assert marker["version"] == 1
    rows = _profile_rows(data, "SELECT summary FROM audit_events")
    assert any(row["summary"] == "owner created from first-run setup" for row in rows)
    assert not (data / "prime.db").exists()
    with pytest.raises(MigrationInProgress, match="this database moved"):
        StateDB(data / "prime.db")
    store.close()


def test_web_owner_moves_an_existing_routine_and_writes_a_backup(tmp_path: Path):
    config = tmp_path / "config"
    data = tmp_path / "data"
    _routine(data)
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    token = ensure_first_run_token(config)
    status, body, _extras = _call(
        server, "POST", "/v1/onboarding/owner", _owner("ada"), token=token
    )
    assert status == 201, body
    prompts = _profile_rows(data, "SELECT prompt FROM routines")
    assert any(row["prompt"] == "keep-this-routine" for row in prompts)
    audits = _profile_rows(data, "SELECT summary FROM audit_events")
    assert any(row["summary"] == "owner created from first-run setup" for row in audits)
    assert not (data / "prime.db").exists()
    assert list((data / "backups").glob("pre-profile-*"))
    marker = json.loads((data / "profiles" / ".migration.json").read_text(encoding="utf-8"))
    assert marker["backup"]
    assert marker["owner_account"] == body["account"]["id"]
    assert read_first_run_token(config) == ""
    store.close()


def test_web_owner_releases_the_daemon_database_before_migrating(tmp_path: Path):
    from praxis_prime.audit.log import AuditLog

    config = tmp_path / "config"
    data = tmp_path / "data"
    held = _routine(data, hold=True)
    assert held is not None
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    log = AuditLog(held)

    class _Runtime:
        def __init__(self) -> None:
            self.db = held
            self.audit = log

    class _Agent:
        def __init__(self) -> None:
            self.runtime = _Runtime()

    server.agent = _Agent()  # type: ignore[assignment]
    server.audit = log
    token = ensure_first_run_token(config)
    status, body, _extras = _call(
        server, "POST", "/v1/onboarding/owner", _owner("ada"), token=token
    )
    assert status == 201, body
    prompts = _profile_rows(data, "SELECT prompt FROM routines")
    assert any(row["prompt"] == "keep-this-routine" for row in prompts)
    audits = _profile_rows(data, "SELECT summary FROM audit_events")
    assert any(row["summary"] == "owner created from first-run setup" for row in audits)
    assert not (data / "prime.db").exists()
    assert (data / "profiles" / ".migration.json").is_file()
    assert read_first_run_token(config) == ""
    store.close()


def test_web_owner_refuses_when_legacy_data_stays_locked(tmp_path: Path):
    config = tmp_path / "config"
    data = tmp_path / "data"
    held = _routine(data, hold=True)
    assert held is not None
    try:
        store = AccountStore(tmp_path / "accounts.db")
        server = _gateway(tmp_path, store, config)
        token = ensure_first_run_token(config)
        status, body, _extras = _call(
            server, "POST", "/v1/onboarding/owner", _owner("ada"), token=token
        )
        assert status == 503
        assert "praxis-prime setup" in body["error"]["message"]
        assert store.count_accounts() == 0
        assert not (data / "profiles" / ".migration.json").exists()
        assert read_first_run_token(config) == token
        prompts = list(held.conn.execute("SELECT prompt FROM routines").fetchall())
        assert any(row["prompt"] == "keep-this-routine" for row in prompts)
        store.close()
    finally:
        held.close()


def test_owner_audit_failure_keeps_the_token_and_discards_the_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from praxis_prime.audit.log import AuditLog

    def boom(self: AuditLog, **kwargs: object) -> str:
        del self, kwargs
        raise OSError("busy")

    monkeypatch.setattr(AuditLog, "append", boom)
    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    token = ensure_first_run_token(config)
    status, body, _extras = _call(
        server, "POST", "/v1/onboarding/owner", _owner("ada"), token=token
    )
    assert status == 503
    assert body["error"]["code"] == "unavailable"
    assert store.count_accounts() == 0
    assert read_first_run_token(config) == token
    store.close()


def test_admin_cannot_send_a_stored_key_to_another_host(tmp_path: Path):
    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    seen: list[dict[str, object]] = []
    events: list[dict[str, object]] = []

    def fetch(method: str, url: str, **kwargs: object) -> FetchResult:
        seen.append({"url": url, "headers": dict(kwargs.get("headers") or {})})
        return _fetch(method, url, **kwargs)

    class _Audit:
        def append(self, **kwargs: object) -> None:
            events.append(kwargs)

        def close(self) -> None:
            return None

    server.onboarding_fetcher = fetch  # type: ignore[attr-defined]
    token = ensure_first_run_token(config)
    saved = {
        "lane": "local",
        "provider": "llamacpp",
        "model": "local-model",
        "baseUrl": "http://127.0.0.1:9",
        "apiKey": "sk-stored",
    }
    status, _body, _extras = _call(
        server, "POST", "/v1/onboarding/save", json.dumps(saved).encode(), token=token
    )
    assert status == 200
    status, owner, extras = _call(
        server, "POST", "/v1/onboarding/owner", _owner("ada"), token=token
    )
    assert status == 201
    admin = store.create_account(
        username_text="bea",
        password=_PASSWORD,
        display_name="Bea",
        role="admin",
    )
    issued = store.open_session(admin)
    server.audit = _Audit()  # type: ignore[assignment]
    seen.clear()
    events.clear()
    evil = {"provider": "llamacpp", "model": "local-model", "baseUrl": "http://192.0.2.20:9"}
    status, body, _extras = _call(
        server,
        "POST",
        "/v1/onboarding/test",
        json.dumps(evil).encode(),
        cookie=issued.token,
        csrf=issued.csrf_token,
    )
    assert status == 400
    assert "re-enter the API key" in body["error"]["message"]
    assert seen == []
    assert any(
        isinstance(event.get("payload"), dict) and event["payload"].get("host") == "192.0.2.20"
        for event in events
    )
    assert "sk-stored" not in json.dumps(events)
    seen.clear()
    same = {"provider": "llamacpp", "model": "local-model", "baseUrl": "http://127.0.0.1:9"}
    status, _body, _extras = _call(
        server,
        "POST",
        "/v1/onboarding/test",
        json.dumps(same).encode(),
        cookie=issued.token,
        csrf=issued.csrf_token,
    )
    assert status == 200
    assert any(
        "sk-stored" in str(headers.get("authorization", ""))
        for headers in (item["headers"] for item in seen)
    )
    assert any(
        isinstance(event.get("payload"), dict) and event["payload"].get("host") == "127.0.0.1"
        for event in events
    )
    seen.clear()
    moved = {
        "lane": "local",
        "provider": "llamacpp",
        "model": "local-model",
        "baseUrl": "http://192.0.2.20:9",
        "replace": True,
    }
    status, body, _extras = _call(
        server,
        "POST",
        "/v1/onboarding/save",
        json.dumps(moved).encode(),
        cookie=issued.token,
        csrf=issued.csrf_token,
    )
    assert status == 409
    assert body["error"]["code"] == "replace"
    assert seen == []
    from praxis_prime.accounts.factors import Factors

    moved["stepUpToken"] = Factors(store)._mint_step_up(admin.id, issued.session_id)
    status, body, _extras = _call(
        server,
        "POST",
        "/v1/onboarding/save",
        json.dumps(moved).encode(),
        cookie=issued.token,
        csrf=issued.csrf_token,
    )
    assert status == 400
    assert "re-enter the API key" in body["error"]["message"]
    assert seen == []
    del owner, extras, admin
    store.close()


def _running(tmp_path: Path, store: AccountStore, config: Path):
    from praxis_prime.runtime import build_runtime

    server = _gateway(tmp_path, store, config)
    data = tmp_path / "data"
    data.mkdir(parents=True, exist_ok=True)
    runtime = build_runtime(
        env={},
        config_path=config / "config.toml",
        data_path=data / "prime.db",
        cwd=tmp_path,
    )

    class _Agent:
        def list_routines(self, profile: str = "") -> list[object]:
            del profile
            self.runtime.db.conn.execute("SELECT 1").fetchone()
            return []

    agent = _Agent()
    agent.runtime = runtime
    server.agent = agent  # type: ignore[assignment]
    server.audit = runtime.audit
    return server, runtime


def _bearer(server: GatewayServer) -> dict[str, str]:
    return {"authorization": f"Bearer {server.token}"}


def test_weak_owner_password_leaves_the_daemon_open(tmp_path: Path):
    config = tmp_path / "config"
    data = tmp_path / "data"
    store = AccountStore(tmp_path / "accounts.db")
    server, runtime = _running(tmp_path, store, config)
    try:
        token = ensure_first_run_token(config)
        weak = json.dumps(
            {"username": "ada", "password": "short", "displayName": "Ada"}
        ).encode()
        status, body, _extras = _call(
            server, "POST", "/v1/onboarding/owner", weak, token=token
        )
        assert status == 400, body
        assert runtime.db is not None and runtime.db.conn is not None
        assert runtime.audit is not None
        runtime.db.conn.execute("SELECT 1").fetchone()
        assert not (data / "profiles" / ".migration.json").exists()
        assert (data / "prime.db").is_file()
        assert read_first_run_token(config) == token
        assert store.count_accounts() == 0
        status, body, _extras = _call(
            server,
            "GET",
            "/v1/routines",
            extra_headers=_bearer(server),
        )
        assert status == 200, body
        runtime.audit.append(
            session_id=None,
            kind="auth.login",
            summary="still open",
            payload={"actor_account": "probe"},
        )
        row = runtime.db.conn.execute(
            "SELECT summary FROM audit_events WHERE summary = 'still open'"
        ).fetchone()
        assert row is not None
    finally:
        runtime.close()
        store.close()


def test_web_owner_reopens_the_profile_database(tmp_path: Path):
    config = tmp_path / "config"
    data = tmp_path / "data"
    store = AccountStore(tmp_path / "accounts.db")
    server, runtime = _running(tmp_path, store, config)
    try:
        token = ensure_first_run_token(config)
        status, body, _extras = _call(
            server, "POST", "/v1/onboarding/owner", _owner("ada"), token=token
        )
        assert status == 201, body
        assert body["restartRequired"] is False
        assert runtime.profile_id == "default"
        assert runtime.db is not None and runtime.db.conn is not None
        assert runtime.audit is not None
        assert not (data / "prime.db").exists()
        assert (data / "profiles" / "default" / "prime.db").is_file()
        status, health, _extras = _call(server, "GET", "/health")
        assert status == 200, health
        status, logged, _extras = _call(
            server,
            "POST",
            "/v1/auth/login",
            json.dumps({"username": "ada", "password": _PASSWORD}).encode(),
        )
        assert status == 200, logged
        rows = runtime.db.conn.execute(
            "SELECT kind, summary FROM audit_events WHERE kind = 'auth.login'"
        ).fetchall()
        assert any(row["summary"] == "login" for row in rows)
        status, routines, _extras = _call(
            server,
            "GET",
            "/v1/routines",
            extra_headers=_bearer(server),
        )
        assert status == 200, routines
        runtime.close()
    finally:
        store.close()


def test_runtime_close_tolerates_a_missing_audit_log(tmp_path: Path):
    from praxis_prime.runtime import build_runtime

    runtime = build_runtime(
        env={},
        config_path=tmp_path / "config.toml",
        data_path=tmp_path / "prime.db",
        cwd=tmp_path,
    )
    audit = runtime.audit
    db = runtime.db
    runtime.audit = None  # type: ignore[assignment]
    runtime.db = None  # type: ignore[assignment]
    runtime.close()
    audit.close()
    db.close()


def test_waiting_owner_request_keeps_the_token_when_audit_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from praxis_prime.audit.log import AuditLog

    entered = threading.Event()
    release = threading.Event()

    def boom(self: AuditLog, **kwargs: object) -> str:
        del self, kwargs
        entered.set()
        assert release.wait(5)
        raise OSError("busy")

    monkeypatch.setattr(AuditLog, "append", boom)
    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    token = ensure_first_run_token(config)
    statuses: list[int] = []

    def post() -> None:
        status, _body, _extras = _call(
            server, "POST", "/v1/onboarding/owner", _owner("ada"), token=token
        )
        statuses.append(status)

    first = threading.Thread(target=post)
    first.start()
    assert entered.wait(5)
    second = threading.Thread(target=post)
    second.start()
    release.set()
    first.join(5)
    second.join(5)
    assert statuses == [503, 503]
    assert store.count_accounts() == 0
    assert read_first_run_token(config) == token
    store.close()


def test_onboarding_save_step_up_matches_on_http_and_websocket(tmp_path: Path):
    import queue

    from praxis_prime.accounts.factors import Factors
    from praxis_prime.gateway.authz import Principal

    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    token = ensure_first_run_token(config)
    status, owner, extras = _call(
        server, "POST", "/v1/onboarding/owner", _owner("ada"), token=token
    )
    assert status == 201, owner
    cookie = _session(extras)
    csrf = str(owner["csrfToken"])
    account_id = str(owner["account"]["id"])
    session_id = store.session_from_token(cookie)
    assert session_id is not None
    saved = {
        "lane": "local",
        "provider": "llamacpp",
        "model": "local-model",
        "baseUrl": "http://127.0.0.1:9",
        "apiKey": "sk-first",
    }
    status, body, _extras = _call(
        server,
        "POST",
        "/v1/onboarding/save",
        json.dumps(saved).encode(),
        cookie=cookie,
        csrf=csrf,
    )
    assert status == 200, body
    replaced = {**saved, "apiKey": "sk-second", "replace": True}
    status, body, _extras = _call(
        server,
        "POST",
        "/v1/onboarding/save",
        json.dumps(replaced).encode(),
        cookie=cookie,
        csrf=csrf,
    )
    assert status == 409, body
    assert body["error"]["code"] == "replace"
    factors = Factors(store)
    replaced["stepUpToken"] = factors._mint_step_up(account_id, session_id.id)
    status, body, _extras = _call(
        server,
        "POST",
        "/v1/onboarding/save",
        json.dumps(replaced).encode(),
        cookie=cookie,
        csrf=csrf,
    )
    assert status == 200, body
    principal = Principal(
        kind="session",
        account_id=account_id,
        username="ada",
        role="owner",
        session_id=session_id.id,
    )
    outgoing: queue.Queue[dict[str, Any]] = queue.Queue()
    without = {
        "lane": "local",
        "provider": "llamacpp",
        "model": "local-model",
        "baseUrl": "http://127.0.0.1:9",
        "apiKey": "sk-third",
        "replace": True,
    }
    server._dispatch(
        {"type": "onboarding.save", "id": "ws-1", "payload": without},
        "operator",
        principal,
        outgoing,
    )
    frame = outgoing.get_nowait()
    assert frame["ok"] is False
    assert frame["payload"]["code"] == "replace"
    without["stepUpToken"] = factors._mint_step_up(account_id, session_id.id)
    server._dispatch(
        {"type": "onboarding.save", "id": "ws-2", "payload": without},
        "operator",
        principal,
        outgoing,
    )
    frame = outgoing.get_nowait()
    assert frame["ok"] is True, frame
    assert frame["payload"]["ok"] is True
    held = factors._mint_step_up(account_id, session_id.id)
    moved = {
        "lane": "local",
        "provider": "llamacpp",
        "model": "local-model",
        "baseUrl": "http://192.0.2.20:9",
        "replace": False,
        "stepUpToken": held,
    }
    status, body, _extras = _call(
        server,
        "POST",
        "/v1/onboarding/save",
        json.dumps(moved).encode(),
        cookie=cookie,
        csrf=csrf,
    )
    assert status == 409, body
    assert factors.step_up_valid(account_id, held, session_id.id) is True
    store.close()


def test_provider_test_records_the_actor(tmp_path: Path):
    from praxis_prime.audit.log import AuditLog
    from praxis_prime.state import StateDB

    config = tmp_path / "config"
    data = tmp_path / "data"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    token = ensure_first_run_token(config)
    status, owner, extras = _call(
        server, "POST", "/v1/onboarding/owner", _owner("ada"), token=token
    )
    assert status == 201, owner
    db = StateDB(data / "profiles" / "default" / "prime.db")
    log = AuditLog(db)
    server.audit = log
    cookie = _session(extras)
    csrf = str(owner["csrfToken"])
    account_id = str(owner["account"]["id"])
    try:
        status, body, _extras = _call(
            server,
            "POST",
            "/v1/onboarding/test",
            json.dumps(
                {"provider": "llamacpp", "model": "local-model", "baseUrl": "http://127.0.0.1:9"}
            ).encode(),
            cookie=cookie,
            csrf=csrf,
        )
        assert status == 200, body
        rows = db.conn.execute(
            "SELECT actor_account, payload_json FROM audit_events WHERE kind = 'provider.test'"
        ).fetchall()
        assert rows
        assert rows[-1]["actor_account"] == account_id
        payload = json.loads(rows[-1]["payload_json"])
        assert payload["actor"] == account_id
        assert payload["actor_account"] == account_id
    finally:
        log.close()
        db.close()
        store.close()
