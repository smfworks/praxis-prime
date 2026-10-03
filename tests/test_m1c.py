"""Per-profile workers: isolation, supervisor lifecycle, approvals, migration."""

from __future__ import annotations

import json
import os
import queue
import socket
import sqlite3
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from praxis_prime.approvals.gate import (
    ApprovalDecision,
    ApprovalRequest,
    approval_account_id,
    approval_actor,
    approval_session_id,
)
from praxis_prime.approvals.queue import ApprovalQueue
from praxis_prime.channels.telegram import PairingStore, TelegramAdapter
from praxis_prime.cli import build_parser
from praxis_prime.daemon import serve
from praxis_prime.gateway.client import Endpoint, GatewayClient
from praxis_prime.gateway.discover import discover
from praxis_prime.gateway.routes import frame_session_ids_agree, ids_agree, route_allowed
from praxis_prime.gateway.server import GatewayServer
from praxis_prime.host import Host, TurnResult
from praxis_prime.loop.control import TurnControl
from praxis_prime.profiles.home import create_profile
from praxis_prime.router.http import open_lines
from praxis_prime.router.types import ProviderUnreachable
from praxis_prime.state import StateDB
from praxis_prime.supervisor.confine import ProfileBoundary, refuse_worker_path
from praxis_prime.supervisor.credentials import (
    bump_generation,
    credential_matches,
    derive,
    generation_for,
    load_or_create_master,
    rotate_master,
)
from praxis_prime.supervisor.grants import is_revoked, load_live_grants, migrate_grants
from praxis_prime.supervisor.ipc import IpcError, recv_message, send_message
from praxis_prime.supervisor.leases import LeaseStore
from praxis_prime.supervisor.migrate import marker_path, migrate_install
from praxis_prime.supervisor.redact import redact
from praxis_prime.supervisor.routing import RoutingHost, RoutingQueue
from praxis_prime.supervisor.supervisor import Supervisor, WorkerUnavailable
from praxis_prime.tools.registry import Risk
from praxis_prime.upstream import MAX_UPSTREAM_BYTES, build_opener
from praxis_prime.worker import WorkerApp

_STUB = Path(__file__).resolve().parent / "support" / "ipc_worker.py"


def test_worker_credentials_are_per_profile_and_generation(tmp_path: Path):
    master_path = tmp_path / "worker-master.key"
    master = load_or_create_master(master_path)
    assert len(master) == 32
    assert master_path.stat().st_mode & 0o777 == 0o600
    generations = tmp_path / "worker-generations.json"
    ada = derive(master, "ada", generation_for(generations, "ada"))
    bea = derive(master, "bea", 1)
    assert ada != bea
    assert credential_matches(ada, ada)
    assert not credential_matches(ada, bea)
    assert not credential_matches("", ada)
    bumped = bump_generation(generations, "ada")
    assert bumped == 2
    assert generation_for(generations, "bea") == 1
    assert not credential_matches(ada, derive(master, "ada", bumped))
    assert credential_matches(bea, derive(master, "bea", 1))
    rotated = rotate_master(master_path)
    assert rotated != master
    assert not credential_matches(bea, derive(rotated, "bea", 1))


def test_worker_path_guard_refuses_another_profile(tmp_path: Path, monkeypatch):
    root = tmp_path / "data"
    create_profile(root, "ada")
    create_profile(root, "bea")
    ada_db = root / "profiles" / "ada" / "prime.db"
    bea_db = root / "profiles" / "bea" / "prime.db"
    refuse_worker_path(bea_db)
    monkeypatch.setenv("PRAXIS_PRIME_WORKER_PROFILE", "ada")
    monkeypatch.setenv("PRAXIS_PRIME_WORKER_DATA", str(root))
    StateDB(ada_db).close()
    with pytest.raises(ProfileBoundary):
        StateDB(bea_db)
    alias = root / "profiles" / "ada" / "other.db"
    alias.symlink_to(bea_db)
    with pytest.raises(ProfileBoundary):
        StateDB(alias)


def test_m1c_migration_is_idempotent_and_does_not_move_the_database(tmp_path: Path):
    root = tmp_path / "data"
    root.mkdir()
    database = root / "prime.db"
    database.write_bytes(b"leave-this-file")
    assert migrate_install(root) is True
    assert migrate_install(root) is False
    assert database.read_bytes() == b"leave-this-file"
    marker = json.loads(marker_path(root).read_text(encoding="utf-8"))
    assert marker["version"] == 1
    assert marker["grants"] == "not-restored"
    assert marker_path(root).stat().st_mode & 0o777 == 0o600


def test_grant_migration_runs_once_and_does_not_restore_revoked_rows(tmp_path: Path):
    db = StateDB(tmp_path / "prime.db")
    legacy = tmp_path / "grants-legacy.json"
    legacy.write_text(
        json.dumps({"active": ["acct:sess:shell"], "revoked": ["acct:sess:old"]}),
        encoding="utf-8",
    )
    assert migrate_grants(db, legacy) is True
    assert load_live_grants(db) == []
    assert is_revoked(db, account_id="acct", session_id="sess", grant_key="old")
    assert not is_revoked(db, account_id="acct", session_id="sess", grant_key="shell")
    legacy.write_text(
        json.dumps({"active": ["acct:sess:later"], "revoked": ["acct:sess:later-revoked"]}),
        encoding="utf-8",
    )
    assert migrate_grants(db, legacy) is False
    assert not is_revoked(db, account_id="acct", session_id="sess", grant_key="later-revoked")
    assert load_live_grants(db) == []
    db.close()


def test_recheck_denies_the_next_call_and_stays_revoked(tmp_path: Path):
    request = ApprovalRequest(
        tool="delete_file",
        risk=Risk.DESTRUCTIVE,
        reason="delete",
        summary="delete",
        arguments={},
        grant_key="delete_file",
        sandboxed=False,
    )
    from praxis_prime.approvals.gate import ApprovalGate

    live = {"ok": True}
    gate = ApprovalGate(lambda _request: ApprovalDecision.ALLOW_SESSION)
    gate.recheck = lambda _request: live["ok"]
    account = approval_account_id.set("acct")
    session = approval_session_id.set("sess")
    try:
        assert gate.authorize(request) == ApprovalDecision.ALLOW_SESSION
        live["ok"] = False
        assert gate.authorize(request) == ApprovalDecision.DENY
        assert approval_actor.get() == "grant-revoked"
    finally:
        approval_account_id.reset(account)
        approval_session_id.reset(session)

    db = StateDB(tmp_path / "prime.db")
    from praxis_prime.supervisor.grants import revoke_grant, save_grant

    save_grant(db, account_id="acct", session_id="sess", grant_key="delete_file", profile_id="ada")
    revoke_grant(db, account_id="acct", session_id="sess", grant_key="delete_file")
    db.close()
    again = StateDB(tmp_path / "prime.db")
    assert is_revoked(again, account_id="acct", session_id="sess", grant_key="delete_file")
    assert load_live_grants(again) == []
    again.close()


def test_routine_lease_retries_once_after_a_crash(tmp_path: Path):
    db = StateDB(tmp_path / "prime.db")
    try:
        clock = {"now": 0.0}
        store = LeaseStore(db, clock=lambda: clock["now"], ttl=30)
        assert store.acquire("routine", "owner-a") == "run"
        assert store.acquire("routine", "owner-b") == "skip"
        clock["now"] = 31
        assert store.acquire("routine", "owner-b") == "retry"
        clock["now"] = 62
        assert store.acquire("routine", "owner-c") == "skip"
        store.release("routine")
        assert store.acquire("routine", "owner-c") == "run"
    finally:
        db.close()


def test_redaction_does_not_shorten_the_rest_of_the_text():
    secret = "worker-secret-value"
    text = f"prefix {secret} suffix that stays intact"
    cleaned = redact(text, [secret])
    assert cleaned == "prefix [redacted] suffix that stays intact"
    assert "suffix that stays intact" in cleaned


def test_supervisor_backoff_doubles_until_the_clock_moves(tmp_path: Path):
    now = {"t": 1000.0}
    supervisor = _supervisor(
        tmp_path,
        names=("ada",),
        env_extra={"STUB_MODE": "crash"},
        clock=lambda: now["t"],
        backoff_base=0.5,
        backoff_cap=30,
        idle_after=100,
    )
    try:
        with pytest.raises(WorkerUnavailable):
            supervisor.ensure("ada")
        slot = supervisor._slots["ada"]
        assert slot.state == "backoff"
        assert slot.failures == 1
        assert slot.next_start == 1000.5
        with pytest.raises(WorkerUnavailable):
            supervisor.ensure("ada")
        assert slot.failures == 1
        now["t"] = 1000.5
        with pytest.raises(WorkerUnavailable):
            supervisor.ensure("ada")
        assert slot.failures == 2
        assert slot.next_start == 1001.5
    finally:
        supervisor.close()


def test_idle_worker_exits_and_starts_again_on_demand(tmp_path: Path):
    now = {"t": 10.0}
    supervisor = _supervisor(
        tmp_path,
        names=("ada",),
        clock=lambda: now["t"],
        idle_after=5,
        backoff_base=0.5,
    )
    try:
        slot = supervisor.ensure("ada")
        assert slot.state == "running"
        now["t"] = 14.9
        supervisor.tick()
        assert slot.state == "running"
        now["t"] = 15.0
        supervisor.tick()
        assert slot.state == "idle"
        assert slot.process is None
        now["t"] = 16
        again = supervisor.ensure("ada")
        assert again.state == "running"
        assert again.process is not None
    finally:
        supervisor.close()


def test_profile_credential_is_rejected_by_the_other_worker(tmp_path: Path):
    supervisor = _supervisor(tmp_path, names=("ada", "bea"))
    try:
        ada = supervisor.ensure("ada")
        bea = supervisor.ensure("bea")
        supervisor.call("ada", "memory.remember", {"content": "ada-note"})
        supervisor.call("bea", "memory.remember", {"content": "bea-note"})
        assert supervisor.call("ada", "memory.list")["entries"] == ["ada-note"]
        assert supervisor.call("bea", "memory.list")["entries"] == ["bea-note"]
        listed = RoutingQueue(supervisor).list_pending()
        assert {item["profileId"] for item in listed} == {"ada", "bea"}
        ada_item = RoutingQueue(supervisor).get("ap_aaaaaaaa")
        assert ada_item is not None
        assert ada_item["profileId"] == "ada"
        refused = _rpc(bea.socket_path, bea.profile, ada.credential, "approvals.list", {})
        assert refused.get("ok") is False
        old = ada.credential
        supervisor.bump("ada")
        restarted = supervisor.ensure("ada")
        assert restarted.credential != old
        assert _rpc(restarted.socket_path, "ada", old, "health", {}).get("ok") is False
        bea_after = supervisor.ensure("bea")
        assert supervisor.call("bea", "memory.list")["entries"] == ["bea-note"]
        assert bea_after.credential == bea.credential
        old_bea = bea.credential
        supervisor.rotate_master()
        fresh = supervisor.ensure("bea")
        assert fresh.credential != old_bea
        refused_after = _rpc(fresh.socket_path, "bea", old_bea, "health", {})
        assert refused_after.get("ok") is False
        assert supervisor.call("bea", "health")["profile"] == "bea"
    finally:
        supervisor.close()


def test_worker_environment_has_no_master_key_or_bot_token(tmp_path: Path):
    env_path = tmp_path / "child-env.json"
    supervisor = _supervisor(
        tmp_path,
        names=("ada",),
        env_extra={
            "STUB_ENV_PATH": str(env_path),
            "PRAXIS_PRIME_TELEGRAM_BOT_TOKEN": "telegram-token",
            "PRAXIS_PRIME_WORKER_MASTER": "should-not-pass",
            "PRAXIS_PRIME_SECRETS_FILE": str(tmp_path / "secrets.env"),
        },
    )
    try:
        stripped = supervisor.worker_env("ada")
        assert "PRAXIS_PRIME_TELEGRAM_BOT_TOKEN" not in stripped
        assert "PRAXIS_PRIME_WORKER_MASTER" not in stripped
        assert "PRAXIS_PRIME_SECRETS_FILE" not in stripped
        assert stripped["PRAXIS_PRIME_WORKER_PROFILE"] == "ada"
        supervisor.ensure("ada")
        child = json.loads(env_path.read_text(encoding="utf-8"))
        assert "telegram-token" not in json.dumps(child)
        assert "should-not-pass" not in json.dumps(child)
        assert child["PRAXIS_PRIME_WORKER_PROFILE"] == "ada"
    finally:
        supervisor.close()


def test_worker_cannot_ask_the_supervisor_to_spawn(tmp_path: Path):
    supervisor = _supervisor(tmp_path, names=("ada",))
    try:
        supervisor.start()
        slot = supervisor.ensure("ada")
        with pytest.raises(IpcError):
            supervisor.call("ada", "spawn", {})
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(str(supervisor.control_path))
        send_message(
            sock,
            {
                "id": "auth",
                "method": "auth",
                "profile": "ada",
                "generation": slot.generation,
                "token": slot.credential,
            },
        )
        assert recv_message(sock).get("ok") is True
        send_message(sock, {"id": "nope", "method": "spawn", "profile": "bea"})
        reply = recv_message(sock)
        sock.close()
        assert reply.get("ok") is False
    finally:
        supervisor.close()


def test_pause_cancels_a_held_turn_quickly(tmp_path: Path):
    hold = tmp_path / "hold"
    supervisor = _supervisor(tmp_path, names=("ada",), env_extra={"STUB_HOLD_CHAT": str(hold)})
    try:
        box: dict[str, object] = {}

        def _chat() -> None:
            try:
                box["result"] = supervisor.call("ada", "chat", {"text": "hello"}, timeout=5)
            except Exception as exc:  # noqa: BLE001
                box["error"] = exc

        thread = threading.Thread(target=_chat)
        thread.start()
        for _ in range(50):
            if hold.exists() and hold.read_text(encoding="utf-8") == "chat":
                break
            time.sleep(0.05)
        else:
            raise AssertionError("worker did not enter the turn")
        started = time.monotonic()
        supervisor.pause("ada")
        thread.join(1)
        assert not thread.is_alive()
        assert time.monotonic() - started < 1
        assert "error" not in box
    finally:
        supervisor.close()


def test_cancel_turn_unblocks_a_pending_approval():
    queue = ApprovalQueue(ttl=30)
    host = Host.__new__(Host)
    host.queue = queue
    host._control = TurnControl()
    host._active_account = "acct"
    request = ApprovalRequest(
        tool="shell",
        risk=Risk.DESTRUCTIVE,
        reason="run",
        summary="run",
        arguments={},
        grant_key="shell",
        sandboxed=True,
    )
    result: dict[str, ApprovalDecision] = {}

    def wait() -> None:
        result["decision"] = queue.authorize(request)

    thread = threading.Thread(target=wait)
    thread.start()
    for _ in range(50):
        if queue.list_pending():
            break
        time.sleep(0.02)
    started = time.monotonic()
    assert host.cancel_turn(actor="revoked") is True
    thread.join(1)
    assert not thread.is_alive()
    assert time.monotonic() - started < 1
    assert host._control.cancelled is True
    assert result["decision"] == ApprovalDecision.DENY


def test_watcher_cancels_when_the_supervisor_denies_the_account(tmp_path: Path):
    app = WorkerApp.__new__(WorkerApp)
    app._stop = threading.Event()
    cancelled: list[str] = []

    class _Host:
        def active_account(self) -> str:
            return "acct"

        def cancel_turn(self, *, actor: str) -> bool:
            cancelled.append(actor)
            app._stop.set()
            return True

    app.host = _Host()  # type: ignore[assignment]
    app._supervisor_allows = lambda _account: False  # type: ignore[method-assign]
    app._profile_mtime = 1
    app.runtime_home = lambda: tmp_path  # type: ignore[method-assign]
    app._audit = lambda *_args, **_kwargs: None  # type: ignore[method-assign]
    thread = threading.Thread(target=app._watch_loop)
    thread.start()
    thread.join(1)
    assert not thread.is_alive()
    assert cancelled == ["revoked"]


def test_telegram_routes_approve_and_deny_to_the_bound_chat(tmp_path: Path):
    store = PairingStore(tmp_path / "code.json", tmp_path / "owner.json")
    store.set_owner(42)
    store.bind_chat(11, "acct-ada", "ada")
    store.bind_chat(22, "acct-bea", "bea")
    assert store.bindings_path().stat().st_mode & 0o777 == 0o600
    assert store.destination("ada", "acct-ada") == 11
    assert store.destination("bea", "acct-bea") == 22
    assert store.destination("ada", "acct-bea") is None
    assert store.may_decide(11, "ada", "acct-ada") is True
    assert store.may_decide(22, "ada", "acct-ada") is False

    queue = ApprovalQueue(ttl=30)
    queue.profile_id = "ada"
    transport = _Transport()
    adapter = TelegramAdapter(transport, store, _Host(), queue)
    account = approval_account_id.set("acct-ada")
    request = ApprovalRequest(
        tool="shell",
        risk=Risk.DESTRUCTIVE,
        reason="run",
        summary="run",
        arguments={},
        grant_key="shell",
        sandboxed=True,
    )

    def wait() -> None:
        queue.authorize(request)

    thread = threading.Thread(target=wait)
    thread.start()
    item = _wait_pending(queue)
    try:
        adapter.notify_pending(item)
        sent = [call for call in transport.calls if call[0] == "sendMessage"]
        assert len(sent) == 1
        assert sent[0][1]["chat_id"] == 11
        approval_id = str(item["id"])
        adapter.handle_update(
            {
                "callback_query": {
                    "id": "q-bea",
                    "data": f"a:{approval_id}:1",
                    "message": {"chat": {"id": 22}},
                }
            }
        )
        assert queue.get(approval_id)["state"] == "pending"  # type: ignore[index]
        adapter.handle_update(
            {
                "callback_query": {
                    "id": "q-ada",
                    "data": f"a:{approval_id}:0",
                    "message": {"chat": {"id": 11}},
                }
            }
        )
        thread.join(2)
        assert not thread.is_alive()
        assert queue.get(approval_id)["state"] == "deny"  # type: ignore[index]
    finally:
        approval_account_id.reset(account)
        queue.deny_all(actor="shutdown")
        thread.join(1)


def test_unbound_default_card_still_reaches_the_owner(tmp_path: Path):
    store = PairingStore(tmp_path / "code.json", tmp_path / "owner.json")
    store.set_owner(42)
    assert store.destination("", "") == 42
    assert store.destination("default", "") == 42
    assert store.destination("ada", "") is None


def test_route_allowlist_and_id_agreement(tmp_path: Path):
    assert route_allowed("GET", "/health") is True
    assert route_allowed("GET", "/v1/not-a-route") is False
    assert frame_session_ids_agree({"sessionId": "one", "payload": {"sessionId": "one"}})
    assert not frame_session_ids_agree({"sessionId": "one", "payload": {"sessionId": "two"}})
    assert ids_agree(query="profile=ada&sessionId=sess")
    assert not ids_agree(query="profile=ada&profile=bea")
    assert not ids_agree(
        path_id="ap_aaaaaaaa",
        body={"id": "ap_bbbbbbbb"},
        keys=("id", "approvalId"),
    )

    agent = _GatewayAgent()
    server = GatewayServer(
        host="127.0.0.1",
        port=0,
        token="test-token",
        agent=agent,  # type: ignore[arg-type]
        approvals=ApprovalQueue(),
        socket_path=None,
    )
    server.start()
    try:
        status, body = _http(server.bound_port, "GET", "/v1/not-a-route")
        assert status == 404
        assert body["error"]["code"] == "not_allowed"
        status, body = _http(
            server.bound_port,
            "POST",
            "/v1/approvals/ap_aaaaaaaa",
            token="test-token",
            body={"id": "ap_bbbbbbbb", "decision": "deny"},
        )
        assert status == 400
        assert "does not match" in body["error"]["message"]
        status, _body = _http(
            server.bound_port,
            "GET",
            "/status?profile=ada&sessionId=sess",
            token="test-token",
        )
        assert status == 200
        client = GatewayClient.connect(Endpoint("127.0.0.1", server.bound_port, "test-token"))
        try:
            frame_id = "frame-mismatch"
            box: queue.Queue[dict[str, object]] = queue.Queue()
            client._waiters[frame_id] = box
            client.ws.send_text(
                json.dumps(
                    {
                        "type": "chat.send",
                        "id": frame_id,
                        "sessionId": "one",
                        "payload": {"text": "hi", "sessionId": "two"},
                    }
                )
            )
            reply = box.get(timeout=2)
            assert reply.get("ok") is False
            assert "session id" in json.dumps(reply)
        finally:
            client.close()
    finally:
        server.shutdown()


def test_chat_profile_reaches_that_worker(tmp_path: Path):
    log = tmp_path / "chats.log"
    root = tmp_path / "data"
    supervisor = _supervisor(
        tmp_path,
        names=("default", "bea"),
        env_extra={"STUB_CHAT_LOG": str(log)},
        data_root=root,
    )
    from praxis_prime.policy.engine import PolicyEngine
    from praxis_prime.router.settings import load_settings

    settings = load_settings({})
    host = RoutingHost(supervisor, PolicyEngine({}), settings)
    server = GatewayServer(
        host="127.0.0.1",
        port=0,
        token="test-token",
        agent=host,  # type: ignore[arg-type]
        approvals=RoutingQueue(supervisor),  # type: ignore[arg-type]
        socket_path=None,
        data_root=root,
        multi_profile=True,
    )
    try:
        supervisor.start()
        server.start()
        client = GatewayClient.connect(Endpoint("127.0.0.1", server.bound_port, "test-token"))
        try:
            client.chat("hello bea", profile="bea", timeout=5)
            client.chat("hello default", timeout=5)
        finally:
            client.close()
        lines = log.read_text(encoding="utf-8").split()
        assert lines == ["bea", "default"]
        parsed = build_parser().parse_args(["ask", "--profile", "bea", "hello"])
        assert parsed.profile == "bea"
        assert parsed.command == "ask"
    finally:
        server.shutdown()
        supervisor.close()


def test_daemon_with_profiles_stays_on_loopback(tmp_path: Path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    from praxis_prime.paths import data_dir

    create_profile(data_dir(), "default")
    stop = threading.Event()
    code: dict[str, int] = {}

    def run() -> None:
        code["n"] = serve(stop=stop, listen="127.0.0.1:0")

    thread = threading.Thread(target=run)
    thread.start()
    try:
        endpoint = None
        for _ in range(50):
            endpoint = discover(timeout=0.2)
            if endpoint is not None:
                break
            time.sleep(0.05)
        assert endpoint is not None
        assert endpoint.host == "127.0.0.1"
        status, body = _http(endpoint.port, "GET", "/health")
        assert status == 200
        assert body["service"] == "praxis-primed"
        marker = data_dir() / "supervisor" / "m1c.json"
        assert marker.is_file()
        assert json.loads(marker.read_text(encoding="utf-8"))["grants"] == "not-restored"
    finally:
        stop.set()
        thread.join(5)
    assert code.get("n") == 0


def test_upstream_refuses_redirects_oversized_bodies_and_deadlines():
    redirect = _serve(_Redirect)
    huge = _serve(_Huge)
    slow = _serve(_Slow)
    try:
        with pytest.raises(ProviderUnreachable, match="redirect refused"):
            _drain(
                open_lines(
                    redirect,
                    b"{}",
                    {"Content-Type": "application/json"},
                    timeout=2,
                    secrets=[],
                    provider="test",
                )
            )
        with pytest.raises(ProviderUnreachable, match="4MB"):
            _drain(
                open_lines(
                    huge,
                    b"{}",
                    {"Content-Type": "application/json"},
                    timeout=5,
                    secrets=[],
                    provider="test",
                )
            )
        with pytest.raises(ProviderUnreachable, match="deadline"):
            _drain(
                open_lines(
                    slow,
                    b"{}",
                    {"Content-Type": "application/json"},
                    timeout=5,
                    deadline=0.2,
                    secrets=[],
                    provider="test",
                )
            )
    finally:
        for server in _SERVERS:
            server.shutdown()


def test_upstream_redacts_a_secret_without_truncating_the_line():
    echoed = _serve(_Echo)
    secret = "echo-this-secret"
    try:
        lines = list(
            open_lines(
                echoed,
                b"{}",
                {"Content-Type": "application/json"},
                timeout=2,
                secrets=[secret],
                provider="test",
            )
        )
    finally:
        pass
    assert lines == ["prefix [redacted] suffix stays\n"]


def test_telegram_transport_refuses_a_redirect():
    from praxis_prime.channels.telegram import HttpTelegramTransport, TelegramError

    local = _serve(_Redirect)

    def opener(request: urllib.request.Request, timeout: float = 15):
        del request
        forwarded = urllib.request.Request(local, data=b"{}", method="POST")
        return build_opener().open(forwarded, timeout=timeout)

    transport = HttpTelegramTransport("telegram-token", opener=opener)
    with pytest.raises(TelegramError, match="redirect refused"):
        transport.call("getMe", {})


def test_real_workers_keep_memory_in_separate_databases(tmp_path: Path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    root = tmp_path / "data" / "praxis-prime"
    create_profile(root, "ada")
    create_profile(root, "bea")
    env = _child_env()
    supervisor = Supervisor(
        data_root=root,
        runtime_dir=tmp_path / "run",
        state_dir=tmp_path / "state",
        env=env,
        idle_after=900,
        start_timeout=60,
    )
    try:
        supervisor.start()
        ada = supervisor.call("ada", "memory.remember", {"content": "Ada keeps this note."})
        bea = supervisor.call("bea", "memory.remember", {"content": "Bea keeps this note."})
        assert ada["content"] == "Ada keeps this note."
        assert bea["content"] == "Bea keeps this note."
        ada_rows = supervisor.call("ada", "memory.list")["entries"]
        bea_rows = supervisor.call("bea", "memory.list")["entries"]
        assert ada_rows == ["Ada keeps this note."]
        assert bea_rows == ["Bea keeps this note."]
        assert _memory_contents(root / "profiles" / "ada" / "prime.db") == ["Ada keeps this note."]
        assert _memory_contents(root / "profiles" / "bea" / "prime.db") == ["Bea keeps this note."]
    finally:
        supervisor.close()


def test_slice_argv_uses_systemd_run_when_requested(tmp_path: Path, monkeypatch):
    supervisor = _supervisor(tmp_path, names=("ada",))
    monkeypatch.setattr(
        "praxis_prime.supervisor.supervisor.shutil.which",
        lambda name: "/bin/systemd-run" if name == "systemd-run" else None,
    )
    try:
        supervisor.use_slice = True
        argv = supervisor._argv("ada", 1)
        assert argv[0] == "/bin/systemd-run"
        assert "--slice=praxis-prime-workers.slice" in argv
        joined = " ".join(argv)
        assert "MemoryMax=512M" in joined
        assert "CPUQuota=50%" in joined
        assert "TasksMax=64" in joined
        supervisor.use_slice = False
        assert supervisor._argv("ada", 1)[0] == sys.executable
    finally:
        supervisor.close()


class _Host:
    def chat(self, text: str, **_kwargs: object) -> TurnResult:
        del text
        return TurnResult(session_id="s", text="ok", error=None, cancelled=False)


class _Transport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def call(self, method: str, payload: dict[str, object]) -> dict[str, object]:
        self.calls.append((method, dict(payload)))
        return {"ok": True, "result": []}


class _GatewayAgent:
    def status(self) -> dict[str, object]:
        return {
            "service": "praxis-primed",
            "version": "test",
            "model": "stub",
            "mode": "ask",
            "pendingApprovals": 0,
            "uptimeSeconds": 0,
        }

    def close(self) -> None:
        return None

    def chat(self, text: str, **kwargs: object) -> TurnResult:
        del text, kwargs
        return TurnResult(session_id="s", text="ok", error=None, cancelled=False)

    def set_model(self, spec: str, *, profile: str = "") -> str:
        del profile
        return spec

    def drop_session(self, session_id: str | None, *, account_id: str = "") -> None:
        del session_id, account_id


class _Redirect(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        self.send_response(302)
        self.send_header("Location", "http://127.0.0.1/elsewhere")
        self.end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
        del fmt, args


class _Huge(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        body = b"a" * (MAX_UPSTREAM_BYTES + 8)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        del fmt, args


class _Slow(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        time.sleep(0.6)
        self.wfile.write(b"late\n")

    def log_message(self, fmt: str, *args: object) -> None:
        del fmt, args


class _Echo(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        body = b"prefix echo-this-secret suffix stays\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        del fmt, args


def _child_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Parent environment plus ``sys.path``, so a worker can import this checkout."""
    env = os.environ.copy()
    entries = [entry for entry in sys.path if entry]
    current = env.get("PYTHONPATH", "")
    if current:
        entries.append(current)
    env["PYTHONPATH"] = os.pathsep.join(entries)
    if extra:
        env.update(extra)
    return env


def _supervisor(
    tmp_path: Path,
    *,
    names: tuple[str, ...],
    env_extra: dict[str, str] | None = None,
    clock: object | None = None,
    data_root: Path | None = None,
    **kwargs: object,
) -> Supervisor:
    root = data_root or (tmp_path / "data")
    env = _child_env(env_extra)
    for name in names:
        if not (root / "profiles" / name / "profile.toml").is_file():
            create_profile(root, name)
    supervisor = Supervisor(
        data_root=root,
        runtime_dir=tmp_path / "run",
        state_dir=tmp_path / "state",
        env=env,
        command=[sys.executable, str(_STUB)],
        clock=clock or time.monotonic,  # type: ignore[arg-type]
        **kwargs,  # type: ignore[arg-type]
    )
    return supervisor


def _rpc(
    path: Path,
    profile: str,
    token: str,
    method: str,
    params: dict[str, object],
) -> dict[str, object]:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect(str(path))
        send_message(
            sock,
            {"id": "auth", "method": "auth", "profile": profile, "token": token},
        )
        auth = recv_message(sock)
        if not auth.get("ok"):
            return auth
        send_message(sock, {"id": "call", "method": method, "params": params})
        return recv_message(sock)
    finally:
        sock.close()


def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("PRAXIS_PRIME_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("PRAXIS_PRIME_SECRETS_FILE", raising=False)
    monkeypatch.delenv("PRAXIS_PRIME_GATEWAY_LISTEN", raising=False)
    monkeypatch.delenv("PRAXIS_PRIME_WORKER_PROFILE", raising=False)
    monkeypatch.delenv("PRAXIS_PRIME_WORKER_DATA", raising=False)


def _http(
    port: int,
    method: str,
    path: str,
    *,
    token: str | None = None,
    body: dict[str, object] | None = None,
) -> tuple[int, dict[str, object]]:
    payload = b"" if body is None else json.dumps(body).encode("utf-8")
    headers = [f"{method} {path} HTTP/1.1", "Host: 127.0.0.1", "Connection: close"]
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


_SERVERS: list[ThreadingHTTPServer] = []


def _serve(handler: type[BaseHTTPRequestHandler]) -> str:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _SERVERS.append(server)
    host, port = server.server_address[:2]
    return f"http://{host}:{port}/"


def _drain(lines: object) -> None:
    list(lines)  # type: ignore[arg-type]


def _memory_contents(path: Path) -> list[str]:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        rows = conn.execute("SELECT content FROM memory_entries").fetchall()
    finally:
        conn.close()
    return [str(row[0]) for row in rows]


def _wait_pending(queue: ApprovalQueue) -> dict[str, object]:
    for _ in range(50):
        rows = queue.list_pending()
        if rows:
            return rows[0]
        time.sleep(0.02)
    raise AssertionError("approval was not queued")

