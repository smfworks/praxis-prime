"""Per-profile workers: isolation, supervisor lifecycle, approvals, migration."""

from __future__ import annotations

import json
import os
import queue
import signal
import socket
import sqlite3
import subprocess
import sys
import textwrap
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
from praxis_prime.policy.boundary import _EXACT_NAMES, _FILE_ROOT_NAMES
from praxis_prime.profiles.home import create_profile
from praxis_prime.router.http import open_lines
from praxis_prime.router.types import ProviderUnreachable
from praxis_prime.state import StateDB
from praxis_prime.supervisor.confine import (
    ProfileBoundary,
    clear_worker_boundary,
    refuse_worker_path,
)
from praxis_prime.supervisor.credentials import (
    CredentialError,
    bump_generation,
    credential_matches,
    derive,
    generation_for,
    load_generations,
    load_or_create_master,
    rotate_master,
)
from praxis_prime.supervisor.grants import is_revoked, load_live_grants, migrate_grants
from praxis_prime.supervisor.ipc import IpcError, recv_message, same_user, send_message
from praxis_prime.supervisor.leases import LeaseStore
from praxis_prime.supervisor.migrate import MigrationError, marker_path, migrate_install
from praxis_prime.supervisor.redact import redact
from praxis_prime.supervisor.routing import RoutingHost, RoutingQueue
from praxis_prime.supervisor.supervisor import Supervisor, WorkerUnavailable
from praxis_prime.tools.registry import Risk
from praxis_prime.upstream import MAX_UPSTREAM_BYTES, build_opener, iter_bounded
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
    try:
        StateDB(ada_db).close()
        with pytest.raises(ProfileBoundary):
            StateDB(bea_db)
        alias = root / "profiles" / "ada" / "other.db"
        alias.symlink_to(bea_db)
        with pytest.raises(ProfileBoundary):
            StateDB(alias)
        monkeypatch.setenv("PRAXIS_PRIME_WORKER_PROFILE", "bea")
        with pytest.raises(ProfileBoundary):
            StateDB(bea_db)
        monkeypatch.delenv("PRAXIS_PRIME_WORKER_DATA")
        with pytest.raises(ProfileBoundary):
            StateDB(bea_db)
    finally:
        clear_worker_boundary()


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
        ran, _token_a = store.acquire("routine", "owner-a")
        assert ran == "run"
        skipped, _empty = store.acquire("routine", "owner-a")
        assert skipped == "skip"
        skipped, _empty = store.acquire("routine", "owner-b")
        assert skipped == "skip"
        clock["now"] = 31
        retry, token_b = store.acquire("routine", "owner-b")
        assert retry == "retry"
        clock["now"] = 62
        skipped, _empty = store.acquire("routine", "owner-c")
        assert skipped == "skip"
        assert store.release("routine", "owner-b", token_b)
        ran, _token_c = store.acquire("routine", "owner-c")
        assert ran == "run"
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
            "PRAXIS_PRIME_OIDC_SECRET_LOCAL": "oidc-secret-value",
            "PRAXIS_PRIME_OIDC_SECRET_WORK_TENANT": "oidc-secret-other",
        },
    )
    try:
        stripped = supervisor.worker_env("ada")
        assert "PRAXIS_PRIME_TELEGRAM_BOT_TOKEN" not in stripped
        assert "PRAXIS_PRIME_WORKER_MASTER" not in stripped
        assert "PRAXIS_PRIME_SECRETS_FILE" not in stripped
        assert "PRAXIS_PRIME_OIDC_SECRET_LOCAL" not in stripped
        assert "PRAXIS_PRIME_OIDC_SECRET_WORK_TENANT" not in stripped
        assert stripped["PRAXIS_PRIME_WORKER_PROFILE"] == "ada"
        supervisor.ensure("ada")
        child = json.loads(env_path.read_text(encoding="utf-8"))
        dumped = json.dumps(child)
        assert "telegram-token" not in dumped
        assert "should-not-pass" not in dumped
        assert "oidc-secret-value" not in dumped
        assert "oidc-secret-other" not in dumped
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
    assert store.destination("ada", "") is None
    assert store.may_decide(11, "ada", "acct-ada") is True
    assert store.may_decide(22, "ada", "acct-ada") is False
    assert store.may_decide(22, "", "") is False
    assert store.may_decide(22, "ada", "") is False
    assert store.may_decide(33, "ada", "acct-ada") is False
    assert store.may_decide(11, "bea", "") is False
    assert store.destination("", "") is None

    queue = ApprovalQueue(ttl=30)
    queue.profile_id = "ada"
    transport = _Transport()
    adapter = TelegramAdapter(transport, store, _Host(), queue)
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
        account = approval_account_id.set("acct-ada")
        try:
            queue.authorize(request)
        finally:
            approval_account_id.reset(account)

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


def test_upstream_short_reads_do_not_rescan_the_buffer():
    class Reader:
        def __init__(self) -> None:
            self.sent = 0

        def read1(self, n: int) -> bytes:
            del n
            if self.sent >= 400_000:
                return b""
            self.sent += 1
            return b"a"

    started = time.monotonic()
    with pytest.raises(ValueError, match="4MB"):
        list(iter_bounded(Reader(), limit=200_000))
    assert time.monotonic() - started < 1.0


def test_upstream_cap_counts_a_body_with_no_newlines():
    class Reader:
        def __init__(self) -> None:
            self.left = MAX_UPSTREAM_BYTES + 8

        def read(self, n: int) -> bytes:
            if self.left <= 0:
                return b""
            take = min(n, self.left)
            self.left -= take
            return b"a" * take

    with pytest.raises(ValueError, match="4MB"):
        list(iter_bounded(Reader()))


def test_upstream_refuses_redirects_oversized_bodies_and_deadlines(monkeypatch):
    monkeypatch.setattr("praxis_prime.upstream.MAX_UPSTREAM_BYTES", 32)
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


def test_upstream_lines_arrive_as_they_are_sent():
    for chunked in (True, False):
        url = _paced_upstream(chunked=chunked, count=5, gap=0.5)
        started = time.monotonic()
        arrivals = [
            time.monotonic() - started
            for line in open_lines(url, b"{}", {}, timeout=10, secrets=[], provider="p")
            if line.strip()
        ]
        assert len(arrivals) == 5
        assert arrivals[0] < 1.0
        assert arrivals[-1] - arrivals[0] > 1.5


def test_upstream_idle_timeout_allows_a_slow_healthy_stream():
    url = _paced_upstream(chunked=False, count=4, gap=0.4)
    lines = [
        line
        for line in open_lines(url, b"{}", {}, timeout=1, secrets=[], provider="p")
        if line.strip()
    ]
    assert len(lines) == 4


def test_peer_cred_rejects_a_different_uid(monkeypatch: pytest.MonkeyPatch):
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        assert same_user(left) is True
        current = os.getuid()
        monkeypatch.setattr("praxis_prime.supervisor.ipc.os.getuid", lambda: current + 1)
        assert same_user(right) is False
    finally:
        left.close()
        right.close()


def test_long_runtime_path_uses_a_private_socket_directory(tmp_path: Path):
    root = tmp_path / "data"
    create_profile(root, "ada")
    supervisor = Supervisor(
        data_root=root,
        runtime_dir=tmp_path / ("x" * 90) / "run",
        state_dir=tmp_path / "state",
        env=_child_env(),
        command=[sys.executable, str(_STUB)],
    )
    control = None
    try:
        supervisor.start()
        control = supervisor.control_path
        assert control.parent != Path("/tmp")
        assert not str(control).startswith("/tmp/pp-")
        assert control.parent.stat().st_mode & 0o777 == 0o700
        assert control.stat().st_mode & 0o777 == 0o600
        assert control.name.endswith("-supervisor.sock")
        ada = Path(str(control).replace("-supervisor.sock", "-ada.sock"))
        assert ada.exists()
        assert ada.stat().st_uid == os.getuid()
        assert ada.stat().st_mode & 0o777 == 0o600
        log = supervisor.ensure("ada").log_path
        assert log is not None
        assert log.stat().st_mode & 0o777 == 0o600
    finally:
        supervisor.close()
    assert control is not None
    assert not control.parent.exists()


def test_a_long_profile_id_does_not_stop_startup(tmp_path: Path):
    long_id = "p" + ("x" * 63)
    root = tmp_path / "data"
    create_profile(root, "ada")
    create_profile(root, long_id)
    token = os.urandom(4).hex()
    runtime = Path("/tmp") / f"r48-{token}-{'y' * 30}"
    assert len(str(runtime)) == 48
    supervisor = Supervisor(
        data_root=root,
        runtime_dir=runtime,
        state_dir=tmp_path / "state",
        env=_child_env(),
        command=[sys.executable, str(_STUB)],
        start_timeout=30,
    )
    chosen = None
    try:
        chosen = supervisor._socket_directory()
        from praxis_prime.supervisor.supervisor import _SOCKET_PATH_MAX, _socket_basename

        sock = chosen / _socket_basename(chosen, supervisor._sock_tag, long_id)
        assert len(os.fsencode(sock)) <= _SOCKET_PATH_MAX
        supervisor.start()
        assert supervisor.call("ada", "memory.list")["entries"] == []
        assert supervisor.call(long_id, "memory.list")["entries"] == []
    finally:
        supervisor.close()
        if runtime.exists():
            for child in runtime.iterdir():
                if child.is_file():
                    child.unlink()
            runtime.rmdir()
    assert chosen is not None
    assert not chosen.exists()


def test_stale_socket_directory_is_removed_on_start(tmp_path: Path):
    import tempfile

    stale = Path(tempfile.mkdtemp(prefix="praxis-prime-socks-"))
    os.chmod(stale, 0o700)
    (stale / "deadbeef-supervisor.sock").write_bytes(b"")
    aged = time.time() - 60
    os.utime(stale, (aged, aged))
    supervisor = _supervisor(tmp_path, names=("ada",))
    try:
        supervisor.start()
        assert not stale.exists()
        assert not (supervisor.runtime_dir / "socket-dir").exists()
    finally:
        supervisor.close()


def test_a_listening_socket_directory_is_kept(tmp_path: Path):
    runtime = tmp_path / ("x" * 90) / "run"
    first = Supervisor(
        data_root=tmp_path / "data-a",
        runtime_dir=runtime,
        state_dir=tmp_path / "state-a",
        env=_child_env(),
        command=[sys.executable, str(_STUB)],
    )
    create_profile(tmp_path / "data-a", "ada")
    second = _supervisor(tmp_path, names=("ada",))
    try:
        first.start()
        live = first._socket_dir
        assert live is not None and live != runtime
        second.start()
        assert live.exists()
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(1)
        probe.connect(str(first.control_path))
        probe.close()
    finally:
        second.close()
        first.close()


def test_worker_spawned_from_a_short_lived_thread_stays_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _isolate(tmp_path, monkeypatch)
    root = tmp_path / "data" / "praxis-prime"
    create_profile(root, "ada")
    create_profile(root, "bea")
    supervisor = Supervisor(
        data_root=root,
        runtime_dir=tmp_path / "run",
        state_dir=tmp_path / "state",
        env=_child_env(),
        start_timeout=60,
    )
    try:
        supervisor.start()
        supervisor.call("bea", "memory.list")
        errors: list[BaseException] = []

        def spawn() -> None:
            try:
                supervisor.call("ada", "memory.list")
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=spawn)
        thread.start()
        thread.join(60)
        assert not thread.is_alive()
        assert errors == []
        ada = supervisor._slots["ada"].process
        bea = supervisor._slots["bea"].process
        assert ada is not None and bea is not None
        ada_pid = ada.pid
        time.sleep(1.5)
        assert ada.poll() is None
        assert bea.poll() is None
        state = Path(f"/proc/{ada_pid}/stat").read_text(encoding="utf-8")
        assert state.rsplit(")", 1)[1].split()[0] != "Z"
        assert supervisor.call("ada", "memory.list")["entries"] == []
        assert supervisor._slots["ada"].failures == 0
        assert supervisor._slots["ada"].process is not None
        assert supervisor._slots["ada"].process.pid == ada_pid
    finally:
        supervisor.close()


def test_stale_lock_reap_checks_supervisor_start_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from praxis_prime.worker import _process_start, _reap_stale_holder

    monkeypatch.setenv("PRAXIS_PRIME_SUPERVISOR_TOKEN", "token")
    lock = tmp_path / "worker.lock"
    holder_code = textwrap.dedent(
        """
        import fcntl, os, sys, time
        fd = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, f"{os.getpid()} {sys.argv[2]}\\n".encode())
        print("held", flush=True)
        time.sleep(30)
        """
    )

    def hold(rest: str) -> subprocess.Popen[str]:
        proc = subprocess.Popen(
            [sys.executable, "-c", holder_code, str(lock), rest],
            stdout=subprocess.PIPE,
            text=True,
        )
        assert proc.stdout is not None
        assert proc.stdout.readline().strip() == "held"
        return proc

    started = _process_start(os.getpid())
    assert started
    kept = hold(f"{os.getpid()} {started} token")
    try:
        assert _reap_stale_holder(lock) is False
        assert kept.poll() is None
    finally:
        kept.kill()
        kept.wait(timeout=5)

    forged = hold(f"{os.getpid()} {started} other-token")
    try:
        # A different token belongs to another live supervisor. Do not kill it.
        assert _reap_stale_holder(lock) is False
        assert forged.poll() is None
    finally:
        forged.kill()
        forged.wait(timeout=5)

    mismatched = hold(f"{os.getpid()} 1 token")
    assert _reap_stale_holder(lock) is True
    mismatched.wait(timeout=5)
    assert mismatched.returncode is not None

    other = subprocess.Popen(["sleep", "30"])
    try:
        reused = hold(str(other.pid))
        assert _reap_stale_holder(lock) is True
        reused.wait(timeout=5)
        assert other.poll() is None
    finally:
        other.kill()
        other.wait(timeout=5)

    dead = subprocess.Popen(["true"])
    dead.wait(timeout=5)
    stale = hold(str(dead.pid))
    assert _reap_stale_holder(lock) is True
    stale.wait(timeout=5)


def test_session_owner_asks_running_workers_before_idle_ones(tmp_path: Path):
    from praxis_prime.policy.engine import PolicyEngine
    from praxis_prime.router.settings import load_settings

    supervisor = _supervisor(
        tmp_path,
        names=("ada", "bea"),
        env_extra={
            "STUB_SESSION_ID": "sess-ada",
            "STUB_SESSION_PROFILE": "ada",
            "STUB_SESSION_ACCOUNT": "acct-ada",
        },
    )
    host = RoutingHost(supervisor, PolicyEngine({}), load_settings({}))
    try:
        supervisor.start()
        supervisor.ensure("ada")
        assert host.session_owner("sess-ada") == ("acct-ada", "ada")
        assert set(supervisor.running()) == {"ada"}
        assert host.session_owner("missing-session") is None
    finally:
        supervisor.close()


def test_session_owner_wakes_an_idle_profile(tmp_path: Path):
    from praxis_prime.policy.engine import PolicyEngine
    from praxis_prime.router.settings import load_settings

    supervisor = _supervisor(
        tmp_path,
        names=("ada", "bea"),
        env_extra={
            "STUB_SESSION_ID": "sess-bea",
            "STUB_SESSION_PROFILE": "bea",
            "STUB_SESSION_ACCOUNT": "acct-bea",
        },
    )
    host = RoutingHost(supervisor, PolicyEngine({}), load_settings({}))
    try:
        supervisor.start()
        supervisor.ensure("ada")
        assert set(supervisor.running()) == {"ada"}
        assert host.session_owner("sess-bea") == ("acct-bea", "bea")
        assert "bea" in supervisor.running()
        host.drop_session("sess-bea", account_id="acct-bea")
    finally:
        supervisor.close()


def test_approval_profile_keeps_the_first_writer(tmp_path: Path):
    supervisor = _supervisor(tmp_path, names=("ada", "bea"))
    try:
        supervisor.note_approval("ada", "ap_same")
        supervisor.note_approval("bea", "ap_same")
        assert supervisor.approval_profile("ap_same") == "ada"
    finally:
        supervisor.close()


def test_generation_bump_rejects_an_open_control_connection(tmp_path: Path):
    supervisor = _supervisor(tmp_path, names=("ada",))
    try:
        supervisor.start()
        slot = supervisor.ensure("ada")
        live = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        live.settimeout(3)
        live.connect(str(supervisor.control_path))
        send_message(
            live,
            {
                "id": "1",
                "method": "auth",
                "profile": "ada",
                "generation": slot.generation,
                "token": slot.credential,
            },
        )
        assert recv_message(live).get("ok") is True
        supervisor.bump("ada")
        send_message(live, {"id": "g", "method": "grant.check", "account": "acct-x"})
        assert recv_message(live).get("ok") is False
        send_message(
            live,
            {
                "id": "e",
                "method": "event",
                "kind": "approval",
                "body": {"approval": {"id": "ap_after_bump"}},
            },
        )
        assert recv_message(live).get("ok") is False
        assert supervisor.approval_profile("ap_after_bump") == ""
        fresh = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        fresh.settimeout(3)
        fresh.connect(str(supervisor.control_path))
        send_message(
            fresh,
            {
                "id": "1",
                "method": "auth",
                "profile": "ada",
                "generation": 1,
                "token": slot.credential,
            },
        )
        assert recv_message(fresh).get("ok") is False
        fresh.close()
        live.close()
    finally:
        supervisor.close()


def test_derive_rejects_a_profile_that_is_not_an_id():
    master = os.urandom(32)
    ada = derive(master, "ada", 12)
    with pytest.raises(CredentialError):
        derive(master, "ada:1", 2)
    assert ada != derive(master, "ada", 1)


def test_generation_bumps_are_not_lost_across_threads(tmp_path: Path):
    path = tmp_path / "worker-generations.json"
    profiles = [f"p{i}" for i in range(16)]

    def bump(profile: str) -> None:
        for _ in range(20):
            bump_generation(path, profile)

    threads = [threading.Thread(target=bump, args=(profile,)) for profile in profiles]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    final = load_generations(path)
    assert final == {profile: 21 for profile in profiles}


def test_corrupt_generations_file_does_not_revive_a_credential(tmp_path: Path):
    path = tmp_path / "worker-generations.json"
    path.write_text("{corrupt", encoding="utf-8")
    with pytest.raises(CredentialError, match="corrupt"):
        generation_for(path, "ada")
    supervisor = _supervisor(tmp_path, names=("ada",))
    try:
        supervisor.start()
        slot = supervisor.ensure("ada")
        token = slot.credential
        supervisor.generation_path.write_text("{corrupt", encoding="utf-8")
        reply = _rpc(supervisor.control_path, "ada", token, "health", {})
        assert reply.get("ok") is False
    finally:
        supervisor.close()


def test_bad_m1c_marker_names_the_problem(tmp_path: Path):
    for label, content, match in (
        ("corrupt", "{oops", "corrupt"),
        ("empty", "", "empty"),
        ("future", json.dumps({"version": 2}), "not supported"),
        ("bool", json.dumps({"version": True}), "corrupt"),
    ):
        root = tmp_path / label
        (root / "supervisor").mkdir(parents=True)
        marker_path(root).write_text(content, encoding="utf-8")
        with pytest.raises(MigrationError, match=match):
            migrate_install(root)


def test_corrupt_marker_is_not_reported_as_bind_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    _isolate(tmp_path, monkeypatch)
    from praxis_prime.gateway.discover import log_path
    from praxis_prime.paths import data_dir

    root = data_dir()
    create_profile(root, "ada")
    marker = marker_path(root)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("{oops", encoding="utf-8")
    assert serve(stop=threading.Event(), listen="127.0.0.1:0") == 1
    assert "m1c marker is corrupt" in capsys.readouterr().err
    logged = log_path().read_text(encoding="utf-8")
    assert "migration_failed" in logged
    assert "bind_failed" not in logged


def test_older_m1c_marker_stays_applied_when_the_version_advances(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr("praxis_prime.supervisor.migrate._VERSION", 2)
    root = tmp_path / "data"
    (root / "supervisor").mkdir(parents=True)
    marker_path(root).write_text(json.dumps({"version": 1}), encoding="utf-8")
    assert migrate_install(root) is False


def test_lease_renewal_keeps_a_long_run_from_being_retried(tmp_path: Path):
    db = StateDB(tmp_path / "prime.db")
    try:
        clock = {"now": 0.0}
        store = LeaseStore(db, clock=lambda: clock["now"], ttl=30)
        ran, token = store.acquire("routine", "owner-a")
        assert ran == "run"
        clock["now"] = 20
        assert store.renew("routine", "owner-a", token) is True
        assert store.renew("routine", "owner-b", token) is False
        assert store.renew("missing", "owner-a", token) is False
        clock["now"] = 49
        skipped, _empty = store.acquire("routine", "owner-b")
        assert skipped == "skip"
        clock["now"] = 50
        assert store.renew("routine", "owner-a", token) is False
        retry, _token_b = store.acquire("routine", "owner-b")
        assert retry == "retry"
        clock["now"] = 81
        skipped, _empty = store.acquire("routine", "owner-c")
        assert skipped == "skip"
    finally:
        db.close()


def test_reboot_clock_still_allows_one_lease_retry(tmp_path: Path):
    db = StateDB(tmp_path / "prime.db")
    try:
        clock = {"now": 864000.0}
        first = LeaseStore(db, clock=lambda: clock["now"])
        ran, _token = first.acquire("rt_00000001", "pid100")
        assert ran == "run"
        second = LeaseStore(db, clock=lambda: 60.0)
        retry, _token = second.acquire("rt_00000001", "pid200")
        assert retry == "retry"
        later = LeaseStore(db, clock=lambda: 864040.0)
        skipped, _empty = later.acquire("rt_00000001", "pid200")
        assert skipped == "skip"
        ran, _token = later.acquire("rt_00000002", "pid200")
        assert ran == "run"
        skipped, _empty = later.acquire("rt_00000002", "pid200")
        assert skipped == "skip"
    finally:
        db.close()


def test_worker_master_key_is_on_the_read_denylist():
    assert "worker-master.key" in _EXACT_NAMES
    assert "worker-master.key" in _FILE_ROOT_NAMES


def test_a_killed_supervisor_does_not_leave_its_worker(tmp_path: Path):
    script = textwrap.dedent(
        """
        import os, sys, time
        from praxis_prime.paths import data_dir
        from praxis_prime.profiles.home import create_profile
        from praxis_prime.supervisor.supervisor import Supervisor
        root = data_dir()
        if not (root / "profiles" / "ada").exists():
            create_profile(root, "ada")
        env = os.environ.copy()
        sup = Supervisor(
            data_root=root,
            runtime_dir=root.parent / "run",
            state_dir=root.parent / "state",
            env=env,
            start_timeout=30,
            backoff_cap=2,
        )
        sup.start()
        try:
            sup.call("ada", "memory.list")
            print("PID", sup._slots["ada"].process.pid, flush=True)
        except Exception as exc:
            print("START_FAIL", type(exc).__name__, exc, flush=True)
            log = root.parent / "state" / "worker-ada.log"
            if log.is_file():
                print(log.read_text(encoding="utf-8")[-800:], flush=True)
        time.sleep(float(sys.argv[1]))
        sup.close()
        """
    )
    child = tmp_path / "child.py"
    child.write_text(script, encoding="utf-8")
    env = _child_env(
        {
            "XDG_DATA_HOME": str(tmp_path / "xdg-data"),
            "XDG_CONFIG_HOME": str(tmp_path / "xdg-config"),
            "XDG_STATE_HOME": str(tmp_path / "xdg-state"),
            "XDG_RUNTIME_DIR": str(tmp_path / "xdg-run"),
            "HOME": str(tmp_path / "home"),
        }
    )
    first = subprocess.Popen(
        [sys.executable, str(child), "60"],
        stdout=subprocess.PIPE,
        text=True,
        env=env,
    )
    assert first.stdout is not None
    line = first.stdout.readline().strip()
    assert line.startswith("PID "), line
    worker_pid = int(line.split()[1])
    first.send_signal(signal.SIGKILL)
    first.wait(timeout=5)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and Path(f"/proc/{worker_pid}").exists():
        time.sleep(0.1)
    assert not Path(f"/proc/{worker_pid}").exists()
    second = subprocess.run(
        [sys.executable, str(child), "2"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    assert second.returncode == 0, second.stderr
    assert second.stdout.startswith("PID "), second.stdout + second.stderr
    assert not Path(f"/proc/{worker_pid}").exists()


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
    """A short body. The cap test lowers the limit so this stays off the wire's 4 MiB path."""

    def do_POST(self) -> None:
        body = b"a\n" * 40
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
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


def _paced_upstream(*, chunked: bool, count: int, gap: float) -> str:
    """Serve ``count`` lines ``gap`` seconds apart, chunked or closed at EOF."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]

    def run() -> None:
        conn, _addr = sock.accept()
        try:
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += conn.recv(65536)
            while not buf.endswith(b"{}"):
                buf += conn.recv(65536)
            header = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            if chunked:
                header += b"Transfer-Encoding: chunked\r\n\r\n"
            else:
                header += b"Connection: close\r\n\r\n"
            conn.sendall(header)
            for index in range(count):
                line = f"data: token{index}\n".encode()
                if chunked:
                    conn.sendall(b"%x\r\n" % len(line) + line + b"\r\n")
                else:
                    conn.sendall(line)
                time.sleep(gap)
            if chunked:
                conn.sendall(b"0\r\n\r\n")
        finally:
            conn.close()
            sock.close()

    threading.Thread(target=run, daemon=True).start()
    return f"http://127.0.0.1:{port}/"


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

