"""Inode cap, login audit order, auth.fail flush, and decide session ids."""

from __future__ import annotations

import json
import os
import queue
import sqlite3
import threading
import time
from pathlib import Path

import pytest
from tests.fakes import ScriptedProvider
from tests.test_accounts import _login, _request
from tests.test_review_fixes import _PRIMARY, _SECOND, _account, _login_body

from praxis_prime.accounts.db import AccountStore
from praxis_prime.approvals.gate import ApprovalRequest, approval_session_id
from praxis_prime.approvals.queue import ApprovalQueue
from praxis_prime.audit.log import AuditLog
from praxis_prime.gateway.authz import Principal, login
from praxis_prime.gateway.server import GatewayServer
from praxis_prime.host import Host
from praxis_prime.observe import JsonLogger
from praxis_prime.policy.boundary import (
    ReadDenied,
    bind_data_root,
    clear_data_inode_cache,
    data_inode_scans,
)
from praxis_prime.profiles.home import create_profile
from praxis_prime.router.types import AssistantFinal
from praxis_prime.runtime import build_runtime
from praxis_prime.state import StateDB
from praxis_prime.tools.builtin import execute_read_file
from praxis_prime.tools.registry import Risk, ToolContext


def test_inode_cap_does_not_call_every_file_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    share = home / ".local" / "share"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(share))
    private = share / "praxis-prime"
    folder = private / "profiles" / "bulk"
    folder.mkdir(parents=True)
    (folder / "SOUL.md").write_text("secret\n", encoding="utf-8")
    # The production cap is 20_000. A lower cap hits the same branch without
    # spending tens of thousands of inodes.
    monkeypatch.setattr("praxis_prime.policy.boundary._PRIVATE_INODE_CAP", 8)
    for index in range(12):
        os.close(os.open(folder / f"f{index}", os.O_CREAT | os.O_WRONLY, 0o600))
    (home / "hello.txt").write_text("hi\n", encoding="utf-8")
    bind_data_root(None)
    clear_data_inode_cache()
    context = ToolContext(cwd=str(home), cancelled=lambda: False)
    before = data_inode_scans()
    assert "hi" in execute_read_file({"path": "hello.txt"}, context)
    assert "hi" in execute_read_file({"path": "hello.txt"}, context)
    assert data_inode_scans() == before + 1
    with pytest.raises(ReadDenied, match="could not scan the account data directory") as caught:
        execute_read_file(
            {"path": ".local/share/praxis-prime/profiles/bulk/SOUL.md"},
            context,
        )
    assert caught.value.code == "data_dir_unscanned"
    assert "secret file" not in str(caught.value)
    assert "more than 8 files" in str(caught.value)
    assert data_inode_scans() == before + 1
    bind_data_root(None)
    clear_data_inode_cache()


def test_unreadable_data_subdir_does_not_deny_other_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    share = home / ".local" / "share"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(share))
    private = share / "praxis-prime"
    (private / "profiles" / "work").mkdir(parents=True)
    (private / "profiles" / "work" / "SOUL.md").write_text("secret\n", encoding="utf-8")
    (private / "profiles" / "hidden").mkdir()
    (home / "hello.txt").write_text("hi\n", encoding="utf-8")
    real = os.scandir

    def denied(path: os.PathLike[str] | str) -> object:
        if Path(path).name == "hidden":
            raise PermissionError(13, "denied", str(path))
        return real(path)

    monkeypatch.setattr(os, "scandir", denied)
    bind_data_root(None)
    clear_data_inode_cache()
    context = ToolContext(cwd=str(home), cancelled=lambda: False)
    assert "hi" in execute_read_file({"path": "hello.txt"}, context)
    with pytest.raises(ReadDenied, match="unreadable directory") as unreadable:
        execute_read_file(
            {"path": ".local/share/praxis-prime/profiles/work/SOUL.md"},
            context,
        )
    assert unreadable.value.code == "data_dir_unscanned"
    assert "secret file" not in str(unreadable.value)
    bind_data_root(None)
    clear_data_inode_cache()


def test_login_audits_before_opening_a_session(tmp_path: Path) -> None:
    store = AccountStore(tmp_path / "accounts.db")
    _account(store, "ada", _PRIMARY, display_name="Ada")
    db = StateDB(tmp_path / "prime.db")
    audit = AuditLog(db)
    locker = sqlite3.connect(db.path)
    locker.execute("BEGIN IMMEDIATE")
    try:
        status, payload, _headers = login(store, _login_body("ada", _PRIMARY), audit)
        assert status == 503
        error = payload["error"]
        assert isinstance(error, dict)
        assert error["code"] == "unavailable"
        assert _session_count(store) == 0
        status, _payload, _headers = login(store, _login_body("ada", "not-the-password"), audit)
        assert status == 503
        assert _session_count(store) == 0
    finally:
        locker.rollback()
        locker.close()
        audit.close()
        db.close()
        store.close()
    store = AccountStore(tmp_path / "accounts.db")
    db = StateDB(tmp_path / "prime.db")
    audit = AuditLog(db)
    try:
        status, payload, _headers = login(store, _login_body("ada", _PRIMARY), audit)
        assert status == 200
        assert payload["ok"] is True
        assert _session_count(store) == 1
    finally:
        audit.close()
        db.close()
        store.close()


def test_auth_fail_summary_flushes_on_close(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "prime.db")
    audit = AuditLog(db)
    try:
        for _ in range(3):
            audit.append(
                session_id=None,
                kind="auth.fail",
                summary="login failed",
                payload={"username": "ada", "ip": "127.0.0.1"},
            )
        assert audit.verify()
    finally:
        audit.close()
    rows = db.conn.execute(
        "SELECT kind, payload_json FROM audit_events ORDER BY id"
    ).fetchall()
    db.close()
    kinds = [str(row["kind"]) for row in rows]
    assert kinds == ["auth.fail", "auth.fail.summary"]
    summary = json.loads(rows[1]["payload_json"])
    assert summary["suppressed"] == 2
    assert "password" not in rows[1]["payload_json"]


def test_decide_hides_a_foreign_session_id(tmp_path: Path) -> None:
    data = tmp_path / "data"
    create_profile(data, "work")
    store = AccountStore(data / "accounts.db")
    ada = _account(store, "ada", _PRIMARY, display_name="Ada")
    bea = _account(store, "bea", _SECOND, display_name="Bea", role="operator")
    store.set_membership(ada.id, "work", "owner")
    store.set_membership(bea.id, "work", "operator")
    runtime = build_runtime(
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=data / "unused.db",
        cwd=tmp_path,
        profile="work",
        providers={"ollama": ScriptedProvider([AssistantFinal(content="ok")])},
    )
    session_id = runtime.store.create(model="fake", preamble="", owner_account=ada.id)
    host = Host(runtime, ApprovalQueue(ttl=5))
    host.queue.profile_id = runtime.profile_id
    server = GatewayServer(
        host="127.0.0.1",
        port=0,
        token="test-token",
        agent=host,
        approvals=host.queue,
        logger=JsonLogger(tmp_path / "daemon.log"),
        accounts=store,
        audit=runtime.audit,
        data_root=data,
    )
    server.start()
    threads: list[threading.Thread] = []
    try:
        first = _pending(host, session_id, threads)
        cookie, csrf, _body = _login(server.bound_port, "bea", _SECOND)
        status, _headers, body = _request(
            server.bound_port,
            "POST",
            f"/v1/approvals/{first}",
            cookie=cookie,
            csrf=csrf,
            body_json={"decision": "deny"},
        )
        assert status == 200
        assert body["approval"]["sessionId"] == ""
        second = _pending(host, session_id, threads)
        principal = Principal(
            kind="session",
            account_id=bea.id,
            username="bea",
            role="operator",
        )
        outgoing: queue.Queue[dict[str, object] | None] = queue.Queue()
        server._decide(
            {
                "id": "d1",
                "payload": {"approvalId": second, "decision": "deny", "profile": "work"},
            },
            principal,
            outgoing,
        )
        frame = outgoing.get(timeout=2)
        assert frame is not None
        payload = frame["payload"]
        assert isinstance(payload, dict)
        assert payload["approval"]["sessionId"] == ""
        third = _pending(host, session_id, threads)
        cookie, csrf, _body = _login(server.bound_port, "ada", _PRIMARY)
        status, _headers, body = _request(
            server.bound_port,
            "POST",
            f"/v1/approvals/{third}",
            cookie=cookie,
            csrf=csrf,
            body_json={"decision": "deny"},
        )
        assert status == 200
        assert body["approval"]["sessionId"] == session_id
    finally:
        host.queue.deny_all(actor="test")
        for thread in threads:
            thread.join(timeout=2)
        server.shutdown()
        runtime.close()
        store.close()


def _pending(host: Host, session_id: str, threads: list[threading.Thread]) -> str:
    request = ApprovalRequest(
        tool="shell",
        risk=Risk.READ,
        reason="read",
        summary="echo hi",
        arguments={"command": "echo hi"},
        grant_key=f"echo-{len(threads)}",
        sandboxed=True,
    )

    def block() -> None:
        token = approval_session_id.set(session_id)
        try:
            host.queue.authorize(request)
        finally:
            approval_session_id.reset(token)

    known = {str(item["id"]) for item in host.queue.list_pending()}
    thread = threading.Thread(target=block)
    thread.start()
    threads.append(thread)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        pending = host.queue.list_pending()
        fresh = [item for item in pending if str(item["id"]) not in known]
        if fresh:
            return str(fresh[0]["id"])
        time.sleep(0.02)
    raise AssertionError("approval was not queued")


def _session_count(store: AccountStore) -> int:
    row = store.conn.execute("SELECT COUNT(*) FROM sessions").fetchone()
    assert row is not None
    return int(row[0])
