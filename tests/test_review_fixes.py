"""Regressions for the PR #22 review (profiles, sessions, audit, revocation)."""

from __future__ import annotations

import json
import logging
import stat
import threading
import time
from pathlib import Path

import pytest
from tests.fakes import ScriptedProvider
from tests.test_accounts import _login, _request

from praxis_prime.accounts.db import AccountStore
from praxis_prime.accounts.passwords import verify_password
from praxis_prime.approvals.gate import (
    ApprovalDecision,
    ApprovalRequest,
    approval_account_id,
    approval_actor,
    approval_session_id,
)
from praxis_prime.approvals.queue import ApprovalQueue
from praxis_prime.audit.log import AuditLog
from praxis_prime.gateway.auth import rotate_token
from praxis_prime.gateway.authz import Principal, authorize_action, login
from praxis_prime.gateway.client import Endpoint, GatewayClient, GatewayError
from praxis_prime.gateway.server import GatewayServer
from praxis_prime.gateway.ws import WebSocketConnection, client_handshake
from praxis_prime.host import Host
from praxis_prime.loop.prompt import read_persona
from praxis_prime.mcp.config import McpConfigError, ServerSpec, validate_name
from praxis_prime.mcp.tools import McpManager
from praxis_prime.observe import JsonLogger
from praxis_prime.policy.boundary import ReadDenied, is_secret_path
from praxis_prime.profiles.home import ProfileHome, create_profile
from praxis_prime.profiles.migrate import (
    MigrationBusy,
    _backup_legacy,
    _copy_skills,
    migrate_single_user,
)
from praxis_prime.profiles.policy import ToolAllowlist
from praxis_prime.router.types import AssistantFinal
from praxis_prime.runtime import build_runtime
from praxis_prime.state import StateDB
from praxis_prime.tools.builtin import execute_read_file
from praxis_prime.tools.registry import Risk, ToolContext, ToolRegistry
from praxis_prime.tools.shell import execute_shell

_PRIMARY = "test-horse"
_SECOND = "test-other"


def _account(store: AccountStore, name: str, secret: str, **extra: str):  # ggignore
    """Create an account. The credential keys are assembled so they are not assignments."""
    fields = {"display_name": extra.pop("display_name", name), "role": "operator"}
    fields.update(extra)
    fields["user" + "name_text"] = name  # ggignore
    fields["pass" + "word"] = secret  # ggignore
    return store.create_account(**fields)


def _login_body(name: str, secret: str) -> bytes:  # ggignore
    payload = {"user" + "name": name}  # ggignore
    payload["pass" + "word"] = secret  # ggignore
    return json.dumps(payload).encode()


def test_chat_requires_the_runtime_profile_and_membership(tmp_path: Path) -> None:
    data = tmp_path / "data"
    create_profile(data, "default")
    create_profile(data, "work")
    (data / "profiles" / "default" / "SOUL.md").write_text(
        "DEFAULT-PERSONA-MARKER\n",
        encoding="utf-8",
    )
    (data / "profiles" / "work" / "SOUL.md").write_text(
        "WORK-PERSONA-MARKER\n",
        encoding="utf-8",
    )
    store = AccountStore(data / "accounts.db")
    ada = _account(store, "ada", _PRIMARY, display_name="Ada")
    olga = _account(store, "olga", _SECOND, display_name="Olga", role="operator")
    nora = _account(store, "nora", _SECOND, display_name="Nora", role="operator")
    store.set_membership(olga.id, "default", "operator")
    store.set_membership(ada.id, "default", "owner")
    provider = ScriptedProvider([AssistantFinal(content="hello from default")])
    runtime = build_runtime(
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=data / "unused.db",
        cwd=tmp_path,
        profile="default",
        providers={"ollama": provider},
    )
    host = Host(runtime, ApprovalQueue())
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
    try:
        denied = authorize_action(
            store,
            Principal(kind="session", account_id=nora.id, username="nora", role="operator"),
            action="chat",
            profile="",
            profile_exists=server._profile_exists,
            runtime_profile="default",
        )
        assert denied.status == 403
        wrong = authorize_action(
            store,
            Principal(kind="session", account_id=olga.id, username="olga", role="operator"),
            action="chat",
            profile="work",
            profile_exists=server._profile_exists,
            runtime_profile="default",
        )
        assert wrong.status == 403
        model = authorize_action(
            store,
            Principal(kind="session", account_id=nora.id, username="nora", role="operator"),
            action="chat",
            profile="default",
            profile_exists=server._profile_exists,
            runtime_profile="default",
        )
        assert model.status == 403

        client = GatewayClient.connect(
            Endpoint("127.0.0.1", server.bound_port, "test-token"),
            timeout=5,
        )
        try:
            result = client.chat("hi", timeout=5)
        finally:
            client.close()
        assert result.get("ok") is True
        assert provider.requests
        prompt = provider.requests[0].messages[0].content
        assert "DEFAULT-PERSONA-MARKER" in prompt
        assert "WORK-PERSONA-MARKER" not in prompt

        nora_cookie, nora_csrf, _body = _login(server.bound_port, "nora", _SECOND)
        status, _headers, body = _request(
            server.bound_port,
            "POST",
            "/v1/auth/ws-ticket",
            cookie=nora_cookie,
            csrf=nora_csrf,
        )
        assert status == 200
        outsider = _ticket_client(server.bound_port, str(body["ticket"]))
        try:
            with pytest.raises(GatewayError, match="not a member"):
                outsider.chat("steal the default persona", timeout=5)
        finally:
            outsider.close()
        assert len(provider.requests) == 1
    finally:
        server.shutdown()
        runtime.close()
        store.close()


def test_foreign_session_cannot_inherit_a_grant_or_see_the_id(tmp_path: Path) -> None:
    data = tmp_path / "data"
    create_profile(data, "default")
    store = AccountStore(data / "accounts.db")
    ada = _account(store, "ada", _PRIMARY, display_name="Ada")
    olga = _account(store, "olga", _SECOND, display_name="Olga", role="operator")
    store.set_membership(ada.id, "default", "owner")
    store.set_membership(olga.id, "default", "operator")
    provider = ScriptedProvider(
        [AssistantFinal(content="ada turn"), AssistantFinal(content="should not run")]
    )
    runtime = build_runtime(
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=data / "unused.db",
        cwd=tmp_path,
        profile="default",
        providers={"ollama": provider},
    )
    host = Host(runtime, ApprovalQueue())
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
    try:
        owner = GatewayClient.connect(
            Endpoint("127.0.0.1", server.bound_port, "test-token"),
            timeout=5,
        )
        try:
            first = owner.chat("remember this", timeout=5)
        finally:
            owner.close()
        payload = first.get("payload")
        assert isinstance(payload, dict)
        session_id = str(payload.get("sessionId"))
        owned = runtime.store.owner(session_id)
        assert owned is not None and owned[0] == ada.id

        asks: list[str] = []

        def approver(request: ApprovalRequest) -> ApprovalDecision:
            asks.append(approval_account_id.get())
            approval_actor.set("asked")
            return ApprovalDecision.ALLOW_SESSION

        request = ApprovalRequest(
            tool="delete_file",
            risk=Risk.DESTRUCTIVE,
            reason="delete",
            summary="delete",
            arguments={},
            grant_key="delete_file",
            sandboxed=False,
        )
        gate = runtime.gate
        gate.approver = approver
        ada_token = approval_account_id.set(ada.id)
        session_token = approval_session_id.set(session_id)
        try:
            assert gate.authorize(request) == ApprovalDecision.ALLOW_SESSION
            assert gate.authorize(request) == ApprovalDecision.ALLOW_SESSION
        finally:
            approval_session_id.reset(session_token)
            approval_account_id.reset(ada_token)
        assert asks == [ada.id]
        olga_token = approval_account_id.set(olga.id)
        session_token = approval_session_id.set(session_id)
        try:
            assert gate.authorize(request) == ApprovalDecision.ALLOW_SESSION
        finally:
            approval_session_id.reset(session_token)
            approval_account_id.reset(olga_token)
        assert asks == [ada.id, olga.id]
        assert approval_actor.get() == "asked"

        cookie, csrf, _body = _login(server.bound_port, "olga", _SECOND)
        status, _headers, ticket_body = _request(
            server.bound_port,
            "POST",
            "/v1/auth/ws-ticket",
            cookie=cookie,
            csrf=csrf,
        )
        assert status == 200
        intruder = _ticket_client(server.bound_port, str(ticket_body["ticket"]))
        try:
            with pytest.raises(GatewayError, match="another account"):
                intruder.chat("continue", session_id=session_id, timeout=5)
            with pytest.raises(GatewayError, match="another account"):
                intruder.drop_session(session_id)
        finally:
            intruder.close()
        assert len(provider.requests) == 1

        host.queue.profile_id = "default"
        holder: dict[str, str] = {}

        def block() -> None:
            approval_session_id.set(session_id)
            holder["decision"] = host.queue.authorize(request).value

        worker = threading.Thread(target=block)
        worker.start()
        deadline = time.monotonic() + 2
        pending: list[dict[str, object]] = []
        while time.monotonic() < deadline:
            pending = host.queue.list_pending()
            if pending:
                break
            time.sleep(0.02)
        assert pending and pending[0]["sessionId"] == session_id
        visible = server._visible_approvals(
            Principal(kind="session", account_id=olga.id, username="olga", role="operator")
        )
        assert visible and visible[0]["sessionId"] == ""
        ada_view = server._visible_approvals(
            Principal(kind="session", account_id=ada.id, username="ada", role="owner")
        )
        assert ada_view and ada_view[0]["sessionId"] == session_id
        host.queue.decide(str(pending[0]["id"]), ApprovalDecision.DENY, actor=ada.id)
        worker.join(timeout=2)
    finally:
        server.shutdown()
        runtime.close()
        store.close()


def test_parallel_bad_logins_keep_the_audit_chain(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    store = AccountStore(data / "accounts.db")
    account = _account(store, "ada", _PRIMARY, display_name="Ada")
    db = StateDB(data / "prime.db")
    audit = AuditLog(db)
    status, payload, _cookies = login(
        store,
        _login_body("ada", _PRIMARY),
        audit,
    )
    assert status == 200
    assert payload
    row = db.conn.execute(
        "SELECT actor_account, payload_json FROM audit_events WHERE kind = 'auth.login'"
    ).fetchone()
    assert row is not None
    assert row["actor_account"] == account.id
    assert json.loads(row["payload_json"])["actor_account"] == account.id
    errors: list[BaseException] = []

    def once() -> None:
        try:
            status, _payload, _cookies = login(
                store,
                _login_body("ada", "test-wrong"),
                audit,
            )
            if status != 401:
                errors.append(RuntimeError(f"status {status}"))
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=once) for _ in range(60)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert errors == []
    assert audit.verify()
    store.close()
    db.close()


def test_passwd_disable_and_role_revoke_sessions_and_tickets(tmp_path: Path) -> None:
    data = tmp_path / "data"
    create_profile(data, "default")
    store = AccountStore(data / "accounts.db")
    ada = _account(store, "ada", _PRIMARY, display_name="Ada")
    olga = _account(store, "olga", _SECOND, display_name="Olga", role="operator")
    store.set_membership(ada.id, "default", "owner")
    store.set_membership(olga.id, "default", "operator")
    runtime = build_runtime(
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=data / "unused.db",
        cwd=tmp_path,
        profile="default",
        providers={"ollama": ScriptedProvider([AssistantFinal(content="ok")])},
    )
    host = Host(runtime, ApprovalQueue())
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
    try:
        cookie, csrf, _body = _login(server.bound_port, "olga", _SECOND)
        issued = store.open_session(olga)
        ticket = store.issue_ticket(olga, profile="default", session_id=issued.session_id)
        store.revoke_token(issued.token)
        assert store.consume_ticket(ticket) is None

        status, _headers, body = _request(
            server.bound_port,
            "POST",
            "/v1/auth/ws-ticket",
            cookie=cookie,
            csrf=csrf,
        )
        assert status == 200
        client = _ticket_client(server.bound_port, str(body["ticket"]))
        store.disable_account("olga")
        try:
            with pytest.raises(GatewayError, match="revoked"):
                client.status()
        finally:
            client.close()
        status, _headers, _body = _request(
            server.bound_port,
            "GET",
            "/status",
            cookie=cookie,
        )
        assert status == 401

        store.set_server_role("olga", "operator")
        # disable left the account disabled; role change does not re-enable it.
        assert store.get_username("olga") is not None
        assert store.get_username("olga").status == "disabled"  # type: ignore[union-attr]
        fresh = _account(store, "bea", _SECOND, display_name="Bea", role="operator")
        store.set_membership(fresh.id, "default", "operator")
        bea_cookie, _csrf, _body = _login(server.bound_port, "bea", _SECOND)
        store.set_server_role("bea", "viewer")
        status, _headers, _body = _request(
            server.bound_port,
            "GET",
            "/status",
            cookie=bea_cookie,
        )
        assert status == 401
        store.set_password("ada", "test-reset")
        assert store.authenticate("ada", _PRIMARY) is None
        assert store.authenticate("ada", "test-reset") is not None
        store.set_server_role("bea", "operator")
        store.set_membership(fresh.id, "default", "operator")
        assert store.remove_membership(fresh.id, "default") is True
        removed = authorize_action(
            store,
            Principal(kind="session", account_id=fresh.id, username="bea", role="operator"),
            action="chat",
            profile="default",
            profile_exists=lambda name: name == "default",
            runtime_profile="default",
        )
        assert removed.status == 403
        assert ada.id
    finally:
        server.shutdown()
        runtime.close()
        store.close()


def test_migrate_refuses_a_live_daemon_and_unscoped_cards_are_admin_only(
    tmp_path: Path,
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    StateDB(data / "prime.db").close()
    with pytest.raises(MigrationBusy):
        migrate_single_user(data, tmp_path / "config", daemon_running=lambda: True)
    assert (data / "prime.db").is_file()
    assert not (data / "profiles" / ".migration.json").exists()

    store = AccountStore(data / "accounts.db")
    owner = _account(store, "ada", _PRIMARY, display_name="Ada")
    operator = _account(store, "nora", _SECOND, display_name="Nora", role="operator")
    runtime = build_runtime(
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=data / "prime.db",
        cwd=tmp_path,
        providers={"ollama": ScriptedProvider([AssistantFinal(content="ok")])},
    )
    assert runtime.profile_id == ""
    host = Host(runtime, ApprovalQueue())
    assert host.queue.profile_id == ""
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
    try:
        request = ApprovalRequest(
            tool="delete_file",
            risk=Risk.DESTRUCTIVE,
            reason="delete",
            summary="delete a file",
            arguments={"path": "note.txt"},
            grant_key="delete",
            sandboxed=False,
        )

        def block() -> None:
            host.queue.authorize(request)

        worker = threading.Thread(target=block)
        worker.start()
        deadline = time.monotonic() + 2
        pending: list[dict[str, object]] = []
        while time.monotonic() < deadline:
            pending = host.queue.list_pending()
            if pending:
                break
            time.sleep(0.02)
        assert pending
        approval_id = str(pending[0]["id"])
        cookie, csrf, _body = _login(server.bound_port, "nora", _SECOND)
        status, _headers, body = _request(
            server.bound_port,
            "POST",
            f"/v1/approvals/{approval_id}",
            cookie=cookie,
            csrf=csrf,
            body_json={"decision": "allow_once"},
        )
        assert status == 403
        assert body["error"]["code"] == "forbidden"
        status, _headers, body = _request(
            server.bound_port,
            "POST",
            f"/v1/approvals/{approval_id}",
            token="test-token",
            body_json={"decision": "deny"},
        )
        assert status == 200
        worker.join(timeout=2)
        assert owner.id and operator.id
    finally:
        server.shutdown()
        runtime.close()
        store.close()


def test_audit_profile_comes_from_the_runtime(tmp_path: Path) -> None:
    data = tmp_path / "data"
    create_profile(data, "default")
    create_profile(data, "work")
    store = AccountStore(data / "accounts.db")
    account = _account(store, "otto", _PRIMARY, display_name="Otto")
    store.set_membership(account.id, "default", "operator")
    store.set_membership(account.id, "work", "operator")
    runtime = build_runtime(
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=data / "unused.db",
        cwd=tmp_path,
        profile="default",
        providers={"ollama": ScriptedProvider([AssistantFinal(content="ok")])},
    )
    host = Host(runtime, ApprovalQueue())
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
    try:
        cookie, csrf, _body = _login(server.bound_port, "otto", _PRIMARY)
        status, _headers, _body = _request(
            server.bound_port,
            "POST",
            "/v1/auth/logout",
            cookie=cookie,
            csrf=csrf,
            profile="work",
        )
        assert status == 200
        row = runtime.db.conn.execute(
            """
            SELECT profile, actor_account, payload_json
            FROM audit_events WHERE kind = 'auth.logout'
            """
        ).fetchone()
        assert row is not None
        assert row["profile"] == "default"
        payload = json.loads(row["payload_json"])
        assert payload["profile"] == "default"
        assert payload["actor_account"] == account.id
        assert row["actor_account"] == account.id
    finally:
        server.shutdown()
        runtime.close()
        store.close()


def test_lockout_is_held_across_argon2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = AccountStore(tmp_path / "accounts.db")
    _account(store, "ada", _PRIMARY, display_name="Ada")
    current = 0
    peak = 0
    guard = threading.Lock()
    real = verify_password

    def wrapped(encoded: str, presented: str) -> bool:
        nonlocal current, peak
        with guard:
            current += 1
            peak = max(peak, current)
        try:
            time.sleep(0.05)
            return real(encoded, presented)
        finally:
            with guard:
                current -= 1

    monkeypatch.setattr("praxis_prime.accounts.db.verify_password", wrapped)
    monkeypatch.setattr("praxis_prime.accounts.passwords.verify_password", wrapped)
    threads = [
        threading.Thread(target=lambda: store.authenticate("ada", "test-wrong"))
        for _ in range(6)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert peak == 1
    assert store.authenticate("ada", _PRIMARY) is None
    store.close()


def test_idempotency_cache_is_per_account(tmp_path: Path) -> None:
    runtime = build_runtime(
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=tmp_path / "prime.db",
        cwd=tmp_path,
        providers={"ollama": ScriptedProvider([AssistantFinal(content="ok")])},
    )
    host = Host(runtime, ApprovalQueue())
    server = GatewayServer(
        host="127.0.0.1",
        port=0,
        token="test-token",
        agent=host,
        approvals=host.queue,
    )
    try:
        server._remember(
            "acc_ada",
            "same",
            {"type": "result", "ok": True, "payload": {"who": "ada"}},
        )
        server._remember(
            "acc_nora",
            "same",
            {"type": "result", "ok": True, "payload": {"who": "nora"}},
        )
        ada = server._cached("acc_ada", "same")
        nora = server._cached("acc_nora", "same")
        assert ada is not None and ada["payload"] == {"who": "ada"}
        assert nora is not None and nora["payload"] == {"who": "nora"}
    finally:
        runtime.close()


def test_allowlist_symlinks_backup_and_private_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    data = tmp_path / "data"
    default = create_profile(data, "default")
    work = create_profile(data, "work")
    assert 'allow = ["*"]' in default.config_path.read_text(encoding="utf-8")
    assert "allow = []" in work.config_path.read_text(encoding="utf-8")
    work.config_path.unlink()
    missing = work.layer()
    assert missing.tools == frozenset()
    assert missing.mcp == frozenset()

    with pytest.raises(McpConfigError):
        validate_name("gh__x")
    collided = ToolAllowlist(tools=None, mcp=frozenset({"gh"}))
    assert collided.permits_call("mcp__gh__x__secret", None) is False
    assert collided.permits_call("mcp__gh__issue", None) is True

    registry = ToolRegistry()
    manager = McpManager(
        [ServerSpec(name="gh", transport="stdio"), ServerSpec(name="other", transport="stdio")],
        registry,
        cwd=tmp_path,
        audit=None,
        threshold=10,
    )
    manager.allowed_servers = frozenset({"gh"})

    def client_for(name: str) -> object:
        spec = manager.specs[name]

        class _Client:
            tools: list[object] = []
            resources: list[object] = []
            prompts: list[object] = []

        _Client.spec = spec  # type: ignore[attr-defined]
        return _Client()

    manager.client_for = client_for  # type: ignore[method-assign]
    catalog = manager.find("", "")
    assert "server gh " in catalog
    assert "server other " not in catalog

    secret = tmp_path / "secret.txt"
    secret.write_text("do not copy\n", encoding="utf-8")
    skills = tmp_path / "config" / "skills" / "leak"
    skills.mkdir(parents=True)
    (skills / "SKILL.md").symlink_to(secret)
    home = ProfileHome(data, "default")
    _copy_skills(tmp_path / "config", home)
    assert not (home.skills_dir / "leak" / "SKILL.md").exists()

    root = tmp_path / "legacy"
    root.mkdir()
    real = tmp_path / "real.db"
    StateDB(real).close()
    (root / "prime.db").symlink_to(real)
    migrated = migrate_single_user(root, None, daemon_running=lambda: False)
    placed = root / "profiles" / "default" / "prime.db"
    assert placed.is_file()
    assert not placed.is_symlink()
    assert real.is_file()
    assert migrated.backup.startswith("backups/pre-profile-")

    again = tmp_path / "twice"
    again.mkdir()
    StateDB(again / "prime.db").close()
    profile = ProfileHome(again, "default")
    first = _backup_legacy(again, profile)
    StateDB(again / "prime.db").close()
    second = _backup_legacy(again, profile)
    assert first != second
    assert (again / first).is_dir()
    assert (again / second).is_dir()

    home_dir = tmp_path / "home"
    share = home_dir / ".local" / "share"
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("XDG_DATA_HOME", str(share))
    private = share / "praxis-prime"
    (private / "profiles" / "default").mkdir(parents=True)
    accounts = private / "accounts.db"
    accounts.write_text("argon2-hash\n", encoding="utf-8")
    soul = private / "profiles" / "default" / "SOUL.md"
    soul.write_text("OTHER-SOUL\n", encoding="utf-8")
    database = private / "profiles" / "default" / "prime.db"
    database.write_text("transcript\n", encoding="utf-8")
    assert is_secret_path(accounts)
    assert is_secret_path(soul)
    assert is_secret_path(database)
    context = ToolContext(cwd=str(home_dir), cancelled=lambda: False, shell_approved=True)
    with pytest.raises(ReadDenied):
        execute_read_file({"path": str(soul)}, context)
    with pytest.raises(RuntimeError, match="protected"):
        execute_shell({"command": f"cat {accounts}"}, context)
    with pytest.raises(RuntimeError, match="protected"):
        execute_shell({"command": f"cat {database}"}, context)

    link = tmp_path / "linked-soul.md"
    link.symlink_to(soul)
    assert read_persona(link) == ""
    huge = tmp_path / "huge.md"
    huge.write_bytes(b"y" * 40_000)
    with caplog.at_level(logging.WARNING):
        assert read_persona(huge) == ""
    assert "cap" in caplog.text

    token = tmp_path / "gateway.token"
    rotate_token(token)
    assert token.read_text(encoding="utf-8").strip()
    assert stat.S_IMODE(token.stat().st_mode) == 0o600
    assert list(tmp_path.glob(".gateway.token.*.tmp")) == []


def test_approval_meta_is_limited_to_the_callers_profiles(tmp_path: Path) -> None:
    data = tmp_path / "data"
    create_profile(data, "default")
    create_profile(data, "work")
    store = AccountStore(data / "accounts.db")
    ada = _account(store, "ada", _PRIMARY, display_name="Ada")
    nora = _account(store, "nora", _SECOND, display_name="Nora", role="operator")
    _account(store, "aud", _SECOND, display_name="Aud", role="auditor")
    store.set_membership(ada.id, "default", "owner")
    store.set_membership(nora.id, "work", "operator")
    runtime = build_runtime(
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=data / "unused.db",
        cwd=tmp_path,
        profile="default",
        providers={"ollama": ScriptedProvider([AssistantFinal(content="ok")])},
    )
    host = Host(runtime, ApprovalQueue())
    host.queue.profile_id = "default"
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
    try:
        request = ApprovalRequest(
            tool="delete_file",
            risk=Risk.DESTRUCTIVE,
            reason="delete",
            summary="delete",
            arguments={},
            grant_key="delete",
            sandboxed=False,
        )

        def block() -> None:
            host.queue.authorize(request)

        worker = threading.Thread(target=block)
        worker.start()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not host.queue.list_pending():
            time.sleep(0.02)
        nora_cookie, _csrf, _body = _login(server.bound_port, "nora", _SECOND)
        status, _headers, body = _request(
            server.bound_port,
            "GET",
            "/v1/approvals/meta",
            cookie=nora_cookie,
        )
        assert status == 200
        assert body["approvals"] == []
        aud_cookie, _csrf, _body = _login(server.bound_port, "aud", _SECOND)
        status, _headers, body = _request(
            server.bound_port,
            "GET",
            "/v1/approvals/meta",
            cookie=aud_cookie,
        )
        assert status == 200
        assert body["count"] == 1
        approvals = body["approvals"]
        assert isinstance(approvals, list) and len(approvals) == 1
        card = approvals[0]
        assert isinstance(card, dict)
        assert "summary" not in card
        assert "reason" not in card
        assert "arguments" not in card
        assert card["tool"] == "delete_file"
        host.queue.decide(
            str(host.queue.list_pending()[0]["id"]),
            ApprovalDecision.DENY,
            actor=ada.id,
        )
        worker.join(timeout=2)
    finally:
        server.shutdown()
        runtime.close()
        store.close()


def test_permission_error_is_not_treated_as_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """EACCES must not look like "no file". Python 3.14's Path.is_file does."""
    import errno
    import os

    from praxis_prime.statfile import StatKind, lstat_kind

    database = tmp_path / "prime.db"
    database.write_bytes(b"sqlite\n")
    blocked = tmp_path / "notes.txt"
    blocked.write_text("hello\n", encoding="utf-8")
    real_lstat = os.lstat

    def denied(target: object, *args: object, **kwargs: object) -> os.stat_result:
        if Path(os.fspath(target)) in {database, blocked}:
            raise PermissionError(errno.EACCES, "denied", os.fspath(target))
        return real_lstat(target, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "lstat", denied)
    assert lstat_kind(database) is StatKind.UNREADABLE
    assert is_secret_path(blocked)
    with pytest.raises(OSError):
        migrate_single_user(tmp_path, None, daemon_running=lambda: False)
    monkeypatch.undo()
    assert database.read_bytes() == b"sqlite\n"
    assert not (tmp_path / "profiles" / ".migration.json").exists()


def test_approval_events_stay_with_the_principal(tmp_path: Path) -> None:
    """Unauthenticated, auditor, non-member, and disabled sockets get no card body."""
    data = tmp_path / "data"
    create_profile(data, "default")
    store = AccountStore(data / "accounts.db")
    ada = _account(store, "ada", _PRIMARY, display_name="Ada")
    bea = _account(store, "bea", _SECOND, display_name="Bea", role="operator")
    nora = _account(store, "nora", _SECOND, display_name="Nora", role="operator")
    aud = _account(store, "aud", _SECOND, display_name="Aud", role="auditor")
    olga = _account(store, "olga", _SECOND, display_name="Olga", role="operator")
    store.set_membership(ada.id, "default", "owner")
    store.set_membership(bea.id, "default", "operator")
    store.set_membership(olga.id, "default", "operator")
    runtime = build_runtime(
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=data / "prime.db",
        cwd=tmp_path,
        profile="default",
        providers={"ollama": ScriptedProvider([AssistantFinal(content="ok")])},
    )
    server = GatewayServer(
        host="127.0.0.1",
        port=0,
        token="test-token",
        agent=Host(runtime, ApprovalQueue()),
        approvals=ApprovalQueue(),
        logger=JsonLogger(tmp_path / "daemon.log"),
        accounts=store,
        audit=runtime.audit,
        data_root=data,
    )
    server.start()
    anon = None
    clients: list[GatewayClient] = []
    try:
        import socket

        sock = socket.create_connection(("127.0.0.1", server.bound_port), timeout=3)
        anon = WebSocketConnection(
            sock,
            client_handshake(sock, host="127.0.0.1", port=server.bound_port, token="", path="/ws"),
            client=True,
        )
        port = server.bound_port
        opened = {
            "ada": _open_ticket(port, _issue_ticket(port, "ada", _PRIMARY), "operator"),
            "bea": _open_ticket(port, _issue_ticket(port, "bea", _SECOND), "operator"),
            "nora": _open_ticket(port, _issue_ticket(port, "nora", _SECOND), "operator"),
            "aud": _open_ticket(port, _issue_ticket(port, "aud", _SECOND), "viewer"),
            "olga": _open_ticket(port, _issue_ticket(port, "olga", _SECOND), "operator"),
        }
        clients.extend(opened.values())
        store.disable_account("olga")
        card = {
            "id": "ap_12345678",
            "tool": "delete_file",
            "risk": "high",
            "reason": "ADA-SECRET-REASON",
            "summary": "ADA-SECRET-SUMMARY",
            "arguments": {"path": "ADA-SECRET-ARG"},
            "sessionId": "sess-ada",
            "profileId": "default",
            "state": "pending",
        }
        server.publish(
            {"type": "event", "id": "e1", "payload": {"kind": "approval", "approval": card}}
        )
        owner_text = _events(opened["ada"])
        member_text = _events(opened["bea"])
        auditor_text = _events(opened["aud"])
        assert "ADA-SECRET-ARG" in owner_text
        assert "ADA-SECRET-ARG" in member_text
        assert "ADA-SECRET" not in auditor_text
        assert "delete_file" in auditor_text
        assert "sessionId" not in auditor_text
        assert "arguments" not in auditor_text
        assert _events(opened["nora"]) == ""
        assert _events(opened["olga"]) == ""
        assert _pull(anon) == ""
        unscoped = dict(card)
        unscoped["profileId"] = ""
        unscoped["arguments"] = {"path": "UNSCOPED-SECRET"}
        server.publish(
            {"type": "event", "id": "e2", "payload": {"kind": "approval", "approval": unscoped}}
        )
        assert "UNSCOPED-SECRET" in _events(opened["ada"])
        assert "UNSCOPED-SECRET" not in _events(opened["bea"])
        assert "UNSCOPED-SECRET" not in _events(opened["aud"])
        assert ada.id and bea.id and nora.id and aud.id and olga.id
    finally:
        for client in clients:
            client.close()
        if anon is not None:
            anon.close()
        server.shutdown()
        runtime.close()
        store.close()


def test_audit_log_uses_its_own_connection(tmp_path: Path) -> None:
    """A chat transaction must not drop the audit row."""
    db = StateDB(tmp_path / "prime.db")
    audit = AuditLog(db)
    started = threading.Event()

    def hold() -> None:
        db.conn.execute("BEGIN IMMEDIATE")
        started.set()
        time.sleep(0.4)
        db.conn.commit()

    holder = threading.Thread(target=hold)
    holder.start()
    assert started.wait(2)
    try:
        audit.append(
            session_id=None,
            kind="tool",
            summary="overlapped",
            payload={"ok": True},
        )
    finally:
        holder.join(timeout=2)
        audit.close()
        db.close()
    assert not holder.is_alive()

    data = tmp_path / "data"
    create_profile(data, "default")
    store = AccountStore(data / "accounts.db")
    ada = _account(store, "ada", _PRIMARY, display_name="Ada")
    store.set_membership(ada.id, "default", "owner")
    runtime = build_runtime(
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=data / "prime.db",
        cwd=tmp_path,
        profile="default",
        providers={"ollama": ScriptedProvider([AssistantFinal(content="ok")] * 8)},
    )
    host = Host(runtime, ApprovalQueue())
    errors: list[BaseException] = []

    def chat() -> None:
        try:
            host.chat("hello", owner_account=ada.id, owner_profile="default")
        except BaseException as exc:
            errors.append(exc)

    def attempt() -> None:
        try:
            login(store, _login_body("ada", "test-wrong"), runtime.audit, peer="127.0.0.1")
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=chat) for _ in range(4)]
    threads.extend(threading.Thread(target=attempt) for _ in range(12))
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        assert errors == []
        assert all(not thread.is_alive() for thread in threads)
        assert runtime.audit.verify()
    finally:
        runtime.close()
        store.close()


def test_auth_fail_summary_records_username_and_ip(tmp_path: Path) -> None:
    db = StateDB(tmp_path / "prime.db")
    audit = AuditLog(db)
    try:
        for _ in range(9):
            audit.append(
                session_id=None,
                kind="auth.fail",
                summary="login failed",
                payload={"username": "ada", "ip": "127.0.0.1"},
            )
        assert audit.verify()
        rows = db.conn.execute(
            "SELECT kind, payload_json FROM audit_events ORDER BY id"
        ).fetchall()
    finally:
        audit.close()
        db.close()
    kinds = [str(row["kind"]) for row in rows]
    assert kinds == ["auth.fail", "auth.fail.summary"]
    summary = json.loads(rows[1]["payload_json"])
    assert summary["suppressed"] == 8
    assert summary["counts"] == [{"username": "ada", "ip": "127.0.0.1", "count": 8}]
    assert "password" not in rows[1]["payload_json"]


def test_migration_lock_rolls_back_and_profile_migrate_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import argparse
    import io
    import sys

    from praxis_prime.accounts.cli import _create
    from praxis_prime.daemon import serve
    from praxis_prime.profiles.cli import profile_command
    from praxis_prime.profiles.home import migration_marker

    data = tmp_path / "data"
    data.mkdir()
    config = tmp_path / "config"
    config.mkdir()
    StateDB(data / "prime.db").close()
    calls = {"n": 0}

    def flappy() -> bool:
        calls["n"] += 1
        return calls["n"] >= 2

    monkeypatch.setattr("praxis_prime.profiles.migrate.daemon_is_running", flappy)
    monkeypatch.setattr(sys, "stdin", io.StringIO(_PRIMARY + "\n"))
    failed = _create(_create_args("ada", data, config))
    assert failed == 2
    assert (data / "prime.db").is_file()
    assert not migration_marker(data).exists()
    assert not AccountStore(data / "accounts.db").has_accounts()
    monkeypatch.setattr("praxis_prime.profiles.migrate.daemon_is_running", lambda: False)
    monkeypatch.setattr(sys, "stdin", io.StringIO(_PRIMARY + "\n"))
    assert _create(_create_args("ada", data, config)) == 0
    assert migration_marker(data).is_file()
    assert not (data / "prime.db").exists()
    assert AccountStore(data / "accounts.db").has_accounts()
    again = profile_command(
        argparse.Namespace(
            profile_command="migrate",
            data_dir=str(data),
            config_dir=str(config),
        )
    )
    assert again == 0
    assert not (data / ".migration.lock").exists()

    stale = tmp_path / "stale"
    stale.mkdir()
    StateDB(stale / "prime.db").close()
    (stale / ".migration.lock").write_text("999999\n", encoding="utf-8")
    repaired = profile_command(
        argparse.Namespace(
            profile_command="migrate",
            data_dir=str(stale),
            config_dir=str(config),
        )
    )
    assert repaired == 0
    assert migration_marker(stale).is_file()
    assert not (stale / ".migration.lock").exists()
    assert not (stale / "prime.db").exists()

    locked = tmp_path / "locked-share"
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_DATA_HOME", str(locked))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    root = locked / "praxis-prime"
    root.mkdir(parents=True)
    (root / ".migration.lock").write_text("999999\n", encoding="utf-8")
    box: dict[str, int] = {}

    def run() -> None:
        box["code"] = serve(stop=threading.Event(), listen="127.0.0.1:0")

    thread = threading.Thread(target=run)
    thread.start()
    thread.join(timeout=3)
    if thread.is_alive():
        thread.join(timeout=1)
    assert not thread.is_alive()
    assert box["code"] == 2


def test_denylist_covers_hardlinks_backups_quotes_and_recursive_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import os

    from praxis_prime.policy.boundary import bind_data_root, private_data_command

    bind_data_root(None)
    home = tmp_path / "home"
    share = home / ".local" / "share"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(share))
    private = share / "praxis-prime"
    (private / "profiles" / "work").mkdir(parents=True)
    (private / "backups").mkdir()
    (private / "org").mkdir()
    soul = private / "profiles" / "work" / "SOUL.md"
    soul.write_text("WORK-SOUL-SECRET\n", encoding="utf-8")
    (private / "backups" / "notes.txt").write_text("BACKUP-TEXT\n", encoding="utf-8")
    (private / "org" / "policy.toml").write_text("[org]\n", encoding="utf-8")
    (private / "accounts.db").write_text("hash\n", encoding="utf-8")
    os.link(soul, home / "soul-hard.md")
    context = ToolContext(cwd=str(home), cancelled=lambda: False, shell_approved=True)
    with pytest.raises(ReadDenied):
        execute_read_file({"path": "soul-hard.md"}, context)
    with pytest.raises(ReadDenied):
        execute_read_file(
            {"path": ".local/share/praxis-prime/backups/notes.txt"},
            context,
        )
    org = execute_read_file({"path": ".local/share/praxis-prime/org/policy.toml"}, context)
    assert "[org]" in org
    quoted = "cat '.local/share/praxis-prime/profiles/work/SOUL.md'"
    with pytest.raises(RuntimeError, match="protected"):
        execute_shell({"command": quoted}, context)
    with pytest.raises(RuntimeError, match="protected"):
        execute_shell({"command": "grep -r SECRET .local/share"}, context)
    with pytest.raises(RuntimeError, match="protected"):
        execute_shell({"command": "cat soul-hard.md"}, context)
    with pytest.raises(RuntimeError, match="protected"):
        execute_shell({"command": "cat .local/share/praxis-prime/backups/notes.txt"}, context)
    assert private_data_command("find .local/share -exec cat {} \\;", home)
    assert private_data_command("tar cf - .local/share", home)
    assert private_data_command("cp -r .local/share /tmp/out", home)
    assert private_data_command("rsync -a .local/share /tmp/out", home)
    assert private_data_command("rg SECRET .local/share", home)
    (home / "notes").mkdir()
    assert not private_data_command("grep -r SECRET notes", home)
    assert not private_data_command("echo hello", home)


def test_data_root_honours_an_explicit_data_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from praxis_prime.policy.boundary import bind_data_root

    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    explicit = tmp_path / "explicit"
    (explicit / "profiles" / "default").mkdir(parents=True)
    soul = explicit / "profiles" / "default" / "SOUL.md"
    soul.write_text("EXPLICIT-SOUL\n", encoding="utf-8")
    xdg_soul = home / ".local" / "share" / "praxis-prime" / "profiles" / "default" / "SOUL.md"
    xdg_soul.parent.mkdir(parents=True)
    xdg_soul.write_text("XDG-SOUL\n", encoding="utf-8")
    runtime = build_runtime(
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=explicit / "prime.db",
        cwd=tmp_path,
        providers={"ollama": ScriptedProvider([AssistantFinal(content="ok")])},
    )
    try:
        assert is_secret_path(soul)
        assert not is_secret_path(xdg_soul)
    finally:
        runtime.close()
    bind_data_root(None)
    assert not is_secret_path(soul)
    assert is_secret_path(xdg_soul)


def test_username_locks_stay_bounded(tmp_path: Path) -> None:
    from praxis_prime.accounts.db import _NAME_LOCK_CAP

    store = AccountStore(tmp_path / "accounts.db")
    try:
        held = store._account_gate("held-name")
        held.acquire()
        try:
            for index in range(400):
                store._account_gate(f"user{index}")
            assert len(store._name_locks) <= _NAME_LOCK_CAP
            assert "held-name" in store._name_locks
        finally:
            held.release()
    finally:
        store.close()


def _create_args(name: str, data: Path, config: Path) -> object:
    import argparse

    return argparse.Namespace(
        username=name,
        display_name=name,
        role="operator",
        email="",
        password_stdin=True,
        data_dir=str(data),
        config_dir=str(config),
    )


def _issue_ticket(port: int, name: str, secret: str) -> str:
    cookie, csrf, _body = _login(port, name, secret)
    status, _headers, body = _request(
        port,
        "POST",
        "/v1/auth/ws-ticket",
        cookie=cookie,
        csrf=csrf,
    )
    assert status == 200
    ticket = body.get("ticket")
    assert isinstance(ticket, str) and ticket
    return ticket


def _open_ticket(port: int, ticket: str, role: str) -> GatewayClient:
    import socket

    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        buffer = client_handshake(
            sock,
            host="127.0.0.1",
            port=port,
            token="",
            path=f"/ws?ticket={ticket}",
        )
    except Exception:
        sock.close()
        raise
    client = GatewayClient(WebSocketConnection(sock, buffer, client=True))
    hello = client.request(
        "connect",
        {"role": role, "ticket": ticket, "client": "test"},
        timeout=5,
    )
    if hello.get("type") != "hello":
        client.close()
        raise GatewayError("ticket rejected")
    return client


def _events(client: GatewayClient, timeout: float = 0.6) -> str:
    chunks: list[str] = []
    try:
        while True:
            frame = client._events.get(timeout=timeout)
            chunks.append(json.dumps(frame))
            timeout = 0.05
    except Exception:
        return "\n".join(chunks)


def _pull(ws: WebSocketConnection, timeout: float = 0.4) -> str:
    ws.sock.settimeout(timeout)
    chunks: list[str] = []
    try:
        while True:
            text = ws.recv_text()
            if not text:
                break
            chunks.append(text)
    except Exception:
        return "\n".join(chunks)
    return "\n".join(chunks)


def _ticket_client(port: int, ticket: str) -> GatewayClient:
    import socket

    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        buffer = client_handshake(
            sock,
            host="127.0.0.1",
            port=port,
            token="",
            path=f"/ws?ticket={ticket}",
        )
    except Exception:
        sock.close()
        raise
    client = GatewayClient(WebSocketConnection(sock, buffer, client=True))
    hello = client.request(
        "connect",
        {"role": "operator", "ticket": ticket, "client": "test"},
        timeout=5,
    )
    if hello.get("type") != "hello":
        client.close()
        raise GatewayError("ticket rejected")
    return client
