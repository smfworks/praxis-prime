"""Accounts, sessions, and the loopback authz guard."""

from __future__ import annotations

import io
import json
import socket
import stat
import threading
from pathlib import Path

from tests.fakes import ScriptedProvider

from praxis_prime.accounts.db import AccountError, AccountStore, cookie_value
from praxis_prime.approvals.gate import ApprovalDecision, ApprovalRequest
from praxis_prime.approvals.queue import ApprovalQueue
from praxis_prime.audit.log import AuditLog
from praxis_prime.cli import main
from praxis_prime.gateway.auth import load_or_create_token, read_token
from praxis_prime.gateway.authz import Denial, authenticate_http
from praxis_prime.gateway.client import Endpoint, GatewayClient, GatewayError
from praxis_prime.gateway.server import GatewayServer
from praxis_prime.gateway.ws import WebSocketConnection, client_handshake
from praxis_prime.host import Host
from praxis_prime.observe import JsonLogger
from praxis_prime.profiles.home import create_profile
from praxis_prime.router.types import AssistantFinal
from praxis_prime.runtime import build_runtime
from praxis_prime.state import StateDB
from praxis_prime.tools.registry import Risk

_PASSWORD = "correct-horse"
_VIEWER_PASSWORD = "viewer-pass-1"
_OUTSIDER_PASSWORD = "outsider-pass"


def test_accounts_db_is_private_wal_and_argon2id(tmp_path: Path):
    path = tmp_path / "accounts.db"
    store = AccountStore(path)
    try:
        first = store.create_account(
            username_text="Ada",
            password=_PASSWORD,
            display_name="Ada",
            role="operator",
        )
        assert first.role == "owner"
        assert first.username == "ada"
        try:
            store.create_account(
                username_text="other",
                password=_PASSWORD,
                display_name="Other",
                role="owner",
            )
        except ValueError as exc:
            assert "owner" in str(exc)
        else:
            raise AssertionError("a second owner must be rejected")
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600
        row = store.conn.execute("PRAGMA journal_mode").fetchone()
        assert str(row[0]).lower() == "wal"
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{path}{suffix}")
            if sidecar.exists():
                assert stat.S_IMODE(sidecar.stat().st_mode) == 0o600
        stored = store.conn.execute(
            "SELECT password_hash FROM accounts WHERE username = 'ada'"
        ).fetchone()
        assert str(stored["password_hash"]).startswith("$argon2id$")
        assert store.authenticate("ada", _PASSWORD) is not None
        assert store.authenticate("missing", _PASSWORD) is None
        for _ in range(5):
            assert store.authenticate("ada", "not-the-password") is None
        assert store.authenticate("ada", _PASSWORD) is None
        store.set_password("ada", "replaced-password")
        assert store.authenticate("ada", "replaced-password") is not None
        listed = store.list_accounts()[0].public()
        assert "password" not in listed
        assert "$argon2" not in json.dumps(listed)
    finally:
        store.close()


def test_session_cookie_csrf_and_single_use_ticket(tmp_path: Path):
    store = AccountStore(tmp_path / "accounts.db")
    try:
        account = store.create_account(
            username_text="ada",
            password=_PASSWORD,
            display_name="Ada",
        )
        issued = store.open_session(account)
        cookie = f"pp_session={issued.token}; HttpOnly; Secure; SameSite=Strict; Path=/"
        assert cookie_value(cookie) == issued.token
        session = store.session_from_token(issued.token)
        assert session is not None
        assert store.csrf_matches(session, issued.csrf_token) is True
        assert store.csrf_matches(session, "nope") is False
        raw = store.issue_ticket(account, profile="default", ttl=0)
        assert store.consume_ticket(raw) is None
        raw = store.issue_ticket(account, profile="default")
        first = store.consume_ticket(raw)
        assert first is not None and first.account_id == account.id
        assert store.consume_ticket(raw) is None
    finally:
        store.close()


def test_cli_bootstrap_migrates_without_printing_the_hash(tmp_path: Path, monkeypatch, capsys):
    data = tmp_path / "data"
    data.mkdir()
    config = tmp_path / "config"
    db = StateDB(data / "prime.db")
    AuditLog(db).append(
        session_id=None,
        kind="note",
        summary="legacy-marker",
        payload={"marker": "keep-me"},
    )
    db.close()
    monkeypatch.setattr("sys.stdin", io.StringIO(f"{_PASSWORD}\n"))
    code = main(
        [
            "account",
            "create",
            "Ada",
            "--password-stdin",
            "--data-dir",
            str(data),
            "--config-dir",
            str(config),
        ]
    )
    assert code == 0
    created = capsys.readouterr().out
    assert "created owner ada" in created
    assert "profile default" in created
    assert "backup" in created
    assert "$argon2" not in created
    assert _PASSWORD not in created
    moved = StateDB(data / "profiles" / "default" / "prime.db")
    try:
        rows = moved.conn.execute("SELECT summary FROM audit_events").fetchall()
        assert any(row["summary"] == "legacy-marker" for row in rows)
        assert AuditLog(moved).verify()
    finally:
        moved.close()
    assert not (data / "prime.db").exists()
    assert main(["account", "list", "--data-dir", str(data)]) == 0
    listed = capsys.readouterr().out
    assert "ada" in listed and "owner" in listed
    assert "$argon2" not in listed
    monkeypatch.setattr("sys.stdin", io.StringIO(f"{_PASSWORD}\n"))
    rejected = main(
        [
            "account",
            "create",
            "eve",
            "--role",
            "owner",
            "--password-stdin",
            "--data-dir",
            str(data),
            "--config-dir",
            str(config),
        ]
    )
    assert rejected == 2
    monkeypatch.setattr("sys.stdin", io.StringIO(f"{_VIEWER_PASSWORD}\n"))
    assert (
        main(
            [
                "account",
                "create",
                "vera",
                "--role",
                "viewer",
                "--password-stdin",
                "--data-dir",
                str(data),
                "--config-dir",
                str(config),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert main(["profile", "create", "work", "--data-dir", str(data)]) == 0
    assert (
        main(
            [
                "profile",
                "assign",
                "work",
                "--account",
                "vera",
                "--role",
                "viewer",
                "--data-dir",
                str(data),
            ]
        )
        == 0
    )
    assert main(["profile", "list", "--data-dir", str(data)]) == 0
    names = capsys.readouterr().out
    assert "default" in names and "work" in names


def test_viewer_cannot_approve_and_a_non_member_is_forbidden(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    store = AccountStore(data / "accounts.db")
    store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
    store.create_account(
        username_text="vera",
        password=_VIEWER_PASSWORD,
        display_name="Vera",
        role="viewer",
    )
    store.create_account(
        username_text="otto",
        password=_OUTSIDER_PASSWORD,
        display_name="Otto",
        role="operator",
    )
    create_profile(data, "work")
    owner = store.get_username("ada")
    viewer = store.get_username("vera")
    assert owner is not None and viewer is not None
    store.set_membership(owner.id, "work", "owner")
    store.set_membership(viewer.id, "work", "viewer")
    runtime = build_runtime(
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=data / "prime.db",
        cwd=tmp_path,
        providers={"ollama": ScriptedProvider([AssistantFinal(content="ok")])},
    )
    queue_host = Host(runtime, ApprovalQueue())
    logger = JsonLogger(tmp_path / "daemon.log")
    server = GatewayServer(
        host="127.0.0.1",
        port=0,
        token="test-token",
        agent=queue_host,
        approvals=queue_host.queue,
        logger=logger,
        accounts=store,
        audit=runtime.audit,
        data_root=data,
    )
    server.start()
    try:
        status, _headers, body = _request(server.bound_port, "GET", "/health")
        assert status == 200 and body["ok"] is True
        status, headers, body = _request(
            server.bound_port,
            "GET",
            "/health",
            host="evil.example",
        )
        assert status == 403
        assert b"evil.example" not in json.dumps(body).encode()
        status, _headers, body = _request(server.bound_port, "GET", "/health", host="")
        assert status == 400
        status, _headers, _body = _request(
            server.bound_port,
            "GET",
            "/health",
            origin="null",
        )
        assert status == 403
        status, _headers, _body = _request(
            server.bound_port,
            "GET",
            "/health",
            origin="http://evil.example",
        )
        assert status == 403
        status, _headers, body = _request(
            server.bound_port,
            "GET",
            "/health",
            duplicate_host=True,
        )
        assert status == 400
        assert body["error"]["code"] == "bad_request"

        status, _headers, body = _request(
            server.bound_port,
            "POST",
            "/v1/auth/login",
            body_json={"username": "ada", "password": "not-the-password"},
        )
        assert status == 401
        log_text = (tmp_path / "daemon.log").read_text(encoding="utf-8")
        assert "not-the-password" not in log_text
        assert "$argon2" not in log_text
        assert "auth_fail" in log_text

        status, _headers, _body = _request(
            server.bound_port,
            "GET",
            "/status",
            token="wrong-token",
        )
        assert status == 401
        status, _headers, body = _request(
            server.bound_port,
            "GET",
            "/status",
            token="test-token",
        )
        assert status == 200
        assert body["status"]["listen"].startswith("127.0.0.1:")

        _cookie, csrf, login_body = _login(server.bound_port, "vera", _VIEWER_PASSWORD)
        assert login_body["account"]["role"] == "viewer"
        assert "token" not in login_body
        assert _cookie not in (tmp_path / "daemon.log").read_text(encoding="utf-8")
        status, _headers, body = _request(
            server.bound_port,
            "POST",
            "/v1/approvals/ap_0000abcd",
            cookie=_cookie,
            body_json={"decision": "allow_once"},
        )
        assert status == 403
        assert body["error"]["code"] == "forbidden"
        status, _headers, body = _request(
            server.bound_port,
            "POST",
            "/v1/approvals/ap_0000abcd",
            cookie=_cookie,
            csrf=csrf,
            body_json={"decision": "allow_once"},
            profile="work",
        )
        assert status == 403

        outsider, outsider_csrf, _body = _login(server.bound_port, "otto", _OUTSIDER_PASSWORD)
        status, _headers, body = _request(
            server.bound_port,
            "GET",
            "/v1/profiles/work",
            cookie=outsider,
        )
        assert status == 403
        status, _headers, body = _request(
            server.bound_port,
            "GET",
            "/v1/profiles/missing",
            cookie=outsider,
        )
        assert status == 404
        status, _headers, body = _request(
            server.bound_port,
            "GET",
            "/v1/profiles",
            cookie=outsider,
        )
        assert status == 200
        assert body["profiles"] == []
        status, _headers, body = _request(
            server.bound_port,
            "POST",
            "/v1/auth/logout",
            cookie=outsider,
        )
        assert status == 403
        status, headers, body = _request(
            server.bound_port,
            "POST",
            "/v1/auth/logout",
            cookie=outsider,
            csrf=outsider_csrf,
        )
        assert status == 200
        assert "Max-Age=0" in headers.get("set-cookie", "")

        owner_cookie, owner_csrf, _owner_body = _login(server.bound_port, "ada", _PASSWORD)
        status, _headers, body = _request(
            server.bound_port,
            "POST",
            "/v1/auth/ws-ticket",
            cookie=owner_cookie,
            csrf=owner_csrf,
            profile="work",
        )
        assert status == 200
        ticket = str(body["ticket"])
        assert ticket not in (tmp_path / "daemon.log").read_text(encoding="utf-8")
        hello = _ws_connect(server.bound_port, ticket, "operator")
        assert hello.get("type") == "hello"
        again = _ws_connect(server.bound_port, ticket, "operator")
        assert again.get("type") == "error"

        viewer_cookie, viewer_csrf, _viewer_body = _login(
            server.bound_port, "vera", _VIEWER_PASSWORD
        )
        status, _headers, body = _request(
            server.bound_port,
            "POST",
            "/v1/auth/ws-ticket",
            cookie=viewer_cookie,
            csrf=viewer_csrf,
        )
        assert status == 200
        refused = _ws_connect(server.bound_port, str(body["ticket"]), "operator")
        assert refused.get("type") == "error"
    finally:
        server.shutdown()
        queue_host.close()
        store.close()


def test_owner_transfer_requires_an_admin_and_is_audited(tmp_path: Path, capsys):
    data = tmp_path / "data"
    data.mkdir()
    store = AccountStore(data / "accounts.db")
    store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
    store.create_account(
        username_text="bea",
        password=_PASSWORD,
        display_name="Bea",
        role="admin",
    )
    store.create_account(
        username_text="cy",
        password=_PASSWORD,
        display_name="Cy",
        role="operator",
    )
    try:
        store.transfer_owner("cy")
    except AccountError as exc:
        assert "admin" in str(exc)
    else:
        raise AssertionError("an operator must not become owner")
    store.close()
    assert main(["account", "transfer-owner", "bea", "--data-dir", str(data)]) == 0
    printed = capsys.readouterr().out
    assert "owner is now bea" in printed
    assert "previous owner ada is admin" in printed
    assert "$argon2" not in printed
    assert _PASSWORD not in printed
    opened = AccountStore(data / "accounts.db")
    try:
        owner = opened.owner()
        assert owner is not None and owner.username == "bea" and owner.role == "owner"
        former = opened.get_username("ada")
        assert former is not None and former.role == "admin"
        try:
            opened.create_account(
                username_text="dee",
                password=_PASSWORD,
                display_name="Dee",
                role="owner",
            )
        except AccountError as exc:
            assert "owner" in str(exc)
        else:
            raise AssertionError("a second owner must be rejected")
    finally:
        opened.close()
    audit_db = StateDB(data / "prime.db")
    try:
        log = AuditLog(audit_db)
        assert log.verify()
        row = audit_db.conn.execute(
            "SELECT kind, payload_json FROM audit_events WHERE kind = 'auth.owner_transfer'"
        ).fetchone()
        assert row is not None
        payload = json.loads(row["payload_json"])
        assert payload["from_username"] == "ada"
        assert payload["to_username"] == "bea"
        assert _PASSWORD not in row["payload_json"]
    finally:
        audit_db.close()


def test_auditor_reads_approval_metadata_and_not_the_card(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    store = AccountStore(data / "accounts.db")
    store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
    store.create_account(
        username_text="aud",
        password=_VIEWER_PASSWORD,
        display_name="Aud",
        role="auditor",
    )
    runtime = build_runtime(
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=data / "prime.db",
        cwd=tmp_path,
        providers={"ollama": ScriptedProvider([AssistantFinal(content="ok")])},
    )
    queue = ApprovalQueue(ttl=30)
    host = Host(runtime, queue)
    server = GatewayServer(
        host="127.0.0.1",
        port=0,
        token="test-token",
        agent=host,
        approvals=queue,
        accounts=store,
        audit=runtime.audit,
        data_root=data,
    )
    server.start()
    worker = threading.Thread(
        target=queue.authorize,
        args=(
            ApprovalRequest(
                tool="delete_file",
                risk=Risk.DESTRUCTIVE,
                reason="delete the secret note",
                summary="path=secret-note",
                arguments={"path": "secret-note", "text": "do-not-leak-this"},
                grant_key="delete_file:secret-note",
                sandboxed=False,
                mount="HOST: runs unsandboxed with full write access",
            ),
        ),
    )
    worker.start()
    try:
        approval_id = ""
        for _ in range(50):
            pending = queue.list_pending()
            if pending:
                approval_id = str(pending[0]["id"])
                break
            threading.Event().wait(0.02)
        assert approval_id
        cookie, csrf, _body = _login(server.bound_port, "aud", _VIEWER_PASSWORD)
        del csrf
        status, _headers, body = _request(
            server.bound_port,
            "GET",
            "/v1/approvals",
            cookie=cookie,
        )
        assert status == 403
        status, _headers, body = _request(
            server.bound_port,
            "GET",
            "/v1/approvals/meta",
            cookie=cookie,
        )
        assert status == 200
        assert body["count"] == 1
        blob = json.dumps(body)
        assert "secret-note" not in blob
        assert "do-not-leak-this" not in blob
        assert "HOST" not in blob
        assert "arguments" not in blob
        row = body["approvals"][0]
        assert set(row) == {"id", "tool", "risk", "createdAt", "decision"}
        assert row["tool"] == "delete_file"
        assert row["risk"] == "DESTRUCTIVE"
        assert row["decision"] == "pending"
        assert row["id"] == approval_id
    finally:
        if approval_id:
            queue.decide(approval_id, ApprovalDecision.DENY, actor="test")
        worker.join(timeout=2)
        server.shutdown()
        host.close()
        store.close()


def test_bearer_token_is_owner_equivalent_until_disabled(tmp_path: Path):
    legacy = authenticate_http(
        None,
        {"authorization": "Bearer test-token"},
        "GET",
        bootstrap_token="test-token",
        bearer_enabled=False,
    )
    assert not isinstance(legacy, Denial)
    assert legacy.role == "operator"

    data = tmp_path / "data"
    data.mkdir()
    store = AccountStore(data / "accounts.db")
    store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
    runtime = build_runtime(
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=data / "prime.db",
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
        accounts=store,
        data_root=data,
        bearer_enabled=False,
    )
    server.start()
    try:
        status, _headers, _body = _request(
            server.bound_port,
            "GET",
            "/status",
            token="test-token",
        )
        assert status == 401
        try:
            GatewayClient.connect(Endpoint("127.0.0.1", server.bound_port, "test-token"), timeout=2)
        except GatewayError as exc:
            assert "rejected" in str(exc).lower() or "token" in str(exc).lower()
        else:
            raise AssertionError("a disabled bearer token must not open a websocket")
        cookie, _csrf, _login_body = _login(server.bound_port, "ada", _PASSWORD)
        status, _headers, body = _request(
            server.bound_port,
            "GET",
            "/status",
            cookie=cookie,
        )
        assert status == 200
        assert body["status"]["listen"].startswith("127.0.0.1:")
    finally:
        server.shutdown()
        host.close()
        store.close()


def test_rotate_token_replaces_the_file_without_printing_it(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    from praxis_prime.gateway.discover import gateway_paths

    path = gateway_paths()[1]
    first = load_or_create_token(path)
    assert main(["daemon", "rotate-token"]) == 0
    printed = capsys.readouterr().out
    second = read_token(path)
    assert second is not None and second != first
    assert first not in printed
    assert second not in printed
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def _login(port: int, username: str, password: str) -> tuple[str, str, dict[str, object]]:
    status, headers, body = _request(
        port,
        "POST",
        "/v1/auth/login",
        body_json={"username": username, "password": password},
    )
    assert status == 200
    cookie = cookie_value(headers.get("set-cookie", ""))
    assert cookie
    assert "HttpOnly" in headers.get("set-cookie", "")
    assert "Secure" in headers.get("set-cookie", "")
    assert "SameSite=Strict" in headers.get("set-cookie", "")
    token = body.get("csrfToken")
    assert isinstance(token, str) and token
    assert cookie not in json.dumps(body)
    return cookie, token, body


def _request(
    port: int,
    method: str,
    path: str,
    *,
    token: str | None = None,
    body_json: dict[str, object] | None = None,
    cookie: str = "",
    csrf: str = "",
    profile: str = "",
    host: str = "127.0.0.1",
    origin: str = "",
    duplicate_host: bool = False,
) -> tuple[int, dict[str, str], dict[str, object]]:
    payload = b"" if body_json is None else json.dumps(body_json).encode("utf-8")
    lines = [f"{method} {path} HTTP/1.1"]
    if host:
        lines.append(f"Host: {host}")
    if duplicate_host:
        lines.append("Host: 127.0.0.1")
    lines.append("Connection: close")
    if origin:
        lines.append(f"Origin: {origin}")
    if token is not None:
        lines.append(f"Authorization: Bearer {token}")
    if cookie:
        lines.append(f"Cookie: pp_session={cookie}")
    if csrf:
        lines.append(f"x-csrf-token: {csrf}")
    if profile:
        lines.append(f"x-praxis-profile: {profile}")
    if method not in {"GET", "HEAD", "OPTIONS"}:
        lines.append("Content-Type: application/json")
    if payload:
        lines.append(f"Content-Length: {len(payload)}")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + payload
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        sock.sendall(raw)
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
    parsed = json.loads(body.decode("utf-8"))
    assert isinstance(parsed, dict)
    return status, headers, parsed


def _ws_connect(port: int, ticket: str, role: str) -> dict[str, object]:
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        buffer = client_handshake(
            sock,
            host="127.0.0.1",
            port=port,
            token="",
            path=f"/ws?ticket={ticket}",
        )
        ws = WebSocketConnection(sock, buffer, client=True)
        ws.send_text(
            json.dumps(
                {
                    "type": "connect",
                    "id": "1",
                    "payload": {"role": role, "ticket": ticket, "client": "test"},
                }
            )
        )
        text = ws.recv_text()
    finally:
        try:
            sock.close()
        except OSError:
            pass
    assert text is not None
    loaded = json.loads(text)
    assert isinstance(loaded, dict)
    return loaded


def test_audit_keeps_a_legacy_row_and_stamps_actor(tmp_path: Path):
    import hashlib

    db = StateDB(tmp_path / "prime.db")
    payload = json.dumps({"marker": "legacy"}, sort_keys=True, separators=(",", ":"))
    prev = "0" * 64
    digest = hashlib.sha256(f"{prev}\n{payload}".encode()).hexdigest()
    db.conn.execute(
        """
        INSERT INTO audit_events (
            session_id, created_at, kind, summary, payload_json, prev_hash, hash,
            actor_account, profile
        ) VALUES ('s1', '2020-01-01T00:00:00+00:00', 'note', 'old', ?, ?, ?, '', '')
        """,
        (payload, prev, digest),
    )
    db.conn.commit()
    log = AuditLog(db)
    assert log.verify()
    log.bind(actor_account="acc_owner", profile="default")
    log.append(session_id="s1", kind="note", summary="new", payload={"tool": "read_file"})
    assert log.verify()
    events = log.for_session("s1")
    assert events[0]["payload"] == {"marker": "legacy"}
    assert events[0]["actor_account"] == ""
    assert events[1]["actor_account"] == "acc_owner"
    assert events[1]["profile"] == "default"
    assert events[1]["payload"]["actor_account"] == "acc_owner"
    assert events[1]["payload"]["profile"] == "default"
    assert "actor" not in events[1]["payload"]
    db.close()
