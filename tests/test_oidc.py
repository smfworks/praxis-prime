"""OIDC sign-in against a local fake provider."""

from __future__ import annotations

import hashlib
import io
import json
import socket
import sqlite3
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pyotp
import pytest

from oidc_fake import FakeOidc, _s256
from praxis_prime.accounts.db import AccountStore, cookie_value
from praxis_prime.accounts.factors import Factors
from praxis_prime.accounts.oidc import (
    ENTRA_ROLE_MAP,
    OidcError,
    add_provider,
    clear_caches,
    list_identities,
    prelink,
)
from praxis_prime.accounts.oidc_cli import resolve_provider_settings
from praxis_prime.approvals.queue import ApprovalQueue
from praxis_prime.audit.log import AuditLog
from praxis_prime.cli import main
from praxis_prime.gateway.oidc import CHANGE, SIGN_IN
from praxis_prime.gateway.server import GatewayServer
from praxis_prime.observe import JsonLogger
from praxis_prime.state import StateDB

_PASSWORD = "correct-horse"
_SECRET = "oidc-test-secret-value"
_CLIENT = "praxis-test"
_REPO = Path(__file__).resolve().parents[1]


class _Agent:
    def status(self) -> dict[str, object]:
        return {}


class World:
    def __init__(
        self,
        tmp_path: Path,
        store: AccountStore,
        audit: AuditLog,
        server: GatewayServer,
        fake: FakeOidc,
        log: Path,
    ) -> None:
        self.store = store
        self.audit = audit
        self.server = server
        self.fake = fake
        self.log = log

    @property
    def port(self) -> int:
        return self.server.bound_port

    def close(self) -> None:
        self.server.shutdown()
        self.fake.close()
        self.audit.close()


@contextmanager
def world(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    allow: tuple[str, ...] = (),
    role_claim: str = "",
    role_map: dict[str, str] | None = None,
) -> Iterator[World]:
    clear_caches()
    data = tmp_path / "data"
    data.mkdir()
    secret_path = tmp_path / "secrets.env"
    secret_path.write_text(f"PRAXIS_PRIME_OIDC_SECRET_LOCAL={_SECRET}\n", encoding="utf-8")
    secret_path.chmod(0o600)
    monkeypatch.setenv("PRAXIS_PRIME_SECRETS_FILE", str(secret_path))
    store = AccountStore(data / "accounts.db")
    store.create_account(
        username_text="ada",
        password=_PASSWORD,
        display_name="Ada",
        email="ada@example.com",
    )
    fake = FakeOidc(client_id=_CLIENT, secret=_SECRET)
    add_provider(
        store,
        provider_id="local",
        display_name="Local",
        issuer=fake.issuer,
        client_id=_CLIENT,
        secret_key="PRAXIS_PRIME_OIDC_SECRET_LOCAL",
        email_allowlist=allow,
        role_claim=role_claim,
        role_map=role_map or {},
        dev_loopback=True,
    )
    state = StateDB(data / "prime.db")
    audit = AuditLog(state)
    log = tmp_path / "daemon.log"
    server = GatewayServer(
        host="127.0.0.1",
        port=0,
        token="test-token",
        agent=_Agent(),  # type: ignore[arg-type]
        approvals=ApprovalQueue(),
        logger=JsonLogger(log),
        accounts=store,
        audit=audit,
    )
    server.start()
    opened = World(tmp_path, store, audit, server, fake, log)
    try:
        yield opened
    finally:
        opened.close()
        clear_caches()


def _http(
    port: int,
    method: str,
    path: str,
    *,
    body: dict[str, object] | None = None,
    cookie: str = "",
    csrf: str = "",
    token: str = "",
    fetch: str = "",
) -> tuple[int, list[str], dict[str, str], dict[str, object]]:
    payload = b"" if body is None else json.dumps(body).encode("utf-8")
    lines = [f"{method} {path} HTTP/1.1", "Host: 127.0.0.1", "Connection: close"]
    if fetch:
        lines.append(f"Sec-Fetch-Site: {fetch}")
    if token:
        lines.append(f"Authorization: Bearer {token}")
    if cookie:
        lines.append(f"Cookie: {cookie}")
    if csrf:
        lines.append(f"x-csrf-token: {csrf}")
    if method not in {"GET", "HEAD"}:
        lines.append("Content-Type: application/json")
        lines.append(f"Content-Length: {len(payload)}")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + payload
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        sock.sendall(raw)
        data = b""
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk
    finally:
        sock.close()
    head, _, blob = data.partition(b"\r\n\r\n")
    rows = head.decode("iso-8859-1").split("\r\n")
    status = int(rows[0].split(" ", 2)[1])
    headers: dict[str, str] = {}
    cookies: list[str] = []
    for line in rows[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().lower()
        if key == "set-cookie":
            cookies.append(value.strip())
        headers[key] = value.strip()
    if not blob.strip():
        return status, cookies, headers, {}
    parsed = json.loads(blob.decode("utf-8"))
    assert isinstance(parsed, dict)
    return status, cookies, headers, parsed


def _cookie(lines: list[str], name: str) -> tuple[str, str]:
    prefix = f"{name}="
    for line in lines:
        item = line.split(";", 1)[0].strip()
        if item.startswith(prefix):
            return item[len(prefix) :], line
    return "", ""


def _events(audit: AuditLog) -> list[tuple[str, dict[str, object]]]:
    conn = sqlite3.connect(audit.db.path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT kind, payload_json FROM audit_events ORDER BY rowid").fetchall()
    conn.close()
    return [(str(row["kind"]), json.loads(str(row["payload_json"]))) for row in rows]


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _begin(ctx: World) -> tuple[str, str]:
    status, cookies, _headers, body = _http(
        ctx.port,
        "POST",
        "/v1/auth/oidc/login",
        body={"provider": "local"},
    )
    assert status == 200, body
    binding, line = _cookie(cookies, "pp_oidc")
    assert binding
    assert "HttpOnly" in line and "Secure" in line and "SameSite=Lax" in line
    url = body.get("authorizationUrl")
    assert isinstance(url, str)
    assert "code_challenge_method=S256" in url
    assert "code_verifier" not in url
    assert _SECRET not in url
    return url, binding


def _authorize(ctx: World, url: str) -> str:
    parts = urlsplit(url)
    query = parse_qs(parts.query)
    redirect = query.get("redirect_uri", [""])[0]
    assert redirect == f"http://127.0.0.1:{ctx.port}/v1/auth/oidc/callback"
    status, _cookies, headers, _body = _http(ctx.fake.port, "GET", parts.path + "?" + parts.query)
    assert status == 302, headers
    location = headers["location"]
    prefix = f"http://127.0.0.1:{ctx.port}/v1/auth/oidc/callback?"
    assert location.startswith(prefix)
    return location


def _finish(
    ctx: World,
    location: str,
    binding: str,
    *,
    session: str = "",
) -> tuple[int, list[str], dict[str, str], dict[str, object]]:
    parts = urlsplit(location)
    path = parts.path + "?" + parts.query
    cookie = f"pp_oidc={binding}"
    if session:
        cookie = f"pp_session={session}; {cookie}"
    return _http(ctx.port, "GET", path, cookie=cookie, fetch="cross-site")


def _sign_in(ctx: World) -> tuple[int, list[str], dict[str, str], dict[str, object]]:
    url, binding = _begin(ctx)
    return _finish(ctx, _authorize(ctx, url), binding)


def _quiet(ctx: World, *needles: str) -> None:
    log = ctx.log.read_text(encoding="utf-8") if ctx.log.is_file() else ""
    database = ctx.store.path.read_bytes().decode("latin1")
    audit = Path(ctx.audit.db.path).read_bytes().decode("latin1")
    for needle in needles:
        assert needle not in log
        assert needle not in database
        assert needle not in audit


def _reason(ctx: World) -> str:
    fails = [payload for kind, payload in _events(ctx.audit) if kind == "auth.fail"]
    assert fails
    reason = fails[-1].get("reason")
    assert isinstance(reason, str)
    return reason


def _nav_error(ctx: World, reason: str) -> None:
    status, _cookies, headers, body = _sign_in(ctx)
    assert status == 302
    assert headers["location"] == "/?oidc=error"
    assert body["error"]["code"] == "oidc_error"
    assert body["error"]["message"] == SIGN_IN
    assert reason not in json.dumps(body)
    assert _reason(ctx) == reason
    _quiet(ctx, _SECRET, "eyJ")


def test_oidc_sign_in_checks_pkce_and_hides_the_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="subject-1")
        url, binding = _begin(ctx)
        query = parse_qs(urlsplit(url).query)
        assert query["code_challenge_method"] == ["S256"]
        location = _authorize(ctx, url)
        code = parse_qs(urlsplit(location).query)["code"][0]
        status, cookies, headers, body = _finish(ctx, location, binding)
        assert status == 302
        assert headers["location"] == "/?oidc=ok"
        assert "code=" not in headers["location"]
        assert body["ok"] is True
        assert "stepUpToken" not in body
        assert "mfaToken" not in body
        session, line = _cookie(cookies, "pp_session")
        assert session
        assert "SameSite=Strict" in line
        assert ctx.fake.token_hits == 1
        assert ctx.fake.secret_ok is True
        assert ctx.fake.last_method == "S256"
        assert _s256(ctx.fake.last_verifier) == query["code_challenge"][0]
        cleared = _cookie(cookies, "pp_oidc")[1]
        assert cleared.endswith("Max-Age=0") or "Max-Age=0" in cleared
        kinds = [kind for kind, _payload in _events(ctx.audit)]
        assert "auth.login" in kinds
        login = [payload for kind, payload in _events(ctx.audit) if kind == "auth.login"][-1]
        assert login["method"] == "oidc"
        _quiet(ctx, _SECRET, code, "eyJ")
        status, _cookies, headers, listed = _http(
            ctx.port,
            "GET",
            "/v1/auth/session",
            cookie=f"pp_session={session}",
        )
        assert status == 200
        assert headers.get("location", "") == ""
        assert listed["account"]["username"] == "ada"


def test_bad_signature_is_generic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="subject-1")
        ctx.fake.sign = "bad"
        _nav_error(ctx, "bad_signature")


def test_wrong_issuer_is_generic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="subject-1")
        ctx.fake.iss = ctx.fake.issuer + "-other"
        _nav_error(ctx, "bad_issuer")


def test_wrong_audience_is_generic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="subject-1")
        ctx.fake.aud = "other-client"
        _nav_error(ctx, "bad_audience")


def test_expired_token_is_generic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="subject-1")
        now = int(time.time())
        ctx.fake.iat = now - 400
        ctx.fake.exp = now - 120
        _nav_error(ctx, "expired")


def test_wrong_nonce_is_generic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="subject-1")
        ctx.fake.nonce = "not-the-nonce"
        _nav_error(ctx, "bad_nonce")


def test_reused_nonce_is_generic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="subject-1")
        url, binding = _begin(ctx)
        nonce = parse_qs(urlsplit(url).query)["nonce"][0]
        status, _cookies, headers, _body = _finish(ctx, _authorize(ctx, url), binding)
        assert status == 302 and headers["location"] == "/?oidc=ok"
        url_b, binding_b = _begin(ctx)
        ctx.store.conn.execute(
            "UPDATE oidc_transactions SET nonce_hash = ? WHERE used = 0",
            (_digest(nonce),),
        )
        ctx.store.conn.commit()
        ctx.fake.nonce = nonce
        status, _cookies, headers, body = _finish(ctx, _authorize(ctx, url_b), binding_b)
        assert status == 302 and headers["location"] == "/?oidc=error"
        assert body["error"]["message"] == SIGN_IN
        assert _reason(ctx) == "reused_nonce"
        _quiet(ctx, _SECRET, "eyJ")


def test_reused_state_does_not_call_the_token_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="subject-1")
        url, binding = _begin(ctx)
        location = _authorize(ctx, url)
        status, _cookies, headers, _body = _finish(ctx, location, binding)
        assert status == 302 and headers["location"] == "/?oidc=ok"
        hits = ctx.fake.token_hits
        status, _cookies, headers, body = _finish(ctx, location, binding)
        assert status == 302 and headers["location"] == "/?oidc=error"
        assert body["error"]["code"] == "oidc_error"
        assert ctx.fake.token_hits == hits
        assert _reason(ctx) == "reused_state"


def test_missing_pkce_does_not_call_the_token_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="subject-1")
        url, binding = _begin(ctx)
        location = _authorize(ctx, url)
        ctx.store.conn.execute("UPDATE oidc_transactions SET verifier = '' WHERE used = 0")
        ctx.store.conn.commit()
        status, _cookies, headers, _body = _finish(ctx, location, binding)
        assert status == 302 and headers["location"] == "/?oidc=error"
        assert ctx.fake.token_hits == 0
        assert _reason(ctx) == "missing_pkce"


def test_alg_none_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="subject-1")
        ctx.fake.sign = "none"
        _nav_error(ctx, "alg_rejected")


def test_hs_signed_with_a_public_key_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="subject-1")
        ctx.fake.sign = "hs"
        _nav_error(ctx, "alg_rejected")


def test_jwks_is_cached_and_refreshed_on_rotation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="subject-1")
        status, _cookies, headers, _body = _sign_in(ctx)
        assert status == 302 and headers["location"] == "/?oidc=ok"
        assert ctx.fake.jwks_hits == 1
        status, _cookies, headers, _body = _sign_in(ctx)
        assert status == 302 and headers["location"] == "/?oidc=ok"
        assert ctx.fake.jwks_hits == 1
        ctx.fake.rotate()
        status, _cookies, headers, _body = _sign_in(ctx)
        assert status == 302 and headers["location"] == "/?oidc=ok"
        assert ctx.fake.jwks_hits == 2


def test_email_linking_stays_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        ctx.fake.email = "ada@example.com"
        ctx.fake.email_verified = True
        _nav_error(ctx, "not_linked")
        assert list_identities(ctx.store, ctx.store.get_username("ada").id) == []  # type: ignore[union-attr]
        assert len(ctx.store.list_accounts()) == 1


def test_allowlist_links_a_verified_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with world(tmp_path, monkeypatch, allow=("ada@example.com",)) as ctx:
        ctx.fake.email_verified = False
        _nav_error(ctx, "email_unverified")
        assert list_identities(ctx.store, ctx.store.get_username("ada").id) == []  # type: ignore[union-attr]


def test_allowlist_rejects_a_string_verified_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with world(tmp_path, monkeypatch, allow=("ada@example.com",)) as ctx:
        ctx.fake.email_verified = "true"
        _nav_error(ctx, "email_unverified")


def test_allowlist_links_when_the_flag_is_boolean_true(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with world(tmp_path, monkeypatch, allow=("ada@example.com",)) as ctx:
        ctx.fake.email_verified = True
        status, _cookies, headers, body = _sign_in(ctx)
        assert status == 302 and headers["location"] == "/?oidc=ok"
        assert body["account"]["username"] == "ada"
        assert len(list_identities(ctx.store, ctx.store.get_username("ada").id)) == 1  # type: ignore[union-attr]
        assert len(ctx.store.list_accounts()) == 1


def test_ec_token_and_clock_skew_are_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="subject-1")
        ctx.fake.sign = "ec"
        now = int(time.time())
        ctx.fake.iat = now - 120
        ctx.fake.exp = now - 30
        status, _cookies, headers, _body = _sign_in(ctx)
        assert status == 302 and headers["location"] == "/?oidc=ok"


def test_future_nbf_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="subject-1")
        ctx.fake.nbf = int(time.time()) + 120
        _nav_error(ctx, "bad_time")


def test_multiple_audiences_need_azp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="subject-1")
        ctx.fake.aud = [_CLIENT, "other"]
        ctx.fake.include_azp = False
        _nav_error(ctx, "bad_azp")
        ctx.fake.include_azp = True
        ctx.fake.azp = _CLIENT
        status, _cookies, headers, _body = _sign_in(ctx)
        assert status == 302 and headers["location"] == "/?oidc=ok"


def test_cross_site_login_post_stays_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        status, _cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/oidc/login",
            body={"provider": "local"},
            fetch="cross-site",
        )
        assert status == 403
        assert body["error"]["code"] == "forbidden"


def test_linking_and_unlinking_need_step_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        status, cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/login",
            body={"username": "ada", "password": _PASSWORD},
        )
        assert status == 200
        session, _line = _cookie(cookies, "pp_session")
        csrf = str(body["csrfToken"])
        status, _cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/oidc/link",
            body={"provider": "local"},
            cookie=f"pp_session={session}",
            csrf=csrf,
        )
        assert status == 401
        assert body["error"]["message"] == CHANGE
        actions = [
            payload.get("action") for kind, payload in _events(ctx.audit) if kind == "auth.oidc"
        ]
        assert "step_up" in actions
        pending = ctx.store.conn.execute(
            "SELECT COUNT(*) AS n FROM oidc_transactions WHERE used = 0"
        ).fetchone()
        assert pending is not None and int(pending["n"]) == 0
        live = ctx.store.session_from_token(session)
        assert live is not None
        step = Factors(ctx.store).prove_password(live.account_id, _PASSWORD, "", session_id=live.id)
        status, cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/oidc/link",
            body={"provider": "local", "stepUpToken": step},
            cookie=f"pp_session={session}",
            csrf=csrf,
        )
        assert status == 200, body
        url = str(body["authorizationUrl"])
        binding, _line = _cookie(cookies, "pp_oidc")
        status, _cookies, headers, body = _finish(
            ctx, _authorize(ctx, url), binding, session=session
        )
        assert status == 302 and headers["location"] == "/?oidc=linked"
        assert "stepUpToken" not in body
        ada = ctx.store.get_username("ada")
        assert ada is not None
        assert len(list_identities(ctx.store, ada.id)) == 1
        status, _cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/oidc/unlink",
            body={"issuer": ctx.fake.issuer, "subject": "subject-1"},
            cookie=f"pp_session={session}",
            csrf=csrf,
        )
        assert status == 401
        assert body["error"]["message"] == CHANGE
        assert len(list_identities(ctx.store, ada.id)) == 1
        status, _cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/oidc/unlink",
            body={"issuer": ctx.fake.issuer, "subject": "subject-1", "stepUpToken": "nope"},
            cookie=f"pp_session={session}",
        )
        assert status == 403
        step_b = Factors(ctx.store).prove_password(ada.id, _PASSWORD, "", session_id=live.id)
        saved = ctx.store.conn.execute(
            "SELECT password_hash FROM accounts WHERE id = ?",
            (ada.id,),
        ).fetchone()
        assert saved is not None
        original = str(saved["password_hash"])
        ctx.store.conn.execute(
            "UPDATE accounts SET password_hash = '!' WHERE id = ?",
            (ada.id,),
        )
        ctx.store.conn.commit()
        status, _cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/oidc/unlink",
            body={"issuer": ctx.fake.issuer, "subject": "subject-1", "stepUpToken": step_b},
            cookie=f"pp_session={session}",
            csrf=csrf,
        )
        assert status == 409
        assert body["error"]["code"] == "last_factor"
        assert body["error"]["message"] == CHANGE
        left = ctx.store.conn.execute(
            "SELECT COUNT(*) AS n FROM step_up WHERE account_id = ?",
            (ada.id,),
        ).fetchone()
        assert left is not None and int(left["n"]) == 1
        assert len(list_identities(ctx.store, ada.id)) == 1
        ctx.store.conn.execute(
            "UPDATE accounts SET password_hash = ? WHERE id = ?",
            (original, ada.id),
        )
        ctx.store.conn.commit()
        status, _cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/oidc/unlink",
            body={"issuer": ctx.fake.issuer, "subject": "subject-1", "stepUpToken": step_b},
            cookie=f"pp_session={session}",
            csrf=csrf,
        )
        assert status == 200, body
        assert list_identities(ctx.store, ada.id) == []


def test_bearer_cannot_link(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        status, cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/login",
            body={"username": "ada", "password": _PASSWORD},
        )
        session, _line = _cookie(cookies, "pp_session")
        live = ctx.store.session_from_token(session)
        assert live is not None
        step = Factors(ctx.store).prove_password(live.account_id, _PASSWORD, "", session_id=live.id)
        status, _cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/oidc/link",
            body={"provider": "local", "stepUpToken": step},
            token="test-token",
        )
        assert status == 401
        left = ctx.store.conn.execute("SELECT COUNT(*) AS n FROM step_up").fetchone()
        assert left is not None and int(left["n"]) == 1
        del body


def test_totp_still_required_after_oidc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        ada = ctx.store.get_username("ada")
        assert ada is not None
        enrolled = Factors(ctx.store).begin_totp(ada.id)
        totp = pyotp.TOTP(enrolled.secret)
        confirmed = int(time.time()) // 30
        Factors(ctx.store).confirm_totp(ada.id, totp.generate_otp(confirmed))
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="subject-1")
        status, cookies, headers, body = _sign_in(ctx)
        assert status == 302 and headers["location"] == "/?oidc=mfa"
        assert "mfaToken" not in body
        assert "stepUpToken" not in body
        assert _cookie(cookies, "pp_session")[0] == ""
        mfa, line = _cookie(cookies, "pp_mfa")
        assert mfa and "SameSite=Strict" in line
        status, cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/login/totp",
            body={"mfaToken": "", "code": totp.generate_otp(confirmed + 1)},
            cookie=f"pp_mfa={mfa}",
        )
        assert status == 200, body
        assert _cookie(cookies, "pp_session")[0]
        assert "Max-Age=0" in _cookie(cookies, "pp_mfa")[1]
        assert cookie_value(f"pp_mfa={mfa}", "pp_mfa") == mfa


def test_role_map_never_changes_the_owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with world(tmp_path, monkeypatch, role_claim="roles", role_map=dict(ENTRA_ROLE_MAP)) as ctx:
        ctx.store.create_account(
            username_text="bea",
            password=_PASSWORD,
            display_name="Bea",
            role="operator",
        )
        prelink(ctx.store, username_text="bea", issuer=ctx.fake.issuer, subject="bea-sub")
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="ada-sub")
        ctx.fake.sign = "ec"
        ctx.fake.subject = "bea-sub"
        status, _cookies, headers, _body = _sign_in(ctx)
        assert status == 302 and headers["location"] == "/?oidc=ok"
        assert ctx.store.get_username("bea").role == "operator"  # type: ignore[union-attr]
        ctx.fake.roles = ["Praxis.Admin"]
        status, _cookies, headers, _body = _sign_in(ctx)
        assert headers["location"] == "/?oidc=ok"
        assert ctx.store.get_username("bea").role == "admin"  # type: ignore[union-attr]
        ctx.fake.roles = ["Praxis.Viewer"]
        status, _cookies, headers, _body = _sign_in(ctx)
        assert headers["location"] == "/?oidc=ok"
        assert ctx.store.get_username("bea").role == "viewer"  # type: ignore[union-attr]
        ctx.fake.subject = "ada-sub"
        ctx.fake.roles = ["Praxis.Viewer"]
        status, _cookies, headers, _body = _sign_in(ctx)
        assert headers["location"] == "/?oidc=ok"
        assert ctx.store.get_username("ada").role == "owner"  # type: ignore[union-attr]


def test_http_issuer_and_well_known_url_are_refused(tmp_path: Path) -> None:
    store = AccountStore(tmp_path / "accounts.db")
    with pytest.raises(OidcError) as caught:
        add_provider(
            store,
            provider_id="local",
            display_name="Local",
            issuer="http://127.0.0.1:9",
            client_id=_CLIENT,
            secret_key="PRAXIS_PRIME_OIDC_SECRET_LOCAL",
            dev_loopback=False,
        )
    assert caught.value.reason == "url_rejected"
    with pytest.raises(OidcError) as caught:
        add_provider(
            store,
            provider_id="local",
            display_name="Local",
            issuer="https://example.com/.well-known/openid-configuration",
            client_id=_CLIENT,
            secret_key="PRAXIS_PRIME_OIDC_SECRET_LOCAL",
        )
    assert caught.value.reason == "url_rejected"


def test_presets_do_not_silently_replace_an_issuer() -> None:
    issuer, preset, claim, mapping = resolve_provider_settings(
        preset="google",
        issuer="",
        tenant="",
        role_claim="",
        role_map=[],
        no_role_map=False,
    )
    assert issuer == "https://accounts.google.com"
    assert preset == "google"
    assert mapping == {}
    assert claim == ""
    with pytest.raises(ValueError):
        resolve_provider_settings(
            preset="google",
            issuer="https://evil.example",
            tenant="",
            role_claim="",
            role_map=[],
            no_role_map=False,
        )
    issuer, _preset, claim, mapping = resolve_provider_settings(
        preset="entra",
        issuer="",
        tenant="contoso.onmicrosoft.com",
        role_claim="",
        role_map=[],
        no_role_map=False,
    )
    assert issuer == "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0"
    assert mapping["Praxis.Admin"] == "admin"
    assert claim == "roles"
    _issuer, _preset, claim, mapping = resolve_provider_settings(
        preset="entra",
        issuer="",
        tenant="contoso.onmicrosoft.com",
        role_claim="",
        role_map=[],
        no_role_map=True,
    )
    assert mapping == {} and claim == ""
    with pytest.raises(ValueError):
        resolve_provider_settings(
            preset="entra",
            issuer="",
            tenant="../evil",
            role_claim="",
            role_map=[],
            no_role_map=False,
        )
    with pytest.raises(ValueError):
        resolve_provider_settings(
            preset="keycloak",
            issuer="",
            tenant="",
            role_claim="",
            role_map=[],
            no_role_map=False,
        )


def test_cli_stores_the_secret_and_can_prelink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data = tmp_path / "data"
    config = tmp_path / "config"
    data.mkdir()
    config.mkdir()
    secret_path = config / "secrets.env"
    monkeypatch.setenv("PRAXIS_PRIME_SECRETS_FILE", str(secret_path))
    store = AccountStore(data / "accounts.db")
    store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
    fake = FakeOidc(client_id=_CLIENT, secret=_SECRET)
    try:
        monkeypatch.setattr(sys, "stdin", io.StringIO(_SECRET + "\n"))
        code = main(
            [
                "oidc",
                "add",
                "local",
                "--display-name",
                "Local",
                "--issuer",
                fake.issuer,
                "--client-id",
                _CLIENT,
                "--dev-loopback",
                "--client-secret-stdin",
                "--data-dir",
                str(data),
                "--config-dir",
                str(config),
            ]
        )
        printed = capsys.readouterr()
        assert code == 0, printed.err
        assert _SECRET not in printed.out
        assert _SECRET not in printed.err
        assert "PRAXIS_PRIME_OIDC_SECRET_LOCAL" in printed.out
        assert secret_path.read_text(encoding="utf-8").count(_SECRET) == 1
        assert _SECRET.encode() not in (data / "accounts.db").read_bytes()
        code = main(["oidc", "list", "--data-dir", str(data), "--config-dir", str(config)])
        listed = capsys.readouterr().out
        assert code == 0
        assert "local" in listed and _SECRET not in listed
        code = main(
            [
                "oidc",
                "link",
                "ada",
                "--issuer",
                fake.issuer,
                "--subject",
                "cli-sub",
                "--data-dir",
                str(data),
                "--config-dir",
                str(config),
            ]
        )
        assert code == 0
        ada = store.get_username("ada")
        assert ada is not None
        assert list_identities(store, ada.id)[0]["subject"] == "cli-sub"
        saved = store.conn.execute(
            "SELECT password_hash FROM accounts WHERE id = ?",
            (ada.id,),
        ).fetchone()
        assert saved is not None
        store.conn.execute("UPDATE accounts SET password_hash = '!' WHERE id = ?", (ada.id,))
        store.conn.commit()
        code = main(
            ["oidc", "remove", "local", "--data-dir", str(data), "--config-dir", str(config)]
        )
        assert code == 2
        assert "last sign-in factor" in capsys.readouterr().err
        assert secret_path.read_text(encoding="utf-8").count(_SECRET) == 1
        store.conn.execute(
            "UPDATE accounts SET password_hash = ? WHERE id = ?",
            (str(saved["password_hash"]), ada.id),
        )
        store.conn.commit()
        code = main(
            ["oidc", "remove", "local", "--data-dir", str(data), "--config-dir", str(config)]
        )
        assert code == 0
        assert _SECRET not in secret_path.read_text(encoding="utf-8")
        assert list_identities(store, ada.id) == []
    finally:
        fake.close()
        clear_caches()


def test_sign_in_shell_matches_dist_and_has_no_inline_code() -> None:
    shell = _REPO / "ui" / "shell"
    dist = _REPO / "ui" / "dist"
    for name in ("index.html", "assets/app.css", "assets/app.js"):
        built = (dist / name).read_text(encoding="utf-8")
        assert (shell / name).read_text(encoding="utf-8") == built
    html = (dist / "index.html").read_text(encoding="utf-8")
    script = (dist / "assets" / "app.js").read_text(encoding="utf-8")
    assert "onclick" not in html
    assert "style=" not in html
    assert '<script src="/assets/app.js">' in html
    assert "Sign in with " in script
    assert "unsafe-inline" not in html
    assert "unsafe-eval" not in html
