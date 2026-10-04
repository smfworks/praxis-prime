"""OIDC sign-in against a local fake provider."""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import secrets as secrets_mod
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
from praxis_prime.accounts import oidc as oidc_mod
from praxis_prime.accounts.db import AccountStore, cookie_value
from praxis_prime.accounts.factors import Factors
from praxis_prime.accounts.oidc import (
    _PENDING_PER_CLIENT,
    ENTRA_ROLE_MAP,
    NONCE_TTL_SECONDS,
    TXN_TTL_SECONDS,
    OidcError,
    add_provider,
    clear_caches,
    forget_pending_verifier,
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
    issuer_slash: bool = False,
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
    if issuer_slash:
        fake.issuer = fake.issuer + "/"
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
        state = parse_qs(urlsplit(url).query)["state"][0]
        forget_pending_verifier(state)
        location = _authorize(ctx, url)
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
        pem = ctx.fake.rsa.as_pem(private=False)
        if isinstance(pem, str):
            pem = pem.encode("utf-8")
        token = ctx.fake._issue("nonce-check", _CLIENT)
        header, payload, signature = token.split(".")
        digest = hmac.new(pem, f"{header}.{payload}".encode("ascii"), hashlib.sha256).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        assert signature == expected
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
    with world(tmp_path, monkeypatch, allow=("bea@example.com",)) as ctx:
        ctx.store.create_account(
            username_text="bea",
            password=_PASSWORD,
            display_name="Bea",
            role="viewer",
            email="bea@example.com",
        )
        ctx.fake.email = "bea@example.com"
        ctx.fake.subject = "bea-sub"
        ctx.fake.email_verified = True
        status, _cookies, headers, body = _sign_in(ctx)
        assert status == 302 and headers["location"] == "/?oidc=ok"
        assert body["account"]["username"] == "bea"
        bea = ctx.store.get_username("bea")
        assert bea is not None
        assert len(list_identities(ctx.store, bea.id)) == 1
        assert len(ctx.store.list_accounts()) == 2


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
        binding, line = _cookie(cookies, "pp_oidc")
        assert f"Max-Age={TXN_TTL_SECONDS}" in line
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


def test_spa_has_oidc_sign_in_and_no_inline_handlers() -> None:
    html = (_REPO / "ui" / "dist" / "index.html").read_text(encoding="utf-8")
    app = (_REPO / "ui" / "src" / "App.tsx").read_text(encoding="utf-8")
    views = (_REPO / "ui" / "src" / "views.tsx").read_text(encoding="utf-8")
    assert "onclick" not in html.lower()
    assert "unsafe-inline" not in html
    assert "unsafe-eval" not in html
    assert 'id="root"' in html
    assert "Sign in with" in app
    assert "/v1/auth/oidc/login" in app
    assert "/v1/auth/oidc/link" in views
    assert "/v1/auth/oidc/unlink" in views
    # The code form must open for ?oidc=mfa even when mfaToken is still empty.
    assert "oidcNeedsCode" in app
    assert "codeStep || mfaToken" in app
    assert "{mfaToken ? (" not in app


def test_allowlist_is_ascii_and_refuses_privileged_accounts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = AccountStore(tmp_path / "plain.db")
    with pytest.raises(OidcError) as caught:
        add_provider(
            store,
            provider_id="local",
            display_name="Local",
            issuer="https://idp.example",
            client_id=_CLIENT,
            secret_key="PRAXIS_PRIME_OIDC_SECRET_LOCAL",
            email_allowlist=("straße@example.com",),
        )
    assert caught.value.reason == "bad_request"
    store.close()
    # The audit log keeps one auth.fail per name per minute, so each refusal
    # needs its own daemon or the later reason is hidden.
    owner_dir = tmp_path / "owner"
    admin_dir = tmp_path / "admin"
    ascii_dir = tmp_path / "ascii"
    owner_dir.mkdir()
    admin_dir.mkdir()
    ascii_dir.mkdir()
    with world(owner_dir, monkeypatch, allow=("ada@example.com",)) as ctx:
        ctx.fake.subject = "ada-oidc"
        _nav_error(ctx, "privileged_link")
        ada = ctx.store.get_username("ada")
        assert ada is not None and list_identities(ctx.store, ada.id) == []
        status, cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/login",
            body={"username": "ada", "password": _PASSWORD},
        )
        assert status == 200
        session, _line = _cookie(cookies, "pp_session")
        csrf = str(body["csrfToken"])
        live = ctx.store.session_from_token(session)
        assert live is not None
        step = Factors(ctx.store).prove_password(ada.id, _PASSWORD, "", session_id=live.id)
        ctx.fake.email = "straße@example.com"
        ctx.fake.subject = "unicode-sub"
        status, cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/oidc/link",
            body={"provider": "local", "stepUpToken": step},
            cookie=f"pp_session={session}",
            csrf=csrf,
        )
        assert status == 200, body
        binding, _line = _cookie(cookies, "pp_oidc")
        status, _cookies, headers, _body = _finish(
            ctx,
            _authorize(ctx, str(body["authorizationUrl"])),
            binding,
            session=session,
        )
        assert status == 302 and headers["location"] == "/?oidc=linked"
        linked = [
            row
            for row in list_identities(ctx.store, ada.id)
            if row["subject"] == "unicode-sub"
        ]
        assert linked and linked[0]["email"] == ""
    with world(admin_dir, monkeypatch, allow=("cam@example.com",)) as ctx:
        ctx.store.create_account(
            username_text="cam",
            password=_PASSWORD,
            display_name="Cam",
            role="admin",
            email="cam@example.com",
        )
        ctx.fake.subject = "cam-oidc"
        ctx.fake.email = "cam@example.com"
        _nav_error(ctx, "privileged_link")
        cam = ctx.store.get_username("cam")
        assert cam is not None and cam.role == "admin"
        assert list_identities(ctx.store, cam.id) == []
    with world(ascii_dir, monkeypatch, allow=("strasse@example.com",)) as ctx:
        ctx.store.create_account(
            username_text="dio",
            password=_PASSWORD,
            display_name="Dio",
            role="viewer",
            email="strasse@example.com",
        )
        ctx.fake.subject = "dio-sub"
        ctx.fake.email = "straße@example.com"
        _nav_error(ctx, "email_not_allowed")
        dio = ctx.store.get_username("dio")
        assert dio is not None and list_identities(ctx.store, dio.id) == []
        ctx.fake.email = "STRASSE@example.com"
        status, _cookies, headers, body = _sign_in(ctx)
        assert status == 302 and headers["location"] == "/?oidc=ok"
        assert body["account"]["username"] == "dio"


def test_oidc_add_again_keeps_the_stored_secret(
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
    replacement = "replacement-secret-value"
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
        assert code == 0, capsys.readouterr().err
        monkeypatch.setattr(sys, "stdin", io.StringIO(replacement + "\n"))
        code = main(
            [
                "oidc",
                "add",
                "local",
                "--display-name",
                "Local again",
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
        assert code == 2
        assert "remove" in printed.err
        assert replacement not in printed.out
        assert replacement not in printed.err
        stored = secret_path.read_text(encoding="utf-8")
        assert stored.count(_SECRET) == 1
        assert replacement not in stored
        monkeypatch.setattr(sys, "stdin", io.StringIO(replacement + "\n"))
        code = main(
            [
                "oidc",
                "add",
                "NOT-AN-ID",
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
        assert code == 2
        assert replacement not in secret_path.read_text(encoding="utf-8")
    finally:
        fake.close()
        clear_caches()
        store.close()


def test_one_client_cannot_exhaust_pending_sign_ins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert NONCE_TTL_SECONDS == 10 * 60
    with world(tmp_path, monkeypatch) as ctx:
        status, cookies, _headers, body = _http(ctx.port, "GET", "/v1/auth/oidc/providers")
        assert status == 200, body
        client, client_line = _cookie(cookies, "pp_client")
        assert client.startswith("v1.")
        assert "HttpOnly" in client_line and "Secure" in client_line
        cookie = f"pp_client={client}"
        status, login_cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/oidc/login",
            body={"provider": "local"},
            cookie=cookie,
        )
        assert status == 200, body
        _binding, binding_line = _cookie(login_cookies, "pp_oidc")
        assert f"Max-Age={TXN_TTL_SECONDS}" in binding_line
        row = ctx.store.conn.execute(
            "SELECT expires_at, created_at FROM oidc_transactions WHERE used = 0"
        ).fetchone()
        assert row is not None
        from datetime import datetime

        lifetime = (
            datetime.fromisoformat(str(row["expires_at"]))
            - datetime.fromisoformat(str(row["created_at"]))
        ).total_seconds()
        assert 60 <= lifetime <= 150
        for _ in range(_PENDING_PER_CLIENT - 1):
            status, _cookies, _headers, body = _http(
                ctx.port,
                "POST",
                "/v1/auth/oidc/login",
                body={"provider": "local"},
                cookie=cookie,
            )
            assert status == 200, body
        status, _cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/oidc/login",
            body={"provider": "local"},
            cookie=cookie,
        )
        assert status == 429
        assert body["error"]["message"] == SIGN_IN
        status, other_cookies, _headers, body = _http(ctx.port, "GET", "/v1/auth/oidc/providers")
        assert status == 200, body
        other, _line = _cookie(other_cookies, "pp_client")
        assert other and other != client
        status, _cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/oidc/login",
            body={"provider": "local"},
            cookie=f"pp_client={other}",
        )
        assert status == 200, body
        from datetime import UTC, timedelta

        stale = (datetime.now(UTC) - timedelta(seconds=5)).isoformat(timespec="seconds")
        ctx.store.conn.execute("UPDATE oidc_transactions SET expires_at = ?", (stale,))
        ctx.store.conn.commit()
        status, _cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/oidc/login",
            body={"provider": "local"},
            cookie=cookie,
        )
        assert status == 200, body


def _pending_keys(ctx: World) -> list[str]:
    rows = ctx.store.conn.execute(
        "SELECT client_key FROM oidc_transactions WHERE used = 0"
    ).fetchall()
    return [str(row["client_key"]) for row in rows]


def test_unsigned_client_cookies_share_one_bucket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        opened = 0
        for _ in range(_PENDING_PER_CLIENT + 4):
            status, _cookies, _headers, body = _http(
                ctx.port,
                "POST",
                "/v1/auth/oidc/login",
                body={"provider": "local"},
            )
            if status == 200:
                opened += 1
            else:
                assert status == 429, body
        for index in range(4):
            status, _cookies, _headers, body = _http(
                ctx.port,
                "POST",
                "/v1/auth/oidc/login",
                body={"provider": "local"},
                cookie=f"pp_client=forged-{index}",
            )
            assert status == 429, body
        status, _cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/oidc/login",
            body={"provider": "local"},
            cookie="pp_client=v1.not-a-real-id." + ("ab" * 32),
        )
        assert status == 429, body
        assert opened == _PENDING_PER_CLIENT
        keys = _pending_keys(ctx)
        assert len(keys) == _PENDING_PER_CLIENT
        assert len(set(keys)) == 1


def test_signed_client_can_start_when_the_pool_is_full(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        status, cookies, _headers, body = _http(ctx.port, "GET", "/v1/auth/oidc/providers")
        assert status == 200, body
        client, _line = _cookie(cookies, "pp_client")
        assert client.startswith("v1.")
        cookie = f"pp_client={client}"
        for _ in range(_PENDING_PER_CLIENT):
            status, _cookies, _headers, body = _http(
                ctx.port,
                "POST",
                "/v1/auth/oidc/login",
                body={"provider": "local"},
            )
            assert status == 200, body
        status, _cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/oidc/login",
            body={"provider": "local"},
        )
        assert status == 429, body
        status, _cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/oidc/login",
            body={"provider": "local"},
            cookie=cookie,
        )
        assert status == 200, body
        oldest = "a" * 64
        planted = "planted-verifier-value"
        ctx.store.conn.execute(
            """
            INSERT INTO oidc_transactions (
                state_hash, binding_hash, provider_id, nonce_hash, verifier,
                kind, account_id, session_id, redirect_uri, expires_at,
                used, created_at, client_key
            ) VALUES (?, ?, 'local', ?, '', 'login', '', '', ?, ?, 0, ?, ?)
            """,
            (
                oldest,
                "b" * 64,
                "c" * 64,
                "http://127.0.0.1:9/v1/auth/oidc/callback",
                "2099-01-01T00:00:00+00:00",
                "2000-01-01T00:00:00+00:00",
                "filler-oldest",
            ),
        )
        oidc_mod._verifiers[oldest] = (time.time() + 600, planted)
        have = len(_pending_keys(ctx))
        for index in range(oidc_mod._PENDING_CAP - have):
            ctx.store.conn.execute(
                """
                INSERT INTO oidc_transactions (
                    state_hash, binding_hash, provider_id, nonce_hash, verifier,
                    kind, account_id, session_id, redirect_uri, expires_at,
                    used, created_at, client_key
                ) VALUES (?, ?, 'local', ?, '', 'login', '', '', ?, ?, 0, ?, ?)
                """,
                (
                    f"{index:064x}",
                    "d" * 64,
                    "e" * 64,
                    "http://127.0.0.1:9/v1/auth/oidc/callback",
                    "2099-01-01T00:00:00+00:00",
                    "2020-01-01T00:00:00+00:00",
                    f"filler-{index}",
                ),
            )
        ctx.store.conn.commit()
        assert len(_pending_keys(ctx)) == oidc_mod._PENDING_CAP
        status, _cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/oidc/login",
            body={"provider": "local"},
            cookie=cookie,
        )
        assert status == 200, body
        gone = ctx.store.conn.execute(
            "SELECT 1 FROM oidc_transactions WHERE state_hash = ?",
            (oldest,),
        ).fetchone()
        assert gone is None
        assert oldest not in oidc_mod._verifiers
        # The signed client is under its own cap here (two rows). Fill it.
        for _ in range(_PENDING_PER_CLIENT - 2):
            status, _cookies, _headers, body = _http(
                ctx.port,
                "POST",
                "/v1/auth/oidc/login",
                body={"provider": "local"},
                cookie=cookie,
            )
            assert status == 200, body
        held = "f" * 64
        ctx.store.conn.execute(
            """
            INSERT INTO oidc_transactions (
                state_hash, binding_hash, provider_id, nonce_hash, verifier,
                kind, account_id, session_id, redirect_uri, expires_at,
                used, created_at, client_key
            ) VALUES (?, ?, 'local', ?, '', 'login', '', '', ?, ?, 0, ?, ?)
            """,
            (
                held,
                "b" * 64,
                "c" * 64,
                "http://127.0.0.1:9/v1/auth/oidc/callback",
                "2099-01-01T00:00:00+00:00",
                "1999-01-01T00:00:00+00:00",
                "filler-held",
            ),
        )
        ctx.store.conn.commit()
        oidc_mod._verifiers[held] = (time.time() + 600, planted)
        status, _cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/oidc/login",
            body={"provider": "local"},
            cookie=cookie,
        )
        assert status == 429, body
        still = ctx.store.conn.execute(
            "SELECT 1 FROM oidc_transactions WHERE state_hash = ?",
            (held,),
        ).fetchone()
        assert still is not None
        assert oidc_mod._verifiers[held][1] == planted


def test_client_cookie_mint_is_rate_limited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        minted = 0
        for _ in range(oidc_mod._CLIENT_MINT_LIMIT + 1):
            status, cookies, _headers, body = _http(ctx.port, "GET", "/v1/auth/oidc/providers")
            assert status == 200, body
            if _cookie(cookies, "pp_client")[0]:
                minted += 1
        assert minted == oidc_mod._CLIENT_MINT_LIMIT
        status, cookies, _headers, body = _http(ctx.port, "GET", "/v1/auth/session")
        assert status == 401, body
        assert _cookie(cookies, "pp_client")[0] == ""
        status, cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/oidc/login",
            body={"provider": "local"},
        )
        assert status == 200, body
        assert _cookie(cookies, "pp_client")[0] == ""
        status, _cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/oidc/login",
            body={"provider": "local"},
            cookie="pp_client=also-forged",
        )
        assert status == 200, body
        keys = _pending_keys(ctx)
        assert len(keys) == 2
        assert len(set(keys)) == 1


def test_logged_out_session_mints_a_signed_client_cookie(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        status, cookies, _headers, body = _http(ctx.port, "GET", "/v1/auth/session")
        assert status == 401, body
        client, line = _cookie(cookies, "pp_client")
        assert client.startswith("v1.")
        assert "HttpOnly" in line and "Path=/" in line
        status, _cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/oidc/login",
            body={"provider": "local"},
            cookie=f"pp_client={client}",
        )
        assert status == 200, body
        assert len(_pending_keys(ctx)) == 1


def test_pkce_verifier_is_not_written_to_the_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="subject-1")
        seen: list[tuple[int, str]] = []
        real = secrets_mod.token_urlsafe

        def spy(nbytes: int = 32) -> str:
            value = real(nbytes)
            seen.append((nbytes, value))
            return value

        monkeypatch.setattr(secrets_mod, "token_urlsafe", spy)
        url, binding = _begin(ctx)
        verifiers = [value for size, value in seen if size == 48]
        assert len(verifiers) == 1
        verifier = verifiers[0]
        ctx.store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        ctx.store.conn.commit()
        blob = ctx.store.path.read_bytes()
        assert verifier.encode("ascii") not in blob
        wal = Path(str(ctx.store.path) + "-wal")
        if wal.is_file():
            assert verifier.encode("ascii") not in wal.read_bytes()
        row = ctx.store.conn.execute(
            "SELECT verifier FROM oidc_transactions WHERE used = 0"
        ).fetchone()
        assert row is not None and str(row["verifier"]) == ""
        status, _cookies, headers, _body = _finish(ctx, _authorize(ctx, url), binding)
        assert status == 302 and headers["location"] == "/?oidc=ok"
        ctx.store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        assert verifier.encode("ascii") not in ctx.store.path.read_bytes()


def test_private_resolved_addresses_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    refused = (
        "10.1.2.3",
        "127.0.0.1",
        "169.254.1.1",
        "192.168.1.1",
        "172.16.5.5",
        "::1",
        "fc00::1",
        "fe80::1",
        "::ffff:10.0.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "240.0.0.1",
        "::",
    )
    for item in refused:
        assert oidc_mod._address_blocked(item) is True, item
    assert oidc_mod._address_blocked("8.8.8.8") is False
    assert oidc_mod._address_blocked("172.15.0.1") is False
    assert oidc_mod._address_blocked("172.32.0.1") is False
    assert oidc_mod._address_blocked("2001:4860:4860::8888") is False
    assert oidc_mod._address_blocked("::ffff:8.8.8.8") is False
    assert oidc_mod._address_blocked("::a00:1") is True
    assert oidc_mod._address_blocked("::10.0.0.1") is True
    assert oidc_mod._address_blocked("2002:a9fe:a9fe::") is True
    assert oidc_mod._address_blocked("64:ff9b::a00:1") is True
    assert oidc_mod._address_blocked("64:ff9b::808:808") is False
    assert oidc_mod._address_blocked("::7f00:1") is True

    def refuse_connect(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("connected to an unchecked address")

    monkeypatch.setattr(socket, "create_connection", refuse_connect)
    for url in (
        "https://10.0.0.1/jwks",
        "https://127.0.0.1/jwks",
        "https://169.254.1.1/jwks",
        "https://192.168.1.1/jwks",
        "https://172.16.0.1/jwks",
        "https://[::1]/jwks",
        "https://[fc00::1]/jwks",
        "https://[fe80::1]/jwks",
        "https://[::ffff:10.0.0.1]/jwks",
    ):
        with pytest.raises(OidcError) as caught:
            oidc_mod._request(
                url,
                method="GET",
                body=None,
                headers={},
                allow_http=False,
                limit=128,
            )
        assert caught.value.reason == "url_rejected", url
    monkeypatch.setattr(oidc_mod, "_resolve", lambda _host, _port: ["10.1.2.3"])
    with pytest.raises(OidcError) as caught:
        oidc_mod._request(
            "https://idp.example/jwks",
            method="GET",
            body=None,
            headers={},
            allow_http=False,
            limit=128,
        )
    assert caught.value.reason == "url_rejected"
    monkeypatch.setattr(oidc_mod, "_resolve", lambda _host, _port: ["8.8.8.8", "10.0.0.1"])
    with pytest.raises(OidcError) as caught:
        oidc_mod._request(
            "https://idp.example/token",
            method="POST",
            body=b"grant_type=authorization_code",
            headers={},
            allow_http=False,
            limit=128,
        )
    assert caught.value.reason == "url_rejected"
    monkeypatch.setattr(oidc_mod, "_resolve", lambda _host, _port: ["10.0.0.1"])
    with pytest.raises(OidcError) as caught:
        oidc_mod._request(
            "http://127.0.0.1:9/token",
            method="GET",
            body=None,
            headers={},
            allow_http=True,
            limit=128,
        )
    assert caught.value.reason == "url_rejected"
    seen: list[tuple[str, int]] = []

    def record(address: tuple[str, int], timeout: float | None = None) -> None:
        del timeout
        seen.append(address)
        raise TimeoutError("stopped")

    monkeypatch.setattr(socket, "create_connection", record)
    monkeypatch.setattr(oidc_mod, "_resolve", lambda _host, _port: ["8.8.8.8"])
    with pytest.raises(OidcError) as caught:
        oidc_mod._request(
            "https://idp.example/.well-known/openid-configuration",
            method="GET",
            body=None,
            headers={},
            allow_http=False,
            limit=128,
        )
    assert caught.value.reason == "provider_unreachable"
    assert seen == [("8.8.8.8", 443)]

    tried: list[tuple[str, int]] = []

    def fail_first(address: tuple[str, int], timeout: float | None = None) -> None:
        del timeout
        tried.append(address)
        raise TimeoutError("slow")

    monkeypatch.setattr(socket, "create_connection", fail_first)
    monkeypatch.setattr(oidc_mod, "_resolve", lambda _host, _port: ["8.8.8.8", "1.1.1.1"])
    with pytest.raises(OidcError) as caught:
        oidc_mod._request(
            "https://idp.example/jwks",
            method="GET",
            body=None,
            headers={},
            allow_http=False,
            limit=128,
        )
    assert caught.value.reason == "provider_unreachable"
    assert tried == [("8.8.8.8", 443), ("1.1.1.1", 443)]
    monkeypatch.setattr(oidc_mod, "_resolve", lambda _host, _port: ["::a00:1"])
    monkeypatch.setattr(socket, "create_connection", refuse_connect)
    with pytest.raises(OidcError) as caught:
        oidc_mod._request(
            "https://idp.example/jwks",
            method="GET",
            body=None,
            headers={},
            allow_http=False,
            limit=128,
        )
    assert caught.value.reason == "url_rejected"


def test_jwks_refetch_is_rate_limited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="subject-1")
        status, _cookies, headers, _body = _sign_in(ctx)
        assert status == 302 and headers["location"] == "/?oidc=ok"
        assert ctx.fake.jwks_hits == 1
        ctx.fake.rotate()
        status, _cookies, headers, _body = _sign_in(ctx)
        assert status == 302 and headers["location"] == "/?oidc=ok"
        assert ctx.fake.jwks_hits == 2
        ctx.fake.rotate()
        _nav_error(ctx, "bad_signature")
        assert ctx.fake.jwks_hits == 2
        oidc_mod._jwks_forced["local"] = 0
        status, _cookies, headers, _body = _sign_in(ctx)
        assert status == 302 and headers["location"] == "/?oidc=ok"
        assert ctx.fake.jwks_hits == 3


def test_role_map_waits_until_totp_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with world(tmp_path, monkeypatch, role_claim="roles", role_map=dict(ENTRA_ROLE_MAP)) as ctx:
        bea = ctx.store.create_account(
            username_text="bea",
            password=_PASSWORD,
            display_name="Bea",
            role="operator",
        )
        enrolled = Factors(ctx.store).begin_totp(bea.id)
        totp = pyotp.TOTP(enrolled.secret)
        step = int(time.time()) // 30
        Factors(ctx.store).confirm_totp(bea.id, totp.at(step * 30))
        prelink(ctx.store, username_text="bea", issuer=ctx.fake.issuer, subject="bea-sub")
        ctx.fake.subject = "bea-sub"
        ctx.fake.roles = ["Praxis.Admin"]
        status, cookies, headers, body = _sign_in(ctx)
        assert status == 302 and headers["location"] == "/?oidc=mfa"
        assert "mfaToken" not in body
        assert ctx.store.get_username("bea").role == "operator"  # type: ignore[union-attr]
        mfa, _line = _cookie(cookies, "pp_mfa")
        status, _cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/login/totp",
            body={"mfaToken": "", "code": "abcdef"},
            cookie=f"pp_mfa={mfa}",
        )
        assert status == 401
        assert ctx.store.get_username("bea").role == "operator"  # type: ignore[union-attr]
        status, _cookies, _headers, body = _http(
            ctx.port,
            "POST",
            "/v1/auth/login/totp",
            body={"mfaToken": "", "code": totp.at((step + 1) * 30)},
            cookie=f"pp_mfa={mfa}",
        )
        assert status == 200, body
        assert ctx.store.get_username("bea").role == "admin"  # type: ignore[union-attr]


def test_trailing_slash_issuer_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with world(tmp_path, monkeypatch) as ctx:
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="subject-1")
        ctx.fake.iss = ctx.fake.issuer + "/"
        _nav_error(ctx, "bad_issuer")
    plain = "https://idp.example"
    slash = plain + "/"
    endpoints = {
        "authorization_endpoint": plain + "/authorize",
        "token_endpoint": plain + "/token",
        "jwks_uri": plain + "/jwks",
    }
    with pytest.raises(OidcError) as caught:
        oidc_mod._parse_discovery({**endpoints, "issuer": slash}, plain, allow_http=False)
    assert caught.value.reason == "discovery_issuer"
    with pytest.raises(OidcError) as caught:
        oidc_mod._parse_discovery({**endpoints, "issuer": plain}, slash, allow_http=False)
    assert caught.value.reason == "discovery_issuer"
    parsed = oidc_mod._parse_discovery({**endpoints, "issuer": slash}, slash, allow_http=False)
    assert parsed.authorization == plain + "/authorize"
    assert oidc_mod._discovery_url(slash) == plain + "/.well-known/openid-configuration"
    assert oidc_mod._discovery_url(plain) == plain + "/.well-known/openid-configuration"
    assert oidc_mod.normalize_issuer("  " + slash + "  ") == slash


def test_issuer_with_a_trailing_slash_signs_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with world(tmp_path, monkeypatch, issuer_slash=True) as ctx:
        assert ctx.fake.issuer.endswith("/")
        provider = oidc_mod.get_provider(ctx.store, "local")
        assert provider is not None and provider.issuer == ctx.fake.issuer
        ada = ctx.store.get_username("ada")
        assert ada is not None
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="subject-1")
        status, _cookies, headers, _body = _sign_in(ctx)
        assert status == 302 and headers["location"] == "/?oidc=ok"
        linked = list_identities(ctx.store, ada.id)
        assert linked[0]["issuer"] == ctx.fake.issuer
        ctx.fake.iss = ctx.fake.issuer[:-1]
        _nav_error(ctx, "bad_issuer")
        with pytest.raises(OidcError) as caught:
            oidc_mod.unlink(ctx.store, ada.id, ctx.fake.issuer[:-1], "subject-1")
        assert caught.value.reason == "not_linked"
        assert list_identities(ctx.store, ada.id)
        oidc_mod.remove_provider(ctx.store, "local")
        assert list_identities(ctx.store, ada.id) == []


def test_opening_the_store_clears_a_legacy_pkce_verifier(tmp_path: Path) -> None:
    path = tmp_path / "accounts.db"
    secret = "legacy-pkce-verifier-value"
    store = AccountStore(path)
    store.conn.execute(
        """
        INSERT INTO oidc_transactions (
            state_hash, binding_hash, provider_id, nonce_hash, verifier,
            kind, account_id, session_id, redirect_uri, expires_at,
            used, created_at, client_key
        ) VALUES (?, ?, 'local', ?, ?, 'login', '', '', ?, ?, 0, ?, '')
        """,
        (
            "ab" * 32,
            "cd" * 32,
            "ef" * 32,
            secret,
            "http://127.0.0.1:9/v1/auth/oidc/callback",
            "2099-01-01T00:00:00+00:00",
            "2020-01-01T00:00:00+00:00",
        ),
    )
    store.conn.commit()
    store.close()
    again = AccountStore(path)
    row = again.conn.execute("SELECT verifier FROM oidc_transactions").fetchone()
    assert row is not None and str(row["verifier"]) == ""
    again.close()


def test_provider_responses_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeOidc(client_id=_CLIENT, secret=_SECRET)
    paths = ("/.well-known/openid-configuration", "/token", "/jwks")
    try:
        fake.mode = "redirect"
        fake.mode_paths = set(paths)
        for path in paths:
            with pytest.raises(OidcError) as caught:
                oidc_mod._request(
                    fake.issuer + path,
                    method="POST" if path == "/token" else "GET",
                    body=b"grant_type=authorization_code" if path == "/token" else None,
                    headers={},
                    allow_http=True,
                    limit=oidc_mod._DISCOVERY_LIMIT,
                )
            assert caught.value.reason == "redirect_refused", path
        assert fake.follow_hits == 0
        fake.mode = "huge"
        for path in paths:
            with pytest.raises(OidcError) as caught:
                oidc_mod._request(
                    fake.issuer + path,
                    method="POST" if path == "/token" else "GET",
                    body=b"grant_type=authorization_code" if path == "/token" else None,
                    headers={},
                    allow_http=True,
                    limit=oidc_mod._JWKS_LIMIT if path == "/jwks" else oidc_mod._TOKEN_LIMIT,
                )
            assert caught.value.reason == "response_too_large", path
        fake.mode = "trickle"
        monkeypatch.setattr(oidc_mod, "_HTTP_TIMEOUT", 1.0)
        for path in paths:
            started = time.monotonic()
            with pytest.raises(OidcError) as caught:
                oidc_mod._request(
                    fake.issuer + path,
                    method="POST" if path == "/token" else "GET",
                    body=b"grant_type=authorization_code" if path == "/token" else None,
                    headers={},
                    allow_http=True,
                    limit=oidc_mod._DISCOVERY_LIMIT,
                )
            assert caught.value.reason == "provider_unreachable", path
            assert time.monotonic() - started < 2.5
    finally:
        fake.close()
