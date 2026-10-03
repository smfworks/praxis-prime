"""Passkey and TOTP enrollment, sign-in, drift, replay, recovery, and lockout."""

from __future__ import annotations

import io
import json
import multiprocessing as mp
import sqlite3
import stat
import threading
from pathlib import Path

import pyotp
from tests.fakes import ScriptedProvider
from tests.soft_passkey import SoftPasskey
from tests.test_accounts import _login, _request

from praxis_prime.accounts.db import LOCK_AFTER_FAILURES, AccountStore
from praxis_prime.accounts.factors import FactorError, Factors
from praxis_prime.accounts.seal import LEGACY_AAD, account_aad, seal, unseal
from praxis_prime.accounts.totp import PERIOD
from praxis_prime.approvals.queue import ApprovalQueue
from praxis_prime.cli import main
from praxis_prime.gateway.server import GatewayServer
from praxis_prime.host import Host
from praxis_prime.observe import JsonLogger
from praxis_prime.router.types import AssistantFinal
from praxis_prime.runtime import build_runtime

_PASSWORD = "correct-horse"
_NOW = 1_700_000_000.0


def test_totp_drift_replay_recovery_and_lockout(tmp_path: Path):
    store = AccountStore(tmp_path / "accounts.db")
    ada = store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
    factors = Factors(store)
    enrollment = factors.begin_totp(ada.id)
    assert enrollment.secret.encode("ascii") not in _stored_bytes(tmp_path / "accounts.db")
    for code in enrollment.recovery_codes:
        assert code.encode("ascii") not in _stored_bytes(tmp_path / "accounts.db")
    confirm = _otp(enrollment.secret, _NOW)
    factors.confirm_totp(ada.id, confirm, now=_NOW)
    assert factors.totp_active(ada.id)
    summary = factors.summary(ada.id)
    assert summary["totp"] is True
    assert summary["recoveryCodesRemaining"] == 10
    assert enrollment.secret not in str(summary)

    token = factors.issue_mfa(ada.id)
    assert factors.complete_mfa(token, confirm, now=_NOW) is None
    assert factors.complete_mfa(token, _otp(enrollment.secret, _NOW + PERIOD), now=_NOW + PERIOD)

    again = factors.issue_mfa(ada.id)
    assert (
        factors.complete_mfa(again, _otp(enrollment.secret, _NOW + PERIOD), now=_NOW + PERIOD)
        is None
    )

    _reset_step(store, ada.id)
    base = _NOW + 10 * PERIOD
    assert factors.complete_mfa(
        factors.issue_mfa(ada.id),
        _otp(enrollment.secret, base - PERIOD),
        now=base,
    )
    _reset_step(store, ada.id)
    assert factors.complete_mfa(
        factors.issue_mfa(ada.id),
        _otp(enrollment.secret, base + PERIOD),
        now=base,
    )
    _reset_step(store, ada.id)
    assert (
        factors.complete_mfa(
            factors.issue_mfa(ada.id),
            _otp(enrollment.secret, base + 2 * PERIOD),
            now=base,
        )
        is None
    )

    _reset_step(store, ada.id)
    _reset_failures(store, ada.id)
    recovery = enrollment.recovery_codes[0]
    signed_in = factors.complete_mfa(factors.issue_mfa(ada.id), recovery, now=base)
    assert signed_in is not None and signed_in.username == "ada"
    assert factors.summary(ada.id)["recoveryCodesRemaining"] == 9
    assert factors.complete_mfa(factors.issue_mfa(ada.id), recovery, now=base) is None

    _reset_failures(store, ada.id)
    bad = _other_code(enrollment.secret, base)
    challenge = factors.issue_mfa(ada.id)
    for _ in range(LOCK_AFTER_FAILURES):
        assert factors.complete_mfa(challenge, bad, now=base) is None
    assert store.account_is_locked(ada.id)
    assert factors.complete_mfa(challenge, _otp(enrollment.secret, base), now=base) is None
    store.close()


def test_password_success_does_not_reset_totp_failures(tmp_path: Path):
    store = AccountStore(tmp_path / "accounts.db")
    ada = store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
    factors = Factors(store)
    enrollment = factors.begin_totp(ada.id)
    factors.confirm_totp(ada.id, _otp(enrollment.secret, _NOW), now=_NOW)
    _reset_step(store, ada.id)
    bad = _other_code(enrollment.secret, _NOW + 10 * PERIOD)
    moment = _NOW + 10 * PERIOD
    token = factors.issue_mfa(ada.id)
    for _ in range(LOCK_AFTER_FAILURES - 1):
        assert factors.complete_mfa(token, bad, now=moment) is None
    assert store.authenticate("ada", _PASSWORD) is not None
    assert not store.account_is_locked(ada.id)
    assert factors.complete_mfa(token, bad, now=moment) is None
    assert store.account_is_locked(ada.id)
    assert factors.complete_mfa(token, _otp(enrollment.secret, moment), now=moment) is None
    store.close()


def test_daemon_enrolls_and_signs_in_with_passkey_and_totp(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    store = AccountStore(data / "accounts.db")
    ada = store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
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
        logger=JsonLogger(tmp_path / "daemon.log"),
        accounts=store,
        audit=runtime.audit,
        data_root=data,
    )
    server.start()
    try:
        origin = f"http://localhost:{server.bound_port}"
        cookie, csrf, _body = _login(server.bound_port, "ada", _PASSWORD)
        step = _step_up(server.bound_port, cookie, csrf, _PASSWORD)
        status, _headers, body = _request(
            server.bound_port,
            "POST",
            "/v1/auth/passkey/register/options",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body_json={"stepUpToken": step},
        )
        assert status == 200
        options = body["options"]
        assert isinstance(options, dict)
        device = SoftPasskey()
        registered = device.register(options, origin=origin)
        status, _headers, _spent = _request(
            server.bound_port,
            "POST",
            "/v1/auth/totp/enroll",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body_json={"stepUpToken": step},
        )
        assert status == 401
        status, _headers, created = _request(
            server.bound_port,
            "POST",
            "/v1/auth/passkey/register/verify",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body_json={"credential": registered, "name": "laptop"},
        )
        assert status == 200
        assert created["passkey"]["name"] == "laptop"

        status, _headers, options_body = _request(
            server.bound_port,
            "POST",
            "/v1/auth/passkey/options",
            origin=origin,
            body_json={"username": "ada"},
        )
        assert status == 200
        auth_options = options_body["options"]
        assert isinstance(auth_options, dict)
        assertion = device.authenticate(auth_options, origin=origin, user_handle=ada.id.encode())
        status, headers, signed = _request(
            server.bound_port,
            "POST",
            "/v1/auth/passkey/verify",
            origin=origin,
            body_json={"credential": assertion},
        )
        assert status == 200
        assert headers.get("set-cookie", "").startswith("pp_session=")
        assert signed["account"]["username"] == "ada"
        replay, _headers, _replay_body = _request(
            server.bound_port,
            "POST",
            "/v1/auth/passkey/verify",
            origin=origin,
            body_json={"credential": assertion},
        )
        assert replay == 401
        status, _headers, options_body = _request(
            server.bound_port,
            "POST",
            "/v1/auth/passkey/options",
            origin=origin,
            body_json={"username": "ada"},
        )
        assert status == 200
        cloned_options = options_body["options"]
        assert isinstance(cloned_options, dict)
        cloned = device.authenticate(
            cloned_options,
            origin=origin,
            user_handle=ada.id.encode(),
            sign_count=device.counter,
        )
        cloned_status, _headers, _cloned_body = _request(
            server.bound_port,
            "POST",
            "/v1/auth/passkey/verify",
            origin=origin,
            body_json={"credential": cloned},
        )
        assert cloned_status == 401

        enroll_step = _step_up(server.bound_port, cookie, csrf, _PASSWORD)
        status, _headers, enrolled = _request(
            server.bound_port,
            "POST",
            "/v1/auth/totp/enroll",
            cookie=cookie,
            csrf=csrf,
            body_json={"stepUpToken": enroll_step},
        )
        assert status == 200
        secret = str(enrolled["secret"])
        assert secret.encode("ascii") not in _stored_bytes(data / "accounts.db")
        log_text = (tmp_path / "daemon.log").read_text(encoding="utf-8")
        assert secret not in log_text
        assert str(enrolled["recoveryCodes"][0]) not in log_text
        assert _PASSWORD not in log_text
        code = pyotp.TOTP(secret).now()
        status, _headers, confirmed = _request(
            server.bound_port,
            "POST",
            "/v1/auth/totp/confirm",
            cookie=cookie,
            csrf=csrf,
            body_json={"code": code},
        )
        assert status == 200 and confirmed["totp"] is True
        status, headers, pending = _request(
            server.bound_port,
            "POST",
            "/v1/auth/login",
            body_json={"username": "ada", "password": _PASSWORD},
        )
        assert status == 200
        assert pending["mfaRequired"] is True
        assert "pp_session=" not in headers.get("set-cookie", "")
        mfa_token = str(pending["mfaToken"])
        assert mfa_token not in (tmp_path / "daemon.log").read_text(encoding="utf-8")
        status, _headers, _finished = _request(
            server.bound_port,
            "POST",
            "/v1/auth/login/totp",
            body_json={"mfaToken": mfa_token, "code": code},
        )
        assert status == 401
        recovery_codes = enrolled["recoveryCodes"]
        assert isinstance(recovery_codes, list) and recovery_codes
        status, headers, finished = _request(
            server.bound_port,
            "POST",
            "/v1/auth/login/totp",
            body_json={"mfaToken": mfa_token, "code": str(recovery_codes[0])},
        )
        assert status == 200
        assert finished["account"]["username"] == "ada"
        assert "pp_session=" in headers.get("set-cookie", "")
        status, _headers, again = _request(
            server.bound_port,
            "POST",
            "/v1/auth/login",
            body_json={"username": "ada", "password": _PASSWORD},
        )
        assert status == 200 and again["mfaRequired"] is True
        status, _headers, _spent = _request(
            server.bound_port,
            "POST",
            "/v1/auth/login/totp",
            body_json={"mfaToken": str(again["mfaToken"]), "code": str(recovery_codes[0])},
        )
        assert status == 401
        status, _headers, bearer = _request(
            server.bound_port,
            "GET",
            "/status",
            token="test-token",
        )
        assert status == 200
        assert bearer["status"]["listen"].startswith("127.0.0.1:")
        status, _headers, listed = _request(
            server.bound_port,
            "GET",
            "/v1/auth/factors",
            token="test-token",
        )
        assert status == 200
        assert listed["totp"] is True
        assert secret not in str(listed)
    finally:
        server.shutdown()
        host.close()
        store.close()


def test_cli_lists_factors_without_printing_the_secret(tmp_path: Path, monkeypatch, capsys):
    data = tmp_path / "data"
    data.mkdir()
    store = AccountStore(data / "accounts.db")
    store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
    store.close()
    assert main(["account", "totp", "enroll", "ada", "--data-dir", str(data)]) == 0
    printed = capsys.readouterr().out
    secret = ""
    for line in printed.splitlines():
        if line.startswith("secret "):
            secret = line.split(" ", 1)[1]
    assert secret
    assert secret.encode("ascii") not in (data / "accounts.db").read_bytes()
    assert main(["account", "factors", "ada", "--data-dir", str(data)]) == 0
    listed = capsys.readouterr().out
    assert "totp=pending" in listed
    assert secret not in listed
    monkeypatch.setattr("sys.stdin", io.StringIO(pyotp.TOTP(secret).now() + "\n"))
    assert main(["account", "totp", "confirm", "ada", "--data-dir", str(data)]) == 0
    assert "totp on" in capsys.readouterr().out
    assert main(["account", "factors", "ada", "--data-dir", str(data)]) == 0
    listed = capsys.readouterr().out
    assert "totp=on" in listed
    assert secret not in listed
    assert main(["account", "passkey", "list", "ada", "--data-dir", str(data)]) == 0
    assert "no passkeys" in capsys.readouterr().out
    assert stat.S_IMODE((data / "accounts.db").stat().st_mode) == 0o600
    recorded = sqlite3.connect(data / "prime.db").execute(
        "SELECT summary, payload_json FROM audit_events"
    ).fetchall()
    text = " ".join(f"{summary} {payload}" for summary, payload in recorded)
    assert "totp enrollment started" in text
    assert "totp confirmed" in text
    assert secret not in text


def test_step_up_origin_mfa_token_and_challenge_cap(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    store = AccountStore(data / "accounts.db")
    ada = store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
    store.create_account(username_text="bob", password=_PASSWORD, display_name="Bob")
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
        logger=JsonLogger(tmp_path / "daemon.log"),
        accounts=store,
        audit=runtime.audit,
        data_root=data,
    )
    server.start()
    try:
        port = server.bound_port
        origin = f"http://localhost:{port}"
        other = f"http://127.0.0.1:{port}"
        cookie, csrf, _body = _login(port, "ada", _PASSWORD)

        status, _headers, _body = _request(port, "POST", "/v1/auth/totp/enroll", origin=origin)
        assert status == 401
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/passkey/register/options",
            cookie=cookie,
            origin=origin,
            body_json={"stepUpToken": "missing"},
        )
        assert status == 403
        for path in (
            "/v1/auth/step-up",
            "/v1/auth/step-up/passkey/options",
            "/v1/auth/step-up/passkey/verify",
            "/v1/auth/passkey/register/verify",
            "/v1/auth/passkey/remove",
            "/v1/auth/totp/enroll",
        ):
            status, _headers, _body = _request(
                port,
                "POST",
                path,
                cookie=cookie,
                origin=origin,
                body_json={"password": _PASSWORD, "stepUpToken": "missing"},
            )
            assert status == 403, path
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/totp/enroll",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body_json={},
        )
        assert status == 401

        step = _step_up(port, cookie, csrf, _PASSWORD)
        status, _headers, options_body = _request(
            port,
            "POST",
            "/v1/auth/passkey/register/options",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body_json={"stepUpToken": step},
        )
        assert status == 200
        options = options_body["options"]
        assert isinstance(options, dict)
        assert "required" in json.dumps(options)
        bare = SoftPasskey()
        refused = bare.register(options, origin=origin, verified=False)
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/passkey/register/verify",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body_json={"credential": refused},
        )
        assert status == 401
        again = _step_up(port, cookie, csrf, _PASSWORD)
        status, _headers, options_body = _request(
            port,
            "POST",
            "/v1/auth/passkey/register/options",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body_json={"stepUpToken": again},
        )
        assert status == 200
        options = options_body["options"]
        assert isinstance(options, dict)

        device = SoftPasskey()
        created = device.register(options, origin=origin)
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/passkey/register/verify",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body_json={"credential": created, "name": "laptop"},
        )
        assert status == 200

        status, _headers, listed = _request(
            port, "GET", "/v1/auth/factors", cookie=cookie, csrf=csrf
        )
        assert status == 200
        credential_id = listed["passkeys"][0]["id"]
        assert isinstance(credential_id, str) and credential_id

        shapes = []
        for username in ("ada", "bob", "nosuchuser"):
            status, _headers, body = _request(
                port,
                "POST",
                "/v1/auth/passkey/options",
                origin=origin,
                body_json={"username": username},
            )
            assert status == 200
            public = body["options"]
            assert isinstance(public, dict)
            assert not public.get("allowCredentials")
            assert credential_id not in json.dumps(public)
            shapes.append(public.get("allowCredentials"))
        assert shapes[0] == shapes[1] == shapes[2]

        for bad_origin in (
            f"http://evil.example:{port}",
            "null",
            f"https://localhost:{port}",
            f"http://localhost:{port + 1}",
        ):
            status, _headers, _body = _request(
                port,
                "POST",
                "/v1/auth/passkey/options",
                origin=bad_origin,
                body_json={"username": "ada"},
            )
            assert status in {400, 403}
        status, _headers, empty_origin = _request(
            port,
            "POST",
            "/v1/auth/passkey/options",
            body_json={"username": "ada"},
        )
        assert status == 200
        assert empty_origin["options"]["rpId"] == "localhost"
        for bad_host in ("evil.example", f"localhost:{port + 1}", f"127.0.0.1.nip.io:{port}"):
            status, _headers, _body = _request(
                port,
                "POST",
                "/v1/auth/passkey/options",
                host=bad_host,
                origin=origin,
                body_json={"username": "ada"},
            )
            assert status == 403

        status, _headers, foreign = _request(
            port,
            "POST",
            "/v1/auth/passkey/options",
            origin=other,
            body_json={"username": "ada"},
        )
        assert status == 200
        assertion = device.authenticate(
            foreign["options"], origin=other, user_handle=ada.id.encode()
        )
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/passkey/verify",
            origin=other,
            body_json={"credential": assertion},
        )
        assert status == 401

        store.conn.execute("DELETE FROM webauthn_challenges")
        store.conn.commit()
        status, _headers, first = _request(
            port,
            "POST",
            "/v1/auth/passkey/options",
            origin=origin,
            body_json={"username": "ada"},
        )
        assert status == 200
        for _ in range(6):
            status, _headers, _body = _request(
                port,
                "POST",
                "/v1/auth/passkey/options",
                origin=origin,
                body_json={"username": "ada"},
            )
            assert status == 200
        kept = device.authenticate(
            first["options"], origin=origin, user_handle=ada.id.encode()
        )
        status, _headers, signed = _request(
            port,
            "POST",
            "/v1/auth/passkey/verify",
            origin=origin,
            body_json={"credential": kept},
        )
        assert status == 200
        assert signed["account"]["username"] == "ada"

        options_token = _step_up(port, cookie, csrf, _PASSWORD)
        status, _headers, step_options = _request(
            port,
            "POST",
            "/v1/auth/step-up/passkey/options",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
        )
        assert status == 200
        proof = device.authenticate(
            step_options["options"], origin=origin, user_handle=ada.id.encode()
        )
        status, _headers, minted = _request(
            port,
            "POST",
            "/v1/auth/step-up/passkey/verify",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body_json={"credential": proof},
        )
        assert status == 200
        assert minted["stepUpToken"] != options_token
        status, _headers, second_options = _request(
            port,
            "POST",
            "/v1/auth/passkey/register/options",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body_json={"stepUpToken": options_token},
        )
        assert status == 200
        other_device = SoftPasskey()
        other_created = other_device.register(second_options["options"], origin=origin)
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/passkey/register/verify",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body_json={"credential": other_created, "name": "backup"},
        )
        assert status == 200
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/passkey/remove",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body_json={"credentialId": credential_id, "stepUpToken": minted["stepUpToken"]},
        )
        assert status == 200
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/passkey/remove",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body_json={"credentialId": credential_id},
        )
        assert status == 401

        enroll_step = _step_up(port, cookie, csrf, _PASSWORD)
        status, _headers, enrolled = _request(
            port,
            "POST",
            "/v1/auth/totp/enroll",
            cookie=cookie,
            csrf=csrf,
            body_json={"stepUpToken": enroll_step},
        )
        assert status == 200
        secret = str(enrolled["secret"])
        code = pyotp.TOTP(secret).now()
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/totp/confirm",
            cookie=cookie,
            csrf=csrf,
            body_json={"code": code},
        )
        assert status == 200
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/totp/enroll",
            cookie=cookie,
            csrf=csrf,
            body_json={},
        )
        assert status == 409

        status, headers, pending = _request(
            port,
            "POST",
            "/v1/auth/login",
            body_json={"username": "ada", "password": _PASSWORD},
        )
        assert pending["mfaRequired"] is True
        mfa_token = str(pending["mfaToken"])
        assert "pp_session=" not in headers.get("set-cookie", "")
        for path in ("/v1/auth/session", "/v1/auth/factors", "/status"):
            as_bearer, _headers, _body = _request(port, "GET", path, token=mfa_token)
            as_cookie, _headers, _body = _request(port, "GET", path, cookie=mfa_token)
            assert as_bearer == 401
            assert as_cookie == 401
        bob_cookie, bob_csrf, _bob = _login(port, "bob", _PASSWORD)
        bob_step = _step_up(port, bob_cookie, bob_csrf, _PASSWORD)
        status, _headers, bob_enrolled = _request(
            port,
            "POST",
            "/v1/auth/totp/enroll",
            cookie=bob_cookie,
            csrf=bob_csrf,
            body_json={"stepUpToken": bob_step},
        )
        assert status == 200
        bob_secret = str(bob_enrolled["secret"])
        bob_code = pyotp.TOTP(bob_secret).now()
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/totp/confirm",
            cookie=bob_cookie,
            csrf=bob_csrf,
            body_json={"code": bob_code},
        )
        assert status == 200
        _reset_step(store, ada.id)
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/login/totp",
            body_json={"mfaToken": mfa_token, "code": pyotp.TOTP(bob_secret).now()},
        )
        assert status == 401
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/login/totp",
            body_json={"mfaToken": mfa_token, "code": bob_enrolled["recoveryCodes"][0]},
        )
        assert status == 401
        store.conn.execute(
            "UPDATE mfa_tokens SET expires_at = '2000-01-01T00:00:00+00:00' WHERE used = 0"
        )
        store.conn.commit()
        _reset_step(store, ada.id)
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/login/totp",
            body_json={"mfaToken": mfa_token, "code": pyotp.TOTP(secret).now()},
        )
        assert status == 401

        store.set_password("ada", "replacement-passphrase")
        status, _headers, _body = _request(port, "GET", "/v1/auth/session", cookie=cookie)
        assert status == 401
        status, _headers, options_body = _request(
            port,
            "POST",
            "/v1/auth/passkey/options",
            origin=origin,
            body_json={"username": "ada"},
        )
        assert status == 200
        assertion = other_device.authenticate(
            options_body["options"], origin=origin, user_handle=ada.id.encode()
        )
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/passkey/verify",
            origin=origin,
            body_json={"credential": assertion},
        )
        assert status == 401
        assert secret not in (tmp_path / "daemon.log").read_text(encoding="utf-8")
    finally:
        server.shutdown()
        host.close()
        store.close()


def test_http_disable_requires_step_up_and_sign_in_challenges_are_sealed(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    store = AccountStore(data / "accounts.db")
    ada = store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
    store.create_account(username_text="bob", password=_PASSWORD, display_name="Bob")
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
        logger=JsonLogger(tmp_path / "daemon.log"),
        accounts=store,
        audit=runtime.audit,
        data_root=data,
    )
    server.start()
    try:
        port = server.bound_port
        origin = f"http://localhost:{port}"
        cookie, csrf, _body = _login(port, "ada", _PASSWORD)
        step = _step_up(port, cookie, csrf, _PASSWORD)
        status, _headers, options_body = _request(
            port,
            "POST",
            "/v1/auth/passkey/register/options",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body_json={"stepUpToken": step},
        )
        assert status == 200
        device = SoftPasskey()
        created = device.register(options_body["options"], origin=origin)
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/passkey/register/verify",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body_json={"credential": created, "name": "laptop"},
        )
        assert status == 200

        enroll_step = _step_up(port, cookie, csrf, _PASSWORD)
        status, _headers, enrolled = _request(
            port,
            "POST",
            "/v1/auth/totp/enroll",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body_json={"stepUpToken": enroll_step},
        )
        assert status == 200
        secret = str(enrolled["secret"])
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/totp/confirm",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body_json={"code": pyotp.TOTP(secret).now()},
        )
        assert status == 200

        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/totp/disable",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body_json={"password": _PASSWORD},
        )
        assert status == 401
        status, _headers, listed = _request(
            port, "GET", "/v1/auth/factors", cookie=cookie, csrf=csrf
        )
        assert listed["totp"] is True
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/step-up",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body_json={"password": _PASSWORD, "code": ""},
        )
        assert status == 401
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/passkey/register/options",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body_json={},
        )
        assert status == 401
        status, _headers, listed = _request(
            port, "GET", "/v1/auth/factors", cookie=cookie, csrf=csrf
        )
        assert len(listed["passkeys"]) == 1

        _reset_step(store, ada.id)
        _reset_failures(store, ada.id)
        disable_step = _step_up(port, cookie, csrf, _PASSWORD, pyotp.TOTP(secret).now())
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/totp/disable",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body_json={"stepUpToken": disable_step},
        )
        assert status == 200
        status, _headers, listed = _request(
            port, "GET", "/v1/auth/factors", cookie=cookie, csrf=csrf
        )
        assert listed["totp"] is False

        lengths = []
        for username in ("ada", "bob", "", "nosuchuser"):
            status, _headers, body = _request(
                port,
                "POST",
                "/v1/auth/passkey/options",
                origin=origin,
                body_json={"username": username},
            )
            assert status == 200
            lengths.append(len(str(body["options"]["challenge"])))
        assert lengths[0] == lengths[1] == lengths[2] == lengths[3]
        stored = store.conn.execute(
            "SELECT count(*) FROM webauthn_challenges WHERE kind = 'authenticate'"
        ).fetchone()
        assert stored is not None and int(stored[0]) == 0

        for _ in range(8):
            status, _headers, _body = _request(
                port,
                "POST",
                "/v1/auth/passkey/options",
                origin=origin,
                body_json={},
            )
            assert status == 200
            status, _headers, _body = _request(
                port,
                "POST",
                "/v1/auth/passkey/options",
                origin=origin,
                body_json={"username": "ada"},
            )
            assert status == 200
        status, _headers, named = _request(
            port,
            "POST",
            "/v1/auth/passkey/options",
            origin=origin,
            body_json={"username": "ada"},
        )
        assert status == 200
        assertion = device.authenticate(
            named["options"], origin=origin, user_handle=ada.id.encode()
        )
        status, _headers, signed = _request(
            port,
            "POST",
            "/v1/auth/passkey/verify",
            origin=origin,
            body_json={"credential": assertion},
        )
        assert status == 200
        assert signed["account"]["username"] == "ada"
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/auth/passkey/verify",
            origin=origin,
            body_json={"credential": assertion},
        )
        assert status == 401
        status, _headers, open_step = _request(
            port,
            "POST",
            "/v1/auth/step-up/passkey/options",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
        )
        assert status == 200
        status, _headers, nameless = _request(
            port,
            "POST",
            "/v1/auth/passkey/options",
            origin=origin,
            body_json={},
        )
        assert status == 200
        again = device.authenticate(
            nameless["options"], origin=origin, user_handle=ada.id.encode()
        )
        status, _headers, signed = _request(
            port,
            "POST",
            "/v1/auth/passkey/verify",
            origin=origin,
            body_json={"credential": again},
        )
        assert status == 200
        assert signed["account"]["username"] == "ada"
        assert open_step["options"]["challenge"]

        minted = _step_up(port, cookie, csrf, _PASSWORD)
        assert minted
        status, _headers, _body = _request(
            port, "POST", "/v1/auth/logout", cookie=cookie, csrf=csrf, origin=origin
        )
        assert status == 200
        left = store.conn.execute(
            "SELECT count(*) FROM step_up WHERE account_id = ?",
            (ada.id,),
        ).fetchone()
        assert left is not None and int(left[0]) == 0
    finally:
        server.shutdown()
        host.close()
        store.close()


def test_cli_disable_totp_uses_the_password_only(tmp_path: Path):
    store = AccountStore(tmp_path / "accounts.db")
    ada = store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
    factors = Factors(store)
    enrollment = factors.begin_totp(ada.id)
    factors.confirm_totp(ada.id, pyotp.TOTP(enrollment.secret).now())
    try:
        factors.disable_totp(ada.username, "not-the-password")
    except FactorError:
        pass
    else:
        raise AssertionError("a wrong password disabled totp")
    assert factors.totp_active(ada.id)
    factors.disable_totp(ada.username, _PASSWORD)
    assert not factors.totp_active(ada.id)
    store.close()


def test_one_totp_step_succeeds_once_under_contention(tmp_path: Path):
    store = AccountStore(tmp_path / "accounts.db")
    ada = store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
    factors = Factors(store)
    enrollment = factors.begin_totp(ada.id)
    factors.confirm_totp(ada.id, _otp(enrollment.secret, _NOW), now=_NOW)
    _reset_step(store, ada.id)
    code = _otp(enrollment.secret, _NOW + 3 * PERIOD)
    moment = _NOW + 3 * PERIOD
    tokens = [factors.issue_mfa(ada.id) for _ in range(4)]
    results: list[bool] = []
    barrier = threading.Barrier(len(tokens))

    def submit(token: str) -> None:
        barrier.wait()
        results.append(factors.complete_mfa(token, code, now=moment) is not None)

    threads = [threading.Thread(target=submit, args=(token,)) for token in tokens]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(True) == 1
    store.close()


def test_seed_is_bound_to_the_account_and_key_is_not_created_on_read(tmp_path: Path):
    store = AccountStore(tmp_path / "accounts.db")
    ada = store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
    bob = store.create_account(username_text="bob", password=_PASSWORD, display_name="Bob")
    factors = Factors(store)
    enrollment = factors.begin_totp(ada.id)
    blob = bytes(
        store.conn.execute(
            "SELECT secret_enc FROM totp WHERE account_id = ?", (ada.id,)
        ).fetchone()[0]
    )
    assert factors._secret(bob.id, blob) is None
    assert factors._secret(ada.id, blob) == enrollment.secret
    key = factors._read_key()
    assert key is not None
    legacy = seal(key, enrollment.secret.encode("ascii"), aad=LEGACY_AAD)
    store.conn.execute(
        "UPDATE totp SET secret_enc = ? WHERE account_id = ?",
        (legacy, ada.id),
    )
    store.conn.commit()
    assert factors._secret(ada.id, legacy) == enrollment.secret
    store.conn.commit()
    rewritten = bytes(
        store.conn.execute(
            "SELECT secret_enc FROM totp WHERE account_id = ?", (ada.id,)
        ).fetchone()[0]
    )
    assert rewritten != legacy
    assert unseal(key, rewritten, aad=account_aad(ada.id)) == enrollment.secret.encode("ascii")
    assert factors._secret(bob.id, rewritten) is None
    store.conn.execute("DELETE FROM auth_meta")
    store.conn.commit()
    assert factors._secret(ada.id, rewritten) is None
    assert factors._read_key() is None
    store.close()


def test_concurrent_open_adds_the_second_factor_column(tmp_path: Path):
    path = tmp_path / "accounts.db"
    store = AccountStore(path)
    store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
    store.conn.execute("ALTER TABLE accounts DROP COLUMN second_factor_failures")
    store.conn.commit()
    store.close()
    ctx = mp.get_context("spawn")
    queue: mp.Queue[str] = ctx.Queue()
    processes = [ctx.Process(target=_open_accounts, args=(str(path), queue)) for _ in range(6)]
    for process in processes:
        process.start()
    for process in processes:
        process.join()
    assert [queue.get() for _ in processes] == ["ok"] * 6
    reopened = AccountStore(path)
    try:
        assert reopened.authenticate("ada", _PASSWORD) is not None
    finally:
        reopened.close()


def _open_accounts(path: str, queue: mp.Queue[str]) -> None:
    try:
        opened = AccountStore(Path(path))
        row = opened.conn.execute(
            "SELECT second_factor_failures FROM accounts"
        ).fetchone()
        opened.close()
        queue.put("ok" if row is not None else "missing")
    except Exception as exc:
        queue.put(repr(exc))


def _step_up(port: int, cookie: str, csrf: str, password: str, code: str = "") -> str:
    status, _headers, body = _request(
        port,
        "POST",
        "/v1/auth/step-up",
        cookie=cookie,
        csrf=csrf,
        body_json={"password": password, "code": code},
    )
    assert status == 200, body
    token = body["stepUpToken"]
    assert isinstance(token, str) and token
    return token


def _otp(secret: str, moment: float) -> str:
    return pyotp.TOTP(secret).generate_otp(int(moment) // PERIOD)


def _other_code(secret: str, moment: float) -> str:
    real = _otp(secret, moment)
    bad = "000000"
    if bad == real:
        return "111111"
    return bad


def _reset_step(store: AccountStore, account_id: str) -> None:
    store.conn.execute("UPDATE totp SET last_step = 0 WHERE account_id = ?", (account_id,))
    store.conn.commit()


def _reset_failures(store: AccountStore, account_id: str) -> None:
    store.clear_failures(account_id)


def _stored_bytes(path: Path) -> bytes:
    blob = path.read_bytes()
    for suffix in ("-wal", "-shm"):
        side = Path(f"{path}{suffix}")
        if side.exists():
            blob += side.read_bytes()
    return blob
