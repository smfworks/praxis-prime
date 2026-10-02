"""Passkey and TOTP enrollment, sign-in, drift, replay, recovery, and lockout."""

from __future__ import annotations

import io
import stat
from pathlib import Path

import pyotp
from tests.fakes import ScriptedProvider
from tests.soft_passkey import SoftPasskey
from tests.test_accounts import _login, _request

from praxis_prime.accounts.db import LOCK_AFTER_FAILURES, AccountStore
from praxis_prime.accounts.factors import Factors
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
        status, _headers, body = _request(
            server.bound_port,
            "POST",
            "/v1/auth/passkey/register/options",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
        )
        assert status == 200
        options = body["options"]
        assert isinstance(options, dict)
        device = SoftPasskey()
        registered = device.register(options, origin=origin)
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

        status, _headers, enrolled = _request(
            server.bound_port,
            "POST",
            "/v1/auth/totp/enroll",
            cookie=cookie,
            csrf=csrf,
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
