"""Theme HTTP API: public CSS, CSP, and install/select/lock roles."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

from tests.test_accounts import _login, _request
from tests.test_web_api import _accounts, _raw, _raw_bytes

from praxis_prime.themes.store import read_builtin_files

_PASSWORD = "correct-horse"


def _sample_zip() -> bytes:
    files = read_builtin_files("smf.praxis")
    text = files["theme.toml"].decode("utf-8").replace('id = "smf.praxis"', 'id = "lab.api"', 1)
    text = text.replace('name = "Praxis"', 'name = "Lab"', 1)
    files["theme.toml"] = text.encode("utf-8")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, payload in files.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


def test_active_theme_css_sends_the_spa_csp(tmp_path: Path):
    server, host, _runtime = _accounts(tmp_path, profile="default")
    try:
        status, _headers, body = _raw(server.bound_port, "GET", "/v1/themes/active")
        assert status == 200
        assert body["id"] == "smf.praxis"
        css_path = str(body["css"])
        status, headers, raw = _raw_bytes(server.bound_port, "GET", css_path)
        assert status == 200
        policy = headers.get("content-security-policy", "")
        assert "default-src 'self'" in policy
        assert "style-src 'self'" in policy
        assert "font-src 'self'" in policy
        assert "script-src 'self'" in policy
        assert "unsafe-inline" not in policy
        assert b"--pp-bg:" in raw
        assert b"fonts.googleapis" not in raw
        font = css_path[: -len(".css")] + "/assets/fonts/Inter.woff2"
        status, headers, font_bytes = _raw_bytes(server.bound_port, "GET", font)
        assert status == 200
        assert font_bytes.startswith(b"wOF2")
        assert "font-src 'self'" in headers.get("content-security-policy", "")
    finally:
        server.shutdown()
        host.close()


def test_install_select_and_lock_follow_roles(tmp_path: Path):
    server, host, runtime = _accounts(tmp_path, profile="default")
    try:
        store = server.accounts
        assert store is not None
        viewer = store.create_account(username_text="vic",
            password=_PASSWORD,
            display_name="Vic",
            role="viewer")
        auditor = store.create_account(
            username_text="aud", password=_PASSWORD, display_name="Aud", role="auditor"
        )
        operator = store.create_account(
            username_text="op", password=_PASSWORD, display_name="Op", role="operator"
        )
        store.set_membership(viewer.id, "default", "viewer")
        store.set_membership(auditor.id, "default", "viewer")
        store.set_membership(operator.id, "default", "operator")
        port = server.bound_port

        status, _headers, body = _request(
            port,
            "GET",
            "/v1/themes",
            token="test-token",
            profile="default",
        )
        assert status == 200
        assert {item["id"] for item in body["themes"]} >= {"smf.praxis", "smf.high-contrast"}

        payload = _sample_zip()
        status, _headers, body = _raw(
            port,
            "POST",
            "/v1/themes/install",
            payload=payload,
            extra={"Authorization": "Bearer test-token", "Content-Type": "application/zip"},
        )
        assert status == 200, body
        assert body["theme"]["id"] == "lab.api"

        vic_cookie, vic_csrf, _vic = _login(port, "vic", _PASSWORD)
        status, _headers, body = _request(
            port,
            "POST",
            "/v1/themes/install",
            cookie=vic_cookie,
            csrf=vic_csrf,
            body_json={"packageHash": "0" * 64},
        )
        assert status == 403

        status, _headers, body = _request(
            port,
            "POST",
            "/v1/themes/select",
            token="test-token",
            profile="default",
            body_json={"id": "smf.high-contrast", "mode": "dark", "profile": "default"},
        )
        assert status == 200
        assert body["id"] == "smf.high-contrast"
        assert body["mode"] == "dark"

        op_cookie, op_csrf, _op = _login(port, "op", _PASSWORD)
        status, _headers, body = _request(
            port,
            "POST",
            "/v1/themes/select",
            cookie=op_cookie,
            csrf=op_csrf,
            profile="default",
            body_json={"id": "smf.praxis", "mode": "light", "profile": "default"},
        )
        assert status == 200
        assert body["id"] == "smf.praxis"

        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/themes/select",
            cookie=vic_cookie,
            csrf=vic_csrf,
            profile="default",
            body_json={"id": "smf.high-contrast", "mode": "dark", "profile": "default"},
        )
        assert status == 403
        aud_cookie, aud_csrf, _aud = _login(port, "aud", _PASSWORD)
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/themes/select",
            cookie=aud_cookie,
            csrf=aud_csrf,
            profile="default",
            body_json={"id": "smf.high-contrast", "mode": "light", "profile": "default"},
        )
        assert status == 403

        status, _headers, body = _request(
            port,
            "POST",
            "/v1/themes/lock",
            token="test-token",
            body_json={"id": "smf.praxis", "mode": "light"},
        )
        assert status == 200
        assert body["locked"] is True
        assert body["id"] == "smf.praxis"
        status, _headers, _body = _request(
            port,
            "POST",
            "/v1/themes/select",
            cookie=op_cookie,
            csrf=op_csrf,
            profile="default",
            body_json={"id": "smf.high-contrast", "mode": "dark", "profile": "default"},
        )
        assert status == 403
        status, _headers, body = _request(
            port,
            "POST",
            "/v1/themes/remove",
            token="test-token",
            body_json={"id": "smf.praxis"},
        )
        assert status == 403

        kinds = [
            row["kind"]
            for row in runtime.audit._conn.execute("SELECT kind FROM audit_events").fetchall()
        ]
        assert "theme.install" in kinds
        assert "theme.activate" in kinds
    finally:
        server.shutdown()
        host.close()


def test_theme_install_audit_records_the_package_hash(tmp_path: Path):
    server, host, runtime = _accounts(tmp_path, profile="default")
    try:
        status, _headers, body = _raw(
            server.bound_port,
            "POST",
            "/v1/themes/install",
            payload=_sample_zip(),
            extra={"Authorization": "Bearer test-token", "Content-Type": "application/zip"},
        )
        assert status == 200
        digest = body["theme"]["packageHash"]
        row = runtime.audit._conn.execute(
            "SELECT payload_json FROM audit_events WHERE kind = 'theme.install'"
        ).fetchone()
        assert row is not None
        payload = json.loads(row["payload_json"])
        assert payload["packageHash"] == digest
        assert payload["id"] == "lab.api"
    finally:
        server.shutdown()
        host.close()
