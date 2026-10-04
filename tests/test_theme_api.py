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

        status, _headers, removed = _request(
            server.bound_port,
            "POST",
            "/v1/themes/remove",
            token="test-token",
            body_json={"id": "lab.api"},
        )
        assert status == 200
        assert removed["removed"] == "lab.api"
        row = runtime.audit._conn.execute(
            "SELECT payload_json FROM audit_events WHERE kind = 'theme.remove'"
        ).fetchone()
        assert row is not None
        payload = json.loads(row["payload_json"])
        assert payload["id"] == "lab.api"
        assert payload["version"] == "1.0.0"
        assert payload["packageHash"] == digest
    finally:
        server.shutdown()
        host.close()


def test_damaged_zip_is_http_400(tmp_path: Path):
    server, host, _runtime = _accounts(tmp_path, profile="default")
    try:
        status, _headers, body = _raw(
            server.bound_port,
            "POST",
            "/v1/themes/install",
            payload=b"this is not a zip",
            extra={"Authorization": "Bearer test-token", "Content-Type": "application/zip"},
        )
        assert status == 400
        assert body["ok"] is False
        issues = body["error"]["issues"]
        assert isinstance(issues, list)
        assert any(item.get("code") == "zip_invalid" for item in issues if isinstance(item, dict))
    finally:
        server.shutdown()
        host.close()


def test_failed_install_discards_the_stage(tmp_path: Path):
    server, host, _runtime = _accounts(tmp_path, profile="default")
    try:
        status, _headers, body = _raw(
            server.bound_port,
            "POST",
            "/v1/themes/preview",
            payload=_sample_zip(),
            extra={"Authorization": "Bearer test-token", "Content-Type": "application/zip"},
        )
        assert status == 200
        digest = str(body["packageHash"])
        stage = server.data_root / "theme-stage" / digest
        assert stage.is_dir()
        (stage / "theme.toml").write_text("not toml", encoding="utf-8")
        status, _headers, failed = _request(
            server.bound_port,
            "POST",
            "/v1/themes/install",
            token="test-token",
            body_json={"packageHash": digest},
        )
        assert status == 400
        assert failed["ok"] is False
        assert not stage.exists()
    finally:
        server.shutdown()
        host.close()


def test_user_smf_copy_does_not_win_and_a_tampered_theme_is_404(tmp_path: Path):
    server, host, _runtime = _accounts(tmp_path, profile="default")
    try:
        assert server.data_root is not None
        builtin = read_builtin_files("smf.praxis")
        planted = server.data_root / "themes" / "smf.praxis" / "1.0.0"
        for name, payload in builtin.items():
            path = planted.joinpath(*name.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        status, _headers, active = _raw(server.bound_port, "GET", "/v1/themes/active")
        assert status == 200
        assert active["id"] == "smf.praxis"
        assert active["source"] == "builtin"

        status, _headers, body = _raw(
            server.bound_port,
            "POST",
            "/v1/themes/install",
            payload=_sample_zip(),
            extra={"Authorization": "Bearer test-token", "Content-Type": "application/zip"},
        )
        assert status == 200
        css_path = str(body["theme"]["css"])
        status, _headers, raw = _raw_bytes(server.bound_port, "GET", css_path)
        assert status == 200
        readme = server.data_root / "themes" / "lab.api" / "1.0.0" / "THEME.md"
        readme.write_bytes(readme.read_bytes() + b"\n")
        status, _headers, raw = _raw_bytes(server.bound_port, "GET", css_path)
        assert status == 404
        assert b"--pp-bg:" not in raw
    finally:
        server.shutdown()
        host.close()


def test_cross_site_theme_upload_is_403_not_a_reset(tmp_path: Path):
    server, host, _runtime = _accounts(tmp_path, profile="default")
    try:
        payload = b"Z" * 65536
        refused = (
            {"Content-Type": "application/zip", "Sec-Fetch-Site": "cross-site"},
            {"Content-Type": "application/zip", "Origin": "https://evil.example"},
        )
        for extra in refused:
            status, _headers, body = _raw(
                server.bound_port,
                "POST",
                "/v1/themes/install",
                payload=payload,
                extra=extra,
            )
            assert status == 403, extra
            assert body["error"]["code"] == "forbidden"
        cookie, _csrf, _session = _login(server.bound_port, "ada", _PASSWORD)
        status, _headers, body = _raw(
            server.bound_port,
            "POST",
            "/v1/themes/preview",
            payload=payload,
            extra={
                "Content-Type": "application/zip",
                "Cookie": f"pp_session={cookie}",
                "x-csrf-token": "not-the-token",
            },
        )
        assert status == 403
        assert body["error"]["code"] == "forbidden"
        assert "csrf" in str(body["error"]["message"]).casefold()
    finally:
        server.shutdown()
        host.close()


def test_preview_png_is_served_under_the_csp_and_not_in_css(tmp_path: Path):
    files = read_builtin_files("smf.praxis")
    text = files["theme.toml"].decode("utf-8").replace('id = "smf.praxis"', 'id = "lab.api"', 1)
    text = text.replace('name = "Praxis"', 'name = "Lab"', 1)
    files["theme.toml"] = text.encode("utf-8")
    png = b"\x89PNG\r\n\x1a\n"
    files["assets/preview.png"] = png
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        for name, blob in files.items():
            archive.writestr(name, blob)
    server, host, _runtime = _accounts(tmp_path, profile="default")
    try:
        status, _headers, body = _raw(
            server.bound_port,
            "POST",
            "/v1/themes/install",
            payload=payload.getvalue(),
            extra={"Authorization": "Bearer test-token", "Content-Type": "application/zip"},
        )
        assert status == 200, body
        css_path = str(body["theme"]["css"])
        status, _headers, raw = _raw_bytes(server.bound_port, "GET", css_path)
        assert status == 200
        assert b"preview" not in raw
        preview = css_path[: -len(".css")] + "/assets/preview.png"
        status, headers, raw = _raw_bytes(server.bound_port, "GET", preview)
        assert status == 200
        assert raw == png
        assert headers.get("content-type", "").startswith("image/png")
        policy = headers.get("content-security-policy", "")
        assert "default-src 'self'" in policy
        assert "img-src 'self'" in policy
        for suffix in ("/assets/preview.jpg", "/assets/gallery.png"):
            status, _headers, missing = _raw(
                server.bound_port,
                "GET",
                css_path[: -len(".css")] + suffix,
            )
            assert status == 404
            assert missing["error"]["code"] == "not_allowed"
    finally:
        server.shutdown()
        host.close()
