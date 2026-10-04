"""First-run wizard in the shipped SPA. Browser coverage is opt-in."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from test_web_smoke import _daemon, _require_browser

_PASSWORD = "correct-horse"


def test_wizard_source_names_the_cloud_warning_without_a_url():
    root = Path(__file__).resolve().parents[1]
    text = (root / "ui" / "src" / "setup.tsx").read_text(encoding="utf-8")
    assert "Requires a BAA/DPA with the provider; PHI will leave this machine" in text
    assert "https://" not in text
    assert "http://" not in text
    assert "defaultChecked" not in text


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        if self.path.split("?", 1)[0] != "/v1/models":
            self.send_error(404)
            return
        body = json.dumps({"data": [{"id": "local-model", "max_model_len": 32768}]}).encode()
        self._send(body)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            payload = {}
        if isinstance(payload, dict) and "tools" in payload:
            message = {"role": "assistant", "content": "", "tool_calls": [{"id": "c1"}]}
        else:
            message = {"role": "assistant", "content": "ready"}
        self._send(json.dumps({"choices": [{"message": message}]}).encode())

    def _send(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        del fmt, args


@pytest.mark.browser
def test_first_run_wizard_verifies_a_local_model(tmp_path: Path):
    playwright_sync = _require_browser()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with _daemon(
            tmp_path,
            [{"content": "unused"}],
            extra_env={"PRAXIS_PRIME_MODEL": ""},
        ) as gateway:
            token_path = tmp_path / "config" / "praxis-prime" / "first-run.token"
            token = token_path.read_text(encoding="utf-8").strip()
            _walk(playwright_sync, gateway, token, int(port))
            assert not token_path.exists()
    finally:
        server.shutdown()
        server.server_close()


def _walk(playwright_sync: object, gateway: int, token: str, model_port: int) -> None:
    sync_playwright = playwright_sync.sync_playwright  # type: ignore[attr-defined]
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.set_default_timeout(30_000)
        page.goto(f"http://127.0.0.1:{gateway}/#setup={token}")
        page.get_by_role("heading", name="Welcome").wait_for()
        assert token not in page.url
        assert "setup=" not in page.url
        page.get_by_role("button", name="Continue").click()
        page.get_by_label("Username").fill("ada")
        page.get_by_label("Password").fill(_PASSWORD)
        page.get_by_role("button", name="Create owner").click()
        page.get_by_role("button", name="Skip enrollment").click()
        page.get_by_role("radio", name="On this computer").check()
        page.get_by_role("button", name="Continue").click()
        page.get_by_label("Provider id").fill("llamacpp")
        page.get_by_label("Base URL").fill(f"127.0.0.1:{model_port}")
        page.get_by_label("Primary model").fill("local-model")
        page.get_by_role("button", name="Test and save").click()
        page.get_by_text("Inference ready").wait_for()
        browser.close()
