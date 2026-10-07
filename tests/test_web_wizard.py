"""First-run wizard in the shipped SPA. Browser coverage is opt-in."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pyotp
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
        _reach_picker(page)
        _fill_provider(page, "llama.cpp server", model_port)
        page.get_by_role("button", name="Test and save").click()
        page.get_by_text("Inference ready").wait_for()
        browser.close()


@pytest.mark.browser
def test_wizard_rerun_replaces_the_provider_and_key(tmp_path: Path):
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
            _replace(playwright_sync, gateway, token, int(port))
            secret = (tmp_path / "config" / "praxis-prime" / "secrets.env").read_text(
                encoding="utf-8"
            )
            assert "sk-second" in secret
            assert "sk-first" not in secret
    finally:
        server.shutdown()
        server.server_close()


def _replace(playwright_sync: object, gateway: int, token: str, model_port: int) -> None:
    sync_playwright = playwright_sync.sync_playwright  # type: ignore[attr-defined]
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.set_default_timeout(30_000)
        page.goto(f"http://127.0.0.1:{gateway}/#setup={token}")
        _reach_picker(page)
        _fill_provider(page, "llama.cpp server", model_port, api_key="sk-first")
        page.get_by_role("button", name="Test and save").click()
        page.get_by_text("Inference ready").wait_for()
        page.get_by_role("button", name="Continue").click()
        page.get_by_role("button", name="Continue").click()
        page.get_by_role("link", name="Continue to the app").click()
        page.get_by_role("button", name="Sign out").wait_for()
        page.goto(f"http://127.0.0.1:{gateway}/#/setup")
        page.get_by_role("heading", name="Choose where Praxis thinks").wait_for()
        _fill_provider(page, "vLLM", model_port, api_key="sk-second")
        page.get_by_role("checkbox", name="Replace the current provider").check()
        page.get_by_label("Account password").fill(_PASSWORD)
        page.get_by_role("button", name="Test and save").click()
        page.get_by_text("Inference ready").wait_for()
        assert "pass --replace" not in page.content()
        browser.close()


def _virtual_authenticator(page: object) -> None:
    """Install a platform authenticator on the page that will call WebAuthn.

    Call this after the page is on the daemon origin. A session opened on
    about:blank does not answer ``credentials.create`` after navigation.
    """
    session = page.context.new_cdp_session(page)  # type: ignore[attr-defined]
    session.send("WebAuthn.enable", {"enableUI": False})
    created = session.send(
        "WebAuthn.addVirtualAuthenticator",
        {
            "options": {
                "protocol": "ctap2",
                "ctap2Version": "ctap2_1",
                "transport": "internal",
                "hasResidentKey": True,
                "hasUserVerification": True,
                "isUserVerified": True,
                "automaticPresenceSimulation": True,
            }
        },
    )
    authenticator_id = str(created["authenticatorId"])
    session.send(
        "WebAuthn.setAutomaticPresenceSimulation",
        {"authenticatorId": authenticator_id, "enabled": True},
    )
    session.send(
        "WebAuthn.setUserVerified",
        {"authenticatorId": authenticator_id, "isUserVerified": True},
    )


def _reach_picker(page: object) -> None:
    page.get_by_role("button", name="Continue").click()  # type: ignore[attr-defined]
    page.get_by_label("Username").fill("ada")  # type: ignore[attr-defined]
    page.get_by_label("Password").fill(_PASSWORD)  # type: ignore[attr-defined]
    page.get_by_role("button", name="Create owner").click()  # type: ignore[attr-defined]
    page.get_by_role("button", name="Skip enrollment").click()  # type: ignore[attr-defined]
    page.get_by_role("heading", name="Choose where Praxis thinks").wait_for()  # type: ignore[attr-defined]


def _fill_provider(page: object, name: str, model_port: int, api_key: str = "") -> None:
    page.get_by_role("option", name=name, exact=True).click()  # type: ignore[attr-defined]
    page.get_by_label("Base URL").fill(f"127.0.0.1:{model_port}")  # type: ignore[attr-defined]
    if api_key:
        page.get_by_label("API key").fill(api_key)  # type: ignore[attr-defined]
    page.get_by_role("button", name="Continue").click()  # type: ignore[attr-defined]
    page.get_by_label("Primary model").fill("local-model")  # type: ignore[attr-defined]


def _first_provider(
    page: object,
    gateway: int,
    token: str,
    model_port: int,
    *,
    host: str = "127.0.0.1",
) -> None:
    page.goto(f"http://{host}:{gateway}/#setup={token}")  # type: ignore[attr-defined]
    _reach_picker(page)
    _fill_provider(page, "llama.cpp server", model_port, api_key="sk-first")
    page.get_by_role("button", name="Test and save").click()  # type: ignore[attr-defined]
    page.get_by_text("Inference ready").wait_for()  # type: ignore[attr-defined]
    page.get_by_role("button", name="Continue").click()  # type: ignore[attr-defined]
    page.get_by_role("button", name="Continue").click()  # type: ignore[attr-defined]
    page.get_by_role("link", name="Continue to the app").click()  # type: ignore[attr-defined]
    page.get_by_role("button", name="Sign out").wait_for()  # type: ignore[attr-defined]


def _replace_provider(page: object, gateway: int, model_port: int, *, code: str) -> None:
    page.goto(f"http://127.0.0.1:{gateway}/#/setup")  # type: ignore[attr-defined]
    page.get_by_role("heading", name="Choose where Praxis thinks").wait_for()  # type: ignore[attr-defined]
    _fill_provider(page, "vLLM", model_port, api_key="sk-second")
    page.get_by_role("checkbox", name="Replace the current provider").check()  # type: ignore[attr-defined]
    page.get_by_label("Account password").fill(_PASSWORD)  # type: ignore[attr-defined]
    if code:
        page.get_by_label("Authenticator code").fill(code)  # type: ignore[attr-defined]
    page.get_by_role("button", name="Test and save").click()  # type: ignore[attr-defined]
    page.get_by_text("Inference ready").wait_for()  # type: ignore[attr-defined]


@pytest.mark.browser
def test_wizard_rerun_accepts_a_totp_step_up(tmp_path: Path):
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
            _totp_replace(playwright_sync, gateway, token, int(port))
            secret = (tmp_path / "config" / "praxis-prime" / "secrets.env").read_text(
                encoding="utf-8"
            )
            assert "sk-second" in secret
            assert "sk-first" not in secret
    finally:
        server.shutdown()
        server.server_close()


def _totp_replace(playwright_sync: object, gateway: int, token: str, model_port: int) -> None:
    sync_playwright = playwright_sync.sync_playwright  # type: ignore[attr-defined]
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.set_default_timeout(30_000)
        _first_provider(page, gateway, token, model_port)
        page.get_by_role("link", name="Security").click()
        enroll = page.get_by_role("group", name="Enroll authenticator")
        enroll.get_by_label("Password").fill(_PASSWORD)
        enroll.get_by_role("button", name="Start enrollment").click()
        secret = page.get_by_text("Secret:", exact=False).inner_text().split("Secret:", 1)[1]
        secret = secret.strip().split()[0]
        code = pyotp.TOTP(secret).now()
        page.get_by_label("Confirm authenticator").fill(code)
        page.get_by_role("button", name="Confirm code").click()
        page.get_by_text("Authenticator enrolled.").wait_for()
        # Confirming enrollment spends that timestep. The next step-up needs a new code.
        _replace_provider(page, gateway, model_port, code=_next_totp(secret, code))
        browser.close()


def _next_totp(secret: str, used: str) -> str:
    """The next authenticator code after ``used``. A repeated step is rejected."""
    totp = pyotp.TOTP(secret)
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        current = totp.now()
        if current != used:
            return current
        time.sleep(0.5)
    raise AssertionError("the next authenticator code did not arrive")


@pytest.mark.browser
def test_wizard_rerun_accepts_a_passkey_step_up(tmp_path: Path):
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
            _passkey_replace(playwright_sync, gateway, token, int(port))
            secret = (tmp_path / "config" / "praxis-prime" / "secrets.env").read_text(
                encoding="utf-8"
            )
            assert "sk-second" in secret
            assert "sk-first" not in secret
    finally:
        server.shutdown()
        server.server_close()


def _passkey_replace(playwright_sync: object, gateway: int, token: str, model_port: int) -> None:
    sync_playwright = playwright_sync.sync_playwright  # type: ignore[attr-defined]
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.set_default_timeout(30_000)
        # Passkeys use localhost so the relying party id is a domain.
        host = "localhost"
        _first_provider(page, gateway, token, model_port, host=host)
        page.get_by_role("link", name="Security").click()
        page.get_by_role("group", name="Add a passkey").wait_for()
        _virtual_authenticator(page)
        form = page.get_by_role("group", name="Add a passkey")
        form.get_by_label("Password").fill(_PASSWORD)
        form.get_by_role("button", name="Enroll passkey").click()
        page.get_by_text("Passkey enrolled.").wait_for()
        page.goto(f"http://{host}:{gateway}/#/setup")
        page.get_by_role("heading", name="Choose where Praxis thinks").wait_for()
        _fill_provider(page, "vLLM", model_port, api_key="sk-second")
        page.get_by_role("checkbox", name="Replace the current provider").check()
        page.get_by_role("button", name="Use a passkey").click()
        page.get_by_text("Passkey confirmed.").wait_for()
        page.get_by_role("button", name="Test and save").click()
        page.get_by_text("Inference ready").wait_for()
        browser.close()


@pytest.mark.browser
def test_wizard_browser_back_returns_to_the_picker(tmp_path: Path):
    playwright_sync = _require_browser()
    with _daemon(
        tmp_path,
        [{"content": "unused"}],
        extra_env={"PRAXIS_PRIME_MODEL": ""},
    ) as gateway:
        token = (
            (tmp_path / "config" / "praxis-prime" / "first-run.token")
            .read_text(encoding="utf-8")
            .strip()
        )
        sync_playwright = playwright_sync.sync_playwright  # type: ignore[attr-defined]
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page()
            page.set_default_timeout(30_000)
            page.goto(f"http://127.0.0.1:{gateway}/#setup={token}")
            _reach_picker(page)
            page.get_by_role("option", name="llama.cpp server", exact=True).click()
            page.wait_for_url("**/#/setup/connect/**")
            page.go_back()
            page.get_by_role("heading", name="Choose where Praxis thinks").wait_for()
            page.get_by_role("option", name="llama.cpp server", exact=True).click()
            page.wait_for_url("**/#/setup/connect/**")
            browser.close()


@pytest.mark.browser
def test_wizard_network_server_reaches_inference_ready(tmp_path: Path):
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
            token = (
                (tmp_path / "config" / "praxis-prime" / "first-run.token")
                .read_text(encoding="utf-8")
                .strip()
            )
            sync_playwright = playwright_sync.sync_playwright  # type: ignore[attr-defined]
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                page = browser.new_page()
                page.set_default_timeout(30_000)
                page.goto(f"http://127.0.0.1:{gateway}/#setup={token}")
                _reach_picker(page)
                page.get_by_role(
                    "option", name="Network server (OpenAI-compatible)", exact=True
                ).click()
                page.get_by_label("Base URL").fill(f"127.0.0.1:{port}")
                page.get_by_role("button", name="Check connection").click()
                page.get_by_text("Connected.").wait_for()
                page.get_by_role("button", name="Continue").click()
                page.get_by_role("button", name="local-model", exact=True).click()
                page.get_by_role("button", name="Test and save").click()
                page.get_by_text("Inference ready").wait_for()
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
