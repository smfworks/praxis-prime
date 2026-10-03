"""Headless browser smoke test for the local web app.

Skipped unless ``PRAXIS_PRIME_BROWSER=1``. CI's frontend job sets that and
installs Playwright's Chromium. The Python matrix does not.
"""

from __future__ import annotations

import json
import os
import signal
import site
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pyotp
import pytest

from praxis_prime.accounts.db import AccountStore
from praxis_prime.accounts.factors import Factors
from praxis_prime.profiles.home import create_profile

_PASSWORD = "correct-horse"


@pytest.mark.browser
def test_daemon_spa_signs_in_streams_and_approves(tmp_path: Path):
    if os.environ.get("PRAXIS_PRIME_BROWSER") != "1":
        pytest.skip("set PRAXIS_PRIME_BROWSER=1 to run the web smoke test")
    playwright_sync = pytest.importorskip("playwright.sync_api")
    ui = Path(__file__).resolve().parents[1] / "ui" / "dist"
    assert (ui / "index.html").is_file()

    data_home = tmp_path / "data"
    root = data_home / "praxis-prime"
    root.mkdir(parents=True)
    create_profile(root, "default")
    store = AccountStore(root / "accounts.db")
    ada = store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
    store.set_membership(ada.id, "default", "owner")
    enrollment = Factors(store).begin_totp(ada.id)
    Factors(store).confirm_totp(ada.id, pyotp.TOTP(enrollment.secret).now())
    secret = enrollment.secret
    store.close()

    replies = tmp_path / "replies.json"
    replies.write_text(
        json.dumps(
            {
                "replies": [
                    {
                        "content": "Looking at the note.",
                        "toolCalls": [
                            {
                                "id": "c1",
                                "name": "shell",
                                "arguments": {"command": "rm -f smoke-note.txt"},
                            }
                        ],
                    },
                    {"content": "Removed the note."},
                ]
            }
        ),
        encoding="utf-8",
    )
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("PRAXIS_PRIME_")
    }
    repo = Path(__file__).resolve().parents[1]
    user_site = site.getusersitepackages()
    python_path = [
        str(repo),
        str(repo / "packages" / "prime-core"),
    ]
    if isinstance(user_site, str) and user_site:
        python_path.append(user_site)
    inherited = env.get("PYTHONPATH", "")
    if inherited:
        python_path.append(inherited)
    env.update(
        {
            "HOME": str(tmp_path / "home"),
            "XDG_CONFIG_HOME": str(tmp_path / "config"),
            "XDG_DATA_HOME": str(data_home),
            "XDG_STATE_HOME": str(tmp_path / "state"),
            "XDG_CACHE_HOME": str(tmp_path / "cache"),
            "XDG_RUNTIME_DIR": str(tmp_path / "runtime"),
            "PYTHONPATH": os.pathsep.join(python_path),
            "PRAXIS_PRIME_GATEWAY_LISTEN": "127.0.0.1:0",
            "PRAXIS_PRIME_STUB_REPLIES": str(replies),
            "PRAXIS_PRIME_UI_DIR": str(ui),
        }
    )
    (tmp_path / "runtime").mkdir()
    output = tmp_path / "daemon.out"
    handle = output.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-m", "praxis_prime.daemon"],
        env=env,
        stdout=handle,
        stderr=subprocess.STDOUT,
    )
    try:
        port = _wait_port(env, proc, output)
        _browser(playwright_sync, port, secret)
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        handle.close()


def _browser(playwright_sync: object, port: int, secret: str) -> None:
    sync_playwright = playwright_sync.sync_playwright  # type: ignore[attr-defined]
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.set_default_timeout(30_000)
        page.goto(f"http://127.0.0.1:{port}/")
        page.get_by_label("Username").fill("ada")
        page.get_by_label("Password").fill(_PASSWORD)
        page.get_by_role("button", name="Sign in").click()
        page.get_by_label("Authenticator code").fill(_fresh_code(secret))
        page.get_by_role("button", name="Verify code").click()
        page.get_by_role("heading", name="Chat").wait_for()
        page.get_by_label("Message").fill("delete the note")
        page.get_by_role("button", name="Send").click()
        page.get_by_role("log").get_by_text("Looking at the note.").wait_for()
        page.get_by_role("button", name="Approve once").click()
        page.get_by_role("log").get_by_text("Removed the note.").wait_for()
        page.get_by_role("button", name="Sign out").click()
        page.get_by_role("button", name="Sign in").wait_for()
        browser.close()


@contextmanager
def _daemon(
    tmp_path: Path,
    replies: list[dict[str, object]],
    *,
    extra_env: dict[str, str] | None = None,
) -> Iterator[int]:
    """A supervisor daemon with the scripted model. The caller creates profiles."""
    ui = Path(__file__).resolve().parents[1] / "ui" / "dist"
    assert (ui / "index.html").is_file()
    file = tmp_path / "replies.json"
    file.write_text(json.dumps({"replies": replies}), encoding="utf-8")
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("PRAXIS_PRIME_")
    }
    repo = Path(__file__).resolve().parents[1]
    user_site = site.getusersitepackages()
    python_path = [str(repo), str(repo / "packages" / "prime-core")]
    if isinstance(user_site, str) and user_site:
        python_path.append(user_site)
    inherited = env.get("PYTHONPATH", "")
    if inherited:
        python_path.append(inherited)
    env.update(
        {
            "HOME": str(tmp_path / "home"),
            "XDG_CONFIG_HOME": str(tmp_path / "config"),
            "XDG_DATA_HOME": str(tmp_path / "data"),
            "XDG_STATE_HOME": str(tmp_path / "state"),
            "XDG_CACHE_HOME": str(tmp_path / "cache"),
            "XDG_RUNTIME_DIR": str(tmp_path / "runtime"),
            "PYTHONPATH": os.pathsep.join(python_path),
            "PRAXIS_PRIME_GATEWAY_LISTEN": "127.0.0.1:0",
            "PRAXIS_PRIME_STUB_REPLIES": str(file),
            "PRAXIS_PRIME_UI_DIR": str(ui),
        }
    )
    if extra_env:
        env.update(extra_env)
    (tmp_path / "runtime").mkdir()
    output = tmp_path / "daemon.out"
    handle = output.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-m", "praxis_prime.daemon"],
        env=env,
        stdout=handle,
        stderr=subprocess.STDOUT,
    )
    try:
        yield _wait_port(env, proc, output, timeout=40)
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        handle.close()


def _require_browser() -> object:
    if os.environ.get("PRAXIS_PRIME_BROWSER") != "1":
        pytest.skip("set PRAXIS_PRIME_BROWSER=1 to run the web smoke test")
    return pytest.importorskip("playwright.sync_api")


def _sign_in(page: object, port: int, username: str, *, settle: str) -> None:
    page.goto(f"http://127.0.0.1:{port}/")  # type: ignore[attr-defined]
    page.get_by_label("Username").fill(username)  # type: ignore[attr-defined]
    page.get_by_label("Password").fill(_PASSWORD)  # type: ignore[attr-defined]
    page.get_by_role("button", name="Sign in").click()  # type: ignore[attr-defined]
    if settle == "Chat":
        page.get_by_role("heading", name="Chat").wait_for()  # type: ignore[attr-defined]
    else:
        page.get_by_text(settle).wait_for()  # type: ignore[attr-defined]


def _frame_text(frame: object) -> str:
    if isinstance(frame, str):
        return frame
    if isinstance(frame, bytes):
        return frame.decode()
    payload = getattr(frame, "payload", None)
    if isinstance(payload, str):
        return payload
    if isinstance(payload, bytes):
        return payload.decode()
    return str(frame)


def _watch_sockets(page: object) -> list[str]:
    sent: list[str] = []

    def on_socket(socket: object) -> None:
        socket.on("framesent", lambda frame: sent.append(_frame_text(frame)))  # type: ignore[attr-defined]

    page.on("websocket", on_socket)  # type: ignore[attr-defined]
    return sent


def _chat_sends(raw_frames: list[str]) -> list[dict[str, object]]:
    sends: list[dict[str, object]] = []
    for raw in raw_frames:
        try:
            loaded = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(loaded, dict) or loaded.get("type") != "chat.send":
            continue
        payload = loaded.get("payload")
        if isinstance(payload, dict):
            sends.append(payload)
    return sends


def _agent_text(page: object) -> str:
    lines = page.get_by_role("log").locator("p").all_inner_texts()  # type: ignore[attr-defined]
    return "\n".join(line for line in lines if line.startswith("Agent:"))


@pytest.mark.browser
def test_catalog_requests_send_the_profile_and_switch_clears_chat(tmp_path: Path):
    """Catalog reads name the selected profile, and another profile starts a new chat."""
    playwright_sync = _require_browser()
    root = tmp_path / "data" / "praxis-prime"
    root.mkdir(parents=True)
    create_profile(root, "default")
    create_profile(root, "beta")
    store = AccountStore(root / "accounts.db")
    ada = store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
    store.set_membership(ada.id, "default", "owner")
    store.set_membership(ada.id, "beta", "owner")
    store.close()
    # Each profile worker loads this file itself, so the first turn on either
    # profile gets the first reply. The second turn must not reuse the session.
    replies = [
        {"content": "SESSION-MARKER"},
        {"content": "SESSION-MARKER"},
    ]
    with _daemon(tmp_path, replies) as port:
        sync_playwright = playwright_sync.sync_playwright  # type: ignore[attr-defined]
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page()
            page.set_default_timeout(30_000)
            gate = {"empty": True}

            def profiles(route: object) -> None:
                if gate["empty"]:
                    route.fulfill(  # type: ignore[attr-defined]
                        status=200,
                        content_type="application/json",
                        body=json.dumps({"ok": True, "profiles": []}),
                    )
                    return
                route.continue_()  # type: ignore[attr-defined]

            page.route("**/v1/profiles", profiles)
            _sign_in(page, port, "ada", settle="Choose a profile.")
            catalog: list[str] = []
            page.on("request", lambda request: catalog.append(request.url))
            page.get_by_role("link", name="Memory").click()
            page.wait_for_timeout(400)
            blocked = ("/v1/memory", "/v1/skills", "/v1/routines")
            assert not any(url.endswith(blocked) for url in catalog)
            gate["empty"] = False
            page.reload()
            page.goto(f"http://127.0.0.1:{port}/#/chat")
            page.get_by_role("heading", name="Chat").wait_for()
            assert page.get_by_label("Profile").input_value() == "default"
            sent = _watch_sockets(page)
            headed: list[tuple[str, str]] = []

            def remember(request: object) -> None:
                url = request.url  # type: ignore[attr-defined]
                header = request.headers.get("x-praxis-profile", "")  # type: ignore[attr-defined]
                headed.append((url, header))

            page.on("request", remember)
            for label, suffix in (
                ("Memory", "/v1/memory"),
                ("Skills", "/v1/skills"),
                ("Routines", "/v1/routines"),
            ):
                page.get_by_role("link", name=label).click()
                page.get_by_role("heading", name=label).wait_for()
                matches = [header for url, header in headed if url.endswith(suffix)]
                assert matches, suffix
                assert matches[-1] == "default"
            page.get_by_role("link", name="Chat").click()
            page.get_by_label("Message").fill("first session")
            page.get_by_role("button", name="Send").click()
            page.get_by_role("log").get_by_text("SESSION-MARKER").wait_for()
            page.get_by_label("Profile").select_option("beta")
            page.get_by_text("No messages yet.").wait_for()
            assert page.get_by_role("log").get_by_text("SESSION-MARKER").count() == 0
            before = len(sent)
            page.get_by_label("Message").fill("second session")
            page.get_by_role("button", name="Send").click()
            page.get_by_role("log").get_by_text("SESSION-MARKER").wait_for()
            sends = _chat_sends(sent[before:])
            assert sends
            assert "sessionId" not in sends[-1]
            assert sends[-1].get("profile") == "beta"
            browser.close()


@pytest.mark.browser
def test_concurrent_sessions_keep_their_own_stream(tmp_path: Path):
    """Two accounts on one profile each see only their own streamed text."""
    playwright_sync = _require_browser()
    root = tmp_path / "data" / "praxis-prime"
    root.mkdir(parents=True)
    create_profile(root, "default")
    store = AccountStore(root / "accounts.db")
    ada = store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
    store.set_membership(ada.id, "default", "owner")
    bea = store.create_account(
        username_text="bea",
        password=_PASSWORD,
        display_name="Bea",
        role="operator",
    )
    store.set_membership(bea.id, "default", "operator")
    store.close()
    ada_marker = "STREAMED-early-ada SECRETADA9988" + ("x" * 24)
    bea_marker = "STREAMED-bea-only-BETA7766"
    replies = [
        {"content": ada_marker, "pace_ms": 50},
        {"content": bea_marker},
    ]
    with _daemon(tmp_path, replies) as port:
        sync_playwright = playwright_sync.sync_playwright  # type: ignore[attr-defined]
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            ada_page = browser.new_context().new_page()
            bea_page = browser.new_context().new_page()
            ada_page.set_default_timeout(30_000)
            bea_page.set_default_timeout(30_000)
            _sign_in(ada_page, port, "ada", settle="Chat")
            _sign_in(bea_page, port, "bea", settle="Chat")
            ada_page.get_by_label("Message").fill("ada question")
            ada_page.get_by_role("button", name="Send").click()
            ada_page.get_by_role("log").get_by_text("STREAMED-early-ada").wait_for()
            bea_page.get_by_label("Message").fill("bea question")
            bea_page.get_by_role("button", name="Send").click()
            ada_page.get_by_role("log").get_by_text("SECRETADA9988").wait_for()
            bea_page.get_by_role("log").get_by_text("BETA7766").wait_for()
            assert ada_marker in _agent_text(ada_page)
            assert bea_marker in _agent_text(bea_page)
            assert "SECRETADA9988" not in bea_page.locator("body").inner_text()
            assert "BETA7766" not in ada_page.locator("body").inner_text()
            browser.close()


def _fresh_code(secret: str) -> str:
    """A code from a later step than enrollment, which already spent one."""
    period = 30
    totp = pyotp.TOTP(secret)
    first = totp.now()
    deadline = time.monotonic() + period + 2
    while time.monotonic() < deadline:
        current = totp.now()
        if current != first:
            return current
        time.sleep(0.25)
    return totp.now()


def _wait_port(
    env: dict[str, str],
    proc: subprocess.Popen[str],
    output: Path,
    timeout: float = 20,
) -> int:
    info = Path(env["XDG_RUNTIME_DIR"]) / "praxis-prime" / "gateway.json"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if info.is_file():
            loaded = json.loads(info.read_text(encoding="utf-8"))
            port = loaded.get("port")
            if isinstance(port, int) and port > 0:
                return port
        if proc.poll() is not None:
            raise AssertionError(output.read_text(encoding="utf-8"))
        time.sleep(0.05)
    raise AssertionError(output.read_text(encoding="utf-8") or "daemon did not publish a port")
