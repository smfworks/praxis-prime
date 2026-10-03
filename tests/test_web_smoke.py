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


def _wait_port(env: dict[str, str], proc: subprocess.Popen[str], output: Path) -> int:
    info = Path(env["XDG_RUNTIME_DIR"]) / "praxis-prime" / "gateway.json"
    deadline = time.monotonic() + 20
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
