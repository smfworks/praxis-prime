"""Shipped SPA assets, the opt-in stub model, and browser OIDC sign-in."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pyotp
import pytest

from oidc_fake import FakeOidc
from praxis_prime.accounts.db import AccountStore
from praxis_prime.accounts.factors import Factors
from praxis_prime.accounts.oidc import add_provider, clear_caches, prelink
from praxis_prime.profiles.home import create_profile
from praxis_prime.router.stub import providers_from_env
from praxis_prime.router.types import ChatMessage, ChatRequest
from test_web_smoke import _daemon, _fresh_code, _require_browser

_PASSWORD = "correct-horse"
_OIDC_SECRET = "oidc-test-secret-value"
_CLIENT = "praxis-test"

_INLINE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>", re.IGNORECASE)
# React's production bundle names these. They are error text and XML namespaces,
# not requests. A CDN, font host, or analytics host is still rejected.
_LOCAL_ONLY = (
    "https://react.dev/errors/",
    "http://www.w3.org/",
)
_FORBIDDEN = (
    "fonts.googleapis",
    "fonts.gstatic",
    "cdn.jsdelivr",
    "unpkg.com",
    "cdnjs.cloudflare",
    "googletagmanager",
    "google-analytics",
)


def test_shipped_spa_is_local_and_has_no_inline_script():
    root = Path(__file__).resolve().parents[1] / "ui" / "dist"
    html_path = root / "index.html"
    assert html_path.is_file()
    html = html_path.read_text(encoding="utf-8")
    assert 'src="/assets/' in html
    assert _INLINE.search(html) is None
    saw_script = False
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".html", ".js", ".css"}:
            continue
        text = path.read_text(encoding="utf-8")
        for host in _FORBIDDEN:
            assert host not in text
        assert "unsafe-inline" not in text
        assert "unsafe-eval" not in text
        stripped = text
        for prefix in _LOCAL_ONLY:
            stripped = stripped.replace(prefix, "")
        assert "http://" not in stripped
        assert "https://" not in stripped
        if path.suffix.lower() == ".js":
            saw_script = True
    assert saw_script


def test_stub_replies_stay_off_unless_the_env_is_set(tmp_path: Path):
    assert providers_from_env({}) is None
    path = tmp_path / "replies.json"
    path.write_text(
        json.dumps(
            {
                "replies": [
                    {
                        "content": "Looking.",
                        "toolCalls": [
                            {"id": "c1", "name": "shell", "arguments": {"command": "rm -f note"}}
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    providers = providers_from_env({"PRAXIS_PRIME_STUB_REPLIES": str(path)})
    assert providers is not None
    provider = providers["ollama"]
    events = list(provider.iter_stream(ChatRequest(model="ollama:qwen3:32b", messages=())))
    assert [type(event).__name__ for event in events] == ["TextDelta", "AssistantFinal"]
    assert getattr(events[0], "text", "") == "Looking."


@pytest.mark.browser
def test_oidc_totp_sign_in_shows_the_code_form(tmp_path: Path) -> None:
    """OIDC plus TOTP finishes in the SPA with an empty mfaToken and pp_mfa."""
    playwright_sync = _require_browser()
    root = tmp_path / "data" / "praxis-prime"
    root.mkdir(parents=True)
    create_profile(root, "default")
    store = AccountStore(root / "accounts.db")
    ada = store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
    store.set_membership(ada.id, "default", "owner")
    enrolled = Factors(store).begin_totp(ada.id)
    Factors(store).confirm_totp(ada.id, pyotp.TOTP(enrolled.secret).now())
    secret_path = tmp_path / "secrets.env"
    secret_path.write_text(f"PRAXIS_PRIME_OIDC_SECRET_LOCAL={_OIDC_SECRET}\n", encoding="utf-8")
    secret_path.chmod(0o600)
    fake = FakeOidc(client_id=_CLIENT, secret=_OIDC_SECRET)
    try:
        add_provider(
            store,
            provider_id="local",
            display_name="Local",
            issuer=fake.issuer,
            client_id=_CLIENT,
            secret_key="PRAXIS_PRIME_OIDC_SECRET_LOCAL",
            dev_loopback=True,
        )
        prelink(store, username_text="ada", issuer=fake.issuer, subject="subject-1")
        store.close()
        clear_caches()
        with _daemon(
            tmp_path,
            [],
            extra_env={"PRAXIS_PRIME_SECRETS_FILE": str(secret_path)},
        ) as port:
            sync_playwright = playwright_sync.sync_playwright  # type: ignore[attr-defined]
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                page = browser.new_page()
                page.set_default_timeout(60_000)
                page.goto(f"http://127.0.0.1:{port}/")  # type: ignore[attr-defined]
                page.get_by_role("button", name="Sign in with Local").click()  # type: ignore[attr-defined]
                page.get_by_label("Authenticator code").wait_for()  # type: ignore[attr-defined]
                assert page.get_by_label("Username").count() == 0  # type: ignore[attr-defined]
                page.get_by_label("Authenticator code").fill(_fresh_code(enrolled.secret))  # type: ignore[attr-defined]
                page.get_by_role("button", name="Verify code").click()  # type: ignore[attr-defined]
                page.get_by_role("heading", name="Chat").wait_for()  # type: ignore[attr-defined]
                assert "code=" not in page.url  # type: ignore[attr-defined]
                browser.close()
    finally:
        fake.close()
        clear_caches()


def test_stub_can_pace_a_reply_and_include_the_user_text(tmp_path: Path):
    path = tmp_path / "replies.json"
    path.write_text(
        json.dumps({"replies": [{"content": "echo {{message}}", "pace_ms": 1}]}),
        encoding="utf-8",
    )
    providers = providers_from_env({"PRAXIS_PRIME_STUB_REPLIES": str(path)})
    assert providers is not None
    request = ChatRequest(
        model="ollama:qwen3:32b",
        messages=(ChatMessage(role="user", content="secret-token"),),
    )
    events = list(providers["ollama"].iter_stream(request))
    deltas = [event for event in events if type(event).__name__ == "TextDelta"]
    assert len(deltas) > 1
    assert "".join(getattr(event, "text", "") for event in deltas) == "echo secret-token"
    assert getattr(events[-1], "content", "") == "echo secret-token"
