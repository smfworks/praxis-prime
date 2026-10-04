"""SPA theme switch under the strict CSP. Skipped unless PRAXIS_PRIME_BROWSER=1."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.test_web_smoke import _PASSWORD, _daemon, _require_browser, _sign_in

from praxis_prime.accounts.db import AccountStore
from praxis_prime.profiles.home import create_profile


@pytest.mark.browser
def test_settings_switches_theme_and_mode(tmp_path: Path):
    playwright_sync = _require_browser()
    root = tmp_path / "data" / "praxis-prime"
    root.mkdir(parents=True)
    create_profile(root, "default")
    store = AccountStore(root / "accounts.db")
    ada = store.create_account(username_text="ada", password=_PASSWORD, display_name="Ada")
    store.set_membership(ada.id, "default", "owner")
    store.close()

    errors: list[str] = []
    with _daemon(tmp_path, [{"content": "ok"}]) as port:
        sync_playwright = playwright_sync.sync_playwright  # type: ignore[attr-defined]
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page(viewport={"width": 1280, "height": 800})
            page.set_default_timeout(30_000)
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on(
                "console",
                lambda message: errors.append(message.text)
                if message.type == "error"
                else None,
            )
            _sign_in(page, port, "ada", settle="Chat")
            page.get_by_role("link", name="Settings").click()
            page.get_by_role("heading", name="Appearance").wait_for()
            page.get_by_label("Mode", exact=True).select_option("light")
            page.wait_for_function("() => document.documentElement.dataset.mode === 'light'")
            for theme_id, light, dark in _THEMES:
                page.get_by_label("Theme", exact=True).select_option(theme_id)
                page.wait_for_function(_BG_IS, arg=light)
                page.get_by_label("Mode", exact=True).select_option("dark")
                page.wait_for_function("() => document.documentElement.dataset.mode === 'dark'")
                page.wait_for_function(_BG_IS, arg=dark)
                page.get_by_label("Mode", exact=True).select_option("light")
                page.wait_for_function(_BG_IS, arg=light)
            page.get_by_label("Theme", exact=True).select_option("omarchy")
            page.wait_for_function(_OMARCHY_SELECTED)
            page.wait_for_function(_BG_IS, arg="#f6f1e7")
            page.get_by_label("Theme", exact=True).select_option("smf.high-contrast")
            page.wait_for_function(_BG_IS, arg="#ffffff")
            page.set_viewport_size({"width": 390, "height": 844})
            page.get_by_role("link", name="Chat").click()
            page.get_by_role("heading", name="Chat").wait_for()
            link = page.locator("#pp-theme")
            assert "smf.high-contrast" in (link.get_attribute("href") or "")
            browser.close()
    blocked = [item for item in errors if "Content Security Policy" in item or "Refused to" in item]
    assert blocked == []


@pytest.mark.browser
def test_apply_theme_rejects_foreign_and_normalized_css(tmp_path: Path):
    playwright_sync = _require_browser()
    digest = "ab" * 32
    foreign = {
        "ok": True,
        "mode": "light",
        "css": "https://evil.example/theme.css",
    }
    normalized = {
        "ok": True,
        "mode": "light",
        "css": f"/themes/../{digest}.css",
    }
    with _daemon(tmp_path, [{"content": "ok"}]) as port:
        sync_playwright = playwright_sync.sync_playwright  # type: ignore[attr-defined]
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page(viewport={"width": 1280, "height": 800})
            page.set_default_timeout(30_000)
            page.route("**/v1/themes/active*", lambda route: _fulfill_json(route, foreign))
            page.goto(f"http://127.0.0.1:{port}/")
            page.locator("h1").first.wait_for()
            page.wait_for_timeout(300)
            assert page.locator("#pp-theme").count() == 0
            page.unroute("**/v1/themes/active*")
            page.route("**/v1/themes/active*", lambda route: _fulfill_json(route, normalized))
            page.reload()
            page.locator("h1").first.wait_for()
            page.wait_for_timeout(300)
            assert page.locator("#pp-theme").count() == 0
            script = page.locator("script[src]").first.get_attribute("src") or ""
            bundle = page.evaluate(
                "(src) => fetch(src).then((response) => response.text())",
                script,
            )
            assert "pp-dial-control" in bundle
            assert "pp-approval-actions" in bundle
            browser.close()


def _fulfill_json(route, body: dict[str, object]) -> None:
    route.fulfill(
        status=200,
        content_type="application/json",
        body=json.dumps(body),
    )


_OMARCHY_SELECTED = "() => document.getElementById('pp-theme-choice').value === 'omarchy'"

_THEMES = (
    ("smf.praxis", "#f6f1e7", "#14110f"),
    ("smf.legal-office", "#f7f3ea", "#0f1522"),
    ("smf.forensic", "#f4f6f8", "#121416"),
    ("smf.education", "#f8fafc", "#0f172a"),
    ("smf.classical", "#f5efe3", "#0a0a0f"),
    ("smf.medical", "#f7fafa", "#0c1a1f"),
    ("smf.dental", "#f6fbfa", "#0d1b1a"),
    ("smf.high-contrast", "#ffffff", "#000000"),
)

_BG_IS = """(expected) => {
  const style = getComputedStyle(document.documentElement);
  const raw = style.getPropertyValue("--pp-bg").trim().toLowerCase();
  const hex = {
    '#ffffff': ['#ffffff', '#fff', 'rgb(255, 255, 255)'],
    '#000000': ['#000000', '#000', 'rgb(0, 0, 0)'],
  };
  return (hex[expected] || [expected]).includes(raw);
}"""
