"""OIDC sign-in in a real browser, when Playwright and Chromium are installed.

The daemon and the fake provider are different ports on 127.0.0.1, which is
one site. The Lax binding cookie is sent on the top-level callback. CI skips
this file when the browser is absent.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from test_oidc import prelink, world


@pytest.mark.skipif(
    importlib.util.find_spec("playwright") is None,
    reason="Playwright is not installed",
)
def test_oidc_sign_in_in_chromium(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if not _chromium_ready():
        pytest.skip("Playwright browsers are not installed")
    from playwright.sync_api import sync_playwright

    with world(tmp_path, monkeypatch) as ctx:
        prelink(ctx.store, username_text="ada", issuer=ctx.fake.issuer, subject="subject-1")
        with sync_playwright() as manager:
            browser = manager.chromium.launch(headless=True)
            try:
                for width, height in ((1280, 800), (390, 844)):
                    context = browser.new_context(viewport={"width": width, "height": height})
                    page = context.new_page()
                    page.goto(f"http://127.0.0.1:{ctx.port}/", wait_until="domcontentloaded")
                    button = page.get_by_role("button", name="Sign in with Local")
                    button.wait_for()
                    box = button.bounding_box()
                    assert box is not None and box["width"] > 40
                    button.click()
                    page.get_by_text("Signed in as ada.").wait_for(timeout=15000)
                    assert page.get_by_text("Signed in.").is_visible()
                    assert "code=" not in page.url
                    assert "oidc=" not in page.url
                    context.close()
            finally:
                browser.close()


def _chromium_ready() -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        manager = sync_playwright().start()
    except Exception:
        return False
    try:
        browser = manager.chromium.launch(headless=True)
        browser.close()
    except Exception:
        return False
    finally:
        manager.stop()
    return True
