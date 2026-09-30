"""Browser drivers.

Playwright is optional. When it is missing, the tool falls back to
``web_fetch`` for read actions. The default profile is a disposable
directory, not the user's signed-in browser.

ARCHITECTURE §13.2.
"""

from __future__ import annotations

import importlib.util
import shutil
import tempfile
from pathlib import Path
from typing import Protocol


def playwright_available() -> bool:
    return importlib.util.find_spec("playwright") is not None


class BrowserDriver(Protocol):
    def navigate(self, url: str) -> str: ...

    def snapshot(self) -> str: ...

    def click(self, selector: str) -> str: ...

    def type_text(self, selector: str, text: str) -> str: ...

    def screenshot(self, path: Path) -> str: ...

    def extract_text(self) -> str: ...

    def download(self, selector: str, dest: Path) -> str: ...

    def close(self) -> str: ...

    def current_url(self) -> str: ...


class PlaywrightDriver:
    """Headless Chromium with its own profile directory."""

    def __init__(self, profile_dir: Path) -> None:
        from playwright.sync_api import sync_playwright

        self._profile = profile_dir
        self._url = ""
        self._allow_download = False
        self._pw = sync_playwright().start()
        self._context = self._pw.chromium.launch_persistent_context(
            user_data_dir=str(profile_dir),
            headless=True,
            accept_downloads=True,
        )
        self._context.on("page", self._watch)
        self._page = self._context.pages[0] if self._context.pages else self._context.new_page()
        self._watch(self._page)

    def navigate(self, url: str) -> str:
        self._allow_download = False
        response = self._page.goto(url, wait_until="domcontentloaded", timeout=20_000)
        self._url = self._page.url
        status = response.status if response is not None else 0
        title = self._page.title()
        return f"url: {self._url}\nstatus: {status}\ntitle: {title}"

    def snapshot(self) -> str:
        try:
            return str(self._page.locator("body").aria_snapshot())
        except Exception:
            return self.extract_text()

    def click(self, selector: str) -> str:
        self._page.click(selector, timeout=5_000)
        self._url = self._page.url
        return f"clicked {selector}\nurl: {self._url}"

    def type_text(self, selector: str, text: str) -> str:
        self._page.fill(selector, text, timeout=5_000)
        return f"typed into {selector}"

    def screenshot(self, path: Path) -> str:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._page.screenshot(path=str(path))
        return f"screenshot: {path}"

    def extract_text(self) -> str:
        return self._page.inner_text("body")

    def download(self, selector: str, dest: Path) -> str:
        dest.mkdir(parents=True, exist_ok=True)
        self._allow_download = True
        try:
            with self._page.expect_download(timeout=10_000) as download_info:
                self._page.click(selector, timeout=5_000)
            download = download_info.value
            target = dest / (download.suggested_filename or "download.bin")
            download.save_as(str(target))
            self._url = self._page.url
            return f"downloaded {target}"
        finally:
            self._allow_download = False

    def close(self) -> str:
        self._context.close()
        self._pw.stop()
        return "closed"

    def current_url(self) -> str:
        return self._url

    def _watch(self, page: object) -> None:
        def _gate(download: object) -> None:
            if self._allow_download:
                return
            cancel = getattr(download, "cancel", None)
            if cancel is not None:
                cancel()

        on = getattr(page, "on", None)
        if on is not None:
            on("download", _gate)


def make_profile_dir(persistent: bool, data_root: Path) -> tuple[Path, bool]:
    """Return ``(path, disposable)``. Disposable directories are removed on close."""
    if persistent:
        path = data_root / "browser-profile"
        path.mkdir(parents=True, exist_ok=True)
        return path, False
    path = Path(tempfile.mkdtemp(prefix="praxis-prime-browser-"))
    return path, True


def remove_profile(path: Path, disposable: bool) -> None:
    if disposable:
        shutil.rmtree(path, ignore_errors=True)
