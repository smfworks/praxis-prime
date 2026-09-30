"""Browser policy, the fake driver, and the web_fetch fallback.

A live Playwright test runs only when Chromium is installed. CI does not
need a browser.
"""

from __future__ import annotations

import importlib.util
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest

from praxis_prime.browser.driver import make_profile_dir, playwright_available, remove_profile
from praxis_prime.browser.guard import BrowserFetchGuard
from praxis_prime.browser.policy import BrowserPolicy, classify_browser
from praxis_prime.browser.tool import BrowserSession
from praxis_prime.policy.boundary import ReadDenied
from praxis_prime.tools.registry import Risk, ToolContext


def test_domain_lists_and_always_ask_actions():
    policy = BrowserPolicy(
        allow_domains=("example.com",),
        deny_domains=("secret.example.com",),
    )
    navigate = classify_browser(
        {"action": "navigate", "url": "https://www.example.com/docs"},
        policy,
    )
    assert navigate.risk is Risk.READ
    assert navigate.force_approval is False

    with pytest.raises(ValueError, match="allow"):
        classify_browser({"action": "navigate", "url": "https://evil.test/x"}, policy)
    with pytest.raises(ValueError, match="denied"):
        classify_browser(
            {"action": "navigate", "url": "https://secret.example.com/home"},
            policy,
        )
    with pytest.raises(ValueError):
        classify_browser({"action": "navigate", "url": "http://169.254.169.254/latest"}, policy)

    payment = classify_browser(
        {"action": "navigate", "url": "https://shop.example.com/checkout"},
        policy,
    )
    assert payment.risk is Risk.SPEND
    assert payment.force_approval is True

    login = classify_browser(
        {"action": "click", "selector": "#login"},
        policy,
        page_url="https://www.example.com/login",
    )
    assert login.risk is Risk.SEND
    assert login.force_approval is True

    submit = classify_browser(
        {"action": "submit", "selector": "button"},
        policy,
        page_url="https://www.example.com/form",
    )
    assert submit.risk is Risk.SEND
    assert "submit" in submit.force_reason

    download = classify_browser(
        {"action": "download", "selector": "a.file"},
        policy,
        page_url="https://www.example.com/files",
    )
    assert download.risk is Risk.SEND

    purchase = classify_browser(
        {"action": "purchase", "selector": "#buy"},
        policy,
        page_url="https://www.example.com/shop",
    )
    assert purchase.risk is Risk.SPEND

    typed = classify_browser(
        {"action": "type", "selector": "#password", "text": "hunter2"},
        policy,
        page_url="https://www.example.com/login",
    )
    assert typed.force_approval is True
    assert "hunter2" not in typed.summary

    card = classify_browser(
        {"action": "type", "selector": "#card", "text": "4111111111111111"},
        policy,
        page_url="https://www.example.com/shop",
    )
    assert card.risk is Risk.SPEND
    assert "4111111111111111" not in card.summary

    plain = classify_browser(
        {"action": "click", "selector": "a.docs"},
        policy,
        page_url="https://www.example.com/docs",
    )
    assert plain.risk is Risk.DRAFT
    assert plain.force_approval is False


def test_metadata_stays_blocked_when_fetch_allow_lists_it():
    policy = BrowserPolicy(fetch_allow=frozenset({"metadata", "loopback", "private", "link_local"}))
    with pytest.raises(ReadDenied) as caught:
        classify_browser(
            {"action": "navigate", "url": "http://169.254.169.254/latest"},
            policy,
        )
    assert caught.value.code == "fetch_metadata"
    allowed = classify_browser({"action": "navigate", "url": "http://127.0.0.1/"}, policy)
    assert allowed.risk is Risk.READ


def test_fake_driver_skips_denied_hosts_and_runs_allowed_ones(tmp_path: Path):
    driver = _FakeDriver()
    policy = BrowserPolicy(allow_domains=("example.com",), deny_domains=())
    session = BrowserSession(
        policy,
        cwd=tmp_path,
        data_root=tmp_path,
        driver_factory=lambda _path: driver,
        playwright_ok=lambda: True,
    )
    context = ToolContext(cwd=str(tmp_path), cancelled=lambda: False)
    try:
        with pytest.raises(ValueError, match="allow"):
            session.execute({"action": "navigate", "url": "https://evil.test/"}, context)
        assert driver.events == []
        text = session.execute(
            {"action": "navigate", "url": "https://www.example.com/a"},
            context,
        )
        assert "example.com" in text
        assert driver.events == [("navigate", "https://www.example.com/a")]
        session.execute({"action": "snapshot"}, context)
        session.execute({"action": "type", "selector": "#q", "text": "hello"}, context)
        session.execute({"action": "extract"}, context)
        shot = session.execute({"action": "screenshot", "path": "shot.png"}, context)
        assert "shot.png" in shot
        session.execute({"action": "close"}, context)
        assert ("close",) in driver.events
    finally:
        session.close()


def test_missing_playwright_falls_back_to_web_fetch(tmp_path: Path):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<html><body><h1>Fetched page</h1></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    session = BrowserSession(
        BrowserPolicy(fetch_allow=frozenset({"loopback"})),
        cwd=tmp_path,
        data_root=tmp_path,
        playwright_ok=lambda: False,
    )
    context = ToolContext(cwd=str(tmp_path), cancelled=lambda: False)
    try:
        port = server.server_address[1]
        text = session.execute(
            {"action": "navigate", "url": f"http://127.0.0.1:{port}/"},
            context,
        )
        assert "web_fetch" in text
        assert "Fetched page" in text
        snapshot = session.execute({"action": "snapshot"}, context)
        assert "Fetched page" in snapshot
        with pytest.raises(RuntimeError, match="Playwright"):
            session.execute({"action": "click", "selector": "a"}, context)
    finally:
        session.close()
        server.shutdown()


def test_disposable_profile_is_removed_and_persistent_stays(tmp_path: Path):
    path, disposable = make_profile_dir(False, tmp_path)
    assert disposable is True
    remove_profile(path, True)
    assert not path.exists()
    kept, disposable = make_profile_dir(True, tmp_path)
    assert disposable is False
    assert kept == tmp_path / "browser-profile"
    assert kept.is_dir()


@pytest.mark.skipif(
    importlib.util.find_spec("playwright") is None, reason="Playwright is not installed"
)
def test_playwright_navigate_when_chromium_is_installed(tmp_path: Path):
    if not _chromium_ready():
        pytest.skip("Playwright browsers are not installed")
    from praxis_prime.browser.driver import PlaywrightDriver

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<html><body><h1>Live page</h1><input id='q'/></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    session = BrowserSession(
        BrowserPolicy(fetch_allow=frozenset({"loopback"})),
        cwd=tmp_path,
        data_root=tmp_path,
        driver_factory=PlaywrightDriver,
        playwright_ok=playwright_available,
    )
    context = ToolContext(cwd=str(tmp_path), cancelled=lambda: False)
    try:
        port = server.server_address[1]
        text = session.execute(
            {"action": "navigate", "url": f"http://127.0.0.1:{port}/"},
            context,
        )
        assert "Live page" in text or "127.0.0.1" in text
        extracted = session.execute({"action": "extract"}, context)
        assert "Live page" in extracted
        session.execute({"action": "type", "selector": "#q", "text": "hi"}, context)
        shot = session.execute({"action": "screenshot", "path": "page.png"}, context)
        assert (tmp_path / "page.png").is_file()
        assert "page.png" in shot
        assert session.execute({"action": "close"}, context) == "closed"
    finally:
        session.close()
        server.shutdown()


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


class _FakeDriver:
    def __init__(self) -> None:
        self.events: list[tuple[str, str]] = []
        self.url = ""

    def navigate(self, url: str) -> str:
        self.events.append(("navigate", url))
        self.url = url
        return f"navigated {url}"

    def snapshot(self) -> str:
        self.events.append(("snapshot", self.url))
        return "snapshot text"

    def click(self, selector: str) -> str:
        self.events.append(("click", selector))
        return f"clicked {selector}"

    def type_text(self, selector: str, text: str) -> str:
        self.events.append(("type", selector))
        return f"typed into {selector}"

    def screenshot(self, path: Path) -> str:
        self.events.append(("screenshot", str(path)))
        path.write_bytes(b"png")
        return f"screenshot: {path}"

    def extract_text(self) -> str:
        self.events.append(("extract", self.url))
        return "extracted"

    def download(self, selector: str, dest: Path) -> str:
        self.events.append(("download", selector))
        return f"downloaded {dest}"

    def close(self) -> str:
        self.events.append(("close",))
        return "closed"

    def current_url(self) -> str:
        return self.url


def test_session_arms_the_driver_with_fetch_allow(tmp_path: Path):
    seen: dict[str, set[str]] = {}

    class _Armed(_FakeDriver):
        def arm(self, fetch_allow):
            seen["allow"] = set(fetch_allow)

    session = BrowserSession(
        BrowserPolicy(fetch_allow=frozenset({"loopback"})),
        cwd=tmp_path,
        data_root=tmp_path,
        driver_factory=lambda _path: _Armed(),
        playwright_ok=lambda: True,
    )
    context = ToolContext(cwd=str(tmp_path), cancelled=lambda: False)
    try:
        session.execute({"action": "navigate", "url": "https://www.example.com/a"}, context)
    finally:
        session.close()
    assert seen["allow"] == {"loopback"}


def test_browser_guard_checks_redirects_subresources_and_metadata():
    calls: list[str] = []

    def resolve(host, port, *args, **kwargs):
        del args, kwargs
        addresses = {
            "public.test": "1.1.1.1",
            "rebind.test": "169.254.169.254",
            "cdn.test": "10.0.0.8",
        }
        ip = addresses[host]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 80))]

    def exchange(url, pinned, timeout, user_agent, max_bytes):
        del timeout, user_agent, max_bytes
        calls.append(pinned)
        if url.startswith("http://public.test/page"):
            assert pinned == "1.1.1.1"
            return 302, {"location": "http://rebind.test/latest"}, b""
        if url.startswith("http://public.test/ok"):
            return 200, {"content-type": "text/html"}, b"<p>ok</p>"
        if url.startswith("http://10.0.0.1/"):
            return 200, {"content-type": "text/plain"}, b"priv"
        raise AssertionError(f"unexpected fetch {url} via {pinned}")

    guard = BrowserFetchGuard(frozenset(), resolve=resolve, exchange=exchange)

    redirected = _Route("http://public.test/page")
    guard.handle_route(redirected)
    assert redirected.aborted == "blockedbyclient"
    assert redirected.fulfilled is None
    assert calls == ["1.1.1.1"]
    assert guard.denied[-1][1] == "fetch_metadata"
    denial = guard.take_denial()
    assert isinstance(denial, ReadDenied)
    assert denial.code == "fetch_metadata"
    assert "rebind.test" not in str(denial)

    subresource = _Route("http://cdn.test/app.js")
    guard.handle_route(subresource)
    assert subresource.aborted == "blockedbyclient"
    assert guard.denied[-1][1] == "fetch_private"
    assert calls == ["1.1.1.1"]

    loopback = _Route("http://127.0.0.1/latest")
    guard.handle_route(loopback)
    assert loopback.aborted == "blockedbyclient"
    assert guard.denied[-1][1] == "fetch_loopback"

    link_local = _Route("http://169.254.1.1/")
    guard.handle_route(link_local)
    assert guard.denied[-1][1] == "fetch_link_local"

    opened = _Route("http://public.test/ok")
    guard.handle_route(opened)
    assert opened.aborted is None
    assert opened.fulfilled is not None
    assert opened.fulfilled["body"] == b"<p>ok</p>"

    internal = _Route("about:blank")
    guard.handle_route(internal)
    assert internal.continued is True
    assert internal.aborted is None

    local_file = _Route("file:///etc/passwd")
    guard.handle_route(local_file)
    assert local_file.aborted == "blockedbyclient"
    assert guard.denied[-1][1] == "fetch_scheme"
    assert "passwd" not in str(guard.take_denial())

    loose = BrowserFetchGuard(
        frozenset({"loopback", "private", "link_local"}),
        resolve=resolve,
        exchange=exchange,
    )
    metadata = _Route("http://169.254.169.254/latest/meta-data")
    loose.handle_route(metadata)
    assert metadata.aborted == "blockedbyclient"
    assert loose.denied[-1][1] == "fetch_metadata"
    named = _Route("http://metadata.google.internal/computeMetadata/v1/")
    loose.handle_route(named)
    assert named.aborted == "blockedbyclient"
    assert loose.denied[-1][1] == "fetch_metadata"

    allowed_private = _Route("http://10.0.0.1/a")
    loose.handle_route(allowed_private)
    assert allowed_private.aborted is None
    assert allowed_private.fulfilled is not None
    assert allowed_private.fulfilled["body"] == b"priv"

    posted = _Route("http://10.0.0.1/submit", method="POST")
    guard.handle_route(posted)
    assert posted.aborted == "blockedbyclient"
    assert posted.continued is False

    listed = BrowserFetchGuard(
        frozenset({"metadata", "loopback", "private", "link_local"}),
        exchange=exchange,
    )
    still_blocked = _Route("http://169.254.169.254/latest")
    listed.handle_route(still_blocked)
    assert still_blocked.aborted == "blockedbyclient"
    assert still_blocked.fulfilled is None
    assert listed.denied[-1][1] == "fetch_metadata"
    assert listed.fetch_allow == frozenset({"loopback", "private", "link_local"})


class _Route:
    def __init__(self, url: str, method: str = "GET") -> None:
        self.request = _Request(url, method)
        self.aborted: str | None = None
        self.continued = False
        self.fulfilled: dict[str, object] | None = None

    def abort(self, error: str) -> None:
        self.aborted = error

    def continue_(self) -> None:
        self.continued = True

    def fulfill(self, **kwargs: object) -> None:
        self.fulfilled = kwargs


class _Request:
    def __init__(self, url: str, method: str) -> None:
        self.url = url
        self.method = method
