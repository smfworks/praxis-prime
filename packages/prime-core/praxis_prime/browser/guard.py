"""Request guard for browser navigation.

GET and HEAD requests, including redirects and subresources, go through
the same hop checks and DNS pin as ``web_fetch``. Other methods are
classified, then continued. Loopback, link-local, and private addresses
follow ``tools.fetch_allow``. Metadata addresses stay blocked.

ARCHITECTURE §13.2 and §16.
"""

from __future__ import annotations

import logging
from collections.abc import Collection
from urllib.parse import urlparse

from praxis_prime.policy.boundary import (
    Exchange,
    ReadDenied,
    Resolver,
    fetch_public,
    pin_destination,
)

_log = logging.getLogger(__name__)
_INTERNAL_SCHEMES = frozenset({"about", "blob", "data", "chrome", "chrome-error", "devtools"})
_BROWSER_FETCH_ALLOW = frozenset({"loopback", "private", "link_local"})


def browser_fetch_allow(fetch_allow: Collection[str]) -> frozenset[str]:
    """Classes the browser may use. Metadata is omitted."""
    return frozenset(
        str(item).strip().lower()
        for item in fetch_allow
        if str(item).strip().lower() in _BROWSER_FETCH_ALLOW
    )


class BrowserFetchGuard:
    """Classify every browser request URL before it is allowed to proceed."""

    def __init__(
        self,
        fetch_allow: Collection[str] = (),
        *,
        resolve: Resolver | None = None,
        exchange: Exchange | None = None,
    ) -> None:
        self.fetch_allow = browser_fetch_allow(fetch_allow)
        self.resolve = resolve
        self.exchange = exchange
        self.denied: list[tuple[str, str, str]] = []

    def take_denial(self) -> ReadDenied | None:
        """Return the latest denial, without the blocked URL."""
        if not self.denied:
            return None
        _url, code, message = self.denied[-1]
        return ReadDenied(message, code)

    def handle_route(self, route: object) -> None:
        """Playwright route hook. Abort a URL the boundary refuses."""
        request = getattr(route, "request", None)
        url = str(getattr(request, "url", "") or "")
        method = str(getattr(request, "method", "GET") or "GET").upper()
        scheme = urlparse(url).scheme.lower()
        try:
            if scheme in _INTERNAL_SCHEMES:
                _continue(route)
                return
            if scheme not in {"http", "https"}:
                raise ReadDenied("browser only allows http and https URLs", "fetch_scheme")
            if method in {"GET", "HEAD"}:
                self._fulfill_checked(route, url)
                return
            pin_destination(url, fetch_allow=self.fetch_allow, resolve=self.resolve)
            _continue(route)
        except ReadDenied as exc:
            self._record(url, exc)
            _abort(route)
        except Exception:
            _log.warning("browser request check failed closed")
            self.denied.append((url, "check_failed", "browser request check failed closed"))
            _abort(route)

    def _fulfill_checked(self, route: object, url: str) -> None:
        result = fetch_public(
            url,
            fetch_allow=self.fetch_allow,
            resolve=self.resolve,
            exchange=self.exchange,
            raise_for_status=False,
            user_agent="praxis-prime-browser",
        )
        fulfill = getattr(route, "fulfill", None)
        if not callable(fulfill):
            raise ReadDenied("browser request check failed closed", "check_failed")
        content_type = result.content_type or "application/octet-stream"
        fulfill(
            status=result.status,
            headers={"content-type": content_type},
            body=result.body,
        )

    def _record(self, url: str, exc: ReadDenied) -> None:
        _log.warning("browser blocked a request (%s)", exc.code)
        self.denied.append((url, exc.code, str(exc)))


def _continue(route: object) -> None:
    method = getattr(route, "continue_", None)
    if callable(method):
        method()


def _abort(route: object) -> None:
    method = getattr(route, "abort", None)
    if not callable(method):
        return
    try:
        method("blockedbyclient")
    except Exception:
        _log.warning("browser request check failed closed")
