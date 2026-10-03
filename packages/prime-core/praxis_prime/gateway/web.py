"""Static files for the local web app.

The daemon serves the built SPA from disk. There is no CDN and no inline
script. A missing build answers 404 and leaves the JSON API in place.

ARCHITECTURE §21 and §23. Addendum A §1.4 (CSP).
"""

from __future__ import annotations

import os
import re
from importlib.resources import files
from pathlib import Path

_ASSET = re.compile(r"^/assets/[A-Za-z0-9._-]{1,128}$")
_HTML = frozenset({"/", "/index.html"})
_MAX_FILE = 2 * 1024 * 1024

# Addendum A §1.4. No unsafe-inline and no unsafe-eval.
CSP = (
    "default-src 'self'; "
    "style-src 'self'; "
    "font-src 'self'; "
    "img-src 'self' data:; "
    "script-src 'self'; "
    "connect-src 'self'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "object-src 'none'"
)

_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".webp": "image/webp",
    ".woff2": "font/woff2",
    ".ico": "image/x-icon",
}


def static_route(method: str, route: str) -> bool:
    if method != "GET":
        return False
    return route in _HTML or _ASSET.fullmatch(route) is not None


def ui_root() -> Path | None:
    """Directory that contains ``index.html``, or None when the SPA is absent."""
    override = os.environ.get("PRAXIS_PRIME_UI_DIR", "").strip()
    if override:
        path = Path(override)
        if (path / "index.html").is_file():
            return path
        return None
    packaged = _packaged_root()
    if packaged is not None:
        return packaged
    return _repo_dist()


def load_asset(route: str) -> tuple[int, bytes, str] | None:
    """Return status, body, and content type for one SPA file.

    ``None`` means this route is not a static file. A missing file is 404.
    """
    if not static_route("GET", route):
        return None
    root = ui_root()
    if root is None:
        return 404, b"", "text/plain; charset=utf-8"
    relative = "index.html" if route in _HTML else route.removeprefix("/")
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        return 404, b"", "text/plain; charset=utf-8"
    if not path.is_file():
        return 404, b"", "text/plain; charset=utf-8"
    try:
        size = path.stat().st_size
    except OSError:
        return 404, b"", "text/plain; charset=utf-8"
    if size > _MAX_FILE:
        return 404, b"", "text/plain; charset=utf-8"
    try:
        body = path.read_bytes()
    except OSError:
        return 404, b"", "text/plain; charset=utf-8"
    return 200, body, _TYPES.get(path.suffix.lower(), "application/octet-stream")


def _packaged_root() -> Path | None:
    try:
        candidate = Path(str(files("praxis_prime") / "_data" / "ui"))
    except (ModuleNotFoundError, TypeError, FileNotFoundError):
        return None
    if (candidate / "index.html").is_file():
        return candidate
    return None


def _repo_dist() -> Path | None:
    """The checkout's ``ui/dist``, and no directory above that checkout.

    ``web.py`` lives at ``packages/prime-core/praxis_prime/gateway/web.py``,
    so the repo root is four parents up. A ``ui/dist`` in any other ancestor
    is not this app.
    """
    here = Path(__file__).resolve()
    if len(here.parents) <= 4:
        return None
    root = here.parents[4]
    if not (root / "pyproject.toml").is_file():
        return None
    if not (root / "packages" / "prime-core").is_dir():
        return None
    candidate = root / "ui" / "dist"
    if (candidate / "index.html").is_file():
        return candidate
    return None
