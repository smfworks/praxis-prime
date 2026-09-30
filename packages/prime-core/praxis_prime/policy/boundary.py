"""Workspace and secret boundary for read tools.

Every read is confined to the session workspace plus paths listed in
config. A relative config entry is ignored. Secret paths stay unreadable
even inside the workspace and even when a path is explicitly allowed.

``web_fetch`` allows only http and https. Each redirect hop is checked
again, including a fresh DNS lookup, and the connection uses that
address so a later lookup cannot swap in a blocked one.

ARCHITECTURE §8, §16, and §25.
"""

from __future__ import annotations

import http.client
import ipaddress
import logging
import os
import re
import socket
import ssl
import stat
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlparse

from praxis_prime.paths import config_dir, runtime_dir

_log = logging.getLogger(__name__)

MAX_REDIRECTS = 5
_MAX_INODE_FILES = 500
_MAX_CREDENTIAL_FILES = 5_000
_MAX_SCAN_ENTRIES = 20_000
# Exact paths a symlink must not walk. ``/etc``, ``/usr``, and ``/dev`` are
# walked with the entry budget. A path that resolves to one of these, or to
# the same inode as ``/``, would scan the whole filesystem or a virtual tree.
_SKIP_SCAN_ROOTS = frozenset({"/", "/proc", "/sys"})
_FETCH_ALLOW = frozenset({"loopback", "private", "link_local", "metadata"})
_BROWSER_FETCH_ALLOW = frozenset({"loopback", "private", "link_local"})
_REDIRECT_STATUS = frozenset({300, 301, 302, 303, 307, 308})
_METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata.goog"})
_METADATA_V4 = ipaddress.ip_address("169.254.169.254")
_PROC_ENVIRON = re.compile(r"^/proc/(?:self|\d+)(?:/task/\d+)?/environ$")
_EXACT_NAMES = frozenset(
    {
        ".env",
        "secrets.env",
        "secrets.env.age",
        "credentials",
        "credentials.json",
        "credentials.yml",
        "credentials.yaml",
        "credentials.toml",
        "credentials.txt",
        "credentials.ini",
        ".credentials",
        "netrc",
        ".netrc",
        "_netrc",
        ".git-credentials",
        "git-credentials",
        "gateway.token",
        ".envrc",
        "service_account.json",
        "service-account.json",
        ".boto",
    }
)
_SERVICE_ACCOUNT_SUFFIXES = (
    "-service-account.json",
    "-service_account.json",
    "_service-account.json",
    "_service_account.json",
)
_KEY_PREFIXES = ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa")
_SOURCE_SUFFIXES = frozenset({".py", ".pyi", ".md", ".rst", ".js", ".ts", ".tsx", ".go", ".rs"})
_SECRET_DIR_PARTS = frozenset({".ssh", ".aws", ".gnupg", ".kube", ".mozilla"})
_BROWSER_CONFIG = frozenset(
    {
        "gcloud",
        "google-chrome",
        "google-chrome-beta",
        "google-chrome-unstable",
        "chromium",
        "bravesoftware",
        "microsoft-edge",
        "opera",
        "vivaldi",
    }
)
# Snap and flatpak profile trees the inode scan already walks. Flatpak keeps
# config under ``config/``, not ``.config/``. Ids are compared lowercase.
_SNAP_BROWSERS = frozenset({"chromium", "firefox"})
_FLATPAK_BROWSERS = frozenset(
    {
        "com.google.chrome",
        "org.chromium.chromium",
        "org.mozilla.firefox",
    }
)
_FLATPAK_PROFILE_DIRS = frozenset({"config", ".mozilla"})
# Browser and gcloud trees contribute these filenames, plus the denylist
# patterns. Credential directories count every file instead.
_PROFILE_SECRET_NAMES = frozenset(
    {
        "login data",
        "cookies",
        "web data",
        "local state",
        "key4.db",
        "key3.db",
        "logins.json",
        "logins-backup.json",
        "cookies.sqlite",
        "cert9.db",
        "signons.sqlite",
        "extension cookies",
        "account web data",
        "login data for account",
        "safe browsing cookies",
    }
)
_GCLOUD_SECRET_NAMES = frozenset(
    {
        "credentials.db",
        "access_tokens.db",
        "application_default_credentials.json",
    }
)
_PROFILE_SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")
_SKIP_WALK = frozenset({".git", "node_modules", ".venv", "__pycache__"})

Resolver = Callable[..., list[tuple[object, ...]]]
Exchange = Callable[[str, str, float, str, int], tuple[int, Mapping[str, str], bytes]]


class ReadDenied(ValueError):
    """A read or fetch the boundary refused. The message has no file contents."""

    def __init__(self, message: str, code: str, *, name: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.display_name = name


@dataclass(frozen=True, slots=True)
class ReadAccess:
    """Explicit exceptions. Empty means the session workspace is the only root."""

    extra_roots: tuple[str, ...] = ()
    allow_paths: tuple[str, ...] = ()
    fetch_allow: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class FetchResult:
    url: str
    content_type: str
    body: bytes
    status: int = 200


def absolute_config_paths(value: object) -> tuple[str, ...]:
    """Keep absolute config paths. Relative entries grant nothing."""
    if not isinstance(value, list):
        return ()
    kept: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        text = item.strip()
        if not text:
            continue
        expanded = Path(text).expanduser()
        if not expanded.is_absolute():
            continue
        kept.append(str(expanded))
    return tuple(kept)


def parse_fetch_allow(value: object) -> frozenset[str]:
    """Keep known fetch exception names. Anything else is ignored."""
    if not isinstance(value, list):
        return frozenset()
    return frozenset(
        item.strip().lower()
        for item in value
        if isinstance(item, str) and item.strip().lower() in _FETCH_ALLOW
    )


def browser_fetch_allow(fetch_allow: Collection[str]) -> frozenset[str]:
    """Classes the browser may use. Metadata is omitted."""
    return frozenset(
        str(item).strip().lower()
        for item in fetch_allow
        if str(item).strip().lower() in _BROWSER_FETCH_ALLOW
    )


def read_access_from_document(data: Mapping[str, object]) -> ReadAccess:
    tools = data.get("tools")
    table = tools if isinstance(tools, Mapping) else {}
    return ReadAccess(
        extra_roots=absolute_config_paths(table.get("read_roots")),
        allow_paths=absolute_config_paths(table.get("read_allow")),
        fetch_allow=parse_fetch_allow(table.get("fetch_allow")),
    )


def assess_read(
    tool: str,
    arguments: Mapping[str, object] | None,
    *,
    workspace_root: str,
    access: ReadAccess,
    cache: InodeScanCache | None = None,
) -> ReadDenied | None:
    """Return a denial for a concrete read that must not run.

    A missing path is left to the tool. Any unexpected error denies the read.
    """
    try:
        return _assess_read(
            tool,
            arguments,
            workspace_root=workspace_root,
            access=access,
            cache=cache,
        )
    except ReadDenied as exc:
        return exc
    except Exception:
        return ReadDenied("read boundary check failed closed", "check_failed")


def confine_path(raw: str, *, cwd: str, access: ReadAccess) -> Path:
    """Resolve ``raw`` and require the real path to stay in a configured root."""
    if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
        raise ReadDenied("path is outside the workspace", "outside_workspace")
    roots = workspace_roots(cwd, access)
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = roots[0] / candidate
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ReadDenied("path is outside the workspace", "outside_workspace") from exc
    if not _inside_any(resolved, roots):
        raise ReadDenied("path is outside the workspace", "outside_workspace")
    return resolved


def workspace_roots(cwd: str, access: ReadAccess) -> tuple[Path, ...]:
    try:
        primary = Path(cwd).resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ReadDenied("workspace root could not be resolved", "outside_workspace") from exc
    if not primary.is_absolute():
        raise ReadDenied("workspace root could not be resolved", "outside_workspace")
    roots = [primary]
    for extra in (*access.extra_roots, *access.allow_paths):
        resolved = _absolute_root(extra)
        if resolved is not None:
            roots.append(resolved)
    return tuple(roots)


def is_secret_path(path: Path) -> bool:
    """True when ``path`` matches the shared secret denylist. Errors deny."""
    try:
        return _is_secret_path(path)
    except Exception:
        return True


def inode_is_secret(
    path: Path,
    inodes: set[tuple[int, int]] | None = None,
    cache: InodeScanCache | None = None,
) -> bool:
    """True when ``path`` is a hard link to a known secret file."""
    try:
        st = path.stat(follow_symlinks=True)
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return False
    known = secret_inode_set(cache) if inodes is None else inodes
    return (st.st_dev, st.st_ino) in known


class InodeScanCache:
    """One loop's inode scan. The loop owns it and passes it on each policy call.

    A finished scan may be reused across read-only tools in that loop. The
    loop clears it at the start of a turn and after any tool that can write,
    so a set from before that write cannot allow a read a fresh scan would
    deny. ``found`` is published before ``ready``.
    """

    def __init__(self) -> None:
        self.ready = False
        self.found: set[tuple[int, int]] | None = None
        self.error: ReadDenied | None = None

    def clear(self) -> None:
        self.ready = False
        self.found = None
        self.error = None


def secret_inode_set(cache: InodeScanCache | None = None) -> set[tuple[int, int]]:
    """Inodes of well-known secret files, so a hard link can be recognized.

    Credential directories contribute every file except ``.kube/cache`` and
    ``.kube/http-cache`` directly under ``.kube``. Browser and gcloud trees
    contribute secret-named files. A root that cannot be finished denies the
    read. ``cache`` reuses one scan until the loop clears it. ``found`` is
    published before ``ready``.
    """
    if cache is not None and cache.ready:
        if cache.error is not None:
            raise cache.error
        if cache.found is None:
            return set()
        return cache.found
    try:
        found = _scan_secret_inodes()
    except ReadDenied as exc:
        if cache is not None:
            cache.error = exc
            cache.ready = True
        raise
    if cache is not None:
        cache.found = found
        cache.ready = True
    return found


def _scan_secret_inodes() -> set[tuple[int, int]]:
    found: set[tuple[int, int]] = set()
    for path in _inode_candidates():
        hit = _collect_inodes(path, found)
        if hit is not None:
            limit, kind = hit
            _refuse_capped_inode_scan(limit, kind)
    return found


def assert_readable(
    path: Path,
    *,
    requested: Path | None = None,
    cache: InodeScanCache | None = None,
) -> None:
    """Refuse secret names and hard links. The message names the file only."""
    target = requested if requested is not None else path
    if is_secret_path(target) or is_secret_path(path) or inode_is_secret(path, cache=cache):
        raise ReadDenied(
            f"refusing to read secret file {target.name}",
            "secret_path",
            name=target.name,
        )


def read_confined_bytes(
    path: Path,
    *,
    cwd: str,
    access: ReadAccess,
    limit: int,
    cache: InodeScanCache | None = None,
) -> bytes:
    """Open a confined regular file and read at most ``limit`` + 1 bytes."""
    roots = workspace_roots(cwd, access)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ReadDenied("path is outside the workspace", "outside_workspace") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ReadDenied("refusing to read a non-regular file", "outside_workspace")
        if (st.st_dev, st.st_ino) in secret_inode_set(cache):
            raise ReadDenied(
                f"refusing to read secret file {path.name}",
                "secret_path",
                name=path.name,
            )
        fd_path = _fd_realpath(fd)
        if not _inside_any(fd_path, roots):
            raise ReadDenied("path is outside the workspace", "outside_workspace")
        return os.read(fd, limit + 1)
    finally:
        os.close(fd)


def readable_file(
    path: Path,
    *,
    cwd: str,
    access: ReadAccess,
    inodes: set[tuple[int, int]],
) -> bool:
    """False when a search result is secret, outside the workspace, or unsafe."""
    if any(part in _SKIP_WALK for part in path.parts):
        return False
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return False
    try:
        roots = workspace_roots(cwd, access)
    except ReadDenied:
        return False
    if not _inside_any(resolved, roots):
        return False
    if is_secret_path(path) or is_secret_path(resolved) or inode_is_secret(resolved, inodes):
        return False
    try:
        st = path.stat(follow_symlinks=True)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode)


def classify_url(url: str, fetch_allow: Collection[str] = ()) -> str:
    """Refuse a URL that is not a public http(s) target. Returns the URL.

    Hostnames are not resolved here. ``pin_destination`` resolves each hop.
    """
    parsed = _parse_fetch_url(url)
    host = _hostname(parsed)
    _refuse_hostname(host, fetch_allow)
    literal = _literal_ip(host)
    if literal is not None:
        _require_allowed(literal, fetch_allow)
    return url.strip()


def pin_destination(
    url: str,
    *,
    fetch_allow: Collection[str] = (),
    resolve: Resolver | None = None,
) -> str:
    """Return the IP to connect to after this hop's DNS answers are checked."""
    parsed = _parse_fetch_url(url)
    host = _hostname(parsed)
    _refuse_hostname(host, fetch_allow)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    literal = _literal_ip(host)
    if literal is not None:
        _require_allowed(literal, fetch_allow)
        return str(literal)
    resolver = resolve or socket.getaddrinfo
    try:
        infos = resolver(host, port, type=socket.SOCK_STREAM)
    except ReadDenied:
        raise
    except Exception as exc:
        raise ReadDenied("web_fetch could not resolve the host", "fetch_unresolved") from exc
    pinned = ""
    for info in infos:
        try:
            address = str(info[4][0]).split("%", 1)[0]
        except (IndexError, TypeError) as exc:
            raise ReadDenied("web_fetch could not resolve the host", "fetch_unresolved") from exc
        ip = _literal_ip(address)
        if ip is None:
            raise ReadDenied("web_fetch could not resolve the host", "fetch_unresolved")
        _require_allowed(ip, fetch_allow)
        if not pinned:
            pinned = str(ip)
    if not pinned:
        raise ReadDenied("web_fetch could not resolve the host", "fetch_unresolved")
    return pinned


def fetch_public(
    url: str,
    *,
    fetch_allow: Collection[str] = (),
    max_bytes: int = 1_000_000,
    user_agent: str = "praxis-prime",
    resolve: Resolver | None = None,
    exchange: Exchange | None = None,
    max_redirects: int = MAX_REDIRECTS,
    raise_for_status: bool = True,
) -> FetchResult:
    """GET ``url``, re-checking scheme, address class, and DNS on every hop."""
    current = url.strip()
    opener = exchange or _exchange
    followed = 0
    while True:
        pinned = pin_destination(current, fetch_allow=fetch_allow, resolve=resolve)
        try:
            status, headers, body = opener(current, pinned, 20, user_agent, max_bytes)
        except ReadDenied:
            raise
        except Exception as exc:
            raise RuntimeError(f"could not fetch {current}: {exc}") from exc
        if status in _REDIRECT_STATUS:
            followed += 1
            if followed > max_redirects:
                raise ReadDenied("web_fetch refused too many redirects", "fetch_redirect")
            location = str(headers.get("location", "")).strip()
            if not location:
                raise ReadDenied("web_fetch redirect is missing a location", "fetch_redirect")
            current = urljoin(current, location)
            continue
        if status >= 400 and raise_for_status:
            detail = body[:500].decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {status} for {current}: {detail[:200]}")
        content_type = str(headers.get("content-type", ""))
        return FetchResult(
            url=current,
            content_type=content_type,
            body=body,
            status=status,
        )


def _assess_read(
    tool: str,
    arguments: Mapping[str, object] | None,
    *,
    workspace_root: str,
    access: ReadAccess,
    cache: InodeScanCache | None = None,
) -> ReadDenied | None:
    if tool == "web_fetch":
        if not arguments or "url" not in arguments:
            return None
        raw = arguments.get("url")
        if not isinstance(raw, str):
            return ReadDenied("web_fetch requires a url", "fetch_scheme")
        pin_destination(raw, fetch_allow=access.fetch_allow)
        return None
    if tool == "browser":
        if not arguments:
            return None
        raw = arguments.get("url")
        if not isinstance(raw, str) or not raw.strip():
            return None
        classify_url(raw, browser_fetch_allow(access.fetch_allow))
        return None
    if tool not in {"read_file", "list_dir", "grep", "glob"}:
        return None
    if arguments is None:
        return None
    if tool == "read_file":
        raw_path = arguments.get("path")
        if not isinstance(raw_path, str) or not raw_path.strip():
            return None
    else:
        raw_path = arguments.get("path", ".")
        if not isinstance(raw_path, str) or not raw_path.strip():
            raw_path = "."
    if not workspace_root and not access.extra_roots and not access.allow_paths:
        return ReadDenied("no workspace root configured", "outside_workspace")
    requested = Path(raw_path)
    resolved = confine_path(raw_path, cwd=workspace_root or ".", access=access)
    assert_readable(
        resolved,
        requested=requested if requested.name else resolved,
        cache=cache,
    )
    return None


def _is_secret_path(path: Path) -> bool:
    if _name_is_secret(path.name) or _components_secret(path.parts) or _special_file(path):
        return True
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return True
    if resolved == path:
        return False
    return (
        _name_is_secret(resolved.name)
        or _components_secret(resolved.parts)
        or _special_file(resolved)
    )


def _name_is_secret(name: str) -> bool:
    lower = name.lower()
    if lower in _EXACT_NAMES or lower.startswith(".env."):
        return True
    if lower.endswith(_SERVICE_ACCOUNT_SUFFIXES):
        return True
    if lower.endswith((".pem", ".key", ".keyring", ".p12", ".pfx")):
        return True
    if lower.startswith(_KEY_PREFIXES):
        return True
    if "credential" in lower:
        return Path(lower).suffix not in _SOURCE_SUFFIXES
    return False


def _components_secret(parts: Sequence[str]) -> bool:
    lower = tuple(part.lower() for part in parts)
    if any(part in _SECRET_DIR_PARTS for part in lower):
        return True
    for index, part in enumerate(lower):
        nxt = lower[index + 1] if index + 1 < len(lower) else ""
        if part == ".docker" and nxt == "config.json":
            return True
        if part == ".config" and nxt in _BROWSER_CONFIG:
            return True
        if part == "snap" and nxt in _SNAP_BROWSERS:
            return True
        if _flatpak_profile(lower, index):
            return True
        if part == ".local" and nxt == "share" and "keyrings" in lower[index + 2 :]:
            return True
    return False


def _flatpak_profile(parts: Sequence[str], index: int) -> bool:
    """True for ``.var/app/<id>/config`` and ``.var/app/<id>/.mozilla``."""
    if index + 3 >= len(parts):
        return False
    if parts[index] != ".var" or parts[index + 1] != "app":
        return False
    if parts[index + 2] not in _FLATPAK_BROWSERS:
        return False
    return parts[index + 3] in _FLATPAK_PROFILE_DIRS


def _special_file(path: Path) -> bool:
    posix = path.as_posix()
    if posix == "/etc/shadow":
        return True
    return _PROC_ENVIRON.match(posix) is not None


def _inode_candidates() -> list[Path]:
    home = Path.home()
    config = home / ".config"
    paths = [
        home / ".ssh",
        home / ".aws",
        config / "gcloud",
        home / ".kube",
        home / ".gnupg",
        home / ".local" / "share" / "keyrings",
        home / ".mozilla",
        config / "google-chrome",
        config / "google-chrome-beta",
        config / "google-chrome-unstable",
        config / "chromium",
        config / "BraveSoftware",
        config / "microsoft-edge",
        config / "vivaldi",
        config / "opera",
        home / "snap" / "chromium" / "common" / "chromium",
        home / "snap" / "firefox" / "common" / ".mozilla",
        home / ".var" / "app" / "com.google.Chrome" / "config" / "google-chrome",
        home / ".var" / "app" / "org.chromium.Chromium" / "config" / "chromium",
        home / ".var" / "app" / "org.mozilla.firefox" / ".mozilla",
        home / ".netrc",
        home / ".boto",
        home / ".git-credentials",
        home / ".docker" / "config.json",
        Path("/etc/shadow"),
    ]
    try:
        paths.append(runtime_dir() / "gateway.token")
        paths.append(config_dir() / "secrets.env")
        paths.append(config_dir() / "secrets.env.age")
    except OSError:
        pass
    return paths


def _profile_file_is_secret(name: str) -> bool:
    """True for denylist names and known browser credential files."""
    if _name_is_secret(name):
        return True
    lower = name.lower()
    if lower in _PROFILE_SECRET_NAMES or lower.startswith("sessionstore"):
        return True
    for suffix in _PROFILE_SIDECAR_SUFFIXES:
        if lower.endswith(suffix) and lower[: -len(suffix)] in _PROFILE_SECRET_NAMES:
            return True
    return False


_CREDENTIAL_ROOTS = frozenset({".ssh", ".aws", ".gnupg", ".kube", "keyrings"})
_KUBE_SKIP_DIRS = frozenset({"cache", "http-cache"})


def _inode_file_is_secret(name: str, directory: Path) -> bool:
    """True when this filename is a secret candidate under a named root."""
    if _profile_file_is_secret(name):
        return True
    lower = name.lower()
    if lower in _GCLOUD_SECRET_NAMES:
        return True
    parts = tuple(part.lower() for part in directory.parts)
    return "legacy_credentials" in parts


def _scan_mode(path: Path) -> str:
    """Credential dirs count every file. Browser and gcloud roots match names."""
    if path.name.lower() in _CREDENTIAL_ROOTS:
        return "all"
    return "named"


def _prune_scan_dirs(
    dirnames: list[str],
    directory: Path,
    kube_root: Path | None,
) -> None:
    """Skip symlink children. Skip kube cache dirs only as direct children."""
    direct_kube = kube_root is not None and _same_dir(directory, kube_root)
    kept: list[str] = []
    for name in dirnames:
        child = directory / name
        if child.is_symlink():
            continue
        if direct_kube and name.lower() in _KUBE_SKIP_DIRS:
            continue
        kept.append(name)
    dirnames[:] = kept


def _same_dir(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(os.path.abspath(right))


def _refuse_capped_inode_scan(limit: int, kind: str) -> None:
    message = (
        f"secret inode scan hit the {limit} {kind} cap; "
        "denying the read because a secret file could have been missed"
    )
    _log.warning(message)
    raise ReadDenied(message, "inode_scan_capped")


def _inside_home(path: Path, home: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(home.resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def _is_unbounded_scan_root(path: Path) -> bool:
    """True when a walk would be ``/``, ``/proc``, ``/sys``, or the same inode as ``/``.

    ``/etc``, ``/usr``, and ``/dev`` are walked with the entry budget. A path
    that resolves to ``/`` (for example ``/etc/..``) is the whole filesystem
    and is skipped. A resolve failure skips the root.
    """
    try:
        posix = path.resolve(strict=False).as_posix()
    except (OSError, RuntimeError, ValueError):
        return True
    if posix in _SKIP_SCAN_ROOTS:
        return True
    try:
        root_stat = os.stat("/")
        here = os.stat(posix)
    except OSError:
        return False
    return (here.st_dev, here.st_ino) == (root_stat.st_dev, root_stat.st_ino)


def _resolve_scan_root(path: Path) -> tuple[Path, bool] | None:
    """Return the path to scan, and whether the walk has an entry budget.

    A top-level symlink is followed in the same mode as the link name.
    ``/``, ``/proc``, and ``/sys`` are skipped. ``/etc``, ``/usr``, and
    ``/dev`` are walked with ``_MAX_SCAN_ENTRIES``, as is any other symlink
    outside ``$HOME``. A symlink that resolves to ``$HOME`` itself uses that
    budget too, so ``~/.ssh -> $HOME`` does not walk the home directory
    without a cap.
    """
    try:
        if not path.is_symlink():
            return path, False
        resolved = path.resolve(strict=False)
        if _is_unbounded_scan_root(resolved):
            return None
        return resolved, _scan_root_needs_budget(resolved, Path.home())
    except (OSError, RuntimeError, ValueError):
        return None


def _scan_root_needs_budget(resolved: Path, home: Path) -> bool:
    """True for a symlink outside ``$HOME`` or one that resolves to ``$HOME``."""
    if not _inside_home(resolved, home):
        return True
    return _same_resolved(resolved, home)


def _same_resolved(left: Path, right: Path) -> bool:
    try:
        return os.path.normcase(str(left.resolve(strict=False))) == os.path.normcase(
            str(right.resolve(strict=False))
        )
    except (OSError, RuntimeError, ValueError):
        return False


def _file_counts(name: str, directory: Path, mode: str) -> bool:
    if mode == "all":
        return True
    return _inode_file_is_secret(name, directory)


def _collect_inodes(
    path: Path, found: set[tuple[int, int]]
) -> tuple[int, str] | None:
    """Scan one candidate. Return ``(limit, kind)`` when a candidate was skipped."""
    resolved = _resolve_scan_root(path)
    if resolved is None:
        return None
    root, budget_entries = resolved
    mode = _scan_mode(path)
    if mode == "all" and budget_entries and _same_resolved(root, Path.home()):
        # Counting every file under $HOME trips the credential cap and marks
        # ordinary files secret. Keep the entry budget; record secret names.
        mode = "named"
    cap = _MAX_CREDENTIAL_FILES if mode == "all" else _MAX_INODE_FILES
    kube_root = root if path.name.lower() == ".kube" else None
    try:
        if root.is_file():
            _add_inode(root, found, 0)
            return None
        if not root.is_dir():
            return None
    except OSError:
        return None
    try:
        walker = os.walk(root, followlinks=False)
    except OSError:
        return None
    count = 0
    entries = 0
    budget = _MAX_SCAN_ENTRIES if budget_entries else None
    for dirpath, dirnames, filenames in walker:
        directory = Path(dirpath)
        _prune_scan_dirs(dirnames, directory, kube_root)
        if budget is not None:
            entries += len(dirnames) + len(filenames)
            if entries > budget:
                return budget, "directory-entry"
        for name in filenames:
            if not _file_counts(name, directory, mode):
                continue
            if count >= cap:
                return cap, "secret-file"
            count = _add_inode(directory / name, found, count)
    return None


def _add_inode(path: Path, found: set[tuple[int, int]], count: int) -> int:
    try:
        st = path.stat(follow_symlinks=True)
    except OSError:
        return count
    if stat.S_ISREG(st.st_mode):
        found.add((st.st_dev, st.st_ino))
        return count + 1
    return count


def _absolute_root(raw: str) -> Path | None:
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        return None
    try:
        return candidate.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return None


def _inside_any(path: Path, roots: Sequence[Path]) -> bool:
    for root in roots:
        try:
            path.relative_to(root)
        except ValueError:
            continue
        return True
    return False


def _fd_realpath(fd: int) -> Path:
    try:
        target = os.readlink(f"/proc/self/fd/{fd}")
    except OSError as exc:
        raise ReadDenied("path is outside the workspace", "outside_workspace") from exc
    if target.endswith(" (deleted)"):
        target = target[: -len(" (deleted)")]
    try:
        return Path(target).resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ReadDenied("path is outside the workspace", "outside_workspace") from exc


def _parse_fetch_url(url: str):
    if not isinstance(url, str) or not url.strip() or any(ch in url for ch in "\r\n\x00"):
        raise ReadDenied("web_fetch only allows http and https URLs", "fetch_scheme")
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise ReadDenied("web_fetch only allows http and https URLs", "fetch_scheme")
    if parsed.username is not None or parsed.password is not None:
        raise ReadDenied("web_fetch refuses URLs with userinfo", "fetch_scheme")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ReadDenied("web_fetch refuses that port", "fetch_scheme")
    if not _hostname(parsed):
        raise ReadDenied("web_fetch requires a host", "fetch_scheme")
    return parsed


def _hostname(parsed: object) -> str:
    host = getattr(parsed, "hostname", None) or ""
    return str(host).strip().lower().rstrip(".")


def _refuse_hostname(host: str, fetch_allow: Collection[str]) -> None:
    allowed = {item.strip().lower() for item in fetch_allow}
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
        if "loopback" not in allowed:
            raise ReadDenied("web_fetch refuses loopback hosts", "fetch_loopback")
    if host in _METADATA_HOSTS or host.endswith(".metadata.google.internal"):
        if "metadata" not in allowed:
            raise ReadDenied("refusing cloud metadata host", "fetch_metadata")


def _require_allowed(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    fetch_allow: Collection[str],
) -> None:
    kind = _address_class(ip)
    if kind == "public":
        return
    allowed = {item.strip().lower() for item in fetch_allow}
    if kind not in allowed:
        if kind == "metadata":
            raise ReadDenied("refusing cloud metadata host", "fetch_metadata")
        if kind == "loopback":
            raise ReadDenied("web_fetch refuses loopback addresses", "fetch_loopback")
        if kind == "link_local":
            raise ReadDenied("web_fetch refuses link-local addresses", "fetch_link_local")
        raise ReadDenied("web_fetch refuses private addresses", "fetch_private")


def _address_class(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip == _METADATA_V4:
        return "metadata"
    if ip.is_loopback or ip.is_unspecified:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_private or not ip.is_global:
        return "private"
    return "public"


def _literal_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    text = host.strip().strip("[]")
    if not text:
        return None
    try:
        return ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        pass
    return _ipv4_literal(text)


def _ipv4_literal(host: str) -> ipaddress.IPv4Address | None:
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    if not all(re.fullmatch(r"0x[0-9a-fA-F]+|\d+", part) for part in parts):
        return None
    try:
        numbers = [_ipv4_number(part) for part in parts]
    except ValueError:
        return None
    if len(numbers) == 1:
        value = numbers[0]
    elif len(numbers) == 2:
        if numbers[0] > 0xFF or numbers[1] > 0xFFFFFF:
            return None
        value = (numbers[0] << 24) | numbers[1]
    elif len(numbers) == 3:
        if numbers[0] > 0xFF or numbers[1] > 0xFF or numbers[2] > 0xFFFF:
            return None
        value = (numbers[0] << 24) | (numbers[1] << 16) | numbers[2]
    else:
        if any(number > 0xFF for number in numbers):
            return None
        value = (numbers[0] << 24) | (numbers[1] << 16) | (numbers[2] << 8) | numbers[3]
    if value > 0xFFFFFFFF:
        return None
    return ipaddress.IPv4Address(value)


def _ipv4_number(token: str) -> int:
    if token.lower().startswith("0x"):
        return int(token, 16)
    if len(token) > 1 and token.startswith("0") and token.isdigit():
        return int(token, 8)
    return int(token, 10)


def _exchange(
    url: str,
    pinned: str,
    timeout: float,
    user_agent: str,
    max_bytes: int,
) -> tuple[int, dict[str, str], bytes]:
    parsed = urlparse(url)
    host = _hostname(parsed)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    header_host = _host_header(host, port, parsed.scheme)
    conn = _connection(parsed.scheme, host, port, pinned, timeout)
    try:
        conn.request(
            "GET",
            path,
            headers={
                "Host": header_host,
                "User-Agent": user_agent,
                "Accept": "*/*",
                "Connection": "close",
            },
        )
        response = conn.getresponse()
        headers = {key.lower(): value for key, value in response.headers.items()}
        body = response.read(max_bytes + 1)
        return response.status, headers, body
    finally:
        conn.close()


def _connection(
    scheme: str,
    host: str,
    port: int,
    pinned: str,
    timeout: float,
) -> http.client.HTTPConnection:
    raw = socket.create_connection((pinned, port), timeout=timeout)
    try:
        if scheme == "https":
            tls = ssl.create_default_context().wrap_socket(raw, server_hostname=host or None)
            secure = http.client.HTTPSConnection(host or pinned, port, timeout=timeout)
            secure.sock = tls
            return secure
        plain = http.client.HTTPConnection(pinned, port, timeout=timeout)
        plain.sock = raw
        return plain
    except Exception:
        raw.close()
        raise


def _host_header(host: str, port: int, scheme: str) -> str:
    default = 443 if scheme == "https" else 80
    display = f"[{host}]" if ":" in host else host
    if port == default:
        return display
    return f"{display}:{port}"
