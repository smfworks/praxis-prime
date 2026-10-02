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

import contextvars
import errno
import glob
import http.client
import ipaddress
import logging
import os
import re
import shlex
import socket
import ssl
import stat
import threading
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlparse

from praxis_prime.paths import config_dir, data_dir, runtime_dir
from praxis_prime.statfile import StatKind, lstat_kind, stat_kind

_log = logging.getLogger(__name__)

MAX_REDIRECTS = 5
_MAX_CREDENTIAL_FILES = 5_000
_MAX_SCAN_ENTRIES = 20_000
# IndexedDB and Extensions sit outside the disk-cache skip, and a used Chrome
# or Firefox profile often holds more than ``_MAX_SCAN_ENTRIES`` files there
# (leveldb tables, extension scripts, locales). Browser roots use this larger
# budget so those profiles stay readable. Overflow still fails every read
# closed. Symlinks, including ``~/.ssh`` -> a profile, ``/usr``, or ``$HOME``,
# stay on ``_MAX_SCAN_ENTRIES``.
_MAX_BROWSER_SCAN_ENTRIES = 200_000
# Names examined under skipped cache directories, per scan root. A stock
# Firefox cache2 is about 20_000 files, and Chrome adds Cache, Code Cache,
# and GPUCache. This pass records secret names at any depth and does not
# charge non-secret names to the directory-entry budget. Crossing the cap
# fails every read closed.
_MAX_CACHE_NAME_ENTRIES = 500_000
# Exact paths a symlink must not walk. ``/etc``, ``/usr``, and ``/dev`` are
# walked with the entry budget. A path that resolves to one of these, or to
# the same inode as ``/``, would scan the whole filesystem or a virtual tree.
_SKIP_SCAN_ROOTS = frozenset({"/", "/proc", "/sys"})
# ``~/.var/app/*/data/keyrings`` is one scan root per Flatpak app. Each root
# would otherwise get its own credential-file cap, so a long app list walks
# without a shared limit. More matches than this fail the scan closed. The
# matches that are kept share ``_MAX_SCAN_ENTRIES`` for the whole scan.
_MAX_FLATPAK_KEYRING_ROOTS = 64
# A directory that vanishes or is replaced while Chrome rewrites IndexedDB
# or ``blob_storage``. Other listing failures, including EACCES and EPERM,
# still fail the scan closed.
_IGNORED_LISTING_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR})
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


@dataclass(frozen=True, slots=True)
class _BrowserProfile:
    """One browser tree shared by direct reads and the inode scan.

    ``scan`` is the directory the inode walk covers, relative to ``$HOME``.
    ``deny`` is the direct-read prefix, also relative to ``$HOME``. ``scan``
    is ``deny`` or a directory under it, so the two cannot name different trees.
    """

    scan: tuple[str, ...]
    deny: tuple[str, ...]


def _profile(
    scan: tuple[str, ...], deny: tuple[str, ...] | None = None
) -> _BrowserProfile:
    prefix = scan if deny is None else deny
    if scan[: len(prefix)] != prefix:
        raise ValueError(f"inode scan {scan} is outside direct-read prefix {prefix}")
    return _BrowserProfile(scan=scan, deny=prefix)


# Native ``~/.config`` names use their on-disk spelling. Snap rows scan and
# deny the whole ``snap/<app>`` tree: Brave, Vivaldi, and Opera keep the
# profile at ``<rev>/.config/<name>/``, and ``current`` is a symlink to that
# revision. Chromium and Firefox profiles under ``common/`` are inside the
# same prefix. Flatpak Chromium-family rows scan and deny the whole
# ``config/`` tree. Chrome beta, Brave beta/nightly, Thorium, and Vivaldi
# snapshot are not published Flatpak app IDs. Chrome Dev and Ungoogled
# Chromium (current and legacy ids) are. ``~/.var/app/*/data/keyrings`` is
# denied and scanned separately.
_BROWSER_PROFILES: tuple[_BrowserProfile, ...] = (
    _profile((".config", "gcloud")),
    _profile((".config", "google-chrome")),
    _profile((".config", "google-chrome-beta")),
    _profile((".config", "google-chrome-unstable")),
    _profile((".config", "chromium")),
    _profile((".config", "chromium-browser")),
    _profile((".config", "BraveSoftware")),
    _profile((".config", "microsoft-edge")),
    _profile((".config", "microsoft-edge-beta")),
    _profile((".config", "microsoft-edge-dev")),
    _profile((".config", "opera")),
    _profile((".config", "opera-beta")),
    _profile((".config", "vivaldi")),
    _profile((".config", "vivaldi-snapshot")),
    _profile(("snap", "chromium")),
    _profile(("snap", "firefox")),
    _profile(("snap", "brave")),
    _profile(("snap", "opera")),
    _profile(("snap", "vivaldi")),
    _profile((".var", "app", "com.google.Chrome", "config")),
    _profile((".var", "app", "com.google.ChromeDev", "config")),
    _profile((".var", "app", "org.chromium.Chromium", "config")),
    _profile(
        (".var", "app", "io.github.ungoogled_software.ungoogled_chromium", "config")
    ),
    _profile((".var", "app", "com.github.Eloston.UngoogledChromium", "config")),
    _profile((".var", "app", "org.mozilla.firefox", ".mozilla")),
    _profile((".var", "app", "org.mozilla.firefox", "config")),
    _profile((".var", "app", "com.brave.Browser", "config")),
    _profile((".var", "app", "com.microsoft.Edge", "config")),
    _profile((".var", "app", "com.opera.Opera", "config")),
    _profile((".var", "app", "com.vivaldi.Vivaldi", "config")),
)
_BROWSER_CONFIG = frozenset(
    profile.deny[1].lower()
    for profile in _BROWSER_PROFILES
    if profile.deny[0] == ".config" and len(profile.deny) == 2
)
_HOME_BROWSER_PREFIXES = tuple(
    tuple(part.lower() for part in profile.deny)
    for profile in _BROWSER_PROFILES
    if profile.deny[0] in {"snap", ".var"}
)
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
# Disk-cache directory names skipped inside a real browser scan root. The match
# is case-insensitive (``Cache`` and ``CACHE``). Chrome stores these beside
# Login Data / Cookies. Firefox stores them beside logins.json / key4.db.
# gcloud is not skipped: its ``cache/`` tree stays on the named walk. A
# name-only pass still records secret-named files at any depth under a skipped
# directory. Non-secret cache entries do not use the directory-entry budget.
_BROWSER_CACHE_DIRS = frozenset(
    {
        ".cache",
        "cache",
        "cache2",
        "code cache",
        "gpucache",
        "media cache",
        "shadercache",
        "grshadercache",
        "dawncache",
        "dawnwebgpucache",
        "dawngraphitecache",
        "startupcache",
        "offlinecache",
        "shader-cache",
        "jumplistcache",
        "scriptcache",
        "cachestorage",
    }
)

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
    if inodes is None:
        inodes = _load_secret_scan(cache)
    return (st.st_dev, st.st_ino) in inodes


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


def secret_scan(cache: InodeScanCache | None = None) -> set[tuple[int, int]]:
    """Inodes of well-known secret files from one finished scan."""
    return _load_secret_scan(cache)


def secret_inode_set(cache: InodeScanCache | None = None) -> set[tuple[int, int]]:
    """Inodes of well-known secret files, so a hard link can be recognized.

    Credential directories contribute every file except ``.kube/cache`` and
    ``.kube/http-cache`` directly under ``.kube``. Browser and gcloud trees
    contribute every secret-named file, with no secret-file count cap.
    Browser disk-cache directories are not descended into. A root that cannot
    be finished under the entry budget, or a credential directory that hits
    the credential-file cap, denies every read. A directory that disappears
    during the walk is skipped. A directory that cannot be listed denies
    every read and names that path. ``cache`` reuses one scan until the loop
    clears it. ``found`` is published before ``ready``.
    """
    return _load_secret_scan(cache)


def _load_secret_scan(cache: InodeScanCache | None) -> set[tuple[int, int]]:
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
    candidates = _inode_candidates()
    if isinstance(candidates, _CapHit):
        _refuse_capped_inode_scan(candidates.limit, candidates.kind, candidates.path)
    keyring_roots = [path for path in candidates if _is_flatpak_keyring_dir(path)]
    if len(keyring_roots) > _MAX_FLATPAK_KEYRING_ROOTS:
        _refuse_capped_inode_scan(
            _MAX_FLATPAK_KEYRING_ROOTS,
            "keyring-root",
            str(Path.home() / ".var" / "app"),
        )
    shared = _SharedEntries()
    share_with = {os.path.normcase(os.path.abspath(path)) for path in keyring_roots}
    for path in candidates:
        key = os.path.normcase(os.path.abspath(path))
        hit = _collect_inodes(path, found, shared if key in share_with else None)
        if hit is not None:
            _refuse_capped_inode_scan(hit.limit, hit.kind, hit.path)
    return found


def assert_readable(
    path: Path,
    *,
    requested: Path | None = None,
    cache: InodeScanCache | None = None,
) -> None:
    """Refuse secret names and hard links. The message names the file only.

    An account-data tree that cannot be scanned does not make every other
    file a secret. A path inside that tree gets its own error.
    """
    target = requested if requested is not None else path
    reason = _data_scan_problem(target) or _data_scan_problem(path)
    if reason:
        raise ReadDenied(
            f"could not scan the account data directory: {reason}",
            "data_dir_unscanned",
            name=target.name,
        )
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
        found = _load_secret_scan(cache)
        if (st.st_dev, st.st_ino) in found:
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


def private_data_command(command: str, workspace: Path) -> bool:
    """True when a shell command names account or profile data.

    Quotes are parsed with ``shlex`` and ``punctuation_chars``, so ``;`` and
    ``&&`` split even when they are not surrounded by spaces. ``cd`` changes
    the directory later tokens are judged against, and globs are expanded on
    the filesystem. A ``cd`` whose target stays inside ``workspace`` is
    allowed, including a coding worktree that lives under the data directory.
    A ``cd`` that leaves that workspace and enters the data directory is
    refused. ``cd -`` fails closed. A recursive reader (``grep -r``,
    ``rg``, ``git grep``, ``ag``, ``ack``, ``find -exec``, ``tar``, ``cp -r``,
    ``rsync``, ``zip -r``) is refused when a path it walks contains the data
    directory. Every root ``account_data_present`` considers is checked, so
    ``--data-dir`` does not leave the default XDG tree off the denylist.

    ``pushd`` and ``popd`` are not tracked. The bubblewrap tmpfs over each
    of those roots is the control that hides them; this walk is defence in
    depth and only follows ``cd``. Without bubblewrap, host shell is refused
    outright once account data exists.
    """
    roots = _account_data_roots()
    if not roots:
        return True
    for root in roots:
        if str(root) in command:
            return True
    try:
        tokens = _shell_tokens(command)
    except ValueError:
        return True
    return any(_command_reaches_data(tokens, workspace, root) for root in roots)


def account_data_present() -> bool:
    """True when the data directory holds accounts, profiles, or their files.

    A missing or empty data directory is a fresh install. Host shell is
    allowed only in that case, and only when bubblewrap is unavailable.
    ``--data-dir`` does not hide account data in the default XDG directory:
    both are checked.
    """
    root = _data_root()
    if root is None:
        return True
    if _directory_has_account_data(root):
        return True
    default = _xdg_data_root()
    if default is None:
        return True
    if default == root:
        return False
    return _directory_has_account_data(default)


def _account_data_roots() -> list[Path] | None:
    """Every directory ``account_data_present`` considers.

    ``None`` means a path could not be resolved. Callers fail closed.
    The override and the default XDG directory are both returned when
    they differ, so ``--data-dir`` cannot leave the default tree unmasked.
    """
    primary = _data_root()
    if primary is None:
        return None
    default = _xdg_data_root()
    if default is None:
        return None
    if default == primary:
        return [primary]
    return [primary, default]


def _xdg_data_root() -> Path | None:
    try:
        return Path(data_dir()).resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return None


def _directory_has_account_data(root: Path) -> bool:
    kind = lstat_kind(root)
    if kind is StatKind.MISSING:
        return False
    if kind is not StatKind.DIR:
        return True
    for name in ("accounts.db", "profiles", "backups", "prime.db", "audit.db", "SOUL.md"):
        if lstat_kind(root / name) is not StatKind.MISSING:
            return True
    try:
        children = list(root.iterdir())
    except OSError:
        return True
    return any(child.name.startswith("accounts.db") for child in children)


def _shell_tokens(command: str) -> list[str]:
    """Split a shell command. Punctuation such as ``;`` and ``&&`` is its own token."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.commenters = ""
    return list(lexer)


_data_root_lock = threading.Lock()
_process_data_roots: list[tuple[int, Path]] = []
_next_data_root_token = 0
# None: this context has not bound a root, so read the process stack.
# (): this context explicitly follows the XDG path.
# A non-empty tuple is this context's stack. The last frame wins.
_local_data_roots: contextvars.ContextVar[tuple[tuple[int, Path], ...] | None] = (
    contextvars.ContextVar("praxis_prime_data_root", default=None)
)


def bind_data_root(path: Path | None) -> int | None:
    """Bind ``path`` for this context. ``None`` follows the XDG path.

    ``praxis-prime --data-dir`` passes that directory into the runtime.
    The binding is a stack on this context, not one process-global slot:
    ``release_data_root`` drops only the frame it was given, and a second
    runtime does not erase the first. Worker threads that have not bound a
    root read the process stack, so a bind on the main thread is visible
    inside gateway turns. ``None`` drops this context's frames. When this
    context had none, it clears the process stack so a leaked bind cannot
    outlive the caller.
    """
    if path is None:
        _reset_data_roots()
        return None
    return _push_data_root(Path(path))


def release_data_root(token: int) -> None:
    """Drop the frame ``bind_data_root`` returned. Other frames stay."""
    with _data_root_lock:
        _process_data_roots[:] = [item for item in _process_data_roots if item[0] != token]
    current = _local_data_roots.get()
    if not current:
        return
    remaining = tuple(item for item in current if item[0] != token)
    _local_data_roots.set(remaining if remaining else None)


def _push_data_root(path: Path) -> int:
    global _next_data_root_token
    with _data_root_lock:
        _next_data_root_token += 1
        token = _next_data_root_token
        _process_data_roots.append((token, path))
    current = _local_data_roots.get()
    frames = () if current is None else current
    _local_data_roots.set((*frames, (token, path)))
    return token


def _reset_data_roots() -> None:
    current = _local_data_roots.get()
    with _data_root_lock:
        if current:
            tokens = {token for token, _path in current}
            _process_data_roots[:] = [
                item for item in _process_data_roots if item[0] not in tokens
            ]
        elif current is None:
            _process_data_roots.clear()
    _local_data_roots.set(())


def _data_root_override_path() -> Path | None:
    current = _local_data_roots.get()
    if current is not None:
        if not current:
            return None
        return current[-1][1]
    with _data_root_lock:
        if not _process_data_roots:
            return None
        return _process_data_roots[-1][1]


def _data_root() -> Path | None:
    override = _data_root_override_path()
    chosen = override
    if chosen is None:
        try:
            chosen = data_dir()
        except (OSError, RuntimeError, ValueError):
            return None
    try:
        return Path(chosen).resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return None


def _is_private_data(path: Path) -> bool:
    """Accounts database, profile trees, backups, and hard links to them.

    A path that cannot be classified is private. ``Path.resolve`` and
    ``Path.is_file`` on Python 3.14 hide permission errors, so this uses
    ``os.stat`` / ``os.path.realpath``.
    """
    root = _data_root()
    if root is None:
        return True
    if lstat_kind(path) is StatKind.UNREADABLE or stat_kind(path) is StatKind.UNREADABLE:
        return True
    try:
        resolved = Path(os.path.realpath(path, strict=False))
    except (OSError, RuntimeError, ValueError):
        return True
    if _private_path(resolved, root):
        return True
    inodes, problem = _cached_private_inodes(root)
    if problem:
        # The tree was not fully scanned. Path rules above still apply.
        # Other files stay readable; a hard link past the cap can be missed.
        return False
    return _inode_in(resolved, inodes)


def _private_path(resolved: Path, root: Path) -> bool:
    if resolved == root / "accounts.db":
        return True
    if resolved.parent == root and resolved.name.startswith("accounts.db-"):
        return True
    if _same_regular_inode(resolved, root / "accounts.db"):
        return True
    if resolved == root / "audit.db":
        return True
    if resolved.parent == root and resolved.name.startswith("audit.db-"):
        return True
    if _same_regular_inode(resolved, root / "audit.db"):
        return True
    for folder in ("profiles", "backups"):
        try:
            resolved.relative_to(root / folder)
        except ValueError:
            continue
        return True
    if resolved.name.lower() == "soul.md":
        try:
            resolved.relative_to(root)
        except ValueError:
            return False
        return True
    return False


_PRIVATE_INODE_CAP = 20_000


@dataclass
class _InodeSnapshot:
    root: str
    stamp: tuple[tuple[str, int], ...]
    inodes: set[tuple[int, int]]
    problem: str


_data_inode_snapshot: _InodeSnapshot | None = None
_data_inode_lock = threading.Lock()
_data_inode_scans = 0


def clear_data_inode_cache() -> None:
    """Drop the cached data-directory inode set. Tests use this."""
    global _data_inode_snapshot
    with _data_inode_lock:
        _data_inode_snapshot = None


def data_inode_scans() -> int:
    """How many times the data-directory tree was walked."""
    with _data_inode_lock:
        return _data_inode_scans


def _data_scan_problem(path: Path) -> str:
    """Why ``path`` cannot be classified, or empty when it is not in that tree."""
    root = _data_root()
    if root is None:
        return ""
    _inodes, problem = _cached_private_inodes(root)
    if not problem:
        return ""
    try:
        resolved = Path(os.path.realpath(path, strict=False))
    except (OSError, RuntimeError, ValueError):
        return problem
    if not _private_path(resolved, root):
        return ""
    return problem


def _cached_private_inodes(root: Path) -> tuple[set[tuple[int, int]], str]:
    """Inodes under profiles and backups, reused while directory mtimes match."""
    global _data_inode_scans, _data_inode_snapshot
    key = str(root)
    with _data_inode_lock:
        cached = _data_inode_snapshot
        if (
            cached is not None
            and cached.root == key
            and cached.stamp
            and _stamp_matches(cached.stamp)
        ):
            return cached.inodes, cached.problem
        _data_inode_scans += 1
        inodes, problem, stamp = _scan_private_inodes(root)
        _data_inode_snapshot = _InodeSnapshot(key, stamp, inodes, problem)
        return inodes, problem


def _stamp_matches(stamp: tuple[tuple[str, int], ...]) -> bool:
    for path, mtime in stamp:
        try:
            st = os.lstat(path)
        except OSError:
            return False
        if not stat.S_ISDIR(st.st_mode) or st.st_mtime_ns != mtime:
            return False
    return True


def _scan_private_inodes(
    root: Path,
) -> tuple[set[tuple[int, int]], str, tuple[tuple[str, int], ...]]:
    found: set[tuple[int, int]] = set()
    dirs: list[tuple[str, int]] = []
    root_stamp = _dir_mtime(root)
    if root_stamp is not None:
        dirs.append(root_stamp)
    problem = ""
    for folder in (root / "profiles", root / "backups"):
        reason = _collect_tree_inodes(folder, found, dirs)
        if reason:
            problem = reason
            break
    if not problem:
        database = root / "accounts.db"
        kind = lstat_kind(database)
        if kind is StatKind.UNREADABLE:
            problem = "unreadable accounts.db"
        elif kind is StatKind.FILE and not _add_regular_inode(database, found):
            problem = f"more than {_PRIVATE_INODE_CAP} files under the account data directory"
    return found, problem, tuple(dirs)


def _dir_mtime(path: Path) -> tuple[str, int] | None:
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISDIR(st.st_mode):
        return None
    return str(path), st.st_mtime_ns


def _collect_tree_inodes(
    folder: Path,
    found: set[tuple[int, int]],
    dirs: list[tuple[str, int]],
) -> str:
    """Empty string when the walk finished. Otherwise why it stopped.

    Symlinks are not followed. Hard links share the inode of the original.
    Each directory's mtime is recorded so a later check can reuse ``found``.
    """
    kind = lstat_kind(folder)
    if kind is StatKind.MISSING:
        return ""
    if kind is StatKind.UNREADABLE:
        return f"unreadable directory {folder}"
    if kind is StatKind.FILE:
        if not _add_regular_inode(folder, found):
            return f"more than {_PRIVATE_INODE_CAP} files under the account data directory"
        return ""
    if kind is not StatKind.DIR:
        return ""
    stack = [folder]
    while stack:
        directory = stack.pop()
        stamp = _dir_mtime(directory)
        if stamp is not None:
            dirs.append(stamp)
        try:
            entries = list(os.scandir(directory))
        except FileNotFoundError:
            continue
        except OSError:
            return f"unreadable directory {directory}"
        for entry in entries:
            if len(found) > _PRIVATE_INODE_CAP:
                return (
                    f"more than {_PRIVATE_INODE_CAP} files under the account data directory"
                )
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                return f"unreadable directory {directory}"
            if stat.S_ISLNK(st.st_mode):
                continue
            if stat.S_ISREG(st.st_mode):
                found.add((st.st_dev, st.st_ino))
            elif stat.S_ISDIR(st.st_mode):
                stack.append(Path(entry.path))
    return ""


def _add_regular_inode(path: Path, found: set[tuple[int, int]]) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return True
    if len(found) > _PRIVATE_INODE_CAP:
        return False
    found.add((st.st_dev, st.st_ino))
    return True


def _inode_in(path: Path, found: set[tuple[int, int]]) -> bool:
    try:
        st = os.stat(path, follow_symlinks=True)
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return False
    return (st.st_dev, st.st_ino) in found


_SHELL_SEPARATORS = frozenset({";", "&&", "||", "|", "&"})
_RECURSIVE_WRAPPERS = frozenset({"sudo", "command", "env", "nice", "nohup", "stdbuf"})
_CWD_SEARCHERS = frozenset({"grep", "egrep", "fgrep", "rg", "ripgrep", "find"})


def _command_reaches_data(tokens: list[str], workspace: Path, root: Path) -> bool:
    """Track ``cd`` and expand globs, then apply the path denylist."""
    cwd = workspace
    for segment in _command_segments(tokens):
        expanded = _expand_globs(segment, cwd)
        if _recursive_segment(expanded, cwd, root):
            return True
        if _plain_tokens_private(expanded, cwd, root):
            return True
        destination, failed = _cd_destination(expanded, cwd)
        if failed:
            return True
        if destination is not None:
            cwd = destination
            if _inside_data(cwd, root) and not _inside_workspace(cwd, workspace):
                return True
    return False


def _expand_globs(segment: list[str], cwd: Path) -> list[str]:
    expanded: list[str] = []
    for token in segment:
        expanded.extend(_glob_token(token, cwd))
    return expanded


def _glob_token(token: str, cwd: Path) -> list[str]:
    if token in _SHELL_SEPARATORS or token in {"[", "]", "[["}:
        return [token]
    if not any(ch in token for ch in "*?["):
        return [token]
    pattern = token if Path(token).is_absolute() else str(Path(cwd) / token)
    try:
        matches = glob.glob(pattern)
    except OSError:
        return [token]
    return matches or [token]


def _plain_tokens_private(argv: list[str], cwd: Path, root: Path) -> bool:
    for token in argv:
        if token.startswith("-") or token in _SHELL_SEPARATORS:
            continue
        if _token_is_private(token, cwd, root):
            return True
    return False


def _recursive_segment(argv: list[str], cwd: Path, root: Path) -> bool:
    unwrapped = _unwrap_command(argv)
    if not unwrapped or not _is_recursive_reader(unwrapped):
        return False
    operands = _operands(unwrapped[1:])
    if Path(unwrapped[0]).name == "git":
        paths = operands[1:]
        if not paths:
            return _contains_data(cwd, root)
        return any(
            _token_is_private(token, cwd, root) or _token_contains_data(token, cwd, root)
            for token in paths
        )
    if not operands and Path(unwrapped[0]).name in _CWD_SEARCHERS:
        return _contains_data(cwd, root)
    for token in operands:
        if _token_is_private(token, cwd, root) or _token_contains_data(token, cwd, root):
            return True
    return False


def _cd_destination(argv: list[str], cwd: Path) -> tuple[Path | None, bool]:
    """Return ``(new cwd, fail closed)``. Not a ``cd`` is ``(None, False)``."""
    unwrapped = _unwrap_command(argv)
    if not unwrapped or Path(unwrapped[0]).name != "cd":
        return None, False
    if any(arg == "-" for arg in unwrapped[1:]):
        return None, True
    args = [arg for arg in unwrapped[1:] if arg != "--" and not arg.startswith("-")]
    if not args:
        try:
            return Path.home().resolve(), False
        except OSError:
            return None, True
    path = Path(args[0])
    if not path.is_absolute():
        path = Path(cwd) / path
    try:
        return Path(os.path.realpath(path, strict=False)), False
    except OSError:
        return None, True


def _inside_workspace(cwd: Path, workspace: Path) -> bool:
    """True when ``cwd`` is ``workspace`` or a directory inside it."""
    try:
        here = Path(os.path.realpath(cwd, strict=False))
        root = Path(os.path.realpath(workspace, strict=False))
    except OSError:
        return False
    if here == root:
        return True
    try:
        here.relative_to(root)
    except ValueError:
        return False
    return True


def _inside_data(cwd: Path, root: Path) -> bool:
    """True when ``cwd`` is the data directory or a path inside it."""
    try:
        resolved = Path(os.path.realpath(cwd, strict=False))
        data = Path(os.path.realpath(root, strict=False))
    except OSError:
        return True
    if resolved == data:
        return True
    try:
        resolved.relative_to(data)
    except ValueError:
        return False
    return True


def _command_segments(tokens: list[str]) -> list[list[str]]:
    parts: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token in _SHELL_SEPARATORS:
            if current:
                parts.append(current)
                current = []
            continue
        current.append(token)
    if current:
        parts.append(current)
    return parts


def _unwrap_command(argv: list[str]) -> list[str]:
    args = list(argv)
    while args and Path(args[0]).name in _RECURSIVE_WRAPPERS:
        args = args[1:]
        while args and "=" in args[0] and not args[0].startswith("-"):
            args = args[1:]
    return args


def _is_recursive_reader(argv: list[str]) -> bool:
    name = Path(argv[0]).name
    rest = argv[1:]
    if name in {"rg", "ripgrep", "rsync", "tar", "ag", "ack"}:
        return True
    if name == "git":
        return "grep" in rest
    if name == "find":
        return any(arg in {"-exec", "-execdir", "-ok", "-okdir"} for arg in rest)
    if name in {"grep", "egrep", "fgrep"}:
        return _short_flag(rest, "rR") or "--recursive" in rest or _directories_recurse(rest)
    if name == "cp":
        return _short_flag(rest, "rRa") or "--recursive" in rest or "--archive" in rest
    if name == "zip":
        return _short_flag(rest, "r") or "--recurse-paths" in rest
    return False


def _short_flag(args: list[str], letters: str) -> bool:
    for arg in args:
        if len(arg) < 2 or not arg.startswith("-") or arg.startswith("--"):
            continue
        if any(ch in letters for ch in arg[1:]):
            return True
    return False


def _directories_recurse(args: list[str]) -> bool:
    for index, arg in enumerate(args):
        if arg in {"-d", "--directories"}:
            nxt = args[index + 1] if index + 1 < len(args) else ""
            if nxt == "recurse":
                return True
        if arg.startswith("--directories=") and arg.endswith("recurse"):
            return True
    return False


def _operands(args: list[str]) -> list[str]:
    skip_value = frozenset(
        {
            "-f",
            "-e",
            "--file",
            "--regexp",
            "--include",
            "--exclude",
            "-d",
            "--directories",
        }
    )
    found: list[str] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg == "--":
            continue
        if arg.startswith("-") and arg != "-":
            if arg in skip_value:
                skip = True
            continue
        found.append(arg)
    return found


def _token_is_private(token: str, workspace: Path, root: Path) -> bool:
    return _path_private_under(_token_path(token, workspace), root)


def _path_private_under(path: Path, root: Path) -> bool:
    """True when ``path`` is account data under ``root``, not only the bound root."""
    if lstat_kind(path) is StatKind.UNREADABLE or stat_kind(path) is StatKind.UNREADABLE:
        return True
    try:
        resolved = Path(os.path.realpath(path, strict=False))
    except (OSError, RuntimeError, ValueError):
        return True
    if _private_path(resolved, root):
        return True
    inodes, problem = _cached_private_inodes(root)
    if problem:
        return False
    return _inode_in(resolved, inodes)


def _token_contains_data(token: str, workspace: Path, root: Path) -> bool:
    return _contains_data(_token_path(token, workspace), root)


def _token_path(token: str, workspace: Path) -> Path:
    candidate = Path(token)
    if candidate.is_absolute():
        return candidate
    return workspace / candidate


def _contains_data(candidate: Path, root: Path) -> bool:
    """True when ``candidate`` is the data dir or a parent of it."""
    try:
        resolved = Path(os.path.realpath(candidate, strict=False))
        data = Path(os.path.realpath(root, strict=False))
    except (OSError, RuntimeError, ValueError):
        return True
    try:
        data.relative_to(resolved)
    except ValueError:
        return False
    return True


def _same_regular_inode(path: Path, target: Path) -> bool:
    """True when both paths are the same regular file, including a hard link."""
    try:
        left = os.stat(path, follow_symlinks=True)
        right = os.stat(target, follow_symlinks=True)
    except OSError:
        return False
    if not stat.S_ISREG(left.st_mode) or not stat.S_ISREG(right.st_mode):
        return False
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _is_secret_path(path: Path) -> bool:
    if (
        _is_private_data(path)
        or _name_is_secret(path.name)
        or _components_secret(path.parts)
        or _special_file(path)
    ):
        return True
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return True
    if resolved == path:
        return False
    return (
        _is_private_data(resolved)
        or _name_is_secret(resolved.name)
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
        if part == ".local" and nxt == "share" and "keyrings" in lower[index + 2 :]:
            return True
    if _xdg_config_browser(lower):
        return True
    return _home_browser_prefix(lower)


def _path_part_prefixes(path: Path) -> tuple[tuple[str, ...], ...]:
    """Lowercased parts of ``path`` and of ``path.resolve()``, without duplicates."""
    found: list[tuple[str, ...]] = []
    seen: set[tuple[str, ...]] = set()
    candidates = [path]
    try:
        candidates.append(path.resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        pass
    for candidate in candidates:
        parts = tuple(part.lower() for part in candidate.parts)
        if parts and parts not in seen:
            seen.add(parts)
            found.append(parts)
    return tuple(found)


def _home_browser_prefix(parts: Sequence[str]) -> bool:
    """True for ``$HOME/snap/<browser>`` and ``$HOME/.var/app/<id>/...`` only.

    Compares both ``Path.home()`` and ``Path.home().resolve()``, so a home
    that is a symlink (``/home`` -> ``/var/home``) still matches. A workspace
    file such as ``ws/snap/firefox/notes.md`` is not under ``$HOME``.
    """
    for home in _path_part_prefixes(Path.home()):
        if len(parts) < len(home) or parts[: len(home)] != home:
            continue
        relative = parts[len(home) :]
        if _is_flatpak_keyrings(relative):
            return True
        if any(relative[: len(prefix)] == prefix for prefix in _HOME_BROWSER_PREFIXES):
            return True
    return False


def _is_flatpak_keyrings(relative: tuple[str, ...]) -> bool:
    """True for ``.var/app/<id>/data/keyrings`` and anything under it."""
    return (
        len(relative) >= 5
        and relative[0] == ".var"
        and relative[1] == "app"
        and relative[3] == "data"
        and relative[4] == "keyrings"
    )


def _absolute_xdg_config_home() -> Path | None:
    """Absolute ``$XDG_CONFIG_HOME``, or None when unset, empty, or relative.

    The XDG base directory spec says a relative value is invalid and must be
    ignored. Native ``~/.config/<name>`` rows cover that fallback.
    """
    raw = os.environ.get("XDG_CONFIG_HOME")
    if not raw:
        return None
    try:
        path = Path(raw).expanduser()
    except (OSError, RuntimeError, ValueError):
        return None
    if not path.is_absolute():
        return None
    return path


def _xdg_config_browser(parts: Sequence[str]) -> bool:
    """True when ``parts`` is a native browser dir under ``$XDG_CONFIG_HOME``.

    Unset, empty, or relative ``XDG_CONFIG_HOME`` stays on the ``~/.config``
    rows. An absolute value is checked both as given and resolved.
    """
    config_home = _absolute_xdg_config_home()
    if config_home is None:
        return False
    try:
        prefixes = _path_part_prefixes(config_home)
    except (OSError, RuntimeError, ValueError):
        return False
    for prefix in prefixes:
        if len(parts) <= len(prefix) or parts[: len(prefix)] != prefix:
            continue
        if parts[len(prefix)] in _BROWSER_CONFIG:
            return True
    return False


def _special_file(path: Path) -> bool:
    posix = path.as_posix()
    if posix == "/etc/shadow":
        return True
    return _PROC_ENVIRON.match(posix) is not None


def _xdg_browser_roots(home: Path) -> list[Path]:
    """Native browser dirs under an absolute ``$XDG_CONFIG_HOME`` other than ``~/.config``."""
    config_home = _absolute_xdg_config_home()
    if config_home is None:
        return []
    if _same_resolved(config_home, home / ".config"):
        return []
    return [
        config_home / profile.deny[1]
        for profile in _BROWSER_PROFILES
        if profile.deny[0] == ".config" and len(profile.deny) == 2
    ]


def _flatpak_keyring_dirs(home: Path) -> list[Path] | _CapHit:
    """Existing ``~/.var/app/*/data/keyrings`` directories.

    Stop after one more than ``_MAX_FLATPAK_KEYRING_ROOTS``. The scan fails
    closed on that overflow instead of giving every match its own budget.
    EACCES or EPERM on ``~/.var/app`` or on an app directory fails closed.
    ENOENT and ENOTDIR still mean that root is absent.
    """
    root = home / ".var" / "app"
    found: list[Path] = []
    limit = _MAX_FLATPAK_KEYRING_ROOTS + 1
    try:
        children = list(root.iterdir())
    except OSError as exc:
        hit = _listing_failure(exc, str(root))
        if hit is not None:
            return hit
        return []
    for child in children:
        candidate = child / "data" / "keyrings"
        followed = _follow_stat(candidate)
        if isinstance(followed, _CapHit):
            return followed
        if isinstance(followed, _Unfollowed) or not stat.S_ISDIR(followed.st_mode):
            continue
        found.append(candidate)
        if len(found) >= limit:
            break
    return found


def _is_flatpak_keyring_dir(path: Path) -> bool:
    """True for ``.../.var/app/<id>/data/keyrings`` and not ``~/.local/share/keyrings``."""
    parts = path.parts
    if len(parts) < 5:
        return False
    tail = parts[-5:]
    return (
        tail[0] == ".var"
        and tail[1] == "app"
        and tail[3] == "data"
        and tail[4] == "keyrings"
    )


def _inode_candidates() -> list[Path] | _CapHit:
    home = Path.home()
    paths = [
        home / ".ssh",
        home / ".aws",
        home / ".kube",
        home / ".gnupg",
        home / ".local" / "share" / "keyrings",
        home / ".mozilla",
    ]
    paths.extend(home.joinpath(*profile.scan) for profile in _BROWSER_PROFILES)
    paths.extend(_xdg_browser_roots(home))
    keyrings = _flatpak_keyring_dirs(home)
    if isinstance(keyrings, _CapHit):
        return keyrings
    paths.extend(keyrings)
    paths.extend(
        [
            home / ".netrc",
            home / ".boto",
            home / ".git-credentials",
            home / ".docker" / "config.json",
            Path("/etc/shadow"),
        ]
    )
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
    root: Path,
    found: set[tuple[int, int]],
    tally: _NameTally,
    *,
    skip_browser_caches: bool,
) -> _CapHit | None:
    """Skip kube caches, browser disk caches, and symlinks that leave the root.

    A symlink that stays inside the root (snap ``current`` -> a revision) is
    kept. The walk records directory inodes and skips one it has already
    seen, so ``current`` is not walked twice. Browser disk-cache directories
    are not descended into by the budgeted walk. Secret-named files at any
    depth under one are recorded by a separate name-only pass.
    """
    direct_kube = kube_root is not None and _same_dir(directory, kube_root)
    kept: list[str] = []
    for name in dirnames:
        child = directory / name
        if direct_kube and name.lower() in _KUBE_SKIP_DIRS:
            continue
        mode = _lstat_mode(child)
        if isinstance(mode, _CapHit):
            return mode
        if mode is not None and stat.S_ISLNK(mode) and not _contains(root, child):
            continue
        if skip_browser_caches and name.lower() in _BROWSER_CACHE_DIRS:
            hit = _record_cache_secret_inodes(child, found, tally)
            if hit is not None:
                return hit
            continue
        kept.append(name)
    dirnames[:] = kept
    return None


def _record_cache_secret_inodes(
    cache_root: Path,
    found: set[tuple[int, int]],
    tally: _NameTally,
) -> _CapHit | None:
    """Record secret-named files nested under a skipped cache directory.

    Directory entries are counted only toward ``tally``, not the scan root's
    entry budget. Symlinks that leave the cache directory are not followed.
    A symlink loop (ELOOP) is a file, not a directory to descend into.
    ENOENT and ENOTDIR on a proper descendant mean that entry vanished. The
    parent is re-listed once so a rename is not skipped. The cache root
    itself, and any vanished path that is not under it, fail the scan closed:
    re-listing the parent would walk a directory the cache skip does not own.
    Any other listing or stat failure, including EACCES and EPERM, fails the
    scan closed.
    """
    seen_dirs: set[tuple[int, int]] = set()
    pending = [cache_root]
    retried = False
    examined_at_start = tally.examined
    while pending:
        current = pending.pop()
        followed = _follow_stat(current)
        if isinstance(followed, _CapHit):
            return followed
        if isinstance(followed, _Unfollowed):
            if followed.loop:
                continue
            hit = _cache_vanish(current, cache_root, pending, seen_dirs, retried)
            if isinstance(hit, _CapHit):
                return hit
            if hit:
                retried = True
                tally.examined = examined_at_start
            continue
        inode = (followed.st_dev, followed.st_ino)
        if not stat.S_ISDIR(followed.st_mode) or inode in seen_dirs:
            continue
        if not _contains(cache_root, current):
            continue
        seen_dirs.add(inode)
        try:
            children = list(os.scandir(current))
        except OSError as exc:
            hit = _listing_failure(exc, _error_filename(exc) or str(current))
            if hit is not None:
                return hit
            queued = _cache_vanish(current, cache_root, pending, seen_dirs, retried)
            if isinstance(queued, _CapHit):
                return queued
            if queued:
                retried = True
                tally.examined = examined_at_start
            continue
        tally.examined += len(children)
        if tally.examined > _MAX_CACHE_NAME_ENTRIES:
            return _CapHit(_MAX_CACHE_NAME_ENTRIES, "cache-name")
        for child in children:
            path = Path(child.path)
            mode = _lstat_mode(path)
            if isinstance(mode, _CapHit):
                return mode
            if mode is None:
                continue
            if stat.S_ISLNK(mode):
                nested = _follow_stat(path)
                if isinstance(nested, _CapHit):
                    return nested
                if not isinstance(nested, _Unfollowed) and stat.S_ISDIR(nested.st_mode):
                    if _contains(cache_root, path):
                        pending.append(path)
                    continue
            elif stat.S_ISDIR(mode):
                pending.append(path)
                continue
            if _inode_file_is_secret(child.name, current):
                added = _add_inode(path, found, 0)
                if isinstance(added, _CapHit):
                    return added
    return None


def _retry_parent(
    current: Path,
    pending: list[Path],
    seen_dirs: set[tuple[int, int]],
) -> _CapHit | bool:
    """Queue a fresh listing of ``current``'s parent. True when that happened."""
    try:
        names = os.listdir(current.parent)
    except OSError as exc:
        hit = _listing_failure(exc, str(current.parent))
        if hit is not None:
            return hit
        return False
    seen_dirs.clear()
    pending.extend(current.parent / name for name in names)
    return True


def _is_proper_descendant(root: Path, path: Path) -> bool:
    """True when ``path`` is strictly inside ``root`` by lexical absolute path."""
    try:
        relative = Path(os.path.abspath(path)).relative_to(os.path.abspath(root))
    except ValueError:
        return False
    return bool(relative.parts)


def _cache_vanish(
    current: Path,
    cache_root: Path,
    pending: list[Path],
    seen_dirs: set[tuple[int, int]],
    retried: bool,
) -> _CapHit | bool:
    """Re-list a vanished descendant, or fail closed for the cache root itself.

    A rename of ``Cache/x`` is recovered by listing ``Cache`` again. A rename
    of ``Cache`` is not: the parent is the profile directory, and walking it
    from the cache pass would miss a secret that left the skipped name.
    """
    if not _is_proper_descendant(cache_root, current):
        return _CapHit(0, "unreadable-directory", str(current))
    if retried:
        return False
    return _retry_parent(current, pending, seen_dirs)


def _same_dir(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(os.path.abspath(right))


@dataclass
class _NameTally:
    """Directory entries examined by the cache name-only pass of one scan root."""

    examined: int = 0


@dataclass
class _SharedEntries:
    """Directory entries counted across every flatpak keyring root in one scan."""

    count: int = 0


@dataclass(frozen=True, slots=True)
class _CapHit:
    """A scan root that stopped early. The caller fails every read closed."""

    limit: int
    kind: str
    path: str | None = None


def _listing_errno_ignored(exc: OSError) -> bool:
    """True when a path vanished or was replaced during the scan.

    Chrome rewrites IndexedDB and ``blob_storage`` while a profile is open.
    That is ENOENT or ENOTDIR. EACCES, EPERM, and any other listing or stat
    failure still fail closed, and that denial stays cached for the rest of
    the turn.
    """
    return exc.errno in _IGNORED_LISTING_ERRNOS


def _listing_failure(exc: OSError, path: str) -> _CapHit | None:
    """A closed-scan hit, or None when the path only vanished."""
    if _listing_errno_ignored(exc):
        return None
    return _CapHit(0, "unreadable-directory", path)


@dataclass(frozen=True, slots=True)
class _Unfollowed:
    """A followed stat that is not a directory to walk.

    ``loop`` is ELOOP on a symlink. That entry is a file. ``loop`` false is
    ENOENT or ENOTDIR: the path vanished during the scan.
    """

    loop: bool


# File-shaped scan roots. A failure to stat one says "could not stat".
# A directory the walk could not list still says "could not list".
_FILE_ROOT_NAMES = frozenset(
    {
        ".netrc",
        ".boto",
        ".git-credentials",
        "config.json",
        "gateway.token",
        "secrets.env",
        "secrets.env.age",
        "shadow",
    }
)


def _lstat_mode(path: Path) -> int | _CapHit | None:
    """``os.lstat`` mode, a closed-scan hit, or None when the path vanished.

    ``Path.is_symlink`` on Python 3.14 returns False for every ``OSError``,
    including EACCES on a mode 000 parent. ``os.lstat`` still raises, so the
    scan can fail closed. The final symlink is not followed.
    """
    try:
        return os.lstat(path).st_mode
    except OSError as exc:
        hit = _listing_failure(exc, str(path))
        if hit is not None:
            return hit
        return None


def _follow_stat(path: Path) -> os.stat_result | _CapHit | _Unfollowed:
    """Followed ``os.stat``, a closed-scan hit, or an unfollowed outcome.

    ELOOP means the entry is a symlink loop. It is not a directory and it
    does not fail the scan. ENOENT and ENOTDIR mean the path vanished.
    EACCES and EPERM fail closed. ``Path.is_dir`` and ``Path.is_file`` on
    Python 3.14 hide those errors by returning False.
    """
    try:
        return os.stat(path, follow_symlinks=True)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return _Unfollowed(loop=True)
        hit = _listing_failure(exc, str(path))
        if hit is not None:
            return hit
        return _Unfollowed(loop=False)


def _error_filename(exc: OSError) -> str | None:
    filename = exc.filename
    if isinstance(filename, bytes):
        return os.fsdecode(filename)
    if filename is None:
        return None
    return str(filename)


def _home_relative(path: str) -> str:
    """``~/...`` when ``path`` is under the home directory, otherwise ``path``."""
    home = str(Path.home())
    if path == home:
        return "~"
    prefix = home + os.sep
    if path.startswith(prefix):
        return "~/" + path[len(prefix) :].replace(os.sep, "/")
    return path


def _under_home_tree(path: str, relative: str) -> bool:
    """True when ``path`` is ``~/<relative>`` or a descendant of it.

    The check is the home directory's own tree, not any path segment with
    the same name. A symlinked ``~/.gnupg`` still matches after the walk
    reports the link target.
    """
    anchor = Path.home().joinpath(*relative.split("/"))
    try:
        Path(path).relative_to(anchor)
        return True
    except ValueError:
        pass
    try:
        real_anchor = os.path.realpath(anchor)
    except OSError:
        return False
    try:
        real_here = os.path.realpath(path)
    except OSError:
        parent = os.path.dirname(path)
        try:
            real_here = os.path.join(os.path.realpath(parent), os.path.basename(path))
        except OSError:
            return False
    return real_here == real_anchor or real_here.startswith(real_anchor + os.sep)


def _under_gnupg(path: str | None) -> bool:
    return path is not None and _under_home_tree(path, ".gnupg")


def _ownership_hint(path: str | None) -> str | None:
    if _under_gnupg(path):
        return "(a root-owned dir, e.g. from `sudo gpg`, in ~/.gnupg; fix ownership)"
    if path is not None and _under_home_tree(path, ".docker"):
        return "(a root-owned dir, e.g. from `sudo docker`, in ~/.docker; fix ownership)"
    if path is not None and _under_home_tree(path, ".config/praxis-prime"):
        return (
            "(a root-owned dir, e.g. from `sudo praxis-prime`, "
            "in ~/.config/praxis-prime; fix ownership)"
        )
    return None


def _refuse_capped_inode_scan(limit: int, kind: str, path: str | None = None) -> None:
    if kind == "unbounded-root":
        detail = "secret inode scan refused an unbounded root"
    elif kind == "unreadable-directory":
        verb = "stat" if path is not None and Path(path).name in _FILE_ROOT_NAMES else "list"
        shown = repr(_home_relative(path)) if path else repr("a directory")
        detail = f"secret inode scan could not {verb} {shown}"
        hint = _ownership_hint(path)
        if hint is not None:
            detail += " " + hint
    else:
        detail = f"secret inode scan hit the {limit} {kind} cap"
    message = f"{detail}; denying the read because a secret file could have been missed"
    if kind == "unreadable-directory" and path:
        _log.warning("%s full_path=%s", message, repr(path))
    else:
        _log.warning("%s", message)
    raise ReadDenied(message, "inode_scan_capped")


def _contains(root: Path, path: Path) -> bool:
    """True when ``path`` resolves to ``root`` or a path under it."""
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def _inside_home(path: Path, home: Path) -> bool:
    return _contains(home, path)


def _dir_inode(path: Path) -> tuple[int, int] | _CapHit | None:
    """Directory inode, a closed-scan hit, or None when the path is not a dir.

    ENOENT, ENOTDIR, and ELOOP return None. ELOOP is a symlink loop, not a
    directory to descend into. EACCES, EPERM, and other stat failures fail
    the scan closed. Mode 0400 lists names but cannot stat children.
    """
    followed = _follow_stat(path)
    if isinstance(followed, _CapHit):
        return followed
    if isinstance(followed, _Unfollowed) or not stat.S_ISDIR(followed.st_mode):
        return None
    return followed.st_dev, followed.st_ino


def _is_unbounded_scan_root(path: Path) -> bool:
    """True when a walk would be ``/``, ``/proc``, ``/sys``, or the same inode as ``/``.

    ``/etc``, ``/usr``, and ``/dev`` are walked with the entry budget. A path
    that resolves to ``/`` (for example ``/etc/..``) is the whole filesystem.
    A resolve failure is treated as unbounded. The caller fails the scan
    closed instead of skipping the root.
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


def _browser_scan_candidates(home: Path) -> list[Path]:
    candidates = [home.joinpath(*profile.scan) for profile in _BROWSER_PROFILES]
    candidates.extend(_xdg_browser_roots(home))
    candidates.append(home / ".mozilla")
    return candidates


def _is_browser_scan_root(path: Path) -> bool:
    """True for a native, snap, flatpak, or ``$XDG_CONFIG_HOME`` browser root.

    A symlink is included when it resolves to one of those roots. Callers that
    must not treat ``~/.ssh`` -> a profile as the profile use
    ``_is_lexical_browser_root``.
    """
    home = Path.home()
    return any(
        _same_resolved(path, candidate) for candidate in _browser_scan_candidates(home)
    )


def _is_lexical_browser_root(path: Path, *, include_gcloud: bool) -> bool:
    """True when ``path`` is a configured browser scan root.

    The path is compared as given, so a profile-sync symlink such as
    ``~/.config/google-chrome`` -> tmpfs still matches. ``~/.ssh`` does not,
    even when that symlink points at a profile. ``include_gcloud`` is false
    for the disk-cache skip. The gcloud row stays on the named walk, so
    ``cache/x/credentials.db`` is recorded there.
    """
    home = Path.home()
    for candidate in _browser_scan_candidates(home):
        if not include_gcloud and candidate.name.lower() == "gcloud":
            continue
        if _same_dir(path, candidate):
            return True
    return False


def _resolve_scan_root(path: Path) -> tuple[Path, bool] | _CapHit | None:
    """Return the path to scan, and whether the walk has an entry budget.

    A top-level symlink is followed in the same mode as the link name.
    ``/``, ``/proc``, ``/sys``, and a path that resolves to ``/`` fail the
    scan closed. ``/etc``, ``/usr``, and ``/dev`` are walked with
    ``_MAX_SCAN_ENTRIES``, as is any other symlink outside ``$HOME``. A
    symlink that resolves to ``$HOME`` itself uses that budget too, so
    ``~/.ssh -> $HOME`` does not walk the home directory without a cap.
    Browser scan roots are budgeted even when they are symlinks, so
    ``~/snap/<app>`` and a profile-sync ``~/.config/google-chrome`` cannot
    walk without a cap. Those roots use ``_MAX_BROWSER_SCAN_ENTRIES``
    because IndexedDB and Extensions sit outside the cache skip. gcloud and
    a credential symlink into a profile keep ``_MAX_SCAN_ENTRIES``. Hitting
    either budget, the cache-name cap, or the credential-file cap fails
    every read closed.
    """
    try:
        mode = _lstat_mode(path)
        if isinstance(mode, _CapHit):
            return mode
        if mode is None:
            return None
        browser = _is_browser_scan_root(path)
        if not stat.S_ISLNK(mode):
            return path, browser
        resolved = path.resolve(strict=False)
        if _is_unbounded_scan_root(resolved):
            return _CapHit(0, "unbounded-root")
        return resolved, browser or _scan_root_needs_budget(resolved, Path.home())
    except OSError as exc:
        # A mode 000 parent hides the root. That is not the same as a root
        # that does not exist.
        hit = _listing_failure(exc, str(path))
        if hit is not None:
            return hit
        return None
    except (RuntimeError, ValueError):
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


def _directory_entry_budget(path: Path, budget_entries: bool) -> int | None:
    """Entry budget for one scan root, or None when the walk is unbounded.

    A configured browser root uses the larger budget so IndexedDB and
    Extensions do not fail every read closed, including when that path is a
    symlink to tmpfs or another disk. gcloud and credential symlinks such as
    ``~/.ssh`` stay on ``_MAX_SCAN_ENTRIES``.
    """
    if not budget_entries:
        return None
    if _is_lexical_browser_root(path, include_gcloud=False):
        return _MAX_BROWSER_SCAN_ENTRIES
    return _MAX_SCAN_ENTRIES


def _file_counts(name: str, directory: Path, mode: str) -> bool:
    if mode == "all":
        return True
    return _inode_file_is_secret(name, directory)


def _collect_inodes(
    path: Path,
    found: set[tuple[int, int]],
    shared: _SharedEntries | None = None,
) -> _CapHit | None:
    """Scan one candidate.

    Return a hit when the walk stops early. The caller fails every read
    closed. Named browser and gcloud walks record every secret-named inode.
    An entry budget, the cache-name cap, or a credential-file cap stops the
    scan. ``shared`` is the entry total for every flatpak keyring root in
    this scan; those roots do not each get a fresh budget.
    """
    resolved = _resolve_scan_root(path)
    if isinstance(resolved, _CapHit):
        return resolved
    if resolved is None:
        return None
    root, budget_entries = resolved
    mode = _scan_mode(path)
    if mode == "all" and budget_entries and _same_resolved(root, Path.home()):
        # Counting every file under $HOME trips the credential cap and marks
        # ordinary files secret. Keep the entry budget and record secret
        # names. This fallback has no secret-file cap: a budget hit fails
        # every read closed, and every secret-named inode is recorded.
        mode = "named"
    file_cap = _MAX_CREDENTIAL_FILES if mode == "all" else None
    kube_root = root if path.name.lower() == ".kube" else None
    # Match the configured path, not where a symlink points. A profile-sync
    # ``~/.config/google-chrome`` is still that browser root. ``~/.ssh`` is not.
    skip_browser_caches = _is_lexical_browser_root(path, include_gcloud=False)
    tally = _NameTally()
    followed = _follow_stat(root)
    if isinstance(followed, _CapHit):
        return followed
    if isinstance(followed, _Unfollowed):
        return None
    if stat.S_ISREG(followed.st_mode):
        added = _add_inode(root, found, 0)
        if isinstance(added, _CapHit):
            return added
        return None
    if not stat.S_ISDIR(followed.st_mode):
        return None
    # Listing errors are handled here. os.walk is a generator, so a
    # try/except around the call itself never sees scandir failures.
    count = 0
    entries = 0
    seen_dirs: set[tuple[int, int]] = set()
    budget = _directory_entry_budget(path, budget_entries)
    shared_before = shared.count if shared is not None else 0
    use_listdir = False
    stack = [root]
    while stack:
        directory = stack.pop()
        listed = _list_dir(directory, use_listdir=use_listdir)
        if isinstance(listed, _CapHit):
            return listed
        if listed is None:
            # The directory vanished between listing and descending. Rescan
            # the root once with listdir, which sees the renamed tree, then
            # accept any further ENOENT or ENOTDIR.
            if not use_listdir:
                use_listdir = True
                stack = [root]
                seen_dirs.clear()
                entries = 0
                count = 0
                tally.examined = 0
                if shared is not None:
                    shared.count = shared_before
                continue
            continue
        dirnames, filenames = listed
        inode = _dir_inode(directory)
        if isinstance(inode, _CapHit):
            return inode
        if inode is None or inode in seen_dirs:
            if inode is None and not use_listdir:
                use_listdir = True
                stack = [root]
                seen_dirs.clear()
                entries = 0
                count = 0
                tally.examined = 0
                if shared is not None:
                    shared.count = shared_before
            continue
        seen_dirs.add(inode)
        hit = _prune_scan_dirs(
            dirnames,
            directory,
            kube_root,
            root,
            found,
            tally,
            skip_browser_caches=skip_browser_caches,
        )
        if hit is not None:
            return hit
        added = len(dirnames) + len(filenames)
        if budget is not None:
            entries += added
            if entries > budget:
                return _CapHit(budget, "directory-entry")
        if shared is not None:
            shared.count += added
            if shared.count > _MAX_SCAN_ENTRIES:
                return _CapHit(_MAX_SCAN_ENTRIES, "directory-entry", str(directory))
        for name in filenames:
            if not _file_counts(name, directory, mode):
                continue
            if file_cap is not None and count >= file_cap:
                return _CapHit(file_cap, "secret-file")
            counted = _add_inode(directory / name, found, count)
            if isinstance(counted, _CapHit):
                return counted
            count = counted
        for name in reversed(dirnames):
            stack.append(directory / name)
    return None


def _list_dir(
    directory: Path, *, use_listdir: bool
) -> tuple[list[str], list[str]] | _CapHit | None:
    """Names in ``directory``, a closed-scan hit, or None if it vanished.

    ``use_listdir`` is the one rescan after a rename. It does not go through
    ``os.scandir``, so a directory renamed between the first listing and the
    descent is still visible.
    """
    if use_listdir:
        try:
            names = os.listdir(directory)
        except OSError as exc:
            hit = _listing_failure(exc, str(directory))
            if hit is not None:
                return hit
            return None
        dirnames: list[str] = []
        filenames: list[str] = []
        for name in names:
            child = directory / name
            followed = _follow_stat(child)
            if isinstance(followed, _CapHit):
                return followed
            if isinstance(followed, _Unfollowed):
                if followed.loop:
                    filenames.append(name)
                continue
            if stat.S_ISDIR(followed.st_mode):
                dirnames.append(name)
            else:
                filenames.append(name)
        return dirnames, filenames
    try:
        entries = list(os.scandir(directory))
    except OSError as exc:
        hit = _listing_failure(exc, _error_filename(exc) or str(directory))
        if hit is not None:
            return hit
        return None
    dirnames = []
    filenames = []
    for entry in entries:
        followed = _follow_stat(Path(entry.path))
        if isinstance(followed, _CapHit):
            return followed
        if isinstance(followed, _Unfollowed):
            if followed.loop:
                filenames.append(entry.name)
            continue
        if stat.S_ISDIR(followed.st_mode):
            dirnames.append(entry.name)
        else:
            filenames.append(entry.name)
    return dirnames, filenames


def _add_inode(path: Path, found: set[tuple[int, int]], count: int) -> int | _CapHit:
    try:
        st = os.stat(path, follow_symlinks=True)
    except OSError as exc:
        # Mode 0400 can list the name and still refuse the stat. That hides
        # a hard link unless the scan fails closed. A vanished file does not.
        # ELOOP is a symlink loop: there is no file to record.
        if exc.errno == errno.ELOOP:
            return count
        hit = _listing_failure(exc, str(path))
        if hit is not None:
            return hit
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
