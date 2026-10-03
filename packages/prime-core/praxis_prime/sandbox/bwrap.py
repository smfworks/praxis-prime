"""Bubblewrap launcher for shell commands.

bubblewrap is LGPL-2.0+ and is invoked as a system binary. It is not linked
into this process. ``--unshare-all`` drops the network namespace. The
workspace is mounted read-only unless the caller has an approved write scope.
That scope is one directory: a task worktree or the approved command's
cwd. It is never ``$HOME`` and never the main checkout when one is named.
Bash is started with ``--noprofile --norc`` so a login alias cannot rewrite
an allowlisted command. ``HOME`` is an empty tmpfs, not the workspace, so a
repo ``.gitconfig`` is not git's global config. System and global git
config are disabled, and ``GIT_NO_LAZY_FETCH`` stops a partial clone from
fetching during an allowlisted command.

If the binary is missing, callers must not run the command on the host unless
a person has approved that command. A failed sandbox does not fall back to an
unsandboxed run.
"""

from __future__ import annotations

import contextvars
import errno
import os
import shutil
import signal
import stat
import subprocess
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path


class SandboxError(RuntimeError):
    """The sandbox could not run the command. The host shell was not used."""


_profile_lock = threading.Lock()
_process_profiles: list[tuple[int, str]] = []
_next_profile_token = 0
# None: this context has not bound a profile, so read the process stack.
# (): this context explicitly has no profile.
# A non-empty tuple is this context's stack. The last frame wins.
_local_profiles: contextvars.ContextVar[tuple[tuple[int, str], ...] | None] = (
    contextvars.ContextVar("praxis_prime_profile", default=None)
)


def bind_profile(profile: str | None) -> int | None:
    """Bind ``profile`` for this context. ``None`` or ``""`` clears it here.

    The binding is a stack, matching ``bind_data_root``. ``release_profile``
    drops only the frame it was given. Worker threads that have not bound a
    profile read the process stack. A context that has not bound a profile
    does not clear another runtime's stack.
    """
    if not profile:
        _reset_profiles()
        return None
    return _push_profile(profile)


def release_profile(token: int) -> None:
    """Drop the frame ``bind_profile`` returned. Other frames stay."""
    with _profile_lock:
        _process_profiles[:] = [item for item in _process_profiles if item[0] != token]
    current = _local_profiles.get()
    if not current:
        return
    remaining = tuple(item for item in current if item[0] != token)
    _local_profiles.set(remaining if remaining else None)


def bound_profile() -> str:
    """Profile id for this context, or the process stack when this context has not bound one."""
    current = _local_profiles.get()
    if current is not None:
        if not current:
            return ""
        return current[-1][1]
    with _profile_lock:
        if not _process_profiles:
            return ""
        return _process_profiles[-1][1]


def _push_profile(profile: str) -> int:
    global _next_profile_token
    with _profile_lock:
        _next_profile_token += 1
        token = _next_profile_token
        _process_profiles.append((token, profile))
    current = _local_profiles.get()
    frames = () if current is None else current
    _local_profiles.set((*frames, (token, profile)))
    return token


def _reset_profiles() -> None:
    """Clear this context's profile. Leave another context's bind on the process stack."""
    current = _local_profiles.get()
    with _profile_lock:
        if current:
            tokens = {token for token, _profile in current}
            _process_profiles[:] = [
                item for item in _process_profiles if item[0] not in tokens
            ]
    _local_profiles.set(())


@dataclass(frozen=True, slots=True)
class CommandStatus:
    """Exit code plus combined output. ``code`` is the process status.

    ``stdout`` is the raw standard output, with stderr left out. The git
    ``--name-only -z`` probe reads that field and does not strip it.
    """

    code: int
    output: str
    stdout: str = ""


def bwrap_available() -> bool:
    return shutil.which("bwrap") is not None


def writable_scope_ok(
    cwd: Path,
    scope: Path | None,
    main_checkout: Path | None = None,
) -> bool:
    """True when ``cwd`` is the one directory this write may mount."""
    if scope is None:
        return False
    try:
        resolved = cwd.resolve()
        allowed = scope.resolve()
        home = Path.home().resolve()
    except OSError:
        return False
    if resolved != allowed:
        return False
    if resolved == home or _contains(resolved, home):
        return False
    if main_checkout is not None:
        try:
            if resolved == main_checkout.resolve():
                return False
        except OSError:
            return False
    return True


def build_bwrap_argv(
    command: str,
    cwd: Path,
    *,
    ro_binds: list[tuple[str, str]] | None = None,
    writable: bool = False,
    scope: Path | None = None,
    main_checkout: Path | None = None,
) -> list[str]:
    """Return a bwrap command that runs ``command`` with network unshared.

    The workspace mount is ``--ro-bind`` unless ``writable`` is set and
    ``scope`` is exactly ``cwd``, and that directory is not ``$HOME`` or
    ``main_checkout``.
    """
    work = _bind_source(cwd)
    mount = "--ro-bind"
    if writable:
        if not writable_scope_ok(work, scope, main_checkout):
            raise SandboxError(
                "refusing read-write bind outside the approved worktree; "
                "the command was not run"
            )
        mount = "--bind"
    argv = [
        "bwrap",
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/local/bin:/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/sandbox-home",
        "--setenv",
        "GIT_CONFIG_NOSYSTEM",
        "1",
        "--setenv",
        "GIT_CONFIG_GLOBAL",
        "/dev/null",
        "--setenv",
        "GIT_NO_LAZY_FETCH",
        "1",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--setenv",
        "TERM",
        "xterm-256color",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/sandbox-home",
        mount,
        str(work),
        "/workspace",
        "--chdir",
        "/workspace",
    ]
    mounts: list[tuple[Path, str]] = [(work, "/workspace")]
    for optional in ("/usr", "/bin", "/lib", "/lib64", "/etc"):
        if Path(optional).exists():
            argv.extend(["--ro-bind", optional, optional])
            mounts.append((Path(optional), optional))
    for src, dest in ro_binds or []:
        source = Path(src)
        if not source.exists():
            continue
        resolved = _bind_source(source)
        argv.extend(["--ro-bind", str(resolved), dest])
        mounts.append((resolved, dest))
    mask = _data_dir_mask(mounts)
    argv.extend(mask)
    argv.extend(hardlink_cover_argv(mounts, _tmpfs_targets(mask)))
    argv.extend(["--", "bash", "--noprofile", "--norc", "-c", command])
    return argv


_HARDLINK_SCAN_CAP = 20_000
# A workspace file that disappears is tried again, then the whole walk is
# tried again, before the launch is refused. Three passes absorb a rename
# during a build without treating a stuck error as success.
_WORKSPACE_VANISH_ATTEMPTS = 3
# Read-only system binds added by the launcher. A workspace that merely
# lives under one of these trees, such as ``/opt`` or ``/usr/local``, is
# a separate mount and is still scanned.
_RO_SYSTEM_BINDS = frozenset({"/usr", "/bin", "/lib", "/lib64", "/etc"})


def _tmpfs_targets(argv: list[str]) -> list[str]:
    found: list[str] = []
    index = 0
    while index < len(argv) - 1:
        if argv[index] == "--tmpfs":
            found.append(argv[index + 1])
            index += 2
            continue
        index += 1
    return found


def hardlink_cover_argv(
    mounts: list[tuple[Path, str]],
    masked: list[str],
    exposed: list[str] | None = None,
) -> list[str]:
    """Cover private hard links inside ``mounts`` with ``/dev/null``.

    The protected inodes are the account-data denylist: ``profiles/``,
    ``backups/``, ``accounts.db``, ``audit.db``, the root ``prime.db``,
    each database's ``-wal``, ``-shm``, and ``-journal`` sidecar, ``SOUL.md``,
    ``worker-master.key``, and the runtime ``gateway.token``. A regular file
    is hidden only when its inode is one of those and ``nlink`` is greater
    than one. When none of them has another name, the workspace is not walked.
    A name left behind after the other link was deleted or replaced has a
    link count of one and is not covered; it behaves like a copy.
    ``.git/objects`` and ``node_modules`` are walked only if some extra name
    is still unaccounted for. The read-only system binds (``/usr``, ``/bin``,
    ``/lib``, ``/lib64``, ``/etc``) are not walked. A workspace under ``/opt``
    or ``/usr/local`` is. A path under a data-root tmpfs is already hidden,
    except a worktree that was bound again on top of that tmpfs
    (``exposed``). One directory entry is counted once. The identity is its
    real path and the device and inode of its parent, so a working directory
    and a write scope inside it cannot use up the link count twice. A mount
    nested in another is not walked again when the sandbox path nests the
    same way. When two mounts overlap and their sandbox paths do not, the
    walk does not stop early. The walk refuses to launch when it cannot
    finish: a directory that cannot be listed, a workspace entry that is
    still missing after a short retry, a tree deeper than the scan limit,
    or a walk that passes the hard-link cap. The error names the folder and
    the reason. A file that disappears inside the account data directory is
    not a failure. The check is at launch: a link created after the scan
    and before bubblewrap starts is not covered.
    """
    from praxis_prime.policy.boundary import (
        _account_data_roots,
        _cached_linked_inodes,
        _cached_private_inodes,
    )

    roots = _account_data_roots()
    if not roots:
        raise SandboxError("refusing to launch; account data could not be classified")
    remaining: dict[tuple[int, int], int] = {}
    for root in roots:
        _inodes, problem = _cached_private_inodes(root)
        if problem:
            raise _account_scan_error(problem)
        linked, link_problem = _cached_linked_inodes(root)
        if link_problem:
            raise _account_scan_error(link_problem)
        for key, nlink in linked.items():
            extra = nlink - 1
            if extra > remaining.get(key, 0):
                remaining[key] = extra
    if not remaining:
        return []
    visible = list(exposed or [])
    vanished: _Vanished | None = None
    for _attempt in range(_WORKSPACE_VANISH_ATTEMPTS):
        try:
            return _cover_mounts(mounts, masked, visible, dict(remaining))
        except _Vanished as exc:
            vanished = exc
    assert vanished is not None
    raise _mount_error(vanished.folder, reason=vanished.reason) from vanished


class _Vanished(Exception):
    """A workspace entry disappeared. The walk may be tried again."""

    def __init__(self, folder: Path, reason: str) -> None:
        self.folder = folder
        self.reason = reason
        super().__init__(reason)


@dataclass
class _CoverScan:
    remaining: dict[tuple[int, int], int]
    seen_paths: set[str]
    seen_dirs: set[tuple[int, int, str]]
    covered: set[str]
    stop_early: bool
    masked: list[str]
    exposed: list[str]
    argv: list[str]
    scanned: int = 0


def _account_scan_error(problem: str) -> SandboxError:
    detail = _public_scan_problem(problem)
    return SandboxError(
        "refusing to launch; the account-data scan did not finish (" + detail + ")"
    )


def _public_scan_problem(problem: str) -> str:
    """Drop absolute account-data paths from a reason string."""
    from praxis_prime.paths import runtime_dir
    from praxis_prime.policy.boundary import _account_data_roots

    text = problem
    roots: list[Path] = list(_account_data_roots() or [])
    try:
        roots.append(runtime_dir())
    except OSError:
        pass
    for root in roots:
        root_s = str(root).rstrip("/")
        if not root_s:
            continue
        text = text.replace(root_s + os.sep, "")
        text = text.replace(root_s + "/", "")
        if root_s in text:
            text = text.replace(root_s, "the account data directory")
    return text


def _errno_reason(exc: OSError | None) -> str:
    if exc is None:
        return "could not be read"
    if exc.errno in {errno.EACCES, errno.EPERM}:
        return "permission denied"
    if exc.errno in {errno.ENOENT, errno.ENOTDIR}:
        return "a directory vanished during the scan"
    if exc.errno == errno.ENAMETOOLONG:
        return "a path is too long"
    if exc.errno == errno.ELOOP:
        return "too many symlinks"
    return exc.strerror or "could not be read"


def _show_folder(folder: Path) -> str:
    from praxis_prime.policy.boundary import _account_relative

    relative = _account_relative(folder)
    if relative is not None:
        return relative
    return str(folder)


def _mount_error(
    folder: Path, exc: OSError | None = None, reason: str = ""
) -> SandboxError:
    why = reason or _errno_reason(exc)
    return SandboxError(
        "refusing to launch; a mount could not be scanned "
        f"({_show_folder(folder)}: {why})"
    )


def _gone(exc: OSError) -> bool:
    return exc.errno in {errno.ENOENT, errno.ENOTDIR}


def _scan_kind(path: Path) -> str:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return "missing"
    except OSError as exc:
        if _gone(exc):
            return "missing"
        raise _mount_error(path, exc) from exc
    if stat.S_ISREG(info.st_mode):
        return "file"
    if stat.S_ISDIR(info.st_mode):
        return "dir"
    return "other"


def _note_scan(scanned: int) -> int:
    scanned += 1
    if scanned > _HARDLINK_SCAN_CAP:
        raise SandboxError(
            "refusing to launch; more than "
            f"{_HARDLINK_SCAN_CAP} hard-linked files to check because account "
            "data has another name on disk (accounts.db-wal, accounts.db-shm, "
            "accounts.db-journal, and the same sidecars for audit.db and "
            "prime.db, plus SOUL.md, worker-master.key, and gateway.token). "
            "Remove those extra links, or run from a smaller directory."
        )
    return scanned


def _links_found(remaining: dict[tuple[int, int], int]) -> bool:
    return all(count <= 0 for count in remaining.values())


def _finished(scan: _CoverScan) -> bool:
    return scan.stop_early and _links_found(scan.remaining)


def _cover_mounts(
    mounts: list[tuple[Path, str]],
    masked: list[str],
    exposed: list[str],
    remaining: dict[tuple[int, int], int],
) -> list[str]:
    chosen, overlap = _mounts_to_walk(mounts)
    scan = _CoverScan(
        remaining=remaining,
        seen_paths=set(),
        seen_dirs=set(),
        covered=set(),
        # A later mount can show a link the first mount already counted.
        # Stop early only when this launch has a single tree to walk.
        stop_early=not overlap and len(chosen) <= 1,
        masked=masked,
        exposed=exposed,
        argv=[],
    )
    for host, dest in chosen:
        if _finished(scan):
            break
        kind = _scan_kind(host)
        if kind == "missing":
            raise _Vanished(host, "a mount vanished during the scan")
        if kind == "file":
            _cover_file(host, dest, scan)
            continue
        if kind != "dir":
            raise _mount_error(host, reason="not a directory")
        _cover_tree(host, dest, scan)
    return scan.argv


def _mounts_to_walk(
    mounts: list[tuple[Path, str]],
) -> tuple[list[tuple[Path, str]], bool]:
    """Drop a nested mount whose sandbox path is already inside another.

    The second value is true when two mounts still share a host tree but
    their sandbox paths differ, so the walk must not stop early.
    """
    planned: list[tuple[Path, str]] = []
    for src, dest in mounts:
        if _skip_hardlink_scan(dest):
            continue
        try:
            host = Path(os.path.realpath(src, strict=False))
        except OSError as exc:
            if _gone(exc):
                raise _Vanished(Path(src), "a mount vanished during the scan") from exc
            raise _mount_error(Path(src), exc) from exc
        planned.append((host, dest))
    skip: set[int] = set()
    overlap = False
    for index, (host, dest) in enumerate(planned):
        for other, (outer_host, outer_dest) in enumerate(planned):
            if index == other:
                continue
            if host == outer_host:
                if _same_sandbox(dest, outer_dest) and index > other:
                    skip.add(index)
                elif not _same_sandbox(dest, outer_dest):
                    overlap = True
                continue
            if not _is_within(host, outer_host):
                continue
            relative = host.relative_to(outer_host)
            expected = Path(outer_dest) / relative
            if _same_sandbox(dest, expected):
                skip.add(index)
            else:
                overlap = True
    chosen = [item for number, item in enumerate(planned) if number not in skip]
    return chosen, overlap


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def _same_sandbox(left: str | Path, right: str | Path) -> bool:
    return os.path.normpath(str(left)) == os.path.normpath(str(right))


def _list_mount(directory: Path) -> list[os.DirEntry[str]]:
    """List ``directory``. A vanished directory is retried once, then raised."""
    try:
        return list(os.scandir(directory))
    except OSError as exc:
        if not _gone(exc):
            raise _mount_error(directory, exc) from exc
    try:
        return list(os.scandir(directory))
    except OSError as exc:
        if _gone(exc):
            raise _Vanished(directory, "a directory vanished during the scan") from exc
        raise _mount_error(directory, exc) from exc


def _lstat_mount(path: Path) -> os.stat_result:
    try:
        return os.lstat(path)
    except OSError as exc:
        if not _gone(exc):
            raise _mount_error(path, exc) from exc
    try:
        return os.lstat(path)
    except OSError as exc:
        if _gone(exc):
            raise _Vanished(path, "a file vanished during the scan") from exc
        raise _mount_error(path, exc) from exc


def _lstat_entry(entry: os.DirEntry[str]) -> os.stat_result:
    path = Path(entry.path)
    try:
        return entry.stat(follow_symlinks=False)
    except OSError as exc:
        if not _gone(exc):
            raise _mount_error(path, exc) from exc
    try:
        return entry.stat(follow_symlinks=False)
    except OSError as exc:
        if _gone(exc):
            raise _Vanished(path, "a file vanished during the scan") from exc
        raise _mount_error(path, exc) from exc


def _already_seen(host: Path, scan: _CoverScan) -> bool:
    """True when this directory entry was already counted.

    The real path catches a symlink and a direct name. The parent device,
    parent inode, and filename catch the same entry seen through two mounts,
    including a bind-mount alias whose real path differs.
    """
    try:
        resolved = os.path.realpath(host, strict=False)
    except OSError as exc:
        raise _mount_error(host, exc) from exc
    try:
        parent = os.lstat(host.parent)
    except OSError as exc:
        if _gone(exc):
            raise _Vanished(host.parent, "a directory vanished during the scan") from exc
        raise _mount_error(host.parent, exc) from exc
    dir_key = (parent.st_dev, parent.st_ino, host.name)
    seen = resolved in scan.seen_paths or dir_key in scan.seen_dirs
    scan.seen_paths.add(resolved)
    scan.seen_dirs.add(dir_key)
    return seen


def _emit_cover(dest: str, scan: _CoverScan) -> None:
    if dest in scan.covered:
        return
    scan.covered.add(dest)
    if _under_mask(dest, scan.masked, scan.exposed):
        return
    scan.argv.extend(["--ro-bind", "/dev/null", dest])


def _bulky_dir(parent: str, name: str) -> bool:
    """True for trees that are large and are scanned only if a link is left.

    ``node_modules`` and ``.git/objects`` are not followed as symlinks.
    A hard link of a protected inode inside them is still covered, after
    the rest of the mount has been checked.
    """
    if name == "node_modules":
        return True
    return name == "objects" and os.path.basename(parent) == ".git"


def _cover_file(host: Path, dest: str, scan: _CoverScan) -> None:
    info = _lstat_mount(host)
    _cover_stat(host, dest, info, scan)


def _cover_stat(host: Path, dest: str, info: os.stat_result, scan: _CoverScan) -> None:
    if not stat.S_ISREG(info.st_mode) or info.st_nlink <= 1:
        return
    key = (info.st_dev, info.st_ino)
    if key not in scan.remaining:
        return
    if _already_seen(host, scan):
        _emit_cover(dest, scan)
        return
    scan.scanned = _note_scan(scan.scanned)
    if scan.remaining[key] > 0:
        scan.remaining[key] -= 1
    _emit_cover(dest, scan)


def _cover_tree(root: Path, dest: str, scan: _CoverScan) -> None:
    _cover_descent(root, dest, scan, defer_bulky=True)


def _cover_bulky(root: Path, dest: str, scan: _CoverScan) -> None:
    """Walk a deferred tree. Symlinks are not followed."""
    kind = _scan_kind(root)
    if kind == "missing":
        raise _Vanished(root, "a directory vanished during the scan")
    if kind == "file":
        _cover_file(root, dest, scan)
        return
    if kind != "dir":
        return
    _cover_descent(root, dest, scan, defer_bulky=False)


def _cover_descent(root: Path, dest: str, scan: _CoverScan, *, defer_bulky: bool) -> None:
    """List ``root`` with ``os.scandir``. A listing error refuses the launch.

    ``os.walk`` without ``onerror`` skips a directory it cannot list. A mode
    ``0300`` directory would hide a hard link. Symlinks are not followed.
    A vanished entry is retried by the caller. Permission errors are not.
    """
    from praxis_prime.policy.boundary import _SCAN_DEPTH_LIMIT

    bulky: list[tuple[Path, str]] = []
    pending: list[tuple[Path, str, int]] = [(root, dest, 1)]
    while pending:
        if _finished(scan):
            return
        directory, sandbox_dir, depth = pending.pop()
        if depth > _SCAN_DEPTH_LIMIT:
            raise SandboxError(
                "refusing to launch; a directory tree is too deep to scan for hard links "
                f"({_show_folder(directory)}: too deep)"
            )
        entries = _list_mount(directory)
        children: list[tuple[Path, str, int]] = []
        for entry in entries:
            if _finished(scan):
                return
            info = _lstat_entry(entry)
            child_dest = str(Path(sandbox_dir) / entry.name)
            if stat.S_ISLNK(info.st_mode):
                continue
            if stat.S_ISDIR(info.st_mode):
                child = Path(directory) / entry.name
                if defer_bulky and _bulky_dir(str(directory), entry.name):
                    bulky.append((child, child_dest))
                else:
                    children.append((child, child_dest, depth + 1))
                continue
            _cover_stat(Path(directory) / entry.name, child_dest, info, scan)
        pending.extend(reversed(children))
    if not defer_bulky or _finished(scan):
        return
    for host, sandbox in bulky:
        if _finished(scan):
            break
        _cover_bulky(host, sandbox, scan)


def _skip_hardlink_scan(dest: str) -> bool:
    """True for a read-only system bind, not for a workspace under that tree."""
    return dest in _RO_SYSTEM_BINDS


def _under_mask(sandbox: str, masked: list[str], exposed: list[str]) -> bool:
    if any(_path_under(sandbox, root) for root in exposed):
        return False
    return any(_path_under(sandbox, root) for root in masked)


def _path_under(path: str, root: str) -> bool:
    if not root:
        return False
    prefix = root.rstrip("/")
    return path == prefix or path.startswith(prefix + "/")


def _data_dir_mask(mounts: list[tuple[Path, str]]) -> list[str]:
    """Hide every account-data root a bind mount contains.

    A later ``--tmpfs`` covers that directory path inside the sandbox.
    Containment of the directory is by real path and by ``(st_dev, st_ino)``,
    so a bind-mount alias of a parent is masked too. A hard link of a
    private file planted outside that directory is covered with a
    ``/dev/null`` bind when its inode is known and ``nlink`` is greater
    than one. A scan that stops early refuses the launch.
    A bind that sits inside a data directory is refused. ``pushd`` and
    ``popd`` are not tracked. Every root ``account_data_present`` considers
    is masked,
    including the default XDG tree when ``--data-dir`` points somewhere
    else. A root that is not on any mount is left alone.
    """
    from praxis_prime.policy.boundary import _account_data_roots

    roots = _account_data_roots()
    if not roots:
        return []
    masked: list[str] = []
    seen: set[str] = set()
    for root in roots:
        masked.extend(_mask_one_data_root(mounts, root, seen))
    return masked


def _mask_one_data_root(
    mounts: list[tuple[Path, str]],
    root: Path,
    seen: set[str],
) -> list[str]:
    from praxis_prime.statfile import StatKind, lstat_kind

    try:
        data = Path(os.path.realpath(root, strict=False))
    except OSError:
        return []
    if lstat_kind(data) is not StatKind.DIR:
        return []
    masked: list[str] = []
    for src, dest in mounts:
        _refuse_bind_inside_data(src, data)
        relative = _data_relative_to_mount(src, data)
        if relative is None:
            continue
        sandbox = str(Path(dest) / relative)
        if sandbox in seen:
            continue
        seen.add(sandbox)
        masked.extend(["--tmpfs", sandbox])
    return masked


def _file_id(path: Path) -> tuple[int, int] | None:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_dev, st.st_ino)


def _data_relative_to_mount(mount: Path, data: Path) -> Path | None:
    """Path of ``data`` inside ``mount``, or None when ``mount`` does not contain it.

    Walks ``data`` and its ancestors and matches ``(st_dev, st_ino)``, so a
    bind-mount alias of a parent counts. A realpath prefix is the same check
    when the two paths are not aliases.
    """
    mount_id = _file_id(mount)
    current = data
    parts: list[str] = []
    while mount_id is not None:
        ident = _file_id(current)
        if ident is not None and ident == mount_id:
            if not parts:
                return None
            return Path(*reversed(parts))
        parent = current.parent
        if parent == current:
            break
        parts.append(current.name)
        current = parent
    try:
        mount_real = Path(os.path.realpath(mount, strict=False))
        data_real = Path(os.path.realpath(data, strict=False))
        relative = data_real.relative_to(mount_real)
    except (OSError, ValueError):
        return None
    if relative == Path("."):
        return None
    return relative


def _bind_source(path: Path) -> Path:
    """Real path of a bind. A symlink is the target, not the link path."""
    try:
        return Path(os.path.realpath(path, strict=False))
    except OSError as exc:
        raise SandboxError(
            "refusing to bind a directory inside the account data directory"
        ) from exc


def _refuse_bind_inside_data(mount: Path, data: Path) -> None:
    """Refuse a bind of the data directory or a path inside it.

    The source is already resolved, so ``worktrees/lnk -> ../profiles`` is
    the profile tree and is refused. A coding task may be bound only when
    it is one git worktree. With no profile bound and no ``profiles``
    directory, that is ``worktrees/<repo>/<task>``. Once a profile is
    bound or ``profiles/`` exists, it is ``worktrees/<profile>/<repo>/<task>``,
    and a bound profile must match the path. ``worktrees/`` itself, a repo
    directory that holds several tasks, a host-planted ``.git`` on a
    shorter path, and every other path inside the data directory are
    refused. A tmpfs cannot hide a directory from a mount that is already
    inside it.
    """
    relative = _path_inside(mount, data)
    if relative is None:
        return
    if _is_task_worktree(mount, relative):
        return
    raise SandboxError("refusing to bind a directory inside the account data directory")


def _is_task_worktree(mount: Path, relative: Path) -> bool:
    """True for one git worktree, not ``worktrees/`` or a parent of several.

    Three segments (``worktrees/<repo>/<task>``) are a worktree only when
    no profile is bound and the data directory has no ``profiles`` folder.
    Otherwise the path needs four segments and, when a profile is bound,
    the second segment has to be that profile. A ``.git`` planted at
    ``worktrees/<profile>/<repo>`` is three segments and is not a task.
    """
    parts = relative.parts
    if not parts or parts[0] != "worktrees":
        return False
    from praxis_prime.statfile import StatKind, lstat_kind

    if lstat_kind(mount / ".git") not in {StatKind.FILE, StatKind.DIR}:
        return False
    try:
        data = mount.parents[len(parts) - 1]
    except IndexError:
        return False
    profile = bound_profile()
    profiles = lstat_kind(data / "profiles")
    profiles_present = profiles in {StatKind.DIR, StatKind.SYMLINK, StatKind.UNREADABLE}
    if profile or profiles_present:
        if len(parts) != 4:
            return False
        if profile and parts[1] != profile:
            return False
        return True
    return len(parts) == 3


def _path_inside(child: Path, parent: Path) -> Path | None:
    """Relative path of ``child`` under ``parent``, or ``.`` when they are the same file.

    None when ``child`` is not inside ``parent``. Device and inode are checked
    first so a bind-mount alias matches, then the real path.
    """
    parent_id = _file_id(parent)
    current = child
    parts: list[str] = []
    while parent_id is not None:
        ident = _file_id(current)
        if ident is not None and ident == parent_id:
            if not parts:
                return Path(".")
            return Path(*reversed(parts))
        nxt = current.parent
        if nxt == current:
            break
        parts.append(current.name)
        current = nxt
    try:
        child_real = Path(os.path.realpath(child, strict=False))
        parent_real = Path(os.path.realpath(parent, strict=False))
        return child_real.relative_to(parent_real)
    except (OSError, ValueError):
        return None


def run_bwrap(
    command: str,
    cwd: Path,
    cancelled: Callable[[], bool],
    *,
    timeout: float = 30,
    env: Mapping[str, str] | None = None,
    writable: bool = False,
    scope: Path | None = None,
    main_checkout: Path | None = None,
    ro_binds: list[tuple[str, str]] | None = None,
) -> str:
    """Run ``command`` inside bubblewrap. Never falls back to the host."""
    if not bwrap_available():
        raise SandboxError(
            "bubblewrap is not available; the command was not run on the host"
        )
    argv = build_bwrap_argv(
        command,
        cwd,
        writable=writable,
        scope=scope,
        main_checkout=main_checkout,
        ro_binds=ro_binds,
    )
    source = os.environ if env is None else env
    try:
        return run_process(
            argv,
            cwd=cwd,
            cancelled=cancelled,
            timeout=timeout,
            env=scrub_env(source),
        )
    except OSError as exc:
        raise SandboxError(
            f"bubblewrap failed to start ({exc}); the command was not run on the host"
        ) from exc


def run_bwrap_status(
    command: str,
    cwd: Path,
    cancelled: Callable[[], bool],
    *,
    timeout: float = 30,
    env: Mapping[str, str] | None = None,
    stdin: str = "",
    writable: bool = False,
    scope: Path | None = None,
    main_checkout: Path | None = None,
    ro_binds: list[tuple[str, str]] | None = None,
) -> CommandStatus:
    """Run ``command`` inside bubblewrap and return its exit code."""
    if not bwrap_available():
        raise SandboxError(
            "bubblewrap is not available; the command was not run on the host"
        )
    argv = build_bwrap_argv(
        command,
        cwd,
        writable=writable,
        scope=scope,
        main_checkout=main_checkout,
        ro_binds=ro_binds,
    )
    source = os.environ if env is None else env
    try:
        return run_captured(
            argv,
            cwd=cwd,
            cancelled=cancelled,
            timeout=timeout,
            env=scrub_env(source),
            stdin=stdin,
        )
    except OSError as exc:
        raise SandboxError(
            f"bubblewrap failed to start ({exc}); the command was not run on the host"
        ) from exc


def run_host_status(
    command: str,
    cwd: Path,
    cancelled: Callable[[], bool],
    *,
    timeout: float = 30,
    env: Mapping[str, str] | None = None,
    stdin: str = "",
) -> CommandStatus:
    """Run a command on the host and return its exit code.

    Callers that use this for a shell tool must already have an approval.
    Project hooks use it only when bubblewrap is missing, and only with a
    scrubbed environment.
    """
    source = os.environ if env is None else env
    return run_captured(
        ["bash", "--noprofile", "--norc", "-c", command],
        cwd=cwd,
        cancelled=cancelled,
        timeout=timeout,
        env=scrub_env(source),
        stdin=stdin,
    )


def run_host_shell(
    command: str,
    cwd: Path,
    cancelled: Callable[[], bool],
    *,
    timeout: float = 30,
    env: Mapping[str, str] | None = None,
) -> str:
    """Run a command on the host. Callers must already have an approval."""
    source = os.environ if env is None else env
    return run_process(
        ["bash", "--noprofile", "--norc", "-c", command],
        cwd=cwd,
        cancelled=cancelled,
        timeout=timeout,
        env=scrub_env(source),
    )


def scrub_env(source: Mapping[str, str]) -> dict[str, str]:
    """Drop credential-shaped variables before a shell starts."""
    blocked_prefixes = (
        "OPENAI_",
        "ANTHROPIC_",
        "XAI_",
        "PRAXIS_PRIME_",
        "AWS_",
        "AZURE_",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "NPM_TOKEN",
    )
    blocked_names = {"BASH_ENV", "ENV", "SHELLOPTS"}
    cleaned: dict[str, str] = {}
    for key, value in source.items():
        upper = key.upper()
        if upper in blocked_names or upper.startswith("BASH_FUNC_"):
            continue
        if upper.startswith(blocked_prefixes):
            continue
        if any(part in upper for part in ("SECRET", "TOKEN", "PASSWORD", "API_KEY", "APIKEY")):
            continue
        cleaned[key] = value
    return cleaned


def run_captured(
    argv: list[str],
    *,
    cwd: Path,
    cancelled: Callable[[], bool],
    timeout: float,
    env: dict[str, str] | None,
    stdin: str = "",
) -> CommandStatus:
    """Run ``argv`` and return the exit code. Does not fall back to another command."""
    if cancelled():
        raise SandboxError("command cancelled")
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    waited = 0.0
    try:
        if proc.stdin is not None:
            try:
                proc.stdin.write(stdin)
                proc.stdin.close()
            except BrokenPipeError:
                pass
            # communicate() refuses a stdin handle that is already closed.
            proc.stdin = None
        while True:
            if cancelled():
                _kill(proc)
                raise SandboxError("command cancelled")
            try:
                stdout, stderr = proc.communicate(timeout=0.2)
                break
            except subprocess.TimeoutExpired:
                waited += 0.2
                if waited >= timeout:
                    _kill(proc)
                    raise SandboxError(f"command timed out after {timeout:.0f}s") from None
        code = proc.returncode if proc.returncode is not None else 1
        output = _combine(stdout, stderr, None)
        return CommandStatus(code=code, output=output, stdout=stdout or "")
    finally:
        if proc.poll() is None:
            _kill(proc)


def run_process(
    argv: list[str],
    *,
    cwd: Path,
    cancelled: Callable[[], bool],
    timeout: float,
    env: dict[str, str] | None,
) -> str:
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    waited = 0.0
    try:
        while True:
            if cancelled():
                _kill(proc)
                raise SandboxError("command cancelled")
            try:
                stdout, stderr = proc.communicate(timeout=0.2)
                break
            except subprocess.TimeoutExpired:
                waited += 0.2
                if waited >= timeout:
                    _kill(proc)
                    raise SandboxError(f"command timed out after {timeout:.0f}s") from None
        return _combine(stdout, stderr, proc.returncode)
    finally:
        if proc.poll() is None:
            _kill(proc)


def _contains(parent: Path, child: Path) -> bool:
    """True when ``child`` is strictly inside ``parent``."""
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return parent != child


def _kill(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        proc.kill()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()


def _combine(stdout: str, stderr: str, code: int | None) -> str:
    parts: list[str] = []
    if stdout:
        parts.append(stdout.rstrip("\n"))
    if stderr:
        parts.append(stderr.rstrip("\n"))
    if code not in (0, None):
        parts.append(f"(exit {code})")
    return "\n".join(parts) if parts else "(no output)"
