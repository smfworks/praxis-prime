"""Move a single-user install into the ``default`` profile.

The move is idempotent. The first run copies ``prime.db`` (and its WAL
sidecars) into ``backups/`` before the file is placed under
``profiles/default/``. A second run sees the marker and does not copy
again. User skills are copied, not removed from the config directory.

docs/blueprint-addendum-2026-09.md §6.3.
"""

from __future__ import annotations

import errno
import json
import os
import secrets
import sqlite3
import stat
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from praxis_prime.privatefile import tighten_dir, tighten_file
from praxis_prime.profiles.home import ProfileHome, create_profile, migration_marker
from praxis_prime.profiles.policy import render_policy_toml
from praxis_prime.statfile import StatKind, lstat_kind

_SIDECARS = ("", "-wal", "-shm", "-journal")


@dataclass(frozen=True, slots=True)
class MigrationResult:
    profile_id: str
    backup: str
    already: bool
    owner_account: str


class MigrationBusy(RuntimeError):
    """The daemon is running, so the database must not be moved."""


def daemon_is_running() -> bool:
    """True when a healthy ``praxis-primed`` is published in the runtime dir."""
    from praxis_prime.gateway.discover import discover

    return discover() is not None


def migration_lock_path(data_root: Path) -> Path:
    """Held for the whole move. The daemon refuses to start while it exists."""
    return Path(data_root) / ".migration.lock"


def migration_in_progress(data_root: Path) -> bool:
    """True when a lock file is present, including a stale one.

    A dead pid still means the move may be half done. ``profile migrate``
    is what clears that lock, after it finishes the move. An empty lock,
    a garbage lock, or a reused pid is stale and ``profile migrate``
    replaces it. ``--force`` replaces a lock that still names a live process.
    """
    return lstat_kind(migration_lock_path(data_root)) is not StatKind.MISSING


def migration_lock_hint(data_root: Path) -> str:
    """Daemon and CLI text: where the lock is, and how to clear it."""
    path = migration_lock_path(data_root)
    return (
        f"a profile migration lock is present ({path}). "
        "Finish the move with `praxis-prime profile migrate`. "
        "If that refuses, `praxis-prime profile migrate --force` replaces a "
        "leftover lock. --force does not override an open prime.db."
    )


def acquire_migration_lock(data_root: Path, *, force: bool = False) -> Path:
    """Create the lock, replacing one whose process is gone.

    The file records the pid and that process's start time. A live pid
    with a different start time was reused and is stale. ``force`` replaces
    a lock that still matches a live process. An open ``prime.db`` is a
    separate flock and is not overridden.
    """
    root = Path(data_root)
    root.mkdir(parents=True, exist_ok=True)
    path = migration_lock_path(root)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    for _attempt in range(2):
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            if not force and not _lock_is_stale(path):
                raise MigrationBusy(migration_lock_hint(root)) from None
            if not _remove_lock_file(path):
                raise MigrationBusy(migration_lock_hint(root)) from None
            continue
        try:
            os.write(fd, _lock_payload().encode())
        finally:
            os.close(fd)
        return path
    raise MigrationBusy(migration_lock_hint(root))


def release_migration_lock(path: Path) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        return
    except OSError:
        return


def migrate_under_lock(
    data_root: Path,
    config_dir: Path | None = None,
    *,
    owner_account: str = "",
    daemon_running: Callable[[], bool] | None = None,
    force: bool = False,
) -> MigrationResult:
    """Migrate while holding the lock the daemon checks at startup.

    The running check happens again after the database flock is held and
    before ``.migration.lock`` is replaced. A daemon that appears in that
    window makes this raise ``MigrationBusy`` before the pid lock changes.
    The lock stays if the move fails after it has started and the marker
    was not written. ``force`` replaces a pid lock that still looks live.
    It does not steal the ``prime.db`` flock.

    When the database still has to move, the exclusive flock is taken
    before ``.migration.lock`` is removed or replaced. A busy database
    leaves the existing lock file untouched.
    """
    running = daemon_is_running if daemon_running is None else daemon_running
    if running():
        raise MigrationBusy(
            "stop praxis-primed before creating the first account; "
            "it still has prime.db open"
        )
    root = Path(data_root)
    marker = migration_marker(root)
    marker_kind = _kind(marker)
    if marker_kind not in {StatKind.MISSING, StatKind.FILE}:
        raise OSError(errno.EPERM, "migration marker is not a regular file", str(marker))
    if marker_kind is StatKind.FILE:
        return _finish_under_migration_lock(
            root,
            config_dir,
            owner_account,
            force,
            move=False,
        )
    from praxis_prime.state import release_db_locks

    held = _hold_exclusive_db_locks(root)
    try:
        if running():
            raise MigrationBusy(
                "stop praxis-primed before creating the first account; "
                "it still has prime.db open"
            )
        return _finish_under_migration_lock(
            root,
            config_dir,
            owner_account,
            force,
            move=True,
        )
    finally:
        release_db_locks(held)


def _finish_under_migration_lock(
    root: Path,
    config_dir: Path | None,
    owner_account: str,
    force: bool,
    *,
    move: bool,
) -> MigrationResult:
    """Replace the pid lock only after the caller has checked the daemon.

    ``move`` is true only when the caller already holds the database flock.
    A busy flock never reaches this function, so ``--force`` cannot delete
    the pid lock and then fail. ``move`` is false when the marker is already
    a regular file; that path does not relocate ``prime.db``.
    """
    lock = acquire_migration_lock(root, force=force)
    keep = False
    try:
        if move:
            return _migrate_holding_locks(root, config_dir, owner_account)
        return migrate_single_user(
            root,
            config_dir,
            owner_account=owner_account,
            daemon_running=lambda: False,
        )
    except MigrationBusy:
        raise
    except Exception:
        if _kind(migration_marker(root)) is not StatKind.FILE:
            keep = True
        raise
    finally:
        if not keep:
            release_migration_lock(lock)


def _lock_is_stale(path: Path) -> bool:
    """True when the lock is not a live process with the recorded start time.

    Empty and garbage contents are stale. A pid that is alive but started
    at a different time was reused. A non-regular file is not stale; ``--force``
    is what removes it.
    """
    if lstat_kind(path) is not StatKind.FILE:
        return False
    pid, start = _read_lock_identity(path)
    if pid is None:
        return True
    if not _pid_alive(pid):
        return True
    # A live pid with no start time was written when ``/proc`` had no
    # starttime. It is not stale; ``--force`` is what replaces it.
    # A dead pid-only lock stays stale. A mismatched start time stays stale.
    if start is None:
        return False
    current = _process_starttime(pid)
    if current is None or current != start:
        return True
    return False


def _read_lock_identity(path: Path) -> tuple[int | None, str | None]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None, None
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines or not lines[0].isdigit():
        return None, None
    start = lines[1] if len(lines) > 1 and lines[1].isdigit() else None
    return int(lines[0]), start


def _lock_payload() -> str:
    pid = os.getpid()
    start = _process_starttime(pid)
    if start is None:
        return f"{pid}\n"
    return f"{pid}\n{start}\n"


def _process_starttime(pid: int) -> str | None:
    """Clock ticks since boot, from ``/proc/<pid>/stat`` field 22.

    A reused pid has a different start time. The comm field may contain
    spaces, so the clock fields are read after the last ``)``.
    """
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return None
    end = raw.rfind(")")
    if end < 0:
        return None
    fields = raw[end + 2 :].split()
    # Field 3 is index 0 after the comm field. Field 22 is starttime.
    if len(fields) <= 19 or not fields[19].isdigit():
        return None
    return fields[19]


def _remove_lock_file(path: Path) -> bool:
    """Unlink a regular file or a symlink. Never follow the link, never rmdir."""
    kind = lstat_kind(path)
    if kind is StatKind.MISSING:
        return True
    if kind is StatKind.DIR or kind is StatKind.UNREADABLE:
        return False
    try:
        os.unlink(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return True


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def migrate_single_user(
    data_root: Path,
    config_dir: Path | None = None,
    *,
    owner_account: str = "",
    daemon_running: Callable[[], bool] | None = None,
) -> MigrationResult:
    """Migrate once. A later call returns the recorded result.

    Refuses while the daemon is up. Moving ``prime.db`` out from under an
    open connection drops its writes.
    """
    root = Path(data_root)
    marker = migration_marker(root)
    marker_kind = _kind(marker)
    if marker_kind is StatKind.FILE:
        recorded = _read_marker(marker)
        if owner_account and not recorded.owner_account:
            _write_marker(marker, recorded.profile_id, recorded.backup, owner_account)
            return MigrationResult(
                recorded.profile_id,
                recorded.backup,
                True,
                owner_account,
            )
        return MigrationResult(recorded.profile_id, recorded.backup, True, recorded.owner_account)
    if marker_kind is not StatKind.MISSING:
        raise OSError(errno.EPERM, "migration marker is not a regular file", str(marker))

    running = daemon_is_running if daemon_running is None else daemon_running
    if running():
        raise MigrationBusy(
            "stop praxis-primed before creating the first account; "
            "it still has prime.db open"
        )
    held = _hold_exclusive_db_locks(root)
    try:
        return _migrate_holding_locks(root, config_dir, owner_account)
    finally:
        from praxis_prime.state import release_db_locks

        release_db_locks(held)


def _hold_exclusive_db_locks(root: Path) -> list[int]:
    """Lock the database a holder would have open. Never the destination alone.

    ``create_profile`` opens ``profiles/default/prime.db`` in this process.
    An exclusive lock on that path would deadlock the shared lock ``StateDB``
    takes. The destination is locked only when a legacy file is about to move,
    which does not open ``StateDB``.
    """
    from praxis_prime.state import DatabaseBusy, acquire_exclusive_db_locks

    legacy = root / "prime.db"
    moving = _is_data_file(legacy) or _any_legacy(root)
    paths = [legacy]
    if moving:
        paths.append(ProfileHome(root, "default").db_path)
    try:
        return acquire_exclusive_db_locks(paths)
    except DatabaseBusy as exc:
        raise MigrationBusy(str(exc)) from exc


def _migrate_holding_locks(
    root: Path,
    config_dir: Path | None,
    owner_account: str,
) -> MigrationResult:
    marker = migration_marker(root)
    home = ProfileHome(root, "default")
    backup_rel = ""
    legacy = root / "prime.db"
    legacy_present = _is_data_file(legacy)
    home_present = _is_data_file(home.db_path)
    if home_present and not legacy_present and not _any_legacy(root):
        _ensure_tree(home, config_dir)
    elif legacy_present or _any_legacy(root):
        backup_rel = _backup_legacy(root, home)
        _ensure_tree(home, config_dir)
        _copy_skills(config_dir, home)
        _apply_config_dials(config_dir, home)
    else:
        create_profile(
            root,
            "default",
            display_name="Default",
            allow_during_migration=True,
        )
        _copy_skills(config_dir, home)
        _apply_config_dials(config_dir, home)
    _write_marker(marker, "default", backup_rel, owner_account)
    return MigrationResult("default", backup_rel, False, owner_account)


def _ensure_tree(home: ProfileHome, config_dir: Path | None) -> None:
    if home.exists():
        home.skills_dir.mkdir(parents=True, exist_ok=True)
        home.routines_dir.mkdir(parents=True, exist_ok=True)
        tighten_dir(home.path)
        return
    home.path.mkdir(parents=True, exist_ok=True)
    tighten_dir(home.path)
    home.skills_dir.mkdir(parents=True, exist_ok=True)
    home.routines_dir.mkdir(parents=True, exist_ok=True)
    if _kind(home.config_path) is StatKind.MISSING:
        text = render_policy_toml(
            table="profile",
            schema="praxis.profile/v1",
            profile="default",
            name="Default",
        )
        _write_new_file(home.config_path, text.encode())
    if _kind(home.soul_path) is StatKind.MISSING:
        _write_new_file(
            home.soul_path,
            b"# Persona\n\nSubordinate to the Praxis Prime safety rules.\n",
        )


def _backup_legacy(root: Path, home: ProfileHome) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup: Path | None = None
    for _ in range(8):
        candidate = root / "backups" / f"pre-profile-{stamp}-{secrets.token_hex(4)}"
        try:
            candidate.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            continue
        backup = candidate
        break
    if backup is None:
        raise FileExistsError("could not create a unique profile backup directory")
    tighten_dir(backup)
    legacy = root / "prime.db"
    if _kind(legacy) is StatKind.FILE:
        _checkpoint(legacy)
    for suffix in _SIDECARS:
        source = Path(f"{legacy}{suffix}") if suffix else legacy
        if not _is_data_file(source):
            continue
        target = backup / source.name
        _copy_classified(source, target)
    home.path.mkdir(parents=True, exist_ok=True)
    tighten_dir(home.path)
    if _is_data_file(legacy) and _kind(home.db_path) is StatKind.MISSING:
        home.db_path.parent.mkdir(parents=True, exist_ok=True)
        _place_database(legacy, home.db_path)
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(f"{legacy}{suffix}")
            if _kind(sidecar) in {StatKind.SYMLINK, StatKind.FILE}:
                sidecar.unlink()
    elif _is_data_file(legacy):
        held = backup / "legacy-left-in-place.txt"
        held.write_text(
            "profiles/default/prime.db already existed. The previous prime.db was copied here.\n",
            encoding="utf-8",
        )
        legacy.replace(backup / "prime.db.unmoved")
        tighten_file(backup / "prime.db.unmoved")
    relative = backup.relative_to(root).as_posix()
    return relative


def _copy_skills(config_dir: Path | None, home: ProfileHome) -> None:
    if config_dir is None:
        return
    source = config_dir / "skills"
    if _kind(source) is not StatKind.DIR:
        return
    home.skills_dir.mkdir(parents=True, exist_ok=True)
    for path in source.rglob("*"):
        # ``rglob`` does not follow directory links. A linked file is skipped
        # here so the copy cannot read through it.
        if _kind(path) is not StatKind.FILE:
            continue
        relative = path.relative_to(source)
        if any(part.startswith(".") or part == ".." for part in relative.parts):
            continue
        target = home.skills_dir / relative
        if _kind(target) is not StatKind.MISSING:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        _copy_classified(path, target)


def _apply_config_dials(config_dir: Path | None, home: ProfileHome) -> None:
    if config_dir is None or _kind(home.config_path) is not StatKind.FILE:
        return
    config = config_dir / "config.toml"
    if _kind(config) is not StatKind.FILE:
        return
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(config, flags)
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            loaded = tomllib.loads(handle.read())
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return
    raw = loaded.get("dials")
    if not isinstance(raw, dict) or not raw:
        return
    from praxis_prime.profiles.policy import load_layer

    try:
        layer = load_layer(home.config_path, table="profile")
    except ValueError:
        return
    if layer.dials:
        return
    text = render_policy_toml(
        table="profile",
        schema="praxis.profile/v1",
        profile="default",
        name="Default",
        dials={str(key): str(value) for key, value in raw.items()},
    )
    home.config_path.write_text(text, encoding="utf-8")
    tighten_file(home.config_path)


def _place_database(source: Path, dest: Path) -> None:
    """Move ``source`` onto ``dest`` as a regular file.

    A symlink is copied as bytes and unlinked. The target outside the
    data directory is left in place, and ``dest`` is not a symlink.
    """
    kind = _kind(source)
    if kind is StatKind.SYMLINK:
        _write_new_file(dest, source.read_bytes())
        source.unlink()
        return
    if kind is not StatKind.FILE:
        raise OSError(errno.EINVAL, f"not a database file: {source}", str(source))
    source.replace(dest)
    tighten_file(dest)


def _any_legacy(root: Path) -> bool:
    legacy = root / "prime.db"
    return any(_is_data_file(Path(f"{legacy}{suffix}")) for suffix in _SIDECARS if suffix)


def _kind(path: Path) -> StatKind:
    """Classify without following a symlink. Permission errors propagate.

    ``Path.is_file`` and ``Path.is_symlink`` on Python 3.14 return False
    when ``lstat`` is denied, which would treat a protected database as
    absent and migrate past it.
    """
    kind = lstat_kind(path)
    if kind is StatKind.UNREADABLE:
        raise OSError(errno.EACCES, f"cannot classify {path}", str(path))
    return kind


def _is_data_file(path: Path) -> bool:
    """True for a regular file or a symlink. Unreadable is an error."""
    return _kind(path) in {StatKind.FILE, StatKind.SYMLINK}


def _copy_classified(source: Path, dest: Path) -> None:
    """Copy ``source`` to a new regular file without following a swap."""
    kind = _kind(source)
    if kind is StatKind.FILE:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        src = os.open(source, flags)
        try:
            info = os.fstat(src)
            if not stat.S_ISREG(info.st_mode):
                raise OSError(errno.EPERM, f"refusing to copy {source}", str(source))
            with os.fdopen(src, "rb") as reader:
                src = -1
                payload = reader.read()
        finally:
            if src >= 0:
                os.close(src)
    elif kind is StatKind.SYMLINK:
        payload = source.read_bytes()
    else:
        raise OSError(errno.EINVAL, f"not a file: {source}", str(source))
    _write_new_file(dest, payload)


def _write_new_file(dest: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(dest, flags, 0o600)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)
    tighten_file(dest)


def _checkpoint(path: Path) -> None:
    try:
        conn = sqlite3.connect(path)
    except sqlite3.Error:
        return
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.Error:
        pass
    finally:
        conn.close()


def _read_marker(path: Path) -> MigrationResult:
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            loaded = json.loads(handle.read())
    except (OSError, UnicodeError, json.JSONDecodeError):
        return MigrationResult("default", "", True, "")
    if not isinstance(loaded, dict):
        return MigrationResult("default", "", True, "")
    return MigrationResult(
        str(loaded.get("profile") or "default"),
        str(loaded.get("backup") or ""),
        True,
        str(loaded.get("owner_account") or ""),
    )


def _write_marker(path: Path, profile: str, backup: str, owner_account: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tighten_dir(path.parent)
    kind = _kind(path)
    if kind not in {StatKind.MISSING, StatKind.FILE}:
        raise OSError(errno.EPERM, "migration marker is not a regular file", str(path))
    payload = {
        "version": 1,
        "profile": profile,
        "backup": backup,
        "owner_account": owner_account,
        "migrated_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    data = (json.dumps(payload, sort_keys=True) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, data)
    finally:
        os.close(descriptor)
    tighten_file(path)
