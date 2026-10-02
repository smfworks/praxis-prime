"""Lows from the mtime cache, data-dir layout, and worktree boundary."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from praxis_prime.policy.boundary import (
    _cached_private_inodes,
    bind_data_root,
    clear_data_inode_cache,
    data_inode_scans,
    is_secret_path,
    private_data_command,
)
from praxis_prime.profiles.home import create_profile, resolve_runtime_layout
from praxis_prime.profiles.migrate import migrate_under_lock
from praxis_prime.sandbox.bwrap import SandboxError, bind_profile, build_bwrap_argv
from praxis_prime.state import MigrationInProgress, StateDB


def _home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    home = tmp_path / "home"
    share = home / ".local" / "share"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(share))
    private = share / "praxis-prime"
    (private / "profiles" / "work").mkdir(parents=True)
    (private / "profiles" / "work" / "SOUL.md").write_text("secret\n", encoding="utf-8")
    bind_data_root(None)
    bind_profile(None)
    return home, private


def _age(root: Path) -> None:
    stale = time.time() - 30
    for directory, _subdirs, _files in os.walk(root):
        os.utime(directory, (stale, stale))


def test_fresh_directory_is_not_cached_and_sees_a_new_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, private = _home(tmp_path, monkeypatch)
    (home / "hello.txt").write_text("hi\n", encoding="utf-8")
    clear_data_inode_cache()
    before = data_inode_scans()
    assert not is_secret_path(home / "hello.txt")
    mid = data_inode_scans()
    assert mid == before + 1
    assert not is_secret_path(home / "hello.txt")
    assert data_inode_scans() == mid + 1
    secret = private / "profiles" / "work" / "late.txt"
    secret.write_text("late\n", encoding="utf-8")
    link = home / "late-link"
    os.link(secret, link)
    parent = secret.parent
    stamped = os.lstat(parent).st_mtime_ns
    os.utime(parent, ns=(stamped, stamped))
    assert is_secret_path(link)
    clear_data_inode_cache()
    bind_data_root(None)


def test_restored_mtime_still_rescans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, private = _home(tmp_path, monkeypatch)
    (home / "hello.txt").write_text("hi\n", encoding="utf-8")
    _age(private)
    clear_data_inode_cache()
    before = data_inode_scans()
    assert not is_secret_path(home / "hello.txt")
    assert data_inode_scans() == before + 1
    folder = private / "profiles" / "work"
    previous = os.lstat(folder).st_mtime_ns
    # The aging ``utime`` sets ctime to this tick. Wait so the new file's
    # directory ctime actually moves; restoring mtime must not hide it.
    time.sleep(0.02)
    secret = folder / "added.txt"
    secret.write_text("added\n", encoding="utf-8")
    link = home / "added-link"
    os.link(secret, link)
    os.utime(folder, ns=(previous, previous))
    assert is_secret_path(link)
    assert data_inode_scans() == before + 2
    clear_data_inode_cache()
    bind_data_root(None)


def test_partial_inode_set_is_checked_past_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, private = _home(tmp_path, monkeypatch)
    monkeypatch.setattr("praxis_prime.policy.boundary._PRIVATE_INODE_CAP", 3)
    secret = private / "profiles" / "work" / "secret.txt"
    secret.write_text("secret\n", encoding="utf-8")
    seen = home / "seen-link"
    os.link(secret, seen)
    backups = private / "backups"
    backups.mkdir()
    for index in range(10):
        (backups / f"f{index}").write_text("x\n", encoding="utf-8")
    (home / "hello.txt").write_text("hi\n", encoding="utf-8")
    _age(private)
    clear_data_inode_cache()
    assert is_secret_path(seen)
    inodes, problem = _cached_private_inodes(private.resolve())
    assert problem
    assert "more than 3 files" in problem
    missed = None
    for candidate in backups.iterdir():
        st = candidate.stat()
        if (st.st_dev, st.st_ino) not in inodes:
            missed = candidate
            break
    assert missed is not None
    missed_link = home / "missed-link"
    os.link(missed, missed_link)
    assert is_secret_path(missed_link)
    assert not is_secret_path(home / "hello.txt")
    clear_data_inode_cache()
    bind_data_root(None)


def test_cd_from_home_into_the_data_dir_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, _private = _home(tmp_path, monkeypatch)
    data = ".local/share/praxis-prime"
    assert private_data_command(f"cd {data}", home)
    assert private_data_command(f"cd {data}\ncat accounts.db", home)
    assert private_data_command(f"cd {data}\ncat profiles/work/SOUL.md", home)
    assert not private_data_command("echo hello", home)
    bind_data_root(None)


def test_profiles_directory_is_not_a_data_dir(tmp_path: Path) -> None:
    root = tmp_path / "data"
    root.mkdir()
    (root / "accounts.db").write_text("hash\n", encoding="utf-8")
    profiles = root / "profiles"
    profiles.mkdir()
    misplaced = profiles / "prime.db"
    with pytest.raises(ValueError, match="profiles directory"):
        resolve_runtime_layout(None, data_file=misplaced, profile=None)
    with pytest.raises(ValueError, match="profiles directory"):
        StateDB(misplaced)
    assert not misplaced.exists()
    named = tmp_path / "profiles"
    named.mkdir()
    database = named / "prime.db"
    opened = StateDB(database)
    opened.close()
    assert database.is_file()


def test_invalid_profile_directory_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "data"
    bad = root / "profiles" / "Bad_Name"
    bad.mkdir(parents=True)
    database = bad / "prime.db"
    with pytest.raises(ValueError, match="invalid profile id"):
        resolve_runtime_layout(None, data_file=database, profile=None)
    with pytest.raises(ValueError, match="invalid profile id"):
        StateDB(database)
    assert not database.exists()
    home = create_profile(root, "work")
    layout = resolve_runtime_layout(None, data_file=home.db_path, profile=None)
    assert layout.profile_id == "work"


def test_create_profile_refuses_during_migration(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / ".migration.lock").write_text(f"{os.getpid()}\n", encoding="utf-8")
    with pytest.raises(MigrationInProgress, match="migration in progress"):
        create_profile(data, "work")
    assert not (data / "profiles" / "work" / "prime.db").exists()
    config = tmp_path / "config"
    config.mkdir()
    (data / ".migration.lock").unlink()
    result = migrate_under_lock(data, config, daemon_running=lambda: False)
    assert result.profile_id == "default"
    assert (data / "profiles" / "default" / "prime.db").is_file()


def test_worktree_shape_follows_profiles_and_the_bound_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    private = home / ".local" / "share" / "praxis-prime"
    (private / "accounts.db").parent.mkdir(parents=True)
    (private / "accounts.db").write_text("hash\n", encoding="utf-8")
    plain = private / "worktrees" / "repo" / "task"
    plain.mkdir(parents=True)
    (plain / ".git").write_text("gitdir: /tmp/unused\n", encoding="utf-8")
    bind_data_root(None)
    bind_profile(None)
    argv = build_bwrap_argv("echo hi", plain)
    assert "/workspace" in argv
    (private / "profiles" / "work").mkdir(parents=True)
    with pytest.raises(SandboxError, match="inside the account data directory"):
        build_bwrap_argv("echo hi", plain)
    task = private / "worktrees" / "work" / "repo" / "task"
    task.mkdir(parents=True)
    (task / ".git").write_text("gitdir: /tmp/unused\n", encoding="utf-8")
    assert "/workspace" in build_bwrap_argv("echo hi", task)
    other = private / "worktrees" / "other" / "repo" / "task"
    other.mkdir(parents=True)
    (other / ".git").write_text("gitdir: /tmp/unused\n", encoding="utf-8")
    bind_profile("work")
    try:
        assert "/workspace" in build_bwrap_argv("echo hi", task)
        with pytest.raises(SandboxError, match="inside the account data directory"):
            build_bwrap_argv("echo hi", other)
    finally:
        bind_profile(None)
        bind_data_root(None)


def test_bind_profile_is_per_context(tmp_path: Path) -> None:
    import threading

    from praxis_prime.sandbox.bwrap import bind_profile, bound_profile, release_profile

    bind_profile(None)
    token = bind_profile("work")
    assert token is not None
    seen: dict[str, str] = {}

    def worker() -> None:
        seen["worker"] = bound_profile()

    try:
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(5)
        assert seen["worker"] == "work"
        other = threading.Thread(target=lambda: bind_profile(None))
        other.start()
        other.join(5)
        again = threading.Thread(target=worker)
        again.start()
        again.join(5)
        assert seen["worker"] == "work"
        assert bound_profile() == "work"
        bind_profile(None)
        assert bound_profile() == ""
        cleared = threading.Thread(target=worker)
        cleared.start()
        cleared.join(5)
        assert seen["worker"] == ""
    finally:
        release_profile(token)
        bind_profile(None)
