"""prime.db flock and stale migration-lock recovery."""

from __future__ import annotations

import argparse
import io
import os
import sys
import threading
from pathlib import Path

import pytest

from praxis_prime.audit.log import AuditLog
from praxis_prime.cli import main
from praxis_prime.mcp.cli import _db_path
from praxis_prime.profiles.migrate import (
    MigrationBusy,
    _process_starttime,
    migrate_under_lock,
    migration_lock_path,
)
from praxis_prime.state import (
    MigrationInProgress,
    StateDB,
    acquire_exclusive_db_locks,
    release_db_locks,
)


def _seed(data: Path, rows: int = 50) -> StateDB:
    data.mkdir(parents=True, exist_ok=True)
    db = StateDB(data / "prime.db")
    db.conn.execute("CREATE TABLE probe (n INTEGER)")
    db.conn.executemany("INSERT INTO probe VALUES (?)", [(i,) for i in range(rows)])
    db.conn.commit()
    return db


def _count(db: StateDB) -> int:
    row = db.conn.execute("SELECT COUNT(*) FROM probe").fetchone()
    assert row is not None
    return int(row[0])


def test_open_database_blocks_migration_until_close(tmp_path: Path) -> None:
    data = tmp_path / "data"
    config = tmp_path / "config"
    config.mkdir()
    db = _seed(data)
    with pytest.raises(MigrationBusy, match=r"prime\.db\.lock"):
        migrate_under_lock(data, config, daemon_running=lambda: False)
    assert (data / "prime.db").is_file()
    assert _count(db) == 50
    assert not (data / "profiles" / "default" / "prime.db").exists()
    db.close()
    result = migrate_under_lock(data, config, daemon_running=lambda: False)
    assert result.already is False
    moved = StateDB(data / "profiles" / "default" / "prime.db")
    try:
        assert _count(moved) == 50
    finally:
        moved.close()
    assert not (data / "prime.db").exists()


def test_stale_locks_do_not_brick_profile_migrate(tmp_path: Path) -> None:
    config = tmp_path / "config"
    config.mkdir()
    start = _process_starttime(os.getpid())
    assert start is not None
    cases = {
        "empty": "",
        "garbage": "not-a-pid\n",
        "dead": "999999\n1\n",
        "reused": f"{os.getpid()}\n0\n",
    }
    for name, text in cases.items():
        data = tmp_path / name
        StateDB(data / "prime.db").close()
        (data / ".migration.lock").write_text(text, encoding="utf-8")
        result = migrate_under_lock(data, config, daemon_running=lambda: False)
        assert result.profile_id == "default", name
        assert not (data / ".migration.lock").exists(), name
        assert not (data / "prime.db").exists(), name


def test_live_lock_names_the_path_and_force_still_honours_the_flock(
    tmp_path: Path,
) -> None:
    config = tmp_path / "config"
    config.mkdir()
    data = tmp_path / "live"
    db = _seed(data, rows=3)
    start = _process_starttime(os.getpid())
    assert start is not None
    lock_text = f"{os.getpid()}\n{start}\n"
    (data / ".migration.lock").write_text(lock_text, encoding="utf-8")
    with pytest.raises(MigrationBusy, match=r"prime\.db\.lock"):
        migrate_under_lock(data, config, daemon_running=lambda: False, force=True)
    assert (data / ".migration.lock").read_text(encoding="utf-8") == lock_text
    assert _count(db) == 3
    assert (data / "prime.db").is_file()
    db.close()
    with pytest.raises(MigrationBusy, match=r"\.migration\.lock"):
        migrate_under_lock(data, config, daemon_running=lambda: False)
    assert (data / ".migration.lock").read_text(encoding="utf-8") == lock_text
    result = migrate_under_lock(data, config, daemon_running=lambda: False, force=True)
    assert result.already is False
    assert not (data / ".migration.lock").exists()
    assert not (data / "prime.db").exists()


def test_force_removes_a_symlink_lock_without_following_it(tmp_path: Path) -> None:
    config = tmp_path / "config"
    config.mkdir()
    data = tmp_path / "link"
    StateDB(data / "prime.db").close()
    target = data / "keep.txt"
    target.write_text("keep", encoding="utf-8")
    (data / ".migration.lock").symlink_to(target)
    with pytest.raises(MigrationBusy, match=r"\.migration\.lock"):
        migrate_under_lock(data, config, daemon_running=lambda: False)
    result = migrate_under_lock(data, config, daemon_running=lambda: False, force=True)
    assert result.profile_id == "default"
    assert target.read_text(encoding="utf-8") == "keep"
    assert not (data / ".migration.lock").exists()


def test_daemon_refusal_names_the_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import io

    from praxis_prime.daemon import serve

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    root = tmp_path / "share" / "praxis-prime"
    root.mkdir(parents=True)
    (root / ".migration.lock").write_text("", encoding="utf-8")
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    code = serve(stop=threading.Event(), listen="127.0.0.1:0")
    assert code == 2
    text = err.getvalue()
    assert ".migration.lock" in text
    assert "profile migrate --force" in text


def test_shared_locks_do_not_block_each_other(tmp_path: Path) -> None:
    data = tmp_path / "data"
    first = _seed(data, rows=1)
    second = StateDB(data / "prime.db")
    try:
        assert _count(first) == 1
        assert _count(second) == 1
    finally:
        second.close()
        first.close()


def test_opener_does_not_wait_or_recreate_during_migration(tmp_path: Path) -> None:
    data = tmp_path / "data"
    config = tmp_path / "config"
    config.mkdir()
    _seed(data, rows=4).close()
    legacy = data / "prime.db"
    held = acquire_exclusive_db_locks([legacy])
    failed = threading.Event()

    def opener() -> None:
        try:
            StateDB(legacy)
        except MigrationInProgress as exc:
            if "migration in progress" in str(exc):
                failed.set()

    thread = threading.Thread(target=opener)
    thread.start()
    thread.join(2)
    assert not thread.is_alive()
    assert failed.is_set()
    release_db_locks(held)
    migrated = migrate_under_lock(data, config, daemon_running=lambda: False)
    assert migrated.already is False
    moved_to = data / "profiles" / "default" / "prime.db"
    with pytest.raises(
        MigrationInProgress,
        match=f"this database moved to {moved_to} after migration",
    ):
        StateDB(legacy)
    assert not legacy.exists()
    moved = StateDB(data / "profiles" / "default" / "prime.db")
    try:
        assert _count(moved) == 4
    finally:
        moved.close()


def test_slow_open_after_the_move_does_not_create_legacy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import praxis_prime.state as state_mod

    data = tmp_path / "data"
    config = tmp_path / "config"
    config.mkdir()
    _seed(data, rows=3).close()
    started = threading.Event()
    release = threading.Event()
    ident: dict[str, int] = {}
    real = state_mod._open_lock_fd

    def slow(path: Path) -> int:
        if threading.get_ident() == ident.get("id"):
            started.set()
            assert release.wait(5)
        return real(path)

    monkeypatch.setattr(state_mod, "_open_lock_fd", slow)
    errors: list[str] = []

    def open_db() -> None:
        ident["id"] = threading.get_ident()
        try:
            StateDB(data / "prime.db")
        except MigrationInProgress as exc:
            errors.append(str(exc))

    thread = threading.Thread(target=open_db)
    thread.start()
    assert started.wait(3)
    migrate_under_lock(data, config, daemon_running=lambda: False)
    release.set()
    thread.join(5)
    assert not thread.is_alive()
    assert errors
    moved_to = data / "profiles" / "default" / "prime.db"
    assert f"this database moved to {moved_to} after migration" in errors[0]
    assert not (data / "prime.db").exists()
    moved = StateDB(data / "profiles" / "default" / "prime.db")
    try:
        assert _count(moved) == 3
    finally:
        moved.close()


def test_cli_openers_refuse_while_the_migration_lock_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    data = home / ".local" / "share" / "praxis-prime"
    _seed(data, rows=1).close()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / ".local" / "state"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    (tmp_path / "run").mkdir()
    migration_lock_path(data).write_text("1\n1\n", encoding="utf-8")
    from praxis_prime.cli import main
    from praxis_prime.runtime import build_runtime

    with pytest.raises(MigrationInProgress, match="migration in progress"):
        build_runtime(env=os.environ)
    assert main(["routines", "list"]) == 2
    assert "migration in progress" in capsys.readouterr().err
    assert main(["chat", "--local"]) == 2
    assert "migration in progress" in capsys.readouterr().err
    assert (data / "prime.db").is_file()
    reopened = StateDB(data / "prime.db", allow_during_migration=True)
    try:
        assert _count(reopened) == 1
    finally:
        reopened.close()


def test_post_migration_commands_open_the_profile_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Memory, routines, compliance, breach, gdpr, mcp, and packs follow the move.

    A finished migration used to look like ``migration in progress`` because
    these commands opened the old top-level ``prime.db``. On a build without
    that refusal they would instead create an empty file and read it.
    """
    home = tmp_path / "home"
    data = home / ".local" / "share" / "praxis-prime"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / ".local" / "state"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    (tmp_path / "run").mkdir()
    db = StateDB(data / "prime.db")
    db.conn.execute(
        """
        INSERT INTO memory_entries (
            id, tier, scope, content, content_hash, source, created_at, updated_at
        ) VALUES (?, 'profile', 'global', ?, 'hash-kept', 'test', ?, ?)
        """,
        (
            "mem-kept",
            "kept-memory-token",
            "2026-01-01T00:00:00+00:00",
            "2026-01-01T00:00:00+00:00",
        ),
    )
    db.conn.execute(
        """
        INSERT INTO routines (
            id, name, prompt, trigger_kind, trigger_expr, timezone, missed_policy,
            min_interval_seconds, max_iterations, created_at, updated_at
        ) VALUES (
            'rt-kept', 'kept-routine', 'say hi', 'cron', '0 0 * * *', 'UTC', 'skip',
            0, 1, '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'
        )
        """
    )
    db.conn.execute(
        """
        INSERT INTO breach_records (
            id, created_at, pack, summary, affected_count, status, notice_draft, payload_json
        ) VALUES (
            'br-kept', '2026-01-01T00:00:00+00:00', 'gdpr', 'kept-breach-token',
            1, 'recorded', 'draft', '{}'
        )
        """
    )
    db.conn.commit()
    AuditLog(db).append(
        session_id=None,
        kind="retention",
        summary="kept-audit-token",
        payload={"ok": True},
    )
    db.close()
    monkeypatch.setattr("sys.stdin", io.StringIO("correct-horse\n"))
    assert main(["account", "create", "ada", "--password-stdin"]) == 0
    capsys.readouterr()
    moved = data / "profiles" / "default" / "prime.db"
    assert moved.is_file()
    assert not (data / "prime.db").exists()

    def run(argv: list[str]) -> str:
        code = main(argv)
        captured = capsys.readouterr()
        text = captured.out + captured.err
        assert code == 0, text
        assert "migration in progress" not in text
        assert "this database moved" not in text
        return text

    bare = [
        ["memory", "list"],
        ["routines", "list"],
        ["compliance", "report"],
        ["breach", "list"],
        ["gdpr", "export", "--subject", "kept-memory-token"],
    ]
    for argv in bare:
        with_dir = [*argv, "--data-dir", str(data)]
        bare_text = run(argv)
        dir_text = run(with_dir)
        if argv[0] == "memory":
            assert "kept-memory-token" in bare_text
            assert "kept-memory-token" in dir_text
        elif argv[0] == "routines":
            assert "kept-routine" in bare_text
            assert "kept-routine" in dir_text
        elif argv[0] == "compliance":
            assert "kept-audit-token" in bare_text
            assert "kept-audit-token" in dir_text
        elif argv[0] == "breach":
            assert "kept-breach-token" in bare_text
            assert "kept-breach-token" in dir_text
        else:
            assert "kept-memory-token" in bare_text
            assert "kept-memory-token" in dir_text
    assert not (data / "prime.db").exists()
    assert _db_path(argparse.Namespace(data_dir=None)) == moved
    assert _db_path(argparse.Namespace(data_dir=str(data))) == moved

    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "pack.json").write_text(
        '{"name": "demo_pack", "version": "1.0.0", "description": "fixture"}\n',
        encoding="utf-8",
    )
    (pack / "LICENSE").write_text(
        "MIT License\nPermission is hereby granted, free of charge\n",
        encoding="utf-8",
    )
    assert "installed demo_pack" in run(["packs", "install", str(pack), "--data-dir", str(data)])
    assert not (data / "prime.db").exists()
    opened = StateDB(moved)
    try:
        kinds = {row["kind"] for row in opened.conn.execute("SELECT kind FROM audit_events")}
    finally:
        opened.close()
    assert "pack.install" in kinds

    with pytest.raises(
        MigrationInProgress,
        match=f"this database moved to {moved} after migration",
    ):
        StateDB(data / "prime.db")
    assert not (data / "prime.db").exists()


def test_pid_only_live_lock_is_not_stale(tmp_path: Path) -> None:
    config = tmp_path / "config"
    config.mkdir()
    data = tmp_path / "pid-only"
    StateDB(data / "prime.db").close()
    text = f"{os.getpid()}\n"
    (data / ".migration.lock").write_text(text, encoding="utf-8")
    with pytest.raises(MigrationBusy, match=r"\.migration\.lock"):
        migrate_under_lock(data, config, daemon_running=lambda: False)
    assert (data / ".migration.lock").read_text(encoding="utf-8") == text
    assert (data / "prime.db").is_file()
    result = migrate_under_lock(data, config, daemon_running=lambda: False, force=True)
    assert result.already is False
    assert not (data / ".migration.lock").exists()
    assert not (data / "prime.db").exists()


def test_replaced_lock_file_does_not_free_migration(tmp_path: Path) -> None:
    config = tmp_path / "config"
    config.mkdir()
    data = tmp_path / "swap"
    db = _seed(data, rows=2)
    lock = data / "prime.db.lock"
    os.unlink(lock)
    replacement = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
    os.close(replacement)
    try:
        with pytest.raises(MigrationBusy, match=r"prime\.db\.lock"):
            migrate_under_lock(data, config, daemon_running=lambda: False)
        assert (data / "prime.db").is_file()
        assert _count(db) == 2
    finally:
        db.close()


def test_two_shared_database_locks_do_not_block(tmp_path: Path) -> None:
    data = tmp_path / "shared"
    first = _seed(data, rows=1)
    second = StateDB(data / "prime.db")
    try:
        assert _count(first) == 1
        assert _count(second) == 1
    finally:
        second.close()
        first.close()
