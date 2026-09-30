"""prime.db flock and stale migration-lock recovery."""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

import pytest

from praxis_prime.profiles.migrate import (
    MigrationBusy,
    _process_starttime,
    migrate_under_lock,
)
from praxis_prime.state import StateDB


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
    (data / ".migration.lock").write_text(f"{os.getpid()}\n{start}\n", encoding="utf-8")
    with pytest.raises(MigrationBusy, match=r"\.migration\.lock"):
        migrate_under_lock(data, config, daemon_running=lambda: False)
    with pytest.raises(MigrationBusy, match=r"prime\.db\.lock"):
        migrate_under_lock(data, config, daemon_running=lambda: False, force=True)
    assert _count(db) == 3
    assert (data / "prime.db").is_file()
    db.close()
    (data / ".migration.lock").write_text(f"{os.getpid()}\n{start}\n", encoding="utf-8")
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
