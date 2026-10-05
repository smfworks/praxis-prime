"""Private gateway token reads and the /tmp runtime fallback."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from praxis_prime.gateway.auth import TokenUnreadable, read_token
from praxis_prime.paths import RuntimeDirError, ensure_private_runtime, runtime_dir

_SECRET = "super-secret-token"


def _write_token(path: Path, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    os.write(descriptor, (_SECRET + "\n").encode())
    os.close(descriptor)
    os.chmod(path, mode)


def test_read_token_accepts_a_private_file(tmp_path: Path) -> None:
    path = tmp_path / "gateway.token"
    _write_token(path, 0o600)
    assert read_token(path) == _SECRET


def test_read_token_missing_is_none(tmp_path: Path) -> None:
    assert read_token(tmp_path / "gateway.token") is None


def test_read_token_rejects_loose_mode(tmp_path: Path) -> None:
    path = tmp_path / "gateway.token"
    _write_token(path, 0o640)
    with pytest.raises(TokenUnreadable) as caught:
        read_token(path)
    assert _SECRET not in str(caught.value)
    assert _SECRET not in repr(caught.value)


def test_read_token_rejects_a_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real"
    _write_token(real, 0o600)
    link = tmp_path / "gateway.token"
    link.symlink_to(real)
    with pytest.raises(TokenUnreadable) as caught:
        read_token(link)
    assert _SECRET not in str(caught.value)
    assert real.read_text(encoding="utf-8") == _SECRET + "\n"


def test_read_token_rejects_other_owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "gateway.token"
    _write_token(path, 0o600)
    real_fstat = os.fstat

    def other_owner(descriptor: int) -> object:
        info = real_fstat(descriptor)

        class _Stat:
            st_mode = info.st_mode
            st_uid = info.st_uid ^ 1

        return _Stat()

    monkeypatch.setattr(os, "fstat", other_owner)
    with pytest.raises(TokenUnreadable) as caught:
        read_token(path)
    assert _SECRET not in str(caught.value)
    assert _SECRET not in repr(caught.value)


def test_daemon_runtime_dir_error_has_no_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from praxis_prime.daemon import serve

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))

    def refuse(env: object = None) -> Path:
        del env
        raise RuntimeDirError("refusing runtime directory /tmp/bad\x1b[0m")

    monkeypatch.setattr("praxis_prime.daemon.runtime_dir", refuse)
    assert serve() == 1
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert "\x1b" not in err
    assert "praxis-primed: refusing runtime directory" in err
    assert "\\x1b" in err


def test_private_runtime_creates_0700(tmp_path: Path) -> None:
    path = tmp_path / "runtime"
    assert ensure_private_runtime(path) == path
    info = path.lstat()
    assert stat.S_ISDIR(info.st_mode)
    assert stat.S_IMODE(info.st_mode) == 0o700
    assert info.st_uid == os.getuid()


def test_private_runtime_accepts_a_precreated_0700(tmp_path: Path) -> None:
    path = tmp_path / "runtime"
    path.mkdir(mode=0o700)
    before = path.lstat().st_mtime_ns
    assert ensure_private_runtime(path) == path
    assert path.lstat().st_mtime_ns == before
    assert stat.S_IMODE(path.lstat().st_mode) == 0o700


def test_private_runtime_rejects_loose_mode(tmp_path: Path) -> None:
    path = tmp_path / "runtime"
    path.mkdir()
    os.chmod(path, 0o755)
    before = path.lstat().st_mtime_ns
    with pytest.raises(RuntimeDirError):
        ensure_private_runtime(path)
    assert stat.S_IMODE(path.lstat().st_mode) == 0o755
    assert path.lstat().st_mtime_ns == before


def test_private_runtime_rejects_a_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "runtime"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(RuntimeDirError):
        ensure_private_runtime(link)
    assert link.is_symlink()
    assert stat.S_IMODE(real.lstat().st_mode) == 0o700


def test_private_runtime_rejects_other_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "runtime"
    path.mkdir(mode=0o700)
    real_lstat = os.lstat

    def other_owner(target: object) -> object:
        info = real_lstat(target)

        class _Stat:
            st_mode = info.st_mode
            st_uid = info.st_uid ^ 1
            st_dev = info.st_dev
            st_ino = info.st_ino

        return _Stat()

    monkeypatch.setattr(os, "lstat", other_owner)
    with pytest.raises(RuntimeDirError):
        ensure_private_runtime(path)
    assert stat.S_IMODE(real_lstat(path).st_mode) == 0o700


def test_runtime_dir_fallback_asks_for_a_private_dir(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Path] = {}

    def fake(path: Path) -> Path:
        seen["path"] = path
        return path

    monkeypatch.setattr("praxis_prime.paths.ensure_private_runtime", fake)
    assert runtime_dir({}) == Path(f"/tmp/praxis-prime-{os.getuid()}")
    assert seen["path"] == Path(f"/tmp/praxis-prime-{os.getuid()}")
