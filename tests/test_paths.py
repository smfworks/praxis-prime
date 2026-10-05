"""XDG directory resolution. ARCHITECTURE §25."""

import os
from pathlib import Path

from praxis_prime.paths import cache_dir, config_dir, data_dir, project_dir, runtime_dir, state_dir


def test_config_dir_honors_xdg_and_home(tmp_path):
    xdg = tmp_path / "xdg"
    assert config_dir({"XDG_CONFIG_HOME": str(xdg), "HOME": "/should/not/use"}) == (
        xdg / "praxis-prime"
    )
    home = tmp_path / "home"
    assert config_dir({"HOME": str(home)}) == home / ".config" / "praxis-prime"
    assert data_dir({"HOME": str(home)}) == home / ".local" / "share" / "praxis-prime"
    assert state_dir({"HOME": str(home)}) == home / ".local" / "state" / "praxis-prime"
    assert cache_dir({"HOME": str(home)}) == home / ".cache" / "praxis-prime"


def test_runtime_and_project_dirs(tmp_path):
    assert runtime_dir({"XDG_RUNTIME_DIR": str(tmp_path)}) == tmp_path / "praxis-prime"
    assert project_dir(tmp_path) == tmp_path / ".prime"


def test_resolved_dirs_stay_off_the_real_home(real_user_dirs):
    """Fail if a base directory resolves into the real praxis-prime folders.

    ``real_user_dirs`` is recorded in ``tests/conftest.py`` before
    ``isolate_user_dirs`` remaps HOME and the XDG variables. This test
    runs after that remap, and ``data_dir()`` with no argument reads the
    remapped environment. A path equal to, or under, one of the
    pre-isolation data, config, state, cache, or runtime folders means a
    CLI test can open the user's ``prime.db``. Being under the real home
    alone is not a failure: pytest's basetemp can live there (for
    example ``TMPDIR=~/tmp``). Runtime is included so the shared
    ``/tmp/praxis-prime-<uid>`` fallback cannot pass just because it sits
    outside the home directory.
    """
    home = real_user_dirs.home
    current = {
        "data": data_dir(),
        "config": config_dir(),
        "state": state_dir(),
        "cache": cache_dir(),
        "runtime": runtime_dir(),
    }
    captured = {
        "data": real_user_dirs.data,
        "config": real_user_dirs.config,
        "state": real_user_dirs.state,
        "cache": real_user_dirs.cache,
        "runtime": real_user_dirs.runtime,
    }
    for name, path in current.items():
        resolved = path.resolve()
        assert resolved != captured[name], f"{name} still uses {resolved}"
        for real_name, real_path in captured.items():
            assert not resolved.is_relative_to(real_path), (
                f"{name} {resolved} is under the real {real_name} folder {real_path}"
            )
    assert Path(os.environ["HOME"]).resolve() != home
    assert data_dir() == Path(os.environ["XDG_DATA_HOME"]) / "praxis-prime"
    assert config_dir() == Path(os.environ["XDG_CONFIG_HOME"]) / "praxis-prime"
    assert state_dir() == Path(os.environ["XDG_STATE_HOME"]) / "praxis-prime"
    assert cache_dir() == Path(os.environ["XDG_CACHE_HOME"]) / "praxis-prime"
    assert runtime_dir() == Path(os.environ["XDG_RUNTIME_DIR"]) / "praxis-prime"
    shared = Path(f"/tmp/praxis-prime-{os.getuid()}")
    assert runtime_dir().resolve() != shared
