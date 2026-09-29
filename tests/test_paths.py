"""XDG directory resolution. ARCHITECTURE §25."""

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
