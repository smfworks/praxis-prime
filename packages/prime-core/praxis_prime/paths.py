"""XDG paths for Praxis Prime.

TODO: ARCHITECTURE §25. Secrets never live in these directories' config files.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

APP_DIRNAME = "praxis-prime"


def _environ(env: Mapping[str, str] | None) -> Mapping[str, str]:
    if env is None:
        return os.environ
    return env


def _home(env: Mapping[str, str]) -> Path:
    home = env.get("HOME")
    if home:
        return Path(home)
    return Path.home()


def _xdg(env: Mapping[str, str], variable: str, fallback: Path) -> Path:
    override = env.get(variable)
    if override:
        return Path(override)
    return fallback


def config_dir(env: Mapping[str, str] | None = None) -> Path:
    """``$XDG_CONFIG_HOME/praxis-prime`` or ``~/.config/praxis-prime``."""
    environ = _environ(env)
    return _xdg(environ, "XDG_CONFIG_HOME", _home(environ) / ".config") / APP_DIRNAME


def data_dir(env: Mapping[str, str] | None = None) -> Path:
    """``$XDG_DATA_HOME/praxis-prime`` or ``~/.local/share/praxis-prime``."""
    environ = _environ(env)
    return _xdg(environ, "XDG_DATA_HOME", _home(environ) / ".local" / "share") / APP_DIRNAME


def state_dir(env: Mapping[str, str] | None = None) -> Path:
    """``$XDG_STATE_HOME/praxis-prime`` or ``~/.local/state/praxis-prime``."""
    environ = _environ(env)
    return _xdg(environ, "XDG_STATE_HOME", _home(environ) / ".local" / "state") / APP_DIRNAME


def cache_dir(env: Mapping[str, str] | None = None) -> Path:
    """``$XDG_CACHE_HOME/praxis-prime`` or ``~/.cache/praxis-prime``."""
    environ = _environ(env)
    return _xdg(environ, "XDG_CACHE_HOME", _home(environ) / ".cache") / APP_DIRNAME


def runtime_dir(env: Mapping[str, str] | None = None) -> Path:
    """``$XDG_RUNTIME_DIR/praxis-prime`` or ``/tmp/praxis-prime-<uid>``."""
    environ = _environ(env)
    runtime = env_value(environ, "XDG_RUNTIME_DIR")
    if runtime:
        return Path(runtime) / APP_DIRNAME
    return Path(f"/tmp/praxis-prime-{os.getuid()}")


def project_dir(root: Path) -> Path:
    """Per-project directory ``.prime/`` (ARCHITECTURE §25)."""
    return Path(root) / ".prime"


def env_value(env: Mapping[str, str], key: str) -> str | None:
    value = env.get(key)
    if value:
        return value
    return None
