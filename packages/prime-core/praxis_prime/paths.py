"""XDG paths for Praxis Prime.

TODO: ARCHITECTURE §25. Secrets never live in these directories' config files.
"""

from __future__ import annotations

import os
import stat
import tomllib
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


class RuntimeDirError(OSError):
    """The ``/tmp`` runtime fallback is not a private directory this user owns."""


def runtime_dir(env: Mapping[str, str] | None = None) -> Path:
    """``$XDG_RUNTIME_DIR/praxis-prime`` or ``/tmp/praxis-prime-<uid>``.

    The ``/tmp`` fallback is created mode 0700 and checked with ``lstat``.
    A symlink, another owner, or any other mode is refused.
    """
    environ = _environ(env)
    runtime = env_value(environ, "XDG_RUNTIME_DIR")
    if runtime:
        return Path(runtime) / APP_DIRNAME
    return ensure_private_runtime(Path(f"/tmp/praxis-prime-{os.getuid()}"))


def ensure_private_runtime(path: Path) -> Path:
    """Create ``path`` mode 0700, then require ``lstat`` to agree.

    A directory that already has that owner and mode is kept. This does not
    follow a symlink and does not change a directory that fails the check.
    """
    target = Path(path)
    try:
        os.mkdir(target, 0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise RuntimeDirError(f"refusing runtime directory {target}") from exc
    try:
        info = os.lstat(target)
    except OSError as exc:
        raise RuntimeDirError(f"refusing runtime directory {target}") from exc
    if not _private_dir(info):
        raise RuntimeDirError(f"refusing runtime directory {target}")
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(target, flags)
    except OSError as exc:
        raise RuntimeDirError(f"refusing runtime directory {target}") from exc
    try:
        held = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (held.st_dev, held.st_ino) != (info.st_dev, info.st_ino) or not _private_dir(held):
        raise RuntimeDirError(f"refusing runtime directory {target}")
    return target


def _private_dir(info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        return False
    if info.st_uid != os.getuid():
        return False
    return stat.S_IMODE(info.st_mode) == 0o700


def project_dir(root: Path) -> Path:
    """Per-project directory ``.prime/`` (ARCHITECTURE §25)."""
    return Path(root) / ".prime"


def env_value(env: Mapping[str, str], key: str) -> str | None:
    value = env.get(key)
    if value:
        return value
    return None


_PROJECT_NAME = "praxis-prime"


def source_checkout_root(start: Path) -> Path | None:
    """Nearest checkout whose ``pyproject.toml`` names ``praxis-prime``.

    Walks ``start`` and its parents. The file must be a regular file, not a
    symlink, and must parse as TOML with ``[project] name = "praxis-prime"``.
    A different project name is skipped. Returns None when no such file
    exists. Nothing above the matching directory is considered.
    """
    origin = Path(start)
    try:
        current = origin.resolve()
    except OSError:
        return None
    if not current.is_dir():
        current = current.parent
    for directory in (current, *current.parents):
        if _pyproject_names_project(directory / "pyproject.toml", _PROJECT_NAME):
            return directory
    return None


def _pyproject_names_project(path: Path, name: str) -> bool:
    text = read_regular_text(path)
    if text is None:
        return False
    try:
        loaded = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return False
    if not isinstance(loaded, dict):
        return False
    project = loaded.get("project")
    if not isinstance(project, dict):
        return False
    return project.get("name") == name


def read_regular_text(path: Path) -> str | None:
    """UTF-8 text of a regular file. A symlink is not read.

    The file is classified with ``lstat`` and opened with ``O_NOFOLLOW``,
    so a symlink swapped in after a ``Path.is_symlink`` check is not
    followed.
    """
    try:
        info = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        with os.fdopen(descriptor, "rb") as handle:
            blob = handle.read()
    except OSError:
        return None
    try:
        return blob.decode("utf-8")
    except UnicodeError:
        return None


_read_regular_text = read_regular_text
