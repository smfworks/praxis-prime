"""Refuse paths outside the worker's own profile directory.

Workers set ``PRAXIS_PRIME_WORKER_PROFILE`` and ``PRAXIS_PRIME_WORKER_DATA``.
The first time both are set to a valid profile, that pair is frozen for
the process. A later change to the environment does not move the home.
``StateDB`` calls :func:`refuse_worker_path` before it opens a database.
When those variables are unset, this is a no-op so the supervisor and the
CLI keep their current open paths.

A symlink that resolves outside the profile home is refused. The check
does not follow a path that cannot be resolved: that fails closed.
"""

from __future__ import annotations

import os
from pathlib import Path

from praxis_prime.profiles.ids import profile_id


class ProfileBoundary(PermissionError):
    """The worker tried to open a file outside its profile home."""


# First valid worker env seen in this process. Later changes are ignored.
_frozen: tuple[str, str] | None = None


def freeze_worker_env() -> None:
    """Remember the worker profile and data root for the rest of this process."""
    _observe_env()


def clear_worker_boundary() -> None:
    """Drop a frozen worker env. Tests use this so one case does not confine the next."""
    global _frozen
    _frozen = None


def worker_home() -> Path | None:
    """Profile directory for this process, or None when it is not a worker."""
    found = _observe_env()
    if found is None:
        return None
    profile, root = found
    return Path(root) / "profiles" / profile


def _observe_env() -> tuple[str, str] | None:
    """Return the frozen pair. The first complete valid env is the one that sticks."""
    global _frozen
    if _frozen is not None:
        return _frozen
    profile = os.environ.get("PRAXIS_PRIME_WORKER_PROFILE", "").strip()
    root = os.environ.get("PRAXIS_PRIME_WORKER_DATA", "").strip()
    if not profile or not root or profile_id(profile) is None:
        return None
    _frozen = (profile, root)
    return _frozen


def path_inside(home: Path, path: Path) -> bool:
    """True when ``path`` resolves inside ``home``.

    Both sides are resolved. A path that cannot be resolved is outside.
    """
    try:
        resolved_home = home.resolve(strict=False)
        resolved = path.resolve(strict=False)
        resolved.relative_to(resolved_home)
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def refuse_worker_path(path: Path) -> None:
    """Raise when this process is a worker and ``path`` is not in its home."""
    home = worker_home()
    if home is None:
        return
    if path_inside(home, Path(path)):
        return
    raise ProfileBoundary("worker cannot open a path outside its profile")


def assert_profile_file(data_root: Path, profile: str, path: Path) -> None:
    """Raise unless ``path`` is inside ``profiles/<profile>``."""
    home = Path(data_root) / "profiles" / profile
    if not path_inside(home, path):
        raise ProfileBoundary("worker cannot open a path outside its profile")
