"""Keep the suite off the real XDG home.

``praxis-prime code`` and the other CLI entry points open ``prime.db``
from ``data_dir()`` before they reject a bad argument. A test that called
``main()`` without its own HOME or XDG setup created ``prime.db-wal`` and
``prime.db-shm`` next to the user's database.

``real_user_dirs`` records the home and the resolved base directories
once, before any test remaps the environment. ``isolate_user_dirs`` then
points HOME and the XDG base directories at a directory under
``tmp_path``. Unset variables are set on purpose: a missing HOME or
XDG_* falls through to the real home, and a missing ``XDG_RUNTIME_DIR``
falls through to ``/tmp/praxis-prime-<uid>``, which is shared with the
user. A test that sets the same variables afterwards overrides this
default. ``monkeypatch`` applies the later ``setenv`` on top and undoes
both when the test ends.

``paths.py`` has no ``PRAXIS_PRIME_HOME``, ``PRAXIS_DATA_DIR``, or
``PRAXIS_CONFIG_DIR``. The path overrides the program does read are
``PRAXIS_PRIME_SECRETS_FILE``, ``PRAXIS_PRIME_WORKER_DATA``, and
``PRAXIS_PRIME_OMARCHY_THEME``. When the parent process set one, it is
moved under the per-test directory. When it is unset, it stays unset and
follows the XDG directories above. Setting it always would hide a later
``XDG_CONFIG_HOME`` from ``secrets_path()``. An inherited
``PRAXIS_PRIME_WORKER_PROFILE`` is cleared so it cannot freeze a worker
boundary onto the real data root. ``PRAXIS_PRIME_UI_DIR``,
``PRAXIS_PRIME_BUNDLED_SKILLS``, and ``PRAXIS_PRIME_STUB_REPLIES`` are
not data directories. An inherited value under the real home is cleared
so the suite keeps the bundled UI, the bundled skills, and the normal
provider map. ``PRAXIS_PRIME_BWRAP_LOG`` is handled the same way: it is
an append-only evidence log that CI points at ``$RUNNER_TEMP`` and reads
after the run, so it passes through untouched unless it names a path
under the real home.

Playwright finds its browsers under ``$XDG_CACHE_HOME/ms-playwright``
(or ``~/.cache/ms-playwright``). ``real_playwright_browsers`` records that
folder, or an inherited ``PLAYWRIGHT_BROWSERS_PATH``, before isolation,
and ``isolate_user_dirs`` sets ``PLAYWRIGHT_BROWSERS_PATH`` to it so the
browser tests still find the installed Chromium.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import NamedTuple

import pytest

from praxis_prime.paths import cache_dir, config_dir, data_dir, runtime_dir, state_dir

# Inherited path overrides. The leaf is placed under the per-test root.
_INHERITED_PATH_ENV = {
    "PRAXIS_PRIME_SECRETS_FILE": "secrets.env",
    "PRAXIS_PRIME_WORKER_DATA": "worker-data",
    "PRAXIS_PRIME_OMARCHY_THEME": "omarchy-theme.json",
}

# Not base directories. Drop an inherited path that still names the real home.
_CLEAR_UNDER_HOME = (
    "PRAXIS_PRIME_UI_DIR",
    "PRAXIS_PRIME_BUNDLED_SKILLS",
    "PRAXIS_PRIME_STUB_REPLIES",
    # Append-only CI evidence log, read by ci.yml after pytest exits.
    "PRAXIS_PRIME_BWRAP_LOG",
)


class RealUserDirs(NamedTuple):
    """Paths resolved before ``isolate_user_dirs`` remaps the environment."""

    home: Path
    data: Path
    config: Path
    state: Path
    cache: Path
    runtime: Path


def _resolved_home() -> Path:
    raw = os.environ.get("HOME", "").strip()
    if raw:
        return Path(raw).resolve()
    return Path.home().resolve()


def _under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root)
    except (OSError, ValueError):
        return False
    return True


@pytest.fixture(scope="session")
def real_user_dirs() -> RealUserDirs:
    """Capture the real home before the per-test fixture remaps it.

    Session scope runs before the function-scoped autouse fixture, which
    depends on this one. The guard test compares ``data_dir()`` with
    these paths after isolation.
    """
    return RealUserDirs(
        home=_resolved_home(),
        data=data_dir().resolve(),
        config=config_dir().resolve(),
        state=state_dir().resolve(),
        cache=cache_dir().resolve(),
        runtime=runtime_dir().resolve(),
    )


@pytest.fixture(scope="session")
def real_playwright_browsers() -> str:
    """Record where Playwright keeps its browsers, before isolation.

    An inherited ``PLAYWRIGHT_BROWSERS_PATH`` wins. Otherwise use the
    folder Playwright would pick on Linux from the real cache directory.
    """
    inherited = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "").strip()
    if inherited:
        return inherited
    cache = os.environ.get("XDG_CACHE_HOME", "").strip()
    cache_root = Path(cache) if cache else _resolved_home() / ".cache"
    return str(cache_root / "ms-playwright")


@pytest.fixture(autouse=True)
def isolate_user_dirs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    real_user_dirs: RealUserDirs,
    real_playwright_browsers: str,
) -> Path:
    """Point HOME and the XDG base directories at ``tmp_path``."""
    root = tmp_path / "isolate"
    home = root / "home"
    data = root / "data"
    config = root / "config"
    state = root / "state"
    cache = root / "cache"
    runtime = root / "runtime"
    for directory in (home, data, config, state, cache, runtime):
        directory.mkdir(parents=True)
    # XDG_RUNTIME_DIR is mode 0700. mkdir honours the umask, so chmod after.
    os.chmod(runtime, 0o700)

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(data))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config))
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    # Keep the installed browsers reachable after XDG_CACHE_HOME moves.
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", real_playwright_browsers)

    # Both variables together freeze a process-wide profile boundary.
    # Clear the profile first, then move a data root that was inherited.
    if os.environ.get("PRAXIS_PRIME_WORKER_PROFILE", "").strip():
        monkeypatch.delenv("PRAXIS_PRIME_WORKER_PROFILE", raising=False)

    for name, leaf in _INHERITED_PATH_ENV.items():
        current = os.environ.get(name, "").strip()
        if not current:
            continue
        target = root / leaf
        if name == "PRAXIS_PRIME_WORKER_DATA":
            target.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv(name, str(target))

    for name in _CLEAR_UNDER_HOME:
        current = os.environ.get(name, "").strip()
        if not current:
            continue
        if _under(Path(current), real_user_dirs.home):
            monkeypatch.delenv(name, raising=False)

    return root


@pytest.fixture(autouse=True)
def stub_locality_resolver(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep provider-locality lookups off the network.

    A name classifies as cloud when the resolver raises. A test that needs
    addresses monkeypatches ``praxis_prime.locality.resolve_host`` again,
    or passes ``resolver=`` into the helper.
    """

    def _refuse(host: str) -> list[str]:
        raise OSError(f"DNS is disabled in tests ({host})")

    from praxis_prime.locality import clear_cache

    clear_cache()
    monkeypatch.setattr("praxis_prime.locality.resolve_host", _refuse)
    yield
    clear_cache()
