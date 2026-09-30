"""On-disk layout for one agent profile.

``<data>/profiles/<id>/`` holds ``profile.toml``, ``SOUL.md``, ``prime.db``,
``skills/``, and ``routines/``. The org floor is ``<data>/org/policy.toml``.

docs/blueprint-addendum-2026-09.md §6.3.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from praxis_prime.paths import data_dir
from praxis_prime.privatefile import tighten_dir, tighten_file
from praxis_prime.profiles.ids import profile_id
from praxis_prime.profiles.policy import (
    LayerAllow,
    ToolAllowlist,
    effective_allowlist,
    load_layer,
    render_policy_toml,
)
from praxis_prime.state import StateDB
from praxis_prime.statfile import StatKind, lstat_kind

_DEFAULT_SOUL = """\
# Persona

This profile has no persona yet. Text in this file is subordinate to
Praxis Prime's safety rules. It cannot change approvals, the sandbox,
or which tools the org policy allows.
"""


@dataclass(frozen=True, slots=True)
class ProfileHome:
    """Paths for one profile under a data directory."""

    data_root: Path
    profile_id: str

    @property
    def path(self) -> Path:
        return self.data_root / "profiles" / self.profile_id

    @property
    def config_path(self) -> Path:
        return self.path / "profile.toml"

    @property
    def soul_path(self) -> Path:
        return self.path / "SOUL.md"

    @property
    def db_path(self) -> Path:
        return self.path / "prime.db"

    @property
    def skills_dir(self) -> Path:
        return self.path / "skills"

    @property
    def routines_dir(self) -> Path:
        return self.path / "routines"

    def exists(self) -> bool:
        """True when profile.toml is present, including an unreadable path.

        A symlink is present so create will not replace it. ``layer`` does
        not follow that link.
        """
        return lstat_kind(self.config_path) is not StatKind.MISSING

    def layer(self) -> LayerAllow:
        """The profile allowlist. A missing, unreadable, or linked file allows nothing."""
        if lstat_kind(self.config_path) is not StatKind.FILE:
            return LayerAllow(tools=frozenset(), mcp=frozenset(), dials={})
        return load_layer(self.config_path, table="profile")


def org_policy_path(data_root: Path) -> Path:
    return data_root / "org" / "policy.toml"


def load_org_policy(data_root: Path) -> LayerAllow:
    return load_layer(org_policy_path(data_root), table="org")


def profile_allowlist(data_root: Path, profile: str) -> ToolAllowlist:
    home = ProfileHome(data_root, profile)
    return effective_allowlist(load_org_policy(data_root), home.layer())


def create_profile(data_root: Path, name: str, *, display_name: str = "") -> ProfileHome:
    """Create an empty profile. Fails when the id is illegal or already present."""
    checked = profile_id(name)
    if checked is None:
        raise ValueError("profile id must be 1 to 64 characters: a-z, 0-9, hyphen")
    home = ProfileHome(Path(data_root), checked)
    if home.exists() or lstat_kind(home.db_path) is not StatKind.MISSING:
        raise ValueError(f"profile {checked} already exists")
    home.path.mkdir(parents=True, exist_ok=True)
    tighten_dir(home.path)
    home.skills_dir.mkdir(parents=True, exist_ok=True)
    home.routines_dir.mkdir(parents=True, exist_ok=True)
    label = display_name.strip() or checked
    # Only the migrated default profile starts unrestricted. Every other
    # new profile starts with an empty allowlist.
    opened = None if checked == "default" else frozenset()
    text = render_policy_toml(
        table="profile",
        schema="praxis.profile/v1",
        profile=checked,
        name=label,
        tools=opened,
        mcp=opened,
    )
    _write(home.config_path, text)
    if lstat_kind(home.soul_path) is StatKind.MISSING:
        _write(home.soul_path, _DEFAULT_SOUL)
    db = StateDB(home.db_path, allow_during_migration=True)
    db.close()
    tighten_file(home.db_path)
    return home


def list_profiles(data_root: Path) -> list[str]:
    root = Path(data_root) / "profiles"
    if lstat_kind(root) is not StatKind.DIR:
        return []
    found: list[str] = []
    try:
        children = list(root.iterdir())
    except OSError:
        return []
    for child in children:
        if lstat_kind(child) is not StatKind.DIR:
            continue
        if profile_id(child.name) is None:
            continue
        if _regular(child / "profile.toml") or _regular(child / "prime.db"):
            found.append(child.name)
    return sorted(found)


def migration_marker(data_root: Path) -> Path:
    return Path(data_root) / "profiles" / ".migration.json"


@dataclass(frozen=True, slots=True)
class RuntimeLayout:
    """Which database, profile, and allowlist a runtime should open."""

    db_path: Path
    profile_id: str
    allowlist: ToolAllowlist | None
    skills_dir: Path | None
    floor_dials: dict[str, str]
    profile_dials: dict[str, str]
    persona_path: Path | None


def resolve_runtime_layout(
    env: Mapping[str, str] | None,
    *,
    data_file: Path | None,
    profile: str | None,
) -> RuntimeLayout:
    """Pick the state file. An explicit database path stays put.

    After the single-user migration marker exists, a default open uses
    ``profiles/default/prime.db`` instead of the old top-level file.
    """
    if profile:
        checked = profile_id(profile)
        if checked is None:
            raise ValueError("invalid profile id")
        root = data_file.parent if data_file is not None else data_dir(env)
        home = ProfileHome(root, checked)
        if lstat_kind(home.config_path) is StatKind.MISSING and not _regular(home.db_path):
            raise ValueError(f"no profile {checked}")
        return _scoped(root, home.db_path, checked, home)
    if data_file is not None:
        return RuntimeLayout(data_file, "", None, None, {}, {}, None)
    root = data_dir(env)
    marker = migration_marker(root)
    default_db = root / "profiles" / "default" / "prime.db"
    if _regular(marker) and _regular(default_db):
        return _scoped(root, default_db, "default", ProfileHome(root, "default"))
    return RuntimeLayout(root / "prime.db", "", None, None, {}, {}, None)


def _regular(path: Path) -> bool:
    """True only for a real file. Symlinks and unreadable paths are not."""
    return lstat_kind(path) is StatKind.FILE


def _scoped(root: Path, db_path: Path, name: str, home: ProfileHome) -> RuntimeLayout:
    org = load_org_policy(root)
    layer = home.layer()
    return RuntimeLayout(
        db_path=db_path,
        profile_id=name,
        allowlist=effective_allowlist(org, layer),
        skills_dir=home.skills_dir,
        floor_dials=org.dials,
        profile_dials=layer.dials,
        persona_path=home.soul_path,
    )


def _write(path: Path, text: str) -> None:
    """Create a regular file. Do not follow a symlink at ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, text.encode())
    finally:
        os.close(descriptor)
    tighten_file(path)
