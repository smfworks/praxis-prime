"""Move a single-user install into the ``default`` profile.

The move is idempotent. The first run copies ``prime.db`` (and its WAL
sidecars) into ``backups/`` before the file is placed under
``profiles/default/``. A second run sees the marker and does not copy
again. User skills are copied, not removed from the config directory.

docs/blueprint-addendum-2026-09.md §6.3.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from praxis_prime.privatefile import tighten_dir, tighten_file
from praxis_prime.profiles.home import ProfileHome, create_profile, migration_marker
from praxis_prime.profiles.policy import render_policy_toml

_SIDECARS = ("", "-wal", "-shm", "-journal")


@dataclass(frozen=True, slots=True)
class MigrationResult:
    profile_id: str
    backup: str
    already: bool
    owner_account: str


def migrate_single_user(
    data_root: Path,
    config_dir: Path | None = None,
    *,
    owner_account: str = "",
) -> MigrationResult:
    """Migrate once. A later call returns the recorded result."""
    root = Path(data_root)
    marker = migration_marker(root)
    if marker.is_file():
        recorded = _read_marker(marker)
        if owner_account and not recorded.owner_account:
            _write_marker(marker, recorded.profile_id, recorded.backup, owner_account)
            return MigrationResult(
                recorded.profile_id,
                recorded.backup,
                True,
                owner_account,
            )
        return MigrationResult(recorded.profile_id, recorded.backup, True, recorded.owner_account)

    home = ProfileHome(root, "default")
    backup_rel = ""
    legacy = root / "prime.db"
    if home.db_path.is_file() and not legacy.is_file():
        _ensure_tree(home, config_dir)
    elif legacy.is_file() or _any_legacy(root):
        backup_rel = _backup_legacy(root, home)
        _ensure_tree(home, config_dir)
        _copy_skills(config_dir, home)
        _apply_config_dials(config_dir, home)
    else:
        create_profile(root, "default", display_name="Default")
        _copy_skills(config_dir, home)
        _apply_config_dials(config_dir, home)
    _write_marker(marker, "default", backup_rel, owner_account)
    return MigrationResult("default", backup_rel, False, owner_account)


def _ensure_tree(home: ProfileHome, config_dir: Path | None) -> None:
    if home.exists():
        home.skills_dir.mkdir(parents=True, exist_ok=True)
        home.routines_dir.mkdir(parents=True, exist_ok=True)
        tighten_dir(home.path)
        return
    home.path.mkdir(parents=True, exist_ok=True)
    tighten_dir(home.path)
    home.skills_dir.mkdir(parents=True, exist_ok=True)
    home.routines_dir.mkdir(parents=True, exist_ok=True)
    if not home.config_path.is_file():
        text = render_policy_toml(
            table="profile",
            schema="praxis.profile/v1",
            profile="default",
            name="Default",
        )
        home.config_path.write_text(text, encoding="utf-8")
        tighten_file(home.config_path)
    if not home.soul_path.is_file():
        home.soul_path.write_text(
            "# Persona\n\nSubordinate to the Praxis Prime safety rules.\n",
            encoding="utf-8",
        )
        tighten_file(home.soul_path)


def _backup_legacy(root: Path, home: ProfileHome) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup = root / "backups" / f"pre-profile-{stamp}"
    backup.mkdir(parents=True, exist_ok=False)
    tighten_dir(backup)
    legacy = root / "prime.db"
    if legacy.is_file():
        _checkpoint(legacy)
    for suffix in _SIDECARS:
        source = Path(f"{legacy}{suffix}") if suffix else legacy
        if not source.is_file():
            continue
        target = backup / source.name
        shutil.copy2(source, target)
        tighten_file(target)
    home.path.mkdir(parents=True, exist_ok=True)
    tighten_dir(home.path)
    if legacy.is_file() and not home.db_path.exists():
        home.db_path.parent.mkdir(parents=True, exist_ok=True)
        legacy.replace(home.db_path)
        tighten_file(home.db_path)
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(f"{legacy}{suffix}")
            if sidecar.is_file():
                sidecar.unlink()
    elif legacy.is_file():
        held = backup / "legacy-left-in-place.txt"
        held.write_text(
            "profiles/default/prime.db already existed. The previous prime.db was copied here.\n",
            encoding="utf-8",
        )
        legacy.replace(backup / "prime.db.unmoved")
        tighten_file(backup / "prime.db.unmoved")
    relative = backup.relative_to(root).as_posix()
    return relative


def _copy_skills(config_dir: Path | None, home: ProfileHome) -> None:
    if config_dir is None:
        return
    source = config_dir / "skills"
    if not source.is_dir():
        return
    home.skills_dir.mkdir(parents=True, exist_ok=True)
    for path in source.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(source)
        if any(part.startswith(".") or part == ".." for part in relative.parts):
            continue
        target = home.skills_dir / relative
        if target.exists():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)


def _apply_config_dials(config_dir: Path | None, home: ProfileHome) -> None:
    if config_dir is None or not home.config_path.is_file():
        return
    config = config_dir / "config.toml"
    if not config.is_file():
        return
    try:
        loaded = tomllib.loads(config.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return
    raw = loaded.get("dials")
    if not isinstance(raw, dict) or not raw:
        return
    from praxis_prime.profiles.policy import load_layer

    try:
        layer = load_layer(home.config_path, table="profile")
    except ValueError:
        return
    if layer.dials:
        return
    text = render_policy_toml(
        table="profile",
        schema="praxis.profile/v1",
        profile="default",
        name="Default",
        dials={str(key): str(value) for key, value in raw.items()},
    )
    home.config_path.write_text(text, encoding="utf-8")
    tighten_file(home.config_path)


def _any_legacy(root: Path) -> bool:
    legacy = root / "prime.db"
    return any(Path(f"{legacy}{suffix}").is_file() for suffix in _SIDECARS if suffix)


def _checkpoint(path: Path) -> None:
    try:
        conn = sqlite3.connect(path)
    except sqlite3.Error:
        return
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.Error:
        pass
    finally:
        conn.close()


def _read_marker(path: Path) -> MigrationResult:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return MigrationResult("default", "", True, "")
    if not isinstance(loaded, dict):
        return MigrationResult("default", "", True, "")
    return MigrationResult(
        str(loaded.get("profile") or "default"),
        str(loaded.get("backup") or ""),
        True,
        str(loaded.get("owner_account") or ""),
    )


def _write_marker(path: Path, profile: str, backup: str, owner_account: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tighten_dir(path.parent)
    payload = {
        "version": 1,
        "profile": profile,
        "backup": backup,
        "owner_account": owner_account,
        "migrated_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    tighten_file(path)
