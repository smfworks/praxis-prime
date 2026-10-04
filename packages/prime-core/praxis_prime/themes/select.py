"""Choose the theme that the SPA should paint.

Precedence is admin lock, then the profile choice, then the device mode
(``system``, which follows ``prefers-color-scheme`` in the stylesheet), then
``smf.praxis``. The Omarchy live theme is used only when the profile chose
``omarchy`` and the rendered file compiles. A lock also wins on mode when
the lock names one. Device preference is not a stored theme id. ``omarchy``
and ``omarchy.live`` cannot be locked, because the file can change.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from praxis_prime.profiles.home import ProfileHome, org_policy_path
from praxis_prime.statfile import StatKind, lstat_kind
from praxis_prime.themes.errors import ThemeError, ThemeIssue
from praxis_prime.themes.omarchy import LIVE_ID, live_theme
from praxis_prime.themes.store import InstalledTheme, find_theme
from praxis_prime.themes.tokens import MODE_CHOICES

_HEADING = re.compile(r"^\[([A-Za-z0-9_.-]+)\]\s*$")
_DEFAULT_ID = "smf.praxis"


@dataclass(frozen=True, slots=True)
class ThemeChoice:
    theme_id: str
    mode: str
    locked: bool
    requested: str
    installed: InstalledTheme

    @property
    def css_path(self) -> str:
        return f"/themes/{self.installed.package.theme_id}/{self.installed.package_hash}.css"


def resolve_theme(data_root: Path, profile: str = "") -> ThemeChoice:
    """Resolve the package and mode for one profile. Empty profile is public."""
    lock_id, lock_mode = _lock(data_root)
    choice_id, choice_mode = _profile_choice(data_root, profile) if profile else ("", "")
    locked = bool(lock_id)
    if locked:
        requested = lock_id
        mode = lock_mode or choice_mode or "system"
        lookup_id = requested
    elif choice_id == "omarchy":
        # Keep the requested id so the SPA still shows System (Omarchy)
        # when the file is missing or the palette is refused.
        requested = "omarchy"
        mode = choice_mode or "system"
        lookup_id = live_theme() or ""
    elif choice_id:
        requested = choice_id
        mode = choice_mode or "system"
        lookup_id = requested
    else:
        requested = ""
        mode = "system"
        lookup_id = ""
    if mode not in MODE_CHOICES:
        mode = "system"
    installed = _lookup(data_root, lookup_id)
    if installed is None:
        installed = _lookup(data_root, _DEFAULT_ID)
    if installed is None:
        raise ThemeError(
            "default theme is missing",
            (ThemeIssue("not_found", "smf.praxis is not available.", _DEFAULT_ID),),
        )
    return ThemeChoice(
        theme_id=installed.package.theme_id,
        mode=mode,
        locked=locked,
        requested=requested or _DEFAULT_ID,
        installed=installed,
    )


def set_profile_theme(data_root: Path, profile: str, theme_id: str, mode: str) -> ThemeChoice:
    if mode not in MODE_CHOICES:
        raise ThemeError(
            "unknown mode",
            (ThemeIssue("schema", "Mode must be light, dark, or system.", "mode"),),
        )
    home = ProfileHome(data_root, profile)
    if lstat_kind(home.config_path) is not StatKind.FILE:
        raise ThemeError(
            f"no profile {profile}",
            (ThemeIssue("not_found", f"No profile {profile}.", profile),),
        )
    if theme_id != "omarchy" and _lookup(data_root, theme_id) is None:
        raise ThemeError(
            f"theme {theme_id} is not installed",
            (ThemeIssue("not_found", f"No theme {theme_id}.", theme_id),),
        )
    _upsert(home.config_path, "profile.theme", [f'id = "{theme_id}"', f'mode = "{mode}"'])
    return resolve_theme(data_root, profile)


def set_lock(data_root: Path, theme_id: str, mode: str = "") -> None:
    """Lock every profile to ``theme_id``. An empty id unlocks."""
    path = org_policy_path(data_root)
    if not theme_id:
        _drop_only(path, "org.theme")
        return
    if mode and mode not in MODE_CHOICES:
        raise ThemeError(
            "unknown mode",
            (ThemeIssue("schema", "Mode must be light, dark, or system.", "mode"),),
        )
    if theme_id in {"omarchy", LIVE_ID}:
        raise ThemeError(
            "omarchy cannot be locked",
            (
                ThemeIssue(
                    "bad_id",
                    "System (Omarchy) follows a file that can change. Lock a fixed theme.",
                    theme_id,
                ),
            ),
        )
    if _lookup(data_root, theme_id) is None:
        raise ThemeError(
            f"theme {theme_id} is not installed",
            (ThemeIssue("not_found", f"No theme {theme_id}.", theme_id),),
        )
    lines = [f'lock = "{theme_id}"']
    if mode:
        lines.append(f'mode = "{mode}"')
    if lstat_kind(path) is StatKind.MISSING:
        path.parent.mkdir(parents=True, exist_ok=True)
    _upsert(path, "org.theme", lines)


def lock_state(data_root: Path) -> tuple[str, str]:
    return _lock(data_root)


def _lookup(data_root: Path, theme_id: str) -> InstalledTheme | None:
    if theme_id == LIVE_ID:
        from praxis_prime.themes.omarchy import installed

        return installed()
    if not theme_id or theme_id == "omarchy":
        return None
    found = find_theme(data_root, theme_id)
    if found is not None:
        return found
    from praxis_prime.themes.legacy import hint_theme

    return hint_theme(data_root, theme_id)


def _lock(data_root: Path) -> tuple[str, str]:
    section = _read(org_policy_path(data_root), "org", "theme")
    return section.get("lock", ""), section.get("mode", "")


def _profile_choice(data_root: Path, profile: str) -> tuple[str, str]:
    home = ProfileHome(data_root, profile)
    section = _read(home.config_path, "profile", "theme")
    return section.get("id", ""), section.get("mode", "")


def _read(path: Path, table: str, child: str) -> dict[str, str]:
    if lstat_kind(path) is not StatKind.FILE:
        return {}
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            loaded = tomllib.loads(handle.read())
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return {}
    parent = loaded.get(table)
    if not isinstance(parent, dict):
        return {}
    section = parent.get(child)
    if not isinstance(section, dict):
        return {}
    found: dict[str, str] = {}
    for key, value in section.items():
        if isinstance(key, str) and isinstance(value, str):
            found[key] = value
    return found


def _upsert(path: Path, heading: str, lines: list[str]) -> None:
    kind = lstat_kind(path)
    if kind is StatKind.SYMLINK or kind is StatKind.UNREADABLE:
        raise ThemeError(
            "refusing to edit a symlink",
            (ThemeIssue("path_unsafe", f"{path.name} is not a regular file.", path.name),),
        )
    existing = ""
    if kind is StatKind.FILE:
        existing = path.read_text(encoding="utf-8")
    body = _drop_section(existing, heading).rstrip()
    block = f"[{heading}]\n" + "\n".join(lines) + "\n"
    text = f"{body}\n\n{block}" if body else block
    _write(path, text)


def _drop_only(path: Path, heading: str) -> None:
    if lstat_kind(path) is not StatKind.FILE:
        return
    text = _drop_section(path.read_text(encoding="utf-8"), heading)
    _write(path, text if text.strip() else "")


def _drop_section(text: str, heading: str) -> str:
    lines = text.splitlines()
    kept: list[str] = []
    skipping = False
    for line in lines:
        match = _HEADING.match(line.strip())
        if match is not None:
            skipping = match.group(1) == heading
            if skipping:
                continue
        if not skipping:
            kept.append(line)
    return "\n".join(kept).rstrip() + ("\n" if kept else "")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o644)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(temporary, path)
