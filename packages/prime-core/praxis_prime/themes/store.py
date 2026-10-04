"""Built-in, system, and user theme packages.

Built-ins live in the wheel at ``praxis_prime/ui_themes``. User themes live
in ``<data>/themes/<id>/<version>/``. System themes live in
``/var/lib/praxis-prime/themes``. A user copy wins over a system copy, which
wins over a built-in. Inside one source the highest ``MAJOR.MINOR.PATCH``
wins. ``theme.lock.json`` records the SHA-256 of every file and the package
hash. The lock file is not part of that hash.
"""

from __future__ import annotations

import os
import re
import shutil
import time
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from praxis_prime.paths import data_dir
from praxis_prime.statfile import StatKind, lstat_kind
from praxis_prime.themes.archive import read_dir
from praxis_prime.themes.errors import ThemeError, ThemeIssue
from praxis_prime.themes.lockfile import lock_document, package_hash
from praxis_prime.themes.model import ThemePackage
from praxis_prime.themes.validate import validate_files

SYSTEM_ROOT = Path("/var/lib/praxis-prime/themes")
_SOURCE_RANK = {"user": 0, "system": 1, "builtin": 2}
_builtin_cache: dict[str, InstalledTheme] = {}


@dataclass(frozen=True, slots=True)
class InstalledTheme:
    package: ThemePackage
    source: str
    root: Path | None
    package_hash: str

    def version_tuple(self) -> tuple[int, int, int]:
        return self.package.version_tuple()


def user_themes_root(data_root: Path | None = None) -> Path:
    return _root(data_root) / "themes"


def builtin_ids() -> list[str]:
    root = files("praxis_prime.ui_themes")
    found: list[str] = []
    for child in root.iterdir():
        name = child.name
        if name.startswith(("_", ".")) or name.endswith(".py"):
            continue
        if child.is_dir():
            found.append(name)
    return sorted(found)


def builtin_theme(theme_id: str) -> InstalledTheme | None:
    return _builtin(theme_id)


def read_builtin_files(theme_id: str) -> dict[str, bytes]:
    root = files("praxis_prime.ui_themes").joinpath(theme_id)
    if not root.is_dir():
        raise ThemeError(
            f"no built-in theme {theme_id}",
            (ThemeIssue("not_found", f"No built-in theme {theme_id}.", theme_id),),
        )
    return _read_tree(root, "")


def install_files(
    file_map: Mapping[str, bytes],
    data_root: Path | None = None,
    *,
    system: bool = False,
) -> InstalledTheme:
    """Validate and write one version. A symlink destination is refused."""
    package = validate_files(file_map)
    root = SYSTEM_ROOT if system else user_themes_root(data_root)
    return _place(package, root, "system" if system else "user")


def remove_theme(theme_id: str, data_root: Path | None = None, *, system: bool = False) -> str:
    """Remove every version of ``theme_id`` from the user or system store.

    Built-ins stay in the wheel. Removing a user copy uncovers the built-in.
    """
    root = SYSTEM_ROOT if system else user_themes_root(data_root)
    target = root / theme_id
    kind = lstat_kind(target)
    if kind is StatKind.SYMLINK:
        raise ThemeError(
            "refusing to remove a symlink",
            (ThemeIssue("path_unsafe", "The theme path is a symlink.", theme_id),),
        )
    if kind is not StatKind.DIR:
        if theme_id in builtin_ids():
            raise ThemeError(
                "built-in themes cannot be removed",
                (
                    ThemeIssue(
                        "forbidden",
                        f"{theme_id} is built in and cannot be removed.",
                        theme_id,
                        "Install a different theme instead of deleting this one.",
                    ),
                ),
            )
        raise ThemeError(
            f"theme {theme_id} is not installed",
            (ThemeIssue("not_found", f"No installed theme {theme_id}.", theme_id),),
        )
    shutil.rmtree(target)
    return theme_id


def list_themes(data_root: Path | None = None) -> list[InstalledTheme]:
    found: list[InstalledTheme] = []
    for theme_id in builtin_ids():
        loaded = _builtin(theme_id)
        if loaded is not None:
            found.append(loaded)
    data = _root(data_root)
    user = user_themes_root(data)
    found.extend(_scan(user, "user"))
    if not _same(user, SYSTEM_ROOT):
        found.extend(_scan(SYSTEM_ROOT, "system"))
    return found


def winners(data_root: Path | None = None) -> dict[str, InstalledTheme]:
    """One package per id, after source and version precedence."""
    chosen: dict[str, InstalledTheme] = {}
    for item in list_themes(data_root):
        current = chosen.get(item.package.theme_id)
        if current is None or _better(item, current):
            chosen[item.package.theme_id] = item
    return chosen


def find_theme(data_root: Path | None, theme_id: str) -> InstalledTheme | None:
    return winners(data_root).get(theme_id)


def stage_theme(package: ThemePackage, data_root: Path | None = None) -> str:
    """Keep a validated package for about 15 minutes so install can commit it."""
    digest = package_hash(package.files)
    root = _stage_dir(data_root)
    root.mkdir(parents=True, exist_ok=True)
    dest = root / digest
    if lstat_kind(dest) is StatKind.SYMLINK:
        raise ThemeError(
            "refusing to stage through a symlink",
            (ThemeIssue("path_unsafe", "The stage path is a symlink.", digest),),
        )
    if lstat_kind(dest) is not StatKind.MISSING:
        shutil.rmtree(dest)
    dest.mkdir()
    for relative, payload in package.files.items():
        path = dest.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        _write_bytes(path, payload)
    _write_bytes(root / f"{digest}.time", str(time.time()).encode("utf-8"))
    return digest


def take_stage(digest: str, data_root: Path | None = None) -> dict[str, bytes] | None:
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        return None
    root = _stage_dir(data_root)
    stamp = root / f"{digest}.time"
    dest = root / digest
    if lstat_kind(stamp) is not StatKind.FILE or lstat_kind(dest) is not StatKind.DIR:
        return None
    try:
        created = float(stamp.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return None
    if time.time() - created > 15 * 60:
        shutil.rmtree(dest, ignore_errors=True)
        stamp.unlink(missing_ok=True)
        return None
    try:
        return read_dir(dest)
    except ThemeError:
        return None


def _stage_dir(data_root: Path | None) -> Path:
    return _root(data_root) / "theme-stage"


def find_hash(data_root: Path | None, theme_id: str, digest: str) -> InstalledTheme | None:
    for item in list_themes(data_root):
        if item.package.theme_id == theme_id and item.package_hash == digest:
            return item
    return None


def _place(package: ThemePackage, root: Path, source: str) -> InstalledTheme:
    base = root / package.theme_id
    if lstat_kind(base) is StatKind.SYMLINK:
        raise ThemeError(
            "refusing to install through a symlink",
            (ThemeIssue("path_unsafe", "The theme directory is a symlink.", package.theme_id),),
        )
    base.mkdir(parents=True, exist_ok=True)
    stage = base / f".{package.version}.{os.getpid()}.tmp"
    if lstat_kind(stage) is not StatKind.MISSING:
        raise ThemeError(
            "theme install is already in progress",
            (ThemeIssue("path_unsafe", "A staging directory already exists.", package.theme_id),),
        )
    stage.mkdir()
    try:
        for relative, payload in package.files.items():
            dest = stage.joinpath(*relative.split("/"))
            if dest.parent != stage:
                dest.parent.mkdir(parents=True, exist_ok=True)
            _write_bytes(dest, payload)
        _write_bytes(stage / "theme.lock.json",
            lock_document(package.theme_id, package.version, package.files))
        final = base / package.version
        if lstat_kind(final) is StatKind.SYMLINK:
            raise ThemeError(
                "refusing to replace a symlink",
                (
                    ThemeIssue(
                        "path_unsafe",
                        "The version directory is a symlink.",
                        package.theme_id,
                    ),
                ),
            )
        if lstat_kind(final) is StatKind.DIR:
            backup = base / f".{package.version}.old.{os.getpid()}"
            os.rename(final, backup)
            os.rename(stage, final)
            shutil.rmtree(backup)
        else:
            os.rename(stage, final)
    except Exception:
        if lstat_kind(stage) is StatKind.DIR:
            shutil.rmtree(stage, ignore_errors=True)
        raise
    digest = package_hash(package.files)
    return InstalledTheme(package, source, final, digest)


def _scan(root: Path, source: str) -> list[InstalledTheme]:
    if lstat_kind(root) is not StatKind.DIR:
        return []
    found: list[InstalledTheme] = []
    try:
        children = list(root.iterdir())
    except OSError:
        return []
    for child in children:
        if lstat_kind(child) is not StatKind.DIR:
            continue
        try:
            versions = list(child.iterdir())
        except OSError:
            continue
        for version_dir in versions:
            if version_dir.name.startswith(".") or lstat_kind(version_dir) is not StatKind.DIR:
                continue
            try:
                file_map = read_dir(version_dir)
                package = validate_files(file_map)
            except (ThemeError, OSError):
                continue
            if package.theme_id != child.name:
                continue
            found.append(
                InstalledTheme(package, source, version_dir, package_hash(package.files))
            )
    return found


def _builtin(theme_id: str) -> InstalledTheme | None:
    cached = _builtin_cache.get(theme_id)
    if cached is not None:
        return cached
    try:
        file_map = read_builtin_files(theme_id)
        package = validate_files(file_map)
    except (ThemeError, OSError, FileNotFoundError):
        return None
    loaded = InstalledTheme(package, "builtin", None, package_hash(package.files))
    _builtin_cache[theme_id] = loaded
    return loaded


def _read_tree(node: object, prefix: str) -> dict[str, bytes]:
    found: dict[str, bytes] = {}
    for child in node.iterdir():  # type: ignore[attr-defined]
        name = child.name
        if name.startswith(("_", ".")) or name == "__pycache__":
            continue
        relative = f"{prefix}/{name}" if prefix else name
        if child.is_dir():
            found.update(_read_tree(child, relative))
        elif child.is_file():
            found[relative] = child.read_bytes()
    return found


def _better(item: InstalledTheme, current: InstalledTheme) -> bool:
    rank = (_SOURCE_RANK[item.source], tuple(-part for part in item.version_tuple()))
    other = (_SOURCE_RANK[current.source], tuple(-part for part in current.version_tuple()))
    return rank < other


def _root(data_root: Path | None) -> Path:
    if data_root is None:
        return data_dir()
    return Path(data_root)


def _same(left: Path, right: Path) -> bool:
    if lstat_kind(left) is StatKind.MISSING and lstat_kind(right) is StatKind.MISSING:
        return False
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return False


def _write_bytes(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o644)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
