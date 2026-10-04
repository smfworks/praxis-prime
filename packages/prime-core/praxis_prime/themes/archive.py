"""Read and write a theme directory or zip without leaving the package root.

Limits from Addendum A §1.5: 5 MiB compressed, 15 MiB expanded, 200 files.
Ornaments are at most 256 KiB. Extraction never follows a symlink and never
uses ``extractall``.
"""

from __future__ import annotations

import io
import os
import re
import stat
import zipfile
import zlib
from collections.abc import Mapping
from pathlib import Path

from praxis_prime.statfile import StatKind, lstat_kind
from praxis_prime.themes.errors import ThemeError, ThemeIssue

MAX_ZIP_BYTES = 5 * 1024 * 1024
MAX_EXPANDED_BYTES = 15 * 1024 * 1024
MAX_FILES = 200
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_ORNAMENT_BYTES = 256 * 1024
MAX_CSS_BYTES = 32 * 1024
MAX_PREVIEW_BYTES = 1 * 1024 * 1024

_ROOT_FILES = frozenset(
    {
        "theme.toml",
        "theme.css",
        "theme.lock.json",
        "THEME.md",
        "LICENSE",
        "LICENSE.txt",
        "NOTICE",
        "OFL.txt",
    }
)
_SCRIPT_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".html", ".htm", ".wasm"})
# Every asset name is a single path segment. Quotes, slashes, and CSS
# punctuation cannot appear, so a filename cannot break out of url("...").
_ASSET_PATH = re.compile(r"^assets/(fonts|ornaments)/[A-Za-z0-9._-]+$")
FONT_PATH = re.compile(r"^assets/fonts/[A-Za-z0-9._-]+\.woff2$")
ORNAMENT_PATH = re.compile(r"^assets/ornaments/[A-Za-z0-9._-]+\.(?:svg|png|webp)$")
_FONT_SIDECAR = frozenset({"OFL.txt", "LICENSE", "LICENSE.txt"})


def read_zip(data: bytes) -> dict[str, bytes]:
    """Return archive members. Raises ``ThemeError`` on a limit or a traversal."""
    if len(data) > MAX_ZIP_BYTES:
        raise ThemeError(
            "theme zip is larger than 5 MiB",
            (_issue("zip_too_large", "Compress the package under 5 MiB.", "package.zip"),),
        )
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, zlib.error) as exc:
        raise _damaged_zip() from exc
    files: dict[str, bytes] = {}
    total = 0
    try:
        with archive:
            infos = archive.infolist()
            if len(infos) > MAX_FILES:
                raise ThemeError(
                    "theme zip has too many members",
                    (
                        _issue(
                            "zip_too_many",
                            "Keep the package to 200 files or fewer.",
                            "package.zip",
                        ),
                    ),
                )
            for info in infos:
                if info.flag_bits & 0x1:
                    raise ThemeError(
                        "encrypted theme zip",
                        (_issue("zip_encrypted", "Do not encrypt the zip.", info.filename),),
                    )
                if stat.S_ISLNK(info.external_attr >> 16):
                    raise ThemeError(
                        "theme zip contains a symlink",
                        (
                            _issue(
                                "zip_symlink",
                                "Remove the symlink and pack regular files.",
                                info.filename,
                            ),
                        ),
                    )
                name = _member_name(info.filename)
                if name is None:
                    raise ThemeError(
                        "theme zip path escapes the package",
                        (
                            _issue(
                                "zip_traversal",
                                "Use relative paths inside the zip. No absolute paths or '..'.",
                                info.filename,
                            ),
                        ),
                    )
                if not name:
                    continue
                if name in files:
                    raise ThemeError(
                        "theme zip repeats a file name",
                        (
                            _issue(
                                "zip_duplicate",
                                "Each file name must appear once.",
                                name,
                            ),
                        ),
                    )
                if info.file_size > MAX_FILE_BYTES or info.file_size > MAX_EXPANDED_BYTES:
                    raise ThemeError(
                        "theme file is over the size limit",
                        (_issue("file_too_large", "Keep each file under 4 MiB.", name),),
                    )
                total += info.file_size
                if total > MAX_EXPANDED_BYTES:
                    raise ThemeError(
                        "theme zip expands past 15 MiB",
                        (_issue("zip_too_large", "Keep the expanded package under 15 MiB.", name),),
                    )
                try:
                    payload = archive.read(info)
                except (zipfile.BadZipFile, zlib.error) as exc:
                    raise _damaged_zip(name) from exc
                if len(payload) > MAX_FILE_BYTES:
                    raise ThemeError(
                        "theme file is over the size limit",
                        (_issue("file_too_large", "Keep each file under 4 MiB.", name),),
                    )
                files[name] = payload
    except ThemeError:
        raise
    except (zipfile.BadZipFile, zlib.error) as exc:
        raise _damaged_zip() from exc
    _check_layout(files)
    return files


def read_dir(root: Path) -> dict[str, bytes]:
    """Read a theme directory. Symlinks are refused."""
    kind = lstat_kind(root)
    if kind is not StatKind.DIR:
        raise ThemeError(
            "theme directory is missing",
            (
                _issue(
                    "path_unsafe",
                    "Point lint or pack at a directory of theme files.",
                    str(root),
                ),
            ),
        )
    files: dict[str, bytes] = {}
    total = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        if lstat_kind(current) is StatKind.SYMLINK:
            raise ThemeError(
                "theme directory contains a symlink",
                (_issue("zip_symlink", "Remove the symlink.", str(current)),),
            )
        dirnames[:] = sorted(dirnames)
        for filename in sorted(filenames):
            path = current / filename
            kind = lstat_kind(path)
            if kind is StatKind.SYMLINK:
                raise ThemeError(
                    "theme directory contains a symlink",
                    (
                        _issue(
                            "zip_symlink",
                            "Remove the symlink and use a regular file.",
                            filename,
                        ),
                    ),
                )
            if kind is not StatKind.FILE:
                raise ThemeError(
                    "theme package contains a non-regular file",
                    (_issue("path_unsafe", "Pack only regular files.", filename),),
                )
            relative = path.relative_to(root).as_posix()
            if _member_name(relative) != relative:
                raise ThemeError(
                    "theme path escapes the package",
                    (
                        _issue(
                            "zip_traversal",
                            "Use relative paths. No absolute paths or '..'.",
                            relative,
                        ),
                    ),
                )
            size = path.stat().st_size
            total += size
            if size > MAX_FILE_BYTES or total > MAX_EXPANDED_BYTES or len(files) >= MAX_FILES:
                code = "zip_too_many" if len(files) >= MAX_FILES else "file_too_large"
                raise ThemeError(
                    "theme directory is over the size limit",
                    (_issue(code, "Stay within 200 files, 4 MiB each, 15 MiB total.", relative),),
                )
            files[relative] = path.read_bytes()
    _check_layout(files)
    return files


def write_zip(files: Mapping[str, bytes], dest: Path) -> None:
    """Write a theme zip of regular file members."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files):
            info = zipfile.ZipInfo(filename=path, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o644 & 0xFFFF) << 16
            archive.writestr(info, files[path])


def _member_name(raw: str) -> str | None:
    text = raw.replace("\\", "/")
    if text.startswith("/") or _has_drive(text):
        return None
    parts = [part for part in text.split("/") if part not in {"", "."}]
    if any(part == ".." for part in parts):
        return None
    if text.endswith("/"):
        return ""
    return "/".join(parts)


def _has_drive(text: str) -> bool:
    return len(text) >= 2 and text[1] == ":" and text[0].isalpha()


def _check_layout(files: Mapping[str, bytes]) -> None:
    issues: list[ThemeIssue] = []
    if len(files) > MAX_FILES:
        issues.append(_issue("zip_too_many", "Keep the package to 200 files or fewer.", ""))
    for path, payload in files.items():
        suffix = Path(path).suffix.lower()
        if suffix in _SCRIPT_SUFFIXES or path.lower().endswith(".svg.js"):
            issues.append(
                _issue(
                    "file_type",
                    "JavaScript, HTML, and WASM cannot ship in a theme.",
                    path,
                )
            )
            continue
        if not _allowed(path):
            issues.append(
                _issue(
                    "file_type",
                    "This file is not part of a theme package.",
                    path,
                )
            )
            continue
        limit = _size_limit(path)
        if len(payload) > limit:
            issues.append(_issue("file_too_large", f"Keep this file under {limit} bytes.", path))
    if issues:
        raise ThemeError(issues[0].message, tuple(issues))


def _allowed(path: str) -> bool:
    """Fixed top-level files, or one safe name under assets/fonts or assets/ornaments."""
    if path in _ROOT_FILES:
        return True
    if _ASSET_PATH.fullmatch(path) is None:
        return False
    folder = path.split("/", 2)[1]
    name = path.split("/", 2)[2]
    if folder == "fonts":
        return FONT_PATH.fullmatch(path) is not None or name in _FONT_SIDECAR
    return ORNAMENT_PATH.fullmatch(path) is not None


def _size_limit(path: str) -> int:
    if path == "theme.css":
        return MAX_CSS_BYTES
    if path.startswith("assets/ornaments/"):
        return MAX_ORNAMENT_BYTES
    if path.startswith("assets/preview."):
        return MAX_PREVIEW_BYTES
    return MAX_FILE_BYTES


def _damaged_zip(path: str = "package.zip") -> ThemeError:
    return ThemeError(
        "theme zip is damaged",
        (
            _issue(
                "zip_invalid",
                "The zip is damaged (bad CRC, name, or compression). Pack it again.",
                path,
            ),
        ),
    )


def _issue(code: str, message: str, path: str) -> ThemeIssue:
    return ThemeIssue(code=code, message=message, path=path, fix=message)
