"""Merge a setup change into config.toml. The previous file is backed up first."""

from __future__ import annotations

import os
import secrets
import time
import tomllib
from collections.abc import Mapping
from pathlib import Path

from praxis_prime.config import default_config_document, dumps_toml
from praxis_prime.statfile import StatKind, lstat_kind

_BACKUP_KEEP = 5


def load_document(path: Path) -> dict[str, object]:
    if not path.is_file():
        return default_config_document()
    loaded = tomllib.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        return default_config_document()
    return loaded


def backup_config(path: Path) -> Path | None:
    """Copy config.toml to a timestamped mode-0600 file. Missing files are skipped."""
    if not path.is_file():
        return None
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    dest = path.with_name(f"config.toml.bak-{stamp}")
    suffix = 0
    while dest.exists():
        suffix += 1
        dest = path.with_name(f"config.toml.bak-{stamp}-{suffix}")
    _write_private(dest, path.read_bytes())
    _prune_backups(path)
    return dest


def _prune_backups(path: Path) -> None:
    """Keep the newest ``config.toml.bak-*`` files. Names sort by time."""
    found = [
        item
        for item in path.parent.glob(f"{path.name}.bak-*")
        if lstat_kind(item) is StatKind.FILE
    ]
    for item in sorted(found)[:-_BACKUP_KEEP]:
        try:
            item.unlink()
        except OSError:
            continue


def write_document(path: Path, document: Mapping[str, object], *, previous: str = "") -> None:
    header = _leading_comments(previous)
    body = dumps_toml(document)
    text = f"{header}{body}" if header else body
    if not text.endswith("\n"):
        text += "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_private(path, text.encode("utf-8"))


def _leading_comments(text: str) -> str:
    if not text.startswith("#"):
        return ""
    kept: list[str] = []
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("#") or stripped == "":
            kept.append(line if line.endswith("\n") else line + "\n")
            continue
        break
    if kept and kept[-1].strip():
        kept.append("\n")
    return "".join(kept)


def _write_private(path: Path, data: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, 0o600)
    try:
        os.write(descriptor, data)
    except Exception:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    os.close(descriptor)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    os.chmod(path, 0o600)
