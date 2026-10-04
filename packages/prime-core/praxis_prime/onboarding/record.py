"""Verification record for the chosen provider. Mode 0600. No keys, no prompts."""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any

RECORD_NAME = "provider-ready.json"


def record_path(config_directory: Path) -> Path:
    return Path(config_directory) / RECORD_NAME


def read_record(config_directory: Path) -> dict[str, Any]:
    path = record_path(config_directory)
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if isinstance(loaded, dict):
        return loaded
    return {}


def write_record(config_directory: Path, record: dict[str, Any]) -> None:
    path = record_path(config_directory)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(record, sort_keys=True, indent=2) + "\n"
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, 0o600)
    try:
        os.write(descriptor, payload.encode("utf-8"))
    except Exception:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    os.close(descriptor)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def inference_ready(config_directory: Path, model_spec: str) -> bool:
    if not model_spec.strip():
        return False
    record = read_record(config_directory)
    return record.get("ready") is True and record.get("spec") == model_spec.strip()
