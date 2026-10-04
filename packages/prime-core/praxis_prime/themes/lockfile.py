"""Package hashes and theme.lock.json.

The package hash is the SHA-256 of ``path <file-sha256>`` lines in path
order. ``theme.lock.json`` is not an input, so writing the lock does not
change the hash the stylesheet URL uses.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

from praxis_prime.themes.tokens import LOCK_SCHEMA

_LOCK_NAME = "theme.lock.json"


def file_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def package_hash(files: Mapping[str, bytes]) -> str:
    lines = [
        f"{path} {file_sha256(files[path])}"
        for path in sorted(files)
        if path != _LOCK_NAME
    ]
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def lock_document(theme_id: str, version: str, files: Mapping[str, bytes]) -> bytes:
    body = {
        "schema": LOCK_SCHEMA,
        "id": theme_id,
        "version": version,
        "packageHash": package_hash(files),
        "files": {
            path: file_sha256(payload)
            for path, payload in sorted(files.items())
            if path != _LOCK_NAME
        },
    }
    return (json.dumps(body, indent=2, sort_keys=True) + "\n").encode("utf-8")


def parse_lock(data: bytes) -> dict[str, object]:
    loaded = json.loads(data.decode("utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("theme.lock.json must be an object")
    return loaded
