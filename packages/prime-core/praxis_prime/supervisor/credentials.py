"""Per-worker credentials derived from a master key.

The master key stays in the supervisor. A worker receives only
HMAC-SHA256(master, ``praxis-prime-worker:`` + profile + generation).
Bumping one profile's generation rejects that profile's old credential
and leaves every other profile valid. Rotating the master key invalidates
every derived credential.

The master key is never placed in a worker's environment.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path

_LABEL = b"praxis-prime-worker:"
_KEY_BYTES = 32


class CredentialError(ValueError):
    """A worker credential could not be derived or stored."""


def derive(master: bytes, profile: str, generation: int) -> str:
    """Hex HMAC for one profile generation. ``master`` is the raw key."""
    if len(master) != _KEY_BYTES:
        raise CredentialError("master key must be 32 bytes")
    if not profile or generation < 1:
        raise CredentialError("profile and generation are required")
    message = _LABEL + f"{profile}:{generation}".encode()
    return hmac.new(master, message, hashlib.sha256).hexdigest()


def credential_matches(presented: str, expected: str) -> bool:
    """Constant-time compare. Empty values never match."""
    if not presented or not expected:
        return False
    left = presented.encode()
    right = expected.encode()
    if len(left) != len(right):
        return False
    return hmac.compare_digest(left, right)


def load_or_create_master(path: Path) -> bytes:
    """Read the master key or create it. The file is mode 0600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        data = path.read_bytes()
        if len(data) == _KEY_BYTES:
            os.chmod(path, 0o600)
            return data
        raise CredentialError("worker master key has the wrong length")
    data = secrets.token_bytes(_KEY_BYTES)
    _write_private(path, data)
    return data


def rotate_master(path: Path) -> bytes:
    """Replace the master key. Every derived credential stops matching."""
    data = secrets.token_bytes(_KEY_BYTES)
    _write_private(path, data)
    return data


def load_generations(path: Path) -> dict[str, int]:
    """Profile id to generation. A missing file is generation 1 for everyone."""
    if not path.is_file():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return {}
    if not isinstance(loaded, dict):
        return {}
    found: dict[str, int] = {}
    for key, value in loaded.items():
        if isinstance(key, str) and isinstance(value, int) and value >= 1:
            found[key] = value
    return found


def generation_for(path: Path, profile: str) -> int:
    return load_generations(path).get(profile, 1)


def bump_generation(path: Path, profile: str) -> int:
    """Advance one profile. Other profiles keep their counters."""
    current = load_generations(path)
    nxt = current.get(profile, 1) + 1
    current[profile] = nxt
    _write_private(path, json.dumps(current, sort_keys=True).encode())
    return nxt


def save_generations(path: Path, values: dict[str, int]) -> None:
    _write_private(path, json.dumps(values, sort_keys=True).encode())


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
