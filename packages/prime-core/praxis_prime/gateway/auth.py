"""Gateway bearer token.

The token lives in the runtime directory, mode 0600. It is the operator
credential for localhost clients. It is not written to config or the log.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from praxis_prime.gateway.protocol import secrets_equal


def load_or_create_token(path: Path) -> str:
    """Read the token file, or create one. The file mode is forced to 0600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    if path.is_file():
        token = path.read_text(encoding="utf-8").strip()
        if token:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return token
    token = secrets.token_urlsafe(32)
    _write_private(path, token)
    return token


def read_token(path: Path) -> str | None:
    if not path.is_file():
        return None
    token = path.read_text(encoding="utf-8").strip()
    return token or None


def bearer_token(headers: dict[str, str]) -> str:
    value = headers.get("authorization", "")
    if len(value) < 8 or not value.lower().startswith("bearer "):
        return ""
    return value[7:].strip()


def token_ok(presented: str, expected: str) -> bool:
    return secrets_equal(presented, expected)


def _write_private(path: Path, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, (text + "\n").encode("utf-8"))
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)
