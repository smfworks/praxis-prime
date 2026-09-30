"""Gateway bearer token.

The token lives in the runtime directory, mode 0600. Once an account
exists it is an owner-equivalent loopback credential. It is not written
to config or the log. ``rotate_token`` replaces the file; the running
daemon keeps the previous value until it is restarted.
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


def rotate_token(path: Path) -> None:
    """Replace the token file. The new value is not returned or logged."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    _write_private(path, secrets.token_urlsafe(32))


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
    """Write the token by replacing a temp file, so readers never see a partial."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, 0o600)
    try:
        os.write(descriptor, (text + "\n").encode("utf-8"))
    except Exception:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    os.close(descriptor)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    os.chmod(path, 0o600)
