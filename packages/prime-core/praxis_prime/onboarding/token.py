"""Single-use first-run token. It is not the loopback bearer token.

The bearer stays owner-equivalent after an account exists. This token is
deleted the moment an owner exists, so it cannot be reused to open setup.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from praxis_prime.gateway.protocol import secrets_equal

TOKEN_NAME = "first-run.token"
HEADER_NAME = "x-praxis-setup-token"


def token_path(config_directory: Path) -> Path:
    return Path(config_directory) / TOKEN_NAME


def ensure_first_run_token(config_directory: Path) -> str:
    """Return the current token, creating a mode-0600 file when needed."""
    path = token_path(config_directory)
    current = read_first_run_token(config_directory)
    if current:
        return current
    value = secrets.token_hex(32)
    _write_private(path, value)
    return value


def read_first_run_token(config_directory: Path) -> str:
    path = token_path(config_directory)
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def invalidate_first_run_token(config_directory: Path) -> None:
    """Delete the token. A later read never matches."""
    path = token_path(config_directory)
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError:
        try:
            _write_private(path, "")
            path.unlink()
        except OSError:
            return


def token_matches(config_directory: Path, presented: str) -> bool:
    """Constant-time compare against the file. Empty never matches."""
    return secrets_equal(read_first_run_token(config_directory), presented.strip())


def _write_private(path: Path, text: str) -> None:
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
