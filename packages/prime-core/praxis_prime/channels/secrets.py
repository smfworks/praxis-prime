"""Read and write secrets in the environment or a secrets file.

The Telegram bot token and OIDC client secrets live here. They are never
written to ``config.toml`` and must not be committed or logged.
"""

from __future__ import annotations

import os
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path

from praxis_prime.paths import config_dir
from praxis_prime.privatefile import tighten_dir, tighten_file

_SECRET_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,80}$")

TOKEN_ENV = "PRAXIS_PRIME_TELEGRAM_BOT_TOKEN"
SECRETS_ENV = "PRAXIS_PRIME_SECRETS_FILE"


def load_telegram_token(env: Mapping[str, str] | None = None) -> str:
    """Return the bot token, or an empty string when Telegram is not configured."""
    environ = os.environ if env is None else env
    direct = environ.get(TOKEN_ENV, "").strip()
    if direct:
        return direct
    path = secrets_path(environ)
    if path is None or not path.is_file():
        return ""
    return parse_env_file(path.read_text(encoding="utf-8")).get(TOKEN_ENV, "").strip()


def secrets_path(env: Mapping[str, str] | None = None) -> Path | None:
    environ = os.environ if env is None else env
    override = environ.get(SECRETS_ENV, "").strip()
    if override:
        return Path(override)
    return config_dir(environ) / "secrets.env"


def write_secret(path: Path, key: str, value: str) -> None:
    """Store one value in a ``KEY=VALUE`` file. The value is not logged.

    The file is replaced atomically and left mode 0600. A value with a
    newline, quote, or backslash is refused so the line cannot break the
    parser or hide a second assignment.
    """
    if not _SECRET_KEY.fullmatch(key):
        raise ValueError("invalid secret name")
    if not _secret_value_ok(value):
        raise ValueError("invalid secret value")
    path.parent.mkdir(parents=True, exist_ok=True)
    tighten_dir(path.parent)
    current: dict[str, str] = {}
    if path.is_file():
        current = parse_env_file(path.read_text(encoding="utf-8"))
    current[key] = value
    _replace_env_file(path, current)


def delete_secret(path: Path, key: str) -> None:
    """Remove one key. Missing files and missing keys are left alone."""
    if not _SECRET_KEY.fullmatch(key) or not path.is_file():
        return
    current = parse_env_file(path.read_text(encoding="utf-8"))
    if key not in current:
        return
    del current[key]
    _replace_env_file(path, current)


def secret_file(config: Path | None = None, env: Mapping[str, str] | None = None) -> Path:
    """The secrets file the daemon reads, or one under ``config``."""
    path = secrets_path(env)
    if path is not None and (env or os.environ).get(SECRETS_ENV, "").strip():
        return path
    if config is not None:
        return Path(config) / "secrets.env"
    assert path is not None
    return path


def parse_env_file(text: str) -> dict[str, str]:
    """Parse ``KEY=VALUE`` lines. Comments and blanks are ignored."""
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def _secret_value_ok(value: str) -> bool:
    if not isinstance(value, str) or not value or len(value) > 2048:
        return False
    if value.strip() != value:
        return False
    return not any(ord(char) < 32 or char in "\"'\\" for char in value)


def _replace_env_file(path: Path, values: dict[str, str]) -> None:
    lines = [f"{key}={values[key]}\n" for key in sorted(values)]
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".secrets-")
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.writelines(lines)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    tighten_file(path)
