"""Read the Telegram bot token from the environment or a secrets file.

The token is never written to ``config.toml`` and must not be committed.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from praxis_prime.paths import config_dir

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
