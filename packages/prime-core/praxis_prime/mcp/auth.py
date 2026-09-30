"""Resolve HTTP bearer tokens without writing them to config or logs.

``token_env`` is a variable name. The value comes from the environment or
the secrets file (ARCHITECTURE §25). Full OAuth 2.1 is not implemented.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping

from praxis_prime.channels.secrets import parse_env_file, secrets_path
from praxis_prime.mcp.protocol import McpError

_INTERP = re.compile(r"\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}")


def lookup_secret(name: str, env: Mapping[str, str] | None = None) -> str:
    """Return one secret value, or an empty string when it is unset."""
    environ = os.environ if env is None else env
    direct = environ.get(name, "").strip()
    if direct:
        return direct
    path = secrets_path(environ)
    if path is None or not path.is_file():
        return ""
    return parse_env_file(path.read_text(encoding="utf-8")).get(name, "").strip()


def resolve_headers(
    headers: tuple[tuple[str, str], ...],
    token_env: str,
    env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build request headers. ``token_env`` replaces Authorization."""
    environ = os.environ if env is None else env
    resolved: dict[str, str] = {}
    for key, value in headers:
        resolved[key] = _interpolate(value, environ)
    if token_env:
        token = lookup_secret(token_env, environ)
        if not token:
            raise McpError(f"MCP token {token_env} is not set")
        resolved["Authorization"] = f"Bearer {token}"
    return resolved


def _interpolate(value: str, env: Mapping[str, str]) -> str:
    def replacer(match: re.Match[str]) -> str:
        name = match.group(1)
        found = lookup_secret(name, env)
        if not found:
            raise McpError(f"MCP header references {name}, which is not set")
        return found

    return _INTERP.sub(replacer, value)
