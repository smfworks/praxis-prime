"""MCP server configuration.

User servers live in ``config.toml`` under ``[mcp.servers.<name>]``.
A project ``.prime/mcp.json`` uses the ``mcpServers`` object that Claude
Code and Cursor write. Project entries override the same name in the user
file. Tokens are not stored here; HTTP auth uses ``token_env``.

ARCHITECTURE §8 and §25.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from praxis_prime.config import dumps_toml, write_default_config

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,40}$")
_DEFAULT_ALLOW = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TERM")
_TRANSPORTS = {"stdio", "http", "sse", "auto"}
_TRUST = {"trusted", "untrusted"}


class McpConfigError(ValueError):
    """The server entry cannot be loaded or saved."""


@dataclass(frozen=True, slots=True)
class ServerSpec:
    """One MCP server. ``env`` values are explicit. The parent environment is not copied."""

    name: str
    transport: str
    command: str = ""
    args: tuple[str, ...] = ()
    env: tuple[tuple[str, str], ...] = ()
    env_allow: tuple[str, ...] | None = None
    url: str = ""
    headers: tuple[tuple[str, str], ...] = ()
    token_env: str = ""
    trust: str = "untrusted"
    sandbox: str = "bwrap"
    network: str = "off"
    write_scope: str = ""
    tool_risks: tuple[tuple[str, str], ...] = ()
    enabled: bool = True
    source: str = "config"

    def allowlist(self) -> tuple[str, ...]:
        if self.env_allow is None:
            return _DEFAULT_ALLOW
        return self.env_allow

    def env_map(self) -> dict[str, str]:
        return dict(self.env)

    def risk_map(self) -> dict[str, str]:
        return dict(self.tool_risks)

    def to_toml_table(self) -> dict[str, object]:
        table: dict[str, object] = {
            "transport": self.transport,
            "trust": self.trust,
            "sandbox": self.sandbox,
            "network": self.network,
            "enabled": self.enabled,
        }
        if self.write_scope:
            table["write_scope"] = self.write_scope
        if self.command:
            table["command"] = self.command
        if self.args:
            table["args"] = list(self.args)
        if self.url:
            table["url"] = self.url
        if self.token_env:
            table["token_env"] = self.token_env
        if self.env:
            table["env"] = dict(self.env)
        if self.env_allow is not None:
            table["env_allow"] = list(self.env_allow)
        if self.headers:
            table["headers"] = dict(self.headers)
        if self.tool_risks:
            table["tools"] = dict(self.tool_risks)
        return table

    def to_mcp_json(self) -> dict[str, object]:
        """Claude Code / Cursor ``mcpServers`` entry, plus our trust fields."""
        body: dict[str, object] = {}
        if self.transport == "stdio" or self.command:
            body["command"] = self.command
            if self.args:
                body["args"] = list(self.args)
        if self.url:
            body["url"] = self.url
            kind = "sse" if self.transport == "sse" else "http"
            body["type"] = kind
        if self.env:
            body["env"] = dict(self.env)
        if self.headers:
            body["headers"] = dict(self.headers)
        if self.token_env:
            body["token_env"] = self.token_env
        if self.env_allow is not None:
            body["envAllow"] = list(self.env_allow)
        body["trust"] = self.trust
        body["sandbox"] = self.sandbox
        body["network"] = self.network
        if self.write_scope:
            body["writeScope"] = self.write_scope
        if not self.enabled:
            body["enabled"] = False
        if self.tool_risks:
            body["toolRisks"] = dict(self.tool_risks)
        return body


def load_servers(
    config_path: Path | None,
    project_root: Path | None = None,
    *,
    include_disabled: bool = False,
) -> list[ServerSpec]:
    """User config first, then ``.prime/mcp.json`` overrides by name."""
    found: dict[str, ServerSpec] = {}
    enabled_flag = True
    if config_path is not None and config_path.is_file():
        document = _load_toml(config_path)
        mcp = _table(document.get("mcp"))
        enabled_flag = _bool(mcp.get("enabled"), default=True)
        for name, raw in _table(mcp.get("servers")).items():
            spec = spec_from_mapping(name, raw, source="config")
            found[spec.name] = spec
    if project_root is not None:
        path = Path(project_root) / ".prime" / "mcp.json"
        if path.is_file():
            for spec in _load_mcp_json(path):
                found[spec.name] = spec
    if not enabled_flag:
        return []
    if include_disabled:
        return list(found.values())
    return [spec for spec in found.values() if spec.enabled]


def mcp_settings(config_path: Path | None) -> tuple[bool, int]:
    """Return ``(serve_enabled, lazy_threshold)``. Serve stays false by default."""
    if config_path is None or not config_path.is_file():
        return False, 8
    mcp = _table(_load_toml(config_path).get("mcp"))
    serve = _bool(mcp.get("serve"), default=False)
    threshold = mcp.get("lazy_threshold", 8)
    try:
        count = int(threshold)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        count = 8
    if count < 1:
        count = 1
    return serve, min(count, 200)


def spec_from_mapping(name: str, raw: object, *, source: str) -> ServerSpec:
    if not isinstance(raw, dict):
        raise McpConfigError(f"MCP server {name} must be a table")
    checked = validate_name(str(name))
    command, args = _command(raw)
    url = _string(raw.get("url"))
    transport = _transport(raw.get("transport") or raw.get("type"), command, url)
    trust = _string(raw.get("trust") or "untrusted").lower()
    if trust not in _TRUST:
        raise McpConfigError(f"MCP server {checked} trust must be trusted or untrusted")
    sandbox = _string(raw.get("sandbox") or "bwrap").lower()
    if sandbox not in {"bwrap", "off"}:
        raise McpConfigError(f"MCP server {checked} sandbox must be bwrap or off")
    # A repository can ship ``.prime/mcp.json``. That file cannot grant a
    # host start. Only the user config can set trusted or sandbox=off.
    if source == "project":
        trust = "untrusted"
        if sandbox == "off":
            sandbox = "bwrap"
    network = _string(raw.get("network") or "off").lower()
    if network not in {"off", "on"}:
        raise McpConfigError(f"MCP server {checked} network must be off or on")
    write_scope = _string(raw.get("write_scope") or raw.get("writeScope"))
    if any(char in write_scope for char in "\r\n\x00"):
        raise McpConfigError(f"MCP server {checked} write_scope cannot contain newlines")
    allow_raw = raw.get("env_allow") if "env_allow" in raw else raw.get("envAllow")
    env_allow = _optional_str_list(allow_raw)
    return ServerSpec(
        name=checked,
        transport=transport,
        command=command,
        args=args,
        env=_pairs(raw.get("env")),
        env_allow=env_allow,
        url=url,
        headers=_pairs(raw.get("headers")),
        token_env=_string(raw.get("token_env") or raw.get("tokenEnv")),
        trust=trust,
        sandbox=sandbox,
        network=network,
        write_scope=write_scope,
        tool_risks=_pairs(
            raw.get("tools") if _is_risk_map(raw.get("tools")) else raw.get("toolRisks")
        ),
        enabled=_bool(raw.get("enabled"), default=True),
        source=source,
    )


def validate_name(name: str) -> str:
    if not _NAME.fullmatch(name) or "__" in name:
        raise McpConfigError(
            "MCP server names are letters, numbers, '_' or '-', up to 41 characters, "
            "and cannot contain '__'"
        )
    return name


def add_server(directory: Path, spec: ServerSpec) -> Path:
    """Insert ``spec`` into ``directory/config.toml``. Dials already in the file stay."""
    path = directory / "config.toml"
    if not path.is_file():
        write_default_config(directory)
    original = path.read_text(encoding="utf-8")
    document = _load_toml(path)
    mcp = _table(document.get("mcp"))
    servers = _table(mcp.get("servers"))
    servers[spec.name] = spec.to_toml_table()
    mcp["servers"] = servers
    document["mcp"] = mcp
    path.write_text(_comment_header(original) + dumps_toml(document), encoding="utf-8")
    return path


def remove_server(directory: Path, name: str) -> bool:
    path = directory / "config.toml"
    if not path.is_file():
        return False
    original = path.read_text(encoding="utf-8")
    document = _load_toml(path)
    mcp = _table(document.get("mcp"))
    servers = _table(mcp.get("servers"))
    if name not in servers:
        return False
    del servers[name]
    mcp["servers"] = servers
    document["mcp"] = mcp
    path.write_text(_comment_header(original) + dumps_toml(document), encoding="utf-8")
    return True


def add_project_server(root: Path, spec: ServerSpec) -> Path:
    path = Path(root) / ".prime" / "mcp.json"
    document = _read_json(path)
    servers = document.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
    servers[spec.name] = spec.to_mcp_json()
    document["mcpServers"] = servers
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


def remove_project_server(root: Path, name: str) -> bool:
    path = Path(root) / ".prime" / "mcp.json"
    if not path.is_file():
        return False
    document = _read_json(path)
    servers = document.get("mcpServers")
    if not isinstance(servers, dict) or name not in servers:
        return False
    del servers[name]
    document["mcpServers"] = servers
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return True


def _load_mcp_json(path: Path) -> list[ServerSpec]:
    document = _read_json(path)
    servers = document.get("mcpServers")
    if not isinstance(servers, dict):
        raise McpConfigError(f"{path} is missing an mcpServers object")
    loaded: list[ServerSpec] = []
    for name, raw in servers.items():
        loaded.append(spec_from_mapping(str(name), raw, source="project"))
    return loaded


def _load_toml(path: Path) -> dict[str, object]:
    loaded = tomllib.loads(path.read_text(encoding="utf-8"))
    if isinstance(loaded, dict):
        return loaded
    return {}


def _read_json(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise McpConfigError(f"{path} is not valid JSON") from exc
    if isinstance(loaded, dict):
        return loaded
    raise McpConfigError(f"{path} must be a JSON object")


def _comment_header(text: str) -> str:
    lines: list[str] = []
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("#") or stripped == "":
            lines.append(line if line.endswith("\n") else line + "\n")
            continue
        break
    return "".join(lines)


def _command(raw: Mapping[str, object]) -> tuple[str, tuple[str, ...]]:
    command = raw.get("command")
    args = _string_list(raw.get("args"))
    if isinstance(command, list):
        parts = [str(item) for item in command if str(item).strip()]
        if not parts:
            return "", tuple(args)
        return parts[0], tuple(parts[1:] + list(args))
    return _string(command), tuple(args)


def _transport(value: object, command: str, url: str) -> str:
    text = _string(value).lower().replace("_", "-")
    aliases = {
        "streamable-http": "http",
        "streamablehttp": "http",
        "http": "http",
        "sse": "sse",
        "stdio": "stdio",
        "auto": "auto",
    }
    if text in aliases:
        kind = aliases[text]
    elif command and not url:
        kind = "stdio"
    elif url and not command:
        kind = "auto"
    elif command:
        kind = "stdio"
    else:
        raise McpConfigError("MCP server needs a command or a url")
    if kind not in _TRANSPORTS:
        raise McpConfigError(f"unknown MCP transport {text}")
    if kind == "stdio" and not command:
        raise McpConfigError("stdio MCP server needs a command")
    if kind in {"http", "sse", "auto"} and not url:
        raise McpConfigError("HTTP MCP server needs a url")
    return kind


def _pairs(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, dict):
        return ()
    pairs: list[tuple[str, str]] = []
    for key, item in value.items():
        if isinstance(item, str):
            pairs.append((str(key), item))
    return tuple(pairs)


def _is_risk_map(value: object) -> bool:
    return isinstance(value, dict) and all(isinstance(item, str) for item in value.values())


def _optional_str_list(value: object) -> tuple[str, ...] | None:
    if value is None:
        return None
    return tuple(_string_list(value))


def _string_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return []


def _string(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _bool(value: object, *, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return default


def _table(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return dict(value)
    return {}
