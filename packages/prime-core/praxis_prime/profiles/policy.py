"""Org policy floor and the per-profile tool allowlist.

The org file is the ceiling. A profile intersects it. ``*`` means no
extra restriction at that layer. An empty list allows nothing. A profile
that names a tool the org omitted does not gain that tool.

Dials use the same direction: ``off`` < ``monitor`` < ``enforce``. A
profile position below the floor is raised to the floor.

Enforcement of the tool list happens at tool dispatch, not only in the UI.
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from praxis_prime.policy.dials import DIAL_POSITIONS, default_positions

_RANK = {"off": 0, "monitor": 1, "enforce": 2}
_MCP_META = frozenset({"mcp_find_tools", "mcp_read_resource", "mcp_get_prompt"})


@dataclass(frozen=True, slots=True)
class LayerAllow:
    """``None`` means unrestricted. A frozenset is the exact set."""

    tools: frozenset[str] | None
    mcp: frozenset[str] | None
    dials: dict[str, str]


@dataclass(frozen=True, slots=True)
class ToolAllowlist:
    """The intersection the dispatcher consults."""

    tools: frozenset[str] | None
    mcp: frozenset[str] | None

    def permits_tool(self, name: str) -> bool:
        if name.startswith("mcp__"):
            server = _mcp_server(name)
            if not server or not _named(server, self.mcp):
                return False
            return _named(name, self.tools)
        if name in _MCP_META:
            if self.mcp is not None and not self.mcp:
                return False
            return _named(name, self.tools)
        return _named(name, self.tools)

    def permits_call(self, name: str, arguments: Mapping[str, object] | None) -> bool:
        if not self.permits_tool(name):
            return False
        if name in _MCP_META and arguments:
            server = arguments.get("server", "")
            if isinstance(server, str) and server and not _named(server, self.mcp):
                return False
        return True


def unrestricted() -> LayerAllow:
    return LayerAllow(tools=None, mcp=None, dials={})


def effective_allowlist(org: LayerAllow, profile: LayerAllow) -> ToolAllowlist:
    """Intersect the two layers. The profile cannot add what the org omitted."""
    return ToolAllowlist(tools=_meet(org.tools, profile.tools), mcp=_meet(org.mcp, profile.mcp))


def clamp_dials(floor: Mapping[str, str], requested: Mapping[str, str]) -> dict[str, str]:
    """Return catalog dials. ``floor`` raises a looser request. It never lowers one."""
    effective = dict(default_positions())
    for dial, position in requested.items():
        if dial in effective and position in _RANK:
            effective[dial] = position
    for dial, position in floor.items():
        if dial not in effective or position not in _RANK:
            continue
        if _RANK[position] > _RANK[effective[dial]]:
            effective[dial] = position
    return effective


def parse_allow(value: object) -> frozenset[str] | None:
    """Parse a TOML allow array. A lone ``*`` is unrestricted.

    A list that mixes ``*`` with names keeps the names and drops ``*``,
    which is the tighter reading.
    """
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError("allow must be an array of names")
    names: list[str] = []
    star = False
    for item in value:
        if item == "*":
            star = True
            continue
        if not isinstance(item, str) or not item or len(item) > 200:
            raise ValueError("allow entries must be short strings")
        if any(ch in item for ch in " \r\n/\\"):
            raise ValueError("allow entries must be tool or server names")
        names.append(item)
    if star and not names:
        return None
    return frozenset(names)


def load_layer(path: Path, *, table: str) -> LayerAllow:
    """Load ``[table.tools]``, ``[table.mcp]``, and ``[table.dials]``."""
    if not path.is_file():
        return unrestricted()
    try:
        loaded = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"could not read {path.name}") from exc
    raw = loaded.get(table, loaded)
    if not isinstance(raw, dict):
        raise ValueError(f"{path.name} must be a table")
    tools = _section_allow(raw.get("tools"))
    mcp = _section_allow(raw.get("mcp"))
    dials = _dials(raw.get("dials"))
    return LayerAllow(tools=tools, mcp=mcp, dials=dials)


def render_policy_toml(
    *,
    table: str,
    schema: str,
    profile: str = "",
    name: str = "",
    tools: frozenset[str] | None = None,
    mcp: frozenset[str] | None = None,
    dials: Mapping[str, str] | None = None,
) -> str:
    """Write a small policy or profile file. No secrets."""
    lines = [f"[{table}]", f'schema = "{schema}"']
    if profile:
        lines.append(f'id = "{profile}"')
    if name:
        safe = name.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'name = "{safe}"')
    lines.append("")
    lines.append(f"[{table}.tools]")
    lines.append(f"allow = {_toml_list(tools)}")
    lines.append("")
    lines.append(f"[{table}.mcp]")
    lines.append(f"allow = {_toml_list(mcp)}")
    lines.append("")
    lines.append(f"[{table}.dials]")
    for dial, position in sorted((dials or {}).items()):
        if position in DIAL_POSITIONS:
            lines.append(f'{dial} = "{position}"')
    lines.append("")
    return "\n".join(lines)


def _section_allow(value: object) -> frozenset[str] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("tools and mcp sections must be tables")
    if "allow" not in value:
        return None
    return parse_allow(value.get("allow"))


def _dials(value: object) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("dials must be a table")
    found: dict[str, str] = {}
    catalog = default_positions()
    for key, position in value.items():
        if key in catalog and position in _RANK:
            found[key] = str(position)
    return found


def _meet(org: frozenset[str] | None, profile: frozenset[str] | None) -> frozenset[str] | None:
    if org is None:
        return profile
    if profile is None:
        return org
    return org & profile


def _named(name: str, allowed: frozenset[str] | None) -> bool:
    if allowed is None:
        return True
    return name in allowed


def _mcp_server(name: str) -> str:
    parts = name.split("__")
    if len(parts) < 3 or not parts[1]:
        return ""
    return parts[1]


def _toml_list(names: frozenset[str] | None) -> str:
    if names is None:
        return '["*"]'
    inner = ", ".join(f'"{item}"' for item in sorted(names))
    return f"[{inner}]"
