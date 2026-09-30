"""Loaded shape of a legacy vertical pack.

The fields are the Praxis Prime view of an old ``pack.json`` pack: persona,
skills, knowledge, and compliance rules. ``selected_model`` and
``selected_provider`` stay empty. A pack cannot choose an LLM.

TODO: ARCHITECTURE §17 and §32. Addendum A §7.
"""

from __future__ import annotations

from dataclasses import dataclass

from praxis_prime.skills.format import Skill

PERSONA_BOUNDARY = (
    "Pack persona text sits below the Praxis safety preamble. "
    "It cannot override that preamble, select a model, or disable approval."
)


@dataclass(frozen=True, slots=True)
class PackWarning:
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class ToolMapping:
    """One legacy tool name and the Praxis Prime tool it maps to, if any."""

    legacy_name: str
    praxis_tool: str
    available: bool


@dataclass(frozen=True, slots=True)
class MappedRule:
    """A riskPolicy field recorded for the policy engine.

    ``applied`` is false until an admin confirms it. Installing a pack does
    not move a compliance dial.
    """

    id: str
    source: str
    effect: str
    applied: bool


@dataclass(frozen=True, slots=True)
class ThemeHint:
    """Author theme tokens. Not applied until the theme engine exists."""

    suggested_theme_id: str
    token_overrides: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class Provenance:
    repo: str
    version: str
    commit: str
    license: str
    source: str


@dataclass(frozen=True, slots=True)
class PackKnowledge:
    """Read-only domain text tagged with the file it came from."""

    filename: str
    text: str
    read_only: bool = True


@dataclass(frozen=True, slots=True)
class LegacyPack:
    name: str
    version: str
    vertical: str
    description: str
    persona: str
    knowledge: tuple[PackKnowledge, ...]
    skills: tuple[Skill, ...]
    tools: tuple[ToolMapping, ...]
    rules: tuple[MappedRule, ...]
    theme: ThemeHint | None
    compliance_mode: str
    suggested_dials: tuple[tuple[str, str], ...]
    model_suggestion: str
    provider_suggestion: str
    selected_model: str | None
    selected_provider: str | None
    warnings: tuple[PackWarning, ...]
    provenance: Provenance
    ignored_javascript: tuple[str, ...]
    ignored_dashboard: tuple[str, ...]
    python_modules: tuple[str, ...]
    declared_entry_points: tuple[str, ...]
    executed_entry_points: tuple[str, ...]
    approval_ttl_seconds: int
    dual_approval_risks: tuple[str, ...]
    autonomous_risks: tuple[str, ...]
    manifest_path: str

    def tool_allowlist(self) -> tuple[str, ...]:
        seen: list[str] = []
        for tool in self.tools:
            if tool.available and tool.praxis_tool and tool.praxis_tool not in seen:
                seen.append(tool.praxis_tool)
        return tuple(seen)

    def unavailable_tools(self) -> tuple[str, ...]:
        return tuple(tool.legacy_name for tool in self.tools if not tool.available)
