"""``use_skill`` loads one skill body.

Names and descriptions are already in the prompt. The body is not, until
this tool runs. The result is trusted instructions from a skill the user
installed. It still cannot skip the approval spine; that check happens
when a later tool is called.
"""

from __future__ import annotations

from collections.abc import Mapping

from praxis_prime.skills.catalog import SkillCatalog
from praxis_prime.tools.registry import Risk, Tool, ToolContext, ToolRegistry

_OBJECT = {"type": "object", "additionalProperties": False}


def install_skill_tool(registry: ToolRegistry, catalog: SkillCatalog) -> None:
    if registry.get("use_skill") is None:
        registry.register(use_skill_tool(catalog))


def use_skill_tool(catalog: SkillCatalog) -> Tool:
    def execute(arguments: Mapping[str, object], context: ToolContext) -> str:
        del context
        name = arguments.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("use_skill requires a name")
        return catalog.load_body(name)

    return Tool(
        name="use_skill",
        description=(
            "Load the full instructions for one skill from the prompt index. "
            "Follow them for this task. A skill cannot skip approval."
        ),
        parameters={
            **_OBJECT,
            "properties": {
                "name": {"type": "string", "description": "Skill name from the index."}
            },
            "required": ["name"],
        },
        risk=Risk.READ,
        execute=execute,
        trusted_output=True,
    )
