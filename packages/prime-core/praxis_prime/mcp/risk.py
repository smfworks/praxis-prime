"""Map an MCP tool onto the approval spine.

Annotations follow the public MCP tool spec. A tool with no read-only
annotation is SEND until someone classifies it (ARCHITECTURE §8).
Untrusted servers still ask for write-like tools when the user classifies
them as DRAFT. Destructive hints cannot be lowered.

"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from praxis_prime.tools.registry import CONSEQUENTIAL_RISKS, Risk

_WRITE = re.compile(
    r"(?i)(write|create|update|delete|remove|edit|send|post|put|exec|shell|"
    r"purchase|pay|submit|upload|mkdir|drop|insert)"
)
_RISKS = {item.value: item for item in Risk}


@dataclass(frozen=True, slots=True)
class RiskDecision:
    risk: Risk
    force_approval: bool
    reason: str
    sandboxed: bool


def map_tool_risk(
    name: str,
    annotations: Mapping[str, object] | None,
    *,
    trust: str,
    override: str = "",
    sandboxed: bool = True,
) -> RiskDecision:
    """Return the risk class and whether the approval hook must ask."""
    hints = annotations or {}
    read_only = hints.get("readOnlyHint") is True
    destructive = hints.get("destructiveHint") is True
    open_world = hints.get("openWorldHint") is True
    write_like = bool(_WRITE.search(name))
    untrusted = trust != "trusted"
    has_annotation = read_only or destructive or open_world

    if destructive:
        risk = Risk.DESTRUCTIVE
        reason = "MCP destructiveHint requires approval"
    elif read_only:
        risk = Risk.READ
        reason = ""
    elif open_world:
        risk = Risk.SEND
        reason = "MCP openWorldHint is treated as SEND"
    elif write_like and untrusted:
        risk = Risk.DRAFT
        reason = "untrusted MCP server: write-like tools require approval"
    elif not has_annotation:
        risk = Risk.SEND
        reason = "MCP tool has no read-only annotation; defaulting to SEND"
    else:
        risk = Risk.READ
        reason = ""

    force = risk in CONSEQUENTIAL_RISKS or (untrusted and write_like and risk is not Risk.READ)

    override_risk = _RISKS.get(override.strip().upper()) if override else None
    if override_risk is not None:
        if destructive and _rank(override_risk) < _rank(Risk.DESTRUCTIVE):
            risk = Risk.DESTRUCTIVE
            force = True
            reason = "MCP destructiveHint cannot be lowered"
        else:
            risk = override_risk
            if risk is Risk.READ and not destructive:
                force = False
                reason = ""
            elif risk in CONSEQUENTIAL_RISKS:
                force = True
                reason = reason or f"tool risk is {risk.value}"
            elif untrusted and write_like:
                force = True
                reason = "untrusted MCP server: write-like tools require approval"
            else:
                force = False
                reason = ""

    if force and not reason:
        reason = f"{risk.value} requires approval"
    return RiskDecision(
        risk=risk,
        force_approval=force,
        reason=reason if force else "",
        sandboxed=sandboxed,
    )


def _rank(risk: Risk) -> int:
    order = {
        Risk.READ: 0,
        Risk.DRAFT: 1,
        Risk.SEND: 2,
        Risk.SHARE: 3,
        Risk.SPEND: 4,
        Risk.DESTRUCTIVE: 5,
    }
    return order[risk]
