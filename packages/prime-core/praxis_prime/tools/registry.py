"""Tool registry.

Each tool declares a risk class. The policy engine reads that class before
the tool runs. Risk names follow ARCHITECTURE §8 and §16: READ and DRAFT may
proceed; SEND, DESTRUCTIVE, SPEND, and SHARE stay behind the approval spine.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Risk(StrEnum):
    """Side-effect class for one tool invocation."""

    READ = "READ"
    DRAFT = "DRAFT"
    SEND = "SEND"
    DESTRUCTIVE = "DESTRUCTIVE"
    SPEND = "SPEND"
    SHARE = "SHARE"


CONSEQUENTIAL_RISKS = frozenset(
    {Risk.SEND, Risk.DESTRUCTIVE, Risk.SPEND, Risk.SHARE}
)


@dataclass(frozen=True, slots=True)
class ToolContext:
    """Runtime facts a tool may use. Tools do not approve themselves.

    ``host_shell_approved`` is true only after a person approved an
    unsandboxed shell command. A missing sandbox must not imply it.
    """

    cwd: str
    cancelled: Callable[[], bool]
    host_shell_approved: bool = False


@dataclass(frozen=True, slots=True)
class PreparedCall:
    """What policy needs before a tool is allowed to run."""

    risk: Risk
    sandboxed: bool
    force_approval: bool
    force_reason: str
    summary: str


@dataclass(frozen=True, slots=True)
class Tool:
    """One registered tool.

    ``classify`` may raise the risk above ``risk`` (never lower it past the
    declared floor). ``execute`` is called only after policy and approval.
    """

    name: str
    description: str
    parameters: dict[str, Any]
    risk: Risk
    execute: Callable[[Mapping[str, Any], ToolContext], str]
    classify: Callable[[Mapping[str, Any]], PreparedCall] | None = None
    trusted_output: bool = False

    def prepare(self, arguments: Mapping[str, Any]) -> PreparedCall:
        if self.classify is not None:
            prepared = self.classify(arguments)
            if _risk_rank(prepared.risk) < _risk_rank(self.risk):
                return PreparedCall(
                    risk=self.risk,
                    sandboxed=prepared.sandboxed,
                    force_approval=prepared.force_approval,
                    force_reason=prepared.force_reason,
                    summary=prepared.summary,
                )
            return prepared
        summary = _summarize(arguments)
        return PreparedCall(
            risk=self.risk,
            sandboxed=True,
            force_approval=False,
            force_reason="",
            summary=summary,
        )

    def openai_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


class ToolRegistry:
    """Name → tool. Registration order is the order schemas are sent."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def names(self) -> tuple[str, ...]:
        return tuple(self._tools)

    def schemas(self) -> list[dict[str, Any]]:
        return [tool.openai_schema() for tool in self._tools.values()]


def _risk_rank(risk: Risk) -> int:
    order = {
        Risk.READ: 0,
        Risk.DRAFT: 1,
        Risk.SEND: 2,
        Risk.SHARE: 3,
        Risk.SPEND: 4,
        Risk.DESTRUCTIVE: 5,
    }
    return order[risk]


def _summarize(arguments: Mapping[str, Any]) -> str:
    parts = [f"{key}={arguments[key]}" for key in arguments]
    return ", ".join(parts)[:180]
