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

from praxis_prime.policy.boundary import InodeScanCache, ReadAccess


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
    ``shell_approved`` is true after a person approved this command,
    sandboxed or not. ``session_write_approved`` is the coding-mode grant
    for one worktree. ``write_scope`` is that worktree; ``main_checkout``
    is never a legal read-write bind.
    ``session_id`` is the chat session when the loop is running one.
    """

    cwd: str
    cancelled: Callable[[], bool]
    host_shell_approved: bool = False
    session_id: str | None = None
    read_access: ReadAccess | None = None
    inode_cache: InodeScanCache | None = None
    shell_approved: bool = False
    session_write_approved: bool = False
    write_scope: str = ""
    main_checkout: str = ""
    audit: object | None = None
    dial_mode: str = "off"


@dataclass(frozen=True, slots=True)
class PreparedCall:
    """What policy needs before a tool is allowed to run."""

    risk: Risk
    sandboxed: bool
    force_approval: bool
    force_reason: str
    summary: str
    write_capable: bool = False


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
                    write_capable=prepared.write_capable,
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
    """Name → tool. Registration order is the order schemas are sent.

    Hidden tools stay callable but are left out of ``schemas`` so a large
    MCP catalog does not land in the prompt until it is revealed.
    """

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}
        self._hidden: set[str] = set()
        self._resolver: Callable[[str], Tool | None] | None = None

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def set_resolver(self, resolver: Callable[[str], Tool | None] | None) -> None:
        """Resolve a name the first time the model calls it."""
        self._resolver = resolver

    def hide(self, name: str) -> None:
        if name in self._tools:
            self._hidden.add(name)

    def reveal(self, name: str) -> bool:
        if name not in self._tools:
            return False
        self._hidden.discard(name)
        return True

    def is_hidden(self, name: str) -> bool:
        return name in self._hidden

    def contains(self, name: str) -> bool:
        return name in self._tools

    def get(self, name: str) -> Tool | None:
        found = self._tools.get(name)
        if found is not None:
            return found
        resolver = self._resolver
        if resolver is None:
            return None
        return resolver(name)

    def names(self) -> tuple[str, ...]:
        return tuple(self._tools)

    def schemas(self) -> list[dict[str, Any]]:
        return [
            tool.openai_schema()
            for tool in self._tools.values()
            if tool.name not in self._hidden
        ]


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
