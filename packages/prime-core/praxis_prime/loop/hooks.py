"""Optional project hooks around a tool call.

A hook may tighten a decision (allow → ask → deny). It cannot turn a
policy denial into an allow. ARCHITECTURE §14.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class HookDecision(StrEnum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class HookResult:
    decision: HookDecision
    reason: str = ""


class LoopHooks(Protocol):
    """Pre-tool, post-tool, and on-finish callbacks for one coding task."""

    def pre_tool(self, name: str, arguments: Mapping[str, object]) -> HookResult:
        """Return deny to stop the tool before it runs."""

    def post_tool(
        self,
        name: str,
        arguments: Mapping[str, object],
        output: str,
        *,
        ok: bool,
    ) -> HookResult:
        """Inspect a tool result. Deny is reported; the call already ran."""

    def on_finish(self, text: str) -> HookResult:
        """Run when a turn ends without being cancelled."""
