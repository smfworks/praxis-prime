"""Events yielded by one agent turn."""

from __future__ import annotations

from dataclasses import dataclass

from praxis_prime.router.types import TextDelta


@dataclass(frozen=True, slots=True)
class StatusEvent:
    """A plan, check, or act step for the timeline."""

    phase: str
    detail: str


@dataclass(frozen=True, slots=True)
class TurnEnded:
    text: str
    cancelled: bool = False
    error: str | None = None


@dataclass(frozen=True, slots=True)
class ToolSpan:
    """One step of a tool call, in AG-UI order: start, args, end, result."""

    phase: str
    tool_call_id: str
    name: str
    detail: str = ""


LoopEvent = TextDelta | StatusEvent | TurnEnded | ToolSpan
