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


LoopEvent = TextDelta | StatusEvent | TurnEnded
