"""Agent loop.

Plan, check, act. The system prompt stays byte-stable. Tool results are
fenced. Turns can be steered or cancelled.

ARCHITECTURE §5.
"""

from praxis_prime.loop.control import TurnControl
from praxis_prime.loop.engine import AgentLoop
from praxis_prime.loop.events import LoopEvent, StatusEvent, TurnEnded
from praxis_prime.loop.prompt import SYSTEM_PROMPT, fence_untrusted, session_preamble

__all__ = [
    "SYSTEM_PROMPT",
    "AgentLoop",
    "LoopEvent",
    "StatusEvent",
    "TurnControl",
    "TurnEnded",
    "fence_untrusted",
    "session_preamble",
]
