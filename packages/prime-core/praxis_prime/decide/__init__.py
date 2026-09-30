"""Local Decision Engine.

A tiered cascade (rules, classifiers, one local judge, a jury, then a larger
model or a human) that returns a typed decision with a calibrated confidence.
It does not call TypeSafe or any hosted Jev service.

ARCHITECTURE §7.
"""

from praxis_prime.decide.engine import DecisionEngine, build_engine
from praxis_prime.decide.schema import DecideError, DecideRequest, DecisionResponse

__all__ = [
    "DecideError",
    "DecideRequest",
    "DecisionEngine",
    "DecisionResponse",
    "build_engine",
    "decide",
]


def decide(
    payload: DecideRequest | dict[str, object],
    *,
    engine: DecisionEngine | None = None,
) -> DecisionResponse:
    """Run one decision. Without an engine, only local rules and keywords run."""
    active = engine if engine is not None else DecisionEngine()
    return active.decide(payload)
