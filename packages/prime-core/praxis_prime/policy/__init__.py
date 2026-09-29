"""Policy engine placeholder.

The baseline spine and the compliance dials are separate. Dials default to
off. Nothing here accepts or denies a tool call yet.

TODO: ARCHITECTURE §16 and §17.
"""

from praxis_prime.policy.dials import (
    BASELINE_SPINE_ALWAYS_ON,
    DIAL_POSITIONS,
    DIALS,
    default_positions,
    dial_ids,
)

__all__ = [
    "BASELINE_SPINE_ALWAYS_ON",
    "DIAL_POSITIONS",
    "DIALS",
    "default_positions",
    "dial_ids",
]
