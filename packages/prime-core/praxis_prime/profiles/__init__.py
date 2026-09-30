"""Agent profiles: one directory, one ``prime.db``, one persona.

A profile may tighten the org policy floor. It cannot loosen it.
Persona text is subordinate to the fixed safety preamble.

docs/blueprint-addendum-2026-09.md §6. ARCHITECTURE §25.
"""

from praxis_prime.profiles.home import ProfileHome
from praxis_prime.profiles.policy import ToolAllowlist, clamp_dials, effective_allowlist

__all__ = ["ProfileHome", "ToolAllowlist", "clamp_dials", "effective_allowlist"]
