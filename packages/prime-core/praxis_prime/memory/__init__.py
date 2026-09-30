"""Session memory.

The MVP stores the working transcript in SQLite. Episodic search, semantic
memory, and procedural skills are not implemented.

TODO: ARCHITECTURE §10 for tiers 2–4.
"""

from praxis_prime.memory.store import SessionStore

__all__ = ["SessionStore"]
