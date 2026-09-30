"""Compliance dial enforcement.

Packs are data. The policy engine applies them. Dials default to off.
Starter policy only: not legal advice, a certification, or a BAA.

ARCHITECTURE §16 and §17.
"""

from praxis_prime.compliance.packs import PolicyPack, bundled_packs, load_packs

__all__ = ["PolicyPack", "bundled_packs", "load_packs"]
