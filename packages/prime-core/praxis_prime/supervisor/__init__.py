"""Per-profile workers and the supervisor that owns them.

The daemon (``praxis-primed``) is the supervisor. Each active profile runs
in its own worker process. See docs/SECURITY.md for the trust boundary.

ARCHITECTURE §3.1 and blueprint addendum §6.4 L1. Landlock and per-profile
Linux users are not this layer.
"""
