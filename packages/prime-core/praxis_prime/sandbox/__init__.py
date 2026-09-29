"""Sandbox helpers.

T1 bubblewrap is used for ``shell`` when the ``bwrap`` binary is on PATH.
Podman, microVM, and remote tiers are not implemented.

TODO: ARCHITECTURE §13 for T2–T4. Network inside T1 stays off.
"""

from praxis_prime.sandbox.bwrap import (
    SandboxError,
    build_bwrap_argv,
    bwrap_available,
    run_bwrap,
    run_host_shell,
)

__all__ = [
    "SandboxError",
    "build_bwrap_argv",
    "bwrap_available",
    "run_bwrap",
    "run_host_shell",
]
