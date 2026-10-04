"""Text the wizard shows. The inference sentence is shared with the router."""

from __future__ import annotations

from collections.abc import Mapping

from praxis_prime.router.types import INFERENCE_NOT_CONFIGURED

CLOUD_WARNING = "Requires a BAA/DPA with the provider; PHI will leave this machine"
WARN_CONTEXT = 32768
BLOCK_CONTEXT = 16384
REGULATED_DIALS = ("hipaa", "ferpa", "coppa", "gdpr", "pci")

__all__ = [
    "BLOCK_CONTEXT",
    "CLOUD_WARNING",
    "INFERENCE_NOT_CONFIGURED",
    "REGULATED_DIALS",
    "WARN_CONTEXT",
    "cloud_warning",
]


def cloud_warning(dials: Mapping[str, str]) -> str:
    """The compliance sentence, or empty when every regulated dial is off."""
    for dial_id in REGULATED_DIALS:
        if dials.get(dial_id) in {"monitor", "enforce"}:
            return CLOUD_WARNING
    return ""
