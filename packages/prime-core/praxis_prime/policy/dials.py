"""Compliance dial catalog.

Every dial defaults to ``off``. The baseline safety spine is not a dial and
cannot be switched off.

Positions are ``off``, ``monitor``, and ``enforce``. Enforcement lives in
the policy engine and the packs under ``packs/compliance``. This module is
the catalog. It does not give legal advice.

ARCHITECTURE §17.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

DialPosition = Literal["off", "monitor", "enforce"]
DialWave = Literal["first", "v1.0"]

DIAL_POSITIONS: tuple[DialPosition, ...] = ("off", "monitor", "enforce")

# The spine (approval for send, delete, spend, share, publish) is always on.
# It is intentionally absent from DIALS.
BASELINE_SPINE_ALWAYS_ON = True

# Praxis jurisdictions, in the order named in ARCHITECTURE §17.
PRAXIS_STATE_CODES: tuple[str, ...] = (
    "CT",
    "FL",
    "GA",
    "MA",
    "MD",
    "NJ",
    "NY",
    "OH",
    "PA",
    "SC",
    "TN",
    "VA",
    "WV",
)

_STATE_NAMES: dict[str, str] = {
    "CT": "Connecticut",
    "FL": "Florida",
    "GA": "Georgia",
    "MA": "Massachusetts",
    "MD": "Maryland",
    "NJ": "New Jersey",
    "NY": "New York",
    "OH": "Ohio",
    "PA": "Pennsylvania",
    "SC": "South Carolina",
    "TN": "Tennessee",
    "VA": "Virginia",
    "WV": "West Virginia",
}


@dataclass(frozen=True, slots=True)
class Dial:
    """One compliance dial. ``wave`` is the roadmap phase that fills it in."""

    id: str
    title: str
    summary: str
    wave: DialWave


def _state_dial(code: str) -> Dial:
    name = _STATE_NAMES[code]
    return Dial(
        id=f"state_{code.lower()}",
        title=f"{name} ({code})",
        summary=(
            "Praxis US-state professional pack. Not imported in this skeleton. "
            "Off by default."
        ),
        wave="first",
    )


_FIRST_FEDERAL: tuple[Dial, ...] = (
    Dial(
        id="hipaa",
        title="HIPAA",
        summary=(
            "PHI handling, local-model pin, and breach-clock evidence. "
            "Technical controls only, not a BAA or certification."
        ),
        wave="first",
    ),
    Dial(
        id="ferpa",
        title="FERPA",
        summary=(
            "Education-record class and school-official limits. "
            "Technical controls only."
        ),
        wave="first",
    ),
    Dial(
        id="coppa",
        title="COPPA",
        summary="Under-13 mode. Paired with FERPA in the blueprint. Not implemented.",
        wave="first",
    ),
    Dial(
        id="gdpr",
        title="GDPR",
        summary=(
            "Consent, export, erasure, and residency pins. "
            "Forgetting hooks are future work."
        ),
        wave="first",
    ),
)

_NORTH_CAROLINA = Dial(
    id="state_nc",
    title="North Carolina (NC)",
    summary=(
        "NC pack stub for N.C.G.S. 75-60 through 75-66 and professional overlays. "
        "Not legal advice. See packs/jurisdictions/nc.py."
    ),
    wave="first",
)

_V1: tuple[Dial, ...] = (
    Dial(
        id="soc2",
        title="SOC 2",
        summary="Operational evidence controls. Not a SOC 2 attestation.",
        wave="v1.0",
    ),
    Dial(
        id="eu_ai_act",
        title="EU AI Act",
        summary="Disclosure, traceability, and human-oversight tags. Not implemented.",
        wave="v1.0",
    ),
    Dial(
        id="ccpa",
        title="CCPA/CPRA",
        summary="Access, delete, and do-not-sell/share controls. Not implemented.",
        wave="v1.0",
    ),
    Dial(
        id="pci",
        title="PCI DSS",
        summary="Card-number redaction and a ban on storing PANs. Not implemented.",
        wave="v1.0",
    ),
    Dial(
        id="nist_ai_rmf",
        title="NIST AI RMF",
        summary="Govern, map, measure, and manage checklist. Not implemented.",
        wave="v1.0",
    ),
    Dial(
        id="iso_42001",
        title="ISO/IEC 42001",
        summary="AI management-system evidence pack. Not a certification.",
        wave="v1.0",
    ),
)

DIALS: tuple[Dial, ...] = (
    *_FIRST_FEDERAL,
    *tuple(_state_dial(code) for code in PRAXIS_STATE_CODES),
    _NORTH_CAROLINA,
    *_V1,
)


def default_positions() -> dict[str, str]:
    """Return every dial id mapped to ``off``.

    There is no other default. Callers must not persist a different position
    unless a person has changed it on purpose.
    """
    return {dial.id: "off" for dial in DIALS}


def dial_ids() -> tuple[str, ...]:
    return tuple(dial.id for dial in DIALS)


def dials_in_wave(wave: DialWave) -> tuple[Dial, ...]:
    return tuple(dial for dial in DIALS if dial.wave == wave)
