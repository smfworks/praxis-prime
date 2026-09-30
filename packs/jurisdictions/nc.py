"""North Carolina jurisdiction profile slots.

Not legal advice. Enforceable ITPA controls (SSN handling, personal-information
redaction, breach records, disposal retention) live in
``packs/compliance/state_nc.toml``. This module keeps the professional-overlay
slots from ARCHITECTURE §17.2. Rows marked S or U in SOURCE-NOTES §11 are not
encoded as rules.

Default position is off.

TODO: import Praxis professional overlays only after their license is confirmed.
"""

PACK_ID = "state:NC"
DEFAULT_POSITION = "off"

# Profile slots from the blueprint. Values are intentionally empty.
PROFILES: tuple[str, ...] = (
    "DATA_PRIVACY",
    "LEGAL",
    "MEDICAL",
    "EDUCATION",
    "HOMESCHOOL",
    "FORENSIC",
)
