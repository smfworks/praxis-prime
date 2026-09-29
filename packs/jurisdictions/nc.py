"""North Carolina jurisdiction pack stub.

Not legal advice. This file does not encode statutes, retention periods, or
notice templates. SOURCE-NOTES §11 marks several rows as secondary (S) or
unverified (U). Those rows have to be read from the primary source before any
rule exists.

Default position is off. Monitor and enforce modes are not implemented.

TODO: ARCHITECTURE §17.2.
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
