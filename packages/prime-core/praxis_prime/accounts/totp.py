"""TOTP (RFC 6238) and one-time recovery codes.

Authenticator apps expect SHA-1, 6 digits, and a 30-second step. The drift
window is one step on either side. Callers record the accepted step and
reject that step again, so a code cannot be replayed inside the window.

Recovery codes are high-entropy and shown once. Callers store SHA-256 only.

No network. ``pyotp`` is a local library.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

import pyotp

PERIOD = 30
DIGITS = 6
DRIFT_STEPS = 1
RECOVERY_COUNT = 10
ISSUER = "Praxis Prime"


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret, digits=DIGITS, interval=PERIOD).provisioning_uri(
        name=username,
        issuer_name=ISSUER,
    )


def matching_step(secret: str, code: str, *, now: float, drift: int = DRIFT_STEPS) -> int | None:
    """Return the timestep ``code`` matches, or None.

    ``now`` is a Unix timestamp. Steps outside ``±drift`` do not match.
    """
    cleaned = code.strip().replace(" ", "")
    if len(cleaned) != DIGITS or not cleaned.isdigit():
        return None
    if not secret:
        return None
    totp = pyotp.TOTP(secret, digits=DIGITS, interval=PERIOD)
    base = int(now) // PERIOD
    for offset in range(-drift, drift + 1):
        step = base + offset
        if step < 0:
            continue
        expected = totp.generate_otp(step)
        if hmac.compare_digest(expected, cleaned):
            return step
    return None


def new_recovery_codes() -> list[str]:
    """Ten codes, each 64 bits, grouped for reading aloud once."""
    codes: list[str] = []
    for _ in range(RECOVERY_COUNT):
        raw = secrets.token_hex(8)
        codes.append(f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}")
    return codes


def normalize_recovery(code: str) -> str | None:
    text = code.strip().casefold().replace(" ", "").replace("-", "")
    if len(text) != 16 or any(ch not in "0123456789abcdef" for ch in text):
        return None
    return text


def recovery_hash(normalized: str) -> str:
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
