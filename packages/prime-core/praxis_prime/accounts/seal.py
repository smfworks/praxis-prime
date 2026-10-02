"""Encrypt TOTP seeds stored in ``accounts.db``.

The key is a random 32-byte value in the same database (``auth_meta``).
The file is the account-data boundary: mode 0600, and the existing denylist
and sandbox mask already hide ``accounts.db``. Encryption keeps a row dump
or a log of one column from showing the seed. Recovery codes are not
encrypted here; callers store only a SHA-256 hash.

docs/blueprint-addendum-2026-09.md §4.3. ARCHITECTURE §22 and §25.
"""

from __future__ import annotations

import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_KEY_LEN = 32
_NONCE_LEN = 12
_AAD = b"praxis-prime-totp-v1"


def new_key() -> bytes:
    return secrets.token_bytes(_KEY_LEN)


def seal(key: bytes, plaintext: bytes) -> bytes:
    """Return ``nonce || ciphertext``. The plaintext is not retained."""
    if len(key) != _KEY_LEN:
        raise ValueError("account data key must be 32 bytes")
    nonce = secrets.token_bytes(_NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, _AAD)


def unseal(key: bytes, blob: bytes) -> bytes:
    """Decrypt a value from ``seal``. Raises if the blob was altered."""
    if len(key) != _KEY_LEN or len(blob) <= _NONCE_LEN:
        raise ValueError("sealed value is unreadable")
    nonce, ciphertext = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ciphertext, _AAD)
