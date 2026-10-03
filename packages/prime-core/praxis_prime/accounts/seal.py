"""Encrypt TOTP seeds stored in ``accounts.db``.

The key is a random 32-byte value in the same database (``auth_meta``).
The file is the account-data boundary: mode 0600, and the existing denylist
and sandbox mask already hide ``accounts.db``. Encryption keeps a row dump
or a log of one column from showing the seed. The associated data is the
account id, so a ciphertext copied onto another account does not decrypt.

Seeds sealed before that binding used the fixed label ``LEGACY_AAD``.
Callers that still see one of those blobs decrypt it once and rewrite it
under the account id. This branch is the first release that stores seeds,
so a legacy blob only exists for a database created from an earlier
revision of this change.

Recovery codes are not encrypted here; callers store only a SHA-256 hash.

docs/blueprint-addendum-2026-09.md §4.3. ARCHITECTURE §22 and §25.
"""

from __future__ import annotations

import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_KEY_LEN = 32
_NONCE_LEN = 12
LEGACY_AAD = b"praxis-prime-totp-v1"
_CHALLENGE_SALT = b"praxis-prime-hkdf-salt-v1"
_CHALLENGE_INFO = b"praxis-prime-webauthn-challenge-v1"


def account_aad(account_id: str) -> bytes:
    """Bind a ciphertext to one account. The id is not a secret."""
    if not account_id.startswith("acc_") or len(account_id) > 80:
        raise ValueError("account id is required")
    if any(ord(char) < 33 or ord(char) > 126 for char in account_id):
        raise ValueError("account id is required")
    return LEGACY_AAD + b"\x00" + account_id.encode("ascii")


def new_key() -> bytes:
    return secrets.token_bytes(_KEY_LEN)


def challenge_key(master: bytes) -> bytes:
    """HKDF subkey for WebAuthn challenges. It is not the TOTP seed key."""
    if len(master) != _KEY_LEN:
        raise ValueError("account data key must be 32 bytes")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=_CHALLENGE_SALT,
        info=_CHALLENGE_INFO,
    ).derive(master)


def seal(key: bytes, plaintext: bytes, *, aad: bytes) -> bytes:
    """Return ``nonce || ciphertext``. The plaintext is not retained."""
    if len(key) != _KEY_LEN:
        raise ValueError("account data key must be 32 bytes")
    if not aad:
        raise ValueError("associated data is required")
    nonce = secrets.token_bytes(_NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def unseal(key: bytes, blob: bytes, *, aad: bytes) -> bytes:
    """Decrypt a value from ``seal``. Raises if the blob was altered."""
    if len(key) != _KEY_LEN or len(blob) <= _NONCE_LEN:
        raise ValueError("sealed value is unreadable")
    if not aad:
        raise ValueError("associated data is required")
    nonce, ciphertext = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ciphertext, aad)
