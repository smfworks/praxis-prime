"""argon2id password hashing.

Parameters are the OWASP minimum for argon2id (19 MiB, t=2, p=1).
Verification of a missing account still runs a hash compare so the
response time does not reveal whether the username exists.

The hash string is not a secret to log, but it is also not something to
print. Callers keep it in ``accounts.db`` only.
"""

from __future__ import annotations

import threading

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128

_HASHER = PasswordHasher(
    time_cost=2,
    memory_cost=19_456,
    parallelism=1,
    hash_len=32,
    salt_len=16,
)
_DUMMY: str | None = None
_DUMMY_LOCK = threading.Lock()


def password_ok(password: str) -> str | None:
    """Return an error message, or None when the password may be stored."""
    if not isinstance(password, str):
        return "password must be 8 to 128 characters"
    size = len(password.encode("utf-8"))
    if size < MIN_PASSWORD_LENGTH or size > MAX_PASSWORD_LENGTH:
        return "password must be 8 to 128 characters"
    if "\x00" in password:
        return "password must be 8 to 128 characters"
    return None


def hash_password(password: str) -> str:
    """Return an argon2id encoded hash. The password is not retained."""
    encoded = _HASHER.hash(password)
    if not encoded.startswith("$argon2id$"):
        raise RuntimeError("password hasher did not produce argon2id")
    return encoded


def verify_password(encoded: str, password: str) -> bool:
    """True when ``password`` matches ``encoded``. Mismatches are False."""
    if not encoded or not isinstance(password, str):
        return False
    if len(password.encode("utf-8")) > MAX_PASSWORD_LENGTH:
        return False
    try:
        return bool(_HASHER.verify(encoded, password))
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def dummy_verify(password: str) -> None:
    """Spend a hash compare when the account does not exist."""
    verify_password(_dummy(), password if isinstance(password, str) else "")


def _dummy() -> str:
    global _DUMMY
    with _DUMMY_LOCK:
        if _DUMMY is None:
            _DUMMY = hash_password("dummy-password-not-a-credential")
        return _DUMMY
