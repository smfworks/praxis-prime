"""Local accounts, server roles, and memberships.

Passwords are argon2id. Sessions and WebSocket tickets live in
``accounts.db`` (SQLite, WAL, mode 0600). Passkeys (WebAuthn) and TOTP
are the M1b factors in this same file. OIDC is M1e.

docs/blueprint-addendum-2026-09.md §4.3 and §6. ARCHITECTURE §22 and §25.
"""

from praxis_prime.accounts.db import AccountStore
from praxis_prime.accounts.roles import SERVER_ROLES, ProfileRole, ServerRole

__all__ = ["AccountStore", "ProfileRole", "SERVER_ROLES", "ServerRole"]
