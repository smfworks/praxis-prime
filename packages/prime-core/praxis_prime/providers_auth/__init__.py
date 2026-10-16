"""xAI subscription sign-in. Tokens stay in this package, not in secrets.env."""

from praxis_prime.providers_auth.broker import (
    ProviderAuthBroker,
    classify_xai_error,
    oauth_sign_in_allowed,
    scrub_audit_payload,
)
from praxis_prime.providers_auth.store import TokenStore
from praxis_prime.providers_auth.xai_oauth import XaiOAuthError, pinned_https

__all__ = [
    "ProviderAuthBroker",
    "TokenStore",
    "XaiOAuthError",
    "classify_xai_error",
    "oauth_sign_in_allowed",
    "pinned_https",
    "scrub_audit_payload",
]
