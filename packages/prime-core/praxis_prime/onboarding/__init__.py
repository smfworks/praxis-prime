"""First-run setup shared by the CLI and the web wizard."""

from praxis_prime.onboarding.messages import CLOUD_WARNING, INFERENCE_NOT_CONFIGURED
from praxis_prime.onboarding.service import OnboardingError, OnboardingService, Selection
from praxis_prime.onboarding.token import (
    ensure_first_run_token,
    invalidate_first_run_token,
    token_matches,
)

__all__ = [
    "CLOUD_WARNING",
    "INFERENCE_NOT_CONFIGURED",
    "OnboardingError",
    "OnboardingService",
    "Selection",
    "ensure_first_run_token",
    "invalidate_first_run_token",
    "token_matches",
]
