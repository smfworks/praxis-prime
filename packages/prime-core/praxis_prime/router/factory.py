"""Build the default provider map from settings. No network calls here."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from praxis_prime.providers_auth.broker import take_worker_token
from praxis_prime.providers_auth.xai_oauth import pinned_https
from praxis_prime.router.anthropic import AnthropicProvider
from praxis_prime.router.ollama import OllamaProvider
from praxis_prime.router.openai_compat import OpenAICompatibleProvider
from praxis_prime.router.router import ChatProvider, ModelRouter
from praxis_prime.router.settings import Settings
from praxis_prime.router.types import ProviderUnreachable

_LOG = logging.getLogger(__name__)
_XAI_PIN = "https://api.x.ai/v1"


def build_router(
    settings: Settings,
    providers: dict[str, ChatProvider] | None = None,
    *,
    config_dir: Path | None = None,
) -> ModelRouter:
    if providers is None:
        providers = default_providers(settings, config_dir=config_dir)
    return ModelRouter(settings.chain(), providers)


def default_providers(
    settings: Settings,
    *,
    config_dir: Path | None = None,
) -> dict[str, ChatProvider]:
    xai_base = settings.xai_base_url
    xai_credential = None
    xai_pin: tuple[str, ...] = ()
    if getattr(settings, "xai_auth", "api_key") == "oauth":
        xai_pin = ("api.x.ai",)
        if not pinned_https(xai_base, inference=True):
            _LOG.warning("xAI oauth base URL is outside api.x.ai; the bearer will not be sent")
        xai_credential = _oauth_credential(config_dir)
    return {
        "ollama": OllamaProvider(settings.ollama_host),
        "openai-compatible": OpenAICompatibleProvider(
            name="openai-compatible",
            base_url=settings.openai_compatible_base_url,
            api_key=settings.openai_compatible_api_key,
            key_hint="PRAXIS_PRIME_OPENAI_COMPATIBLE_API_KEY (optional for local servers)",
            require_key=False,
        ),
        "openai": OpenAICompatibleProvider(
            name="openai",
            base_url=settings.openai_base_url,
            api_key=settings.openai_api_key,
            key_hint="PRAXIS_PRIME_OPENAI_API_KEY or OPENAI_API_KEY",
            require_key=True,
        ),
        "xai": OpenAICompatibleProvider(
            name="xai",
            base_url=xai_base,
            api_key=settings.xai_api_key,
            key_hint="PRAXIS_PRIME_XAI_API_KEY or XAI_API_KEY",
            require_key=True,
            credential=xai_credential,
            pin_hosts=xai_pin,
        ),
        "anthropic": AnthropicProvider(
            base_url=settings.anthropic_base_url,
            api_key=settings.anthropic_api_key,
        ),
    }


def _oauth_credential(config_dir: Path | None):
    """Worker asks the supervisor. The daemon broker is the only refresher."""
    if os.environ.get("PRAXIS_PRIME_WORKER_PROFILE"):
        return _worker_bearer

    def _daemon() -> str:
        from praxis_prime.paths import config_dir as default_config
        from praxis_prime.providers_auth.broker import ProviderAuthBroker

        directory = config_dir if config_dir is not None else default_config()
        return ProviderAuthBroker(directory).access_token()

    return _daemon


def _worker_bearer() -> str:
    token = take_worker_token()
    if not token:
        raise ProviderUnreachable("xai", "sign in again")
    return token


def pinned_inference_base() -> str:
    return _XAI_PIN
