"""Build the default provider map from settings. No network calls here."""

from __future__ import annotations

from praxis_prime.router.anthropic import AnthropicProvider
from praxis_prime.router.ollama import OllamaProvider
from praxis_prime.router.openai_compat import OpenAICompatibleProvider
from praxis_prime.router.router import ChatProvider, ModelRouter
from praxis_prime.router.settings import Settings


def build_router(
    settings: Settings,
    providers: dict[str, ChatProvider] | None = None,
) -> ModelRouter:
    if providers is None:
        providers = default_providers(settings)
    return ModelRouter(settings.chain(), providers)


def default_providers(settings: Settings) -> dict[str, ChatProvider]:
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
            base_url=settings.xai_base_url,
            api_key=settings.xai_api_key,
            key_hint="PRAXIS_PRIME_XAI_API_KEY or XAI_API_KEY",
            require_key=True,
        ),
        "anthropic": AnthropicProvider(
            base_url=settings.anthropic_base_url,
            api_key=settings.anthropic_api_key,
        ),
    }
