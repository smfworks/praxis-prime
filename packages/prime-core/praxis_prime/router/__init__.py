"""Model router.

Ollama is the default. OpenAI-compatible endpoints cover llama.cpp server
and vLLM. Anthropic, OpenAI, and xAI are optional and read keys from the
environment.

ARCHITECTURE §6. Sensitivity pinning and the Decision Engine role are later.
"""

from praxis_prime.router.factory import build_router, default_providers
from praxis_prime.router.router import ModelRouter
from praxis_prime.router.settings import Settings, load_settings
from praxis_prime.router.types import (
    AssistantFinal,
    ChatMessage,
    ChatRequest,
    FallbackNotice,
    ProviderUnreachable,
    RouterExhausted,
    TextDelta,
    ToolCall,
    parse_model_spec,
)

__all__ = [
    "AssistantFinal",
    "ChatMessage",
    "ChatRequest",
    "FallbackNotice",
    "ModelRouter",
    "ProviderUnreachable",
    "RouterExhausted",
    "Settings",
    "TextDelta",
    "ToolCall",
    "build_router",
    "default_providers",
    "load_settings",
    "parse_model_spec",
]
