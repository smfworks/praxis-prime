"""Model router.

No provider is selected until the operator chooses one. OpenAI-compatible
endpoints cover llama.cpp, vLLM, and LM Studio. Anthropic, OpenAI, and xAI
read keys from the environment or the secrets file.

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
    InferenceNotConfigured,
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
    "InferenceNotConfigured",
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
