"""Provider-neutral chat types.

Every adapter speaks this shape. Tool arguments are objects, not raw model
text, by the time they leave a provider.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ToolCall:
    id: str
    name: str
    arguments: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ChatMessage:
    role: str
    content: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    tool_call_id: str | None = None

    def to_openai(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.role == "assistant" and self.tool_calls:
            payload["tool_calls"] = [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {
                        "name": call.name,
                        "arguments": json.dumps(dict(call.arguments), separators=(",", ":")),
                    },
                }
                for call in self.tool_calls
            ]
        if self.role == "tool" and self.tool_call_id:
            payload["tool_call_id"] = self.tool_call_id
        return payload


@dataclass(frozen=True, slots=True)
class ChatRequest:
    model: str
    messages: tuple[ChatMessage, ...]
    tools: tuple[dict[str, Any], ...] = ()
    temperature: float = 0.2


@dataclass(frozen=True, slots=True)
class TextDelta:
    text: str


@dataclass(frozen=True, slots=True)
class AssistantFinal:
    content: str
    tool_calls: tuple[ToolCall, ...] = ()


@dataclass(frozen=True, slots=True)
class FallbackNotice:
    text: str


StreamEvent = TextDelta | AssistantFinal | FallbackNotice


@dataclass(frozen=True, slots=True)
class ModelRef:
    provider: str
    model: str

    def spec(self) -> str:
        return f"{self.provider}:{self.model}"


class ProviderError(RuntimeError):
    """A provider failed. ``unreachable`` errors are eligible for fallback."""

    def __init__(self, provider: str, message: str, *, unreachable: bool = False) -> None:
        self.provider = provider
        self.message = message
        self.unreachable = unreachable
        super().__init__(f"{provider}: {message}")


class ProviderUnreachable(ProviderError):
    def __init__(self, provider: str, message: str) -> None:
        super().__init__(provider, message, unreachable=True)


INFERENCE_NOT_CONFIGURED = (
    "No model provider is configured. Run `praxis-prime setup` or open the web UI."
)


def unverified_provider_message(spec: str) -> str:
    """A config names a provider that has not passed the setup test."""
    return (
        f"{spec} is named in the config and has not been verified. "
        "Run `praxis-prime setup` to test it and mark it ready."
    )


class InferenceNotConfigured(RuntimeError):
    """Chat was asked to run before the operator chose and verified a provider."""

    def __init__(self, message: str = INFERENCE_NOT_CONFIGURED) -> None:
        super().__init__(message)


class RouterExhausted(RuntimeError):
    """Every provider in the chain failed before producing a response."""

    def __init__(self, attempts: list[ProviderUnreachable]) -> None:
        self.attempts = attempts
        lines = ["The configured model provider is not reachable."]
        for attempt in attempts:
            lines.append(f"- {attempt.provider}: {attempt.message}")
        lines.append("Run `praxis-prime setup` or open the web UI.")
        super().__init__("\n".join(lines))


def parse_model_spec(spec: str) -> ModelRef:
    """Parse ``provider:model``. The model may itself contain colons."""
    text = spec.strip()
    if ":" not in text:
        raise ValueError(
            f"model spec {spec!r} must look like 'ollama:qwen3:8b' or 'openai:gpt-4o'"
        )
    provider, model = text.split(":", 1)
    provider = provider.strip().lower()
    model = model.strip()
    aliases = {
        "llamacpp": "openai-compatible",
        "llama.cpp": "openai-compatible",
        "llama_cpp": "openai-compatible",
        "vllm": "openai-compatible",
        "lmstudio": "openai-compatible",
        "openai_compatible": "openai-compatible",
    }
    provider = aliases.get(provider, provider)
    known = {"ollama", "openai-compatible", "openai", "anthropic", "xai"}
    if provider not in known:
        raise ValueError(
            f"unknown provider {provider!r} in {spec!r}. "
            f"Known providers: {', '.join(sorted(known))}."
        )
    if not model:
        raise ValueError(f"model spec {spec!r} is missing a model name")
    return ModelRef(provider, model)


def canonical_spec(spec: str) -> str:
    """``provider:model`` after alias folding. ``llamacpp:m`` is ``openai-compatible:m``."""
    return parse_model_spec(spec).spec()


def specs_cover(spec: str, verified: object) -> bool:
    """True when ``spec`` and one verified entry name the same provider and model.

    Both sides are normalized. A bad entry is skipped so one stale record
    cannot break a load. An empty spec is not covered.
    """
    text = spec.strip()
    if not text:
        return False
    try:
        wanted = canonical_spec(text)
    except ValueError:
        return False
    if not isinstance(verified, (list, tuple, set, frozenset)):
        return False
    for item in verified:
        if not isinstance(item, str) or not item.strip():
            continue
        try:
            if canonical_spec(item) == wanted:
                return True
        except ValueError:
            continue
    return False


def parse_arguments(raw: object) -> dict[str, Any]:
    """Accept a JSON object or a JSON string of an object."""
    if isinstance(raw, str):
        if not raw.strip():
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"tool arguments are not valid JSON: {exc}") from exc
    elif isinstance(raw, dict):
        parsed = raw
    else:
        raise ValueError("tool arguments must be a JSON object")
    if not isinstance(parsed, dict):
        raise ValueError("tool arguments must be a JSON object")
    return dict(parsed)


def scrub_secrets(text: str, secrets: list[str]) -> str:
    cleaned = text
    for secret in secrets:
        if secret:
            cleaned = cleaned.replace(secret, "[redacted]")
    return cleaned[:500]


@dataclass
class ToolCallBuffer:
    """Accumulate streamed tool-call fragments."""

    id: str = ""
    name: str = ""
    arguments: str = ""
    raw_arguments: dict[str, Any] | None = None

    def as_call(self, fallback_id: str) -> ToolCall:
        if self.raw_arguments is not None and not self.arguments:
            arguments = dict(self.raw_arguments)
        else:
            arguments = parse_arguments(self.arguments or "{}")
        return ToolCall(id=self.id or fallback_id, name=self.name, arguments=arguments)


@dataclass
class StreamAssembler:
    """Collect text deltas and tool calls into one assistant message."""

    content_parts: list[str] = field(default_factory=list)
    tools: dict[int, ToolCallBuffer] = field(default_factory=dict)

    def add_text(self, text: str) -> TextDelta | None:
        if not text:
            return None
        self.content_parts.append(text)
        return TextDelta(text)

    def tool(self, index: int) -> ToolCallBuffer:
        if index not in self.tools:
            self.tools[index] = ToolCallBuffer()
        return self.tools[index]

    def finish(self) -> AssistantFinal:
        calls: list[ToolCall] = []
        for index in sorted(self.tools):
            buffer = self.tools[index]
            if buffer.name:
                calls.append(buffer.as_call(f"call_{index}"))
        return AssistantFinal(content="".join(self.content_parts), tool_calls=tuple(calls))
