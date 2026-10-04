"""Model router.

One chain of providers behind ``stream``. The first provider that returns a
token wins. Connection failures, missing keys, and HTTP errors try the next
entry. The chain never sends a secret to a provider that was not selected.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import Protocol

from praxis_prime.router.types import (
    ChatRequest,
    FallbackNotice,
    InferenceNotConfigured,
    ModelRef,
    ProviderUnreachable,
    RouterExhausted,
    StreamEvent,
    unverified_provider_message,
)


class ChatProvider(Protocol):
    name: str

    def iter_stream(self, request: ChatRequest) -> Iterator[StreamEvent]:
        """Yield events. Raise ``ProviderUnreachable`` before the first yield on failure."""


class ModelRouter:
    def __init__(
        self,
        chain: list[ModelRef],
        providers: dict[str, ChatProvider],
        *,
        require_verified: bool = False,
        verified_specs: set[str] | None = None,
    ) -> None:
        self.chain = list(chain)
        self.providers = providers
        self.require_verified = require_verified
        self.verified_specs = set(verified_specs or ())

    @property
    def primary(self) -> ModelRef:
        if not self.chain:
            raise InferenceNotConfigured()
        return self.chain[0]

    def use_primary(self, ref: ModelRef) -> None:
        rest = [item for item in self.chain if item != ref]
        self.chain = [ref, *rest]

    async def stream(self, request: ChatRequest) -> AsyncIterator[StreamEvent]:
        for event in self.iter_stream(request):
            yield event

    def iter_stream(self, request: ChatRequest) -> Iterator[StreamEvent]:
        if not self.chain:
            raise InferenceNotConfigured()
        if self.require_verified and self.chain[0].spec() not in self.verified_specs:
            raise InferenceNotConfigured(unverified_provider_message(self.chain[0].spec()))
        errors: list[ProviderUnreachable] = []
        for index, ref in enumerate(self.chain):
            provider = self.providers.get(ref.provider)
            if provider is None:
                errors.append(
                    ProviderUnreachable(
                        ref.provider,
                        f"no adapter is configured for {ref.provider}",
                    )
                )
                continue
            bound = ChatRequest(
                model=ref.model,
                messages=request.messages,
                tools=request.tools,
                temperature=request.temperature,
            )
            try:
                iterator = iter(provider.iter_stream(bound))
                first = next(iterator)
            except StopIteration:
                return
            except ProviderUnreachable as exc:
                errors.append(exc)
                if index + 1 < len(self.chain):
                    nxt = self.chain[index + 1]
                    yield FallbackNotice(
                        f"{exc.provider} is not usable ({exc.message}). "
                        f"Trying {nxt.provider}:{nxt.model}."
                    )
                continue
            yield first
            yield from iterator
            return
        raise RouterExhausted(errors)
