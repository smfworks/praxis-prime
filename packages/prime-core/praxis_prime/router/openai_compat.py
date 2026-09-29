"""OpenAI-compatible chat completions adapter.

Covers OpenAI, xAI, llama.cpp server, and vLLM. Local servers may omit the
API key. Cloud servers refuse to start a request when the key is missing,
with an error that names the environment variable to set.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator

from praxis_prime.router.http import normalize_base, open_lines
from praxis_prime.router.types import (
    ChatRequest,
    ProviderUnreachable,
    StreamAssembler,
    StreamEvent,
    TextDelta,
)


def completions_url(base_url: str) -> str:
    base = normalize_base(base_url)
    if base.endswith("/v1"):
        return base + "/chat/completions"
    return base + "/v1/chat/completions"


def completions_body(request: ChatRequest) -> dict[str, object]:
    payload: dict[str, object] = {
        "model": request.model,
        "messages": [message.to_openai() for message in request.messages],
        "temperature": request.temperature,
        "stream": True,
    }
    if request.tools:
        payload["tools"] = list(request.tools)
    return payload


def parse_openai_sse_line(line: str, assembler: StreamAssembler) -> list[TextDelta]:
    text = line.strip()
    if not text or text.startswith(":") or text.startswith("event:"):
        return []
    if text.startswith("data:"):
        text = text[5:].strip()
    if text == "[DONE]" or not text:
        return []
    try:
        event = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProviderUnreachable("openai-compatible", f"invalid stream JSON: {exc}") from exc
    if not isinstance(event, dict):
        return []
    if event.get("error"):
        err = event["error"]
        message = err.get("message") if isinstance(err, dict) else str(err)
        raise ProviderUnreachable("openai-compatible", str(message))
    choices = event.get("choices") or []
    if not choices or not isinstance(choices[0], dict):
        return []
    delta = choices[0].get("delta") or {}
    if not isinstance(delta, dict):
        return []
    deltas: list[TextDelta] = []
    content = delta.get("content")
    if isinstance(content, str):
        piece = assembler.add_text(content)
        if piece is not None:
            deltas.append(piece)
    for call in delta.get("tool_calls") or []:
        if not isinstance(call, dict):
            continue
        index = int(call.get("index") or 0)
        buffer = assembler.tool(index)
        if call.get("id"):
            buffer.id = str(call["id"])
        function = call.get("function") or {}
        if isinstance(function, dict):
            if function.get("name"):
                buffer.name = str(function["name"])
            if function.get("arguments"):
                buffer.arguments += str(function["arguments"])
    return deltas


class OpenAICompatibleProvider:
    def __init__(
        self,
        *,
        name: str,
        base_url: str,
        api_key: str | None,
        key_hint: str,
        timeout: float = 90,
        require_key: bool = False,
    ) -> None:
        self.name = name
        self.base_url = normalize_base(base_url)
        self.api_key = api_key or ""
        self.key_hint = key_hint
        self.timeout = timeout
        self.require_key = require_key

    async def stream(self, request: ChatRequest) -> AsyncIterator[StreamEvent]:
        for event in self.iter_stream(request):
            yield event

    def iter_stream(self, request: ChatRequest) -> Iterator[StreamEvent]:
        if self.require_key and not self.api_key:
            raise ProviderUnreachable(
                self.name,
                f"{self.name} API key is not set. Export {self.key_hint}. "
                "Keys stay in the environment and are never written to config.",
            )
        if not self.base_url:
            raise ProviderUnreachable(
                self.name,
                f"{self.name} base URL is not set. "
                "Set PRAXIS_PRIME_OPENAI_COMPATIBLE_BASE_URL for llama.cpp or vLLM.",
            )
        url = completions_url(self.base_url)
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = json.dumps(completions_body(request)).encode("utf-8")
        lines = open_lines(
            url,
            body,
            headers,
            timeout=self.timeout,
            secrets=[self.api_key],
            provider=self.name,
        )
        assembler = StreamAssembler()
        try:
            for line in lines:
                yield from parse_openai_sse_line(line, assembler)
        except ProviderUnreachable as exc:
            raise ProviderUnreachable(self.name, exc.message) from exc
        except OSError as exc:
            raise ProviderUnreachable(self.name, f"stream failed ({exc})") from exc
        yield assembler.finish()
