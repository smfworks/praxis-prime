"""Anthropic Messages API adapter.

The wire format differs from OpenAI. This module converts both ways. A
missing key fails before any network call.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from typing import Any

from praxis_prime.router.http import normalize_base, open_lines
from praxis_prime.router.types import (
    ChatMessage,
    ChatRequest,
    ProviderUnreachable,
    StreamAssembler,
    StreamEvent,
    TextDelta,
)


def anthropic_messages(messages: tuple[ChatMessage, ...]) -> tuple[str, list[dict[str, Any]]]:
    system_parts: list[str] = []
    converted: list[dict[str, Any]] = []
    for message in messages:
        if message.role == "system":
            if message.content:
                system_parts.append(message.content)
            continue
        if message.role == "user":
            converted.append({"role": "user", "content": message.content})
            continue
        if message.role == "assistant":
            blocks: list[dict[str, Any]] = []
            if message.content:
                blocks.append({"type": "text", "text": message.content})
            for call in message.tool_calls:
                blocks.append(
                    {
                        "type": "tool_use",
                        "id": call.id,
                        "name": call.name,
                        "input": dict(call.arguments),
                    }
                )
            converted.append({"role": "assistant", "content": blocks or message.content})
            continue
        if message.role == "tool":
            converted.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": message.tool_call_id or "",
                            "content": message.content,
                        }
                    ],
                }
            )
    return "\n\n".join(system_parts), _merge_roles(converted)


def anthropic_tools(tools: tuple[dict[str, Any], ...]) -> list[dict[str, Any]]:
    converted = []
    for tool in tools:
        function = tool.get("function") or tool
        if not isinstance(function, dict):
            continue
        converted.append(
            {
                "name": function.get("name"),
                "description": function.get("description") or "",
                "input_schema": function.get("parameters") or {"type": "object", "properties": {}},
            }
        )
    return converted


def parse_anthropic_sse_line(
    line: str,
    assembler: StreamAssembler,
    state: dict[str, Any],
) -> list[TextDelta]:
    text = line.strip()
    if not text:
        return []
    if text.startswith("event:"):
        state["event"] = text[6:].strip()
        return []
    if text.startswith("data:"):
        text = text[5:].strip()
    if not text or text == "[DONE]":
        return []
    try:
        event = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProviderUnreachable("anthropic", f"invalid stream JSON: {exc}") from exc
    if not isinstance(event, dict):
        return []
    kind = str(event.get("type") or state.get("event") or "")
    if kind == "error":
        err = event.get("error") or {}
        message = err.get("message") if isinstance(err, dict) else str(err)
        raise ProviderUnreachable("anthropic", str(message))
    deltas: list[TextDelta] = []
    if kind == "content_block_start":
        block = event.get("content_block") or {}
        index = int(event.get("index") or 0)
        if isinstance(block, dict) and block.get("type") == "tool_use":
            buffer = assembler.tool(index)
            buffer.id = str(block.get("id") or "")
            buffer.name = str(block.get("name") or "")
        return deltas
    if kind == "content_block_delta":
        delta = event.get("delta") or {}
        index = int(event.get("index") or 0)
        if not isinstance(delta, dict):
            return deltas
        if delta.get("type") == "text_delta" and isinstance(delta.get("text"), str):
            piece = assembler.add_text(delta["text"])
            if piece is not None:
                deltas.append(piece)
        if delta.get("type") == "input_json_delta" and delta.get("partial_json"):
            assembler.tool(index).arguments += str(delta["partial_json"])
    return deltas


class AnthropicProvider:
    name = "anthropic"

    def __init__(
        self,
        *,
        base_url: str = "https://api.anthropic.com",
        api_key: str | None,
        timeout: float = 90,
    ) -> None:
        self.base_url = normalize_base(base_url or "https://api.anthropic.com")
        self.api_key = api_key or ""
        self.timeout = timeout

    async def stream(self, request: ChatRequest) -> AsyncIterator[StreamEvent]:
        for event in self.iter_stream(request):
            yield event

    def iter_stream(self, request: ChatRequest) -> Iterator[StreamEvent]:
        if not self.api_key:
            raise ProviderUnreachable(
                self.name,
                "Anthropic API key is not set. Export PRAXIS_PRIME_ANTHROPIC_API_KEY "
                "or ANTHROPIC_API_KEY. Keys stay in the environment and are "
                "never written to config.",
            )
        system, messages = anthropic_messages(request.messages)
        payload: dict[str, Any] = {
            "model": request.model,
            "max_tokens": 4096,
            "temperature": request.temperature,
            "messages": messages,
            "stream": True,
        }
        if system:
            payload["system"] = system
        tools = anthropic_tools(request.tools)
        if tools:
            payload["tools"] = tools
        url = self.base_url + "/v1/messages"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }
        lines = open_lines(
            url,
            json.dumps(payload).encode("utf-8"),
            headers,
            timeout=self.timeout,
            secrets=[self.api_key],
            provider=self.name,
        )
        assembler = StreamAssembler()
        state: dict[str, Any] = {}
        try:
            for line in lines:
                yield from parse_anthropic_sse_line(line, assembler, state)
        except ProviderUnreachable as exc:
            raise ProviderUnreachable(self.name, exc.message) from exc
        except OSError as exc:
            raise ProviderUnreachable(self.name, f"stream failed ({exc})") from exc
        yield assembler.finish()


def _merge_roles(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    for message in messages:
        if merged and merged[-1]["role"] == message["role"]:
            merged[-1]["content"] = _concat_content(merged[-1]["content"], message["content"])
        else:
            merged.append(message)
    return merged


def _concat_content(left: object, right: object) -> object:
    left_blocks = _as_blocks(left)
    right_blocks = _as_blocks(right)
    return left_blocks + right_blocks


def _as_blocks(content: object) -> list[dict[str, Any]]:
    if isinstance(content, str):
        return [{"type": "text", "text": content}] if content else []
    if isinstance(content, list):
        return [block for block in content if isinstance(block, dict)]
    return []
