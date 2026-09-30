"""Ollama adapter. Local, and the default provider.

Uses the native ``/api/chat`` stream (newline-delimited JSON). No API key.
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
    parse_arguments,
)


def ollama_url(host: str) -> str:
    return normalize_base(host or "http://127.0.0.1:11434") + "/api/chat"


def ollama_body(request: ChatRequest) -> dict[str, object]:
    payload: dict[str, object] = {
        "model": request.model,
        "messages": [message.to_openai() for message in request.messages],
        "stream": True,
        "options": {"temperature": request.temperature},
    }
    if request.tools:
        payload["tools"] = list(request.tools)
    return payload


def parse_ollama_line(line: str, assembler: StreamAssembler) -> list[TextDelta]:
    text = line.strip()
    if not text:
        return []
    try:
        event = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProviderUnreachable("ollama", f"Ollama returned invalid JSON: {exc}") from exc
    if not isinstance(event, dict):
        return []
    if event.get("error"):
        raise ProviderUnreachable("ollama", str(event["error"]))
    message = event.get("message") or {}
    deltas: list[TextDelta] = []
    if isinstance(message, dict):
        content = message.get("content") or ""
        if isinstance(content, str):
            delta = assembler.add_text(content)
            if delta is not None:
                deltas.append(delta)
        for index, call in enumerate(message.get("tool_calls") or []):
            if not isinstance(call, dict):
                continue
            function = call.get("function") or call
            if not isinstance(function, dict):
                continue
            buffer = assembler.tool(index)
            buffer.id = str(call.get("id") or buffer.id or f"call_{index}")
            name = function.get("name")
            if isinstance(name, str) and name:
                buffer.name = name
            raw_args = function.get("arguments")
            if isinstance(raw_args, dict):
                buffer.raw_arguments = parse_arguments(raw_args)
            elif isinstance(raw_args, str) and raw_args:
                buffer.arguments += raw_args
    return deltas


class OllamaProvider:
    name = "ollama"

    def __init__(self, host: str = "http://127.0.0.1:11434", *, timeout: float = 90) -> None:
        self.host = normalize_base(host or "http://127.0.0.1:11434")
        self.timeout = timeout

    async def stream(self, request: ChatRequest) -> AsyncIterator[StreamEvent]:
        for event in self.iter_stream(request):
            yield event

    def iter_stream(self, request: ChatRequest) -> Iterator[StreamEvent]:
        url = ollama_url(self.host)
        body = json.dumps(ollama_body(request)).encode("utf-8")
        try:
            lines = open_lines(
                url,
                body,
                {"Content-Type": "application/json"},
                timeout=self.timeout,
                secrets=[],
                provider=self.name,
            )
        except ProviderUnreachable as exc:
            raise ProviderUnreachable(
                self.name,
                f"Ollama is not reachable at {self.host}. "
                "Start it with `ollama serve`, or set PRAXIS_PRIME_OLLAMA_HOST. "
                f"{exc.message}",
            ) from exc
        assembler = StreamAssembler()
        try:
            for line in lines:
                yield from parse_ollama_line(line, assembler)
        except ProviderUnreachable:
            raise
        except OSError as exc:
            raise ProviderUnreachable(self.name, f"Ollama stream failed ({exc})") from exc
        yield assembler.finish()
