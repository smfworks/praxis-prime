"""Opt-in scripted model for tests.

``PRAXIS_PRIME_STUB_REPLIES`` points at a JSON file of assistant turns.
When the variable is unset, this module does nothing and the normal
provider map is used. It is not a configured model and it does not
open a network connection.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from pathlib import Path

from praxis_prime.router.router import ChatProvider
from praxis_prime.router.types import AssistantFinal, ChatRequest, StreamEvent, TextDelta, ToolCall


class ScriptedProvider:
    """Replay prepared assistant messages. Records each request."""

    def __init__(self, replies: list[AssistantFinal], *, name: str = "ollama") -> None:
        self.name = name
        self.replies = list(replies)
        self.requests: list[ChatRequest] = []

    def iter_stream(self, request: ChatRequest) -> Iterator[StreamEvent]:
        self.requests.append(request)
        if not self.replies:
            raise RuntimeError("scripted provider ran out of replies")
        reply = self.replies.pop(0)
        if reply.content:
            yield TextDelta(reply.content)
        yield reply


def providers_from_env(env: Mapping[str, str]) -> dict[str, ChatProvider] | None:
    """Return an ollama stand-in, or None when the test hook is unset."""
    raw = env.get("PRAXIS_PRIME_STUB_REPLIES", "").strip()
    if not raw:
        return None
    return {"ollama": ScriptedProvider(load_replies(Path(raw)))}


def load_replies(path: Path) -> list[AssistantFinal]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("stub replies file is not JSON") from exc
    rows = loaded.get("replies") if isinstance(loaded, dict) else loaded
    if not isinstance(rows, list) or not rows:
        raise ValueError("stub replies file needs a list of turns")
    return [_reply(item) for item in rows]


def _reply(item: object) -> AssistantFinal:
    if not isinstance(item, dict):
        raise ValueError("stub reply must be an object")
    content = item.get("content", "")
    if not isinstance(content, str):
        raise ValueError("stub content must be a string")
    raw_calls = item.get("toolCalls", item.get("tool_calls", []))
    if raw_calls is None:
        raw_calls = []
    if not isinstance(raw_calls, list):
        raise ValueError("stub tool calls must be a list")
    calls = tuple(_call(call) for call in raw_calls)
    return AssistantFinal(content=content, tool_calls=calls)


def _call(item: object) -> ToolCall:
    if not isinstance(item, dict):
        raise ValueError("stub tool call must be an object")
    name = item.get("name", "")
    call_id = item.get("id", "")
    arguments = item.get("arguments", {})
    if not isinstance(name, str) or not name:
        raise ValueError("stub tool call needs a name")
    if not isinstance(call_id, str) or not call_id:
        raise ValueError("stub tool call needs an id")
    if not isinstance(arguments, dict):
        raise ValueError("stub tool arguments must be an object")
    return ToolCall(id=call_id, name=name, arguments=arguments)
