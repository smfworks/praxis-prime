"""In-process model providers for tests. They do not open sockets."""

from __future__ import annotations

from praxis_prime.router.types import AssistantFinal, ChatRequest, TextDelta


class ScriptedProvider:
    """Replay prepared assistant messages. Records each request."""

    def __init__(self, replies: list[AssistantFinal | Exception], *, name: str = "ollama") -> None:
        self.name = name
        self.replies = list(replies)
        self.requests: list[ChatRequest] = []

    def iter_stream(self, request: ChatRequest):
        self.requests.append(request)
        if not self.replies:
            raise RuntimeError("scripted provider ran out of replies")
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        if reply.content:
            yield TextDelta(reply.content)
        yield reply
