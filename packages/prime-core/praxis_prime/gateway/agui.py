"""Map a chat turn onto AG-UI events.

The gateway still sends the existing ``kind`` payloads. Each AG-UI event
is an extra frame so a CLI that only reads ``kind`` keeps working. Nothing
here calls a hosted service.

docs/OPENDOTS-BORROWED-PATTERNS.md pattern 1.
"""

from __future__ import annotations

from collections.abc import Mapping

AGUI_TYPES = frozenset(
    {
        "RUN_STARTED",
        "RUN_FINISHED",
        "RUN_ERROR",
        "TEXT_MESSAGE_START",
        "TEXT_MESSAGE_CONTENT",
        "TEXT_MESSAGE_END",
        "TOOL_CALL_START",
        "TOOL_CALL_ARGS",
        "TOOL_CALL_END",
        "TOOL_CALL_RESULT",
    }
)


class TurnStream:
    """One chat turn's AG-UI events, in the order the UI should apply them."""

    def __init__(self, *, thread_id: str, run_id: str) -> None:
        self.thread_id = thread_id or run_id
        self.run_id = run_id
        self.message_id = f"msg_{run_id}"
        self._text_open = False

    def start(self) -> list[dict[str, object]]:
        return [
            {
                "type": "RUN_STARTED",
                "threadId": self.thread_id,
                "runId": self.run_id,
            }
        ]

    def feed(self, event: Mapping[str, object]) -> list[dict[str, object]]:
        kind = event.get("kind")
        if kind == "text":
            return self._text(str(event.get("text") or ""))
        if kind == "tool":
            return self._tool(event)
        return []

    def finish(self, *, error: str | None) -> list[dict[str, object]]:
        frames: list[dict[str, object]] = []
        if self._text_open:
            frames.append({"type": "TEXT_MESSAGE_END", "messageId": self.message_id})
            self._text_open = False
        if error:
            frames.append(
                {
                    "type": "RUN_ERROR",
                    "message": error,
                    "threadId": self.thread_id,
                    "runId": self.run_id,
                }
            )
            return frames
        frames.append(
            {
                "type": "RUN_FINISHED",
                "threadId": self.thread_id,
                "runId": self.run_id,
            }
        )
        return frames

    def _text(self, delta: str) -> list[dict[str, object]]:
        frames: list[dict[str, object]] = []
        if not self._text_open:
            self._text_open = True
            frames.append(
                {
                    "type": "TEXT_MESSAGE_START",
                    "messageId": self.message_id,
                    "role": "assistant",
                }
            )
        frames.append(
            {
                "type": "TEXT_MESSAGE_CONTENT",
                "messageId": self.message_id,
                "delta": delta,
            }
        )
        return frames

    def _tool(self, event: Mapping[str, object]) -> list[dict[str, object]]:
        phase = str(event.get("phase") or "")
        tool_id = str(event.get("toolCallId") or "")
        name = str(event.get("name") or "")
        detail = str(event.get("detail") or "")
        if phase == "start":
            return [
                {
                    "type": "TOOL_CALL_START",
                    "toolCallId": tool_id,
                    "toolCallName": name,
                    "parentMessageId": self.message_id,
                }
            ]
        if phase == "args":
            return [{"type": "TOOL_CALL_ARGS", "toolCallId": tool_id, "delta": detail}]
        if phase == "end":
            return [{"type": "TOOL_CALL_END", "toolCallId": tool_id}]
        if phase == "result":
            return [
                {
                    "type": "TOOL_CALL_RESULT",
                    "messageId": f"result_{tool_id}",
                    "toolCallId": tool_id,
                    "content": detail,
                    "role": "tool",
                }
            ]
        return []
