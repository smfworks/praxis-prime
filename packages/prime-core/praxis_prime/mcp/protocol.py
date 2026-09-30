"""JSON-RPC helpers for the Model Context Protocol.

The framing follows the public spec: one JSON object per line on stdio,
and HTTP responses that are either a JSON body or an SSE event. This file
is original. It does not vendor the ``mcp`` SDK.

ARCHITECTURE §8.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

PROTOCOL_VERSION = "2025-03-26"
PROTOCOL_FALLBACK = "2024-11-05"
_SECRET_KEY = re.compile(
    r"(?i)(secret|token|password|api[_-]?key|authorization|credential|cookie)"
)


class McpError(RuntimeError):
    """A server or transport failed. The message must not include secrets."""


def dumps_message(message: Mapping[str, Any]) -> bytes:
    return json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


def parse_message(raw: str | bytes) -> dict[str, Any] | None:
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    text = text.strip()
    if not text:
        return None
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(loaded, dict):
        return loaded
    return None


def tool_result_text(result: Mapping[str, Any]) -> str:
    """Flatten an MCP ``tools/call`` result into text. Images are omitted."""
    if result.get("isError") is True:
        body = _content_text(result.get("content"))
        detail = body or "MCP tool reported an error"
        raise McpError(detail[:500])
    return _content_text(result.get("content")) or "(empty)"


def resource_text(result: Mapping[str, Any]) -> str:
    contents = result.get("contents")
    if not isinstance(contents, list):
        return "(empty)"
    parts: list[str] = []
    for item in contents:
        if not isinstance(item, dict):
            continue
        uri = str(item.get("uri", ""))
        text = item.get("text")
        if isinstance(text, str):
            parts.append(f"{uri}\n{text}" if uri else text)
        elif item.get("blob"):
            note = "[binary resource omitted]"
            parts.append(f"{uri}\n{note}" if uri else note)
    return "\n\n".join(parts) if parts else "(empty)"


def prompt_text(result: Mapping[str, Any]) -> str:
    messages = result.get("messages")
    if not isinstance(messages, list):
        return "(empty)"
    parts: list[str] = []
    for item in messages:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role", "user"))
        content = item.get("content")
        if isinstance(content, str):
            parts.append(f"{role}: {content}")
        elif isinstance(content, dict):
            text = content.get("text")
            if isinstance(text, str):
                parts.append(f"{role}: {text}")
        elif isinstance(content, list):
            parts.append(f"{role}: {_content_text(content)}")
    return "\n".join(parts) if parts else "(empty)"


def clean_description(text: str, limit: int = 280) -> str:
    """One line, with fence markers removed so a server cannot forge them."""
    flat = " ".join(str(text).split())
    flat = flat.replace("<<<", "").replace(">>>", "")
    if len(flat) <= limit:
        return flat
    return flat[: limit - 1] + "…"


def schema_for_model(schema: object) -> dict[str, Any]:
    """Keep a tool schema small enough for the prompt."""
    if not isinstance(schema, dict):
        return {"type": "object", "properties": {}, "additionalProperties": True}
    raw = json.dumps(schema, default=str)
    if len(raw) <= 4000:
        return schema
    props = schema.get("properties")
    names = list(props)[:30] if isinstance(props, dict) else []
    return {
        "type": "object",
        "properties": {name: {"type": "string"} for name in names},
        "additionalProperties": True,
    }


def redact_mapping(arguments: Mapping[str, object], limit: int = 180) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    for key, value in arguments.items():
        name = str(key)
        if _SECRET_KEY.search(name):
            cleaned[name] = "[redacted]"
            continue
        text = " ".join(str(value).split())
        cleaned[name] = text if len(text) <= limit else text[: limit - 1] + "…"
    return cleaned


def expose_name(server: str, tool: str) -> str:
    """``mcp__<server>__<tool>`` with characters the model tool schema accepts."""
    safe_tool = re.sub(r"[^A-Za-z0-9_-]", "_", tool).strip("_") or "tool"
    return f"mcp__{server}__{safe_tool}"


def _content_text(content: object) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for item in content:
        if isinstance(item, str):
            parts.append(item)
            continue
        if not isinstance(item, dict):
            continue
        if item.get("type") == "text" and isinstance(item.get("text"), str):
            parts.append(item["text"])
        elif item.get("type") in {"image", "audio", "resource"}:
            parts.append(f"[{item.get('type')} omitted]")
    return "\n".join(parts)
