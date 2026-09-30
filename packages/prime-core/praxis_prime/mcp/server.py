"""Optional MCP server on stdio.

``praxis-prime mcp serve`` exposes ``decide``, ``recall``, and ``skills_list``.
It does not start with the daemon. ``mcp.serve`` stays false in the default
config. The process speaks newline-delimited JSON-RPC on stdin and stdout
and does not listen on a port.

ARCHITECTURE §8.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from typing import Any

from praxis_prime import __version__
from praxis_prime.decide.schema import DecideError, simple_request
from praxis_prime.mcp.protocol import dumps_message, parse_message
from praxis_prime.runtime import Runtime

_TOOLS: tuple[dict[str, Any], ...] = (
    {
        "name": "decide",
        "description": (
            "Ask the local Decision Engine. Does not call a hosted service "
            "and does not approve actions."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "question": {"type": "string"},
                "options": {"type": "string", "description": "Comma-separated choices."},
                "state": {"type": "string"},
                "max_tier": {"type": "integer"},
            },
            "required": ["question"],
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "recall",
        "description": "Search local memory. Results may include untrusted notes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer"},
            },
            "required": ["query"],
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "skills_list",
        "description": "List skill names and descriptions. Does not return skill bodies.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
        "annotations": {"readOnlyHint": True},
    },
)


def run_stdio_server(runtime: Runtime) -> None:
    """Serve until stdin closes. Logs go to stderr, never stdout."""
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return
        message = parse_message(line)
        if message is None:
            continue
        response = handle_message(runtime, message)
        if response is None:
            continue
        sys.stdout.buffer.write(dumps_message(response))
        sys.stdout.buffer.flush()


def handle_message(runtime: Runtime, message: Mapping[str, Any]) -> dict[str, Any] | None:
    method = str(message.get("method", ""))
    req_id = message.get("id")
    if method.startswith("notifications/") or (req_id is None and method):
        return None
    if method == "initialize":
        return _ok(
            req_id,
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "praxis-prime", "version": __version__},
            },
        )
    if method == "ping":
        return _ok(req_id, {})
    if method == "tools/list":
        _audit(runtime, method, ok=True, extra={"count": len(_TOOLS)})
        return _ok(req_id, {"tools": list(_TOOLS)})
    if method == "tools/call":
        params = message.get("params")
        body = params if isinstance(params, dict) else {}
        try:
            text = _call(runtime, body)
        except (DecideError, ValueError, OSError) as exc:
            _audit(runtime, method, ok=False, extra={"tool": str(body.get("name", ""))})
            return _ok(
                req_id,
                {"content": [{"type": "text", "text": str(exc)}], "isError": True},
            )
        _audit(runtime, method, ok=True, extra={"tool": str(body.get("name", ""))})
        return _ok(req_id, {"content": [{"type": "text", "text": text}], "isError": False})
    if req_id is None:
        return None
    return _err(req_id, -32601, f"method not found: {method}")


def _call(runtime: Runtime, params: Mapping[str, Any]) -> str:
    name = str(params.get("name", ""))
    arguments = params.get("arguments")
    args = arguments if isinstance(arguments, dict) else {}
    if name == "decide":
        return _decide(runtime, args)
    if name == "recall":
        return _recall(runtime, args)
    if name == "skills_list":
        return _skills(runtime)
    raise ValueError(f"unknown tool {name}")


def _decide(runtime: Runtime, arguments: Mapping[str, Any]) -> str:
    question = arguments.get("question")
    if not isinstance(question, str) or not question.strip():
        raise ValueError("decide requires a question")
    options_raw = arguments.get("options")
    options = (
        [part.strip() for part in options_raw.split(",") if part.strip()]
        if isinstance(options_raw, str)
        else None
    )
    state = arguments.get("state")
    state_text = state if isinstance(state, str) else ""
    max_tier = arguments.get("max_tier")
    tier = int(max_tier) if isinstance(max_tier, int) else None
    request = simple_request(question, options=options, state=state_text, max_tier=tier)
    response = runtime.engine.decide(request)
    answer = response.answers["q"]
    return (
        f"label: {answer.label}\n"
        f"confidence: {answer.confidence:.4f}\n"
        f"tier: {answer.tier}\n"
        f"rationale: {answer.rationale}"
    )


def _recall(runtime: Runtime, arguments: Mapping[str, Any]) -> str:
    query = arguments.get("query")
    if not isinstance(query, str) or not query.strip():
        raise ValueError("recall requires a query")
    limit = arguments.get("limit")
    count = limit if isinstance(limit, int) and limit > 0 else 5
    hits = runtime.memory.search(query, limit=count, scopes=runtime.memory.scopes())
    if not hits:
        return "No matching memory."
    return "\n".join(f"{hit.entry.tier} {hit.entry.id}: {hit.entry.content}" for hit in hits)


def _skills(runtime: Runtime) -> str:
    skills = runtime.skills.ordered()
    if not skills:
        return "No skills."
    return "\n".join(skill.index_line() for skill in skills)


def _audit(runtime: Runtime, method: str, *, ok: bool, extra: dict[str, object]) -> None:
    payload = {"server": "serve", "method": method, "ok": ok, **extra}
    runtime.audit.append(
        session_id=None,
        kind="mcp",
        summary=f"serve {method} {'ok' if ok else 'error'}",
        payload=payload,
    )


def _ok(req_id: object, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _err(req_id: object, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}
