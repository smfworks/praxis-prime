"""``remember``, ``forget``, and ``recall`` tools.

Episodic rows are written by the loop when a turn ends. These tools write
profile facts and semantic notes, delete them, and search.
"""

from __future__ import annotations

from collections.abc import Mapping

from praxis_prime.memory.tiers import MemoryStore, memory_channel, resolve_scope
from praxis_prime.tools.registry import Risk, Tool, ToolContext, ToolRegistry

_OBJECT = {"type": "object", "additionalProperties": False}


def install_memory_tools(registry: ToolRegistry, store: MemoryStore) -> None:
    for tool in (remember_tool(store), forget_tool(store), recall_tool(store)):
        if registry.get(tool.name) is None:
            registry.register(tool)


def remember_tool(store: MemoryStore) -> Tool:
    def execute(arguments: Mapping[str, object], context: ToolContext) -> str:
        del context
        content = arguments.get("content")
        if not isinstance(content, str) or not content.strip():
            raise ValueError("remember requires content")
        tier = arguments.get("tier")
        kind = tier if isinstance(tier, str) and tier.strip() else "profile"
        raw_scope = arguments.get("scope")
        scope_text = raw_scope if isinstance(raw_scope, str) else "global"
        channel = memory_channel.get()
        scope = resolve_scope(scope_text, store.cwd, channel)
        entry = store.remember(content, tier=kind, scope=scope, channel=channel)
        return f"Remembered {entry.id} in {entry.tier} ({entry.scope})."

    return Tool(
        name="remember",
        description=(
            "Save a durable fact. tier is profile (always in the prompt) or semantic "
            "(searchable). scope is global, project, or channel. Secrets are redacted."
        ),
        parameters={
            **_OBJECT,
            "properties": {
                "content": {"type": "string", "description": "The fact to store."},
                "tier": {
                    "type": "string",
                    "description": "profile or semantic. Default profile.",
                },
                "scope": {
                    "type": "string",
                    "description": "global, project, or channel. Default global.",
                },
            },
            "required": ["content"],
        },
        risk=Risk.DRAFT,
        execute=execute,
    )


def forget_tool(store: MemoryStore) -> Tool:
    def execute(arguments: Mapping[str, object], context: ToolContext) -> str:
        del context
        entry_id = arguments.get("id") if isinstance(arguments.get("id"), str) else ""
        match = arguments.get("match") if isinstance(arguments.get("match"), str) else ""
        if not entry_id and not match:
            raise ValueError("forget needs an id or a match")
        removed = store.forget(entry_id=entry_id, match=match)
        return f"Forgot {removed} memory row(s)."

    return Tool(
        name="forget",
        description="Delete memory by id or by a text match. Does not delete the audit log.",
        parameters={
            **_OBJECT,
            "properties": {
                "id": {"type": "string", "description": "Memory id, mem_…"},
                "match": {"type": "string", "description": "Substring to delete."},
            },
            "required": [],
        },
        risk=Risk.DRAFT,
        execute=execute,
    )


def recall_tool(store: MemoryStore) -> Tool:
    def execute(arguments: Mapping[str, object], context: ToolContext) -> str:
        del context
        query = arguments.get("query")
        if not isinstance(query, str) or not query.strip():
            raise ValueError("recall requires a query")
        limit = arguments.get("limit")
        count = limit if isinstance(limit, int) and limit > 0 else 5
        hits = store.search(query, limit=count, scopes=store.scopes(memory_channel.get()))
        if not hits:
            return "No matching memory."
        lines = [f"{hit.entry.tier} {hit.entry.id}: {hit.entry.content}" for hit in hits]
        return "\n".join(lines)

    return Tool(
        name="recall",
        description=(
            "Search profile, episodic, and semantic memory. Uses embeddings when "
            "the configured Ollama embed model answers, otherwise keyword BM25."
        ),
        parameters={
            **_OBJECT,
            "properties": {
                "query": {"type": "string", "description": "What to look for."},
                "limit": {"type": "integer", "description": "Maximum hits. Default 5."},
            },
            "required": ["query"],
        },
        risk=Risk.READ,
        execute=execute,
    )
