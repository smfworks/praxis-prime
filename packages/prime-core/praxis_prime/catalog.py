"""Read-only rows for one profile's memory, skills, and routines.

The worker that owns the profile database builds these. The gateway does
not open that database itself.
"""

from __future__ import annotations

_BODY_LIMIT = 8000


def memory_rows(memory: object) -> list[dict[str, object]]:
    entries = memory.list_entries()  # type: ignore[attr-defined]
    return [item.public() for item in entries]


def skill_rows(catalog: object) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for skill in catalog.ordered():  # type: ignore[attr-defined]
        body = str(skill.body)
        if len(body) > _BODY_LIMIT:
            body = body[:_BODY_LIMIT] + "\n…[truncated]"
        rows.append(
            {
                "name": skill.name,
                "description": skill.description,
                "source": skill.source,
                "body": body,
            }
        )
    return rows


def routine_rows(store: object) -> list[dict[str, object]]:
    return [item.public() for item in store.list_routines()]  # type: ignore[attr-defined]
