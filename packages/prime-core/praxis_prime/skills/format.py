"""SKILL.md parser.

YAML frontmatter with ``name`` and ``description``, then a markdown body.
The shape matches the public Claude Code, Hermes, and OpenClaw skill file.
This parser is original; it only reads ``key: value`` lines.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_NAME_MAX = 64


@dataclass(frozen=True, slots=True)
class Skill:
    name: str
    description: str
    body: str
    path: Path
    source: str
    meta: dict[str, str]

    def index_line(self) -> str:
        return f"- {self.name}: {self.description}"


def parse_skill(text: str, path: Path, source: str) -> Skill:
    if not text.startswith("---"):
        raise ValueError(f"{path} is missing YAML frontmatter")
    end = _frontmatter_end(text)
    raw = text[3:end].strip("\n")
    body = text[end + 4 :].strip("\n")
    meta = _fields(raw)
    name = meta.get("name", "").strip()
    description = " ".join(meta.get("description", "").split())
    if len(name) > _NAME_MAX or not _NAME.fullmatch(name):
        raise ValueError(f"{path} name must be lowercase words separated by hyphens")
    if not description:
        raise ValueError(f"{path} needs a description")
    return Skill(
        name=name,
        description=description,
        body=body.strip() + ("\n" if body.strip() else ""),
        path=path,
        source=source,
        meta=meta,
    )


def _frontmatter_end(text: str) -> int:
    lines = text.splitlines(keepends=True)
    consumed = len(lines[0]) if lines else 0
    for line in lines[1:]:
        if line.strip() == "---":
            return consumed
        consumed += len(line)
    raise ValueError("frontmatter is not closed with ---")


def _fields(block: str) -> dict[str, str]:
    meta: dict[str, str] = {}
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" not in stripped:
            raise ValueError(f"bad frontmatter line {stripped!r}")
        key, value = stripped.split(":", 1)
        meta[key.strip()] = _unquote(value.strip())
    return meta


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value
