"""Lightweight repository context for a coding prompt.

This is a file-tree summary plus a keyword search. It does not build an
embedding index.

TODO: ARCHITECTURE §10 — semantic memory (sqlite-vec) should replace
``relevant_files`` when that tier exists. Do not add an embedding model here.
"""

from __future__ import annotations

import re
from pathlib import Path

_SKIP = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
}
_MAX_TREE = 200
_MAX_FILE = 200_000
_MAX_HITS = 8


def file_tree_summary(root: Path, *, limit: int = _MAX_TREE) -> str:
    """List project files, skipping dependency and VCS directories."""
    root = Path(root)
    paths: list[str] = []
    truncated = False
    for path in _walk(root):
        if len(paths) >= limit:
            truncated = True
            break
        rel = path.relative_to(root).as_posix()
        paths.append(rel + ("/" if path.is_dir() else ""))
    if not paths:
        return "(empty tree)"
    header = f"{len(paths)} paths"
    if truncated:
        header += f", stopped at {limit}"
    return header + "\n" + "\n".join(paths)


def relevant_files(root: Path, query: str, *, limit: int = _MAX_HITS) -> str:
    """Rank files by path and text overlap with ``query``.

    TODO: ARCHITECTURE §10 — this keyword scan is a stand-in for a semantic
    index. Do not treat the scores as embeddings.
    """
    tokens = [token for token in re.split(r"\W+", query.lower()) if len(token) >= 3]
    if not tokens:
        return "(no query terms)"
    scored: list[tuple[int, str, str]] = []
    root = Path(root)
    for path in _walk(root):
        if path.is_dir() or not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        lowered = rel.lower()
        score = 0
        for token in tokens:
            if token in lowered:
                score += 5
        snippet = ""
        if path.stat().st_size <= _MAX_FILE and _looks_text(path):
            text = path.read_text(encoding="utf-8", errors="replace")
            haystack = text.lower()
            for token in tokens:
                if token in haystack:
                    score += 1
            if score:
                snippet = _snippet(text, tokens)
        if score:
            scored.append((score, rel, snippet))
    scored.sort(key=lambda item: (-item[0], item[1]))
    if not scored:
        return "(no matching files)"
    lines: list[str] = []
    for _score, rel, snippet in scored[:limit]:
        if snippet:
            lines.append(f"{rel}: {snippet}")
        else:
            lines.append(rel)
    return "\n".join(lines)


def _walk(root: Path) -> list[Path]:
    found: list[Path] = []
    if not root.is_dir():
        return found

    def visit(directory: Path) -> None:
        try:
            entries = sorted(directory.iterdir(), key=lambda item: item.name.lower())
        except OSError:
            return
        for entry in entries:
            if entry.name in _SKIP:
                continue
            found.append(entry)
            if entry.is_dir() and not entry.is_symlink():
                visit(entry)

    visit(root)
    return found


def _looks_text(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:1024]
    except OSError:
        return False
    return b"\x00" not in sample


def _snippet(text: str, tokens: list[str]) -> str:
    for line in text.splitlines():
        lowered = line.lower()
        if any(token in lowered for token in tokens):
            flat = " ".join(line.split())
            return flat[:160]
    flat = " ".join(text.split())
    return flat[:160]
