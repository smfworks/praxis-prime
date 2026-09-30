"""Project instruction discovery.

Files are merged from the global config, then from the git root down to the
working directory. Later text has higher precedence: it is appended, and a
directory's ``AGENTS.override.md`` replaces that directory's ``AGENTS.md``.

The merged text is capped (default 32 KiB, ARCHITECTURE §14). Writes to
these files still need approval; this module only reads them.

ARCHITECTURE §14.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

INSTRUCTION_CAP = 32 * 1024

_SECRET_LINE = (
    "token",
    "secret",
    "password",
    "api_key",
    "apikey",
    "api-key",
)


@dataclass(frozen=True, slots=True)
class InstructionSource:
    """One file that contributed text, in precedence order."""

    path: str
    kind: str
    text: str


@dataclass(frozen=True, slots=True)
class InstructionBundle:
    """Merged instructions plus the report the CLI prints."""

    text: str
    sources: tuple[InstructionSource, ...]
    truncated: bool
    cap: int
    report: str


def discover_instructions(
    repo: Path,
    *,
    cwd: Path | None = None,
    global_dir: Path | None = None,
    cap: int = INSTRUCTION_CAP,
) -> InstructionBundle:
    """Read instruction files. ``repo`` is the git root. ``cwd`` may be deeper."""
    root = Path(repo).resolve()
    start = Path(cwd).resolve() if cwd is not None else root
    sources: list[InstructionSource] = []
    if global_dir is not None:
        sources.extend(_global_sources(Path(global_dir)))
    for directory in _directories(root, start):
        sources.extend(_directory_sources(directory))
    rendered = _render(sources)
    raw = rendered.encode("utf-8")
    truncated = len(raw) > cap
    if truncated:
        rendered = raw[:cap].decode("utf-8", errors="ignore")
    report = (
        f"{len(sources)} files, {len(raw)} bytes, cap {cap}"
        + (", truncated" if truncated else "")
    )
    return InstructionBundle(
        text=rendered,
        sources=tuple(sources),
        truncated=truncated,
        cap=cap,
        report=report,
    )


def _directories(repo: Path, cwd: Path) -> list[Path]:
    if cwd != repo and repo not in cwd.parents:
        cwd = repo
    chain: list[Path] = []
    current = cwd
    while True:
        chain.append(current)
        if current == repo:
            break
        if current.parent == current:
            break
        current = current.parent
    chain.reverse()
    return chain


def _global_sources(directory: Path) -> list[InstructionSource]:
    if not directory.is_dir():
        return []
    sources: list[InstructionSource] = []
    override = directory / "AGENTS.override.md"
    agents = directory / "AGENTS.md"
    if override.is_file():
        sources.append(_source(override, "global AGENTS.override.md"))
    elif agents.is_file():
        sources.append(_source(agents, "global AGENTS.md"))
    claude = directory / "CLAUDE.md"
    if claude.is_file():
        sources.append(_source(claude, "global CLAUDE.md"))
    return sources


def _directory_sources(directory: Path) -> list[InstructionSource]:
    sources: list[InstructionSource] = []
    override = directory / "AGENTS.override.md"
    agents = directory / "AGENTS.md"
    if override.is_file():
        sources.append(_source(override, "AGENTS.override.md"))
    elif agents.is_file():
        sources.append(_source(agents, "AGENTS.md"))
    claude = directory / "CLAUDE.md"
    if claude.is_file():
        sources.append(_source(claude, "CLAUDE.md"))
    rules = directory / ".claude" / "rules"
    if rules.is_dir():
        for path in sorted(rules.rglob("*.md")):
            if path.is_file():
                sources.append(_source(path, "claude rule"))
    cursor = directory / ".cursor" / "rules"
    if cursor.is_dir():
        files = [
            path
            for path in sorted(cursor.iterdir())
            if path.is_file() and path.suffix.lower() in {".mdc", ".md"}
        ]
        always: list[InstructionSource] = []
        conditional: list[InstructionSource] = []
        for path in files:
            source = _cursor_source(path)
            if source.kind.startswith("cursor rule (always"):
                always.append(source)
            else:
                conditional.append(source)
        sources.extend(always)
        sources.extend(conditional)
    copilot = directory / ".github" / "copilot-instructions.md"
    if copilot.is_file():
        sources.append(_source(copilot, "copilot instructions"))
    prime_rules = directory / ".prime" / "rules"
    if prime_rules.is_dir():
        for path in sorted(prime_rules.rglob("*.md")):
            if path.is_file():
                sources.append(_source(path, "prime rule"))
    for name in ("environment.toml", "config.toml"):
        config = directory / ".prime" / name
        if config.is_file():
            sources.append(_source(config, f"prime {name}", redact=True))
    return sources


def _cursor_source(path: Path) -> InstructionSource:
    meta, body = _frontmatter(path.read_text(encoding="utf-8", errors="replace"))
    always = meta.get("alwaysapply", "true").lower() in {"true", "yes", "1"}
    if "alwaysapply" not in meta and not meta:
        always = True
    description = meta.get("description", "")
    globs = meta.get("globs", "")
    if always:
        text = body.strip()
        kind = "cursor rule (always)"
    else:
        kind = "cursor rule (conditional)"
        text = (
            "Apply only when files match globs: "
            + (globs or "(none)")
            + "\nDescription: "
            + (description or "(none)")
            + "\n\n"
            + body.strip()
        )
    return InstructionSource(path=str(path), kind=kind, text=text)


def _frontmatter(text: str) -> tuple[dict[str, str], str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text
    meta: dict[str, str] = {}
    end: int | None = None
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            end = index
            break
        if ":" in line:
            key, value = line.split(":", 1)
            meta[key.strip().lower()] = value.strip().strip("\"'")
    if end is None:
        return {}, text
    return meta, "\n".join(lines[end + 1 :])


def _source(path: Path, kind: str, *, redact: bool = False) -> InstructionSource:
    text = path.read_text(encoding="utf-8", errors="replace")
    if redact:
        text = _redact(text)
    return InstructionSource(path=str(path), kind=kind, text=text.strip())


def _redact(text: str) -> str:
    lines: list[str] = []
    for line in text.splitlines():
        key = line.split("=", 1)[0].strip().lower().replace("-", "_")
        if any(part in key for part in _SECRET_LINE) and "=" in line:
            lines.append(line.split("=", 1)[0] + " = [redacted]")
            continue
        lines.append(line)
    return "\n".join(lines)


def _render(sources: list[InstructionSource]) -> str:
    blocks: list[str] = []
    for source in sources:
        blocks.append(f"## {source.kind} ({source.path})\n{source.text}")
    return "\n\n".join(blocks)
