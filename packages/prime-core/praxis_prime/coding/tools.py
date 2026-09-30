"""Coding tools: write, exact edit, search, and sandboxed commands.

Edits inside the task worktree are DRAFT. Writes outside that worktree, and
writes to instruction files, require approval. ``git push``, force
operations, and deletes of tracked files are consequential on the existing
approval hook.

``grep`` and ``glob`` stay inside the workspace and skip secret files.
``run_command`` and ``run_tests`` use bubblewrap when it is installed.

ARCHITECTURE §8 and §14.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Mapping
from pathlib import Path

from praxis_prime.policy.boundary import (
    InodeScanCache,
    ReadAccess,
    ReadDenied,
    assert_readable,
    confine_path,
    inode_is_secret,
    is_secret_path,
    read_confined_bytes,
    readable_file,
    secret_scan,
)
from praxis_prime.tools.builtin import builtin_registry
from praxis_prime.tools.registry import PreparedCall, Risk, Tool, ToolContext, ToolRegistry
from praxis_prime.tools.shell import classify_command, execute_shell

_OBJECT = {"type": "object", "additionalProperties": False}
_MAX_WRITE = 1_000_000
_MAX_GREP_FILE = 200_000
_PROTECTED_NAMES = {
    "agents.md",
    "agents.override.md",
    "claude.md",
    "soul.md",
}
_FORCE_GIT = re.compile(
    r"(?i)\bgit\s+(?:"
    r"push\b[^\n]*(?:--force(?:-with-lease)?\b|\s-f\b)"
    r"|reset\s+--hard\b"
    r"|clean\b[^\n]*(?:-f\b|--force\b)"
    r"|checkout\b[^\n]*(?:\s-f\b|--force\b)"
    r"|switch\b[^\n]*--discard-changes\b"
    r"|branch\s+-D\b"
    r"|rebase\b[^\n]*(?:--force\b|\s-f\b)"
    r")"
)
_PUSH = re.compile(r"(?i)\bgit\s+push\b")
_GIT_RM = re.compile(r"(?i)\bgit\s+rm\b")
_RM = re.compile(r"(?i)(?:^|[;&|(`\n])\s*(?:sudo\s+)?(?:rm|unlink)\b([^;&|\n]*)")
_TEST_LINE = re.compile(r"(?i)^tests?\s*:\s*(.+)$")


def coding_registry(worktree: Path) -> ToolRegistry:
    """Built-in tools plus the coding set, bound to ``worktree``."""
    root = Path(worktree).resolve()
    registry = builtin_registry()
    registry.register(_write_file_tool(root))
    registry.register(_edit_file_tool(root))
    registry.register(_grep_tool(root))
    registry.register(_glob_tool(root))
    registry.register(_run_command_tool(root))
    registry.register(_run_tests_tool(root))
    return registry


def classify_write(arguments: Mapping[str, object], *, root: Path) -> PreparedCall:
    path = _preview_path(arguments.get("path"), root)
    return _write_prepared(path, root, verb="write")


def classify_edit(arguments: Mapping[str, object], *, root: Path) -> PreparedCall:
    path = _preview_path(arguments.get("path"), root)
    return _write_prepared(path, root, verb="edit")


def classify_run_command(
    arguments: Mapping[str, object],
    *,
    root: Path,
    sandbox_ready: bool | None = None,
) -> PreparedCall:
    """Risk for a worktree command. Push, force, and tracked deletes always ask."""
    command = arguments.get("command")
    text = command if isinstance(command, str) else ""
    base = classify_command(text, sandbox_ready=sandbox_ready, workspace=root)
    risk = base.risk
    force = base.force_approval
    reason = base.force_reason
    if _is_force(text) or deletes_tracked(text, root):
        risk = Risk.DESTRUCTIVE
        force = True
        reason = "git force operation or delete of a tracked file requires approval"
    elif _PUSH.search(text):
        risk = _higher(risk, Risk.SEND)
        force = True
        reason = "git push requires approval and is not run on its own"
    if not base.sandboxed:
        force = True
        if not reason:
            reason = base.force_reason or "bubblewrap is not available"
    if risk != Risk.READ:
        force = True
    return PreparedCall(
        risk=risk,
        sandboxed=base.sandboxed,
        force_approval=force,
        force_reason=reason,
        summary=text.strip()[:180],
        write_capable=base.write_capable or risk != Risk.READ,
    )


def deletes_tracked(command: str, root: Path) -> bool:
    """True when the command removes a path that git is tracking."""
    if _GIT_RM.search(command):
        return True
    tracked = tracked_files(root)
    if not tracked:
        return False
    for match in _RM.finditer(command):
        for token in _tokens(match.group(1)):
            if token.startswith("-"):
                continue
            rel = token.strip("'\"")
            if rel.startswith("/"):
                continue
            rel = rel.removeprefix("./").rstrip("/")
            if rel in tracked or any(item.startswith(rel + "/") for item in tracked):
                return True
    return False


def tracked_files(root: Path) -> set[str]:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "ls-files"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    return {line.strip() for line in completed.stdout.splitlines() if line.strip()}


def detect_test_command(root: Path) -> str:
    """Pick a test command from instruction files or a project manifest."""
    for name in ("AGENTS.override.md", "AGENTS.md", "CLAUDE.md"):
        path = root / name
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            match = _TEST_LINE.match(line.strip())
            if match:
                return match.group(1).strip()
    manifest = (root / "pyproject.toml").is_file() or (root / "pytest.ini").is_file()
    if manifest or (root / "tests").is_dir():
        return "python -m pytest"
    if (root / "package.json").is_file():
        return "npm test"
    makefile = root / "Makefile"
    if makefile.is_file():
        text = makefile.read_text(encoding="utf-8", errors="replace")
        if re.search(r"(?m)^test\s*:", text):
            return "make test"
    if (root / "Cargo.toml").is_file():
        return "cargo test"
    if (root / "go.mod").is_file():
        return "go test ./..."
    raise ValueError("no test command detected; pass command")


def execute_write_file(arguments: Mapping[str, object], context: ToolContext) -> str:
    raw = arguments.get("path")
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("write_file requires a path")
    content = arguments.get("content")
    if not isinstance(content, str):
        raise ValueError("write_file requires content")
    if len(content) > _MAX_WRITE:
        raise ValueError("write_file content is too large")
    path = _resolve(raw, context.cwd)
    _refuse_secret_write(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return f"wrote {path} ({len(content)} characters)"


def execute_edit_file(arguments: Mapping[str, object], context: ToolContext) -> str:
    raw = arguments.get("path")
    old = arguments.get("old_string")
    new = arguments.get("new_string")
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("edit_file requires a path. The file was not modified.")
    if not isinstance(old, str) or old == "":
        raise ValueError("edit_file: old_string is empty. The file was not modified.")
    if not isinstance(new, str):
        raise ValueError("edit_file requires new_string. The file was not modified.")
    if old == new:
        raise ValueError(
            "edit_file: old_string and new_string are the same. The file was not modified."
        )
    path = _resolve(raw, context.cwd)
    if is_secret_path(path) or inode_is_secret(path):
        raise ValueError(
            f"refusing to edit secret file {path.name}. The file was not modified."
        )
    if not path.is_file():
        raise ValueError(f"edit_file: not a file: {path}. The file was not modified.")
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    display = path.name
    if count == 0:
        raise ValueError(
            f"edit_file: old_string was not found in {display}. The file was not modified."
        )
    if count > 1:
        raise ValueError(
            f"edit_file: old_string matched {count} times in {display}. "
            "Provide a longer unique snippet. The file was not modified."
        )
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    return f"edited {path}"


def execute_grep(arguments: Mapping[str, object], context: ToolContext) -> str:
    pattern = arguments.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("grep requires a pattern")
    raw_path = arguments.get("path", ".")
    if not isinstance(raw_path, str) or not raw_path.strip():
        raw_path = "."
    access = _read_access(context)
    base = confine_path(raw_path, cwd=context.cwd, access=access)
    assert_readable(base, requested=Path(raw_path), cache=context.inode_cache)
    return _python_grep(
        pattern,
        base,
        cwd=context.cwd,
        access=access,
        cache=context.inode_cache,
    )


def execute_glob(arguments: Mapping[str, object], context: ToolContext) -> str:
    pattern = arguments.get("pattern")
    if not isinstance(pattern, str) or not pattern.strip():
        raise ValueError("glob requires a pattern")
    raw_path = arguments.get("path", ".")
    if not isinstance(raw_path, str) or not raw_path.strip():
        raw_path = "."
    access = _read_access(context)
    base = confine_path(raw_path, cwd=context.cwd, access=access)
    assert_readable(base, requested=Path(raw_path), cache=context.inode_cache)
    if not base.is_dir():
        raise ValueError(f"not a directory: {base}")
    inodes = secret_scan(context.inode_cache)
    matches: list[str] = []
    for path in sorted(base.glob(pattern)):
        if _skipped(path) or is_secret_path(path):
            continue
        try:
            resolved = path.resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            continue
        if not readable_file(
            resolved,
            cwd=context.cwd,
            access=access,
            inodes=inodes,
        ):
            if not (resolved.is_dir() and not is_secret_path(resolved)):
                continue
            try:
                confine_path(str(resolved), cwd=context.cwd, access=access)
            except ReadDenied:
                continue
        try:
            rel = path.resolve(strict=False).relative_to(base).as_posix()
        except ValueError:
            continue
        directory = path.is_dir() and not path.is_symlink()
        matches.append(rel + ("/" if directory else ""))
        if len(matches) >= 200:
            matches.append("…[truncated]")
            break
    return "\n".join(matches) if matches else "(no matches)"


def execute_run_command(arguments: Mapping[str, object], context: ToolContext) -> str:
    return execute_shell(arguments, context)


def execute_run_tests(arguments: Mapping[str, object], context: ToolContext) -> str:
    command = arguments.get("command")
    if not isinstance(command, str) or not command.strip():
        command = detect_test_command(Path(context.cwd))
    timeout = arguments.get("timeout_seconds", 120)
    return execute_run_command(
        {"command": command, "timeout_seconds": timeout},
        context,
    )


def _write_file_tool(root: Path) -> Tool:
    return Tool(
        name="write_file",
        description=(
            "Create or replace a UTF-8 text file inside the task worktree. "
            "Writes outside the worktree, and writes to instruction files, need approval."
        ),
        parameters={
            **_OBJECT,
            "properties": {
                "path": {"type": "string", "description": "File path, relative to the worktree."},
                "content": {"type": "string", "description": "Full new contents."},
            },
            "required": ["path", "content"],
        },
        risk=Risk.DRAFT,
        execute=execute_write_file,
        classify=lambda arguments: classify_write(arguments, root=root),
    )


def _edit_file_tool(root: Path) -> Tool:
    return Tool(
        name="edit_file",
        description=(
            "Replace one exact old_string with new_string. The old_string must "
            "match exactly once. If it is missing or matches more than once, "
            "the file is not modified."
        ),
        parameters={
            **_OBJECT,
            "properties": {
                "path": {"type": "string"},
                "old_string": {"type": "string", "description": "Exact text to replace."},
                "new_string": {"type": "string", "description": "Replacement text."},
            },
            "required": ["path", "old_string", "new_string"],
        },
        risk=Risk.DRAFT,
        execute=execute_edit_file,
        classify=lambda arguments: classify_edit(arguments, root=root),
    )


def _grep_tool(root: Path) -> Tool:
    del root
    return Tool(
        name="grep",
        description=(
            "Search file contents for a regular expression inside the workspace. "
            "Secret files are skipped."
        ),
        parameters={
            **_OBJECT,
            "properties": {
                "pattern": {"type": "string"},
                "path": {
                    "type": "string",
                    "description": "Directory or file. Defaults to the worktree.",
                },
            },
            "required": ["pattern"],
        },
        risk=Risk.READ,
        execute=execute_grep,
    )


def _glob_tool(root: Path) -> Tool:
    del root
    return Tool(
        name="glob",
        description=(
            "List files matching a glob inside the workspace. "
            "Secret files and paths outside the workspace are omitted."
        ),
        parameters={
            **_OBJECT,
            "properties": {
                "pattern": {"type": "string", "description": "Glob such as **/*.py."},
                "path": {"type": "string", "description": "Directory. Defaults to the worktree."},
            },
            "required": ["pattern"],
        },
        risk=Risk.READ,
        execute=execute_glob,
    )


def _run_command_tool(root: Path) -> Tool:
    return Tool(
        name="run_command",
        description=(
            "Run a bash command in the task worktree. Uses bubblewrap with no "
            "network when bwrap is installed. The worktree is mounted read-only "
            "unless this command was approved as a write. Commands that are not "
            "on the read-only allowlist always need approval."
        ),
        parameters={
            **_OBJECT,
            "properties": {
                "command": {"type": "string"},
                "timeout_seconds": {"type": "number"},
            },
            "required": ["command"],
        },
        risk=Risk.READ,
        execute=execute_run_command,
        classify=lambda arguments: classify_run_command(arguments, root=root),
    )


def _run_tests_tool(root: Path) -> Tool:
    def classify(arguments: Mapping[str, object]) -> PreparedCall:
        command = arguments.get("command")
        if not isinstance(command, str) or not command.strip():
            command = detect_test_command(root)
        timeout = arguments.get("timeout_seconds", 120)
        return classify_run_command(
            {"command": command, "timeout_seconds": timeout},
            root=root,
        )

    return Tool(
        name="run_tests",
        description=(
            "Run the project's tests in the worktree. Pass command to override "
            "detection from AGENTS.md, CLAUDE.md, or the manifest."
        ),
        parameters={
            **_OBJECT,
            "properties": {
                "command": {"type": "string", "description": "Optional test command."},
                "timeout_seconds": {"type": "number"},
            },
            "required": [],
        },
        risk=Risk.READ,
        execute=execute_run_tests,
        classify=classify,
    )


def _write_prepared(path: Path | None, root: Path, *, verb: str) -> PreparedCall:
    if path is None:
        return PreparedCall(
            risk=Risk.DRAFT,
            sandboxed=False,
            force_approval=True,
            force_reason=f"{verb} is missing a path",
            summary=verb,
        )
    outside = not _inside(path, root)
    protected = is_protected(path)
    force = outside or protected
    if outside:
        reason = f"{verb} is outside the task worktree"
        risk = Risk.DESTRUCTIVE
    elif protected:
        reason = "protected instruction or policy file"
        risk = Risk.DESTRUCTIVE
    else:
        reason = ""
        risk = Risk.DRAFT
    display = path.name if outside else _relative(path, root)
    return PreparedCall(
        risk=risk,
        sandboxed=False,
        force_approval=force,
        force_reason=reason,
        summary=f"{verb} {display}"[:180],
    )


def is_protected(path: Path) -> bool:
    """Instruction files, policy files, and secret names."""
    name = path.name.lower()
    if name in _PROTECTED_NAMES or is_secret_path(path):
        return True
    parts = [part.lower() for part in path.parts]
    if ".cursor" in parts and "rules" in parts:
        return True
    if ".claude" in parts:
        return True
    if ".prime" in parts:
        return True
    if name in {"profile.toml", "hooks.toml"}:
        return True
    return False


def _refuse_secret_write(path: Path) -> None:
    if is_secret_path(path) or inode_is_secret(path):
        raise ValueError(f"refusing to write secret file {path.name}")


def _read_access(context: ToolContext) -> ReadAccess:
    access = context.read_access
    if isinstance(access, ReadAccess):
        return access
    return ReadAccess()


def _is_force(command: str) -> bool:
    return _FORCE_GIT.search(command) is not None


def _higher(left: Risk, right: Risk) -> Risk:
    order = {
        Risk.READ: 0,
        Risk.DRAFT: 1,
        Risk.SEND: 2,
        Risk.SHARE: 3,
        Risk.SPEND: 4,
        Risk.DESTRUCTIVE: 5,
    }
    return left if order[left] >= order[right] else right


def _preview_path(raw: object, root: Path) -> Path | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    return _resolve(raw, str(root))


def _resolve(raw: str, cwd: str) -> Path:
    path = Path(raw)
    if not path.is_absolute():
        path = Path(cwd) / path
    return path.resolve()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _tokens(tail: str) -> list[str]:
    return [token for token in re.split(r"\s+", tail.strip()) if token]


def _skipped(path: Path) -> bool:
    return any(part in {".git", "node_modules", ".venv", "__pycache__"} for part in path.parts)


def _python_grep(
    pattern: str,
    base: Path,
    *,
    cwd: str,
    access: ReadAccess,
    cache: InodeScanCache | None = None,
) -> str:
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"invalid grep pattern: {exc}") from exc
    lines: list[str] = []
    inodes = secret_scan(cache)
    for path in _search_files(base, cwd=cwd, access=access, inodes=inodes):
        try:
            data = read_confined_bytes(
                path,
                cwd=cwd,
                access=access,
                limit=_MAX_GREP_FILE,
                cache=cache,
            )
        except (OSError, ReadDenied):
            continue
        if b"\x00" in data[:1024]:
            continue
        content = data.decode("utf-8", errors="replace")
        for number, line in enumerate(content.splitlines(), start=1):
            if compiled.search(line):
                lines.append(f"{path}:{number}:{line[:200]}")
                if len(lines) >= 100:
                    lines.append("…[truncated]")
                    return "\n".join(lines)
    return "\n".join(lines) if lines else "(no matches)"


def _search_files(
    base: Path,
    *,
    cwd: str,
    access: ReadAccess,
    inodes: set[tuple[int, int]],
) -> list[Path]:
    if base.is_file() or base.is_symlink():
        if readable_file(
            base,
            cwd=cwd,
            access=access,
            inodes=inodes,
        ):
            return [base.resolve(strict=False)]
        return []
    found: list[Path] = []
    if not base.is_dir():
        return found
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        kept: list[str] = []
        for name in dirnames:
            child = Path(dirpath) / name
            if name in {".git", "node_modules", ".venv", "__pycache__"}:
                continue
            if child.is_symlink() or is_secret_path(child):
                continue
            kept.append(name)
        dirnames[:] = kept
        for name in filenames:
            path = Path(dirpath) / name
            if not readable_file(
                path,
                cwd=cwd,
                access=access,
                inodes=inodes,
            ):
                continue
            try:
                found.append(path.resolve(strict=False))
            except (OSError, RuntimeError, ValueError):
                continue
            if len(found) >= 2000:
                return found
    return found


