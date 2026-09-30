"""Project hooks for coding mode.

Configured in ``.prime/hooks.toml`` (ARCHITECTURE §14) or ``.prime/hooks``
(a TOML file or a directory of ``*.toml`` files). ``.claude/settings.json``
and ``.cursor/hooks.json`` are read when they use the command-hook shape.

A command hook runs in the task worktree. Bubblewrap is used when it is
installed. Exit code 2 blocks the action. Any other non-zero exit also
blocks, so a broken guard does not fail open. A hook allow cannot override
a policy deny: the loop only calls these hooks after policy has allowed
or a person has approved.

HTTP and MCP hook handlers are not implemented.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from praxis_prime.loop.hooks import HookDecision, HookResult
from praxis_prime.sandbox.bwrap import (
    SandboxError,
    bwrap_available,
    run_bwrap_status,
    run_host_status,
)

_EVENT_NAMES = {
    "pretooluse": "PreToolUse",
    "pre_tool": "PreToolUse",
    "pre-tool": "PreToolUse",
    "pre": "PreToolUse",
    "posttooluse": "PostToolUse",
    "post_tool": "PostToolUse",
    "post-tool": "PostToolUse",
    "post": "PostToolUse",
    "stop": "Stop",
    "on_finish": "Stop",
    "on-finish": "Stop",
    "finish": "Stop",
}


@dataclass(frozen=True, slots=True)
class HookSpec:
    event: str
    matcher: str
    command: str
    source: str


class ProjectHooks:
    """Load ``.prime`` hooks and run them around tool calls."""

    def __init__(self, repo: Path, cwd: Path) -> None:
        self.repo = Path(repo)
        self.cwd = Path(cwd)
        self.specs = load_hooks(self.repo)

    def pre_tool(self, name: str, arguments: Mapping[str, object]) -> HookResult:
        return self._run("PreToolUse", name, arguments)

    def post_tool(
        self,
        name: str,
        arguments: Mapping[str, object],
        output: str,
        *,
        ok: bool,
    ) -> HookResult:
        return self._run("PostToolUse", name, arguments, output=output, ok=ok)

    def on_finish(self, text: str) -> HookResult:
        return self._run("Stop", "", {}, text=text)

    def _run(
        self,
        event: str,
        name: str,
        arguments: Mapping[str, object],
        *,
        output: str = "",
        ok: bool = True,
        text: str = "",
    ) -> HookResult:
        decision = HookDecision.ALLOW
        reasons: list[str] = []
        payload = {
            "event": event,
            "tool": name,
            "arguments": _jsonable(arguments),
            "ok": ok,
            "output": output[:4000],
            "text": text[:4000],
        }
        for spec in self.specs:
            if spec.event != event:
                continue
            if event != "Stop" and not matches(spec.matcher, name):
                continue
            code, body = run_hook_command(spec.command, self.cwd, payload)
            hook_decision, reason = interpret_hook(code, body)
            if hook_decision == HookDecision.DENY:
                decision = HookDecision.DENY
                reasons.append(reason or f"hook blocked ({spec.source})")
            elif hook_decision == HookDecision.ASK and decision != HookDecision.DENY:
                decision = HookDecision.ASK
                reasons.append(reason or "hook asked for approval")
        if decision == HookDecision.ALLOW:
            return HookResult(HookDecision.ALLOW, "")
        return HookResult(decision, "; ".join(reasons))


def load_hooks(repo: Path) -> list[HookSpec]:
    """Read hook specs from the repository. Missing files yield an empty list."""
    root = Path(repo)
    specs: list[HookSpec] = []
    specs.extend(_load_toml(root / ".prime" / "hooks.toml"))
    hooks_path = root / ".prime" / "hooks"
    if hooks_path.is_file():
        specs.extend(_load_toml(hooks_path))
    elif hooks_path.is_dir():
        for path in sorted(hooks_path.glob("*.toml")):
            specs.extend(_load_toml(path))
    specs.extend(_load_json_hooks(root / ".claude" / "settings.json"))
    specs.extend(_load_json_hooks(root / ".cursor" / "hooks.json"))
    return specs


def matches(matcher: str, tool: str) -> bool:
    """True when ``matcher`` is empty or matches the tool name."""
    pattern = matcher.strip()
    if not pattern or pattern == "*":
        return True
    try:
        return re.search(pattern, tool) is not None
    except re.error:
        return pattern in tool


def interpret_hook(code: int, body: str) -> tuple[HookDecision, str]:
    """Map a hook exit code to a decision. Exit 2 always denies."""
    parsed = _json_decision(body)
    if code == 2:
        reason = ""
        if parsed is not None:
            reason = parsed[1]
        return HookDecision.DENY, reason or body.strip() or "hook exited 2"
    if code != 0:
        return HookDecision.DENY, body.strip() or f"hook exited {code}"
    if parsed is not None:
        return parsed
    return HookDecision.ALLOW, ""


def run_hook_command(command: str, cwd: Path, payload: Mapping[str, object]) -> tuple[int, str]:
    """Run one hook. Bubblewrap when present; otherwise a scrubbed host process."""
    stdin = json.dumps(payload)
    try:
        if bwrap_available():
            status = run_bwrap_status(
                command,
                cwd,
                lambda: False,
                timeout=30,
                stdin=stdin,
            )
        else:
            status = run_host_status(
                command,
                cwd,
                lambda: False,
                timeout=30,
                stdin=stdin,
            )
    except SandboxError as exc:
        return 2, f"hook sandbox failed: {exc}"
    return status.code, status.output


def _load_toml(path: Path) -> list[HookSpec]:
    if not path.is_file():
        return []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    specs: list[HookSpec] = []
    for item in _as_list(data.get("hook")):
        spec = _spec_from_mapping(item, default_event="", source=str(path))
        if spec is not None:
            specs.append(spec)
    for event in ("PreToolUse", "PostToolUse", "Stop"):
        for item in _as_list(data.get(event)):
            spec = _spec_from_mapping(item, default_event=event, source=str(path))
            if spec is not None:
                specs.append(spec)
    return specs


def _load_json_hooks(path: Path) -> list[HookSpec]:
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    hooks = data.get("hooks", data) if isinstance(data, dict) else None
    if not isinstance(hooks, dict):
        return []
    specs: list[HookSpec] = []
    for event, groups in hooks.items():
        canonical = _canonical_event(str(event))
        if canonical is None or not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            matcher = str(group.get("matcher", ""))
            inner = group.get("hooks", [group])
            if not isinstance(inner, list):
                continue
            for hook in inner:
                if not isinstance(hook, dict):
                    continue
                kind = str(hook.get("type", "command"))
                if kind not in {"command", ""}:
                    continue
                command = hook.get("command")
                if isinstance(command, str) and command.strip():
                    specs.append(
                        HookSpec(canonical, matcher, command.strip(), str(path))
                    )
    return specs


def _spec_from_mapping(
    item: object,
    *,
    default_event: str,
    source: str,
) -> HookSpec | None:
    if not isinstance(item, dict):
        return None
    event = _canonical_event(str(item.get("event", default_event)))
    command = item.get("command")
    if event is None or not isinstance(command, str) or not command.strip():
        return None
    matcher = item.get("matcher", "")
    return HookSpec(event, str(matcher), command.strip(), source)


def _canonical_event(name: str) -> str | None:
    key = name.strip().lower().replace(" ", "")
    if not key:
        return None
    return _EVENT_NAMES.get(key)


def _as_list(value: object) -> list[object]:
    if isinstance(value, list):
        return value
    return []


def _json_decision(body: str) -> tuple[HookDecision, str] | None:
    text = body.strip()
    if not text:
        return None
    candidates = [text]
    last = text.splitlines()[-1].strip()
    if last != text:
        candidates.append(last)
    for candidate in candidates:
        if not candidate.startswith("{"):
            continue
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        raw = str(data.get("decision", "allow")).lower()
        reason = str(data.get("reason", ""))
        if raw in {"deny", "block"}:
            return HookDecision.DENY, reason
        if raw == "ask":
            return HookDecision.ASK, reason
        return HookDecision.ALLOW, reason
    return None


def _jsonable(arguments: Mapping[str, object]) -> dict[str, object]:
    cleaned: dict[str, object] = {}
    for key, value in arguments.items():
        if isinstance(value, str | int | float | bool) or value is None:
            cleaned[str(key)] = value
        else:
            cleaned[str(key)] = str(value)
    return cleaned
