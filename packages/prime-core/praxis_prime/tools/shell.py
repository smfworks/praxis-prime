"""Shell command risk classification and execution.

Deleting, sending, spending, and sharing need approval even inside
bubblewrap. When bubblewrap is missing, every command needs approval.
A sandbox failure never reruns the command on the host.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path

from praxis_prime.sandbox.bwrap import (
    SandboxError,
    bwrap_available,
    run_bwrap,
    run_host_shell,
)
from praxis_prime.tools.registry import PreparedCall, Risk, ToolContext

_DESTRUCTIVE_PATTERNS = (
    re.compile(r"(?i)(?:^|[;&|(`\n])\s*(?:sudo\s+)?(?:rm|rmdir|unlink|shred)\b"),
    re.compile(r"(?i)\bmkfs(?:\.\w+)?\b"),
    re.compile(r"(?i)\bdd\b[^\n]*\bof="),
    re.compile(r"(?i)\btruncate\b"),
    re.compile(r"(?i)\bgit\s+clean\b"),
    re.compile(r"(?i)\bgit\s+reset\s+--hard\b"),
    re.compile(r"(?i)\bgit\s+push\b[^\n]*(?:\s-f\b|\s--force\b)"),
    re.compile(r"(?i)\b(?:drop\s+table|delete\s+from|truncate\s+table)\b"),
    re.compile(r"(?i)\bfind\b[^\n]*\s-delete\b"),
    re.compile(r"(?i)\bgio\s+trash\b"),
)

_SEND_PATTERNS = (
    re.compile(r"(?i)(?:^|[;&|(`\n])\s*(?:sudo\s+)?(?:sendmail|msmtp|mail|mailx)\b"),
    re.compile(r"(?i)\bgit\s+push\b"),
    re.compile(r"(?i)(?:^|[;&|(`\n])\s*(?:scp|rsync)\b"),
)

_SPEND_PATTERNS = (
    re.compile(r"(?i)\b(?:stripe|paypal)\b[^\n]*(?:charge|pay|transfer)\b"),
)

_SHARE_PATTERNS = (
    re.compile(r"(?i)\bchmod\b[^\n]*\ba\+r"),
    re.compile(r"(?i)\bgit\s+remote\s+add\b"),
)

_PROTECTED = (
    "agents.md",
    "claude.md",
    "soul.md",
    "secrets.env",
    "profile.toml",
    "prime.db",
    "audit.db",
)

_OVERWRITE = re.compile(r"(?<![>&|])>(?![&>])")
_QUOTED = re.compile(r"'(?:\\'|[^'])*'|\"(?:\\.|[^\"])*\"")


def classify_command(command: str, *, sandbox_ready: bool | None = None) -> PreparedCall:
    """Return the risk and whether policy must ask before running."""
    ready = bwrap_available() if sandbox_ready is None else sandbox_ready
    risk = Risk.READ
    reason = ""
    if _matches(_DESTRUCTIVE_PATTERNS, command) or _has_overwrite(command):
        risk = Risk.DESTRUCTIVE
        reason = "command looks destructive (delete or overwrite)"
    elif _matches(_SPEND_PATTERNS, command):
        risk = Risk.SPEND
        reason = "command looks like a payment"
    elif _matches(_SHARE_PATTERNS, command):
        risk = Risk.SHARE
        reason = "command looks like it shares access"
    elif _matches(_SEND_PATTERNS, command):
        risk = Risk.SEND
        reason = "command looks like it sends data"
    force = False
    force_reason = ""
    if _mentions_protected(command):
        force = True
        force_reason = "protected file (instructions, policy, secrets, or the audit log)"
        if risk == Risk.READ:
            risk = Risk.DESTRUCTIVE
            reason = force_reason
    if not ready:
        force = True
        force_reason = (
            "bubblewrap is not available; every shell command needs approval"
        )
    return PreparedCall(
        risk=risk,
        sandboxed=ready,
        force_approval=force or risk != Risk.READ,
        force_reason=force_reason or reason,
        summary=command.strip()[:180],
    )


def execute_shell(arguments: Mapping[str, object], context: ToolContext) -> str:
    command = arguments.get("command")
    if not isinstance(command, str) or not command.strip():
        raise ValueError("shell requires a command string")
    timeout = _timeout(arguments.get("timeout_seconds"))
    cwd = Path(context.cwd)
    try:
        if bwrap_available():
            return run_bwrap(command, cwd, context.cancelled, timeout=timeout)
        if not context.host_shell_approved:
            raise RuntimeError(
                "bubblewrap is not available and this command was not approved "
                "for the host; it was not run"
            )
        return run_host_shell(command, cwd, context.cancelled, timeout=timeout)
    except SandboxError as exc:
        raise RuntimeError(str(exc)) from exc


def _matches(patterns: tuple[re.Pattern[str], ...], command: str) -> bool:
    return any(pattern.search(command) for pattern in patterns)


def _has_overwrite(command: str) -> bool:
    scrubbed = _QUOTED.sub("", command)
    return _OVERWRITE.search(scrubbed) is not None


def _mentions_protected(command: str) -> bool:
    lowered = command.lower()
    if not any(name in lowered for name in _PROTECTED):
        return False
    if re.search(r"(?i)\b(cat|head|tail|less|more|wc)\b", command):
        return False
    return True


def _timeout(value: object) -> float:
    if value is None:
        return 30
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError("timeout_seconds must be a number") from exc
    if number <= 0 or number > 120:
        raise ValueError("timeout_seconds must be between 1 and 120")
    return number
