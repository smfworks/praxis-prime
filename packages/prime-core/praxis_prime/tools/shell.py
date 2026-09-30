"""Shell command risk classification and execution.

Only a small read-only allowlist runs without approval. Deletes, writes,
interpreters, and anything the parser cannot classify need a human, including
inside bubblewrap. A content ``git diff``, ``git log -p``, or ``git show``
that the classifier would auto-approve is checked again: the same revisions
and pathspecs run as ``git --name-only`` inside the read-only sandbox. If
that probe fails, or git lists a secret or a path the classifier did not
approve, the command asks. The workspace bind stays read-only after
approval unless the command is write-shaped. An explicit coding-session
write grant applies only to an approved or write-shaped command. An
auto-approved read stays read-only. When bubblewrap is missing, every
command needs approval and runs on the host with full write access. A
sandbox failure never reruns the command on the host.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path

from praxis_prime.policy.boundary import InodeScanCache
from praxis_prime.sandbox.bwrap import (
    CommandStatus,
    SandboxError,
    bwrap_available,
    run_bwrap,
    run_bwrap_status,
    run_host_shell,
)
from praxis_prime.tools.registry import PreparedCall, Risk, ToolContext
from praxis_prime.tools.shellclass import (
    GitProbe,
    classify_shell,
    command_for_sandbox,
    listed_paths_are_approved,
)

_GIT_PROBE_TIMEOUT = 5.0

_SECRET_VALUE = re.compile(
    r"(?i)((?:api[_-]?key|token|secret|password|authorization)\s*[=:]\s*)\S+"
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

def classify_command(
    command: str,
    *,
    sandbox_ready: bool | None = None,
    workspace: Path | None = None,
    cache: InodeScanCache | None = None,
) -> PreparedCall:
    """Return the risk and whether policy must ask before running."""
    ready = bwrap_available() if sandbox_ready is None else sandbox_ready
    verdict = classify_shell(command, workspace=workspace, cache=cache)
    risk = verdict.risk
    reason = verdict.reason
    force = not verdict.allowlisted or risk != Risk.READ
    force_reason = reason
    if _mentions_protected(command):
        force = True
        force_reason = "protected file (instructions, policy, secrets, or the audit log)"
        if risk == Risk.READ:
            risk = Risk.DESTRUCTIVE
    if not ready:
        force = True
        bubble = "bubblewrap is not available; every shell command needs approval"
        force_reason = f"{force_reason}; {bubble}" if force_reason else bubble
    if verdict.allowlisted and ready and not _mentions_protected(command):
        if verdict.probes and not _git_probes_allow(verdict.probes, workspace):
            force = True
            force_reason = "git would show a path outside the approved files"
        else:
            force = False
            force_reason = ""
    return PreparedCall(
        risk=risk,
        sandboxed=ready,
        force_approval=force,
        force_reason=force_reason,
        summary=command.strip()[:180],
        write_capable=verdict.write_capable,
    )


def _git_probes_allow(probes: tuple[GitProbe, ...], workspace: Path | None) -> bool:
    """True when each probe's ``--name-only`` list is the approved file set."""
    if workspace is None:
        return False
    try:
        for probe in probes:
            status = run_bwrap_status(
                probe.command,
                workspace,
                _not_cancelled,
                timeout=_GIT_PROBE_TIMEOUT,
            )
            paths = _name_only_paths(status)
            if paths is None or not listed_paths_are_approved(paths, probe.approved, workspace):
                return False
        return True
    except (SandboxError, OSError):
        return False


def _not_cancelled() -> bool:
    return False


def _name_only_paths(status: CommandStatus) -> list[str] | None:
    """Split a ``git --name-only -z`` stdout. Paths are kept as git printed them."""
    if status.code not in (0, 1):
        return None
    raw = status.stdout
    if not raw:
        return []
    parts = raw.split("\0")
    if parts[-1] == "":
        parts.pop()
    if any(part == "" for part in parts):
        return None
    return parts


def execute_shell(arguments: Mapping[str, object], context: ToolContext) -> str:
    command = arguments.get("command")
    if not isinstance(command, str) or not command.strip():
        raise ValueError("shell requires a command string")
    timeout = _timeout(arguments.get("timeout_seconds"))
    cwd = Path(context.cwd)
    from praxis_prime.policy.boundary import private_data_command

    if private_data_command(command, cwd):
        raise RuntimeError("refusing to read protected account or profile data")
    prepared = classify_command(command, workspace=cwd, cache=context.inode_cache)
    approved = context.shell_approved or context.host_shell_approved
    if prepared.force_approval and not approved:
        _audit_mount(context, command, prepared, mount="ro", ran=False, decision="deny")
        raise RuntimeError(
            "this shell command is not on the read-only allowlist and was not "
            "approved; it was not run"
        )
    writable = _writable(context, prepared)
    scope = Path(context.write_scope) if context.write_scope else cwd
    main = Path(context.main_checkout) if context.main_checkout else None
    ran = command if prepared.force_approval else command_for_sandbox(command)
    try:
        if bwrap_available():
            result = run_bwrap(
                ran,
                cwd,
                context.cancelled,
                timeout=timeout,
                writable=writable,
                scope=scope if writable else None,
                main_checkout=main if writable else None,
            )
            _audit_mount(
                context,
                command,
                prepared,
                mount="rw" if writable else "ro",
                ran=True,
                decision="allow",
            )
            return result
        if not context.host_shell_approved:
            _audit_mount(context, command, prepared, mount="host", ran=False, decision="deny")
            raise RuntimeError(
                "bubblewrap is not available and this command was not approved "
                "for the host; it was not run"
            )
        result = run_host_shell(ran, cwd, context.cancelled, timeout=timeout)
        _audit_mount(context, command, prepared, mount="host", ran=True, decision="allow")
        return result
    except SandboxError as exc:
        _audit_mount(context, command, prepared, mount="ro", ran=False, decision="deny")
        raise RuntimeError(str(exc)) from exc


def bind_is_writable(
    *,
    write_capable: bool,
    approved: bool,
    session_write_approved: bool,
    write_scope: str,
    cwd: str,
    main_checkout: str,
) -> bool:
    """True when this command may mount the workspace read-write.

    Approval keeps ``--ro-bind`` unless the command is write-shaped.
    ``session_write_approved`` is an explicit coding-session write grant.
    It applies only when this command was approved or is write-shaped.
    An auto-approved read stays read-only. The grant is not inferred.
    """
    session = session_write_approved and bool(write_scope)
    if write_capable:
        if not approved and not session:
            return False
    elif not (approved and session):
        return False
    if not main_checkout:
        return True
    if not write_scope:
        return False
    try:
        cwd_path = Path(cwd).resolve()
        main = Path(main_checkout).resolve()
        scope = Path(write_scope).resolve()
    except OSError:
        return False
    return cwd_path != main and scope != main


def _writable(context: ToolContext, prepared: PreparedCall) -> bool:
    """Read-write for a write-shaped command, or a grant on an approved one."""
    return bind_is_writable(
        write_capable=prepared.write_capable,
        approved=context.shell_approved or context.host_shell_approved,
        session_write_approved=context.session_write_approved,
        write_scope=context.write_scope,
        cwd=context.cwd,
        main_checkout=context.main_checkout,
    )


def _audit_mount(
    context: ToolContext,
    command: str,
    prepared: PreparedCall,
    *,
    mount: str,
    ran: bool,
    decision: str,
) -> None:
    audit = context.audit
    if audit is None or not hasattr(audit, "append"):
        return
    mode = context.dial_mode or "off"
    shown = _redact_command(command)
    if mode == "monitor":
        summary = f"monitor: {shown}"
    elif mode == "enforce":
        summary = f"enforce: {mount} {decision} {shown}"
    else:
        summary = f"{mount} {decision} {shown}"
    audit.append(
        session_id=context.session_id,
        kind="shell_mount",
        summary=summary[:300],
        payload={
            "command": shown,
            "mount": mount,
            "decision": decision,
            "ran": ran,
            "dial_mode": mode,
            "risk": prepared.risk.value,
            "allowlisted": (not prepared.force_approval and prepared.risk == Risk.READ),
            "write_scope": context.write_scope,
            "main_checkout": context.main_checkout,
        },
    )


def _redact_command(command: str) -> str:
    cleaned = _SECRET_VALUE.sub(r"\1[redacted]", command)
    flat = " ".join(cleaned.split())
    return flat[:180]


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
