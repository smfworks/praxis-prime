"""Shell and worktree-bind decisions on the compliance dial.

The allowlist and the read-only bind are baseline controls. They stay on
when every dial is ``off``. Dial position does not loosen them:

- ``off``: non-allowlisted commands ask; the bind stays read-only until a
  write is approved. The decision is still written to the audit log.
- ``monitor``: the same decision, and the command text is logged.
- ``enforce``: a prepared call that says "allow" cannot bypass classification.
  The engine re-reads the command and asks when it is not allowlisted.

ARCHITECTURE §16 and §17. This is a technical control, not a regulatory pack.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path

from praxis_prime.policy.engine import PolicyContext, PolicyEngine, Verdict
from praxis_prime.tools.shell import classify_command

_SHELL_TOOLS = frozenset({"shell", "run_command", "run_tests"})
_SECRET_VALUE = re.compile(
    r"(?i)((?:api[_-]?key|token|secret|password|authorization)\s*[=:]\s*)\S+"
)


def compliance_mode(positions: Mapping[str, str]) -> str:
    """Strictest active dial. ``enforce`` beats ``monitor`` beats ``off``."""
    values = set(positions.values())
    if "enforce" in values:
        return "enforce"
    if "monitor" in values:
        return "monitor"
    return "off"


def apply_shell_guard(engine: PolicyEngine, ctx: PolicyContext, verdict: Verdict) -> Verdict:
    """Tighten a shell verdict that skipped the allowlist, then audit it."""
    if ctx.hook.value != "H3" or ctx.tool not in _SHELL_TOOLS:
        return verdict
    command, complete = _command_text(ctx)
    workspace = Path(ctx.workspace_root) if ctx.workspace_root else None
    prepared = classify_command(
        command,
        sandbox_ready=ctx.sandboxed,
        workspace=workspace,
    )
    mode = compliance_mode(engine.positions)
    decision = verdict.decision
    reason = verdict.reason
    bypass_blocked = False
    needs_approval = (not complete) or prepared.force_approval or prepared.risk.value != "READ"
    if needs_approval and decision == "allow":
        decision = "ask"
        reason = prepared.force_reason or "shell command is not on the read-only allowlist"
        if not complete:
            reason = "truncated shell command requires approval"
        bypass_blocked = True
        if mode == "enforce":
            reason = f"compliance enforce: no bypass. {reason}"
    updated = Verdict(
        decision,
        reason,
        verdict.hook,
        verdict.grant_key,
        verdict.warnings,
        verdict.data_classes,
        verdict.redacted_text,
        verdict.route_groups,
        verdict.redact,
    )
    _audit(
        engine,
        ctx,
        updated,
        prepared_allowlisted=not needs_approval,
        mode=mode,
        command=command,
        bypass_blocked=bypass_blocked,
    )
    return updated


def _command_text(ctx: PolicyContext) -> tuple[str, bool]:
    if ctx.arguments:
        raw = ctx.arguments.get("command")
        if isinstance(raw, str):
            return raw, True
    if len(ctx.summary) >= 180:
        return ctx.summary, False
    return ctx.summary, True


def _audit(
    engine: PolicyEngine,
    ctx: PolicyContext,
    verdict: Verdict,
    *,
    prepared_allowlisted: bool,
    mode: str,
    command: str,
    bypass_blocked: bool,
) -> None:
    audit = engine.audit
    if audit is None or not hasattr(audit, "append"):
        return
    shown = _redact(command)
    if mode == "monitor":
        summary = f"monitor: {shown}"
    elif mode == "enforce":
        summary = f"enforce: {verdict.decision} {shown}"
    else:
        summary = f"{verdict.decision} {shown}"
    audit.append(
        session_id=engine.session_id,
        kind="shell_policy",
        summary=summary[:300],
        payload={
            "hook": ctx.hook.value,
            "tool": ctx.tool,
            "decision": verdict.decision,
            "dial_mode": mode,
            "allowlisted": prepared_allowlisted,
            "command": shown,
            "mount": "ro",
            "bypass_blocked": bypass_blocked,
            "risk": ctx.risk.value,
        },
    )


def _redact(command: str) -> str:
    cleaned = _SECRET_VALUE.sub(r"\1[redacted]", command)
    return " ".join(cleaned.split())[:180]
