"""Policy engine: baseline spine plus compliance-dial hooks.

The spine is always on. SEND, SPEND, SHARE, and DESTRUCTIVE actions ask for
approval. No dial, mode, or hook can turn that into an allow.

Dial hooks are skipped entirely while every dial is ``off``. A hook that does
run may only tighten a verdict (allow → ask → deny).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, Protocol

from praxis_prime.compliance.packs import PolicyPack, load_packs
from praxis_prime.compliance.providers import ProviderFlags
from praxis_prime.policy.boundary import InodeScanCache, ReadAccess, ReadDenied, assess_read
from praxis_prime.policy.dials import DIALS, default_positions
from praxis_prime.router.types import ModelRef
from praxis_prime.tools.registry import CONSEQUENTIAL_RISKS, Risk

Decision = Literal["allow", "ask", "deny"]
_RANK: dict[Decision, int] = {"allow": 0, "ask": 1, "deny": 2}


class HookPoint(StrEnum):
    """The seven policy hook points from ARCHITECTURE §16.2."""

    H1_INGRESS = "H1"
    H2_PRE_MODEL = "H2"
    H3_PRE_TOOL = "H3"
    H4_POST_TOOL = "H4"
    H5_PRE_SEND = "H5"
    H6_MEMORY_WRITE = "H6"
    H7_RETENTION = "H7"


@dataclass(frozen=True, slots=True)
class PolicyContext:
    """One decision the engine is asked to make."""

    hook: HookPoint
    tool: str = ""
    risk: Risk = Risk.READ
    arguments: Mapping[str, object] | None = None
    sandboxed: bool = True
    force_approval: bool = False
    force_reason: str = ""
    mode: str = "ask"
    summary: str = ""
    text: str = ""
    workspace_root: str = ""
    extra_roots: tuple[str, ...] = ()
    allow_paths: tuple[str, ...] = ()
    fetch_allow: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Verdict:
    decision: Decision
    reason: str
    hook: str
    grant_key: str = ""
    warnings: tuple[str, ...] = ()
    data_classes: tuple[str, ...] = ()
    redacted_text: str = ""
    route_groups: tuple[tuple[str, ...], ...] = ()
    redact: bool = False

    def derive(self, decision: Decision | None = None, reason: str | None = None) -> Verdict:
        """Copy this verdict, optionally replacing the decision or reason."""
        return Verdict(
            self.decision if decision is None else decision,
            self.reason if reason is None else reason,
            self.hook,
            self.grant_key,
            self.warnings,
            self.data_classes,
            self.redacted_text,
            self.route_groups,
            self.redact,
        )


class DialHook(Protocol):
    """A compliance dial. ``apply`` may tighten ``current`` and must not weaken it."""

    dial_id: str

    def apply(self, ctx: PolicyContext, current: Verdict) -> Verdict | None:
        """Return a tighter verdict, or None to leave ``current`` alone."""


class NoOpDialHook:
    """Placeholder hook. Active dials call it; it adds no regulatory rules yet."""

    def __init__(self, dial_id: str) -> None:
        self.dial_id = dial_id

    def apply(self, ctx: PolicyContext, current: Verdict) -> Verdict | None:
        del ctx
        return current


class PolicyEngine:
    """Spine first, then dials that are not off."""

    def __init__(
        self,
        positions: Mapping[str, str] | None = None,
        hooks: list[DialHook] | None = None,
        *,
        packs: tuple[PolicyPack, ...] | None = None,
        audit: object | None = None,
        provider_flags: Mapping[str, ProviderFlags] | None = None,
        config_dir: object | None = None,
        project_root: object | None = None,
        read_access: ReadAccess | None = None,
        workspace_root: str = "",
    ) -> None:
        self.positions = dict(default_positions())
        if positions:
            for dial_id, position in positions.items():
                if dial_id in self.positions and position in {"off", "monitor", "enforce"}:
                    self.positions[dial_id] = position
        self.hooks: list[DialHook] = list(hooks) if hooks is not None else [
            NoOpDialHook(dial.id) for dial in DIALS
        ]
        if packs is None:
            from pathlib import Path

            config_path = Path(config_dir) if config_dir is not None else None
            project_path = Path(project_root) if project_root is not None else None
            self.packs = load_packs(config_dir=config_path, project_root=project_path)
        else:
            self.packs = packs
        self.audit = audit
        self.provider_flags = dict(provider_flags or {})
        self.session_id: str | None = None
        self.read_access = read_access or ReadAccess()
        self.workspace_root = workspace_root
        self.inode_cache: InodeScanCache | None = None

    def dials_active(self) -> bool:
        return any(position != "off" for position in self.positions.values())

    def enforce_active(self) -> bool:
        return any(position == "enforce" for position in self.positions.values())

    def set_dial(self, dial_id: str, position: str, *, owner: bool) -> None:
        """Change one dial. Hooks, skills, MCP servers, and the Decision Engine cannot."""
        if not owner:
            raise PermissionError(
                "A hook, skill, MCP server, or Decision Engine cannot change a compliance dial. "
                "Only the owner config can."
            )
        if dial_id not in self.positions or position not in {"off", "monitor", "enforce"}:
            raise ValueError(f"unknown dial or position: {dial_id}={position}")
        previous = self.positions[dial_id]
        if previous == position:
            return
        self.positions[dial_id] = position
        if self.audit is not None:
            self.audit.append(
                session_id=self.session_id,
                kind="dial_change",
                summary=f"{dial_id} {previous} -> {position}",
                payload={
                    "actor": "owner",
                    "dial": dial_id,
                    "from": previous,
                    "to": position,
                },
            )

    def constrain_chain(
        self, chain: list[ModelRef], verdict: Verdict
    ) -> tuple[list[ModelRef], str]:
        """Return the providers enforce mode still allows, plus a block message."""
        from praxis_prime.compliance.evaluate import constrain_chain

        result = constrain_chain(self, chain, verdict)
        return list(result.chain), result.message

    def evaluate(self, ctx: PolicyContext) -> Verdict:
        verdict = self._spine(ctx)
        if not self.dials_active():
            return verdict
        from praxis_prime.compliance.evaluate import apply_compliance

        verdict = apply_compliance(self, ctx, verdict)
        for hook in self.hooks:
            position = self.positions.get(hook.dial_id, "off")
            if position == "off":
                continue
            proposed = hook.apply(ctx, verdict)
            verdict = tighten(verdict, proposed)
        return self._deny_blocked_read(ctx, verdict)

    def _spine(self, ctx: PolicyContext) -> Verdict:
        if ctx.hook == HookPoint.H3_PRE_TOOL:
            return self._pre_tool(ctx)
        if ctx.hook == HookPoint.H5_PRE_SEND and ctx.risk in CONSEQUENTIAL_RISKS:
            return self._ask(ctx, f"baseline spine: {ctx.risk.value} requires approval before send")
        if ctx.hook == HookPoint.H7_RETENTION:
            if not self.dials_active():
                return Verdict(
                    "allow",
                    "retention sweeper is not running in this milestone",
                    ctx.hook.value,
                )
            return Verdict("allow", "retention sweep is allowed", ctx.hook.value)
        if not self.dials_active():
            return Verdict(
                "allow",
                f"{ctx.hook.value} has nothing to add while dials are off",
                ctx.hook.value,
            )
        return Verdict("allow", f"{ctx.hook.value} baseline allows this", ctx.hook.value)

    def _pre_tool(self, ctx: PolicyContext) -> Verdict:
        if ctx.mode == "plan" and ctx.tool in {"shell", "run_command", "run_tests"}:
            return Verdict("deny", "plan mode does not run commands", ctx.hook.value)
        if ctx.mode == "plan" and ctx.risk != Risk.READ:
            return Verdict("deny", "plan mode is read-only", ctx.hook.value)
        if ctx.risk in CONSEQUENTIAL_RISKS:
            return self._ask(ctx, f"baseline spine: {ctx.risk.value} requires approval")
        if ctx.force_approval:
            reason = ctx.force_reason or "this action requires approval"
            return self._ask(ctx, reason)
        return Verdict(
            "allow",
            "read-only action is allowed",
            ctx.hook.value,
            grant_key=grant_key(ctx),
        )

    def _deny_blocked_read(self, ctx: PolicyContext, verdict: Verdict) -> Verdict:
        """Enforce mode denies a blocked read and records it. Other modes do not.

        The tool still refuses the read when every dial is off. Enforce mode
        fails closed before the tool runs, including when the check errors.
        """
        if not self.enforce_active() or ctx.hook != HookPoint.H3_PRE_TOOL:
            return verdict
        denial = self._read_denial(ctx)
        if denial is None:
            return verdict
        self._audit_read_denied(ctx, denial)
        denied = Verdict(
            "deny",
            str(denial),
            ctx.hook.value,
            grant_key=verdict.grant_key or grant_key(ctx),
        )
        return tighten(verdict, denied)

    def _read_denial(self, ctx: PolicyContext) -> ReadDenied | None:
        root, access = self._access_for(ctx)
        try:
            return assess_read(
                ctx.tool,
                ctx.arguments,
                workspace_root=root,
                access=access,
                cache=self.inode_cache,
            )
        except Exception:
            return ReadDenied("read boundary check failed closed", "check_failed")

    def _access_for(self, ctx: PolicyContext) -> tuple[str, ReadAccess]:
        fetch_allow = frozenset(ctx.fetch_allow) or self.read_access.fetch_allow
        access = ReadAccess(
            extra_roots=ctx.extra_roots or self.read_access.extra_roots,
            allow_paths=ctx.allow_paths or self.read_access.allow_paths,
            fetch_allow=fetch_allow,
        )
        return ctx.workspace_root or self.workspace_root, access

    def _audit_read_denied(self, ctx: PolicyContext, denial: ReadDenied) -> None:
        if self.audit is None:
            return
        try:
            self.audit.append(
                session_id=self.session_id,
                kind="read_denied",
                summary=f"read denied ({denial.code})",
                payload={
                    "hook": ctx.hook.value,
                    "tool": ctx.tool,
                    "decision": "deny",
                    "code": denial.code,
                    "name": denial.display_name,
                },
            )
        except Exception:
            return

    def _ask(self, ctx: PolicyContext, reason: str) -> Verdict:
        return Verdict("ask", reason, ctx.hook.value, grant_key=grant_key(ctx))


def tighten(current: Verdict, proposed: Verdict | None) -> Verdict:
    """Keep the stricter decision. A hook cannot turn ask or deny into allow."""
    if proposed is None:
        return current
    decision = current.decision
    reason = current.reason
    if _RANK[proposed.decision] > _RANK[current.decision]:
        decision = proposed.decision
        reason = proposed.reason
    return Verdict(
        decision,
        reason,
        current.hook,
        current.grant_key,
        tuple(dict.fromkeys((*current.warnings, *proposed.warnings))),
        tuple(dict.fromkeys((*current.data_classes, *proposed.data_classes))),
        proposed.redacted_text or current.redacted_text,
        tuple(dict.fromkeys((*current.route_groups, *proposed.route_groups))),
        current.redact or proposed.redact,
    )


def grant_key(ctx: PolicyContext) -> str:
    """Session-grant identity.

    Shell grants are per exact command so allowing one command does not
    allow a later delete. Other tools grant the tool and its risk class.
    """
    sandbox = "bwrap" if ctx.sandboxed else "host"
    base = f"{ctx.tool}:{ctx.risk.value}:{sandbox}"
    exact = {"shell", "run_command", "run_tests", "write_file", "edit_file", "browser"}
    if ctx.tool in exact or ctx.tool.startswith("mcp__"):
        digest = hashlib.sha256(ctx.summary.encode()).hexdigest()[:12]
        return f"{base}:{digest}"
    return base
