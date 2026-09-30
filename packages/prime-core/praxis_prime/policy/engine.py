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

from praxis_prime.policy.dials import DIALS, default_positions
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


@dataclass(frozen=True, slots=True)
class Verdict:
    decision: Decision
    reason: str
    hook: str
    grant_key: str = ""


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
    ) -> None:
        self.positions = dict(default_positions())
        if positions:
            for dial_id, position in positions.items():
                if dial_id in self.positions and position in {"off", "monitor", "enforce"}:
                    self.positions[dial_id] = position
        self.hooks: list[DialHook] = list(hooks) if hooks is not None else [
            NoOpDialHook(dial.id) for dial in DIALS
        ]

    def dials_active(self) -> bool:
        return any(position != "off" for position in self.positions.values())

    def evaluate(self, ctx: PolicyContext) -> Verdict:
        verdict = self._spine(ctx)
        if not self.dials_active():
            return verdict
        for hook in self.hooks:
            position = self.positions.get(hook.dial_id, "off")
            if position == "off":
                continue
            proposed = hook.apply(ctx, verdict)
            verdict = tighten(verdict, proposed)
        return verdict

    def _spine(self, ctx: PolicyContext) -> Verdict:
        if ctx.hook == HookPoint.H3_PRE_TOOL:
            return self._pre_tool(ctx)
        if ctx.hook == HookPoint.H5_PRE_SEND and ctx.risk in CONSEQUENTIAL_RISKS:
            return self._ask(ctx, f"baseline spine: {ctx.risk.value} requires approval before send")
        if ctx.hook == HookPoint.H7_RETENTION:
            return Verdict(
                "allow",
                "retention sweeper is not running in this milestone",
                ctx.hook.value,
            )
        return Verdict(
            "allow",
            f"{ctx.hook.value} has nothing to add while dials are off",
            ctx.hook.value,
        )

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

    def _ask(self, ctx: PolicyContext, reason: str) -> Verdict:
        return Verdict("ask", reason, ctx.hook.value, grant_key=grant_key(ctx))


def tighten(current: Verdict, proposed: Verdict | None) -> Verdict:
    """Keep the stricter decision. A hook cannot turn ask or deny into allow."""
    if proposed is None:
        return current
    if _RANK[proposed.decision] > _RANK[current.decision]:
        return Verdict(proposed.decision, proposed.reason, current.hook, current.grant_key)
    return current


def grant_key(ctx: PolicyContext) -> str:
    """Session-grant identity.

    Shell grants are per exact command so allowing one command does not
    allow a later delete. Other tools grant the tool and its risk class.
    """
    sandbox = "bwrap" if ctx.sandboxed else "host"
    base = f"{ctx.tool}:{ctx.risk.value}:{sandbox}"
    exact = {"shell", "run_command", "run_tests", "write_file", "edit_file"}
    if ctx.tool in exact:
        digest = hashlib.sha256(ctx.summary.encode()).hexdigest()[:12]
        return f"{base}:{digest}"
    return base
