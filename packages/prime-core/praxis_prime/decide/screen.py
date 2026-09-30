"""Optional approval pre-screener.

Off unless ``decide.prescreen`` is true. It may auto-deny a clearly unsafe
command, and it may attach an approve/deny recommendation. It never turns
an ask into an allow, and it never auto-approves an always-ask action:
git push, force operations, deletes of tracked files, or writes outside
the task worktree. The baseline spine is unchanged (ARCHITECTURE §7.7).
"""

from __future__ import annotations

import re

from praxis_prime.decide.engine import DecisionEngine
from praxis_prime.policy.engine import PolicyContext, Verdict
from praxis_prime.tools.registry import CONSEQUENTIAL_RISKS

_RANK = {"allow": 0, "ask": 1, "deny": 2}

_PUSH = re.compile(r"(?i)\bgit\s+push\b")
_FORCE = re.compile(
    r"(?i)\bgit\s+(?:"
    r"push\b[^\n]*(?:--force(?:-with-lease)?\b|\s-f\b)"
    r"|reset\s+--hard\b"
    r"|clean\b[^\n]*(?:-f\b|--force\b)"
    r"|checkout\b[^\n]*(?:\s-f\b|--force\b)"
    r"|branch\s+-D\b"
    r")"
)
_UNSAFE = (
    re.compile(r"(?i)\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b"),
    re.compile(r"(?i)\brm\s+-[^\n]*\brf\b[^\n]*\s+/(?:\s|$)"),
    re.compile(r"(?i)\brm\s+-rf\s+/(?:\s|$)"),
    re.compile(r"(?i)\bmkfs(?:\.\w+)?\b"),
    re.compile(r"(?i)\bdd\b[^\n]*\bof=/dev/"),
)


class ActionScreener:
    def __init__(self, engine: DecisionEngine, *, enabled: bool) -> None:
        self.engine = engine
        self.enabled = enabled

    def apply(self, verdict: Verdict, ctx: PolicyContext) -> Verdict:
        if not self.enabled or verdict.decision == "deny":
            return verdict
        if clearly_unsafe(ctx):
            return verdict.derive(
                "deny",
                "decision engine auto-denied a clearly unsafe action",
            )
        decision = verdict.decision
        reason = verdict.reason
        if is_always_ask(ctx) and decision == "allow":
            decision = "ask"
            reason = ctx.force_reason or "always-ask action requires approval"
        if decision == "ask":
            note = self._recommend(ctx)
            if note:
                reason = f"{reason} ({note})"
        if is_always_ask(ctx) and decision == "allow":
            decision = "ask"
        if _RANK[decision] < _RANK[verdict.decision]:
            decision = verdict.decision
            reason = verdict.reason
        return verdict.derive(decision, reason)

    def _recommend(self, ctx: PolicyContext) -> str:
        try:
            response = self.engine.decide(
                {
                    "model": "prime-decide-default",
                    "state": {
                        "tool": ctx.tool,
                        "summary": ctx.summary,
                        "reason": ctx.force_reason,
                    },
                    "questions": {
                        "approve": {
                            "type": "noul",
                            "instructions": "Is it safe to approve this action without a human?",
                            "criteria": {
                                "true": "Clearly safe to run with no human",
                                "false": "Needs a human or should not run",
                            },
                        }
                    },
                    "x_prime": {
                        "purpose": "approval_screen",
                        "max_tier": self.engine.config.max_tier,
                    },
                }
            )
        except Exception:
            return ""
        answer = response.answers.get("approve")
        if answer is None:
            return ""
        word = "approve" if answer.label == "true" else "deny"
        return (
            f"decision engine recommends {word} "
            f"({answer.confidence:.2f}, tier T{answer.tier})"
        )


def is_always_ask(ctx: PolicyContext) -> bool:
    """Push, force, tracked deletes, writes outside the worktree, and the spine.

    Shell commands that are not on the read-only allowlist always ask. The
    decision engine cannot turn that into an allow.
    """
    blob = f"{ctx.summary}\n{ctx.force_reason}"
    if ctx.risk in CONSEQUENTIAL_RISKS:
        return True
    if _PUSH.search(blob) or _FORCE.search(blob):
        return True
    lowered = blob.lower()
    if "tracked file" in lowered:
        return True
    if "outside the task worktree" in lowered or "outside the worktree" in lowered:
        return True
    if ctx.tool in {"shell", "run_command", "run_tests"} and _shell_needs_approval(ctx):
        return True
    return False


def _shell_needs_approval(ctx: PolicyContext) -> bool:
    from praxis_prime.tools.shell import classify_command

    command = ctx.summary
    if ctx.arguments:
        raw = ctx.arguments.get("command")
        if isinstance(raw, str) and raw.strip():
            command = raw
    if not command.strip():
        return True
    prepared = classify_command(command, sandbox_ready=ctx.sandboxed)
    return prepared.force_approval or prepared.risk in CONSEQUENTIAL_RISKS


def clearly_unsafe(ctx: PolicyContext) -> bool:
    blob = f"{ctx.summary}\n{ctx.force_reason}"
    return any(pattern.search(blob) for pattern in _UNSAFE)
