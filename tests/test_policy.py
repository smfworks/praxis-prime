"""Approval spine and dial hooks."""

from praxis_prime.policy.dials import default_positions
from praxis_prime.policy.engine import (
    HookPoint,
    PolicyContext,
    PolicyEngine,
    Verdict,
    tighten,
)
from praxis_prime.tools.registry import Risk
from praxis_prime.tools.shell import classify_command


def _destructive(tool: str = "delete_file") -> PolicyContext:
    return PolicyContext(
        hook=HookPoint.H3_PRE_TOOL,
        tool=tool,
        risk=Risk.DESTRUCTIVE,
        mode="ask",
        summary="rm x",
    )


def test_consequential_risks_always_ask():
    engine = PolicyEngine()
    for risk in (Risk.SEND, Risk.SPEND, Risk.SHARE, Risk.DESTRUCTIVE):
        verdict = engine.evaluate(
            PolicyContext(hook=HookPoint.H3_PRE_TOOL, tool="example", risk=risk, summary="x")
        )
        assert verdict.decision == "ask", risk
        assert "baseline spine" in verdict.reason


def test_read_is_allowed_without_approval():
    engine = PolicyEngine()
    verdict = engine.evaluate(
        PolicyContext(hook=HookPoint.H3_PRE_TOOL, tool="read_file", risk=Risk.READ, summary="a")
    )
    assert verdict.decision == "allow"


def test_unsandboxed_shell_asks_even_for_a_read():
    prepared = classify_command("echo hi", sandbox_ready=False)
    assert prepared.sandboxed is False
    assert prepared.force_approval is True
    engine = PolicyEngine()
    verdict = engine.evaluate(
        PolicyContext(
            hook=HookPoint.H3_PRE_TOOL,
            tool="shell",
            risk=prepared.risk,
            sandboxed=False,
            force_approval=True,
            force_reason=prepared.force_reason,
            summary=prepared.summary,
        )
    )
    assert verdict.decision == "ask"
    assert "bubblewrap" in verdict.reason


def test_sandboxed_delete_still_asks():
    prepared = classify_command("rm -rf build", sandbox_ready=True)
    assert prepared.risk == Risk.DESTRUCTIVE
    verdict = PolicyEngine().evaluate(
        PolicyContext(
            hook=HookPoint.H3_PRE_TOOL,
            tool="shell",
            risk=prepared.risk,
            sandboxed=True,
            force_approval=prepared.force_approval,
            force_reason=prepared.force_reason,
            summary=prepared.summary,
        )
    )
    assert verdict.decision == "ask"


def test_sandboxed_echo_is_allowed():
    prepared = classify_command("echo hi", sandbox_ready=True)
    assert prepared.risk == Risk.READ
    assert prepared.force_approval is False
    verdict = PolicyEngine().evaluate(
        PolicyContext(
            hook=HookPoint.H3_PRE_TOOL,
            tool="shell",
            risk=prepared.risk,
            sandboxed=True,
            force_approval=prepared.force_approval,
            summary=prepared.summary,
        )
    )
    assert verdict.decision == "allow"


def test_dials_off_are_not_consulted_and_cannot_weaken_the_spine():
    calls: list[str] = []

    class Weaken:
        dial_id = "hipaa"

        def apply(self, ctx: PolicyContext, current: Verdict) -> Verdict:
            calls.append(ctx.hook.value)
            return Verdict("allow", "dial tried to allow it", ctx.hook.value)

    engine = PolicyEngine(positions=default_positions(), hooks=[Weaken()])
    verdict = engine.evaluate(_destructive())
    assert verdict.decision == "ask"
    assert calls == []

    active = {**default_positions(), "hipaa": "enforce"}
    engine = PolicyEngine(positions=active, hooks=[Weaken()])
    verdict = engine.evaluate(_destructive())
    assert verdict.decision == "ask"
    assert calls == ["H3"]
    assert tighten(verdict, Verdict("allow", "nope", "H3")).decision == "ask"


def test_other_hook_points_are_allow_when_dials_are_off():
    engine = PolicyEngine()
    for hook in (
        HookPoint.H1_INGRESS,
        HookPoint.H2_PRE_MODEL,
        HookPoint.H4_POST_TOOL,
        HookPoint.H6_MEMORY_WRITE,
        HookPoint.H7_RETENTION,
    ):
        verdict = engine.evaluate(PolicyContext(hook=hook))
        assert verdict.decision == "allow"
    send = engine.evaluate(
        PolicyContext(hook=HookPoint.H5_PRE_SEND, tool="send_mail", risk=Risk.SEND)
    )
    assert send.decision == "ask"


def test_plan_mode_denies_shell():
    prepared = classify_command("echo hi", sandbox_ready=True)
    verdict = PolicyEngine().evaluate(
        PolicyContext(
            hook=HookPoint.H3_PRE_TOOL,
            tool="shell",
            risk=prepared.risk,
            sandboxed=True,
            mode="plan",
            summary=prepared.summary,
        )
    )
    assert verdict.decision == "deny"


def test_shell_command_classes():
    assert classify_command("echo hi > out.txt", sandbox_ready=True).risk == Risk.DESTRUCTIVE
    assert classify_command("echo hi >> out.txt", sandbox_ready=True).risk == Risk.READ
    assert classify_command("git push origin main", sandbox_ready=True).risk == Risk.SEND
    protected = classify_command("printf x > AGENTS.md", sandbox_ready=True)
    assert protected.risk == Risk.DESTRUCTIVE
    assert "protected file" in protected.force_reason
