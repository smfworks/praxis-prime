"""Pending approvals: one decision, session grants, and timeout-to-deny."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from tests.fakes import ScriptedProvider

from praxis_prime.approvals.gate import (
    ApprovalDecision,
    ApprovalGate,
    ApprovalRequest,
    approval_session_id,
)
from praxis_prime.approvals.queue import ApprovalQueue
from praxis_prime.loop.engine import AgentLoop
from praxis_prime.policy.engine import PolicyEngine
from praxis_prime.router.router import ModelRouter
from praxis_prime.router.types import AssistantFinal, ModelRef, ToolCall
from praxis_prime.tools.registry import Risk, Tool, ToolRegistry


def _request(key: str = "delete:secret") -> ApprovalRequest:
    return ApprovalRequest(
        tool="delete_file",
        risk=Risk.DESTRUCTIVE,
        reason="command looks destructive",
        summary="path=secret",
        arguments={"path": "secret", "api_key": "hidden"},
        grant_key=key,
        sandboxed=True,
    )


def _wait_pending(queue: ApprovalQueue) -> dict[str, object]:
    for _ in range(50):
        pending = queue.list_pending()
        if pending:
            return pending[0]
        time.sleep(0.02)
    raise AssertionError("approval was not queued")


def test_queue_approve_is_single_use_and_redacts_secrets():
    queue = ApprovalQueue(ttl=5)
    holder: dict[str, ApprovalDecision] = {}

    def block() -> None:
        holder["decision"] = queue.authorize(_request())

    worker = threading.Thread(target=block)
    worker.start()
    item = _wait_pending(queue)
    arguments = item["arguments"]
    assert isinstance(arguments, dict)
    assert arguments["api_key"] == "[redacted]"
    assert arguments["path"] == "secret"
    decided = queue.decide(str(item["id"]), ApprovalDecision.ALLOW_ONCE, actor="operator")
    assert decided["state"] == "allow_once"
    assert decided["actor"] == "operator"
    worker.join(timeout=2)
    assert holder["decision"] == ApprovalDecision.ALLOW_ONCE
    try:
        queue.decide(str(item["id"]), ApprovalDecision.ALLOW_ONCE, actor="operator")
    except LookupError:
        return
    raise AssertionError("a second decision must fail")


def test_deny_and_unknown_id():
    queue = ApprovalQueue(ttl=5)
    holder: dict[str, ApprovalDecision] = {}

    def block() -> None:
        holder["decision"] = queue.authorize(_request())

    worker = threading.Thread(target=block)
    worker.start()
    item = _wait_pending(queue)
    queue.decide(str(item["id"]), ApprovalDecision.DENY, actor="operator")
    worker.join(timeout=2)
    assert holder["decision"] == ApprovalDecision.DENY
    try:
        queue.decide("nope", ApprovalDecision.DENY, actor="operator")
    except LookupError:
        return
    raise AssertionError("bad ids are rejected")


def test_timeout_denies_and_does_not_run_a_destructive_tool(tmp_path: Path):
    resolved: list[dict[str, object]] = []
    queue = ApprovalQueue(ttl=0.2, on_resolved=resolved.append)
    decision = queue.authorize(_request())
    assert decision == ApprovalDecision.DENY
    assert resolved[-1]["state"] == "expired"
    assert resolved[-1]["actor"] == "timeout"

    ran: list[str] = []
    registry = ToolRegistry()

    def execute(arguments, context):
        del arguments, context
        ran.append("ran")
        return "deleted"

    registry.register(
        Tool(
            name="delete_file",
            description="Delete.",
            parameters={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            risk=Risk.DESTRUCTIVE,
            execute=execute,
        )
    )
    provider = ScriptedProvider(
        [
            AssistantFinal(
                content="",
                tool_calls=(
                    ToolCall(id="c1", name="delete_file", arguments={"path": "secret"}),
                ),
            ),
            AssistantFinal(content="stopped"),
        ]
    )
    loop = AgentLoop(
        router=ModelRouter([ModelRef("ollama", "fake")], {"ollama": provider}),
        registry=registry,
        policy=PolicyEngine(),
        gate=ApprovalGate(queue.authorize),
        cwd=tmp_path,
        max_iterations=4,
        preamble="workspace",
    )
    list(loop.run_turn("delete the secret"))
    assert ran == []
    assert resolved[-1]["actor"] == "timeout"


def test_allow_session_does_not_cross_sessions():
    queue = ApprovalQueue(ttl=5)
    gate = ApprovalGate(queue.authorize)

    def allow_when_pending() -> None:
        item = _wait_pending(queue)
        queue.decide(str(item["id"]), ApprovalDecision.ALLOW_SESSION, actor="operator")

    worker = threading.Thread(target=allow_when_pending)
    worker.start()
    token = approval_session_id.set("session-a")
    try:
        first = gate.authorize(_request())
        second = gate.authorize(_request())
    finally:
        approval_session_id.reset(token)
    worker.join(timeout=2)
    assert first == ApprovalDecision.ALLOW_SESSION
    assert second == ApprovalDecision.ALLOW_SESSION
    assert queue.list_pending() == []

    other: dict[str, ApprovalDecision] = {}

    def block() -> None:
        other_token = approval_session_id.set("session-b")
        try:
            other["decision"] = gate.authorize(_request())
        finally:
            approval_session_id.reset(other_token)

    other_worker = threading.Thread(target=block)
    other_worker.start()
    item = _wait_pending(queue)
    queue.decide(str(item["id"]), ApprovalDecision.DENY, actor="operator")
    other_worker.join(timeout=2)
    assert other["decision"] == ApprovalDecision.DENY
