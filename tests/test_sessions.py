"""SQLite sessions and the audit chain live under the data directory."""

from tests.fakes import ScriptedProvider

from praxis_prime.approvals.gate import ApprovalDecision, ApprovalGate
from praxis_prime.audit.log import AuditLog
from praxis_prime.loop.engine import AgentLoop
from praxis_prime.memory.store import SessionStore
from praxis_prime.policy.engine import PolicyEngine
from praxis_prime.router.router import ModelRouter
from praxis_prime.router.types import AssistantFinal, ModelRef, ToolCall
from praxis_prime.state import StateDB
from praxis_prime.tools.registry import Risk, Tool, ToolRegistry


def test_session_and_audit_round_trip(tmp_path):
    db = StateDB(tmp_path / "prime.db")
    store = SessionStore(db)
    audit = AuditLog(db)
    ran: list[str] = []

    def execute(arguments, context):
        del context
        ran.append("yes")
        return "removed"

    registry = ToolRegistry()
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
                tool_calls=(ToolCall(id="c1", name="delete_file", arguments={"path": "notes"}),),
            ),
            AssistantFinal(content="deleted notes"),
        ]
    )
    session_id = store.create(model="ollama:fake", preamble="preamble")

    def allow(request):
        assert request.tool == "delete_file"
        return ApprovalDecision.ALLOW_ONCE

    loop = AgentLoop(
        router=ModelRouter([ModelRef("ollama", "fake")], {"ollama": provider}),
        registry=registry,
        policy=PolicyEngine(),
        gate=ApprovalGate(allow),
        cwd=tmp_path,
        store=store,
        audit=audit,
        session_id=session_id,
        preamble="preamble",
    )
    list(loop.run_turn("delete notes"))
    assert ran == ["yes"]

    reloaded = SessionStore(StateDB(tmp_path / "prime.db"))
    messages = reloaded.load(session_id)
    roles = [message.role for message in messages]
    assert roles[0] == "user"
    assert "delete notes" in messages[0].content
    assert "preamble" in messages[0].content
    assert any(message.role == "tool" and "removed" in message.content for message in messages)

    log = AuditLog(StateDB(tmp_path / "prime.db"))
    assert log.verify()
    kinds = [event["kind"] for event in log.for_session(session_id)]
    assert "approval" in kinds
    assert "tool_call" in kinds
    assert "policy" in kinds

    db.conn.execute("UPDATE audit_events SET payload_json = '{}' WHERE id = 1")
    db.conn.commit()
    assert AuditLog(db).verify() is False
    db.close()
