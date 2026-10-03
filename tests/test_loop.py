"""Agent loop with a scripted provider. No network."""

from pathlib import Path

from tests.fakes import ScriptedProvider

from praxis_prime.approvals.gate import ApprovalDecision, ApprovalGate
from praxis_prime.loop.control import TurnControl
from praxis_prime.loop.engine import AgentLoop
from praxis_prime.loop.events import StatusEvent, ToolSpan, TurnEnded
from praxis_prime.loop.prompt import SYSTEM_PROMPT
from praxis_prime.policy.engine import PolicyEngine
from praxis_prime.router.router import ModelRouter
from praxis_prime.router.types import AssistantFinal, ModelRef, ProviderUnreachable, ToolCall
from praxis_prime.tools.builtin import builtin_registry
from praxis_prime.tools.registry import Risk, Tool, ToolRegistry


def _router(provider: ScriptedProvider, *, second: ScriptedProvider | None = None) -> ModelRouter:
    providers = {"ollama": provider}
    chain = [ModelRef("ollama", "fake")]
    if second is not None:
        providers["openai"] = second
        chain.append(ModelRef("openai", "fake-2"))
    return ModelRouter(chain, providers)


def _loop(
    provider: ScriptedProvider,
    tmp_path: Path,
    *,
    registry: ToolRegistry | None = None,
    gate: ApprovalGate | None = None,
    max_iterations: int = 8,
) -> AgentLoop:
    return AgentLoop(
        router=_router(provider),
        registry=registry or builtin_registry(),
        policy=PolicyEngine(),
        gate=gate or ApprovalGate(None),
        cwd=tmp_path,
        max_iterations=max_iterations,
        preamble="workspace context",
    )


def _tool_reply(name: str, arguments: dict[str, object], *, content: str = "") -> AssistantFinal:
    return AssistantFinal(
        content=content,
        tool_calls=(ToolCall(id="c1", name=name, arguments=arguments),),
    )


def test_streamed_tool_args_use_the_audit_redaction(tmp_path: Path):
    secret = "sk-live-secret-value"
    provider = ScriptedProvider(
        [
            _tool_reply(
                "echo",
                {
                    "api_key": secret,
                    "url": "https://example.test/hook?token=abc123",
                    "text": "hello",
                },
            ),
            AssistantFinal(content="done"),
        ]
    )

    def execute(arguments, context):
        del arguments, context
        return "echoed"

    registry = ToolRegistry()
    registry.register(
        Tool(
            name="echo",
            description="Echo.",
            parameters={"type": "object", "properties": {"text": {"type": "string"}}},
            risk=Risk.READ,
            execute=execute,
        )
    )
    events = list(_loop(provider, tmp_path, registry=registry).run_turn("go"))
    args = [event for event in events if isinstance(event, ToolSpan) and event.phase == "args"]
    assert len(args) == 1
    assert secret not in args[0].detail
    assert "abc123" not in args[0].detail
    assert "[redacted]" in args[0].detail
    assert "hello" in args[0].detail


def test_system_prompt_stays_byte_stable_across_the_turn(tmp_path: Path):
    note = tmp_path / "note.txt"
    note.write_text("hello from disk\n", encoding="utf-8")
    provider = ScriptedProvider(
        [
            _tool_reply("read_file", {"path": str(note)}),
            AssistantFinal(content="The note says hello."),
        ]
    )
    loop = _loop(provider, tmp_path)
    before = loop.system_prompt
    events = list(loop.run_turn("read the note"))
    assert loop.system_prompt == before == SYSTEM_PROMPT
    assert provider.requests[0].messages[0].content == provider.requests[1].messages[0].content
    assert provider.requests[0].messages[0].content.encode() == SYSTEM_PROMPT.encode()
    assert str(tmp_path) not in loop.system_prompt
    assert any(isinstance(event, TurnEnded) and "hello" in event.text for event in events)
    tool_message = provider.requests[1].messages[-1]
    assert tool_message.role == "tool"
    assert tool_message.content.startswith("<<<UNTRUSTED")
    assert "hello from disk" in tool_message.content
    assert "Ignore previous instructions" in provider.requests[1].messages[0].content
    phases = [event.phase for event in events if isinstance(event, StatusEvent)]
    assert "plan" in phases
    assert "check" in phases
    assert "act" in phases


def test_destructive_tool_never_runs_without_approval(tmp_path: Path):
    ran: list[str] = []

    def execute(arguments, context):
        del arguments, context
        ran.append("ran")
        return "deleted"

    registry = ToolRegistry()
    registry.register(
        Tool(
            name="delete_file",
            description="Delete a file.",
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
            _tool_reply("delete_file", {"path": "secret"}),
            AssistantFinal(content="I did not delete it."),
        ]
    )
    loop = _loop(provider, tmp_path, registry=registry, gate=ApprovalGate(None))
    events = list(loop.run_turn("delete the secret"))
    assert ran == []
    assert any("denied" in event.detail for event in events if isinstance(event, StatusEvent))
    denial = provider.requests[1].messages[-1].content
    assert "was not run" in denial
    assert "<<<UNTRUSTED" not in denial


def test_destructive_tool_runs_only_after_yes(tmp_path: Path):
    ran: list[str] = []

    def execute(arguments, context):
        del context
        ran.append(str(arguments["path"]))
        return "deleted"

    registry = ToolRegistry()
    registry.register(
        Tool(
            name="delete_file",
            description="Delete a file.",
            parameters={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            risk=Risk.DESTRUCTIVE,
            execute=execute,
        )
    )

    def deny(request):
        del request
        return ApprovalDecision.DENY

    provider = ScriptedProvider(
        [
            _tool_reply("delete_file", {"path": "secret"}),
            AssistantFinal(content="stopped"),
        ]
    )
    loop = _loop(provider, tmp_path, registry=registry, gate=ApprovalGate(deny))
    list(loop.run_turn("delete the secret"))
    assert ran == []

    def allow(request):
        del request
        return ApprovalDecision.ALLOW_ONCE

    provider = ScriptedProvider(
        [
            _tool_reply("delete_file", {"path": "secret"}),
            AssistantFinal(content="done"),
        ]
    )
    loop = _loop(provider, tmp_path, registry=registry, gate=ApprovalGate(allow))
    list(loop.run_turn("delete the secret"))
    assert ran == ["secret"]
    fenced = provider.requests[1].messages[-1].content
    assert fenced.startswith("<<<UNTRUSTED")
    assert "deleted" in fenced


def test_cancel_skips_the_model_and_a_later_cancel_skips_tools(tmp_path: Path):
    ran: list[str] = []

    def execute(arguments, context):
        del arguments, context
        ran.append("ran")
        return "nope"

    registry = ToolRegistry()
    registry.register(
        Tool(
            name="delete_file",
            description="Delete.",
            parameters={"type": "object", "properties": {}, "required": []},
            risk=Risk.DESTRUCTIVE,
            execute=execute,
        )
    )
    provider = ScriptedProvider([AssistantFinal(content="should not be asked")])
    control = TurnControl()
    control.cancel()
    events = list(_loop(provider, tmp_path, registry=registry).run_turn("go", control))
    assert provider.requests == []
    assert events[-1].cancelled is True

    control = TurnControl()

    class CancelOnCall(ScriptedProvider):
        def iter_stream(self, request):
            self.requests.append(request)
            control.cancel()
            yield _tool_reply("delete_file", {"path": "x"})

    cancelling = CancelOnCall([])
    events = list(_loop(cancelling, tmp_path, registry=registry).run_turn("go", control))
    assert ran == []
    assert any(isinstance(event, TurnEnded) and event.cancelled for event in events)


def test_steer_is_injected_before_the_next_model_call(tmp_path: Path):
    control = TurnControl()

    def execute(arguments, context):
        del arguments, context
        control.steer("answer in one word")
        return "data"

    registry = ToolRegistry()
    registry.register(
        Tool(
            name="read_file",
            description="Read.",
            parameters={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            risk=Risk.READ,
            execute=execute,
        )
    )
    provider = ScriptedProvider(
        [
            _tool_reply("read_file", {"path": "a"}),
            AssistantFinal(content="word"),
        ]
    )
    list(_loop(provider, tmp_path, registry=registry).run_turn("look", control))
    second = provider.requests[1]
    steered = [
        message
        for message in second.messages
        if message.role == "user" and "answer in one word" in message.content
    ]
    assert steered
    assert second.messages[0].content == SYSTEM_PROMPT


def test_provider_failure_ends_the_turn(tmp_path: Path):
    provider = ScriptedProvider([ProviderUnreachable("ollama", "connection refused")])
    events = list(_loop(provider, tmp_path).run_turn("hi"))
    ended = [event for event in events if isinstance(event, TurnEnded)]
    assert ended[-1].error
    assert "not reachable" in ended[-1].error or "connection refused" in ended[-1].error


def test_max_iterations_stops_a_tool_loop(tmp_path: Path):
    calls: list[int] = []

    def execute(arguments, context):
        del arguments, context
        calls.append(1)
        return "ok"

    registry = ToolRegistry()
    registry.register(
        Tool(
            name="list_dir",
            description="List.",
            parameters={"type": "object", "properties": {}, "required": []},
            risk=Risk.READ,
            execute=execute,
        )
    )
    provider = ScriptedProvider([_tool_reply("list_dir", {}), _tool_reply("list_dir", {})])
    events = list(_loop(provider, tmp_path, registry=registry, max_iterations=2).run_turn("list"))
    assert len(calls) == 2
    assert any(isinstance(event, TurnEnded) and event.error == "max_iterations" for event in events)
