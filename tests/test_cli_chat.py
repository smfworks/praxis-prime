"""Terminal chat and one-shot ask."""

from pathlib import Path

from tests.fakes import ScriptedProvider

from praxis_prime.cli import build_parser, main
from praxis_prime.config import write_default_config
from praxis_prime.repl import run_ask, run_repl, terminal_approver
from praxis_prime.router.types import AssistantFinal, ProviderUnreachable, ToolCall
from praxis_prime.runtime import build_runtime
from praxis_prime.tools.registry import Risk, Tool, ToolRegistry


def _runtime(tmp_path: Path, replies: list[AssistantFinal | Exception]):
    provider = ScriptedProvider(replies)
    runtime = build_runtime(
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=tmp_path / "prime.db",
        cwd=tmp_path,
        providers={"ollama": provider},
    )
    return runtime, provider


def test_help_lists_chat_and_ask():
    text = build_parser().format_help()
    assert "chat" in text
    assert "ask" in text
    assert "doctor" in text


def test_repl_commands_and_streaming_answer(tmp_path: Path):
    runtime, provider = _runtime(tmp_path, [AssistantFinal(content="hello there")])
    lines = iter(["/help", "/model", "say hi", "/clear", "/quit"])

    def read_line(prompt: str) -> str:
        del prompt
        return next(lines)

    chunks: list[str] = []
    try:
        code = run_repl(runtime, read_line=read_line, write=chunks.append, color=False)
    finally:
        runtime.close()
    text = "".join(chunks)
    assert code == 0
    assert "/model <spec>" in text
    assert "ollama:qwen3:32b" in text
    assert "hello there" in text
    assert "plan" in text
    assert "new session" in text
    assert provider.requests


def test_repl_denies_a_destructive_tool_until_yes(tmp_path: Path):
    ran: list[str] = []

    def execute(arguments, context):
        del context
        ran.append(str(arguments.get("path")))
        return "gone"

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
            AssistantFinal(content="stopped"),
            AssistantFinal(
                content="",
                tool_calls=(ToolCall(id="c2", name="delete_file", arguments={"path": "notes"}),),
            ),
            AssistantFinal(content="removed"),
        ]
    )
    runtime = build_runtime(
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=tmp_path / "prime.db",
        cwd=tmp_path,
        providers={"ollama": provider},
        registry=registry,
    )
    lines = iter(["delete notes", "n", "delete notes", "a", "/quit"])

    def read_line(prompt: str) -> str:
        del prompt
        return next(lines)

    chunks: list[str] = []
    runtime.gate.approver = terminal_approver(read_line, chunks.append, color=False)
    try:
        code = run_repl(runtime, read_line=read_line, write=chunks.append)
    finally:
        runtime.close()
    text = "".join(chunks)
    assert code == 0
    assert "approval needed" in text
    assert "always for this session" in text
    assert ran == ["notes"]
    assert "approval denied" in text


def test_ask_prints_the_answer_and_reports_provider_failure(tmp_path: Path, monkeypatch, capsys):
    runtime, _provider = _runtime(tmp_path, [AssistantFinal(content="four")])

    def builder(**kwargs):
        del kwargs
        return runtime

    monkeypatch.setattr("praxis_prime.runtime.build_runtime", builder)
    assert main(["ask", "what", "is", "2+2"]) == 0
    captured = capsys.readouterr()
    assert "four" in captured.out
    assert "plan" in captured.err

    down, _provider = _runtime(tmp_path / "down", [])
    down.router.providers["ollama"] = ScriptedProvider(
        [ProviderUnreachable("ollama", "Ollama is not reachable at http://127.0.0.1:11434")]
    )

    def builder_down(**kwargs):
        del kwargs
        return down

    monkeypatch.setattr("praxis_prime.runtime.build_runtime", builder_down)
    assert main(["ask", "hi"]) == 1
    err = capsys.readouterr().err
    assert "not reachable" in err


def test_ask_runner_and_config_do_not_store_secrets(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-secret")
    write_default_config(tmp_path)
    text = (tmp_path / "config.toml").read_text(encoding="utf-8")
    assert "sk-test-secret" not in text
    runtime, _provider = _runtime(tmp_path, [AssistantFinal(content="ok")])
    try:
        code = run_ask("hi", runtime, write_out=lambda text: None, write_err=lambda text: None)
    finally:
        runtime.close()
    assert code == 0
