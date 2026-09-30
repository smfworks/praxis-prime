"""Provider parsers and local-only HTTP. No calls leave the machine."""

import json
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from praxis_prime.router.anthropic import (
    AnthropicProvider,
    anthropic_messages,
    parse_anthropic_sse_line,
)
from praxis_prime.router.ollama import OllamaProvider, parse_ollama_line
from praxis_prime.router.openai_compat import OpenAICompatibleProvider, parse_openai_sse_line
from praxis_prime.router.types import (
    AssistantFinal,
    ChatMessage,
    ChatRequest,
    ProviderUnreachable,
    StreamAssembler,
    ToolCall,
)


def test_ollama_parser_collects_text_and_tool_calls():
    assembler = StreamAssembler()
    lines = [
        json.dumps({"message": {"role": "assistant", "content": "Hel"}, "done": False}),
        json.dumps(
            {
                "message": {
                    "role": "assistant",
                    "content": "lo",
                    "tool_calls": [
                        {"function": {"name": "read_file", "arguments": {"path": "a.txt"}}}
                    ],
                },
                "done": False,
            }
        ),
        json.dumps({"message": {"role": "assistant", "content": ""}, "done": True}),
    ]
    deltas = []
    for line in lines:
        deltas.extend(parse_ollama_line(line, assembler))
    final = assembler.finish()
    assert "".join(delta.text for delta in deltas) == "Hello"
    assert final.tool_calls[0].name == "read_file"
    assert dict(final.tool_calls[0].arguments) == {"path": "a.txt"}


def test_openai_and_anthropic_parsers():
    assembler = StreamAssembler()
    tool_delta = {
        "choices": [
            {
                "delta": {
                    "tool_calls": [
                        {
                            "index": 0,
                            "id": "c1",
                            "function": {"name": "list_dir", "arguments": '{"path":"."}'},
                        }
                    ]
                }
            }
        ]
    }
    chunks = [
        'data: {"choices":[{"delta":{"content":"Hi"}}]}',
        "data: " + json.dumps(tool_delta),
        "data: [DONE]",
    ]
    for line in chunks:
        parse_openai_sse_line(line, assembler)
    final = assembler.finish()
    assert final.content == "Hi"
    assert final.tool_calls[0].name == "list_dir"
    assert dict(final.tool_calls[0].arguments) == {"path": "."}

    assembler = StreamAssembler()
    state: dict[str, object] = {}
    payload = {
        "type": "content_block_delta",
        "index": 0,
        "delta": {"type": "text_delta", "text": "Yo"},
    }
    block = "event: content_block_delta\ndata: " + json.dumps(payload)
    for line in block.splitlines():
        parse_anthropic_sse_line(line, assembler, state)
    assert assembler.finish().content == "Yo"


def test_anthropic_conversion_keeps_the_system_prompt_separate():
    system, messages = anthropic_messages(
        (
            ChatMessage(role="system", content="stable prompt"),
            ChatMessage(role="user", content="hi"),
            ChatMessage(
                role="assistant",
                content="",
                tool_calls=(ToolCall(id="c1", name="read_file", arguments={"path": "a"}),),
            ),
            ChatMessage(role="tool", content="data", tool_call_id="c1"),
        )
    )
    assert system == "stable prompt"
    assert messages[0]["role"] == "user"
    assert messages[1]["role"] == "assistant"
    assert messages[2]["content"][0]["type"] == "tool_result"


def test_missing_cloud_key_fails_before_the_network():
    anthropic_missing = AnthropicProvider(api_key="")
    try:
        list(anthropic_missing.iter_stream(ChatRequest(model="claude", messages=())))
    except ProviderUnreachable as exc:
        assert "API key is not set" in exc.message
        assert "ANTHROPIC_API_KEY" in exc.message
    else:
        raise AssertionError("expected a missing-key error")

    openai = OpenAICompatibleProvider(
        name="openai",
        base_url="https://api.openai.com/v1",
        api_key="",
        key_hint="OPENAI_API_KEY",
        require_key=True,
    )
    try:
        list(openai.iter_stream(ChatRequest(model="gpt", messages=())))
    except ProviderUnreachable as exc:
        assert "OPENAI_API_KEY" in exc.message
    else:
        raise AssertionError("expected a missing-key error")


def test_ollama_against_a_local_server_and_a_closed_port():
    seen: dict[str, object] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            seen["path"] = self.path
            seen["body"] = json.loads(self.rfile.read(length))
            payload = "\n".join(
                [
                    json.dumps({"message": {"role": "assistant", "content": "Hi"}, "done": False}),
                    json.dumps({"message": {"role": "assistant", "content": ""}, "done": True}),
                ]
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, fmt, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host = f"http://127.0.0.1:{server.server_address[1]}"
        provider = OllamaProvider(host, timeout=5)
        events = list(
            provider.iter_stream(
                ChatRequest(
                    model="qwen",
                    messages=(ChatMessage(role="user", content="hi"),),
                )
            )
        )
    finally:
        server.shutdown()
    assert seen["path"] == "/api/chat"
    assert seen["body"]["model"] == "qwen"
    finals = [event for event in events if isinstance(event, AssistantFinal)]
    assert finals[-1].content == "Hi"

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    dead = OllamaProvider(f"http://127.0.0.1:{port}", timeout=2)
    try:
        list(dead.iter_stream(ChatRequest(model="qwen", messages=())))
    except ProviderUnreachable as exc:
        assert "not reachable" in exc.message
        assert "ollama serve" in exc.message
    else:
        raise AssertionError("expected an unreachable Ollama")
