"""Router fallback and settings. No network."""

from pathlib import Path

from tests.fakes import ScriptedProvider

from praxis_prime.router.router import ModelRouter
from praxis_prime.router.settings import load_settings
from praxis_prime.router.types import (
    AssistantFinal,
    ChatRequest,
    ModelRef,
    ProviderUnreachable,
    RouterExhausted,
    TextDelta,
)


def _request() -> ChatRequest:
    return ChatRequest(model="unused", messages=())


def test_fallback_when_the_primary_is_unreachable():
    down = ScriptedProvider(
        [ProviderUnreachable("ollama", "connection refused at 127.0.0.1:11434")]
    )
    up = ScriptedProvider(
        [AssistantFinal(content="from fallback")],
        name="openai-compatible",
    )
    router = ModelRouter(
        [ModelRef("ollama", "qwen"), ModelRef("openai-compatible", "local")],
        {"ollama": down, "openai-compatible": up},
    )
    events = list(router.iter_stream(_request()))
    texts = [event.text for event in events if isinstance(event, TextDelta)]
    notices = [event.text for event in events if event.__class__.__name__ == "FallbackNotice"]
    assert texts == ["from fallback"]
    assert notices and "Trying openai-compatible:local" in notices[0]
    assert up.requests[0].model == "local"
    assert len(down.requests) == 1


def test_primary_success_does_not_call_the_fallback():
    primary = ScriptedProvider([AssistantFinal(content="local")])
    secondary = ScriptedProvider([AssistantFinal(content="should not run")], name="openai")

    def boom(request):
        raise AssertionError(request)

    secondary.iter_stream = boom  # type: ignore[method-assign]
    router = ModelRouter(
        [ModelRef("ollama", "qwen"), ModelRef("openai", "gpt")],
        {"ollama": primary, "openai": secondary},
    )
    texts = [event.text for event in router.iter_stream(_request()) if isinstance(event, TextDelta)]
    assert texts == ["local"]


def test_all_providers_down_raises_a_clear_error():
    ollama = ScriptedProvider([ProviderUnreachable("ollama", "Ollama is not reachable at http://127.0.0.1:11434")])
    cloud = ScriptedProvider(
        [ProviderUnreachable("openai", "OpenAI API key is not set. Export OPENAI_API_KEY.")],
        name="openai",
    )
    router = ModelRouter(
        [ModelRef("ollama", "qwen"), ModelRef("openai", "gpt")],
        {"ollama": ollama, "openai": cloud},
    )
    try:
        list(router.iter_stream(_request()))
    except RouterExhausted as exc:
        message = str(exc)
    else:
        raise AssertionError("expected RouterExhausted")
    assert "No configured model provider is reachable" in message
    assert "Ollama is not reachable" in message
    assert "API key is not set" in message
    assert "ollama serve" in message


def test_settings_chain_falls_back_to_ollama_and_hides_keys(tmp_path: Path):
    missing = tmp_path / "missing.toml"
    settings = load_settings(
        {
            "PRAXIS_PRIME_MODEL": "anthropic:claude-sonnet",
            "PRAXIS_PRIME_ANTHROPIC_API_KEY": "sk-test-secret",
            "PRAXIS_PRIME_OPENAI_COMPATIBLE_BASE_URL": "http://127.0.0.1:8080/v1",
        },
        config_path=missing,
    )
    chain = [(ref.provider, ref.model) for ref in settings.chain()]
    assert chain[0] == ("anthropic", "claude-sonnet")
    assert ("ollama", "qwen3:32b") in chain
    assert ("openai-compatible", "local") in chain
    assert "sk-test-secret" not in repr(settings)
    assert settings.anthropic_api_key == "sk-test-secret"


def test_model_spec_aliases_and_rejection():
    from praxis_prime.router.types import parse_model_spec

    assert parse_model_spec("vllm:my-model").provider == "openai-compatible"
    assert parse_model_spec("llamacpp:qwen").provider == "openai-compatible"
    assert parse_model_spec("ollama:qwen3:32b").model == "qwen3:32b"
    try:
        parse_model_spec("mystery:model")
    except ValueError as exc:
        assert "unknown provider" in str(exc)
    else:
        raise AssertionError("expected ValueError")
