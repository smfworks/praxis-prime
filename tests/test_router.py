"""Router fallback and settings. No network."""

import json
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
    assert "The configured model provider is not reachable" in message
    assert "Ollama is not reachable" in message
    assert "API key is not set" in message
    assert "praxis-prime setup" in message
    assert "ollama serve" not in message


def test_settings_chain_does_not_guess_a_provider(tmp_path: Path):
    missing = tmp_path / "missing.toml"
    settings = load_settings(
        {
            "OPENAI_API_KEY": "sk-env-secret",
            "OLLAMA_HOST": "http://127.0.0.1:11434",
            "PRAXIS_PRIME_OPENAI_COMPATIBLE_BASE_URL": "http://127.0.0.1:8080/v1",
        },
        config_path=missing,
    )
    assert settings.model_spec == ""
    assert settings.chain() == []
    assert settings.openai_api_key == "sk-env-secret"
    assert "sk-env-secret" not in repr(settings)

    chosen = load_settings(
        {
            "PRAXIS_PRIME_MODEL": "anthropic:claude-sonnet",
            "PRAXIS_PRIME_ANTHROPIC_API_KEY": "sk-test-secret",
            "PRAXIS_PRIME_FALLBACK_MODELS": "ollama:qwen3:8b",
            "PRAXIS_PRIME_OPENAI_COMPATIBLE_BASE_URL": "http://127.0.0.1:8080/v1",
        },
        config_path=missing,
    )
    chain = [(ref.provider, ref.model) for ref in chosen.chain()]
    assert chain == [("anthropic", "claude-sonnet")]
    assert "sk-test-secret" not in repr(chosen)


def test_alias_records_verify_the_canonical_spec(tmp_path: Path):
    config = tmp_path / "config.toml"
    config.write_text(
        "\n".join(
            [
                "[models]",
                'primary = "llamacpp:local-model"',
                'fallback = ["vllm:other-model", "ollama:not-verified"]',
                "",
            ]
        ),
        encoding="utf-8",
    )
    ready = {
        "ready": True,
        "spec": "llamacpp:local-model",
        "fallbacks": ["lmstudio:side"],
        "roles": {"utility": {"spec": "vllm:other-model", "passed": True}},
    }
    (tmp_path / "provider-ready.json").write_text(
        json.dumps(ready),
        encoding="utf-8",
    )
    settings = load_settings({}, config_path=config)
    assert settings.model_spec == "llamacpp:local-model"
    assert settings.verified_specs == (
        "openai-compatible:local-model",
        "openai-compatible:side",
        "openai-compatible:other-model",
    )
    assert settings.provider_ready() is True
    assert [(ref.provider, ref.model) for ref in settings.chain()] == [
        ("openai-compatible", "local-model"),
        ("openai-compatible", "other-model"),
    ]


def test_model_spec_aliases_and_rejection():
    from praxis_prime.router.types import parse_model_spec

    assert parse_model_spec("vllm:my-model").provider == "openai-compatible"
    assert parse_model_spec("llamacpp:qwen").provider == "openai-compatible"
    assert parse_model_spec("lmstudio:local").provider == "openai-compatible"
    assert parse_model_spec("ollama:qwen3:32b").model == "qwen3:32b"
    try:
        parse_model_spec("mystery:model")
    except ValueError as exc:
        assert "unknown provider" in str(exc)
    else:
        raise AssertionError("expected ValueError")
