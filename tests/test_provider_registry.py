"""Provider catalog: unique ids, known adapters, and unchanged legacy aliases."""

from __future__ import annotations

from praxis_prime.onboarding.detect import KEY_ENV_NAMES, LOCAL_SERVERS
from praxis_prime.onboarding.registry import (
    CLOUD_BASES,
    CLOUD_PROVIDERS,
    KEY_NAMES,
    LOCAL_PROVIDERS,
    PROVIDERS,
    REQUIRED_KEY,
    lane_for,
    resolve_alias,
)
from praxis_prime.router.factory import default_providers
from praxis_prime.router.settings import load_settings
from praxis_prime.router.types import parse_model_spec

_OLD_CLOUD = ("openai", "anthropic", "xai", "openai-compatible")
_OLD_LOCAL = ("ollama", "llamacpp", "vllm", "lmstudio", "openai-compatible")
_OLD_KEYS = {
    "openai": "PRAXIS_PRIME_OPENAI_API_KEY",
    "anthropic": "PRAXIS_PRIME_ANTHROPIC_API_KEY",
    "xai": "PRAXIS_PRIME_XAI_API_KEY",
    "openai-compatible": "PRAXIS_PRIME_OPENAI_COMPATIBLE_API_KEY",
    "llamacpp": "PRAXIS_PRIME_OPENAI_COMPATIBLE_API_KEY",
    "vllm": "PRAXIS_PRIME_OPENAI_COMPATIBLE_API_KEY",
    "lmstudio": "PRAXIS_PRIME_OPENAI_COMPATIBLE_API_KEY",
    "ollama": "PRAXIS_PRIME_OLLAMA_API_KEY",
}
_OLD_BASES = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com",
    "xai": "https://api.x.ai/v1",
}
_OLD_REQUIRED = {"openai", "anthropic", "xai"}
_OLD_SERVERS = (
    ("ollama", "http://127.0.0.1:11434", "/api/tags", ""),
    ("llamacpp", "http://127.0.0.1:8080", "/v1/models", "/props"),
    ("vllm", "http://127.0.0.1:8000", "/v1/models", ""),
    ("lmstudio", "http://127.0.0.1:1234", "/v1/models", ""),
)
_OLD_ENV = (
    "OPENAI_API_KEY",
    "PRAXIS_PRIME_OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "PRAXIS_PRIME_ANTHROPIC_API_KEY",
    "XAI_API_KEY",
    "PRAXIS_PRIME_XAI_API_KEY",
    "PRAXIS_PRIME_OPENAI_COMPATIBLE_API_KEY",
    "PRAXIS_PRIME_OLLAMA_API_KEY",
)


def test_ids_are_unique_and_adapters_parse():
    ids = [entry.id for entry in PROVIDERS]
    assert len(ids) == len(set(ids))
    known = set(default_providers(load_settings({})))
    for entry in PROVIDERS:
        parsed = parse_model_spec(f"{entry.adapter}:demo")
        assert parsed.provider == entry.adapter
        assert entry.adapter in known
        for method in entry.auth_methods:
            assert method.oauth is None


def test_aliases_resolve_and_network_stays_a_local_entry():
    grok = resolve_alias("grok")
    xai = resolve_alias("x.ai")
    llama = resolve_alias("llama.cpp")
    glm = resolve_alias("glm")
    sglang = resolve_alias("sglang")
    assert grok is not None and grok.id == "xai"
    assert xai is not None and xai.id == "xai"
    assert llama is not None and llama.id == "llamacpp"
    assert glm is not None and glm.id == "network"
    assert sglang is not None and sglang.id == "network"
    network = resolve_alias("Network server (OpenAI-compatible)")
    assert network is not None
    assert network.adapter == "openai-compatible"
    assert network.section == "local"
    assert network.detect is None
    other = resolve_alias("Other OpenAI-compatible server")
    assert other is not None and other.id == "openai-compatible"


def test_derived_aliases_match_the_pre_picker_constants():
    assert CLOUD_PROVIDERS == _OLD_CLOUD
    assert LOCAL_PROVIDERS == _OLD_LOCAL
    assert KEY_NAMES == _OLD_KEYS
    assert "network" not in KEY_NAMES
    assert "openai-compatible-cloud" not in KEY_NAMES
    assert CLOUD_BASES == _OLD_BASES
    assert REQUIRED_KEY == _OLD_REQUIRED
    assert LOCAL_SERVERS == _OLD_SERVERS
    assert KEY_ENV_NAMES == _OLD_ENV


def test_lane_for_matches_the_old_helper():
    assert lane_for("openai", "") == "cloud"
    assert lane_for("xai", "https://api.x.ai/v1") == "cloud"
    assert lane_for("llamacpp", "http://127.0.0.1:8080") == "local"
    assert lane_for("llamacpp", "") == "local"
    assert lane_for("vllm", "http://192.168.1.50:8000") == "lan"
    assert lane_for("openai-compatible-cloud", "https://example.com/v1") == "cloud"
    assert lane_for("network", "192.168.1.50:8000") == "lan"
    assert lane_for("network", "http://127.0.0.1:9") == "local"
    assert lane_for("network", "http://[fd00::5]:8000") == "lan"
