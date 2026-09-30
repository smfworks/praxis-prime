"""Model settings from the XDG config file and the environment.

API keys are read from the environment only. They are not written to
``config.toml`` and they do not appear in ``Settings``'s repr.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from praxis_prime.compliance.providers import ProviderFlags, flags_from_config
from praxis_prime.paths import config_dir
from praxis_prime.policy.dials import default_positions
from praxis_prime.router.http import normalize_base
from praxis_prime.router.types import ModelRef, parse_model_spec

_MODES = {"plan", "ask", "auto", "full"}
_DEFAULT_MODEL = "ollama:qwen3:32b"


@dataclass(frozen=True, slots=True)
class Settings:
    model_spec: str
    fallback_specs: tuple[str, ...]
    ollama_host: str
    openai_compatible_base_url: str
    openai_compatible_model: str
    openai_base_url: str
    anthropic_base_url: str
    xai_base_url: str
    openai_api_key: str
    anthropic_api_key: str
    xai_api_key: str
    openai_compatible_api_key: str
    max_iterations: int
    mode: str
    dials: dict[str, str]
    timezone: str = "America/New_York"
    embed_spec: str = "local:bge-small"
    memory_redact: str = "secrets"
    memory_profile_cap: int = 20
    memory_profile_chars: int = 4000
    memory_half_life_days: float = 14.0
    memory_episodic_ttl_days: int = 90
    provider_flags: dict[str, ProviderFlags] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            "Settings("
            f"model_spec={self.model_spec!r}, "
            f"fallback_specs={self.fallback_specs!r}, "
            f"ollama_host={self.ollama_host!r}, "
            f"mode={self.mode!r}, "
            "keys=hidden)"
        )

    def chain(self) -> list[ModelRef]:
        """Primary, then explicit fallbacks, then a local fallback when it helps."""
        refs: list[ModelRef] = []

        def add(spec: str) -> None:
            ref = parse_model_spec(spec)
            if ref not in refs:
                refs.append(ref)

        add(self.model_spec)
        for spec in self.fallback_specs:
            add(spec)
        if refs[0].provider != "ollama":
            add(_DEFAULT_MODEL)
        if self.openai_compatible_base_url and not any(
            ref.provider == "openai-compatible" for ref in refs
        ):
            add(f"openai-compatible:{self.openai_compatible_model}")
        return refs


def load_settings(
    env: Mapping[str, str] | None = None,
    *,
    config_path: Path | None = None,
) -> Settings:
    environ = os.environ if env is None else env
    path = config_path if config_path is not None else config_dir(environ) / "config.toml"
    file_data: dict[str, object] = {}
    if path.is_file():
        loaded = tomllib.loads(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            file_data = loaded
    models = _table(file_data.get("models"))
    core = _table(file_data.get("core"))
    providers = _table(models.get("providers"))
    ollama_cfg = _table(providers.get("ollama"))
    compat_cfg = _table(providers.get("openai_compatible"))

    primary = _first(
        environ.get("PRAXIS_PRIME_MODEL"),
        _str(models.get("primary")),
        _DEFAULT_MODEL,
    )
    fallback_env = environ.get("PRAXIS_PRIME_FALLBACK_MODELS", "")
    if fallback_env.strip():
        fallbacks = tuple(part.strip() for part in fallback_env.split(",") if part.strip())
    else:
        raw_fallback = models.get("fallback") or []
        if isinstance(raw_fallback, list):
            fallbacks = tuple(str(item) for item in raw_fallback if str(item).strip())
        else:
            fallbacks = ()

    dials = default_positions()
    for dial_id, position in _table(file_data.get("dials")).items():
        if dial_id in dials and position in {"off", "monitor", "enforce"}:
            dials[str(dial_id)] = str(position)

    memory = _table(file_data.get("memory"))
    mode = _first(environ.get("PRAXIS_PRIME_MODE"), _str(core.get("mode")), "ask")
    if mode not in _MODES:
        mode = "ask"

    ollama_host = normalize_base(
        _first(
            environ.get("PRAXIS_PRIME_OLLAMA_HOST"),
            environ.get("OLLAMA_HOST"),
            _str(ollama_cfg.get("host")),
            "http://127.0.0.1:11434",
        )
    )
    compat_url = normalize_base(
        _first(
            environ.get("PRAXIS_PRIME_OPENAI_COMPATIBLE_BASE_URL"),
            _str(compat_cfg.get("base_url")),
            "",
        )
    )
    openai_url = normalize_base(
        _first(environ.get("PRAXIS_PRIME_OPENAI_BASE_URL"), "https://api.openai.com/v1")
    )
    anthropic_url = normalize_base(
        _first(environ.get("PRAXIS_PRIME_ANTHROPIC_BASE_URL"), "https://api.anthropic.com")
    )
    xai_url = normalize_base(
        _first(environ.get("PRAXIS_PRIME_XAI_BASE_URL"), "https://api.x.ai/v1")
    )
    provider_flags = {
        "ollama": flags_from_config("ollama", ollama_cfg, base_url=ollama_host),
        "openai-compatible": flags_from_config(
            "openai-compatible", compat_cfg, base_url=compat_url
        ),
        "openai": flags_from_config("openai", _table(providers.get("openai")), base_url=openai_url),
        "anthropic": flags_from_config(
            "anthropic", _table(providers.get("anthropic")), base_url=anthropic_url
        ),
        "xai": flags_from_config("xai", _table(providers.get("xai")), base_url=xai_url),
    }

    return Settings(
        model_spec=primary,
        fallback_specs=fallbacks,
        ollama_host=ollama_host,
        openai_compatible_base_url=compat_url,
        openai_compatible_model=_first(
            environ.get("PRAXIS_PRIME_OPENAI_COMPATIBLE_MODEL"),
            _str(compat_cfg.get("model")),
            "local",
        ),
        openai_base_url=openai_url,
        anthropic_base_url=anthropic_url,
        xai_base_url=xai_url,
        openai_api_key=_first(
            environ.get("PRAXIS_PRIME_OPENAI_API_KEY"),
            environ.get("OPENAI_API_KEY"),
            "",
        ),
        anthropic_api_key=_first(
            environ.get("PRAXIS_PRIME_ANTHROPIC_API_KEY"),
            environ.get("ANTHROPIC_API_KEY"),
            "",
        ),
        xai_api_key=_first(environ.get("PRAXIS_PRIME_XAI_API_KEY"), environ.get("XAI_API_KEY"), ""),
        openai_compatible_api_key=environ.get("PRAXIS_PRIME_OPENAI_COMPATIBLE_API_KEY", ""),
        max_iterations=_positive_int(
            _first(
                environ.get("PRAXIS_PRIME_MAX_ITERATIONS"),
                _str(core.get("max_iterations")),
                "200",
            )
        ),
        mode=mode,
        dials=dials,
        timezone=_first(_str(core.get("timezone")), "America/New_York"),
        embed_spec=_first(_str(models.get("embed")), "local:bge-small"),
        memory_redact=_redact_mode(_first(_str(memory.get("redact")), "secrets")),
        memory_profile_cap=_bounded_int(_str(memory.get("profile_cap")), 20, 1, 200),
        memory_profile_chars=_bounded_int(_str(memory.get("profile_chars")), 4000, 200, 100_000),
        memory_half_life_days=_positive_float(_str(memory.get("episodic_half_life_days")), 14.0),
        memory_episodic_ttl_days=_bounded_int(_str(memory.get("episodic_ttl_days")), 90, 1, 3650),
        provider_flags=provider_flags,
    )


def _table(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return value
    return {}


def _str(value: object) -> str:
    if value is None:
        return ""
    return str(value)


def _first(*values: str | None) -> str:
    for value in values:
        if value:
            return value
    return ""


def _redact_mode(value: str) -> str:
    if value in {"off", "secrets", "pii"}:
        return value
    return "secrets"


def _bounded_int(value: str, default: int, low: int, high: int) -> int:
    try:
        number = int(value)
    except ValueError:
        return default
    if number < low:
        return default
    return min(number, high)


def _positive_float(value: str, default: float) -> float:
    try:
        number = float(value)
    except ValueError:
        return default
    if number <= 0:
        return default
    return number


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        return 200
    if number < 1:
        return 200
    return min(number, 500)
