"""Shared setup operations. The CLI and the gateway both call this module."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from praxis_prime.channels.secrets import secret_file, write_secret
from praxis_prime.onboarding.configio import backup_config, load_document, write_document
from praxis_prime.onboarding.detect import detect as detect_local
from praxis_prime.onboarding.messages import BLOCK_CONTEXT, WARN_CONTEXT, cloud_warning
from praxis_prime.onboarding.probe import (
    TEST_LIMIT,
    FetchResult,
    ProbeError,
    parse_json,
)
from praxis_prime.onboarding.probe import (
    fetch as default_fetch,
)
from praxis_prime.onboarding.record import inference_ready, read_record, write_record
from praxis_prime.policy.dials import dial_ids
from praxis_prime.router.settings import load_settings
from praxis_prime.router.types import canonical_spec, parse_model_spec

CLOUD_PROVIDERS = ("openai", "anthropic", "xai", "openai-compatible")
LOCAL_PROVIDERS = ("ollama", "llamacpp", "vllm", "lmstudio", "openai-compatible")
KEY_NAMES = {
    "openai": "PRAXIS_PRIME_OPENAI_API_KEY",
    "anthropic": "PRAXIS_PRIME_ANTHROPIC_API_KEY",
    "xai": "PRAXIS_PRIME_XAI_API_KEY",
    "openai-compatible": "PRAXIS_PRIME_OPENAI_COMPATIBLE_API_KEY",
    "llamacpp": "PRAXIS_PRIME_OPENAI_COMPATIBLE_API_KEY",
    "vllm": "PRAXIS_PRIME_OPENAI_COMPATIBLE_API_KEY",
    "lmstudio": "PRAXIS_PRIME_OPENAI_COMPATIBLE_API_KEY",
    "ollama": "PRAXIS_PRIME_OLLAMA_API_KEY",
}
CLOUD_BASES = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com",
    "xai": "https://api.x.ai/v1",
}
_REQUIRED_KEY = {"openai", "anthropic", "xai"}

Fetcher = Callable[..., FetchResult]
AuditFn = Callable[[str, str, dict[str, object]], None]


class OnboardingError(Exception):
    def __init__(self, message: str, *, code: str = "error") -> None:
        self.code = code
        super().__init__(message)


@dataclass
class Selection:
    lane: str
    provider: str = ""
    model: str = ""
    utility_model: str = ""
    vision_model: str = ""
    judge_model: str = ""
    base_url: str = ""
    api_key: str = ""
    tls_fingerprint: str = ""
    replace: bool = False
    actor: str = ""


@dataclass
class OnboardingService:
    config_dir: Path
    data_dir: Path | None = None
    env: Mapping[str, str] = field(default_factory=dict)
    fetcher: Fetcher | None = None
    hardware_runner: Callable[[list[str]], str] | None = None
    audit: AuditFn | None = None
    actor: str = ""

    def status(self, *, owner_exists: bool) -> dict[str, object]:
        settings = self._settings()
        ready = inference_ready(self.config_dir, settings.model_spec)
        missing: list[dict[str, str]] = []
        if not owner_exists:
            missing.append({"id": "no owner account", "step": "owner"})
        if not settings.model_spec.strip():
            missing.append({"id": "no provider chosen", "step": "provider"})
        elif not ready:
            missing.append({"id": "provider not verified", "step": "test"})
        record = read_record(self.config_dir)
        return {
            "setupRequired": not owner_exists,
            "inferenceReady": ready,
            "missing": missing,
            "provider": settings.model_spec,
            "lane": str(record.get("lane", "")),
            "locality": str(record.get("locality", "")),
            "models": {
                "primary": settings.model_spec,
                "utility": settings.utility_spec,
                "vision": settings.vision_spec,
                "judge": settings.judge_spec,
            },
            "dials": dict(settings.dials),
            "cloudWarning": cloud_warning(settings.dials),
            "allowProviders": list(settings.allow_providers),
        }

    def detect(self) -> dict[str, object]:
        return detect_local(self.env, fetcher=self.fetcher, runner=self.hardware_runner)

    def probe(
        self,
        url: str,
        *,
        pin: str = "",
        capture_fingerprint: bool = False,
    ) -> dict[str, object]:
        fetch = self.fetcher or default_fetch
        try:
            result = fetch(
                "GET",
                url,
                timeout=5.0,
                limit=256 * 1024,
                pin=pin,
                capture_fingerprint=capture_fingerprint,
            )
        except ProbeError as exc:
            return {
                "ok": False,
                "error": str(exc),
                "fingerprint": exc.fingerprint,
            }
        models, context = _models_from_body(result.body)
        return {
            "ok": 200 <= result.status < 300,
            "status": result.status,
            "models": models,
            "contextLength": context,
            "fingerprint": result.fingerprint,
        }

    def test(
        self,
        *,
        provider: str,
        model: str,
        base_url: str = "",
        lane: str = "",
        api_key: str = "",
        pin: str = "",
    ) -> dict[str, object]:
        provider_id = provider.strip().lower()
        model_name = model.strip()
        if not provider_id or not model_name:
            raise OnboardingError("a provider and a model are required", code="usage")
        url = _base_url(provider_id, base_url, lane)
        key = self._key_for(provider_id, url, api_key)
        if provider_id in _REQUIRED_KEY and not key:
            raise OnboardingError(
                f"{provider_id} needs an API key in the secrets file or --api-key-env",
                code="usage",
            )
        if lane == "cloud" and provider_id == "openai-compatible" and not key:
            raise OnboardingError(
                "a cloud OpenAI-compatible provider needs an API key",
                code="usage",
            )
        fetch = self.fetcher or default_fetch
        warnings: list[str] = []
        context = self._reported_context(fetch, provider_id, url, model_name, key, pin)
        if context is not None and context < BLOCK_CONTEXT:
            raise OnboardingError(
                f"context length {context} is below 16384; agent mode stays off "
                "and the provider is not marked ready",
                code="context",
            )
        if context is not None and context < WARN_CONTEXT:
            warnings.append(f"context length {context} is below 32768")
        elif context is None:
            warnings.append("the server did not report a context length")
        completion = self._completion(fetch, provider_id, url, model_name, key, pin)
        if not completion:
            raise OnboardingError("the completion test did not return text", code="test")
        tool_ok = self._tool_call(fetch, provider_id, url, model_name, key, pin)
        if not tool_ok:
            raise OnboardingError("the tool-call test did not return a tool call", code="test")
        return {
            "ok": True,
            "provider": provider_id,
            "model": model_name,
            "spec": f"{provider_id}:{model_name}",
            "baseUrl": url,
            "contextLength": context,
            "toolCall": True,
            "warnings": warnings,
        }

    def save(self, selection: Selection) -> dict[str, object]:
        lane = selection.lane.strip().lower()
        if lane not in {"local", "lan", "cloud", "skip"}:
            raise OnboardingError("lane must be local, lan, cloud, or skip", code="usage")
        if lane == "skip":
            return self._skip(selection)
        provider = selection.provider.strip().lower()
        model = selection.model.strip()
        self._check_allowlist(provider)
        if lane == "cloud" and provider not in CLOUD_PROVIDERS:
            raise OnboardingError(f"{provider} is not a cloud preset", code="usage")
        if lane in {"local", "lan"} and provider not in LOCAL_PROVIDERS:
            raise OnboardingError(f"{provider} is not a local provider", code="usage")
        if not model:
            raise OnboardingError("a primary model is required", code="usage")
        spec = f"{provider}:{model}"
        self._refuse_clobber(selection)
        base = _base_url(provider, selection.base_url, lane)
        tested = self.test(
            provider=provider,
            model=model,
            base_url=base,
            lane=lane,
            api_key=selection.api_key,
            pin=selection.tls_fingerprint,
        )
        roles = self._optional_roles(selection, base, lane, tested["warnings"])
        self._persist(selection, provider, model, base, lane, tested, roles)
        self._audit(
            "provider.configured",
            "provider configured",
            {
                "spec": spec,
                "provider": provider,
                "model": model,
                "lane": lane,
                "host": _host_of(base),
                "tested_at": _now(),
                "actor": selection.actor,
            },
        )
        return {"ok": True, "inferenceReady": True, "spec": spec, "warnings": tested["warnings"]}

    def set_dials(self, positions: Mapping[str, str], *, actor: str = "") -> dict[str, str]:
        known = set(dial_ids())
        clean: dict[str, str] = {}
        for dial_id, position in positions.items():
            if dial_id not in known:
                raise OnboardingError(f"unknown dial {dial_id}", code="usage")
            if position not in {"off", "monitor", "enforce"}:
                raise OnboardingError(
                    f"dial {dial_id} must be off, monitor, or enforce",
                    code="usage",
                )
            clean[str(dial_id)] = str(position)
        path = self.config_dir / "config.toml"
        previous = path.read_text(encoding="utf-8") if path.is_file() else ""
        document = load_document(path)
        dials = document.get("dials")
        if not isinstance(dials, dict):
            dials = {}
        dials.update(clean)
        document["dials"] = dials
        backup_config(path)
        write_document(path, document, previous=previous)
        self._audit("dials.updated", "compliance dials updated", {"dials": clean, "actor": actor})
        return {str(key): str(value) for key, value in dials.items()}

    def _skip(self, selection: Selection) -> dict[str, object]:
        settings = self._settings()
        if settings.model_spec.strip() and not selection.replace:
            raise OnboardingError(
                "a provider is already configured; pass --replace to skip it",
                code="replace",
            )
        if settings.model_spec.strip() and selection.replace:
            path = self.config_dir / "config.toml"
            previous = path.read_text(encoding="utf-8") if path.is_file() else ""
            document = load_document(path)
            models = document.get("models")
            if not isinstance(models, dict):
                models = {}
            models["primary"] = ""
            document["models"] = models
            backup_config(path)
            write_document(path, document, previous=previous)
        write_record(
            self.config_dir,
            {"ready": False, "spec": "", "lane": "skip", "tested_at": _now(), "warnings": []},
        )
        self._audit("provider.configured", "provider skipped", {"lane": "skip", "ready": False})
        return {"ok": True, "inferenceReady": False, "skipped": True}

    def requires_replace(self, selection: Selection) -> bool:
        """True when this save would change a configured provider, endpoint, or key.

        The same spec at a new base URL counts. A model-only change counts
        too. The caller still decides whether a step-up is required.
        """
        lane = selection.lane.strip().lower()
        current = self._settings().model_spec.strip()
        if lane == "skip":
            return bool(current)
        provider = selection.provider.strip().lower()
        model = selection.model.strip()
        if not provider or not model:
            return False
        spec = f"{provider}:{model}"
        changing = bool(current) and not _same_model_spec(current, spec)
        return changing or self._replacing_key(provider, selection) or self._endpoint_changed(
            selection
        )

    def needs_step_up(self, selection: Selection) -> bool:
        """True when the browser must spend a step-up before this save.

        A model-only change does not. Changing the provider, its base URL,
        or a stored key does. The CLI does not call this.
        """
        lane = selection.lane.strip().lower()
        provider = selection.provider.strip().lower()
        current = self._settings().model_spec.strip()
        if lane == "skip":
            return bool(current)
        if self._replacing_key(provider, selection):
            return True
        if not current:
            return False
        current_provider = current.split(":", 1)[0]
        if provider and _canonical_provider(provider) != _canonical_provider(current_provider):
            return True
        return self._endpoint_changed(selection)

    def _replacing_key(self, provider: str, selection: Selection) -> bool:
        if not selection.api_key:
            return False
        key_name = KEY_NAMES.get(provider, "")
        if not key_name:
            return False
        return _secret_exists(self.config_dir, self.env, key_name)

    def _endpoint_changed(self, selection: Selection) -> bool:
        """True when the proposed base URL differs from the saved one.

        An unusable base URL returns false so ``save`` can raise its own
        usage error instead of a replace error.
        """
        lane = selection.lane.strip().lower()
        provider = selection.provider.strip().lower()
        if lane == "skip" or not provider:
            return False
        recorded = self._recorded_base()
        if not recorded:
            return False
        try:
            proposed = _normalize_base(_base_url(provider, selection.base_url, lane))
        except OnboardingError:
            return False
        return bool(proposed) and proposed != recorded

    def _recorded_base(self) -> str:
        record = read_record(self.config_dir)
        record_base = str(record.get("base_url", "") or "").strip()
        if record_base:
            return _normalize_base(record_base)
        current = self._settings().model_spec.strip()
        if not current:
            return ""
        return self._bound_base(current.split(":", 1)[0])

    def _refuse_clobber(self, selection: Selection) -> None:
        if self.requires_replace(selection) and not selection.replace:
            raise OnboardingError(
                "a provider is already configured; pass --replace to change it",
                code="replace",
            )

    def _persist(
        self,
        selection: Selection,
        provider: str,
        model: str,
        base: str,
        lane: str,
        tested: dict[str, object],
        roles: dict[str, dict[str, object]],
    ) -> None:
        if selection.api_key:
            key_name = KEY_NAMES.get(provider)
            if key_name is None:
                raise OnboardingError("this provider does not take an API key", code="usage")
            write_secret(secret_file(self.config_dir, self.env), key_name, selection.api_key)
        path = self.config_dir / "config.toml"
        previous = path.read_text(encoding="utf-8") if path.is_file() else ""
        document = load_document(path)
        models = document.get("models")
        if not isinstance(models, dict):
            models = {}
        models["primary"] = f"{provider}:{model}"
        if selection.utility_model and "utility" in roles:
            models["utility"] = f"{provider}:{selection.utility_model.strip()}"
        if selection.vision_model and "vision" in roles:
            models["vision"] = f"{provider}:{selection.vision_model.strip()}"
        providers = models.get("providers")
        if not isinstance(providers, dict):
            providers = {}
        if provider == "ollama":
            ollama = providers.get("ollama")
            if not isinstance(ollama, dict):
                ollama = {}
            ollama["host"] = base
            providers["ollama"] = ollama
        elif provider in {"llamacpp", "vllm", "lmstudio", "openai-compatible"}:
            compat = providers.get("openai_compatible")
            if not isinstance(compat, dict):
                compat = {}
            compat["base_url"] = base
            compat["model"] = model
            if selection.tls_fingerprint:
                compat["tls_fingerprint"] = selection.tls_fingerprint
            providers["openai_compatible"] = compat
        models["providers"] = providers
        document["models"] = models
        if selection.judge_model and "judge" in roles:
            decide = document.get("decide")
            if not isinstance(decide, dict):
                decide = {}
            decide_models = decide.get("models")
            if not isinstance(decide_models, dict):
                decide_models = {}
            decide_models["tier2"] = f"{provider}:{selection.judge_model.strip()}"
            decide["models"] = decide_models
            document["decide"] = decide
        backup_config(path)
        write_document(path, document, previous=previous)
        locality = _locality(lane, base)
        write_record(
            self.config_dir,
            {
                "ready": True,
                "spec": _ready_spec(provider, model),
                "provider": provider,
                "model": model,
                "lane": lane,
                "locality": locality,
                "base_url": base,
                "tested_at": _now(),
                "context_length": tested.get("contextLength"),
                "tool_call": True,
                "warnings": list(tested.get("warnings") or []),
                "roles": {
                    "primary": {
                        "spec": _ready_spec(provider, model),
                        "tested_at": _now(),
                        "passed": True,
                    },
                    **roles,
                },
                "fallbacks": [],
            },
        )

    def _optional_roles(
        self,
        selection: Selection,
        base: str,
        lane: str,
        warnings: object,
    ) -> dict[str, dict[str, object]]:
        saved: dict[str, dict[str, object]] = {}
        pairs = (
            ("utility", selection.utility_model),
            ("vision", selection.vision_model),
            ("judge", selection.judge_model),
        )
        for role, raw in pairs:
            name = raw.strip()
            if not name:
                continue
            try:
                self.test(
                    provider=selection.provider,
                    model=name,
                    base_url=base,
                    lane=lane,
                    api_key=selection.api_key,
                    pin=selection.tls_fingerprint,
                )
            except OnboardingError:
                if isinstance(warnings, list):
                    warnings.append(f"{role} model {name} did not pass and was left unchanged")
                continue
            saved[role] = {
                "spec": _ready_spec(selection.provider.strip().lower(), name),
                "tested_at": _now(),
                "passed": True,
            }
        return saved

    def _check_allowlist(self, provider: str) -> None:
        allowed = self._settings().allow_providers
        if allowed and provider not in allowed:
            raise OnboardingError(
                f"{provider} is not on the admin provider allowlist",
                code="allowlist",
            )

    def _settings(self):
        return load_settings(self.env, config_path=self.config_dir / "config.toml")

    def _existing_key(self, provider: str) -> str:
        settings = self._settings()
        return {
            "openai": settings.openai_api_key,
            "anthropic": settings.anthropic_api_key,
            "xai": settings.xai_api_key,
            "openai-compatible": settings.openai_compatible_api_key,
            "llamacpp": settings.openai_compatible_api_key,
            "vllm": settings.openai_compatible_api_key,
            "lmstudio": settings.openai_compatible_api_key,
            "ollama": "",
        }.get(provider, "")

    def _key_for(self, provider: str, base: str, supplied: str) -> str:
        """Use a stored key only with the base URL it was saved for.

        A different host has to receive the key again in this request.
        The stored value is never attached to that request.
        """
        if supplied.strip():
            return supplied.strip()
        stored = self._existing_key(provider).strip()
        if not stored:
            return ""
        bound = self._bound_base(provider)
        if bound and _normalize_base(base) == bound:
            return stored
        self._audit(
            "provider.test",
            "provider test refused",
            {"provider": provider, "host": _host_of(base), "status": "refused"},
        )
        raise OnboardingError(
            "re-enter the API key to use a different base URL",
            code="usage",
        )

    def _bound_base(self, provider: str) -> str:
        """Base URL the stored key may be sent to. Empty means never send it."""
        key_name = KEY_NAMES.get(provider, "")
        if not key_name:
            return ""
        record = read_record(self.config_dir)
        record_provider = str(record.get("provider", "") or "").strip().lower()
        record_base = str(record.get("base_url", "") or "").strip()
        if record_base and KEY_NAMES.get(record_provider, "") == key_name:
            return _normalize_base(record_base)
        settings = self._settings()
        if provider == "ollama":
            return _normalize_base(settings.ollama_host)
        if provider in {"llamacpp", "vllm", "lmstudio", "openai-compatible"}:
            return _normalize_base(settings.openai_compatible_base_url)
        if provider in CLOUD_BASES:
            return _normalize_base(CLOUD_BASES[provider])
        return ""

    def _reported_context(
        self,
        fetch: Fetcher,
        provider: str,
        base: str,
        model: str,
        key: str,
        pin: str,
    ) -> int | None:
        path = "/api/tags" if provider == "ollama" else "/v1/models"
        try:
            result = fetch(
                "GET",
                base.rstrip("/") + path,
                headers=_headers(provider, key),
                timeout=5.0,
                limit=256 * 1024,
                pin=pin,
            )
        except (ProbeError, OSError, TimeoutError, ValueError):
            return None
        if result.status < 200 or result.status >= 300:
            return None
        _names, context = _models_from_body(result.body, prefer=model)
        return context

    def _completion(
        self,
        fetch: Fetcher,
        provider: str,
        base: str,
        model: str,
        key: str,
        pin: str,
    ) -> str:
        status, payload = self._post(fetch, provider, base, model, key, pin, tools=False)
        if status < 200 or status >= 300:
            raise OnboardingError("the completion test was refused", code="test")
        if provider == "anthropic":
            return _anthropic_text(payload)
        return _openai_text(payload)

    def _tool_call(
        self,
        fetch: Fetcher,
        provider: str,
        base: str,
        model: str,
        key: str,
        pin: str,
    ) -> bool:
        status, payload = self._post(fetch, provider, base, model, key, pin, tools=True)
        if status < 200 or status >= 300:
            return False
        if provider == "anthropic":
            return _anthropic_tool(payload)
        return _openai_tool(payload)

    def _post(
        self,
        fetch: Fetcher,
        provider: str,
        base: str,
        model: str,
        key: str,
        pin: str,
        *,
        tools: bool,
    ) -> tuple[int, dict[str, object]]:
        if provider == "anthropic":
            url = base.rstrip("/") + "/v1/messages"
            body = _anthropic_body(model, tools)
        elif provider == "ollama":
            url = base.rstrip("/") + "/v1/chat/completions"
            body = _openai_body(model, tools)
        else:
            url = base.rstrip("/") + "/v1/chat/completions"
            body = _openai_body(model, tools)
        try:
            result = fetch(
                "POST",
                url,
                body=json.dumps(body).encode("utf-8"),
                headers=_headers(provider, key),
                timeout=5.0,
                limit=TEST_LIMIT,
                pin=pin,
            )
        except ProbeError as exc:
            raise OnboardingError(str(exc), code="test") from exc
        try:
            payload = parse_json(result.body)
        except ProbeError as exc:
            raise OnboardingError(str(exc), code="test") from exc
        self._audit(
            "provider.test",
            "provider test",
            {
                "provider": provider,
                "model": model,
                "host": _host_of(url),
                "tool_call": tools,
                "status": result.status,
                "tested_at": _now(),
            },
        )
        return result.status, payload

    def _audit(self, kind: str, summary: str, payload: dict[str, object]) -> None:
        if self.audit is None:
            return
        safe = {
            key: value
            for key, value in payload.items()
            if "key" not in key and "secret" not in key
        }
        if self.actor and "actor" not in safe:
            safe["actor"] = self.actor
        try:
            self.audit(kind, summary, safe)
        except (OSError, RuntimeError, ValueError):
            return


def _secret_exists(config_directory: Path, env: Mapping[str, str], name: str) -> bool:
    path = secret_file(config_directory, env)
    if not path.is_file():
        return False
    from praxis_prime.channels.secrets import parse_env_file

    try:
        values = parse_env_file(path.read_text(encoding="utf-8"))
    except OSError:
        return False
    return bool(values.get(name, "").strip())


def _ready_spec(provider: str, model: str) -> str:
    """Spec stored in provider-ready.json. Aliases fold to the adapter name."""
    return canonical_spec(f"{provider}:{model}")


def _same_model_spec(left: str, right: str) -> bool:
    """True when both strings name the same provider and model after alias folding."""
    one = left.strip()
    other = right.strip()
    if not one or not other:
        return one == other
    try:
        return canonical_spec(one) == canonical_spec(other)
    except ValueError:
        return one == other


def _canonical_provider(provider: str) -> str:
    """Adapter id for a wizard provider or a ``provider:model`` spec."""
    text = provider.strip().lower()
    if not text:
        return ""
    spec = text if ":" in text else f"{text}:model"
    try:
        return parse_model_spec(spec).provider
    except ValueError:
        return text.split(":", 1)[0]


def _base_url(provider: str, base_url: str, lane: str) -> str:
    text = base_url.strip().rstrip("/")
    if text:
        if "://" not in text:
            text = "http://" + text
        return text
    if provider in CLOUD_BASES and lane in {"cloud", ""}:
        return CLOUD_BASES[provider]
    defaults = {
        "ollama": "http://127.0.0.1:11434",
        "llamacpp": "http://127.0.0.1:8080",
        "vllm": "http://127.0.0.1:8000",
        "lmstudio": "http://127.0.0.1:1234",
    }
    if provider in defaults:
        return defaults[provider]
    raise OnboardingError("a base URL is required for this provider", code="usage")


def _normalize_base(url: str) -> str:
    """Compare scheme, host, port, and path. ``http`` and ``https`` stay distinct."""
    text = url.strip()
    if not text:
        return ""
    if "://" not in text:
        text = "http://" + text
    parts = urlsplit(text)
    host = (parts.hostname or "").lower()
    if not host:
        return ""
    if ":" in host:
        host = f"[{host}]"
    scheme = parts.scheme.lower()
    port = parts.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    netloc = host if port is None else f"{host}:{port}"
    path = parts.path.rstrip("/")
    query = f"?{parts.query}" if parts.query else ""
    return f"{scheme}://{netloc}{path}{query}"


def _host_of(url: str) -> str:
    text = url.strip()
    if text and "://" not in text:
        text = "http://" + text
    return (urlsplit(text).hostname or "").lower()


def _locality(lane: str, base: str) -> str:
    if lane == "cloud":
        return "cloud"
    host = base.split("://", 1)[-1].split("/", 1)[0].split("@")[-1]
    host = host.split(":")[0].strip("[]").lower()
    if host in {"127.0.0.1", "localhost", "::1"}:
        return "local"
    return "lan"


def _headers(provider: str, key: str) -> dict[str, str]:
    headers = {"content-type": "application/json", "accept": "application/json"}
    if provider == "anthropic":
        headers["anthropic-version"] = "2023-06-01"
        if key:
            headers["x-api-key"] = key
        return headers
    if key:
        headers["authorization"] = f"Bearer {key}"
    return headers


def _openai_body(model: str, tools: bool) -> dict[str, object]:
    body: dict[str, object] = {
        "model": model,
        "messages": [{"role": "user", "content": "Reply with the word ready."}],
        "max_tokens": 16,
        "temperature": 0,
        "stream": False,
    }
    if tools:
        body["messages"] = [{"role": "user", "content": "Call the ping tool."}]
        body["max_tokens"] = 64
        body["tools"] = [
            {
                "type": "function",
                "function": {
                    "name": "ping",
                    "description": "Reply pong.",
                    "parameters": {"type": "object", "properties": {}},
                },
            }
        ]
        body["tool_choice"] = "auto"
    return body


def _anthropic_body(model: str, tools: bool) -> dict[str, object]:
    body: dict[str, object] = {
        "model": model,
        "max_tokens": 16 if not tools else 64,
        "messages": [
            {
                "role": "user",
                "content": "Call the ping tool." if tools else "Reply with the word ready.",
            }
        ],
    }
    if tools:
        body["tools"] = [
            {
                "name": "ping",
                "description": "Reply pong.",
                "input_schema": {"type": "object", "properties": {}},
            }
        ]
    return body


def _openai_text(payload: Mapping[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    return content.strip() if isinstance(content, str) else ""


def _openai_tool(payload: Mapping[str, Any]) -> bool:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return False
    message = choices[0].get("message")
    if not isinstance(message, dict):
        return False
    calls = message.get("tool_calls")
    return isinstance(calls, list) and bool(calls)


def _anthropic_text(payload: Mapping[str, Any]) -> str:
    content = payload.get("content")
    if isinstance(content, str):
        return content.strip()
    if not isinstance(content, list):
        return ""
    parts = [
        str(block.get("text", ""))
        for block in content
        if isinstance(block, dict) and block.get("type") == "text"
    ]
    return "".join(parts).strip()


def _anthropic_tool(payload: Mapping[str, Any]) -> bool:
    content = payload.get("content")
    if not isinstance(content, list):
        return False
    return any(isinstance(block, dict) and block.get("type") == "tool_use" for block in content)


def _models_from_body(body: bytes, prefer: str = "") -> tuple[list[str], int | None]:
    from praxis_prime.onboarding.detect import _parse_models

    names, context = _parse_models(body)
    if prefer and names:
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            return names, context
        if isinstance(payload, dict):
            data = payload.get("data")
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and item.get("id") == prefer:
                        from praxis_prime.onboarding.detect import _context_number

                        specific = _context_number(item)
                        if specific is not None:
                            return names, specific
    return names, context


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
