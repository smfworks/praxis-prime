"""Setup backend: no silent provider, detection, secrets, and a safe re-run."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from praxis_prime.accounts.db import AccountError, AccountStore
from praxis_prime.onboarding.messages import CLOUD_WARNING
from praxis_prime.onboarding.probe import FetchResult, ProbeError, fetch
from praxis_prime.onboarding.record import read_record
from praxis_prime.onboarding.service import OnboardingError, OnboardingService, Selection
from praxis_prime.onboarding.token import ensure_first_run_token, read_first_run_token
from praxis_prime.router.settings import load_settings
from praxis_prime.router.types import INFERENCE_NOT_CONFIGURED, InferenceNotConfigured
from praxis_prime.runtime import build_runtime


def _fetch(method: str, url: str, **kwargs: object) -> FetchResult:
    if kwargs.get("pin") == "bad":
        raise ProbeError("TLS fingerprint does not match")
    if url.endswith("/v1/models") or url.endswith("/api/tags"):
        if "11434" in url:
            body = {"models": [{"name": "qwen3:8b"}]}
        else:
            body = {"data": [{"id": "local-model", "max_model_len": 32768}]}
        return FetchResult(200, json.dumps(body).encode("utf-8"))
    raw = kwargs.get("body") or b"{}"
    payload = json.loads(raw if isinstance(raw, (bytes, str)) else b"{}")
    tools = isinstance(payload, dict) and "tools" in payload
    if "/v1/messages" in url:
        block = {"type": "tool_use", "name": "ping"} if tools else {"type": "text", "text": "ready"}
        return FetchResult(200, json.dumps({"content": [block]}).encode("utf-8"))
    message: dict[str, object]
    if tools:
        message = {"role": "assistant", "content": "", "tool_calls": [{"id": "c1"}]}
    else:
        message = {"role": "assistant", "content": "ready"}
    return FetchResult(200, json.dumps({"choices": [{"message": message}]}).encode("utf-8"))


def _service(tmp_path: Path, *, context: int = 32768) -> OnboardingService:
    def fetch(method: str, url: str, **kwargs: object) -> FetchResult:
        result = _fetch(method, url, **kwargs)
        if url.endswith("/v1/models"):
            body = {"data": [{"id": "local-model", "max_model_len": context}]}
            return FetchResult(200, json.dumps(body).encode("utf-8"))
        return result

    return OnboardingService(config_dir=tmp_path, data_dir=tmp_path / "data", fetcher=fetch)


def test_fresh_config_has_no_provider_and_chat_refuses(tmp_path: Path):
    from praxis_prime.router.types import ChatRequest

    settings = load_settings(
        {"OPENAI_API_KEY": "sk-secret", "OLLAMA_HOST": "http://127.0.0.1:11434"},
        config_path=tmp_path / "missing.toml",
    )
    assert settings.model_spec == ""
    assert settings.chain() == []
    assert settings.openai_api_key == "sk-secret"
    runtime = build_runtime(
        env={"OPENAI_API_KEY": "sk-secret"},
        config_path=tmp_path / "missing.toml",
        data_path=tmp_path / "prime.db",
        cwd=tmp_path,
    )
    try:
        with pytest.raises(InferenceNotConfigured):
            list(runtime.router.iter_stream(ChatRequest(model="x", messages=())))
        _session, loop = runtime.open_loop()
        events = list(loop.run_turn("hello"))
    finally:
        runtime.close()
    text = " ".join(
        str(getattr(event, "text", "")) + str(getattr(event, "error", "") or "") for event in events
    )
    assert INFERENCE_NOT_CONFIGURED in text


def test_env_and_detection_do_not_select_a_provider(tmp_path: Path):
    seen: list[str] = []

    def fetch(method: str, url: str, **kwargs: object) -> FetchResult:
        del method, kwargs
        seen.append(url)
        if url.endswith("/api/tags"):
            return FetchResult(200, json.dumps({"models": [{"name": "qwen3:8b"}]}).encode())
        raise ProbeError("down")

    service = OnboardingService(
        config_dir=tmp_path,
        env={"OPENAI_API_KEY": "sk-live", "XAI_API_KEY": "xai-live"},
        fetcher=fetch,
        hardware_runner=lambda argv: "Ada Lovelace, 580.1\n" if argv[0] == "nvidia-smi" else "",
    )
    found = service.detect()
    assert found["envKeys"] == ["OPENAI_API_KEY", "XAI_API_KEY"]
    assert "sk-live" not in json.dumps(found)
    assert found["servers"][0]["provider"] == "ollama"
    assert service.status(owner_exists=False)["missing"][0]["id"] == "no owner account"
    assert service.status(owner_exists=True)["missing"][0]["id"] == "no provider chosen"
    assert "nvidia" in json.dumps(found["hardware"])


def test_save_marks_ready_only_after_a_passing_test(tmp_path: Path):
    events: list[tuple[str, dict[str, object]]] = []
    service = _service(tmp_path)
    service.audit = lambda kind, summary, payload: events.append((kind, payload))
    result = service.save(
        Selection(lane="local", provider="llamacpp", model="local-model", api_key="sk-local")
    )
    assert result["inferenceReady"] is True
    settings = load_settings({}, config_path=tmp_path / "config.toml")
    assert settings.model_spec == "llamacpp:local-model"
    assert settings.openai_compatible_api_key == "sk-local"
    text = (tmp_path / "config.toml").read_text(encoding="utf-8")
    assert "sk-local" not in text
    record = read_record(tmp_path)
    assert record["ready"] is True
    assert record["spec"] == "llamacpp:local-model"
    assert "sk-local" not in json.dumps(record)
    assert "sk-local" not in json.dumps(events)
    assert any(kind == "provider.configured" for kind, _payload in events)
    service.save(
        Selection(
            lane="local",
            provider="llamacpp",
            model="local-model",
            api_key="sk-local",
            replace=True,
        )
    )
    backups = list(tmp_path.glob("config.toml.bak-*"))
    assert backups
    assert (backups[0].stat().st_mode & 0o777) == 0o600


def test_short_context_does_not_mark_ready_and_replace_is_required(tmp_path: Path):
    short = _service(tmp_path, context=8000)
    with pytest.raises(OnboardingError) as exc:
        short.save(Selection(lane="local", provider="vllm", model="local-model"))
    assert exc.value.code == "context"
    assert not (tmp_path / "config.toml").exists()

    warned = _service(tmp_path, context=20000)
    result = warned.save(Selection(lane="local", provider="vllm", model="local-model"))
    assert any("32768" in item for item in result["warnings"])

    with pytest.raises(OnboardingError) as again:
        warned.save(Selection(lane="cloud", provider="openai", model="gpt-4o", api_key="sk-new"))
    assert again.value.code == "replace"
    secrets = tmp_path / "secrets.env"
    assert not secrets.exists() or "sk-new" not in secrets.read_text(encoding="utf-8")
    kept = load_settings({}, config_path=tmp_path / "config.toml")
    assert kept.model_spec == "vllm:local-model"


def test_replace_does_not_delete_another_providers_secret(tmp_path: Path):
    service = _service(tmp_path)
    service.save(Selection(lane="cloud", provider="openai", model="gpt-4o", api_key="sk-openai"))
    service.save(
        Selection(
            lane="cloud",
            provider="anthropic",
            model="claude",
            api_key="sk-anthropic",
            replace=True,
        )
    )
    text = (tmp_path / "secrets.env").read_text(encoding="utf-8")
    assert "sk-openai" in text
    assert "sk-anthropic" in text
    settings = load_settings({}, config_path=tmp_path / "config.toml")
    assert settings.model_spec == "anthropic:claude"
    assert settings.openai_api_key == "sk-openai"


def test_allowlist_and_skip_and_dials(tmp_path: Path):
    (tmp_path / "config.toml").write_text(
        'dials = {}\n[models]\nallow_providers = ["ollama"]\nprimary = ""\n',
        encoding="utf-8",
    )
    service = _service(tmp_path)
    with pytest.raises(OnboardingError) as exc:
        service.save(Selection(lane="local", provider="vllm", model="local-model"))
    assert exc.value.code == "allowlist"
    skipped = service.save(Selection(lane="skip"))
    assert skipped["inferenceReady"] is False
    dials = service.set_dials({"hipaa": "monitor"})
    assert dials["hipaa"] == "monitor"
    assert service.status(owner_exists=True)["cloudWarning"] == CLOUD_WARNING
    again = service.set_dials({})
    assert again["hipaa"] == "monitor"


def test_probe_refuses_metadata_and_credential_urls():
    with pytest.raises(ProbeError):
        fetch("GET", "http://169.254.169.254/latest/meta-data/", timeout=0.2)
    with pytest.raises(ProbeError):
        fetch("GET", "http://user:secret@127.0.0.1/v1/models", timeout=0.2)
    with pytest.raises(ProbeError):
        fetch("GET", "file:///etc/passwd", timeout=0.2)


def test_two_connections_cannot_both_create_the_owner(tmp_path: Path):
    path = tmp_path / "accounts.db"
    first = AccountStore(path)
    second = AccountStore(path)
    errors: list[BaseException] = []
    winners: list[str] = []

    def create(store: AccountStore, name: str) -> None:
        try:
            account = store.create_account(
                username_text=name,
                password="correct-horse",
                display_name=name,
                role="owner",
            )
            winners.append(account.role)
        except AccountError as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=create, args=(first, "ada")),
        threading.Thread(target=create, args=(second, "bea")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert winners == ["owner"]
    assert errors and "already exists" in str(errors[0])
    assert first.count_accounts() == 1
    first.close()
    second.close()
    token_dir = tmp_path / "config"
    token_dir.mkdir()
    ensure_first_run_token(token_dir)
    assert read_first_run_token(token_dir)
