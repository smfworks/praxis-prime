"""LAN base URLs and a network server saved as today's lan lane."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from praxis_prime.accounts.db import AccountStore
from praxis_prime.onboarding.probe import FetchResult
from praxis_prime.onboarding.record import read_record
from praxis_prime.onboarding.service import (
    OnboardingError,
    OnboardingService,
    Selection,
    normalize_server_base,
)
from praxis_prime.onboarding.token import ensure_first_run_token
from praxis_prime.router.settings import load_settings
from test_onboarding_api import _call, _gateway, _owner, _session


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("192.168.1.50:8000", "http://192.168.1.50:8000"),
        ("http://192.168.1.50:8000/v1", "http://192.168.1.50:8000"),
        ("http://192.168.1.50:8000/v1/", "http://192.168.1.50:8000"),
        ("http://10.0.0.5:30000", "http://10.0.0.5:30000"),
        ("https://gpu.lan:8443/v1", "https://gpu.lan:8443"),
        ("http://[fd00::5]:8000", "http://[fd00::5]:8000"),
        ("http://203.0.113.10:8080", "http://203.0.113.10:8080"),
    ],
)
def test_server_bases_that_are_accepted(raw: str, expected: str):
    assert normalize_server_base(raw) == expected
    assert normalize_server_base(expected) == expected


@pytest.mark.parametrize(
    ("raw", "fragment"),
    [
        ("ftp://x", "Only http and https"),
        ("http://user:pw@192.168.1.5:8000", "Credentials"),
        ("http://192.168.1.5:99999", "port"),
        ("http://192.168.1.5:8000/?q=1", "query"),
        ("", "host and port"),
        ("http://", "host"),
    ],
)
def test_server_bases_that_are_rejected(raw: str, fragment: str):
    with pytest.raises(OnboardingError) as exc:
        normalize_server_base(raw)
    assert fragment in str(exc.value)


def _glm_body() -> bytes:
    return json.dumps(
        {
            "object": "list",
            "data": [
                {"id": "zai-org/GLM-4.6", "object": "model"},
                {"id": "glm-4.5-air", "object": "model"},
            ],
        }
    ).encode("utf-8")


def _fetch(method: str, url: str, **kwargs: object) -> FetchResult:
    del method
    if url.endswith("/v1/models"):
        if "missing-models" in url:
            return FetchResult(500, b"{}")
        return FetchResult(200, _glm_body())
    raw = kwargs.get("body") or b"{}"
    payload = json.loads(raw if isinstance(raw, (bytes, str)) else b"{}")
    tools = isinstance(payload, dict) and "tools" in payload
    headers = kwargs.get("headers")
    if isinstance(headers, dict) and "sk-lan" in json.dumps(headers):
        assert "192.168.1.50" in url
    message: dict[str, object]
    if tools:
        message = {"role": "assistant", "content": "", "tool_calls": [{"id": "c1"}]}
    else:
        message = {"role": "assistant", "content": "ready"}
    return FetchResult(200, json.dumps({"choices": [{"message": message}]}).encode())


def _service(tmp_path: Path) -> OnboardingService:
    return OnboardingService(config_dir=tmp_path, data_dir=tmp_path / "data", fetcher=_fetch)


def test_probe_returns_glm_ids_for_a_lan_base(tmp_path: Path):
    service = _service(tmp_path)
    probed = service.probe_models("network", "http://192.168.1.50:8000/v1/")
    assert probed["ok"] is True
    assert probed["models"] == ["zai-org/GLM-4.6", "glm-4.5-air"]
    assert probed["baseUrl"] == "http://192.168.1.50:8000"
    assert probed["network"] is True
    assert probed["loopback"] is False
    assert probed["https"] is False
    empty = service.probe_models("network", "http://missing-models.lan:9")
    assert empty["ok"] is False
    assert empty["models"] == []


def test_network_save_matches_a_lan_config_and_binds_the_key(tmp_path: Path):
    service = _service(tmp_path)
    result = service.save(
        Selection(
            lane="",
            provider="network",
            model="zai-org/GLM-4.6",
            base_url="192.168.1.50:8000",
            api_key="sk-lan",
        )
    )
    assert result["spec"] == "openai-compatible:zai-org/GLM-4.6"
    record = read_record(tmp_path)
    assert record["provider"] == "openai-compatible"
    assert record["lane"] == "lan"
    assert record["spec"] == "openai-compatible:zai-org/GLM-4.6"
    assert record["base_url"] == "http://192.168.1.50:8000"
    settings = load_settings({}, config_path=tmp_path / "config.toml")
    assert settings.model_spec == "openai-compatible:zai-org/GLM-4.6"
    secret = (tmp_path / "secrets.env").read_text(encoding="utf-8")
    assert "sk-lan" in secret
    assert "PRAXIS_PRIME_OPENAI_COMPATIBLE_API_KEY" in secret
    same = service.test(
        provider="openai-compatible",
        model="zai-org/GLM-4.6",
        base_url="http://192.168.1.50:8000",
        lane="lan",
    )
    assert same["ok"] is True
    with pytest.raises(OnboardingError) as exc:
        service.test(
            provider="openai-compatible",
            model="zai-org/GLM-4.6",
            base_url="http://192.168.1.51:8000",
            lane="lan",
        )
    assert exc.value.code == "usage"


def test_typed_model_saves_when_the_list_is_empty(tmp_path: Path):
    service = _service(tmp_path)
    result = service.save(
        Selection(
            lane="",
            provider="openai-compatible",
            model="glm-4.6",
            base_url="http://10.0.0.5:30000/v1",
        )
    )
    assert result["spec"] == "openai-compatible:glm-4.6"
    record = read_record(tmp_path)
    assert record["lane"] == "lan"
    assert record["base_url"] == "http://10.0.0.5:30000"


def test_gateway_probe_accepts_a_base_url(tmp_path: Path):
    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    server.onboarding_fetcher = _fetch  # type: ignore[attr-defined]
    token = ensure_first_run_token(config)
    status, owner, extras = _call(
        server, "POST", "/v1/onboarding/owner", _owner("ada"), token=token
    )
    assert status == 201, owner
    cookie = _session(extras)
    csrf = str(owner["csrfToken"])
    status, body, _extras = _call(
        server,
        "POST",
        "/v1/onboarding/probe",
        json.dumps({"provider": "network", "baseUrl": "192.168.1.50:8000"}).encode(),
        cookie=cookie,
        csrf=csrf,
    )
    assert status == 200, body
    assert body["models"] == ["zai-org/GLM-4.6", "glm-4.5-air"]
    assert body["baseUrl"] == "http://192.168.1.50:8000"
    assert body["network"] is True
    saved = {
        "provider": "network",
        "model": "zai-org/GLM-4.6",
        "baseUrl": "http://192.168.1.50:8000/v1",
        "apiKey": "sk-lan",
    }
    status, body, _extras = _call(
        server,
        "POST",
        "/v1/onboarding/save",
        json.dumps(saved).encode(),
        cookie=cookie,
        csrf=csrf,
    )
    assert status == 200, body
    assert body["spec"] == "openai-compatible:zai-org/GLM-4.6"
    record = read_record(config)
    assert record["lane"] == "lan"
    assert record["provider"] == "openai-compatible"
    store.close()
