"""Providers catalog route and the save fields added with the picker."""

from __future__ import annotations

import json
from pathlib import Path

from praxis_prime.accounts.db import AccountStore
from praxis_prime.accounts.factors import Factors
from praxis_prime.gateway.authz import Principal
from praxis_prime.onboarding.record import read_record
from praxis_prime.onboarding.token import ensure_first_run_token
from test_onboarding_api import _call, _gateway, _owner, _session

_PASSWORD = "correct-horse"


def test_providers_accepts_the_first_run_token_and_hides_key_values(tmp_path: Path):
    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    server.onboarding_env = {"XAI_API_KEY": "sk-should-not-leak"}  # type: ignore[attr-defined]
    token = ensure_first_run_token(config)
    status, body, _extras = _call(server, "POST", "/v1/onboarding/providers", b"{}")
    assert status == 401, body
    status, body, _extras = _call(server, "POST", "/v1/onboarding/providers", b"{}", token=token)
    assert status == 200, body
    encoded = json.dumps(body)
    assert "sk-should-not-leak" not in encoded
    assert "XAI_API_KEY" in body["detection"]["envKeys"]
    ids = [item["id"] for item in body["providers"]]
    assert "network" in ids
    assert body["policy"]["subscriptionOauthEnabled"] is False
    xai = next(item for item in body["providers"] if item["id"] == "xai")
    methods = {method["id"]: method for method in xai["authMethods"]}
    assert methods["api_key"]["available"] is True
    assert methods["oauth"]["available"] is False
    assert "client_id" not in json.dumps(methods["oauth"])
    store.close()


def test_providers_is_owner_or_admin_after_an_owner_exists(tmp_path: Path):
    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    token = ensure_first_run_token(config)
    status, owner, extras = _call(
        server, "POST", "/v1/onboarding/owner", _owner("ada"), token=token
    )
    assert status == 201, owner
    cookie = _session(extras)
    csrf = str(owner["csrfToken"])
    status, body, _extras = _call(
        server, "POST", "/v1/onboarding/providers", b"{}", cookie=cookie, csrf=csrf
    )
    assert status == 200, body
    bob = store.create_account(username_text="bob", password=_PASSWORD, display_name="Bob")
    issued = store.open_session(bob)
    status, body, _extras = _call(
        server,
        "POST",
        "/v1/onboarding/providers",
        b"{}",
        cookie=issued.token,
        csrf=issued.csrf_token,
    )
    assert status == 403, body
    import queue

    principal = Principal(
        kind="session",
        account_id=str(owner["account"]["id"]),
        username="ada",
        role="owner",
        session_id=store.session_from_token(cookie).id,  # type: ignore[union-attr]
    )
    outgoing: queue.Queue[dict[str, object]] = queue.Queue()
    server._dispatch(
        {"type": "onboarding.providers", "id": "ws-providers", "payload": {}},
        "operator",
        principal,
        outgoing,
    )
    frame = outgoing.get_nowait()
    assert frame["ok"] is True
    assert any(item["id"] == "network" for item in frame["payload"]["providers"])
    store.close()


def test_save_derives_lane_for_an_owner_and_refuses_oauth(tmp_path: Path):
    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    token = ensure_first_run_token(config)
    status, owner, extras = _call(
        server, "POST", "/v1/onboarding/owner", _owner("ada"), token=token
    )
    assert status == 201, owner
    cookie = _session(extras)
    csrf = str(owner["csrfToken"])
    account_id = str(owner["account"]["id"])
    session = store.session_from_token(cookie)
    assert session is not None
    old = {
        "lane": "local",
        "provider": "llamacpp",
        "model": "local-model",
        "baseUrl": "http://127.0.0.1:9",
    }
    status, body, _extras = _call(
        server,
        "POST",
        "/v1/onboarding/save",
        json.dumps(old).encode(),
        cookie=cookie,
        csrf=csrf,
    )
    assert status == 200, body
    record = read_record(config)
    assert record["provider"] == "llamacpp"
    assert record["spec"] == "openai-compatible:local-model"
    assert record["auth_method"] == "none"
    factors = Factors(store)
    held = factors._mint_step_up(account_id, session.id)
    refused = {
        "provider": "xai",
        "model": "grok-4.7",
        "authMethod": "oauth",
        "replace": True,
        "stepUpToken": held,
    }
    status, body, _extras = _call(
        server,
        "POST",
        "/v1/onboarding/save",
        json.dumps(refused).encode(),
        cookie=cookie,
        csrf=csrf,
    )
    assert status == 400, body
    assert body["error"]["code"] == "oauth_unavailable"
    assert factors.step_up_valid(account_id, held, session.id) is True
    kept = read_record(config)
    assert kept["provider"] == "llamacpp"
    derived = {
        "provider": "vllm",
        "model": "local-model",
        "baseUrl": "http://192.0.2.20:9",
        "replace": True,
        "stepUpToken": factors._mint_step_up(account_id, session.id),
    }
    status, body, _extras = _call(
        server,
        "POST",
        "/v1/onboarding/save",
        json.dumps(derived).encode(),
        cookie=cookie,
        csrf=csrf,
    )
    assert status == 200, body
    moved = read_record(config)
    assert moved["lane"] == "lan"
    assert moved["provider"] == "vllm"
    store.close()
