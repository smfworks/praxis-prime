"""xAI device-code sign-in. No network. Tokens in these tests are fixtures."""

from __future__ import annotations

import json
import stat
import threading
import time
from pathlib import Path

from joserfc import jwt
from joserfc.jwk import ECKey

from praxis_prime.accounts.db import AccountStore
from praxis_prime.accounts.factors import Factors
from praxis_prime.onboarding.cli import setup_command
from praxis_prime.onboarding.configio import backup_config
from praxis_prime.onboarding.probe import FetchResult
from praxis_prime.onboarding.service import OnboardingError, OnboardingService, Selection
from praxis_prime.providers_auth.broker import ProviderAuthBroker, classify_xai_error
from praxis_prime.providers_auth.xai_oauth import CLIENT_ID, ISSUER, XaiOAuthClient, pinned_https
from praxis_prime.router.factory import default_providers
from praxis_prime.router.openai_compat import OpenAICompatibleProvider
from praxis_prime.router.settings import load_settings
from praxis_prime.router.types import ChatMessage, ChatRequest, ProviderUnreachable
from praxis_prime.supervisor.supervisor import Supervisor, _worker_env_dropped
from test_onboarding_api import _call, _gateway, _owner, _session
from test_onboarding_cli import _args, _env, _run

_ACCESS = "access-token-fixture-not-a-secret-file"
_REFRESH = "refresh-token-fixture-not-a-secret-file"
_DEVICE = "device-code-fixture-not-logged"
_USER = "ABCD-EFGH"
_PASSWORD = "correct-horse"


def _flag(config: Path) -> None:
    config.mkdir(parents=True, exist_ok=True)
    (config / "config.toml").write_text(
        "[providers.xai]\nallow_subscription_oauth = true\n",
        encoding="utf-8",
    )


def _id_token(key: ECKey, *, aud: str = CLIENT_ID, exp: int | None = None) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": "subject-1",
        "aud": aud,
        "exp": now + 3600 if exp is None else exp,
        "iat": now,
        "email": "ada@example.com",
        "name": "Ada",
    }
    return jwt.encode({"alg": "ES256", "kid": key.kid, "typ": "JWT"}, claims, key)


class _Fake:
    def __init__(self) -> None:
        self.key = ECKey.generate_key("P-256", auto_kid=True)
        self.calls: list[str] = []
        self.refresh_posts = 0
        self.token_status = 400
        self.token_error = "authorization_pending"
        self.access = _ACCESS
        self.refresh = _REFRESH
        self.bad_host = ""
        self.drop_refresh = False
        self.bad_aud = False

    def __call__(self, method: str, url: str, **kwargs: object) -> FetchResult:
        self.calls.append(url)
        if not pinned_https(url):
            raise AssertionError(url)
        if url.endswith("openid-configuration"):
            if self.bad_host:
                body = {name: self.bad_host for name in (
                    "device_authorization_endpoint",
                    "token_endpoint",
                    "revocation_endpoint",
                    "jwks_uri",
                )}
            else:
                body = {
                    "device_authorization_endpoint": "https://auth.x.ai/oauth2/device/code",
                    "token_endpoint": "https://auth.x.ai/oauth2/token",
                    "revocation_endpoint": "https://auth.x.ai/oauth2/revoke",
                    "jwks_uri": "https://auth.x.ai/oauth2/jwks",
                }
            return FetchResult(200, json.dumps(body).encode())
        if url.endswith("/device/code"):
            return FetchResult(
                200,
                json.dumps(
                    {
                        "device_code": _DEVICE,
                        "user_code": _USER,
                        "verification_uri": "https://auth.x.ai/device",
                        "verification_uri_complete": "https://auth.x.ai/device?user_code=ABCD-EFGH",
                        "expires_in": 600,
                        "interval": 0,
                    }
                ).encode(),
            )
        if url.endswith("/jwks"):
            public = self.key.as_dict(private=False)
            body = public and {"keys": [public]}
            return FetchResult(200, json.dumps(body).encode())
        if url.endswith("/token"):
            raw = kwargs.get("body") or b""
            text = raw.decode() if isinstance(raw, bytes) else str(raw)
            if "refresh_token" in text and "grant_type=refresh_token" in text:
                self.refresh_posts += 1
                if self.token_status >= 400:
                    body = json.dumps({"error": self.token_error}).encode()
                    return FetchResult(self.token_status, body)
                return FetchResult(200, json.dumps(self._pair("access-2", "refresh-2")).encode())
            if self.token_error:
                return FetchResult(400, json.dumps({"error": self.token_error}).encode())
            pair = self._pair(self.access, "" if self.drop_refresh else self.refresh)
            return FetchResult(200, json.dumps(pair).encode())
        if url.endswith("/revoke"):
            return FetchResult(200, b"{}")
        if "/v1/models" in url or url.endswith("/v1/language-models"):
            models = {"data": [{"id": "grok-4.7", "max_model_len": 32768}]}
            return FetchResult(200, json.dumps(models).encode())
        if "/v1/chat/completions" in url:
            headers = kwargs.get("headers") or {}
            if isinstance(headers, dict):
                auth = str(headers.get("authorization") or headers.get("Authorization") or "")
                if _ACCESS not in auth and "access-2" not in auth and "access-token" not in auth:
                    return FetchResult(401, b"{}")
            raw = kwargs.get("body") or b"{}"
            payload = json.loads(raw if isinstance(raw, (bytes, str)) else b"{}")
            tools = isinstance(payload, dict) and "tools" in payload
            if tools:
                message = {"role": "assistant", "content": "", "tool_calls": [{"id": "c1"}]}
            else:
                message = {"role": "assistant", "content": "ready"}
            return FetchResult(200, json.dumps({"choices": [{"message": message}]}).encode())
        return FetchResult(404, b"{}")

    def _pair(self, access: str, refresh: str) -> dict[str, object]:
        body: dict[str, object] = {
            "access_token": access,
            "expires_in": 3600,
            "id_token": _id_token(self.key, aud="other" if self.bad_aud else CLIENT_ID),
            "scope": "openid",
        }
        if refresh:
            body["refresh_token"] = refresh
        return body


def test_flag_off_refuses_start_without_spending_step_up(tmp_path: Path) -> None:
    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    token_mod = __import__(
        "praxis_prime.onboarding.token",
        fromlist=["ensure_first_run_token"],
    )
    token = token_mod.ensure_first_run_token(config)
    status, owner, extras = _call(
        server, "POST", "/v1/onboarding/owner", _owner("ada"), token=token
    )
    assert status == 201, owner
    cookie = _session(extras)
    account_id = str(owner["account"]["id"])
    session_id = store.session_from_token(cookie).id  # type: ignore[union-attr]
    step = Factors(store).prove_password(account_id, _PASSWORD, "", session_id=session_id)
    status, body, _extras = _call(
        server,
        "POST",
        "/v1/onboarding/oauth/start",
        json.dumps({"provider": "xai", "flow": "device", "stepUpToken": step}).encode(),
        cookie=cookie,
        csrf=str(owner["csrfToken"]),
    )
    assert status == 400, body
    assert body["error"]["code"] == "oauth_unavailable"
    assert Factors(store).step_up_valid(account_id, step, session_id) is True
    store.close()


def test_first_run_token_is_refused_on_oauth(tmp_path: Path) -> None:
    config = tmp_path / "config"
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    from praxis_prime.onboarding.token import ensure_first_run_token

    token = ensure_first_run_token(config)
    status, body, _extras = _call(
        server,
        "POST",
        "/v1/onboarding/oauth/start",
        b"{}",
        token=token,
    )
    assert status == 401, body
    assert _ACCESS not in json.dumps(body)
    store.close()


def test_flag_on_device_flow_hides_tokens(tmp_path: Path) -> None:
    config = tmp_path / "config"
    _flag(config)
    store = AccountStore(tmp_path / "accounts.db")
    server = _gateway(tmp_path, store, config)
    fake = _Fake()
    fake.token_error = ""
    server.onboarding_fetcher = fake  # type: ignore[attr-defined]
    from praxis_prime.onboarding.token import ensure_first_run_token

    token = ensure_first_run_token(config)
    status, owner, extras = _call(
        server, "POST", "/v1/onboarding/owner", _owner("ada"), token=token
    )
    assert status == 201, owner
    cookie = _session(extras)
    csrf = str(owner["csrfToken"])
    status, started, _extras = _call(
        server,
        "POST",
        "/v1/onboarding/oauth/start",
        b'{"provider":"xai","flow":"device"}',
        cookie=cookie,
        csrf=csrf,
    )
    assert status == 200, started
    encoded = json.dumps(started)
    assert _DEVICE not in encoded
    assert _ACCESS not in encoded
    assert started["userCode"] == _USER
    status, polled, _extras = _call(
        server,
        "POST",
        "/v1/onboarding/oauth/poll",
        json.dumps({"flowId": started["flowId"]}).encode(),
        cookie=cookie,
        csrf=csrf,
    )
    assert status == 200, polled
    assert polled["status"] == "approved"
    assert _ACCESS not in json.dumps(polled)
    assert _REFRESH not in json.dumps(polled)
    store.close()


def test_save_requires_completion_and_skips_secrets(tmp_path: Path) -> None:
    config = tmp_path / "config"
    _flag(config)
    fake = _Fake()
    fake.token_error = ""
    service = OnboardingService(config_dir=config, fetcher=fake, audit=lambda *_args: None)
    broker = ProviderAuthBroker(config, fake)
    started = broker.start_device(session_id="cli", account_id="owner")
    approved = broker.poll(str(started["flowId"]), "cli")
    assert approved["status"] == "approved"
    fake.calls.clear()
    result = service.save(
        Selection(lane="cloud", provider="xai", model="grok-4.7", auth_method="oauth")
    )
    assert result["ok"] is True
    secrets = config / "secrets.env"
    assert not secrets.exists() or _ACCESS not in secrets.read_text(encoding="utf-8")
    record = json.loads((config / "provider-ready.json").read_text(encoding="utf-8"))
    assert record["auth_method"] == "oauth"
    assert _ACCESS not in json.dumps(record)
    assert _REFRESH not in json.dumps(record)
    assert "sub_hash" in record["account"]


def test_failed_completion_does_not_mark_ready(tmp_path: Path) -> None:
    config = tmp_path / "config"
    _flag(config)
    fake = _Fake()
    fake.token_error = ""

    def refuse_chat(method: str, url: str, **kwargs: object) -> FetchResult:
        if "/v1/chat/completions" in url:
            empty = {"choices": [{"message": {"content": ""}}]}
            return FetchResult(200, json.dumps(empty).encode())
        return fake(method, url, **kwargs)

    service = OnboardingService(config_dir=config, fetcher=fake)
    broker = ProviderAuthBroker(config, fake)
    started = broker.start_device(session_id="cli", account_id="owner")
    assert broker.poll(str(started["flowId"]), "cli")["status"] == "approved"
    service.fetcher = refuse_chat
    try:
        service.save(Selection(lane="cloud", provider="xai", model="grok-4.7", auth_method="oauth"))
    except OnboardingError as exc:
        assert exc.code == "test"
    else:
        raise AssertionError("ready without a completion")
    record_path = config / "provider-ready.json"
    if record_path.exists():
        assert json.loads(record_path.read_text(encoding="utf-8")).get("ready") is not True


def test_host_pin_never_calls_credential() -> None:
    called = {"n": 0}

    def credential() -> str:
        called["n"] += 1
        return _ACCESS

    provider = OpenAICompatibleProvider(
        name="xai",
        base_url="https://evil.example/v1",
        api_key="",
        key_hint="xai",
        require_key=True,
        credential=credential,
        pin_hosts=("api.x.ai",),
    )
    request = ChatRequest(model="grok-4.7", messages=(ChatMessage(role="user", content="hi"),))
    try:
        next(provider.iter_stream(request))
    except ProviderUnreachable:
        pass
    assert called["n"] == 0
    assert pinned_https("https://cli-chat-proxy.grok.com/v1", inference=True) is False
    settings = load_settings(
        {"PRAXIS_PRIME_XAI_BASE_URL": "https://evil.example/v1"},
        config_path=Path("/no/such/config.toml"),
    )
    built = default_providers(settings)
    assert built["xai"].pin_hosts == ()


def test_oauth_factory_pins_and_ignores_override(tmp_path: Path) -> None:
    config = tmp_path / "config"
    config.mkdir()
    (config / "config.toml").write_text(
        "[models]\nprimary = \"xai:grok-4.7\"\n\n[models.providers.xai]\nauth = \"oauth\"\n",
        encoding="utf-8",
    )
    settings = load_settings(
        {"PRAXIS_PRIME_XAI_BASE_URL": "https://evil.example/v1"},
        config_path=config / "config.toml",
    )
    assert settings.xai_auth == "oauth"
    built = default_providers(settings, config_dir=config)
    provider = built["xai"]
    assert provider.pin_hosts == ("api.x.ai",)
    assert provider.base_url.startswith("https://evil.example")
    called = {"n": 0}
    provider.credential = lambda: called.__setitem__("n", called["n"] + 1) or _ACCESS
    request = ChatRequest(model="grok-4.7", messages=(ChatMessage(role="user", content="hi"),))
    try:
        next(provider.iter_stream(request))
    except ProviderUnreachable:
        pass
    assert called["n"] == 0


def test_two_refreshers_post_once(tmp_path: Path) -> None:
    config = tmp_path / "config"
    config.mkdir()
    fake = _Fake()
    fake.token_error = ""
    clock = {"now": 1_000_000.0}
    broker = ProviderAuthBroker(config, fake, clock=lambda: clock["now"])
    broker.save_pair(
        access_token=_ACCESS,
        refresh_token=_REFRESH,
        expires_in=10,
        account={"sub": "subject-1"},
        scope="openid",
        token_endpoint="https://auth.x.ai/oauth2/token",
    )
    clock["now"] = 1_000_020.0
    fake.token_status = 200
    fake.token_error = ""
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def refresh() -> None:
        try:
            barrier.wait(timeout=5)
            broker.access_token()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=refresh) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert not errors
    assert fake.refresh_posts == 1


def test_reused_refresh_is_quarantined(tmp_path: Path) -> None:
    config = tmp_path / "config"
    config.mkdir()
    fake = _Fake()
    broker = ProviderAuthBroker(config, fake, clock=lambda: 1_000_000.0)
    broker.save_pair(
        access_token=_ACCESS,
        refresh_token=_REFRESH,
        expires_in=10,
        account={"sub": "subject-1"},
        scope="openid",
        token_endpoint="https://auth.x.ai/oauth2/token",
    )
    broker._used_refresh.add(_REFRESH)
    broker.clock = lambda: 1_000_020.0  # type: ignore[method-assign]
    try:
        broker.access_token()
    except Exception as exc:
        assert _REFRESH not in str(exc)
    record = broker.store.load(issuer=ISSUER, client_id=CLIENT_ID)
    assert record is not None
    assert record.get("state") == "needs_reauth"
    assert not record.get("refresh_token")
    assert not record.get("access_token")


def test_discovery_rejects_a_foreign_host(tmp_path: Path) -> None:
    fake = _Fake()
    fake.bad_host = "https://evil.example/token"
    client = XaiOAuthClient(fake)
    try:
        client.discovery()
    except Exception as exc:
        assert "evil.example" not in str(exc) or "not pinned" in str(exc).lower() or exc
        assert _ACCESS not in str(exc)
    else:
        raise AssertionError("foreign discovery host was accepted")


def test_worker_env_drops_the_store_path(tmp_path: Path) -> None:
    assert _worker_env_dropped("PRAXIS_PRIME_PROVIDER_AUTH_DIR")
    assert _worker_env_dropped("PRAXIS_PRIME_PROVIDER_AUTH_KEY")
    supervisor = Supervisor(
        data_root=tmp_path / "data",
        runtime_dir=tmp_path / "run",
        state_dir=tmp_path / "state",
        env={
            "PRAXIS_PRIME_PROVIDER_AUTH_DIR": str(tmp_path / "provider-auth"),
            "PRAXIS_PRIME_PROVIDER_AUTH_KEY": str(tmp_path / "provider-auth" / ".key"),
            "HOME": str(tmp_path),
        },
    )
    env = supervisor.worker_env("default")
    assert "PRAXIS_PRIME_PROVIDER_AUTH_DIR" not in env
    assert "provider-auth" not in json.dumps(env)


def test_worker_credential_returns_access_only(tmp_path: Path) -> None:
    config = tmp_path / "config"
    config.mkdir()
    (config / "config.toml").write_text("", encoding="utf-8")
    fake = _Fake()
    broker = ProviderAuthBroker(config, fake, clock=lambda: 1_000_000.0)
    broker.save_pair(
        access_token=_ACCESS,
        refresh_token=_REFRESH,
        expires_in=3600,
        account={"sub": "subject-1"},
        scope="openid",
        token_endpoint="https://auth.x.ai/oauth2/token",
    )
    granted = broker.credential_for_worker()
    assert set(granted) == {"accessToken", "expiresAt"}
    assert granted["accessToken"] == _ACCESS
    assert _REFRESH not in json.dumps(granted)


def test_backup_does_not_copy_provider_auth(tmp_path: Path) -> None:
    config = tmp_path / "config"
    config.mkdir()
    path = config / "config.toml"
    path.write_text("primary = \"xai:grok-4.7\"\n", encoding="utf-8")
    auth = config / "provider-auth"
    auth.mkdir(mode=0o700)
    (auth / "xai.json.enc").write_bytes(b"ciphertext-fixture")
    copied = backup_config(path)
    assert copied is not None
    assert b"ciphertext-fixture" not in copied.read_bytes()
    assert not list(config.glob("provider-auth.bak*"))


def test_classifier_table() -> None:
    assert classify_xai_error(401, "") == "stale_token"
    assert classify_xai_error(403, "[WKE=unauthenticated:no]") == "stale_token"
    assert classify_xai_error(403, "used all available credits") == "entitlement"
    assert classify_xai_error(429, "") == "rate_limited"
    assert classify_xai_error(404, "") == "model_missing"


def test_cli_oauth_still_refused_when_flag_off(tmp_path: Path) -> None:
    env = _env(tmp_path)
    code, text = _run(
        tmp_path,
        _args(tmp_path, non_interactive=True, auth="oauth", provider="xai", model="grok-4.7"),
        "",
        env,
    )
    assert code == 2
    assert "later release" in text


def test_store_file_mode(tmp_path: Path) -> None:
    config = tmp_path / "config"
    config.mkdir()
    broker = ProviderAuthBroker(config, clock=lambda: 10.0)
    broker.save_pair(
        access_token=_ACCESS,
        refresh_token=_REFRESH,
        expires_in=100,
        account={"sub": "subject-1"},
        scope="openid",
        token_endpoint="https://auth.x.ai/oauth2/token",
    )
    file_mode = stat.S_IMODE(broker.store.path.stat().st_mode)
    dir_mode = stat.S_IMODE(broker.store.root.stat().st_mode)
    assert file_mode == 0o600
    assert dir_mode == 0o700
    assert _ACCESS not in broker.store.path.read_text(encoding="utf-8")


def test_scripted_oauth_when_flag_on(tmp_path: Path) -> None:
    env = _env(tmp_path)
    config = tmp_path / "config" / "praxis-prime"
    _flag(config)
    fake = _Fake()
    fake.token_error = ""
    import io

    out = io.StringIO()
    code = setup_command(
        _args(
            tmp_path,
            non_interactive=True,
            auth="oauth",
            provider="xai",
            model="grok-4.7",
            oauth_timeout=5,
        ),
        stdin=io.StringIO(""),
        stdout=out,
        env=env,
        fetcher=fake,
    )
    text = out.getvalue()
    assert code == 0, text
    assert _ACCESS not in text
    assert _REFRESH not in text
    assert _DEVICE not in text
    assert "Signed in." in text
    secrets = config / "secrets.env"
    assert not secrets.exists() or _ACCESS not in secrets.read_text(encoding="utf-8")
