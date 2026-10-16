"""Gateway oauth/start|poll|cancel|signout. Flag off spends nothing."""

from __future__ import annotations

from typing import Any

from praxis_prime.accounts.factors import Factors
from praxis_prime.onboarding.service import OnboardingError
from praxis_prime.providers_auth.broker import ProviderAuthBroker, oauth_sign_in_allowed
from praxis_prime.providers_auth.xai_oauth import XaiOAuthError
from praxis_prime.router.settings import load_settings

_OAUTH_MESSAGE = "Subscription sign-in is coming in a later release."


def broker_for(server: Any) -> ProviderAuthBroker:
    held = getattr(server, "_xai_broker", None)
    if isinstance(held, ProviderAuthBroker):
        return held
    fetcher = getattr(server, "onboarding_fetcher", None)
    broker = ProviderAuthBroker(server.config_dir, fetcher)
    server._xai_broker = broker
    return broker


def refuse_if_off(server: Any) -> None:
    settings = load_settings({}, config_path=server.config_dir / "config.toml")
    if not oauth_sign_in_allowed(server.config_dir, settings.dials):
        raise OnboardingError(_OAUTH_MESSAGE, code="oauth_unavailable")


def start(server: Any, principal: Any, payload: dict[str, object]) -> dict[str, object]:
    refuse_if_off(server)
    if str(payload.get("provider") or "xai") != "xai":
        raise OnboardingError("only xAI sign-in is available", code="usage")
    if str(payload.get("flow") or "device") != "device":
        raise OnboardingError("only the device flow is available", code="usage")
    broker = broker_for(server)
    if broker.has_tokens():
        _spend(server, principal, payload)
    session_id = str(getattr(principal, "session_id", "") or "")
    account_id = str(getattr(principal, "account_id", "") or "")
    if not session_id:
        raise OnboardingError("sign-in needs an owner session", code="forbidden")
    try:
        return broker.start_device(session_id=session_id, account_id=account_id)
    except XaiOAuthError as exc:
        raise OnboardingError(str(exc), code="oauth_unavailable") from exc


def poll(server: Any, principal: Any, payload: dict[str, object]) -> dict[str, object]:
    refuse_if_off(server)
    return _session_call(server, principal, str(payload.get("flowId") or ""), "poll")


def cancel(server: Any, principal: Any, payload: dict[str, object]) -> dict[str, object]:
    refuse_if_off(server)
    _session_call(server, principal, str(payload.get("flowId") or ""), "cancel")
    return {"ok": True}


def sign_out(server: Any, principal: Any, payload: dict[str, object]) -> dict[str, object]:
    refuse_if_off(server)
    _spend(server, principal, payload)
    revoked = broker_for(server).sign_out()
    return {"ok": True, "revoked": revoked, "inferenceReady": False}


def _session_call(server: Any, principal: Any, flow_id: str, action: str) -> dict[str, object]:
    session_id = str(getattr(principal, "session_id", "") or "")
    broker = broker_for(server)
    try:
        if action == "cancel":
            broker.cancel(flow_id, session_id)
            return {"ok": True}
        return broker.poll(flow_id, session_id)
    except XaiOAuthError as exc:
        code = "forbidden" if exc.code == "forbidden" else "not_found"
        raise OnboardingError(str(exc), code=code) from exc


def _spend(server: Any, principal: Any, payload: dict[str, object]) -> None:
    session_id = str(getattr(principal, "session_id", "") or "")
    token = str(payload.get("stepUpToken") or "")
    account_id = str(getattr(principal, "account_id", "") or "")
    spent = False
    if account_id and session_id and token:
        spent = Factors(server.accounts).step_up_valid(account_id, token, session_id)
    if not spent:
        raise OnboardingError(
            "changing the provider, its endpoint, or its key needs a step-up, "
            "or `praxis-prime setup --replace`",
            code="replace",
        )
