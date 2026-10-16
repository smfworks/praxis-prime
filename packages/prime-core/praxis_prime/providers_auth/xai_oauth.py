"""xAI device-code client. Every call goes through the injected fetcher."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet

# ProbeError stays inside the call sites. A module import cycles through onboarding.service.
Fetcher = Callable[..., object]
Clock = Callable[[], float]

ISSUER = "https://auth.x.ai"
CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
SCOPES = ("openid", "profile", "email", "offline_access", "grok-cli:access", "api:access")
REFERRER = "praxis-prime"
DISCOVERY_URL = "https://auth.x.ai/.well-known/openid-configuration"
INFERENCE_HOST = "api.x.ai"
_CACHE_SECONDS = 3600.0
_ENDPOINTS = (
    "device_authorization_endpoint",
    "token_endpoint",
    "revocation_endpoint",
    "jwks_uri",
)


class XaiOAuthError(Exception):
    def __init__(self, message: str, *, code: str = "failed") -> None:
        self.code = code
        super().__init__(message)


@dataclass
class DeviceStart:
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int


@dataclass
class TokenPair:
    access_token: str
    refresh_token: str
    expires_in: int
    id_claims: dict[str, object]
    scope: str
    token_endpoint: str


def pinned_https(url: str, *, inference: bool = False) -> bool:
    """True when ``url`` may receive an xAI call. Inference is ``api.x.ai`` only."""
    parts = urlsplit(url.strip())
    if parts.scheme != "https" or parts.username or parts.password:
        return False
    host = (parts.hostname or "").lower().rstrip(".")
    if not host or host != host.encode("ascii", "ignore").decode("ascii"):
        return False
    if inference:
        return host == INFERENCE_HOST
    return host == "x.ai" or host.endswith(".x.ai")


class XaiOAuthClient:
    def __init__(self, fetcher: Fetcher, *, clock: Clock | None = None) -> None:
        self.fetcher = fetcher
        self.clock = clock or time.time
        self._discovery: dict[str, str] | None = None
        self._discovery_at = 0.0

    def discovery(self) -> dict[str, str]:
        now = self.clock()
        cached = self._discovery
        if cached is not None and now - self._discovery_at < _CACHE_SECONDS:
            self._require_endpoints(cached)
            return cached
        result = self._call("GET", DISCOVERY_URL)
        if result.status < 200 or result.status >= 300:
            raise XaiOAuthError("discovery was refused", code="network")
        try:
            payload = json.loads(result.body.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise XaiOAuthError("discovery was refused", code="network") from exc
        if not isinstance(payload, dict):
            raise XaiOAuthError("discovery was refused", code="network")
        found: dict[str, str] = {}
        for name in _ENDPOINTS:
            value = payload.get(name)
            if not isinstance(value, str):
                raise XaiOAuthError("discovery endpoint is not pinned", code="network")
            found[name] = value
        self._require_endpoints(found)
        self._discovery = found
        self._discovery_at = now
        return found

    def start_device(self) -> DeviceStart:
        document = self.discovery()
        body = _form(
            {
                "client_id": CLIENT_ID,
                "scope": " ".join(SCOPES),
                "referrer": REFERRER,
            }
        )
        result = self._call(
            "POST",
            document["device_authorization_endpoint"],
            body=body,
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        if result.status < 200 or result.status >= 300:
            raise XaiOAuthError("device authorization was refused", code="network")
        payload = _object(result.body)
        device = _text(payload, "device_code")
        user = _text(payload, "user_code")
        uri = _text(payload, "verification_uri")
        complete = _text(payload, "verification_uri_complete") or uri
        if not device or not user or not uri:
            raise XaiOAuthError("device authorization was refused", code="network")
        if not pinned_https(uri) or not pinned_https(complete):
            raise XaiOAuthError("verification URL is not on x.ai", code="network")
        return DeviceStart(
            device_code=device,
            user_code=user,
            verification_uri=uri,
            verification_uri_complete=complete,
            expires_in=_int(payload.get("expires_in"), 900),
            interval=max(0, _int(payload.get("interval"), 5)),
        )

    def poll_device(self, device_code: str) -> tuple[str, TokenPair | None]:
        """Return ``(status, pair)``.

        Status is pending, slow_down, denied, expired, ineligible, or approved.
        """
        document = self.discovery()
        body = _form(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": CLIENT_ID,
                "device_code": device_code,
            }
        )
        result = self._call(
            "POST",
            document["token_endpoint"],
            body=body,
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        if result.status == 403:
            return "ineligible", None
        payload = _object(result.body) if result.body else {}
        error = str(payload.get("error") or "")
        if error == "authorization_pending":
            return "pending", None
        if error == "slow_down":
            return "slow_down", None
        if error == "access_denied":
            return "denied", None
        if error == "expired_token":
            return "expired", None
        if result.status < 200 or result.status >= 300 or error:
            return "failed", None
        return "approved", self._pair(payload, document["token_endpoint"])

    def refresh(self, refresh_token: str, token_endpoint: str) -> TokenPair:
        self._require_endpoints({"token_endpoint": token_endpoint})
        body = _form(
            {
                "grant_type": "refresh_token",
                "client_id": CLIENT_ID,
                "refresh_token": refresh_token,
            }
        )
        result = self._call(
            "POST",
            token_endpoint,
            body=body,
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        payload = _object(result.body) if result.body else {}
        error = str(payload.get("error") or "")
        if result.status in {400, 401} or error in {"invalid_grant", "invalid_token"}:
            raise XaiOAuthError("the grant was revoked", code="needs_reauth")
        if result.status < 200 or result.status >= 300:
            raise XaiOAuthError("refresh was refused", code="network")
        return self._pair(payload, token_endpoint)

    def revoke(self, refresh_token: str) -> bool:
        from praxis_prime.onboarding.probe import ProbeError

        try:
            document = self.discovery()
        except XaiOAuthError:
            return False
        body = _form(
            {
                "token": refresh_token,
                "token_type_hint": "refresh_token",
                "client_id": CLIENT_ID,
            }
        )
        try:
            result = self._call(
                "POST",
                document["revocation_endpoint"],
                body=body,
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
        except (XaiOAuthError, ProbeError, OSError):
            return False
        return 200 <= result.status < 300

    def _pair(self, payload: dict[str, object], token_endpoint: str) -> TokenPair:
        access = _text(payload, "access_token")
        refresh = _text(payload, "refresh_token")
        if not access or not refresh:
            raise XaiOAuthError("token response is missing a refresh token", code="failed")
        claims = self._id_token(_text(payload, "id_token"))
        return TokenPair(
            access_token=access,
            refresh_token=refresh,
            expires_in=_int(payload.get("expires_in"), 0),
            id_claims=claims,
            scope=_text(payload, "scope") or " ".join(SCOPES),
            token_endpoint=token_endpoint,
        )

    def _id_token(self, token: str) -> dict[str, object]:
        if token.count(".") != 2:
            raise XaiOAuthError("id token was rejected", code="failed")
        document = self.discovery()
        result = self._call("GET", document["jwks_uri"])
        if result.status < 200 or result.status >= 300:
            raise XaiOAuthError("id token was rejected", code="failed")
        try:
            keys = KeySet.import_key_set(json.loads(result.body.decode("utf-8")))
            decoded = jwt.decode(token, keys, algorithms=["ES256"])
        except (JoseError, ValueError, TypeError, json.JSONDecodeError, UnicodeError) as exc:
            raise XaiOAuthError("id token was rejected", code="failed") from exc
        claims = decoded.claims
        if not isinstance(claims, dict):
            raise XaiOAuthError("id token was rejected", code="failed")
        if claims.get("iss") != ISSUER or claims.get("aud") != CLIENT_ID:
            raise XaiOAuthError("id token was rejected", code="failed")
        now = int(time.time())
        exp = claims.get("exp")
        iat = claims.get("iat")
        if not isinstance(exp, int) or not isinstance(iat, int) or exp <= now or iat > now + 300:
            raise XaiOAuthError("id token was rejected", code="failed")
        kept: dict[str, object] = {}
        for name in ("sub", "email", "name"):
            value = claims.get(name)
            if isinstance(value, str):
                kept[name] = value
        if not isinstance(kept.get("sub"), str) or not kept["sub"]:
            raise XaiOAuthError("id token was rejected", code="failed")
        return kept

    def _call(self, method: str, url: str, **kwargs: object) -> object:
        from praxis_prime.onboarding.probe import ProbeError

        if not pinned_https(url):
            raise XaiOAuthError("endpoint is not pinned to x.ai", code="network")
        try:
            return self.fetcher(method, url, **kwargs)
        except ProbeError as exc:
            raise XaiOAuthError("the auth call was refused", code="network") from exc

    def _require_endpoints(self, document: dict[str, str]) -> None:
        for name in _ENDPOINTS:
            value = document.get(name, "")
            if name not in document and name == "revocation_endpoint":
                continue
            if name in document and not pinned_https(value):
                raise XaiOAuthError("endpoint is not pinned to x.ai", code="network")


def _form(fields: dict[str, str]) -> bytes:
    from urllib.parse import urlencode

    return urlencode(fields).encode("utf-8")


def _object(body: bytes) -> dict[str, object]:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _text(payload: dict[str, object], name: str) -> str:
    value = payload.get(name)
    return value.strip() if isinstance(value, str) else ""


def _int(value: object, default: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return value
