"""One refresher for the xAI grant. Workers never see the refresh token."""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from praxis_prime.providers_auth.store import StoreError, TokenStore
from praxis_prime.providers_auth.xai_oauth import (
    CLIENT_ID,
    ISSUER,
    XaiOAuthClient,
    XaiOAuthError,
    pinned_https,
)
from praxis_prime.router.types import scrub_secrets

Fetcher = Callable[..., object]
Clock = Callable[[], float]
Sleeper = Callable[[float], None]
_DROP = ("key", "secret", "token", "code")


class SecretStr:
    """``str`` and ``repr`` never reveal the value."""

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __str__(self) -> str:
        return "[redacted]"

    def __repr__(self) -> str:
        return "[redacted]"


def classify_xai_error(status: int, body: str) -> str:
    text = body or ""
    if status == 401:
        return "stale_token"
    if status == 403 and (
        "[WKE=unauthenticated:" in text or "OAuth2 access token could not be validated" in text
    ):
        return "stale_token"
    if status == 403:
        return "entitlement"
    if status == 429:
        return "rate_limited"
    if status == 404:
        return "model_missing"
    if 200 <= status < 300:
        return "ok"
    return "other"


def scrub_audit_payload(
    payload: dict[str, object],
    secrets: list[str] | None = None,
) -> dict[str, object]:
    hidden = [item for item in (secrets or []) if item]
    safe: dict[str, object] = {}
    for key, value in payload.items():
        folded = key.lower()
        if any(part in folded for part in _DROP):
            continue
        if isinstance(value, str):
            safe[key] = scrub_secrets(value, hidden)
        else:
            safe[key] = value
    return safe


def oauth_sign_in_allowed(config_dir: Path, dials: dict[str, str] | None = None) -> bool:
    # Late import: onboarding.service imports this module.
    from praxis_prime.onboarding.messages import REGULATED_DIALS

    if not _flag(config_dir):
        return False
    positions = dials or {}
    return not any(str(positions.get(dial_id, "")) == "enforce" for dial_id in REGULATED_DIALS)


def subscription_oauth_enabled(config_dir: Path) -> bool:
    return _flag(config_dir)


def _flag(config_dir: Path) -> bool:
    path = Path(config_dir) / "config.toml"
    if not path.is_file():
        return False
    try:
        loaded = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return False
    providers = loaded.get("providers") if isinstance(loaded, dict) else None
    if not isinstance(providers, dict):
        return False
    xai = providers.get("xai")
    if not isinstance(xai, dict):
        return False
    return xai.get("allow_subscription_oauth") is True


def sub_hash(sub: str) -> str:
    return hashlib.sha256(sub.encode("utf-8")).hexdigest()[:16]


@dataclass
class PendingFlow:
    flow_id: str
    session_id: str
    account_id: str
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_at: float
    interval: float
    next_poll: float
    status: str = "pending"
    account: dict[str, str] = field(default_factory=dict)
    error: str = ""


class ProviderAuthBroker:
    def __init__(
        self,
        config_dir: Path,
        fetcher: Fetcher | None = None,
        *,
        clock: Clock | None = None,
        sleeper: Sleeper | None = None,
    ) -> None:
        self.config_dir = Path(config_dir)
        self.store = TokenStore(self.config_dir)
        self.clock = clock or time.time
        self.sleeper = sleeper or time.sleep
        self.client = XaiOAuthClient(fetcher or _missing_fetcher, clock=self.clock)
        self._lock = threading.Lock()
        self._memory: dict[str, object] | None = None
        self._used_refresh: set[str] = set()
        self.flow: PendingFlow | None = None
        self.refresh_posts = 0

    def has_tokens(self) -> bool:
        record = self._current()
        refresh = str(record.get("refresh_token") or "") if record else ""
        return bool(record and refresh and record.get("state") == "ok")

    def public_status(self) -> dict[str, object]:
        record = self._current()
        if record is None:
            return {"provider": "xai", "method": "oauth", "state": "needs_reauth"}
        account = record.get("account")
        sub = ""
        if isinstance(account, dict) and isinstance(account.get("sub"), str):
            sub = sub_hash(account["sub"])
        state = str(record.get("state") or "needs_reauth")
        if state == "ok" and self._expiring(record):
            state = "expiring"
        body: dict[str, object] = {
            "provider": "xai",
            "method": "oauth",
            "state": state,
            "lastRefresh": record.get("last_refresh") or 0,
        }
        if sub:
            body["account"] = {"issuer": ISSUER, "sub_hash": sub}
        return body

    def access_token(self) -> str:
        with self._lock:
            with self.store.locked():
                record = self._read_locked()
                if record is None or not str(record.get("access_token") or ""):
                    raise XaiOAuthError("sign in again", code="needs_reauth")
                if record.get("state") == "needs_persist":
                    self._persist_locked(record)
                    record = self._read_locked() or record
                if self._should_refresh(record):
                    record = self._refresh_locked(record)
                token = str(record.get("access_token") or "")
                if not token:
                    raise XaiOAuthError("sign in again", code="needs_reauth")
                return token

    def save_pair(
        self,
        *,
        access_token: str,
        refresh_token: str,
        expires_in: int,
        account: dict[str, object],
        scope: str,
        token_endpoint: str,
    ) -> None:
        now = int(self.clock())
        record = {
            "version": 1,
            "issuer": ISSUER,
            "client_id": CLIENT_ID,
            "scope": scope,
            "token_endpoint": token_endpoint,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_at": now + max(expires_in, 0),
            "last_refresh": now,
            "account": account,
            "state": "ok",
        }
        with self._lock:
            with self.store.locked():
                self._persist_locked(record)

    def sign_out(self) -> bool:
        record = self._current()
        refresh = str((record or {}).get("refresh_token") or "")
        revoked = False
        if refresh:
            revoked = self.client.revoke(refresh)
        with self._lock:
            with self.store.locked():
                self.store.delete_tokens(issuer=ISSUER, client_id=CLIENT_ID, reason="signed_out")
                self._memory = None
        return revoked

    def start_device(self, *, session_id: str, account_id: str) -> dict[str, object]:
        started = self.client.start_device()
        now = self.clock()
        deadline = min(now + started.expires_in, now + 15 * 60)
        self.flow = PendingFlow(
            flow_id=secrets.token_hex(16),
            session_id=session_id,
            account_id=account_id,
            device_code=started.device_code,
            user_code=started.user_code,
            verification_uri=started.verification_uri,
            verification_uri_complete=started.verification_uri_complete,
            expires_at=deadline,
            interval=float(started.interval),
            next_poll=now + started.interval,
        )
        return self._public_flow(self.flow)

    def poll(self, flow_id: str, session_id: str) -> dict[str, object]:
        flow = self._owned(flow_id, session_id)
        self._tick(flow)
        return self._state(flow)

    def cancel(self, flow_id: str, session_id: str) -> None:
        flow = self._owned(flow_id, session_id)
        flow.status = "expired"
        flow.device_code = ""
        if self.flow is flow:
            self.flow = None

    def _tick(self, flow: PendingFlow) -> None:
        if flow.status != "pending":
            return
        now = self.clock()
        if now >= flow.expires_at:
            flow.status = "expired"
            flow.device_code = ""
            return
        if now < flow.next_poll:
            return
        try:
            status, pair = self.client.poll_device(flow.device_code)
        except XaiOAuthError:
            flow.status = "failed"
            flow.device_code = ""
            flow.error = "failed"
            return
        if status == "slow_down":
            flow.interval += 5
            flow.next_poll = now + flow.interval
            return
        if status == "pending":
            flow.next_poll = now + flow.interval
            return
        if status == "approved" and pair is not None:
            try:
                self.save_pair(
                    access_token=pair.access_token,
                    refresh_token=pair.refresh_token,
                    expires_in=pair.expires_in,
                    account=pair.id_claims,
                    scope=pair.scope,
                    token_endpoint=pair.token_endpoint,
                )
            except XaiOAuthError:
                flow.status = "failed"
                flow.device_code = ""
                flow.error = "failed"
                return
            flow.status = "approved"
            flow.device_code = ""
            account = pair.id_claims
            flow.account = {
                "name": str(account.get("name") or ""),
                "email": str(account.get("email") or ""),
            }
            return
        terminal = {"denied", "expired", "ineligible", "failed"}
        flow.status = status if status in terminal else "failed"
        flow.device_code = ""
        flow.error = flow.status

    def _refresh_locked(self, record: dict[str, object]) -> dict[str, object]:
        refresh = str(record.get("refresh_token") or "")
        endpoint = str(record.get("token_endpoint") or "")
        if not refresh or refresh in self._used_refresh:
            return self._quarantine_locked(record, "reused")
        if not pinned_https(endpoint):
            return self._quarantine_locked(record, "network")
        self._used_refresh.add(refresh)
        self.refresh_posts += 1
        try:
            pair = self.client.refresh(refresh, endpoint)
        except XaiOAuthError as exc:
            if exc.code == "needs_reauth":
                return self._quarantine_locked(record, "invalid_grant")
            raise
        now = int(self.clock())
        updated = dict(record)
        updated["access_token"] = pair.access_token
        updated["refresh_token"] = pair.refresh_token
        updated["expires_at"] = now + max(pair.expires_in, 0)
        updated["last_refresh"] = now
        updated["token_endpoint"] = pair.token_endpoint
        updated["state"] = "ok"
        try:
            self._persist_locked(updated)
        except StoreError:
            updated["state"] = "needs_persist"
            self._memory = updated
        return self._read_locked() or updated

    def _persist_locked(self, record: dict[str, object]) -> None:
        try:
            self.store.save(record, issuer=ISSUER, client_id=CLIENT_ID)
        except StoreError:
            record["state"] = "needs_persist"
            self._memory = dict(record)
            raise
        self._memory = None

    def _quarantine_locked(self, record: dict[str, object], reason: str) -> dict[str, object]:
        self.store.delete_tokens(issuer=ISSUER, client_id=CLIENT_ID, reason=reason)
        self._memory = None
        kept = self.store.load(issuer=ISSUER, client_id=CLIENT_ID) or {}
        return kept

    def _read_locked(self) -> dict[str, object] | None:
        if self._memory is not None and self._memory.get("state") == "needs_persist":
            return dict(self._memory)
        try:
            disk = self.store.load(issuer=ISSUER, client_id=CLIENT_ID)
        except StoreError:
            disk = None
        if disk is None:
            return self._memory
        return disk

    def _current(self) -> dict[str, object] | None:
        with self._lock:
            with self.store.locked():
                return self._read_locked()

    def _should_refresh(self, record: dict[str, object]) -> bool:
        if record.get("state") not in {"ok", "needs_persist"}:
            return False
        if not str(record.get("refresh_token") or ""):
            return False
        return self._expiring(record)

    def _expiring(self, record: dict[str, object]) -> bool:
        expires = record.get("expires_at")
        last = record.get("last_refresh")
        if not isinstance(expires, int):
            return True
        now = self.clock()
        lifetime = expires - int(last) if isinstance(last, int) else expires - now
        lead = max(120, min(600, 0.25 * max(lifetime, 0)))
        return expires - now < lead

    def _owned(self, flow_id: str, session_id: str) -> PendingFlow:
        flow = self.flow
        if flow is None or flow.flow_id != flow_id:
            raise XaiOAuthError("that sign-in is not active", code="not_found")
        if flow.session_id != session_id:
            raise XaiOAuthError("that sign-in belongs to another session", code="forbidden")
        return flow

    def _public_flow(self, flow: PendingFlow) -> dict[str, object]:
        return {
            "flowId": flow.flow_id,
            "userCode": flow.user_code,
            "verificationUri": flow.verification_uri,
            "verificationUriComplete": flow.verification_uri_complete,
            "expiresAt": int(flow.expires_at),
            "interval": int(flow.interval),
        }

    def _state(self, flow: PendingFlow) -> dict[str, object]:
        body: dict[str, object] = {"status": flow.status}
        if flow.status == "approved":
            body["account"] = {
                "name": flow.account.get("name", ""),
                "email": flow.account.get("email", ""),
            }
        if flow.error and flow.status != "approved":
            body["error"] = flow.error
        return body


    def credential_for_worker(self) -> dict[str, object]:
        """Access token only. The refresh token stays in this process."""
        token = self.access_token()
        record = self._current() or {}
        expires = record.get("expires_at")
        return {
            "accessToken": token,
            "expiresAt": int(expires) if isinstance(expires, int) else 0,
        }


_process_brokers: dict[str, ProviderAuthBroker] = {}
_process_brokers_lock = threading.Lock()


def process_broker(config_dir: Path, fetcher: Fetcher | None = None) -> ProviderAuthBroker:
    """One broker per config directory for this process.

    A directory that already has a broker keeps that instance, including its fetcher.
    """
    key = str(Path(config_dir).resolve())
    with _process_brokers_lock:
        held = _process_brokers.get(key)
        if held is not None:
            return held
        if fetcher is None:
            # Late import: onboarding.service imports this module.
            from praxis_prime.onboarding.probe import fetch as probe_fetch

            fetcher = probe_fetch
        created = ProviderAuthBroker(config_dir, fetcher)
        _process_brokers[key] = created
        return created


def _missing_fetcher(*_args: object, **_kwargs: object) -> object:
    raise XaiOAuthError("no auth fetcher is configured", code="network")


_worker_token_fn: Callable[[], str] | None = None


def install_worker_token(fn: Callable[[], str] | None) -> None:
    """Worker process hook. The factory calls this instead of opening the store."""
    global _worker_token_fn
    _worker_token_fn = fn


def take_worker_token() -> str:
    fn = _worker_token_fn
    if fn is None:
        return ""
    try:
        return str(fn() or "")
    except (OSError, RuntimeError, ValueError):
        return ""
