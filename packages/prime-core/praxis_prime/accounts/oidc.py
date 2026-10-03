"""Generic OpenID Connect sign-in for the loopback daemon.

Authorization Code with PKCE (S256), a single-use state, and a single-use
nonce. The ID token is checked against the provider's JWKS. An identity is
the provider issuer plus the subject. Email is not an identity. Linking an
existing account is a step-up action or an owner pre-link. Automatic
email linking stays off unless that provider has an allowlist, and then
only a verified address on the list can match or create an account.

The client secret is read from the secrets file. It is not stored in
``config.toml`` and it is not written to the audit log.

An OIDC sign-in is one factor. It does not mint a step-up token. When TOTP
is confirmed, the session still waits for that second factor, and a role
mapped from the provider is applied only after that code succeeds. Step-up
remains a password plus TOTP, or a passkey. The PKCE verifier stays in
process memory and is dropped when the callback uses it or it expires.

docs/blueprint-addendum-2026-09.md §4.3 and §5.4. M1e.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import re
import secrets
import socket
import sqlite3
import ssl
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlencode, urlsplit

from joserfc import jwt
from joserfc.errors import InvalidKeyIdError, JoseError
from joserfc.jwk import KeySet

from praxis_prime.accounts.db import (
    Account,
    AccountError,
    AccountStore,
    _account,
    _is_locked,
    _new_id,
    _now,
)
from praxis_prime.mcp.auth import lookup_secret
from praxis_prime.profiles.ids import username

ALLOWED_ALGS = (
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
)
CLOCK_SKEW_SECONDS = 60
# A pending sign-in occupies a slot only briefly. Spent nonces are remembered
# longer so a captured nonce cannot be replayed inside the old window.
TXN_TTL_SECONDS = 2 * 60
NONCE_TTL_SECONDS = 10 * 60
MFA_TTL_SECONDS = 5 * 60
_PENDING_CAP = 100
_PENDING_PER_CLIENT = 8
# New signed browser keys. A process that omits or forges pp_client does not
# get one of these; it stays on the single anonymous bucket.
_CLIENT_MINT_LIMIT = 20
_CLIENT_MINT_WINDOW = 60.0
_CLIENT_KEY_NAME = "oidc_client"
_HTTP_TIMEOUT = 5
_JWKS_REFRESH_SECONDS = 30.0
_DISCOVERY_LIMIT = 65_536
_TOKEN_LIMIT = 65_536
_JWKS_LIMIT = 262_144
OIDC_COOKIE = "pp_oidc"
MFA_COOKIE = "pp_mfa"
CLIENT_COOKIE = "pp_client"
CLIENT_COOKIE_TTL = 30 * 24 * 60 * 60
UNUSABLE_PASSWORD = "!"
_PROVIDER_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_LOOPBACK = frozenset({"127.0.0.1", "localhost"})
_RANK = {"viewer": 1, "auditor": 2, "operator": 3, "admin": 4}
_ROLES = frozenset(_RANK)
_PRIVILEGED = frozenset({"owner", "admin"})
# Fail closed on anything that is not a global unicast address. The explicit
# networks cover the ranges named in the review even if a Python release
# classifies one of them differently. IPv4-mapped IPv6 is checked as IPv4.
_BLOCKED_V4 = tuple(
    ipaddress.ip_network(item)
    for item in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)
_BLOCKED_V6 = tuple(
    ipaddress.ip_network(item)
    for item in (
        "::/128",
        "::1/128",
        "2001:db8::/32",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)

ENTRA_ROLE_CLAIM = "roles"
ENTRA_ROLE_MAP = {
    "Praxis.Admin": "admin",
    "Praxis.Operator": "operator",
    "Praxis.Viewer": "viewer",
    "Praxis.Auditor": "auditor",
}


class OidcError(Exception):
    """A refused OIDC step. ``reason`` is for the audit log, not the user."""

    def __init__(self, reason: str, *, status: int = 400) -> None:
        self.reason = reason
        self.status = status
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class Provider:
    id: str
    display_name: str
    issuer: str
    client_id: str
    secret_key: str
    scopes: str
    email_allowlist: tuple[str, ...]
    role_claim: str
    role_map: dict[str, str]
    dev_loopback: bool
    enabled: bool
    preset: str


@dataclass(frozen=True, slots=True)
class _Discovery:
    authorization: str
    token: str
    jwks: str


@dataclass(frozen=True, slots=True)
class _Transaction:
    provider_id: str
    nonce_hash: str
    verifier: str
    kind: str
    account_id: str
    session_id: str
    redirect_uri: str


@dataclass(frozen=True, slots=True)
class Completed:
    kind: str
    account: Account
    provider_id: str
    mapped_role: str = ""


class _Cache:
    def __init__(self, ttl: float) -> None:
        self.ttl = ttl
        self._lock = threading.Lock()
        self._items: dict[str, tuple[float, object]] = {}

    def get(self, key: str) -> object | None:
        now = time.monotonic()
        with self._lock:
            hit = self._items.get(key)
            if hit is not None and now - hit[0] < self.ttl:
                return hit[1]
        return None

    def put(self, key: str, value: object) -> None:
        with self._lock:
            self._items[key] = (time.monotonic(), value)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


_DISCOVERY = _Cache(600)
_JWKS = _Cache(3600)
_jwks_lock = threading.Lock()
_jwks_forced: dict[str, float] = {}
# state hash -> (unix expiry, verifier). Not written to accounts.db, so a
# checkpoint or a WAL frame cannot keep the verifier after it is forgotten.
_verifiers: dict[str, tuple[float, str]] = {}
_verifier_lock = threading.Lock()
_mint_lock = threading.Lock()
_mint_tokens = float(_CLIENT_MINT_LIMIT)
_mint_at = 0.0


def clear_caches() -> None:
    """Drop cached discovery documents, key sets, verifiers, and the mint bucket."""
    global _mint_tokens, _mint_at
    _DISCOVERY.clear()
    _JWKS.clear()
    with _jwks_lock:
        _jwks_forced.clear()
    with _verifier_lock:
        _verifiers.clear()
    with _mint_lock:
        _mint_tokens = float(_CLIENT_MINT_LIMIT)
        _mint_at = 0.0


def forget_pending_verifier(state: str) -> None:
    """Drop one PKCE verifier. A missing verifier cannot be exchanged."""
    if not isinstance(state, str) or not state:
        return
    with _verifier_lock:
        _verifiers.pop(_hash(state), None)


def _remember_verifier(state_hash: str, verifier: str, expires_at: float) -> None:
    with _verifier_lock:
        _drop_expired_verifiers()
        _verifiers[state_hash] = (expires_at, verifier)


def _pop_verifier(state_hash: str) -> str:
    with _verifier_lock:
        _drop_expired_verifiers()
        item = _verifiers.pop(state_hash, None)
    if item is None:
        return ""
    return item[1]


def _forget_verifier_hashes(hashes: list[str]) -> None:
    if not hashes:
        return
    with _verifier_lock:
        for item in hashes:
            _verifiers.pop(item, None)


def _drop_expired_verifiers(now: float | None = None) -> None:
    """Caller holds ``_verifier_lock``."""
    moment = time.time() if now is None else now
    stale = [key for key, (expires, _value) in _verifiers.items() if expires <= moment]
    for key in stale:
        _verifiers.pop(key, None)


def binding_cookie(token: str, *, max_age: int) -> str:
    """Short-lived cookie that binds an OIDC transaction to this browser.

    ``SameSite=Lax`` so the provider's top-level redirect still presents it.
    The session cookie stays ``SameSite=Strict`` and is a different cookie.
    """
    if max_age <= 0 or not token:
        return (
            f"{OIDC_COOKIE}=; HttpOnly; Secure; SameSite=Lax; "
            "Path=/v1/auth/oidc; Max-Age=0"
        )
    return (
        f"{OIDC_COOKIE}={token}; HttpOnly; Secure; SameSite=Lax; "
        f"Path=/v1/auth/oidc; Max-Age={max_age}"
    )


def mfa_cookie(token: str, *, max_age: int = MFA_TTL_SECONDS) -> str:
    """HttpOnly cookie holding the second-factor token after an OIDC sign-in."""
    if max_age <= 0 or not token:
        return clear_mfa_cookie()
    return (
        f"{MFA_COOKIE}={token}; HttpOnly; Secure; SameSite=Strict; "
        f"Path=/; Max-Age={max_age}"
    )


def clear_mfa_cookie() -> str:
    return f"{MFA_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"


def client_cookie(token: str, *, max_age: int = CLIENT_COOKIE_TTL) -> str:
    """Stable browser key for the pending-sign-in cap. Not a session."""
    if max_age <= 0 or not token:
        return (
            f"{CLIENT_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
        )
    return (
        f"{CLIENT_COOKIE}={token}; HttpOnly; Secure; SameSite=Lax; "
        f"Path=/; Max-Age={max_age}"
    )


def loopback_redirect(host_header: str, port: int) -> str:
    """Redirect URI on the daemon's own loopback origin. No other host."""
    name = host_header.split(":", 1)[0].strip().casefold()
    if name not in _LOOPBACK or port <= 0 or port > 65535:
        raise OidcError("bad_redirect")
    return f"http://{name}:{port}/v1/auth/oidc/callback"


def secret_name(provider_id: str) -> str:
    """Environment key for one provider's client secret. Not the secret."""
    return "PRAXIS_PRIME_OIDC_SECRET_" + provider_id.upper().replace("-", "_")


def normalize_issuer(value: str) -> str:
    """Issuer as published, apart from surrounding whitespace.

    A trailing slash is part of the identifier. ``https://x/`` and
    ``https://x`` do not match. Discovery removes one slash only when it
    builds the well-known URL.
    """
    return value.strip()


def _discovery_url(issuer: str) -> str:
    """OpenID Connect Discovery 1.0 §4. One terminating slash is removed."""
    base = issuer[:-1] if issuer.endswith("/") else issuer
    return base + "/.well-known/openid-configuration"


def add_provider(
    store: AccountStore,
    *,
    provider_id: str,
    display_name: str,
    issuer: str,
    client_id: str,
    secret_key: str,
    scopes: str = "openid email profile",
    email_allowlist: tuple[str, ...] = (),
    role_claim: str = "",
    role_map: Mapping[str, str] | None = None,
    dev_loopback: bool = False,
    preset: str = "",
) -> Provider:
    """Insert a provider and read its discovery document once.

    ``secret_key`` is the name of the secret, never the secret itself.
    """
    checked = _provider_id(provider_id)
    shown = _display(display_name)
    normalized = normalize_issuer(issuer)
    _require_issuer(normalized, dev_loopback=dev_loopback)
    client = _client_id(client_id)
    scope = _scopes(scopes)
    allow = _allowlist(email_allowlist)
    claim, mapping = _role_config(role_claim, role_map or {})
    discover(normalized, dev_loopback=dev_loopback, force=True)
    now = _now()
    with store._lock:
        try:
            store.conn.execute(
                """
                INSERT INTO oidc_providers (
                    id, display_name, issuer, client_id, secret_key, scopes,
                    email_allowlist, role_claim, role_map, dev_loopback,
                    enabled, preset, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    checked,
                    shown,
                    normalized,
                    client,
                    secret_key,
                    scope,
                    json.dumps(list(allow), separators=(",", ":")),
                    claim,
                    json.dumps(mapping, sort_keys=True, separators=(",", ":")),
                    1 if dev_loopback else 0,
                    preset,
                    now,
                ),
            )
            store.conn.commit()
        except sqlite3.IntegrityError as exc:
            store.conn.rollback()
            raise OidcError("provider_exists") from exc
    found = get_provider(store, checked)
    if found is None:
        raise OidcError("unknown_provider")
    return found


def list_providers(store: AccountStore) -> list[Provider]:
    with store._lock:
        rows = store.conn.execute(
            "SELECT * FROM oidc_providers ORDER BY id"
        ).fetchall()
    return [_provider(row) for row in rows]


def get_provider(store: AccountStore, provider_id: str) -> Provider | None:
    checked = _provider_id(provider_id) if isinstance(provider_id, str) else None
    if checked is None:
        return None
    with store._lock:
        row = store.conn.execute(
            "SELECT * FROM oidc_providers WHERE id = ?",
            (checked,),
        ).fetchone()
    if row is None or not int(row["enabled"]):
        return None
    return _provider(row)


def public_providers(store: AccountStore) -> list[dict[str, str]]:
    """Names the login page may show. No client id and no secret."""
    return [
        {"id": item.id, "displayName": item.display_name}
        for item in list_providers(store)
        if item.enabled
    ]


def remove_provider(store: AccountStore, provider_id: str) -> str:
    """Delete a provider and its links, unless that would remove a last factor.

    Returns the secret key name so the caller can delete the secret.
    """
    provider = get_provider(store, provider_id)
    if provider is None:
        raise OidcError("unknown_provider")
    with store._lock:
        store.conn.execute("BEGIN IMMEDIATE")
        try:
            rows = store.conn.execute(
                "SELECT account_id FROM oidc_identities WHERE issuer = ?",
                (provider.issuer,),
            ).fetchall()
            for row in rows:
                if _removes_last_factor(store.conn, str(row["account_id"])):
                    raise OidcError("last_factor", status=409)
            store.conn.execute(
                "DELETE FROM oidc_identities WHERE issuer = ?",
                (provider.issuer,),
            )
            store.conn.execute("DELETE FROM oidc_providers WHERE id = ?", (provider.id,))
            store.conn.commit()
        except Exception:
            store.conn.rollback()
            raise
    return provider.secret_key


def prelink(
    store: AccountStore,
    *,
    username_text: str,
    issuer: str,
    subject: str,
) -> Account:
    """Attach ``iss`` + ``sub`` to an existing account. Owner CLI only."""
    provider = _provider_by_issuer(store, normalize_issuer(issuer))
    if provider is None:
        raise OidcError("unknown_provider")
    account = store.get_username(username_text)
    if account is None or account.status != "active":
        raise AccountError("no such account")
    sub = _subject(subject)
    with store._lock:
        store.conn.execute("BEGIN IMMEDIATE")
        try:
            _insert_identity(
                store.conn,
                issuer=provider.issuer,
                subject=sub,
                account_id=account.id,
                provider_id=provider.id,
                email="",
            )
            store.conn.commit()
        except Exception:
            store.conn.rollback()
            raise
    return account


def list_identities(store: AccountStore, account_id: str) -> list[dict[str, str]]:
    with store._lock:
        rows = store.conn.execute(
            """
            SELECT i.issuer, i.subject, i.provider_id, i.email, i.linked_at,
                   p.display_name
            FROM oidc_identities AS i
            LEFT JOIN oidc_providers AS p ON p.id = i.provider_id
            WHERE i.account_id = ?
            ORDER BY i.linked_at
            """,
            (account_id,),
        ).fetchall()
    items: list[dict[str, str]] = []
    for row in rows:
        items.append(
            {
                "issuer": str(row["issuer"]),
                "subject": str(row["subject"]),
                "providerId": str(row["provider_id"]),
                "displayName": str(row["display_name"] or row["issuer"]),
                "email": str(row["email"]),
                "linkedAt": str(row["linked_at"]),
            }
        )
    return items


def unlink_allowed(store: AccountStore, account_id: str, issuer: str, subject: str) -> None:
    """Raise before a step-up token is spent when the change must not happen."""
    with store._lock:
        row = store.conn.execute(
            """
            SELECT 1 FROM oidc_identities
            WHERE account_id = ? AND issuer = ? AND subject = ?
            """,
            (account_id, normalize_issuer(issuer), subject),
        ).fetchone()
        if row is None:
            raise OidcError("not_linked")
        if _removes_last_factor(store.conn, account_id):
            raise OidcError("last_factor", status=409)


def unlink(store: AccountStore, account_id: str, issuer: str, subject: str) -> None:
    """Remove one linked identity. Refuses to remove the last sign-in factor."""
    normalized = normalize_issuer(issuer)
    sub = _subject(subject)
    with store._lock:
        store.conn.execute("BEGIN IMMEDIATE")
        try:
            row = store.conn.execute(
                """
                SELECT 1 FROM oidc_identities
                WHERE account_id = ? AND issuer = ? AND subject = ?
                """,
                (account_id, normalized, sub),
            ).fetchone()
            if row is None:
                raise OidcError("not_linked")
            if _removes_last_factor(store.conn, account_id):
                raise OidcError("last_factor", status=409)
            store.conn.execute(
                """
                DELETE FROM oidc_identities
                WHERE account_id = ? AND issuer = ? AND subject = ?
                """,
                (account_id, normalized, sub),
            )
            store.conn.commit()
        except Exception:
            store.conn.rollback()
            raise


def begin(
    store: AccountStore,
    *,
    provider_id: str,
    redirect_uri: str,
    kind: str,
    account_id: str = "",
    session_id: str = "",
    client_key: str = "",
) -> tuple[str, str]:
    """Start a transaction. Returns the authorization URL and the binding token.

    ``client_key`` is a verified browser id or the signed-in session id.
    An empty key is the one anonymous bucket. One client can hold only a
    few unused sign-ins. When the global pool is full, the oldest unused
    row is dropped so the pool cannot be held shut. The per-client cap is
    applied first. The PKCE verifier is kept in memory, not in the database.
    """
    if kind not in {"login", "link"}:
        raise OidcError("bad_request")
    if not redirect_uri.startswith("http://127.0.0.1:") and not redirect_uri.startswith(
        "http://localhost:"
    ):
        raise OidcError("bad_redirect")
    if not redirect_uri.endswith("/v1/auth/oidc/callback"):
        raise OidcError("bad_redirect")
    provider = get_provider(store, provider_id)
    if provider is None:
        raise OidcError("unknown_provider")
    if kind == "link" and (not account_id or not session_id):
        raise OidcError("session_expired", status=401)
    document = discover(provider.issuer, dev_loopback=provider.dev_loopback)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)
    binding = secrets.token_urlsafe(32)
    expires = (datetime.now(UTC).timestamp()) + TXN_TTL_SECONDS
    expires_at = datetime.fromtimestamp(expires, UTC).isoformat(timespec="seconds")
    client = _client_key(client_key)
    state_hash = _hash(state)
    with store._lock:
        store.conn.execute("BEGIN IMMEDIATE")
        try:
            _sweep_pending(store)
            mine = store.conn.execute(
                """
                SELECT COUNT(*) AS n FROM oidc_transactions
                WHERE used = 0 AND client_key = ?
                """,
                (client,),
            ).fetchone()
            if mine is not None and int(mine["n"]) >= _PENDING_PER_CLIENT:
                raise OidcError("busy", status=429)
            pending = store.conn.execute(
                "SELECT COUNT(*) AS n FROM oidc_transactions WHERE used = 0"
            ).fetchone()
            while pending is not None and int(pending["n"]) >= _PENDING_CAP:
                _evict_oldest_pending(store)
                pending = store.conn.execute(
                    "SELECT COUNT(*) AS n FROM oidc_transactions WHERE used = 0"
                ).fetchone()
            store.conn.execute(
                """
                INSERT INTO oidc_transactions (
                    state_hash, binding_hash, provider_id, nonce_hash, verifier,
                    kind, account_id, session_id, redirect_uri, expires_at,
                    used, created_at, client_key
                ) VALUES (?, ?, ?, ?, '', ?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (
                    state_hash,
                    _hash(binding),
                    provider.id,
                    _hash(nonce),
                    kind,
                    account_id,
                    session_id,
                    redirect_uri,
                    expires_at,
                    _now(),
                    client,
                ),
            )
            store.conn.commit()
        except Exception:
            store.conn.rollback()
            raise
    _remember_verifier(state_hash, verifier, expires)
    query = urlencode(
        {
            "response_type": "code",
            "client_id": provider.client_id,
            "redirect_uri": redirect_uri,
            "scope": provider.scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": _s256(verifier),
            "code_challenge_method": "S256",
        }
    )
    joiner = "&" if "?" in document.authorization else "?"
    return document.authorization + joiner + query, binding


def abandon(store: AccountStore, state: str) -> None:
    """Close a transaction when the provider returned an error."""
    if not isinstance(state, str) or not state or len(state) > 256:
        return
    digest = _hash(state)
    with store._lock:
        store.conn.execute(
            """
            UPDATE oidc_transactions
            SET used = 1, verifier = ''
            WHERE state_hash = ? AND used = 0
            """,
            (digest,),
        )
        store.conn.commit()
    _forget_verifier_hashes([digest])


def transaction_kind(store: AccountStore, state: str) -> tuple[str, str]:
    """``(kind, provider id)`` for a stored state. Empty strings when it is gone."""
    if not isinstance(state, str) or not state or len(state) > 256:
        return "", ""
    with store._lock:
        row = store.conn.execute(
            "SELECT kind, provider_id FROM oidc_transactions WHERE state_hash = ?",
            (_hash(state),),
        ).fetchone()
    if row is None or str(row["kind"]) not in {"login", "link"}:
        return "", ""
    return str(row["kind"]), str(row["provider_id"])


def complete(
    store: AccountStore,
    *,
    state: str,
    binding: str,
    code: str,
    scrub: Callable[[str], None] | None = None,
) -> Completed:
    """Exchange one code and resolve the account. Does not open a session."""
    transaction = _take(store, state, binding)
    if not isinstance(code, str) or not code or len(code) > 2048:
        raise OidcError("missing_code")
    provider = get_provider(store, transaction.provider_id)
    if provider is None:
        raise OidcError("unknown_provider")
    document = discover(provider.issuer, dev_loopback=provider.dev_loopback)
    raw = _exchange(
        provider,
        document,
        code=code,
        redirect_uri=transaction.redirect_uri,
        verifier=transaction.verifier,
        scrub=scrub,
    )
    claims = _id_token(raw, provider, document, nonce_hash=transaction.nonce_hash)
    _spend_nonce(store, str(claims["nonce"]))
    if transaction.kind == "link":
        account = _link_callback(store, provider, claims, transaction)
        return Completed(kind="link", account=account, provider_id=provider.id)
    account = _login_account(store, provider, claims)
    mapped = _mapped_role(provider, claims) or ""
    return Completed(
        kind="login",
        account=account,
        provider_id=provider.id,
        mapped_role=mapped,
    )


def discover(issuer: str, *, dev_loopback: bool, force: bool = False) -> _Discovery:
    """Fetch ``.well-known/openid-configuration``. HTTPS, or explicit loopback."""
    exact = normalize_issuer(issuer)
    _require_issuer(exact, dev_loopback=dev_loopback)
    if not force:
        cached = _DISCOVERY.get(exact)
        if isinstance(cached, _Discovery):
            return cached
    url = _discovery_url(exact)
    document = _get_json(url, allow_http=dev_loopback, limit=_DISCOVERY_LIMIT)
    parsed = _parse_discovery(document, exact, allow_http=dev_loopback)
    _DISCOVERY.put(exact, parsed)
    return parsed


def _take(store: AccountStore, state: str, binding: str) -> _Transaction:
    if not isinstance(state, str) or not state or len(state) > 256:
        raise OidcError("bad_state")
    if not isinstance(binding, str) or not binding or len(binding) > 256:
        raise OidcError("bad_binding")
    state_hash = _hash(state)
    binding_hash = _hash(binding)
    taken: sqlite3.Row | None = None
    with store._lock:
        store.conn.execute("BEGIN IMMEDIATE")
        committed = False
        try:
            row = store.conn.execute(
                "SELECT * FROM oidc_transactions WHERE state_hash = ?",
                (state_hash,),
            ).fetchone()
            if row is None:
                raise OidcError("bad_state")
            if int(row["used"]):
                raise OidcError("reused_state")
            if str(row["expires_at"]) <= _now():
                store.conn.execute(
                    """
                    UPDATE oidc_transactions
                    SET used = 1, verifier = ''
                    WHERE state_hash = ?
                    """,
                    (state_hash,),
                )
                store.conn.commit()
                committed = True
                _forget_verifier_hashes([state_hash])
                raise OidcError("bad_state")
            if not hmac.compare_digest(str(row["binding_hash"]), binding_hash):
                # A wrong cookie must not burn the victim's transaction.
                store.conn.commit()
                committed = True
                raise OidcError("bad_binding")
            cursor = store.conn.execute(
                """
                UPDATE oidc_transactions
                SET used = 1, verifier = ''
                WHERE state_hash = ? AND used = 0
                """,
                (state_hash,),
            )
            if cursor.rowcount != 1:
                raise OidcError("reused_state")
            store.conn.commit()
            committed = True
            taken = row
        except OidcError:
            if not committed:
                store.conn.rollback()
            raise
        except Exception:
            store.conn.rollback()
            raise
    verifier = _pop_verifier(state_hash)
    if taken is None or not verifier:
        raise OidcError("missing_pkce")
    return _Transaction(
        provider_id=str(taken["provider_id"]),
        nonce_hash=str(taken["nonce_hash"]),
        verifier=verifier,
        kind=str(taken["kind"]),
        account_id=str(taken["account_id"]),
        session_id=str(taken["session_id"]),
        redirect_uri=str(taken["redirect_uri"]),
    )


def _exchange(
    provider: Provider,
    document: _Discovery,
    *,
    code: str,
    redirect_uri: str,
    verifier: str,
    scrub: Callable[[str], None] | None,
) -> str:
    if not verifier:
        raise OidcError("missing_pkce")
    secret = lookup_secret(provider.secret_key)
    if not secret:
        raise OidcError("secret_missing")
    if scrub is not None:
        scrub(secret)
    body = urlencode(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": provider.client_id,
            "client_secret": secret,
            "code_verifier": verifier,
        }
    ).encode("utf-8")
    raw = _request(
        document.token,
        method="POST",
        body=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        allow_http=provider.dev_loopback,
        limit=_TOKEN_LIMIT,
    )
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise OidcError("token_rejected") from exc
    if not isinstance(payload, dict) or payload.get("error"):
        raise OidcError("token_rejected")
    token = payload.get("id_token")
    if not isinstance(token, str) or token.count(".") != 2 or len(token) > 16_384:
        raise OidcError("missing_id_token")
    return token


def _id_token(
    token: str,
    provider: Provider,
    document: _Discovery,
    *,
    nonce_hash: str,
) -> dict[str, object]:
    keys = _jwks(provider, document, force=False)
    try:
        decoded = _decode(token, keys)
    except OidcError as exc:
        if exc.reason not in {"unknown_kid", "bad_signature"}:
            raise
        keys = _jwks(provider, document, force=True)
        try:
            decoded = _decode(token, keys)
        except OidcError as again:
            if again.reason == "alg_rejected":
                raise
            raise OidcError("bad_signature") from again
    claims = decoded.claims
    if not isinstance(claims, dict):
        raise OidcError("malformed")
    _check_claims(claims, provider, nonce_hash=nonce_hash)
    return claims


def _decode(token: str, keys: KeySet) -> jwt.Token:
    header = _unverified_header(token)
    alg = header.get("alg")
    if not isinstance(alg, str) or not _alg_allowed(alg):
        raise OidcError("alg_rejected")
    try:
        return jwt.decode(token, keys, algorithms=list(ALLOWED_ALGS))
    except InvalidKeyIdError as exc:
        raise OidcError("unknown_kid") from exc
    except JoseError as exc:
        raise OidcError("bad_signature") from exc


def _jwks(provider: Provider, document: _Discovery, *, force: bool) -> KeySet:
    if not force:
        cached = _JWKS.get(document.jwks)
        if isinstance(cached, KeySet):
            return cached
    elif not _jwks_refresh_allowed(provider.id):
        cached = _JWKS.get(document.jwks)
        if isinstance(cached, KeySet):
            return cached
        raise OidcError("bad_signature")
    payload = _get_json(document.jwks, allow_http=provider.dev_loopback, limit=_JWKS_LIMIT)
    if not isinstance(payload, dict) or not isinstance(payload.get("keys"), list):
        raise OidcError("bad_signature")
    try:
        keys = KeySet.import_key_set(payload)
    except (ValueError, JoseError, TypeError) as exc:
        raise OidcError("bad_signature") from exc
    _JWKS.put(document.jwks, keys)
    return keys


def _check_claims(claims: Mapping[str, object], provider: Provider, *, nonce_hash: str) -> None:
    iss = claims.get("iss")
    if not isinstance(iss, str) or iss != provider.issuer:
        raise OidcError("bad_issuer")
    _check_audience(claims, provider.client_id)
    _check_time(claims)
    nonce = claims.get("nonce")
    if not isinstance(nonce, str) or not nonce or len(nonce) > 256:
        raise OidcError("bad_nonce")
    if not hmac.compare_digest(_hash(nonce), nonce_hash):
        raise OidcError("bad_nonce")
    _subject(claims.get("sub"))


def _check_audience(claims: Mapping[str, object], client_id: str) -> None:
    aud = claims.get("aud")
    if isinstance(aud, str):
        audiences = [aud]
    elif isinstance(aud, list) and aud and all(isinstance(item, str) for item in aud):
        audiences = [str(item) for item in aud]
    else:
        raise OidcError("bad_audience")
    if client_id not in audiences:
        raise OidcError("bad_audience")
    azp = claims.get("azp")
    if len(audiences) > 1 and "azp" not in claims:
        raise OidcError("bad_azp")
    if "azp" in claims and (not isinstance(azp, str) or azp != client_id):
        raise OidcError("bad_azp")


def _check_time(claims: Mapping[str, object]) -> None:
    now = int(datetime.now(UTC).timestamp())
    exp = _epoch(claims.get("exp"))
    iat = _epoch(claims.get("iat"))
    if exp is None or iat is None or exp < iat:
        raise OidcError("bad_time")
    if now > exp + CLOCK_SKEW_SECONDS:
        raise OidcError("expired")
    if iat > now + CLOCK_SKEW_SECONDS:
        raise OidcError("bad_time")
    if "nbf" in claims and claims.get("nbf") is not None:
        nbf = _epoch(claims.get("nbf"))
        if nbf is None or nbf > now + CLOCK_SKEW_SECONDS:
            raise OidcError("bad_time")


def _spend_nonce(store: AccountStore, nonce: str) -> None:
    digest = _hash(nonce)
    expires = datetime.fromtimestamp(
        datetime.now(UTC).timestamp() + NONCE_TTL_SECONDS,
        UTC,
    ).isoformat(timespec="seconds")
    with store._lock:
        store.conn.execute("BEGIN IMMEDIATE")
        try:
            store.conn.execute("DELETE FROM oidc_spent WHERE expires_at <= ?", (_now(),))
            found = store.conn.execute(
                "SELECT 1 FROM oidc_spent WHERE nonce_hash = ?",
                (digest,),
            ).fetchone()
            if found is not None:
                raise OidcError("reused_nonce")
            store.conn.execute(
                "INSERT INTO oidc_spent (nonce_hash, expires_at) VALUES (?, ?)",
                (digest, expires),
            )
            store.conn.commit()
        except Exception:
            store.conn.rollback()
            raise


def _login_account(
    store: AccountStore, provider: Provider, claims: Mapping[str, object]
) -> Account:
    subject = _subject(claims.get("sub"))
    with store._lock:
        store.conn.execute("BEGIN IMMEDIATE")
        try:
            existing = store.conn.execute(
                """
                SELECT account_id FROM oidc_identities
                WHERE issuer = ? AND subject = ?
                """,
                (provider.issuer, subject),
            ).fetchone()
            if existing is not None:
                account = _active_account(store.conn, str(existing["account_id"]))
                store.conn.commit()
            else:
                account = _allowlist_account(store, provider, claims, subject)
                store.conn.commit()
        except Exception:
            store.conn.rollback()
            raise
    return account


def apply_mapped_role(store: AccountStore, account: Account, role: str) -> Account:
    """Apply a provider role after sign-in has finished.

    An account that still needs TOTP keeps its current role. The owner role
    is never granted or changed.
    """
    if not role or role == account.role or account.role == "owner" or role not in _ROLES:
        return account
    try:
        return store.set_server_role(account.username, role)
    except AccountError:
        return account


def _allowlist_account(
    store: AccountStore,
    provider: Provider,
    claims: Mapping[str, object],
    subject: str,
) -> Account:
    """Caller holds the account lock and an open transaction."""
    if not provider.email_allowlist:
        raise OidcError("not_linked")
    if claims.get("email_verified") is not True:
        raise OidcError("email_unverified")
    raw_mail = claims.get("email")
    mail = _ascii_email(raw_mail)
    if not mail or mail not in provider.email_allowlist:
        raise OidcError("email_not_allowed")
    rows = store.conn.execute(
        "SELECT id, email, status, role FROM accounts WHERE email != ''"
    ).fetchall()
    matches = [
        row
        for row in rows
        if _ascii_email(row["email"]) == mail and str(row["status"]) == "active"
    ]
    if len(matches) > 1:
        raise OidcError("email_ambiguous")
    if len(matches) == 1:
        account = _active_account(store.conn, str(matches[0]["id"]))
        if account.role in _PRIVILEGED:
            raise OidcError("privileged_link")
        _insert_identity(
            store.conn,
            issuer=provider.issuer,
            subject=subject,
            account_id=account.id,
            provider_id=provider.id,
            email=mail,
        )
        return account
    owner = store.conn.execute(
        "SELECT 1 FROM accounts WHERE role = 'owner' LIMIT 1"
    ).fetchone()
    if owner is None:
        raise OidcError("not_linked")
    account = _insert_external_account(store.conn, mail)
    _insert_identity(
        store.conn,
        issuer=provider.issuer,
        subject=subject,
        account_id=account.id,
        provider_id=provider.id,
        email=mail,
    )
    return account


def _link_callback(
    store: AccountStore,
    provider: Provider,
    claims: Mapping[str, object],
    transaction: _Transaction,
) -> Account:
    subject = _subject(claims.get("sub"))
    with store._lock:
        store.conn.execute("BEGIN IMMEDIATE")
        try:
            if not _session_live(store.conn, transaction.session_id):
                raise OidcError("session_expired", status=401)
            account = _active_account(store.conn, transaction.account_id)
            _insert_identity(
                store.conn,
                issuer=provider.issuer,
                subject=subject,
                account_id=account.id,
                provider_id=provider.id,
                email=_ascii_email(claims.get("email")),
            )
            store.conn.commit()
        except Exception:
            store.conn.rollback()
            raise
    return account


def _mapped_role(provider: Provider, claims: Mapping[str, object]) -> str | None:
    if not provider.role_claim or not provider.role_map:
        return None
    raw = claims.get(provider.role_claim)
    if isinstance(raw, str):
        values = [raw]
    elif isinstance(raw, list):
        values = [item for item in raw if isinstance(item, str)]
    else:
        return None
    best = ""
    rank = 0
    for value in values:
        role = provider.role_map.get(value, "")
        score = _RANK.get(role, 0)
        if score > rank:
            best = role
            rank = score
    return best or None


def _insert_identity(
    conn: sqlite3.Connection,
    *,
    issuer: str,
    subject: str,
    account_id: str,
    provider_id: str,
    email: str,
) -> None:
    current = conn.execute(
        "SELECT account_id FROM oidc_identities WHERE issuer = ? AND subject = ?",
        (issuer, subject),
    ).fetchone()
    if current is not None:
        if str(current["account_id"]) == account_id:
            return
        raise OidcError("identity_taken")
    other = conn.execute(
        "SELECT subject FROM oidc_identities WHERE account_id = ? AND issuer = ?",
        (account_id, issuer),
    ).fetchone()
    if other is not None and str(other["subject"]) != subject:
        raise OidcError("issuer_taken")
    conn.execute(
        """
        INSERT INTO oidc_identities (
            issuer, subject, account_id, provider_id, email, linked_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (issuer, subject, account_id, provider_id, email, _now()),
    )


def _insert_external_account(conn: sqlite3.Connection, mail: str) -> Account:
    chosen = _username_for(conn, mail)
    now = _now()
    account_id = _new_id("acc")
    shown = mail.split("@", 1)[0][:80] or chosen
    conn.execute(
        """
        INSERT INTO accounts (
            id, username, display_name, email, password_hash, role,
            status, created_at, updated_at, failed_logins, locked_until
        ) VALUES (?, ?, ?, ?, ?, 'viewer', 'active', ?, ?, 0, '')
        """,
        (account_id, chosen, shown, mail, UNUSABLE_PASSWORD, now, now),
    )
    return Account(account_id, chosen, shown, mail, "viewer", "active", now)


def _username_for(conn: sqlite3.Connection, mail: str) -> str:
    local = mail.split("@", 1)[0].lower()
    cleaned = "".join(char if char.isalnum() or char in "._-" else "-" for char in local)
    cleaned = cleaned.strip("._-")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "user" + cleaned
    base = cleaned[:56]
    for index in range(20):
        trial = base if index == 0 else f"{base}-{index}"
        checked = username(trial)
        if checked is None:
            continue
        found = conn.execute(
            "SELECT 1 FROM accounts WHERE username = ?",
            (checked,),
        ).fetchone()
        if found is None:
            return checked
    return "user-" + secrets.token_hex(3)


def _active_account(conn: sqlite3.Connection, account_id: str) -> Account:
    row = conn.execute(
        """
        SELECT id, username, display_name, email, role, status, created_at,
               locked_until
        FROM accounts WHERE id = ?
        """,
        (account_id,),
    ).fetchone()
    if row is None or str(row["status"]) != "active":
        raise OidcError("disabled")
    if _is_locked(str(row["locked_until"])):
        raise OidcError("locked")
    return _account(row)


def _session_live(conn: sqlite3.Connection, session_id: str) -> bool:
    if not session_id:
        return False
    row = conn.execute(
        """
        SELECT s.revoked, s.expires_at, a.status
        FROM sessions AS s
        JOIN accounts AS a ON a.id = s.account_id
        WHERE s.id = ?
        """,
        (session_id,),
    ).fetchone()
    if row is None or int(row["revoked"]) or str(row["status"]) != "active":
        return False
    return str(row["expires_at"]) > _now()


def _removes_last_factor(conn: sqlite3.Connection, account_id: str) -> bool:
    """True when deleting one OIDC identity would leave no sign-in factor."""
    password = conn.execute(
        "SELECT password_hash FROM accounts WHERE id = ?",
        (account_id,),
    ).fetchone()
    usable = password is not None and str(password["password_hash"]).startswith("$argon2id$")
    passkeys = conn.execute(
        "SELECT COUNT(*) AS n FROM passkeys WHERE account_id = ?",
        (account_id,),
    ).fetchone()
    identities = conn.execute(
        "SELECT COUNT(*) AS n FROM oidc_identities WHERE account_id = ?",
        (account_id,),
    ).fetchone()
    has_passkey = passkeys is not None and int(passkeys["n"]) > 0
    remaining = int(identities["n"]) - 1 if identities is not None else 0
    return not usable and not has_passkey and remaining < 1


def _provider_by_issuer(store: AccountStore, issuer: str) -> Provider | None:
    with store._lock:
        row = store.conn.execute(
            "SELECT * FROM oidc_providers WHERE issuer = ? AND enabled = 1",
            (issuer,),
        ).fetchone()
    if row is None:
        return None
    return _provider(row)


def _provider(row: sqlite3.Row) -> Provider:
    try:
        allow = json.loads(str(row["email_allowlist"]))
    except json.JSONDecodeError:
        allow = []
    try:
        mapping = json.loads(str(row["role_map"]))
    except json.JSONDecodeError:
        mapping = {}
    emails = (
        tuple(item for item in allow if isinstance(item, str))
        if isinstance(allow, list)
        else ()
    )
    roles = (
        {str(key): str(value) for key, value in mapping.items() if value in _ROLES}
        if isinstance(mapping, dict)
        else {}
    )
    return Provider(
        id=str(row["id"]),
        display_name=str(row["display_name"]),
        issuer=str(row["issuer"]),
        client_id=str(row["client_id"]),
        secret_key=str(row["secret_key"]),
        scopes=str(row["scopes"]),
        email_allowlist=emails,
        role_claim=str(row["role_claim"]),
        role_map=roles,
        dev_loopback=bool(int(row["dev_loopback"])),
        enabled=bool(int(row["enabled"])),
        preset=str(row["preset"]),
    )


def _parse_discovery(document: object, issuer: str, *, allow_http: bool) -> _Discovery:
    if not isinstance(document, dict):
        raise OidcError("discovery_endpoint")
    got = document.get("issuer")
    if not isinstance(got, str) or got != issuer:
        raise OidcError("discovery_issuer")
    authorization = document.get("authorization_endpoint")
    token = document.get("token_endpoint")
    jwks = document.get("jwks_uri")
    for endpoint in (authorization, token, jwks):
        if not isinstance(endpoint, str) or not _url_allowed(endpoint, allow_http=allow_http):
            raise OidcError("discovery_endpoint")
    return _Discovery(str(authorization), str(token), str(jwks))


def _get_json(url: str, *, allow_http: bool, limit: int) -> object:
    raw = _request(
        url,
        method="GET",
        body=None,
        headers={"Accept": "application/json"},
        allow_http=allow_http,
        limit=limit,
    )
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise OidcError("provider_http") from exc


def _request(
    url: str,
    *,
    method: str,
    body: bytes | None,
    headers: dict[str, str],
    allow_http: bool,
    limit: int,
) -> bytes:
    parts = _url_allowed(url, allow_http=allow_http)
    if parts is None:
        raise OidcError("url_rejected")
    scheme, host, port, path = parts
    # Resolve before connecting. Any blocked address refuses the whole set,
    # and the socket uses the address that was checked so a later DNS answer
    # cannot point the same name at a private host.
    addresses = _resolve(host, port)
    if scheme == "http":
        if any(not _is_loopback(item) for item in addresses):
            raise OidcError("url_rejected")
    elif any(_address_blocked(item) for item in addresses):
        raise OidcError("url_rejected")
    pinned = addresses[0]
    deadline = time.monotonic() + _HTTP_TIMEOUT
    connection: http.client.HTTPConnection | None = None
    response: http.client.HTTPResponse | None = None
    payload = b""
    try:
        tls = ssl.create_default_context() if scheme == "https" else None
        connection = _BoundConnection(
            host,
            port,
            timeout=_remaining(deadline),
            pinned=pinned,
            tls=tls,
        )
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        if response.status in {301, 302, 303, 307, 308}:
            _read_bounded(response, connection, 1024, deadline)
            raise OidcError("redirect_refused")
        payload = _read_bounded(response, connection, limit + 1, deadline)
    except OidcError:
        raise
    except (OSError, http.client.HTTPException, TimeoutError) as exc:
        raise OidcError("provider_unreachable") from exc
    finally:
        if connection is not None:
            connection.close()
    if len(payload) > limit:
        raise OidcError("response_too_large")
    if response is None or response.status != 200:
        raise OidcError("provider_http")
    return payload


def _remaining(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise OidcError("provider_unreachable")
    return left


def _read_bounded(
    response: http.client.HTTPResponse,
    connection: http.client.HTTPConnection,
    limit: int,
    deadline: float,
) -> bytes:
    """Read at most ``limit`` bytes, and stop when the overall deadline passes.

    A per-read socket timeout resets every time a byte arrives, so a slow
    trickle can hold the caller for much longer than ``_HTTP_TIMEOUT``.
    """
    payload = bytearray()
    while len(payload) < limit:
        # HTTP/1.0 responses clear HTTPConnection.sock after the headers, so
        # the timeout has to be set on the socket the body is still reading.
        # read1 returns one recv. A large read() would keep going while bytes
        # trickle in and ignore this deadline.
        sock = _body_socket(response, connection)
        if sock is not None:
            sock.settimeout(_remaining(deadline))
        else:
            _remaining(deadline)
        try:
            chunk = response.read1(min(8192, limit - len(payload)))
        except TimeoutError as exc:
            raise OidcError("provider_unreachable") from exc
        if not chunk:
            break
        payload.extend(chunk)
    return bytes(payload)


def _body_socket(
    response: http.client.HTTPResponse,
    connection: http.client.HTTPConnection,
) -> socket.socket | None:
    if connection.sock is not None:
        return connection.sock
    raw: object = getattr(response, "fp", None)
    while raw is not None:
        sock = getattr(raw, "_sock", None)
        if isinstance(sock, socket.socket):
            return sock
        raw = getattr(raw, "raw", None)
    return None


class _BoundConnection(http.client.HTTPConnection):
    """Connect to the address that was checked, and keep the URL host for TLS."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        timeout: float,
        pinned: str,
        tls: ssl.SSLContext | None,
    ) -> None:
        super().__init__(host, port, timeout=timeout)
        self._pinned = pinned
        self._tls = tls

    def connect(self) -> None:
        raw = socket.create_connection((self._pinned, self.port), self.timeout)
        if self._tls is None:
            self.sock = raw
            return
        try:
            self.sock = self._tls.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def _url_allowed(url: str, *, allow_http: bool) -> tuple[str, str, int, str] | None:
    if not isinstance(url, str) or len(url) > 2048 or any(ord(char) < 33 for char in url):
        return None
    parts = urlsplit(url)
    if parts.username or parts.password or parts.fragment or parts.query and "\r" in parts.query:
        return None
    host = parts.hostname or ""
    if not host or host.endswith("."):
        return None
    if parts.scheme == "https":
        port = parts.port or 443
    elif parts.scheme == "http" and allow_http and host.casefold() in _LOOPBACK:
        port = parts.port or 80
    else:
        return None
    if port <= 0 or port > 65535:
        return None
    path = parts.path or "/"
    if parts.query:
        path = path + "?" + parts.query
    if not path.startswith("/"):
        return None
    return parts.scheme, host, port, path


def _require_issuer(issuer: str, *, dev_loopback: bool) -> None:
    if _url_allowed(issuer, allow_http=dev_loopback) is None:
        raise OidcError("url_rejected")
    parts = urlsplit(issuer)
    if parts.query or parts.fragment:
        raise OidcError("url_rejected")
    lowered = issuer.casefold()
    if "/.well-known/" in lowered or lowered.endswith("/.well-known"):
        raise OidcError("url_rejected")


def _unverified_header(token: str) -> dict[str, object]:
    piece = token.split(".", 1)[0]
    pad = "=" * (-len(piece) % 4)
    try:
        data = base64.urlsafe_b64decode(piece + pad)
        header = json.loads(data)
    except (ValueError, json.JSONDecodeError, UnicodeError) as exc:
        raise OidcError("malformed") from exc
    if not isinstance(header, dict):
        raise OidcError("malformed")
    return header


def _alg_allowed(alg: str) -> bool:
    if alg.lower() == "none" or alg.upper().startswith("HS"):
        return False
    return alg in ALLOWED_ALGS


def _s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _client_key(value: str) -> str:
    """Hash the browser key. An empty key shares one anonymous bucket."""
    if not isinstance(value, str) or not value or len(value) > 256:
        value = "\0anonymous"
    return _hash("oidc-client:" + value)


def client_binding(store: AccountStore, presented: str) -> tuple[str, list[tuple[str, str]]]:
    """Resolve ``pp_client`` for one request.

    A verified cookie returns its id and no new cookie. A missing, malformed,
    or forged cookie is the anonymous id. A fresh signed cookie is set for
    the next request when the mint limit allows it. This request does not
    use the cookie it just minted.
    """
    verified = _verified_client_id(store, presented) if presented else ""
    if verified:
        return verified, []
    minted = _mint_client_cookie(store)
    if minted is None:
        return "", []
    return "", [("Set-Cookie", client_cookie(minted))]


def _verified_client_id(store: AccountStore, presented: str) -> str:
    """The id inside a signed cookie, or ``""`` when the signature fails."""
    parts = presented.split(".")
    client_id = parts[1] if len(parts) == 3 else ""
    mac = parts[2] if len(parts) == 3 else ""
    material = client_id if client_id.isascii() and len(client_id) <= 128 else ""
    expected = hmac.new(
        _client_mac_key(store),
        f"v1.{material}".encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    presented_mac = mac if len(mac) == 64 and mac.isascii() else "0" * 64
    signed = hmac.compare_digest(presented_mac, expected)
    if (
        not signed
        or len(parts) != 3
        or parts[0] != "v1"
        or not material
        or any(char not in "0123456789abcdef" for char in mac)
    ):
        return ""
    return client_id


def _mint_client_cookie(store: AccountStore) -> str | None:
    """A new signed cookie, or None when the process is minting too quickly."""
    if not _take_client_mint():
        return None
    client_id = secrets.token_urlsafe(32)
    mac = hmac.new(
        _client_mac_key(store),
        f"v1.{client_id}".encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return f"v1.{client_id}.{mac}"


def _take_client_mint() -> bool:
    """Token bucket. About ``_CLIENT_MINT_LIMIT`` new keys per minute."""
    global _mint_tokens, _mint_at
    now = time.monotonic()
    with _mint_lock:
        if _mint_at <= 0.0:
            _mint_at = now
        else:
            rate = _CLIENT_MINT_LIMIT / _CLIENT_MINT_WINDOW
            _mint_tokens = min(float(_CLIENT_MINT_LIMIT), _mint_tokens + (now - _mint_at) * rate)
            _mint_at = now
        if _mint_tokens < 1.0:
            return False
        _mint_tokens -= 1.0
        return True


def _client_mac_key(store: AccountStore) -> bytes:
    """HMAC key for ``pp_client``. Created once and kept in ``accounts.db``."""
    with store._lock:
        row = store.conn.execute(
            "SELECT value FROM auth_meta WHERE key = ?",
            (_CLIENT_KEY_NAME,),
        ).fetchone()
        if row is not None and len(bytes(row["value"])) == 32:
            return bytes(row["value"])
        if row is not None:
            store.conn.execute(
                "DELETE FROM auth_meta WHERE key = ?",
                (_CLIENT_KEY_NAME,),
            )
        fresh = secrets.token_bytes(32)
        store.conn.execute(
            "INSERT INTO auth_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING",
            (_CLIENT_KEY_NAME, fresh),
        )
        store.conn.commit()
        stored = store.conn.execute(
            "SELECT value FROM auth_meta WHERE key = ?",
            (_CLIENT_KEY_NAME,),
        ).fetchone()
    if stored is None or len(bytes(stored["value"])) != 32:
        raise OidcError("rejected")
    return bytes(stored["value"])


def _evict_oldest_pending(store: AccountStore) -> None:
    """Drop the oldest unused sign-in and its in-memory verifier.

    The caller holds the account lock and an open write transaction.
    """
    row = store.conn.execute(
        """
        SELECT state_hash FROM oidc_transactions
        WHERE used = 0
        ORDER BY created_at ASC, state_hash ASC
        LIMIT 1
        """
    ).fetchone()
    if row is None:
        raise OidcError("busy", status=429)
    digest = str(row["state_hash"])
    store.conn.execute(
        "DELETE FROM oidc_transactions WHERE state_hash = ?",
        (digest,),
    )
    _forget_verifier_hashes([digest])


def _sweep_pending(store: AccountStore) -> None:
    """Delete expired pending rows and their in-memory verifiers.

    The caller holds the account lock and an open write transaction.
    """
    rows = store.conn.execute(
        "SELECT state_hash FROM oidc_transactions WHERE expires_at <= ?",
        (_now(),),
    ).fetchall()
    store.conn.execute(
        "DELETE FROM oidc_transactions WHERE expires_at <= ?",
        (_now(),),
    )
    _forget_verifier_hashes([str(row["state_hash"]) for row in rows])


def _jwks_refresh_allowed(provider_id: str) -> bool:
    """True when a forced JWKS refetch may run. At most once per interval."""
    now = time.monotonic()
    with _jwks_lock:
        last = _jwks_forced.get(provider_id, 0.0)
        if now - last < _JWKS_REFRESH_SECONDS:
            return False
        _jwks_forced[provider_id] = now
    return True


def _resolve(host: str, port: int) -> list[str]:
    """Addresses for ``host``. Tests replace this to avoid real DNS."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise OidcError("provider_unreachable") from exc
    found: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        address = str(sockaddr[0]).split("%", 1)[0]
        if address and address not in found:
            found.append(address)
    if not found:
        raise OidcError("provider_unreachable")
    return found


def _is_loopback(ip: str) -> bool:
    parsed = _parse_ip(ip)
    if parsed is None:
        return False
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return _is_loopback(str(parsed.ipv4_mapped))
    return bool(parsed.is_loopback)


def _address_blocked(ip: str) -> bool:
    """True for private, loopback, link-local, multicast, unspecified, or reserved."""
    parsed = _parse_ip(ip)
    if parsed is None:
        return True
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return _address_blocked(str(parsed.ipv4_mapped))
    if (
        parsed.is_unspecified
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_private
    ):
        return True
    nets = _BLOCKED_V6 if parsed.version == 6 else _BLOCKED_V4
    return any(parsed in net for net in nets)


def _parse_ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    text = ip.split("%", 1)[0].strip()
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _epoch(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = int(value)
    if number < 0 or number > 4_000_000_000:
        return None
    return number


def _provider_id(value: object) -> str:
    if not isinstance(value, str) or _PROVIDER_ID.fullmatch(value) is None:
        raise OidcError("bad_request")
    return value


def _display(value: str) -> str:
    text = " ".join(value.replace("\r", " ").replace("\n", " ").split())
    if not text or len(text) > 80:
        raise OidcError("bad_request")
    return text


def _client_id(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 200
        or any(ord(char) < 33 or char.isspace() for char in value)
    ):
        raise OidcError("bad_request")
    return value


def _scopes(value: str) -> str:
    if not isinstance(value, str) or len(value) > 200:
        raise OidcError("bad_request")
    parts = value.split()
    if "openid" not in parts or any(not part.isascii() or not part for part in parts):
        raise OidcError("bad_request")
    return " ".join(parts)


def _allowlist(values: tuple[str, ...]) -> tuple[str, ...]:
    if len(values) > 64:
        raise OidcError("bad_request")
    cleaned: list[str] = []
    for value in values:
        mail = _ascii_email(value)
        if not mail:
            raise OidcError("bad_request")
        if mail not in cleaned:
            cleaned.append(mail)
    return tuple(cleaned)


def _role_config(claim: str, mapping: Mapping[str, str]) -> tuple[str, dict[str, str]]:
    if not isinstance(claim, str) or len(claim) > 64 or any(ord(char) < 33 for char in claim):
        raise OidcError("bad_request")
    cleaned: dict[str, str] = {}
    if len(mapping) > 32:
        raise OidcError("bad_request")
    for key, value in mapping.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise OidcError("bad_request")
        if not key or len(key) > 128 or any(ord(char) < 33 for char in key):
            raise OidcError("bad_request")
        if value not in _ROLES:
            raise OidcError("bad_request")
        cleaned[key] = value
    if cleaned and not claim:
        raise OidcError("bad_request")
    return claim, cleaned


def _subject(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 255:
        raise OidcError("malformed")
    if any(ord(char) < 32 for char in value):
        raise OidcError("malformed")
    return value


def _email(value: object) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text or len(text) > 254 or any(char.isspace() for char in text) or text.count("@") != 1:
        return ""
    return text


def _ascii_email(value: object) -> str:
    """ASCII lowercasing only. Unicode casefold is not used.

    ``straße``.casefold() is ``strasse``, which would let a verified address
    match a different allowlist entry. A non-ASCII address does not match
    and cannot be stored on an allowlist.
    """
    mail = _email(value)
    if not mail or not mail.isascii():
        return ""
    return mail.lower()
