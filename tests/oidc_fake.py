"""Loopback OpenID provider for tests.

It serves discovery, a JWKS, an authorize redirect, and a token endpoint.
Tests flip the hooks on the instance to mint a bad token. Nothing here is
a production provider, and it does not write tokens to disk.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

from joserfc import jwt
from joserfc.jwk import ECKey, RSAKey


def _b64(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class FakeOidc:
    """One provider on 127.0.0.1 with an RSA key and an EC key."""

    def __init__(self, *, client_id: str, secret: str) -> None:
        self.client_id = client_id
        self._secret = secret
        self.rsa = RSAKey.generate_key(2048, auto_kid=True)
        self.ec = ECKey.generate_key("P-256", auto_kid=True)
        self._lock = threading.Lock()
        self._codes: dict[str, dict[str, str]] = {}
        self.token_hits = 0
        self.jwks_hits = 0
        self.secret_ok = False
        self.last_verifier = ""
        self.last_challenge = ""
        self.last_method = ""
        self.sign = "rsa"
        self.subject = "subject-1"
        self.email = "ada@example.com"
        self.email_verified: object = True
        self.iss: str | None = None
        self.aud: object = None
        self.include_azp = True
        self.azp: str | None = None
        self.exp: int | None = None
        self.iat: int | None = None
        self.nbf: int | None = None
        self.nonce: str | None = None
        self.roles: list[str] | None = None
        self._httpd = _Server(self)
        self.port = int(self._httpd.server_address[1])
        self.issuer = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def rotate(self) -> None:
        """Publish a new RSA key. A cached JWKS has to be fetched again."""
        with self._lock:
            self.rsa = RSAKey.generate_key(2048, auto_kid=True)

    def _public_jwks(self) -> dict[str, object]:
        with self._lock:
            keys = [self.rsa.as_dict(private=False), self.ec.as_dict(private=False)]
        return {"keys": keys}

    def _issue(self, nonce: str, client_id: str) -> str:
        now = int(time.time())
        aud = client_id if self.aud is None else self.aud
        claims: dict[str, object] = {
            "iss": self.issuer if self.iss is None else self.iss,
            "sub": self.subject,
            "aud": aud,
            "exp": now + 300 if self.exp is None else self.exp,
            "iat": now if self.iat is None else self.iat,
            "nonce": nonce if self.nonce is None else self.nonce,
            "email": self.email,
            "email_verified": self.email_verified,
        }
        if self.include_azp:
            claims["azp"] = client_id if self.azp is None else self.azp
        if self.nbf is not None:
            claims["nbf"] = self.nbf
        if self.roles is not None:
            claims["roles"] = list(self.roles)
        if self.sign == "none":
            return _b64({"alg": "none", "typ": "JWT"}) + "." + _b64(claims) + "."
        if self.sign == "hs":
            return _b64({"alg": "HS256", "typ": "JWT"}) + "." + _b64(claims) + ".sig"
        with self._lock:
            if self.sign == "ec":
                key = self.ec
                alg = "ES256"
            elif self.sign == "bad":
                key = RSAKey.generate_key(2048, parameters={"kid": self.rsa.kid})
                alg = "RS256"
            else:
                key = self.rsa
                alg = "RS256"
            header = {"alg": alg, "kid": key.kid, "typ": "JWT"}
        return jwt.encode(header, claims, key)


class _Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, fake: FakeOidc) -> None:
        self.fake = fake
        super().__init__(("127.0.0.1", 0), _Handler)


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        fake = self.server.fake
        parts = urlsplit(self.path)
        if parts.path == "/.well-known/openid-configuration":
            body = {
                "issuer": fake.issuer,
                "authorization_endpoint": f"{fake.issuer}/authorize",
                "token_endpoint": f"{fake.issuer}/token",
                "jwks_uri": f"{fake.issuer}/jwks",
            }
            self._json(body)
            return
        if parts.path == "/jwks":
            with fake._lock:
                fake.jwks_hits += 1
            self._json(fake._public_jwks())
            return
        if parts.path == "/authorize":
            self._authorize(fake, parts.query)
            return
        self._json({"error": "not_found"}, status=404)

    def do_POST(self) -> None:
        fake = self.server.fake
        if urlsplit(self.path).path != "/token":
            self._json({"error": "not_found"}, status=404)
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        form = {key: values[0] for key, values in parse_qs(raw).items() if len(values) == 1}
        with fake._lock:
            fake.token_hits += 1
            record = fake._codes.get(form.get("code", ""))
        verifier = form.get("code_verifier", "")
        fake.last_verifier = verifier
        fake.secret_ok = form.get("client_secret", "") == fake._secret
        if record is None or not verifier or not fake.secret_ok:
            self._json({"error": "invalid_grant"}, status=400)
            return
        if form.get("redirect_uri") != record["redirect"]:
            self._json({"error": "invalid_grant"}, status=400)
            return
        if _s256(verifier) != record["challenge"]:
            self._json({"error": "invalid_grant"}, status=400)
            return
        token = fake._issue(record["nonce"], form.get("client_id", ""))
        self._json({"token_type": "Bearer", "id_token": token})

    def _authorize(self, fake: FakeOidc, query: str) -> None:
        params = {key: values[0] for key, values in parse_qs(query).items() if len(values) == 1}
        redirect = params.get("redirect_uri", "")
        host = urlsplit(redirect).hostname or ""
        method = params.get("code_challenge_method", "")
        challenge = params.get("code_challenge", "")
        state = params.get("state", "")
        nonce = params.get("nonce", "")
        fake.last_method = method
        fake.last_challenge = challenge
        if host not in {"127.0.0.1", "localhost"} or method != "S256" or not challenge:
            self._json({"error": "invalid_request"}, status=400)
            return
        if not state or not nonce or params.get("client_id") != fake.client_id:
            self._json({"error": "invalid_request"}, status=400)
            return
        code = secrets.token_urlsafe(18)
        with fake._lock:
            fake._codes[code] = {"nonce": nonce, "challenge": challenge, "redirect": redirect}
        location = redirect + ("&" if "?" in redirect else "?") + urlencode(
            {"code": code, "state": state}
        )
        body = b""
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: object, *, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
