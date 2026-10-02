"""In-process passkey for tests. It does not talk to a network or a device."""

from __future__ import annotations

import hashlib
import json
import secrets

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers import bytes_to_base64url


class SoftPasskey:
    """P-256 authenticator that speaks the JSON shape ``navigator.credentials`` returns."""

    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = secrets.token_bytes(32)
        self.counter = 0

    def register(self, options: dict[str, object], *, origin: str) -> dict[str, object]:
        rp = options.get("rp")
        rp_id = rp.get("id") if isinstance(rp, dict) else None
        if not isinstance(rp_id, str):
            raise RuntimeError("registration options have no rp id")
        return self._credential(
            kind="webauthn.create",
            challenge=_challenge(options),
            origin=origin,
            rp_id=rp_id,
            sign_count=0,
            attested=True,
            user_handle=b"",
        )

    def authenticate(
        self,
        options: dict[str, object],
        *,
        origin: str,
        user_handle: bytes,
        sign_count: int | None = None,
    ) -> dict[str, object]:
        rp_id = options.get("rpId")
        if not isinstance(rp_id, str):
            raise RuntimeError("authentication options have no rp id")
        if sign_count is None:
            self.counter += 1
            sign_count = self.counter
        return self._credential(
            kind="webauthn.get",
            challenge=_challenge(options),
            origin=origin,
            rp_id=rp_id,
            sign_count=sign_count,
            attested=False,
            user_handle=user_handle,
        )

    def _credential(
        self,
        *,
        kind: str,
        challenge: str,
        origin: str,
        rp_id: str,
        sign_count: int,
        attested: bool,
        user_handle: bytes,
    ) -> dict[str, object]:
        client = json.dumps(
            {
                "type": kind,
                "challenge": challenge,
                "origin": origin,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        flags = 0x01 | 0x04
        auth_data = hashlib.sha256(rp_id.encode("utf-8")).digest()
        auth_data += bytes([flags | (0x40 if attested else 0)])
        auth_data += sign_count.to_bytes(4, "big")
        if attested:
            auth_data += bytes(16)
            auth_data += len(self.credential_id).to_bytes(2, "big")
            auth_data += self.credential_id
            auth_data += _cose(self._key.public_key())
        encoded_id = bytes_to_base64url(self.credential_id)
        if attested:
            attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
            response: dict[str, object] = {
                "clientDataJSON": bytes_to_base64url(client),
                "attestationObject": bytes_to_base64url(attestation),
            }
        else:
            signature = self._key.sign(
                auth_data + hashlib.sha256(client).digest(),
                ec.ECDSA(hashes.SHA256()),
            )
            response = {
                "clientDataJSON": bytes_to_base64url(client),
                "authenticatorData": bytes_to_base64url(auth_data),
                "signature": bytes_to_base64url(signature),
                "userHandle": bytes_to_base64url(user_handle),
            }
        return {
            "id": encoded_id,
            "rawId": encoded_id,
            "type": "public-key",
            "response": response,
        }


def _challenge(options: dict[str, object]) -> str:
    value = options.get("challenge")
    if not isinstance(value, str) or not value:
        raise RuntimeError("options have no challenge")
    return value


def _cose(public_key: ec.EllipticCurvePublicKey) -> bytes:
    numbers = public_key.public_numbers()
    return cbor2.dumps(
        {
            1: 2,
            3: -7,
            -1: 1,
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }
    )
