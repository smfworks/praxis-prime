"""WebAuthn ceremonies for the loopback daemon.

The relying party id is the browser origin host, ``localhost`` or
``127.0.0.1``. A credential is bound to the id it was registered with.
There is no attestation service and no phone-home. Verification uses the
``webauthn`` library locally.

docs/blueprint-addendum-2026-09.md §4.3.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.authentication.verify_authentication_response import VerifiedAuthentication
from webauthn.helpers import base64url_to_bytes, parse_client_data_json
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.registration.verify_registration_response import VerifiedRegistration

RP_NAME = "Praxis Prime"
_MAX_FIELD = 8192


@dataclass(frozen=True, slots=True)
class Ceremony:
    challenge: bytes
    rp_id: str
    origin: str
    options: dict[str, object]


def loopback_ceremony(origin_header: str, port: int) -> tuple[str, str] | None:
    """Return ``(rp_id, origin)`` for this daemon port, or None.

    An empty Origin header defaults to ``http://localhost:<port>``, which is
    the name passkeys should use. ``http://127.0.0.1:<port>`` is the other
    allowed origin. The two ids are not interchangeable.
    """
    if port <= 0 or port > 65535:
        return None
    if not origin_header:
        return "localhost", f"http://localhost:{port}"
    parsed = _origin(origin_header, port)
    if parsed is None:
        return None
    host = parsed
    return host, f"http://{host}:{port}"


def registration_options(
    *,
    rp_id: str,
    origin: str,
    user_id: bytes,
    user_name: str,
    user_display_name: str,
    exclude: list[bytes],
) -> Ceremony:
    excluded = [PublicKeyCredentialDescriptor(id=item) for item in exclude] or None
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_id=user_id,
        user_name=user_name,
        user_display_name=user_display_name,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        exclude_credentials=excluded,
    )
    return Ceremony(
        challenge=options.challenge,
        rp_id=rp_id,
        origin=origin,
        options=_options_dict(options),
    )


def authentication_options(*, rp_id: str, origin: str, allow: list[bytes]) -> Ceremony:
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[PublicKeyCredentialDescriptor(id=item) for item in allow] or None,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return Ceremony(
        challenge=options.challenge,
        rp_id=rp_id,
        origin=origin,
        options=_options_dict(options),
    )


def verify_registration(
    credential: dict[str, object],
    *,
    challenge: bytes,
    rp_id: str,
    origin: str,
) -> VerifiedRegistration:
    return verify_registration_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=rp_id,
        expected_origin=origin,
        require_user_verification=False,
    )


def verify_authentication(
    credential: dict[str, object],
    *,
    challenge: bytes,
    rp_id: str,
    origin: str,
    public_key: bytes,
    sign_count: int,
) -> VerifiedAuthentication:
    return verify_authentication_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=rp_id,
        expected_origin=origin,
        credential_public_key=public_key,
        credential_current_sign_count=sign_count,
        require_user_verification=False,
    )


def client_challenge(credential: object) -> bytes | None:
    if not isinstance(credential, dict):
        return None
    response = credential.get("response")
    if not isinstance(response, dict):
        return None
    encoded = response.get("clientDataJSON")
    if not isinstance(encoded, str) or not encoded or len(encoded) > _MAX_FIELD:
        return None
    try:
        parsed = parse_client_data_json(base64url_to_bytes(encoded))
    except (WebAuthnException, ValueError):
        return None
    challenge = parsed.challenge
    if not isinstance(challenge, bytes) or not challenge or len(challenge) > 256:
        return None
    return challenge


def credential_id(credential: object) -> bytes | None:
    if not isinstance(credential, dict):
        return None
    raw = credential.get("rawId")
    if not isinstance(raw, str) or not raw or len(raw) > _MAX_FIELD:
        return None
    try:
        decoded = base64url_to_bytes(raw)
    except (WebAuthnException, ValueError):
        return None
    if not decoded or len(decoded) > 1024:
        return None
    return decoded


def _options_dict(options: object) -> dict[str, object]:
    parsed = json.loads(options_to_json(options))
    if not isinstance(parsed, dict):
        raise RuntimeError("webauthn options were not an object")
    return parsed


def _origin(value: str, port: int) -> str | None:
    if len(value) > 200 or any(ord(char) < 33 for char in value):
        return None
    if not value.startswith("http://"):
        return None
    rest = value[len("http://") :]
    if not rest or any(char in rest for char in "/?#\\"):
        return None
    if rest.count(":") != 1:
        return None
    host, port_text = rest.rsplit(":", 1)
    if host not in {"localhost", "127.0.0.1"}:
        return None
    if not port_text.isdigit() or int(port_text) != port:
        return None
    return host
