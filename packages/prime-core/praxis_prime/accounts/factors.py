"""Passkeys, TOTP, and recovery codes on top of ``accounts.db``.

Password login stays a full session until TOTP is confirmed. After that,
the password only mints a short-lived second-factor token. A passkey opens
a session on its own. Recovery codes are a one-time fallback for TOTP.

Failures share the account lockout with passwords (5 failures, 15 minutes).
A successful password does not reset second-factor failures, so a known
password cannot buy unlimited code guesses.

docs/blueprint-addendum-2026-09.md §4.3.
"""

from __future__ import annotations

import secrets
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.exceptions import WebAuthnException

from praxis_prime.accounts.db import (
    Account,
    AccountStore,
    _hash,
    _is_locked,
    _now,
)
from praxis_prime.accounts.passkeys import (
    authentication_options,
    client_challenge,
    credential_id,
    loopback_ceremony,
    registration_options,
    verify_authentication,
    verify_registration,
)
from praxis_prime.accounts.seal import (
    LEGACY_AAD,
    account_aad,
    challenge_key,
    new_key,
    seal,
    unseal,
)
from praxis_prime.accounts.totp import (
    matching_step,
    new_recovery_codes,
    new_secret,
    normalize_recovery,
    provisioning_uri,
    recovery_hash,
)

MFA_TTL_SECONDS = 5 * 60
CHALLENGE_TTL_SECONDS = 5 * 60
STEP_UP_TTL_SECONDS = 5 * 60
_OPEN_CHALLENGES = 5
_SIGNIN_AAD = b"praxis-prime-webauthn-signin-v1"
_SIGNIN_RP = 32
_SIGNIN_ORIGIN = 64
_SIGNIN_ACCOUNT = 32


class FactorError(ValueError):
    """A rejected factor change. The message includes no secret."""

    def __init__(self, message: str, *, status: int = 400, code: str = "bad_request") -> None:
        super().__init__(message)
        self.status = status
        self.code = code


@dataclass(frozen=True, slots=True)
class TotpEnrollment:
    secret: str
    otpauth_uri: str
    recovery_codes: tuple[str, ...]


class Factors:
    """Factor ceremonies for one ``AccountStore``. Uses that store's lock."""

    def __init__(self, store: AccountStore) -> None:
        self.store = store

    def totp_active(self, account_id: str) -> bool:
        with self.store._lock:
            row = self.store.conn.execute(
                "SELECT confirmed FROM totp WHERE account_id = ?",
                (account_id,),
            ).fetchone()
        return row is not None and int(row["confirmed"]) == 1

    def begin_totp(self, account_id: str) -> TotpEnrollment:
        account = self._active(account_id)
        if self.totp_active(account.id):
            raise FactorError("totp is already enrolled", status=409, code="conflict")
        secret = new_secret()
        codes = new_recovery_codes()
        now = _now()
        with self.store._lock:
            self.store.conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self.store.conn.execute(
                    "SELECT confirmed FROM totp WHERE account_id = ?",
                    (account.id,),
                ).fetchone()
                if existing is not None and int(existing["confirmed"]) == 1:
                    self.store.conn.rollback()
                    raise FactorError("totp is already enrolled", status=409, code="conflict")
                key = self._key()
                sealed = seal(key, secret.encode("ascii"), aad=account_aad(account.id))
                self.store.conn.execute("DELETE FROM totp WHERE account_id = ?", (account.id,))
                self.store.conn.execute(
                    "DELETE FROM recovery_codes WHERE account_id = ?",
                    (account.id,),
                )
                self.store.conn.execute(
                    """
                    INSERT INTO totp (
                        account_id, secret_enc, confirmed, created_at, confirmed_at, last_step
                    ) VALUES (?, ?, 0, ?, '', 0)
                    """,
                    (account.id, sealed, now),
                )
                self._insert_codes(account.id, codes, now)
                self.store.conn.commit()
            except Exception:
                self.store.conn.rollback()
                raise
        return TotpEnrollment(secret, provisioning_uri(secret, account.username), tuple(codes))

    def confirm_totp(self, account_id: str, code: str, *, now: float | None = None) -> None:
        account = self._active(account_id)
        moment = _moment(now)
        with self.store._account_gate(account.username):
            with self.store._lock:
                if self._row_locked(account.id):
                    raise FactorError("invalid code", status=401, code="unauthorized")
                row = self.store.conn.execute(
                    "SELECT secret_enc, confirmed, last_step FROM totp WHERE account_id = ?",
                    (account.id,),
                ).fetchone()
                if row is None or int(row["confirmed"]) == 1:
                    raise FactorError("totp is not pending")
                secret = self._secret(account.id, row["secret_enc"])
                step = matching_step(secret or "", code, now=moment)
                if secret is None or step is None or step <= int(row["last_step"]):
                    self.store._note_second_factor_failure(account.id)
                    raise FactorError("invalid code", status=401, code="unauthorized")
                cursor = self.store.conn.execute(
                    """
                    UPDATE totp
                    SET confirmed = 1, confirmed_at = ?, last_step = ?
                    WHERE account_id = ? AND confirmed = 0 AND last_step < ?
                    """,
                    (_now(), step, account.id, step),
                )
                if cursor.rowcount != 1:
                    self.store.conn.rollback()
                    self.store._note_second_factor_failure(account.id)
                    raise FactorError("invalid code", status=401, code="unauthorized")
                self.store.conn.execute(
                    "DELETE FROM step_up WHERE account_id = ?",
                    (account.id,),
                )
                self.store._clear_failure_counters(account.id)
                self.store.conn.commit()

    def disable_totp(self, username: str, password: str) -> Account:
        """Turn TOTP off from the CLI. The password is the OS-user check.

        The HTTP route does not call this. It requires a step-up token and
        then ``clear_totp``.
        """
        account = self.store.authenticate(username, password)
        if account is None:
            raise FactorError("invalid code", status=401, code="unauthorized")
        self.clear_totp(account.id)
        return account

    def clear_totp(self, account_id: str) -> None:
        """Delete TOTP, recovery codes, and outstanding second-factor tokens."""
        account = self._active(account_id)
        with self.store._lock:
            self.store.conn.execute("DELETE FROM totp WHERE account_id = ?", (account.id,))
            self.store.conn.execute(
                "DELETE FROM recovery_codes WHERE account_id = ?",
                (account.id,),
            )
            self.store.conn.execute(
                "UPDATE mfa_tokens SET used = 1 WHERE account_id = ? AND used = 0",
                (account.id,),
            )
            self.store._clear_failure_counters(account.id)
            self.store.conn.commit()

    def regenerate_recovery(
        self,
        account_id: str,
        code: str,
        *,
        now: float | None = None,
    ) -> tuple[str, ...]:
        account = self._active(account_id)
        if not self._consume_totp(account, code, now=now):
            raise FactorError("invalid code", status=401, code="unauthorized")
        codes = new_recovery_codes()
        with self.store._lock:
            self.store.conn.execute("BEGIN IMMEDIATE")
            try:
                self.store.conn.execute(
                    "DELETE FROM recovery_codes WHERE account_id = ?",
                    (account.id,),
                )
                self._insert_codes(account.id, codes, _now())
                self.store.conn.commit()
            except Exception:
                self.store.conn.rollback()
                raise
        return tuple(codes)

    def issue_mfa(self, account_id: str, *, pending_role: str = "") -> str:
        account = self._active(account_id)
        if not self.totp_active(account.id):
            raise FactorError("totp is not enrolled")
        raw = secrets.token_urlsafe(32)
        expires = (datetime.now(UTC) + timedelta(seconds=MFA_TTL_SECONDS)).isoformat(
            timespec="seconds"
        )
        # A role from a half-finished OIDC sign-in waits on this token.
        # Password sign-in passes an empty role. Owner is never stored.
        role = pending_role if pending_role in {"admin", "operator", "viewer", "auditor"} else ""
        with self.store._lock:
            self.store.conn.execute(
                "DELETE FROM mfa_tokens WHERE account_id = ? AND (used = 1 OR expires_at <= ?)",
                (account.id, _now()),
            )
            self.store.conn.execute(
                """
                INSERT INTO mfa_tokens (
                    token_hash, account_id, expires_at, used, created_at, pending_role
                ) VALUES (?, ?, ?, 0, ?, ?)
                """,
                (_hash(raw), account.id, expires, _now(), role),
            )
            self.store.conn.commit()
        return raw

    def take_pending_role(self, token: str) -> str:
        """Read and clear a role stored on a token that TOTP already accepted.

        A wrong code leaves the token unused, so this returns nothing and the
        role stays put for the retry.
        """
        if not isinstance(token, str) or not token or len(token) > 256:
            return ""
        digest = _hash(token)
        with self.store._lock:
            self.store.conn.execute("BEGIN IMMEDIATE")
            try:
                row = self.store.conn.execute(
                    "SELECT pending_role, used FROM mfa_tokens WHERE token_hash = ?",
                    (digest,),
                ).fetchone()
                if row is None or int(row["used"]) != 1:
                    self.store.conn.rollback()
                    return ""
                role = str(row["pending_role"])
                self.store.conn.execute(
                    "UPDATE mfa_tokens SET pending_role = '' WHERE token_hash = ?",
                    (digest,),
                )
                self.store.conn.commit()
            except Exception:
                self.store.conn.rollback()
                raise
        return role

    def complete_mfa(self, token: str, code: str, *, now: float | None = None) -> Account | None:
        if not isinstance(token, str) or not token or len(token) > 256:
            return None
        if not isinstance(code, str) or len(code) > 64:
            return None
        digest = _hash(token)
        moment = _moment(now)
        with self.store._lock:
            found = self.store.conn.execute(
                """
                SELECT account_id, expires_at, used FROM mfa_tokens WHERE token_hash = ?
                """,
                (digest,),
            ).fetchone()
        if found is None or int(found["used"]) or str(found["expires_at"]) <= _now():
            return None
        account = self.store.get_id(str(found["account_id"]))
        if account is None or account.status != "active":
            return None
        with self.store._account_gate(account.username):
            return self._finish_mfa(account, digest, code, moment)

    def summary(self, account_id: str) -> dict[str, object]:
        with self.store._lock:
            totp = self.store.conn.execute(
                "SELECT confirmed FROM totp WHERE account_id = ?",
                (account_id,),
            ).fetchone()
            remaining = self.store.conn.execute(
                """
                SELECT COUNT(*) AS n FROM recovery_codes
                WHERE account_id = ? AND used_at = ''
                """,
                (account_id,),
            ).fetchone()
            passkeys = self.store.conn.execute(
                """
                SELECT credential_id, name, created_at, last_used_at
                FROM passkeys WHERE account_id = ? ORDER BY created_at
                """,
                (account_id,),
            ).fetchall()
        confirmed = totp is not None and int(totp["confirmed"]) == 1
        pending = totp is not None and int(totp["confirmed"]) == 0
        return {
            "totp": confirmed,
            "totpPending": pending,
            "recoveryCodesRemaining": int(remaining["n"]) if confirmed and remaining else 0,
            "passkeys": [_passkey_public(row) for row in passkeys],
        }

    def begin_registration(
        self,
        account: Account,
        *,
        origin_header: str,
        port: int,
        session_id: str,
    ) -> dict[str, object]:
        """Start a registration ceremony for the session that spent a step-up.

        The caller spends the step-up token before this. Verify finishes
        this ceremony and does not ask for a second token. Another session
        cannot finish it.
        """
        selected = loopback_ceremony(origin_header, port)
        if selected is None:
            raise FactorError("origin is not allowed")
        if not isinstance(session_id, str) or not session_id or len(session_id) > 128:
            raise FactorError("authentication required", status=401, code="unauthorized")
        rp_id, origin = selected
        with self.store._lock:
            try:
                rows = self.store.conn.execute(
                    "SELECT credential_id FROM passkeys WHERE account_id = ? AND rp_id = ?",
                    (account.id, rp_id),
                ).fetchall()
                exclude = [_decode_id(str(row["credential_id"])) for row in rows]
                ceremony = registration_options(
                    rp_id=rp_id,
                    origin=origin,
                    user_id=account.id.encode("ascii"),
                    user_name=account.username,
                    user_display_name=account.display_name,
                    exclude=[item for item in exclude if item],
                )
                self._store_challenge(
                    account.id,
                    "register",
                    ceremony.challenge,
                    rp_id,
                    origin,
                    session_id=session_id,
                )
                self.store.conn.commit()
            except Exception:
                self.store.conn.rollback()
                raise
        return ceremony.options

    def finish_registration(
        self,
        account: Account,
        credential: object,
        *,
        name: str = "",
        session_id: str,
    ) -> dict[str, object]:
        """Finish the ceremony ``begin_registration`` stored for ``session_id``.

        A different session leaves the ceremony unused. A matching session
        spends it, including when the authenticator proof is rejected.
        """
        challenge = client_challenge(credential)
        if challenge is None or not isinstance(credential, dict):
            raise FactorError("passkey was rejected", status=401, code="unauthorized")
        if not isinstance(session_id, str) or not session_id or len(session_id) > 128:
            raise FactorError("passkey was rejected", status=401, code="unauthorized")
        with self.store._account_gate(account.username):
            with self.store._lock:
                row = self._take_challenge(
                    challenge, "register", account.id, session_id=session_id
                )
                if row is None:
                    self.store._note_second_factor_failure(account.id)
                    raise FactorError("passkey was rejected", status=401, code="unauthorized")
                try:
                    verified = verify_registration(
                        credential,
                        challenge=challenge,
                        rp_id=str(row["rp_id"]),
                        origin=str(row["origin"]),
                    )
                except WebAuthnException:
                    self.store._note_second_factor_failure(account.id)
                    raise FactorError(
                        "passkey was rejected",
                        status=401,
                        code="unauthorized",
                    ) from None
                encoded = bytes_to_base64url(verified.credential_id)
                label = _label(name)
                now = _now()
                try:
                    self.store.conn.execute(
                        """
                        INSERT INTO passkeys (
                            credential_id, account_id, public_key, sign_count, rp_id,
                            name, created_at, last_used_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, '')
                        """,
                        (
                            encoded,
                            account.id,
                            verified.credential_public_key,
                            int(verified.sign_count),
                            str(row["rp_id"]),
                            label,
                            now,
                        ),
                    )
                    self.store.conn.commit()
                except sqlite3.IntegrityError:
                    self.store.conn.rollback()
                    raise FactorError(
                        "passkey was rejected",
                        status=401,
                        code="unauthorized",
                    ) from None
        return {"id": encoded, "name": label, "createdAt": now}

    def remove_passkey(self, account_id: str, credential: str) -> bool:
        if not isinstance(credential, str) or not credential or len(credential) > 512:
            raise FactorError("no such passkey", status=404, code="not_found")
        with self.store._lock:
            cursor = self.store.conn.execute(
                "DELETE FROM passkeys WHERE account_id = ? AND credential_id = ?",
                (account_id, credential),
            )
            self.store.conn.commit()
        if cursor.rowcount != 1:
            raise FactorError("no such passkey", status=404, code="not_found")
        return True

    def prove_password(
        self,
        account_id: str,
        password: str,
        code: str,
        *,
        session_id: str,
        now: float | None = None,
    ) -> str:
        """Mint a step-up token from the password and, when set, a TOTP code.

        A recovery code counts as that second factor and is consumed. The
        token is bound to ``session_id`` (empty for the loopback bearer) and
        lasts five minutes. The first factor change spends it. A second
        change needs a new token.
        """
        account = self._active(account_id)
        if not isinstance(session_id, str) or len(session_id) > 128:
            raise FactorError("invalid step-up", status=401, code="unauthorized")
        if self.store.authenticate(account.username, password) is None:
            raise FactorError("invalid step-up", status=401, code="unauthorized")
        if self.totp_active(account.id) and not self._consume_totp(account, code, now=now):
            raise FactorError("invalid step-up", status=401, code="unauthorized")
        return self._mint_step_up(account.id, session_id)

    def begin_passkey_step_up(
        self,
        account: Account,
        *,
        origin_header: str,
        port: int,
    ) -> dict[str, object]:
        """Authentication options for this account's own passkeys.

        The caller is already signed in, so the allow list is not an
        anonymous username oracle. The assertion is a step-up, not a login.
        """
        selected = loopback_ceremony(origin_header, port)
        if selected is None:
            raise FactorError("origin is not allowed")
        rp_id, origin = selected
        with self.store._lock:
            try:
                rows = self.store.conn.execute(
                    "SELECT credential_id FROM passkeys WHERE account_id = ? AND rp_id = ?",
                    (account.id, rp_id),
                ).fetchall()
                allow = [
                    item
                    for item in (_decode_id(str(row["credential_id"])) for row in rows)
                    if item
                ]
                if not allow:
                    raise FactorError("no passkey on this account")
                ceremony = authentication_options(rp_id=rp_id, origin=origin, allow=allow)
                self._store_challenge(account.id, "authenticate", ceremony.challenge, rp_id, origin)
                self.store.conn.commit()
            except Exception:
                self.store.conn.rollback()
                raise
        return ceremony.options

    def finish_passkey_step_up(
        self,
        account: Account,
        credential: object,
        *,
        session_id: str,
    ) -> str:
        """Turn a fresh passkey assertion into a five-minute step-up token."""
        if not isinstance(session_id, str) or len(session_id) > 128:
            raise FactorError("passkey was rejected", status=401, code="unauthorized")
        signed_in = self.finish_authentication(credential)
        if signed_in is None or signed_in.id != account.id:
            raise FactorError("passkey was rejected", status=401, code="unauthorized")
        return self._mint_step_up(account.id, session_id)

    def step_up_valid(self, account_id: str, token: str, session_id: str) -> bool:
        """Spend a fresh step-up token for this account and session.

        The delete runs inside ``BEGIN IMMEDIATE``. A second presentation
        of the same token finds no row.
        """
        if not isinstance(token, str) or not token or len(token) > 256:
            return False
        if not isinstance(session_id, str) or len(session_id) > 128:
            return False
        with self.store._lock:
            self.store.conn.execute("BEGIN IMMEDIATE")
            try:
                spent = self.store.conn.execute(
                    """
                    DELETE FROM step_up
                    WHERE token_hash = ? AND account_id = ? AND session_id = ?
                      AND expires_at > ?
                    """,
                    (_hash(token), account_id, session_id, _now()),
                )
                if spent.rowcount != 1:
                    self.store.conn.rollback()
                    return False
                self.store.conn.commit()
            except Exception:
                self.store.conn.rollback()
                raise
        return True

    def _mint_step_up(self, account_id: str, session_id: str) -> str:
        raw = secrets.token_urlsafe(32)
        expires = (datetime.now(UTC) + timedelta(seconds=STEP_UP_TTL_SECONDS)).isoformat(
            timespec="seconds"
        )
        with self.store._lock:
            self.store.conn.execute("DELETE FROM step_up WHERE expires_at <= ?", (_now(),))
            self.store.conn.execute(
                """
                INSERT INTO step_up (
                    token_hash, account_id, session_id, expires_at, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (_hash(raw), account_id, session_id, expires, _now()),
            )
            self.store.conn.commit()
        return raw

    def begin_authentication(
        self,
        username_text: str,
        *,
        origin_header: str,
        port: int,
    ) -> dict[str, object]:
        selected = loopback_ceremony(origin_header, port)
        if selected is None:
            raise FactorError("origin is not allowed")
        rp_id, origin = selected
        account = self.store.get_username(username_text) if username_text else None
        bound = ""
        if account is not None and account.status == "active":
            bound = account.id
        # The response never lists credential ids. The username is sealed
        # inside the challenge, so another account's passkey cannot finish
        # it, and the blob is not stored. Anonymous callers cannot fill the
        # per-account cap that registration and step-up use. The key is
        # read before a write transaction. A missing key is the only reason
        # to take ``BEGIN IMMEDIATE``.
        with self.store._lock:
            key = self._read_key()
            if key is None:
                self.store.conn.execute("BEGIN IMMEDIATE")
                try:
                    key = self._key()
                    self.store.conn.commit()
                except Exception:
                    self.store.conn.rollback()
                    raise
        expires = int(datetime.now(UTC).timestamp()) + CHALLENGE_TTL_SECONDS
        challenge = _seal_sign_in(
            challenge_key(key),
            account_id=bound,
            rp_id=rp_id,
            origin=origin,
            expires=expires,
        )
        ceremony = authentication_options(
            rp_id=rp_id,
            origin=origin,
            allow=[],
            challenge=challenge,
        )
        return ceremony.options

    def finish_authentication(self, credential: object) -> Account | None:
        challenge = client_challenge(credential)
        presented = credential_id(credential)
        if challenge is None or presented is None or not isinstance(credential, dict):
            return None
        encoded = bytes_to_base64url(presented)
        with self.store._lock:
            existing = self.store.conn.execute(
                """
                SELECT account_id, public_key, sign_count, rp_id
                FROM passkeys WHERE credential_id = ?
                """,
                (encoded,),
            ).fetchone()
            challenge_row = self.store.conn.execute(
                """
                SELECT account_id, rp_id, origin, expires_at, used, kind
                FROM webauthn_challenges WHERE challenge = ?
                """,
                (challenge,),
            ).fetchone()
        if challenge_row is None:
            return self._finish_signed(credential, challenge, encoded)
        if str(challenge_row["kind"]) != "authenticate":
            return None
        if int(challenge_row["used"]) or str(challenge_row["expires_at"]) <= _now():
            return None
        if existing is None:
            bound_id = str(challenge_row["account_id"])
            if bound_id:
                self._burn_and_fail(bound_id, challenge)
            else:
                self._burn_challenge(challenge)
            return None
        account = self.store.get_id(str(existing["account_id"]))
        if account is None or account.status != "active":
            self._burn_challenge(challenge)
            return None
        bound = str(challenge_row["account_id"])
        if bound and bound != account.id:
            self._burn_and_fail(account.id, challenge)
            return None
        if str(existing["rp_id"]) != str(challenge_row["rp_id"]):
            self._burn_and_fail(account.id, challenge)
            return None
        with self.store._account_gate(account.username):
            if self.store.account_is_locked(account.id):
                self._burn_challenge(challenge)
                return None
            try:
                verified = verify_authentication(
                    credential,
                    challenge=challenge,
                    rp_id=str(challenge_row["rp_id"]),
                    origin=str(challenge_row["origin"]),
                    public_key=bytes(existing["public_key"]),
                    sign_count=int(existing["sign_count"]),
                )
            except WebAuthnException:
                self._burn_and_fail(account.id, challenge)
                return None
            with self.store._lock:
                self.store.conn.execute("BEGIN IMMEDIATE")
                try:
                    current = self.store.conn.execute(
                        """
                        SELECT sign_count FROM passkeys WHERE credential_id = ?
                        """,
                        (encoded,),
                    ).fetchone()
                    fresh = self.store.conn.execute(
                        "SELECT used FROM webauthn_challenges WHERE challenge = ?",
                        (challenge,),
                    ).fetchone()
                    if current is None or fresh is None or int(fresh["used"]):
                        self.store.conn.rollback()
                        return None
                    new_count = int(verified.new_sign_count)
                    old_count = int(current["sign_count"])
                    spent = self.store.conn.execute(
                        """
                        UPDATE webauthn_challenges SET used = 1
                        WHERE challenge = ? AND used = 0
                        """,
                        (challenge,),
                    )
                    if spent.rowcount != 1 or _sign_count_replayed(new_count, old_count):
                        self.store._note_second_factor_failure(account.id)
                        return None
                    self.store.conn.execute(
                        """
                        UPDATE passkeys
                        SET sign_count = ?, last_used_at = ?
                        WHERE credential_id = ?
                        """,
                        (new_count, _now(), encoded),
                    )
                    self.store._clear_failure_counters(account.id)
                    self.store.conn.commit()
                except Exception:
                    self.store.conn.rollback()
                    raise
        return account

    def _finish_signed(
        self,
        credential: dict[str, object],
        challenge: bytes,
        encoded: str,
    ) -> Account | None:
        """Finish a sealed sign-in challenge. It is stored only once spent."""
        opened = self._open_sign_in(challenge)
        if opened is None:
            return None
        account_id, rp_id, origin, expires_at = opened
        with self.store._lock:
            existing = self.store.conn.execute(
                """
                SELECT account_id, public_key, sign_count, rp_id
                FROM passkeys WHERE credential_id = ?
                """,
                (encoded,),
            ).fetchone()
        if existing is None:
            self._reject_signed(account_id, challenge, expires_at, fail=bool(account_id))
            return None
        account = self.store.get_id(str(existing["account_id"]))
        if account is None or account.status != "active":
            self._reject_signed("", challenge, expires_at, fail=False)
            return None
        if account_id and account_id != account.id:
            self._reject_signed(account.id, challenge, expires_at, fail=True)
            return None
        if str(existing["rp_id"]) != rp_id:
            self._reject_signed(account.id, challenge, expires_at, fail=True)
            return None
        with self.store._account_gate(account.username):
            if self.store.account_is_locked(account.id):
                self._reject_signed("", challenge, expires_at, fail=False)
                return None
            try:
                verified = verify_authentication(
                    credential,
                    challenge=challenge,
                    rp_id=rp_id,
                    origin=origin,
                    public_key=bytes(existing["public_key"]),
                    sign_count=int(existing["sign_count"]),
                )
            except WebAuthnException:
                self._reject_signed(account.id, challenge, expires_at, fail=True)
                return None
            with self.store._lock:
                self.store.conn.execute("BEGIN IMMEDIATE")
                try:
                    current = self.store.conn.execute(
                        "SELECT sign_count FROM passkeys WHERE credential_id = ?",
                        (encoded,),
                    ).fetchone()
                    fresh = self._spend_sign_in(challenge, expires_at)
                    new_count = int(verified.new_sign_count)
                    old_count = int(current["sign_count"]) if current is not None else 0
                    if current is None or not fresh or _sign_count_replayed(new_count, old_count):
                        if fresh:
                            self.store._note_second_factor_failure(account.id)
                        else:
                            self.store.conn.rollback()
                        return None
                    self.store.conn.execute(
                        """
                        UPDATE passkeys
                        SET sign_count = ?, last_used_at = ?
                        WHERE credential_id = ?
                        """,
                        (new_count, _now(), encoded),
                    )
                    self.store._clear_failure_counters(account.id)
                    self.store.conn.commit()
                except Exception:
                    self.store.conn.rollback()
                    raise
        return account

    def _open_sign_in(self, challenge: bytes) -> tuple[str, str, str, str] | None:
        with self.store._lock:
            key = self._read_key()
        if key is None:
            return None
        try:
            raw = unseal(challenge_key(key), challenge, aad=_SIGNIN_AAD)
        except Exception:
            return None
        parsed = _unpack_sign_in(raw)
        if parsed is None:
            return None
        account_id, rp_id, origin, expires_unix = parsed
        if expires_unix <= int(datetime.now(UTC).timestamp()):
            return None
        expires_at = datetime.fromtimestamp(expires_unix, UTC).isoformat(timespec="seconds")
        return account_id, rp_id, origin, expires_at

    def _spend_sign_in(self, challenge: bytes, expires_at: str) -> bool:
        """Record one use. Caller holds ``_lock`` and the write transaction."""
        self.store.conn.execute(
            "DELETE FROM webauthn_spent WHERE expires_at <= ?",
            (_now(),),
        )
        seen = self.store.conn.execute(
            "SELECT 1 FROM webauthn_spent WHERE challenge = ?",
            (challenge,),
        ).fetchone()
        if seen is not None:
            return False
        self.store.conn.execute(
            "INSERT INTO webauthn_spent (challenge, expires_at) VALUES (?, ?)",
            (challenge, expires_at),
        )
        return True

    def _reject_signed(
        self,
        account_id: str,
        challenge: bytes,
        expires_at: str,
        *,
        fail: bool,
    ) -> None:
        """Spend a sealed challenge. A repeat spend does not count as a new failure."""
        with self.store._lock:
            self.store.conn.execute("BEGIN IMMEDIATE")
            try:
                fresh = self._spend_sign_in(challenge, expires_at)
                if fresh and fail and account_id:
                    self.store._note_second_factor_failure(account_id)
                    return
                self.store.conn.commit()
            except Exception:
                self.store.conn.rollback()
                raise

    def _finish_mfa(
        self,
        account: Account,
        digest: str,
        code: str,
        moment: float,
    ) -> Account | None:
        with self.store._lock:
            self.store.conn.execute("BEGIN IMMEDIATE")
            try:
                token = self.store.conn.execute(
                    """
                    SELECT expires_at, used FROM mfa_tokens WHERE token_hash = ?
                    """,
                    (digest,),
                ).fetchone()
                if token is None or int(token["used"]) or str(token["expires_at"]) <= _now():
                    self.store.conn.rollback()
                    return None
                if self._row_locked(account.id):
                    self.store.conn.rollback()
                    return None
                if not self._accept_code(account.id, code, moment):
                    self.store.conn.rollback()
                    self.store._note_second_factor_failure(account.id)
                    return None
                spent = self.store.conn.execute(
                    """
                    UPDATE mfa_tokens SET used = 1
                    WHERE token_hash = ? AND used = 0
                    """,
                    (digest,),
                )
                if spent.rowcount != 1:
                    self.store.conn.rollback()
                    return None
                self.store._clear_failure_counters(account.id)
                self.store.conn.commit()
            except Exception:
                self.store.conn.rollback()
                raise
        fresh = self.store.get_id(account.id)
        return fresh

    def _accept_code(self, account_id: str, code: str, moment: float) -> bool:
        """Consume a TOTP step or a recovery code. Caller holds the transaction."""
        row = self.store.conn.execute(
            "SELECT secret_enc, confirmed, last_step FROM totp WHERE account_id = ?",
            (account_id,),
        ).fetchone()
        if row is None or int(row["confirmed"]) != 1:
            return False
        secret = self._secret(account_id, row["secret_enc"])
        step = matching_step(secret or "", code, now=moment)
        if step is not None:
            if step <= int(row["last_step"]):
                return False
            cursor = self.store.conn.execute(
                """
                UPDATE totp SET last_step = ?
                WHERE account_id = ? AND last_step < ?
                """,
                (step, account_id, step),
            )
            return cursor.rowcount == 1
        normalized = normalize_recovery(code)
        if normalized is None:
            return False
        cursor = self.store.conn.execute(
            """
            UPDATE recovery_codes SET used_at = ?
            WHERE code_hash = ? AND account_id = ? AND used_at = ''
            """,
            (_now(), recovery_hash(normalized), account_id),
        )
        return cursor.rowcount == 1

    def _consume_totp(self, account: Account, code: str, *, now: float | None) -> bool:
        moment = _moment(now)
        with self.store._account_gate(account.username):
            with self.store._lock:
                if self._row_locked(account.id):
                    return False
                self.store.conn.execute("BEGIN IMMEDIATE")
                try:
                    if not self._accept_code(account.id, code, moment):
                        self.store.conn.rollback()
                        self.store._note_second_factor_failure(account.id)
                        return False
                    self.store.conn.commit()
                except Exception:
                    self.store.conn.rollback()
                    raise
        return True

    def _active(self, account_id: str) -> Account:
        account = self.store.get_id(account_id)
        if account is None or account.status != "active":
            raise FactorError("authentication required", status=401, code="unauthorized")
        return account

    def _read_key(self) -> bytes | None:
        """Return the data key, or None. Does not insert one."""
        row = self.store.conn.execute(
            "SELECT value FROM auth_meta WHERE key = 'data'"
        ).fetchone()
        if row is None:
            return None
        value = bytes(row["value"])
        if len(value) != 32:
            return None
        return value

    def _key(self) -> bytes:
        """Insert a missing key, then re-read the stored row.

        Caller holds the write transaction. ``ON CONFLICT DO NOTHING`` keeps
        a concurrent insert. This does not overwrite a key that is already
        there, and ``_secret`` does not call this.
        """
        existing = self._read_key()
        if existing is not None:
            return existing
        self.store.conn.execute(
            "INSERT INTO auth_meta (key, value) VALUES ('data', ?) "
            "ON CONFLICT(key) DO NOTHING",
            (new_key(),),
        )
        stored = self._read_key()
        if stored is None:
            raise FactorError("account data key is missing", status=500, code="error")
        return stored

    def _secret(self, account_id: str, blob: object) -> str | None:
        """Decrypt a seed for ``account_id``. A legacy blob is rewritten.

        A ciphertext sealed for another account does not decrypt. A blob
        sealed with ``LEGACY_AAD`` (no account id) decrypts once and is
        stored again under ``account_aad``. ``_read_key`` never creates a key.
        """
        key = self._read_key()
        if key is None:
            return None
        raw = _decrypt(key, blob, account_aad(account_id))
        legacy = False
        if raw is None:
            raw = _decrypt(key, blob, LEGACY_AAD)
            legacy = raw is not None
        if raw is None:
            return None
        try:
            text = raw.decode("ascii")
        except UnicodeError:
            return None
        if not text or len(text) > 128:
            return None
        if legacy:
            self.store.conn.execute(
                "UPDATE totp SET secret_enc = ? WHERE account_id = ?",
                (seal(key, raw, aad=account_aad(account_id)), account_id),
            )
        return text

    def _insert_codes(self, account_id: str, codes: list[str], now: str) -> None:
        for code in codes:
            normalized = normalize_recovery(code)
            if normalized is None:
                raise RuntimeError("recovery code generator returned an unreadable code")
            self.store.conn.execute(
                """
                INSERT INTO recovery_codes (code_hash, account_id, created_at, used_at)
                VALUES (?, ?, ?, '')
                """,
                (recovery_hash(normalized), account_id, now),
            )

    def _store_challenge(
        self,
        account_id: str,
        kind: str,
        challenge: bytes,
        rp_id: str,
        origin: str,
        *,
        session_id: str = "",
    ) -> None:
        self.store.conn.execute(
            "DELETE FROM webauthn_challenges WHERE used = 1 OR expires_at <= ?",
            (_now(),),
        )
        rows = self.store.conn.execute(
            """
            SELECT challenge FROM webauthn_challenges
            WHERE account_id = ? AND used = 0
            """,
            (account_id,),
        ).fetchall()
        # Registration and step-up only. Both require a session, so an
        # anonymous options call cannot land here. Sign-in challenges are
        # sealed and are not rows in this table. Leave stored challenges in
        # place: deleting the oldest one used to drop a ceremony already
        # in flight.
        if len(rows) >= _OPEN_CHALLENGES:
            raise FactorError(
                "too many challenges",
                status=429,
                code="too_many",
            )
        expires = (datetime.now(UTC) + timedelta(seconds=CHALLENGE_TTL_SECONDS)).isoformat(
            timespec="seconds"
        )
        self.store.conn.execute(
            """
            INSERT INTO webauthn_challenges (
                challenge, account_id, kind, rp_id, origin, expires_at, used, session_id
            ) VALUES (?, ?, ?, ?, ?, ?, 0, ?)
            """,
            (challenge, account_id, kind, rp_id, origin, expires, session_id),
        )

    def _take_challenge(
        self,
        challenge: bytes,
        kind: str,
        account_id: str,
        *,
        session_id: str | None = None,
    ) -> sqlite3.Row | None:
        row = self.store.conn.execute(
            """
            SELECT account_id, kind, rp_id, origin, expires_at, used, session_id
            FROM webauthn_challenges WHERE challenge = ?
            """,
            (challenge,),
        ).fetchone()
        if row is None or str(row["kind"]) != kind or int(row["used"]):
            return None
        if str(row["expires_at"]) <= _now() or str(row["account_id"]) != account_id:
            return None
        # A registration ceremony is bound to the session that spent the
        # step-up. A mismatch leaves the row unused so that session can
        # still finish it. Other ceremonies do not pass ``session_id``.
        if session_id is not None and str(row["session_id"]) != session_id:
            return None
        cursor = self.store.conn.execute(
            "UPDATE webauthn_challenges SET used = 1 WHERE challenge = ? AND used = 0",
            (challenge,),
        )
        if cursor.rowcount != 1:
            return None
        return row

    def _burn_challenge(self, challenge: bytes) -> None:
        with self.store._lock:
            self.store.conn.execute(
                "UPDATE webauthn_challenges SET used = 1 WHERE challenge = ? AND used = 0",
                (challenge,),
            )
            self.store.conn.commit()

    def _burn_and_fail(self, account_id: str, challenge: bytes) -> None:
        with self.store._lock:
            self.store.conn.execute(
                "UPDATE webauthn_challenges SET used = 1 WHERE challenge = ? AND used = 0",
                (challenge,),
            )
            self.store._note_second_factor_failure(account_id)

    def _row_locked(self, account_id: str) -> bool:
        row = self.store.conn.execute(
            "SELECT locked_until, status FROM accounts WHERE id = ?",
            (account_id,),
        ).fetchone()
        if row is None or str(row["status"]) != "active":
            return True
        return _is_locked(str(row["locked_until"]))

def _decrypt(key: bytes, blob: object, aad: bytes) -> bytes | None:
    try:
        return unseal(key, bytes(blob), aad=aad)  # type: ignore[arg-type]
    except Exception:
        return None


def _passkey_public(row: Any) -> dict[str, object]:
    return {
        "id": str(row["credential_id"]),
        "name": str(row["name"]),
        "createdAt": str(row["created_at"]),
        "lastUsedAt": str(row["last_used_at"]),
    }


def _label(value: str) -> str:
    text = " ".join(value.replace("\r", " ").replace("\n", " ").split())
    if not text:
        return "passkey"
    return text[:64]


def _seal_sign_in(
    key: bytes,
    *,
    account_id: str,
    rp_id: str,
    origin: str,
    expires: int,
) -> bytes:
    """Seal a fixed-width sign-in challenge. The length does not identify the account."""
    if "\x00" in account_id or "\x00" in rp_id or "\x00" in origin:
        raise FactorError("origin is not allowed")
    try:
        packed = (
            int(expires).to_bytes(4, "big")
            + _fit(rp_id, _SIGNIN_RP)
            + _fit(origin, _SIGNIN_ORIGIN)
            + _fit(account_id, _SIGNIN_ACCOUNT)
        )
    except ValueError:
        raise FactorError("origin is not allowed") from None
    return seal(key, packed, aad=_SIGNIN_AAD)


def _unpack_sign_in(raw: bytes) -> tuple[str, str, str, int] | None:
    width = 4 + _SIGNIN_RP + _SIGNIN_ORIGIN + _SIGNIN_ACCOUNT
    if len(raw) != width:
        return None
    expires = int.from_bytes(raw[:4], "big")
    rp_id = _unfit(raw[4 : 4 + _SIGNIN_RP])
    origin = _unfit(raw[4 + _SIGNIN_RP : 4 + _SIGNIN_RP + _SIGNIN_ORIGIN])
    account_id = _unfit(raw[4 + _SIGNIN_RP + _SIGNIN_ORIGIN :])
    if rp_id is None or origin is None or account_id is None or not rp_id or not origin:
        return None
    return account_id, rp_id, origin, expires


def _fit(value: str, width: int) -> bytes:
    raw = value.encode("ascii")
    if len(raw) > width:
        raise ValueError("too long")
    return raw.ljust(width, b"\x00")


def _unfit(raw: bytes) -> str | None:
    text = raw.split(b"\x00", 1)[0]
    try:
        return text.decode("ascii")
    except UnicodeError:
        return None


def _sign_count_replayed(new_count: int, old_count: int) -> bool:
    """True when the authenticator did not advance a counter it uses."""
    if new_count <= 0 and old_count <= 0:
        return False
    return new_count <= old_count


def _moment(now: float | None) -> float:
    if now is None:
        return datetime.now(UTC).timestamp()
    return float(now)


def _decode_id(value: str) -> bytes:
    from webauthn.helpers import base64url_to_bytes

    try:
        return base64url_to_bytes(value)
    except (WebAuthnException, ValueError):
        return b""
