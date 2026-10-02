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
from praxis_prime.accounts.seal import LEGACY_AAD, account_aad, new_key, seal, unseal
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
                self.store._clear_failure_counters(account.id)
                self.store.conn.commit()

    def disable_totp(self, username: str, password: str) -> Account:
        account = self.store.authenticate(username, password)
        if account is None:
            raise FactorError("invalid code", status=401, code="unauthorized")
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
        return account

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

    def issue_mfa(self, account_id: str) -> str:
        account = self._active(account_id)
        if not self.totp_active(account.id):
            raise FactorError("totp is not enrolled")
        raw = secrets.token_urlsafe(32)
        expires = (datetime.now(UTC) + timedelta(seconds=MFA_TTL_SECONDS)).isoformat(
            timespec="seconds"
        )
        with self.store._lock:
            self.store.conn.execute(
                "DELETE FROM mfa_tokens WHERE account_id = ? AND (used = 1 OR expires_at <= ?)",
                (account.id, _now()),
            )
            self.store.conn.execute(
                """
                INSERT INTO mfa_tokens (token_hash, account_id, expires_at, used, created_at)
                VALUES (?, ?, ?, 0, ?)
                """,
                (_hash(raw), account.id, expires, _now()),
            )
            self.store.conn.commit()
        return raw

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
    ) -> dict[str, object]:
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
                exclude = [_decode_id(str(row["credential_id"])) for row in rows]
                ceremony = registration_options(
                    rp_id=rp_id,
                    origin=origin,
                    user_id=account.id.encode("ascii"),
                    user_name=account.username,
                    user_display_name=account.display_name,
                    exclude=[item for item in exclude if item],
                )
                self._store_challenge(account.id, "register", ceremony.challenge, rp_id, origin)
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
    ) -> dict[str, object]:
        challenge = client_challenge(credential)
        if challenge is None or not isinstance(credential, dict):
            raise FactorError("passkey was rejected", status=401, code="unauthorized")
        with self.store._account_gate(account.username):
            with self.store._lock:
                row = self._take_challenge(challenge, "register", account.id)
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
        lasts five minutes. It can be presented more than once in that window
        so a registration ceremony can use options and then verify.
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
        """True when ``token`` was minted for this account and session and is fresh."""
        if not isinstance(token, str) or not token or len(token) > 256:
            return False
        if not isinstance(session_id, str) or len(session_id) > 128:
            return False
        with self.store._lock:
            row = self.store.conn.execute(
                """
                SELECT account_id, session_id, expires_at
                FROM step_up WHERE token_hash = ?
                """,
                (_hash(token),),
            ).fetchone()
        if row is None or str(row["expires_at"]) <= _now():
            return False
        return str(row["account_id"]) == account_id and str(row["session_id"]) == session_id

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
        # The response never lists credential ids. A username still binds the
        # challenge, so another account's passkey cannot finish it.
        with self.store._lock:
            try:
                ceremony = authentication_options(rp_id=rp_id, origin=origin, allow=[])
                self._store_challenge(bound, "authenticate", ceremony.challenge, rp_id, origin)
                self.store.conn.commit()
            except Exception:
                self.store.conn.rollback()
                raise
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
        if challenge_row is None or str(challenge_row["kind"]) != "authenticate":
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
        # Leave outstanding challenges in place. Deleting the oldest one let
        # an anonymous caller evict a sign-in the user had already started.
        if len(rows) >= _OPEN_CHALLENGES:
            raise FactorError(
                "too many sign-in challenges",
                status=429,
                code="too_many",
            )
        expires = (datetime.now(UTC) + timedelta(seconds=CHALLENGE_TTL_SECONDS)).isoformat(
            timespec="seconds"
        )
        self.store.conn.execute(
            """
            INSERT INTO webauthn_challenges (
                challenge, account_id, kind, rp_id, origin, expires_at, used
            ) VALUES (?, ?, ?, ?, ?, ?, 0)
            """,
            (challenge, account_id, kind, rp_id, origin, expires),
        )

    def _take_challenge(
        self,
        challenge: bytes,
        kind: str,
        account_id: str,
    ) -> sqlite3.Row | None:
        row = self.store.conn.execute(
            """
            SELECT account_id, kind, rp_id, origin, expires_at, used
            FROM webauthn_challenges WHERE challenge = ?
            """,
            (challenge,),
        ).fetchone()
        if row is None or str(row["kind"]) != kind or int(row["used"]):
            return None
        if str(row["expires_at"]) <= _now() or str(row["account_id"]) != account_id:
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
