"""Encrypted xAI grant. Mode 0600, not copied into config backups."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from praxis_prime.privatefile import tighten_dir, tighten_file

_VERSION = 1
_KEY_LEN = 32
_NONCE_LEN = 12


class StoreError(Exception):
    """The grant file could not be read or written. The message has no token."""


class TokenStore:
    """``<config_dir>/provider-auth/xai.json.enc``."""

    def __init__(self, config_dir: Path) -> None:
        self.config_dir = Path(config_dir)
        self.root = self.config_dir / "provider-auth"
        self.path = self.root / "xai.json.enc"
        self.key_path = self.root / ".key"
        self.lock_path = self.root / "xai.lock"
        self.fail_next_write = False

    def associated_data(self, issuer: str, client_id: str) -> bytes:
        return ("xai" + issuer + client_id).encode("utf-8")

    @contextmanager
    def locked(self) -> Iterator[None]:
        self._ensure_dir()
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.lock_path, flags, 0o600)
        try:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                os.fchmod(descriptor, 0o600)
            except OSError:
                pass
            yield
        finally:
            try:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def load(self, *, issuer: str, client_id: str) -> dict[str, object] | None:
        if not self.path.exists():
            return None
        raw = self._read_private(self.path)
        try:
            envelope = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise StoreError("provider auth file is not readable") from exc
        if not isinstance(envelope, dict) or envelope.get("key_source") != "file":
            raise StoreError("provider auth file is not readable")
        nonce = _b64(envelope.get("nonce"))
        ciphertext = _b64(envelope.get("ciphertext"))
        if nonce is None or ciphertext is None:
            raise StoreError("provider auth file is not readable")
        key = self._read_key()
        try:
            plain = AESGCM(key).decrypt(nonce, ciphertext, self.associated_data(issuer, client_id))
        except Exception as exc:
            raise StoreError("provider auth file is not readable") from exc
        try:
            record = json.loads(plain.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise StoreError("provider auth file is not readable") from exc
        if not isinstance(record, dict):
            raise StoreError("provider auth file is not readable")
        return record

    def save(self, record: dict[str, object], *, issuer: str, client_id: str) -> None:
        if self.fail_next_write:
            self.fail_next_write = False
            raise StoreError("provider auth file could not be written")
        self._ensure_dir()
        key = self._read_key() if self.key_path.exists() else self._create_key()
        nonce = os.urandom(_NONCE_LEN)
        plain = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ciphertext = AESGCM(key).encrypt(nonce, plain, self.associated_data(issuer, client_id))
        envelope = {
            "version": _VERSION,
            "key_source": "file",
            "nonce": _b64_out(nonce),
            "ciphertext": _b64_out(ciphertext),
        }
        payload = (json.dumps(envelope, sort_keys=True) + "\n").encode("utf-8")
        self._replace(self.path, payload)

    def delete_tokens(
        self,
        *,
        issuer: str,
        client_id: str,
        reason: str,
    ) -> dict[str, object] | None:
        current = self.load(issuer=issuer, client_id=client_id)
        if current is None:
            return None
        account = current.get("account")
        kept = {
            "version": _VERSION,
            "issuer": issuer,
            "client_id": client_id,
            "scope": current.get("scope") or "",
            "token_endpoint": "",
            "access_token": "",
            "refresh_token": "",
            "expires_at": 0,
            "last_refresh": current.get("last_refresh") or 0,
            "account": account if isinstance(account, dict) else {},
            "state": "needs_reauth",
            "reason": reason,
        }
        self.save(kept, issuer=issuer, client_id=client_id)
        return kept

    def _ensure_dir(self) -> None:
        self.root.mkdir(parents=True, mode=0o700, exist_ok=True)
        tighten_dir(self.root)
        if self.root.is_symlink():
            raise StoreError("provider auth directory is not a real directory")

    def _create_key(self) -> bytes:
        key = os.urandom(_KEY_LEN)
        self._replace(self.key_path, key)
        return key

    def _read_key(self) -> bytes:
        key = self._read_private(self.key_path)
        if len(key) != _KEY_LEN:
            raise StoreError("provider auth key is not readable")
        return key

    def _read_private(self, path: Path) -> bytes:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise StoreError("provider auth file is not readable") from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise StoreError("provider auth file is not a regular file")
            if info.st_uid != os.getuid():
                raise StoreError("provider auth file has the wrong owner")
            chunks: list[bytes] = []
            while True:
                block = os.read(descriptor, 65536)
                if not block:
                    break
                chunks.append(block)
        finally:
            os.close(descriptor)
        return b"".join(chunks)

    def _replace(self, path: Path, payload: bytes) -> None:
        self._ensure_dir()
        temporary = path.with_name(f".{path.name}.{os.urandom(4).hex()}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
        except Exception:
            os.close(descriptor)
            temporary.unlink(missing_ok=True)
            raise
        os.close(descriptor)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        tighten_file(path)


def _b64(value: object) -> bytes | None:
    import base64

    if not isinstance(value, str) or not value:
        return None
    try:
        return base64.urlsafe_b64decode(value.encode("ascii"))
    except (ValueError, UnicodeError):
        return None


def _b64_out(value: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(value).decode("ascii")
