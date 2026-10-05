"""Gateway bearer token.

The token lives in the runtime directory, mode 0600. Once an account
exists it is an owner-equivalent loopback credential. It is not written
to config or the log. ``rotate_token`` replaces the file; the running
daemon keeps the previous value until it is restarted.
"""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

from praxis_prime.gateway.protocol import secrets_equal

_TOKEN_CAP = 8192


class TokenUnreadable(OSError):
    """The token file is not safe to read. The message does not include the token."""

    def __init__(self) -> None:
        super().__init__("refusing to read the gateway token")


def load_or_create_token(path: Path) -> str:
    """Read the token file, or create one. The file mode is forced to 0600.

    The open uses ``O_NOFOLLOW``. A symlink raises ``TokenUnreadable`` and is
    left in place. A regular file this user owns is read, then ``fchmod``
    tightens a looser mode. The error does not include the token.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        descriptor = None
    except OSError as exc:
        raise TokenUnreadable() from exc
    if descriptor is not None:
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise TokenUnreadable()
            try:
                blob = os.read(descriptor, _TOKEN_CAP + 1)
            except OSError as exc:
                raise TokenUnreadable() from exc
            if stat.S_IMODE(info.st_mode) & 0o077:
                os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
        if len(blob) > _TOKEN_CAP:
            raise TokenUnreadable()
        token = blob.decode("utf-8", errors="replace").strip()
        if token:
            return token
    token = secrets.token_urlsafe(32)
    _write_private(path, token)
    return token


def rotate_token(path: Path) -> None:
    """Replace the token file. The new value is not returned or logged."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    _write_private(path, secrets.token_urlsafe(32))


def read_token(path: Path) -> str | None:
    """Read a regular token file owned by this user.

    The open uses ``O_NOFOLLOW``. ``fstat`` must show the current uid and a
    mode with no group or other bits. A missing file is ``None``. A symlink,
    another owner, or a looser mode raises ``TokenUnreadable``. That error
    does not include the file contents.
    """
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise TokenUnreadable() from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise TokenUnreadable()
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise TokenUnreadable()
        try:
            blob = os.read(descriptor, _TOKEN_CAP + 1)
        except OSError as exc:
            raise TokenUnreadable() from exc
    finally:
        os.close(descriptor)
    if len(blob) > _TOKEN_CAP:
        raise TokenUnreadable()
    text = blob.decode("utf-8", errors="replace").strip()
    return text or None


def bearer_token(headers: dict[str, str]) -> str:
    value = headers.get("authorization", "")
    if len(value) < 8 or not value.lower().startswith("bearer "):
        return ""
    return value[7:].strip()


def token_ok(presented: str, expected: str) -> bool:
    return secrets_equal(presented, expected)


def _write_private(path: Path, text: str) -> None:
    """Write the token by replacing a temp file, so readers never see a partial."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, 0o600)
    try:
        os.write(descriptor, (text + "\n").encode("utf-8"))
    except Exception:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    os.close(descriptor)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    os.chmod(path, 0o600)
