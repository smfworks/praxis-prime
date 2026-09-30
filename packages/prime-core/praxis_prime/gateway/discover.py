"""Find a running daemon via the runtime directory.

``gateway.json`` holds the pid and bind address. The token stays in a
separate mode-0600 file and is not copied into the JSON.
"""

from __future__ import annotations

import json
import os
import socket
from collections.abc import Mapping
from pathlib import Path

from praxis_prime.gateway.auth import read_token
from praxis_prime.gateway.client import Endpoint
from praxis_prime.paths import runtime_dir, state_dir


def gateway_paths(env: Mapping[str, str] | None = None) -> tuple[Path, Path]:
    root = runtime_dir(env)
    return root / "gateway.json", root / "gateway.token"


def log_path(env: Mapping[str, str] | None = None) -> Path:
    return state_dir(env) / "daemon.log"


def write_discovery(
    *,
    env: Mapping[str, str] | None,
    pid: int,
    port: int,
    socket_path: str | None,
    version: str,
    started_at: str,
) -> None:
    info_path, _token_path = gateway_paths(env)
    info_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(info_path.parent, 0o700)
    except OSError:
        pass
    payload = {
        "pid": pid,
        "host": "127.0.0.1",
        "port": port,
        "version": version,
        "startedAt": started_at,
    }
    if socket_path:
        payload["socket"] = socket_path
    text = json.dumps(payload)
    temporary = info_path.with_name(".gateway.json.tmp")
    temporary.write_text(text + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(info_path)


def clear_discovery(env: Mapping[str, str] | None = None) -> None:
    info_path, _token_path = gateway_paths(env)
    info_path.unlink(missing_ok=True)
    root = runtime_dir(env)
    socket_path = root / "prime.sock"
    try:
        os.unlink(socket_path)
    except OSError:
        return


def discover(env: Mapping[str, str] | None = None, *, timeout: float = 0.4) -> Endpoint | None:
    """Return the live endpoint, or None when no healthy daemon is published."""
    info_path, token_path = gateway_paths(env)
    if not info_path.is_file():
        return None
    token = read_token(token_path)
    if not token:
        return None
    try:
        info = json.loads(info_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(info, dict):
        return None
    host = info.get("host")
    port = info.get("port")
    if host != "127.0.0.1" or not isinstance(port, int):
        return None
    if not probe_health(host, port, timeout=timeout):
        return None
    socket_path = info.get("socket")
    return Endpoint(
        host=host,
        port=port,
        token=token,
        socket_path=socket_path if isinstance(socket_path, str) else None,
    )


def read_info(env: Mapping[str, str] | None = None) -> dict[str, object] | None:
    info_path, _token_path = gateway_paths(env)
    if not info_path.is_file():
        return None
    try:
        loaded = json.loads(info_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if isinstance(loaded, dict):
        return loaded
    return None


def probe_health(host: str, port: int, *, timeout: float) -> bool:
    request = (
        f"GET /health HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request)
            data = b""
            while len(data) < 4096:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                data += chunk
    except OSError:
        return False
    head, _, body = data.partition(b"\r\n\r\n")
    if b" 200 " not in head:
        return False
    return b'"ok": true' in body or b'"ok":true' in body


def pid_is_daemon(pid: int) -> bool:
    """True when ``pid`` still looks like this daemon. Avoids killing a recycled pid."""
    if pid <= 0:
        return False
    proc = Path(f"/proc/{pid}/cmdline")
    try:
        raw = proc.read_bytes()
    except OSError:
        return False
    text = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace")
    return "praxis-primed" in text or "praxis_prime.daemon" in text or "praxis_prime/daemon" in text
