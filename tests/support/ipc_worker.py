"""Stand-in worker for supervisor tests.

It speaks the supervisor's Unix RPC and does not open a profile database.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from pathlib import Path

from praxis_prime.supervisor.credentials import credential_matches
from praxis_prime.supervisor.ipc import SUPERVISOR_METHODS, IpcError, recv_message, send_message


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--supervisor-socket", default="")
    parser.add_argument("--data-dir", default="")
    parser.add_argument("--generation", type=int, default=1)
    parser.add_argument("--config", default="")
    args = parser.parse_args()
    credential = sys.stdin.readline().strip()
    if not credential:
        return 2
    _write_env()
    if os.environ.get("STUB_MODE") == "crash":
        return 3
    memory: list[str] = []
    approval = _approval(args.profile)
    stop = threading.Event()
    sock = _bind(Path(args.socket))
    try:
        while not stop.is_set():
            try:
                conn, _addr = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(
                target=_client,
                args=(conn, args.profile, credential, memory, approval, stop),
                daemon=True,
            ).start()
    finally:
        sock.close()
    return 0


def _write_env() -> None:
    path = os.environ.get("STUB_ENV_PATH", "")
    if not path:
        return
    Path(path).write_text(json.dumps(dict(os.environ)), encoding="utf-8")


def _approval(profile: str) -> dict[str, object]:
    approval_id = "ap_aaaaaaaa" if profile == "ada" else "ap_bbbbbbbb"
    return {
        "id": approval_id,
        "tool": "shell",
        "risk": "destructive",
        "state": "pending",
        "profileId": profile,
        "requester": f"acct-{profile}",
        "createdAt": "2026-01-01T00:00:00+00:00",
    }


def _client(
    conn: object,
    profile: str,
    credential: str,
    memory: list[str],
    approval: dict[str, object],
    stop: threading.Event,
) -> None:
    try:
        first = recv_message(conn)  # type: ignore[arg-type]
        token = str(first.get("token", ""))
        claimed = str(first.get("profile", ""))
        matched = (
            first.get("method") == "auth"
            and claimed == profile
            and credential_matches(token, credential)
        )
        if not matched:
            send_message(
                conn,  # type: ignore[arg-type]
                {"id": first.get("id", ""), "ok": False, "error": "rejected"},
            )
            return
        send_message(conn, {"id": first.get("id", ""), "ok": True, "result": {}})  # type: ignore[arg-type]
        message = recv_message(conn)  # type: ignore[arg-type]
        method = str(message.get("method", ""))
        if method not in SUPERVISOR_METHODS:
            send_message(
                conn,  # type: ignore[arg-type]
                {"id": message.get("id", ""), "ok": False, "error": "forbidden"},
            )
            return
        params = message.get("params")
        body = params if isinstance(params, dict) else {}
        result = _handle(method, body, profile, memory, approval, stop)
        send_message(
            conn,  # type: ignore[arg-type]
            {"id": message.get("id", ""), "ok": True, "result": result},
        )
        if method == "shutdown" or (method == "health" and os.environ.get("STUB_MODE") == "die"):
            stop.set()
    except IpcError:
        return
    finally:
        try:
            conn.close()  # type: ignore[attr-defined]
        except OSError:
            return


def _handle(
    method: str,
    params: dict[str, object],
    profile: str,
    memory: list[str],
    approval: dict[str, object],
    stop: threading.Event,
) -> dict[str, object]:
    if method == "health":
        return {"ready": True, "profile": profile, "pid": os.getpid()}
    if method == "shutdown":
        return {"stopping": True}
    if method == "events.pull":
        return {"events": []}
    if method == "memory.remember":
        memory.append(str(params.get("content", "")))
        return {"content": memory[-1]}
    if method == "memory.list":
        return {"entries": list(memory)}
    if method == "approvals.list":
        return {"approvals": [dict(approval)]}
    if method == "approvals.get":
        if str(params.get("approvalId", "")) == approval["id"]:
            return {"approval": dict(approval)}
        return {"approval": None}
    if method == "approvals.decide":
        approval["state"] = str(params.get("decision", ""))
        return {"approval": dict(approval)}
    if method == "chat":
        _note_chat(profile)
        _hold_for_revoke(stop)
        return {"text": "ok", "sessionId": "s", "cancelled": False, "error": None}
    if method == "revoke":
        _release_chat()
        return {"cancelled": True}
    if method == "status":
        return {"model": "stub", "profile": profile}
    if method == "model.set":
        return {"model": str(params.get("spec", ""))}
    if method == "session.owner":
        wanted = os.environ.get("STUB_SESSION_ID", "")
        session_id = str(params.get("sessionId", ""))
        owner_profile = os.environ.get("STUB_SESSION_PROFILE", "")
        if wanted and session_id == wanted and (not owner_profile or owner_profile == profile):
            return {
                "owner": {
                    "account": os.environ.get("STUB_SESSION_ACCOUNT", "acct"),
                    "profile": profile,
                }
            }
        return {"owner": None}
    return {}


def _note_chat(profile: str) -> None:
    path = os.environ.get("STUB_CHAT_LOG", "")
    if not path:
        return
    with Path(path).open("a", encoding="utf-8") as handle:
        handle.write(profile + "\n")


def _hold_for_revoke(stop: threading.Event) -> None:
    path = os.environ.get("STUB_HOLD_CHAT", "")
    if not path:
        return
    flag = Path(path)
    flag.write_text("chat", encoding="utf-8")
    while not stop.is_set():
        if flag.exists() and flag.read_text(encoding="utf-8") == "go":
            return
        stop.wait(0.05)


def _release_chat() -> None:
    path = os.environ.get("STUB_HOLD_CHAT", "")
    if path:
        Path(path).write_text("go", encoding="utf-8")


def _bind(path: Path):
    import socket

    if path.exists():
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(path))
    os.chmod(path, 0o600)
    sock.listen(16)
    sock.settimeout(0.5)
    return sock


if __name__ == "__main__":
    raise SystemExit(main())
