"""One profile's agent process.

The supervisor starts this module and passes the derived credential on
stdin. The master key is not in the environment. The process binds its
profile and the account data root, opens only that profile's database,
and answers the supervisor on a Unix socket.

``python -m praxis_prime.worker``
"""

from __future__ import annotations

import argparse
import fcntl
import os
import resource
import select
import signal
import socket
import sys
import threading
import time
import uuid
from collections.abc import Mapping
from pathlib import Path

from praxis_prime.approvals.gate import (
    ApprovalRequest,
    approval_account_id,
    approval_session_id,
)
from praxis_prime.approvals.queue import ApprovalQueue, parse_decision
from praxis_prime.host import Host
from praxis_prime.policy.boundary import bind_data_root
from praxis_prime.sandbox.bwrap import bind_profile
from praxis_prime.scheduler.service import scheduler_for
from praxis_prime.scheduler.store import RoutineRun
from praxis_prime.supervisor.confine import ProfileBoundary, assert_profile_file, freeze_worker_env
from praxis_prime.supervisor.credentials import credential_matches
from praxis_prime.supervisor.grants import (
    is_revoked,
    load_live_grants,
    migrate_grants,
    revoke_grant,
    save_grant,
)
from praxis_prime.supervisor.ipc import (
    SUPERVISOR_METHODS,
    IpcError,
    recv_message,
    same_user,
    send_message,
)
from praxis_prime.supervisor.leases import LeaseStore
from praxis_prime.supervisor.redact import redact_value
from praxis_prime.supervisor.socketdir import ensure_private_dir

_NOFILE = 256
# Events waiting for the supervisor to poll one chat's stream. The cap keeps
# that turn from holding an unbounded list. A drain past the cap tells the client.
_STREAM_LIMIT = 500
_STREAM_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")


def remember_stream_event(
    buffer: list[dict[str, object]],
    dropped: int,
    payload: dict[str, object],
    *,
    limit: int = _STREAM_LIMIT,
) -> int:
    """Append one event and return how many have been dropped."""
    buffer.append(payload)
    extra = len(buffer) - limit
    if extra <= 0:
        return dropped
    del buffer[:extra]
    return dropped + extra


def drain_stream(
    buffer: list[dict[str, object]],
    dropped: int,
) -> tuple[list[dict[str, object]], int]:
    """Take the buffer. A drop count becomes the first event the client sees."""
    events = list(buffer)
    buffer.clear()
    if dropped:
        events.insert(
            0,
            {
                "kind": "status",
                "phase": "truncated",
                "detail": "earlier stream events were dropped",
                "dropped": dropped,
            },
        )
    return events, 0


class _ChatStream:
    """One chat call's events. Other calls never read or clear this list."""

    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []
        self.dropped = 0


def _stream_body(events: list[dict[str, object]]) -> dict[str, object]:
    body: dict[str, object] = {"events": events}
    if events and events[0].get("phase") == "truncated":
        body["truncated"] = True
        body["dropped"] = events[0].get("dropped", 0)
    return body


def stream_id_of(value: object) -> str:
    """A caller-supplied stream id, or empty when the value cannot be one."""
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text or len(text) > 64 or any(char not in _STREAM_ID_CHARS for char in text):
        return ""
    return text


def main(argv: list[str] | None = None) -> int:
    _arm_supervisor_pipe()
    parser = argparse.ArgumentParser(prog="praxis-prime-worker")
    parser.add_argument("--profile", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--supervisor-socket", required=True)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--generation", type=int, required=True)
    parser.add_argument("--config", default="")
    args = parser.parse_args(argv)
    credential = sys.stdin.readline().strip()
    if not credential or args.generation < 1:
        print("praxis-prime-worker: missing credential", file=sys.stderr)
        return 2
    os.environ.pop("PRAXIS_PRIME_WORKER_MASTER", None)
    os.environ["PRAXIS_PRIME_WORKER_PROFILE"] = args.profile
    os.environ["PRAXIS_PRIME_WORKER_DATA"] = args.data_dir
    freeze_worker_env()
    apply_limits()
    try:
        app = WorkerApp(
            profile=args.profile,
            data_root=Path(args.data_dir),
            socket_path=Path(args.socket),
            supervisor_socket=Path(args.supervisor_socket),
            credential=credential,
            generation=args.generation,
            config_path=Path(args.config) if args.config else None,
        )
        return app.serve()
    except (OSError, ProfileBoundary, ValueError) as exc:
        print(f"praxis-prime-worker: {exc}", file=sys.stderr)
        return 1


def apply_limits() -> None:
    """Cap open files. Address space is capped only when the env asks."""
    soft = resource.getrlimit(resource.RLIMIT_NOFILE)
    nofile = min(_NOFILE, soft[1] if soft[1] > 0 else _NOFILE)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
    except (OSError, ValueError):
        pass
    raw = os.environ.get("PRAXIS_PRIME_WORKER_AS_BYTES", "").strip()
    if not raw:
        return
    try:
        size = int(raw)
    except ValueError:
        return
    if size > 0:
        resource.setrlimit(resource.RLIMIT_AS, (size, size))


class WorkerApp:
    """The profile runtime behind the worker socket."""

    def __init__(
        self,
        *,
        profile: str,
        data_root: Path,
        socket_path: Path,
        supervisor_socket: Path,
        credential: str,
        generation: int,
        config_path: Path | None,
    ) -> None:
        self.profile = profile
        self.data_root = data_root
        self.socket_path = socket_path
        self.supervisor_socket = supervisor_socket
        self.credential = credential
        self.generation = generation
        self.config_path = config_path
        self._stop = threading.Event()
        self._events: list[dict[str, object]] = []
        self._event_lock = threading.Lock()
        self._streams: dict[str, _ChatStream] = {}
        self._stream_lock = threading.Lock()
        self._listen: socket.socket | None = None
        self._lock_fd = _lock_profile(data_root / "profiles" / profile)
        self._data_token = bind_data_root(data_root)
        self._profile_token = bind_profile(profile)
        from praxis_prime.runtime import build_runtime

        self.runtime = build_runtime(
            env=os.environ,
            config_path=config_path,
            profile=profile,
            cwd=data_root / "profiles" / profile,
        )
        assert_profile_file(data_root, profile, self.runtime.db.path)
        self.queue = ApprovalQueue()
        self.queue.profile_id = profile
        self.queue.on_pending = self._queue_event
        self.queue.on_resolved = self._queue_event
        self.host = Host(self.runtime, self.queue)
        self._install_grants()
        self.leases = LeaseStore(self.runtime.db, clock=time.time)
        self._profile_mtime = _mtime(self.runtime_home() / "profile.toml")
        self.scheduler = scheduler_for(
            self.runtime,
            deliver=self._deliver,
            lane=self.host._lock,
        )
        inner = self.scheduler.runner
        self.scheduler.runner = lambda routine, trigger: self._run_routine(routine, trigger, inner)
        self._watch = threading.Thread(target=self._watch_loop, name="praxis-revoke", daemon=True)

    def runtime_home(self) -> Path:
        return self.data_root / "profiles" / self.profile

    def serve(self) -> int:
        self.scheduler.start()
        self._watch.start()
        self._listen = _bind(self.socket_path)
        try:
            while not self._stop.is_set():
                try:
                    conn, _addr = self._listen.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                threading.Thread(
                    target=self._client,
                    args=(conn,),
                    name="praxis-worker-rpc",
                    daemon=True,
                ).start()
        finally:
            self.shutdown()
        return 0

    def shutdown(self) -> None:
        if self._stop.is_set() and self._listen is None:
            return
        self._stop.set()
        self.queue.deny_all(actor="shutdown")
        self.scheduler.request_stop()
        self.scheduler.join(timeout=2)
        listen = self._listen
        self._listen = None
        if listen is not None:
            try:
                listen.close()
            except OSError:
                pass
        self.socket_path.unlink(missing_ok=True)
        self.host.close()
        if self._data_token is not None:
            from praxis_prime.policy.boundary import release_data_root

            release_data_root(self._data_token)
            self._data_token = None
        if self._profile_token is not None:
            from praxis_prime.sandbox.bwrap import release_profile

            release_profile(self._profile_token)
            self._profile_token = None
        if self._lock_fd >= 0:
            os.close(self._lock_fd)
            self._lock_fd = -1

    def _client(self, conn: socket.socket) -> None:
        try:
            if not same_user(conn):
                return
            first = recv_message(conn)
            if not self._auth(first):
                send_message(conn, {"id": first.get("id", ""), "ok": False, "error": "rejected"})
                return
            send_message(conn, {"id": first.get("id", ""), "ok": True, "result": {}})
            while not self._stop.is_set():
                message = recv_message(conn)
                method = str(message.get("method", ""))
                if method not in SUPERVISOR_METHODS:
                    send_message(
                        conn,
                        {"id": message.get("id", ""), "ok": False, "error": "forbidden"},
                    )
                    continue
                params = message.get("params")
                body = params if isinstance(params, dict) else {}
                try:
                    result = self.handle(method, body)
                except PermissionError as exc:
                    send_message(
                        conn,
                        {"id": message.get("id", ""), "ok": False, "error": str(exc)},
                    )
                    continue
                except LookupError as exc:
                    send_message(
                        conn,
                        {"id": message.get("id", ""), "ok": False, "error": str(exc)},
                    )
                    continue
                except WorkerStop:
                    send_message(
                        conn,
                        {"id": message.get("id", ""), "ok": True, "result": {"stopping": True}},
                    )
                    self._stop.set()
                    return
                send_message(
                    conn,
                    {
                        "id": message.get("id", ""),
                        "ok": True,
                        "result": redact_value(result, [self.credential]),
                    },
                )
        except IpcError:
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _auth(self, message: Mapping[str, object]) -> bool:
        if message.get("method") != "auth":
            return False
        if str(message.get("profile", "")) != self.profile:
            return False
        return credential_matches(str(message.get("token", "")), self.credential)

    def handle(self, method: str, params: Mapping[str, object]) -> dict[str, object]:
        claimed = params.get("profile")
        if isinstance(claimed, str) and claimed.strip() and claimed.strip() != self.profile:
            raise PermissionError("this daemon runs a different profile")
        if method == "health":
            return {"ready": True, "profile": self.profile, "pid": os.getpid()}
        if method == "shutdown":
            raise WorkerStop()
        if method == "status":
            return self.host.status()
        if method == "chat":
            return self._chat(params)
        if method == "approvals.list":
            return {"approvals": self.queue.list_pending()}
        if method == "approvals.get":
            item = self.queue.get(str(params.get("approvalId", "")))
            return {"approval": item}
        if method == "approvals.decide":
            decision = parse_decision(params.get("decision"))
            item = self.queue.decide(
                str(params.get("approvalId", "")),
                decision,
                actor=str(params.get("actor", "") or "operator"),
            )
            return {"approval": item}
        if method == "approvals.deny_all":
            self.queue.deny_all(actor=str(params.get("actor", "") or "shutdown"))
            return {}
        if method == "session.drop":
            self.host.drop_session(
                str(params.get("sessionId", "") or "") or None,
                account_id=str(params.get("account", "")),
            )
            return {}
        if method == "session.owner":
            found = self.runtime.store.owner(str(params.get("sessionId", "")))
            if found is None:
                return {"owner": None}
            return {"owner": {"account": found[0], "profile": found[1]}}
        if method == "model.set":
            return {"model": self.host.set_model(str(params.get("spec", "")))}
        if method == "routine.fire":
            status, payload = self.scheduler.fire_http(str(params.get("routineId", "")))
            return {"status": status, "payload": payload}
        if method == "revoke":
            self.host.cancel_turn(actor=str(params.get("actor", "") or "revoked"))
            self._audit("access.revoked", "in-flight turn cancelled")
            return {"cancelled": True}
        if method == "memory.remember":
            entry = self.runtime.memory.remember(str(params.get("content", "")))
            return {"id": entry.id, "content": entry.content}
        if method == "memory.list":
            rows = self.runtime.memory.list_entries()
            return {"entries": [item.content for item in rows]}
        if method == "memory.catalog":
            from praxis_prime.catalog import memory_rows

            return {"entries": memory_rows(self.runtime.memory)}
        if method == "skills.list":
            from praxis_prime.catalog import skill_rows

            return {"skills": skill_rows(self.runtime.skills)}
        if method == "routines.list":
            from praxis_prime.catalog import routine_rows

            return {"routines": routine_rows(self.scheduler.store)}
        if method == "chat.events":
            return self._read_stream(stream_id_of(params.get("streamId")))
        if method == "events.pull":
            with self._event_lock:
                events = list(self._events)
                self._events.clear()
            return {"events": events}
        if method == "runtime.reload":
            import sqlite3

            from praxis_prime.runtime import reload_serving_router

            if self.config_path is None:
                raise LookupError("router reload failed")
            try:
                reload_serving_router(
                    self.host.runtime,
                    env=os.environ,
                    config_path=self.config_path,
                    lock=self.host._lock,
                )
            except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
                raise LookupError("router reload failed") from exc
            return {"ok": True}
        raise IpcError("method is not allowed")

    def _chat(self, params: Mapping[str, object]) -> dict[str, object]:
        text = params.get("text")
        if not isinstance(text, str) or not text.strip():
            raise LookupError("chat text is empty")
        session = params.get("sessionId")
        session_id = session if isinstance(session, str) and session else None
        stream_id = stream_id_of(params.get("streamId")) or uuid.uuid4().hex

        def on_event(payload: dict[str, object]) -> None:
            self._note_stream(stream_id, payload)

        try:
            result = self.host.chat(
                text,
                session_id=session_id,
                untrusted=bool(params.get("untrusted")),
                source=str(params.get("source", "") or "channel"),
                channel=str(params.get("channel", "")),
                owner_account=str(params.get("account", "")),
                owner_profile=self.profile,
                on_event=on_event,
            )
            tail = self._take_stream(stream_id)
        finally:
            self._drop_stream(stream_id)
        body: dict[str, object] = {
            "sessionId": result.session_id,
            "text": result.text,
            "error": result.error,
            "cancelled": result.cancelled,
        }
        if tail:
            body["events"] = tail
        return body

    def _note_stream(self, stream_id: str, payload: dict[str, object]) -> None:
        with self._stream_lock:
            buf = self._streams.get(stream_id)
            if buf is None:
                buf = _ChatStream()
                self._streams[stream_id] = buf
            buf.dropped = remember_stream_event(buf.events, buf.dropped, payload)

    def _read_stream(self, stream_id: str) -> dict[str, object]:
        """Events for one chat call. An unknown id does not touch any other call."""
        if not stream_id:
            return {"events": []}
        with self._stream_lock:
            buf = self._streams.get(stream_id)
            if buf is None:
                return {"events": []}
            events, buf.dropped = drain_stream(buf.events, buf.dropped)
        return _stream_body(events)

    def _take_stream(self, stream_id: str) -> list[dict[str, object]]:
        with self._stream_lock:
            buf = self._streams.pop(stream_id, None)
        if buf is None:
            return []
        events, _dropped = drain_stream(buf.events, buf.dropped)
        return events

    def _drop_stream(self, stream_id: str) -> None:
        with self._stream_lock:
            self._streams.pop(stream_id, None)

    def _install_grants(self) -> None:
        legacy = self.runtime_home() / "grants-legacy.json"
        migrate_grants(self.runtime.db, legacy)
        gate = self.runtime.gate
        gate.recheck = self._grant_still_valid
        gate.persist = self._persist_grant
        gate.on_revoke = self._persist_revoke
        for account, session, key in load_live_grants(self.runtime.db):
            if is_revoked(
                self.runtime.db,
                account_id=account,
                session_id=session,
                grant_key=key,
            ):
                continue
            if account and not self._supervisor_allows(account):
                revoke_grant(
                    self.runtime.db,
                    account_id=account,
                    session_id=session,
                    grant_key=key,
                )
                continue
            gate.remember(account, session, key)

    def _grant_still_valid(self, request: ApprovalRequest) -> bool:
        account = approval_account_id.get()
        session = approval_session_id.get() or ""
        if is_revoked(
            self.runtime.db,
            account_id=account,
            session_id=session,
            grant_key=request.grant_key,
        ):
            return False
        if account and not self._supervisor_allows(account):
            return False
        return True

    def _persist_grant(self, request: ApprovalRequest) -> None:
        save_grant(
            self.runtime.db,
            account_id=approval_account_id.get(),
            session_id=approval_session_id.get() or "",
            grant_key=request.grant_key,
            profile_id=self.profile,
        )

    def _persist_revoke(self, request: ApprovalRequest) -> None:
        revoke_grant(
            self.runtime.db,
            account_id=approval_account_id.get(),
            session_id=approval_session_id.get() or "",
            grant_key=request.grant_key,
        )

    def _supervisor_allows(self, account: str) -> bool:
        try:
            sock = _connect_supervisor(self.supervisor_socket, 2)
        except (IpcError, OSError):
            return False
        try:
            send_message(
                sock,
                {
                    "id": "auth",
                    "method": "auth",
                    "profile": self.profile,
                    "generation": self.generation,
                    "token": self.credential,
                },
            )
            auth = recv_message(sock)
            if not auth.get("ok"):
                return False
            send_message(
                sock,
                {"id": "grant", "method": "grant.check", "account": account},
            )
            reply = recv_message(sock)
        except (IpcError, OSError):
            return False
        finally:
            sock.close()
        result = reply.get("result")
        return isinstance(result, dict) and bool(result.get("allowed"))

    def _run_routine(self, routine: object, trigger: str, inner: object) -> RoutineRun:
        routine_id = str(getattr(routine, "id", ""))
        owner = str(os.getpid())
        decision, token = self.leases.acquire(routine_id, owner)
        if decision == "skip":
            self._audit("routine.lease", "routine lease held or retry already used")
            return _skipped(routine_id, trigger, "lease held")
        if decision == "retry":
            self._audit("routine.lease", "routine lease expired; retrying once")
        actor = _run_as(self.runtime.db, routine_id)
        if actor and not self._supervisor_allows(actor):
            self.host.cancel_turn(actor="revoked")
            self._audit("access.revoked", "routine actor lost access")
            self.leases.release(routine_id, owner, token)
            return _skipped(routine_id, trigger, "membership revoked")
        stop_beat = threading.Event()
        beat_lock = threading.Lock()
        interval = max(1.0, self.leases.ttl / 3.0)

        def beat() -> None:
            while not stop_beat.wait(interval):
                with beat_lock:
                    if stop_beat.is_set():
                        return
                    self.leases.renew(routine_id, owner, token)

        thread = threading.Thread(target=beat, name="praxis-lease", daemon=True)
        thread.start()
        try:
            run = inner(routine, trigger)  # type: ignore[operator]
        finally:
            stop_beat.set()
            with beat_lock:
                self.leases.release(routine_id, owner, token)
            thread.join(timeout=2)
        return run

    def _watch_loop(self) -> None:
        while not self._stop.wait(0.2):
            if _supervisor_gone():
                os.kill(os.getpid(), signal.SIGTERM)
                return
            account = self.host.active_account()
            if account and not self._supervisor_allows(account):
                if self.host.cancel_turn(actor="revoked"):
                    self._audit("access.revoked", "membership revoked during a turn")
                continue
            current = _mtime(self.runtime_home() / "profile.toml")
            if self._profile_mtime and current and current != self._profile_mtime:
                self._profile_mtime = current
                if self.host.cancel_turn(actor="profile-changed"):
                    self._audit("access.revoked", "profile changed during a turn")

    def _queue_event(self, item: dict[str, object]) -> None:
        with self._event_lock:
            self._events.append({"kind": "approval", "approval": dict(item)})

    def _deliver(self, text: str) -> None:
        self._emit("routine", {"text": text})

    def _emit(self, kind: str, body: dict[str, object]) -> None:
        try:
            sock = _connect_supervisor(self.supervisor_socket, 2)
        except (IpcError, OSError):
            return
        try:
            send_message(
                sock,
                {
                    "id": "auth",
                    "method": "auth",
                    "profile": self.profile,
                    "generation": self.generation,
                    "token": self.credential,
                },
            )
            if not recv_message(sock).get("ok"):
                return
            send_message(
                sock,
                {
                    "id": "event",
                    "method": "event",
                    "kind": kind,
                    "profile": self.profile,
                    "body": body,
                },
            )
            recv_message(sock)
        except (IpcError, OSError):
            return
        finally:
            sock.close()

    def _audit(self, kind: str, summary: str) -> None:
        try:
            self.runtime.audit.append(
                session_id=None,
                kind=kind,
                summary=summary,
                payload={"profile": self.profile},
            )
        except Exception:
            pass
        self._emit("audit", {"kind": kind, "summary": summary})


class WorkerStop(Exception):
    """The supervisor asked this worker to exit."""


def _lock_profile(home: Path) -> int:
    home.mkdir(parents=True, exist_ok=True)
    path = home / "worker.lock"
    fd = _lock_once(path)
    if fd < 0 and _reap_stale_holder(path):
        fd = _lock_once(path)
    if fd < 0:
        raise ProfileBoundary("this profile already has a worker")
    _stamp_lock(fd)
    return fd


def _lock_once(path: Path) -> int:
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        return -1
    return fd


def _stamp_lock(fd: int) -> None:
    supervisor = os.environ.get("PRAXIS_PRIME_SUPERVISOR_PID", "0").strip() or "0"
    started = os.environ.get("PRAXIS_PRIME_SUPERVISOR_START", "").strip() or "-"
    token = os.environ.get("PRAXIS_PRIME_SUPERVISOR_TOKEN", "").strip() or "-"
    os.ftruncate(fd, 0)
    os.lseek(fd, 0, os.SEEK_SET)
    os.write(fd, f"{os.getpid()} {supervisor} {started} {token}\n".encode())


def _reap_stale_holder(path: Path) -> bool:
    """Stop a holder whose supervisor is dead or whose start time does not match.

    A live pid is not enough: the pid may have been reused. The stamp has to
    carry the same start time. A stamp with no start time is reaped, and the
    signal goes to the holder recorded in the lock, not to the supervisor pid.
    A different ``PRAXIS_PRIME_SUPERVISOR_TOKEN`` does not make a live
    supervisor stale. Two supervisors on one data root have different tokens;
    the second worker refuses while the first supervisor is still that process.
    """
    try:
        text = path.read_text(encoding="utf-8").split()
    except OSError:
        return False
    if len(text) < 2:
        return False
    try:
        worker_pid = int(text[0])
        supervisor_pid = int(text[1])
    except ValueError:
        return False
    started = text[2] if len(text) >= 3 and text[2] not in {"", "-"} else None
    if worker_pid <= 1 or _supervisor_still_running(supervisor_pid, started):
        return False
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.kill(worker_pid, sig)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        time.sleep(0.05)
    return not _pid_alive(worker_pid)


def _supervisor_still_running(pid: int, started: str | None) -> bool:
    """True when the stamped supervisor is alive with that ``/proc`` start time.

    The token in the lock is not part of this check. Matching pid and start
    time means the process that stamped the lock is still that process, so
    the holder is live and must not be signalled.
    """
    if pid <= 1 or not started or not _pid_alive(pid):
        return False
    current = _process_start(pid)
    if current is None:
        return False
    return current == started


def _bind(path: Path) -> socket.socket:
    ensure_private_dir(path.parent)
    if path.exists():
        path.unlink()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(path))
    os.chmod(path, 0o600)
    sock.listen(16)
    sock.settimeout(0.5)
    return sock


def _connect_supervisor(path: Path, timeout: float) -> socket.socket:
    """Connect and refuse another uid before any credential is written."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(str(path))
        if not same_user(sock):
            raise IpcError("peer uid rejected")
    except Exception:
        sock.close()
        raise
    return sock


def _arm_supervisor_pipe() -> None:
    """Exit when the supervisor process closes its end of the pipe.

    The write end is held by the supervisor process, so a request thread
    returning does not close it. ``PR_SET_PDEATHSIG`` is not used: that
    signal is delivered when the thread that forked this process exits.
    A worker started under ``systemd-run`` does not receive the pipe and
    uses the supervisor-pid watch instead.
    """
    raw = os.environ.get("PRAXIS_PRIME_SUPERVISOR_PIPE", "").strip()
    if not raw:
        return
    try:
        fd = int(raw)
    except ValueError:
        return
    # select leaves O_NONBLOCK alone. That flag is shared with the supervisor
    # and with every other worker that inherited this pipe.
    state = _pipe_signaled(fd, wait=0)
    if state is None:
        return
    if state:
        _exit_with_supervisor()
        return

    def watch() -> None:
        if _pipe_signaled(fd, wait=None):
            _exit_with_supervisor()

    threading.Thread(target=watch, name="praxis-supervisor-pipe", daemon=True).start()


def _pipe_signaled(fd: int, *, wait: float | None) -> bool | None:
    """True when the pipe is closed, False while it is open, None if ``fd`` is bad."""
    try:
        readable, _, _ = select.select([fd], [], [], wait)
    except (OSError, ValueError):
        return None
    if not readable:
        return False
    try:
        os.read(fd, 1)
    except OSError:
        return None
    return True


def _exit_with_supervisor() -> None:
    os.kill(os.getpid(), signal.SIGTERM)
    if threading.current_thread() is threading.main_thread():
        raise SystemExit(128 + signal.SIGTERM)


def _supervisor_gone() -> bool:
    raw = os.environ.get("PRAXIS_PRIME_SUPERVISOR_PID", "").strip()
    if not raw:
        return False
    try:
        pid = int(raw)
    except ValueError:
        return False
    return pid > 0 and not _pid_alive(pid)


def _process_start(pid: int) -> str | None:
    """``/proc/<pid>/stat`` field 22 (starttime), or None when it cannot be read."""
    if pid <= 0:
        return None
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        fields = text.rsplit(")", 1)[1].split()
        return fields[19]
    except (IndexError, OSError):
        return None


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        state = stat.rsplit(")", 1)[1].split()[0]
    except (IndexError, OSError):
        return True
    return state != "Z"


def _mtime(path: Path) -> int:
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return 0


def _skipped(routine_id: str, trigger: str, summary: str) -> RoutineRun:
    return RoutineRun(
        id="",
        routine_id=routine_id,
        session_id="",
        started_at="",
        finished_at="",
        outcome="skipped",
        summary=summary,
        trigger=trigger,
    )


def _run_as(db: object, routine_id: str) -> str:
    conn = getattr(db, "conn", None)
    if conn is None:
        return ""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS routine_actors (
            routine_id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL
        )
        """
    )
    row = conn.execute(
        "SELECT account_id FROM routine_actors WHERE routine_id = ?",
        (routine_id,),
    ).fetchone()
    if row is None:
        return ""
    return str(row[0])


def set_run_as(db: object, routine_id: str, account_id: str) -> None:
    """Record the account a routine runs as. The worker rechecks it."""
    conn = getattr(db, "conn", None)
    if conn is None:
        return
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS routine_actors (
            routine_id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        INSERT INTO routine_actors (routine_id, account_id) VALUES (?, ?)
        ON CONFLICT (routine_id) DO UPDATE SET account_id = excluded.account_id
        """,
        (routine_id, account_id),
    )
    conn.commit()


if __name__ == "__main__":
    raise SystemExit(main())
