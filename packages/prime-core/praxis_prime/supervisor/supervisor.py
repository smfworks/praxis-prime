"""Start, stop, restart, and health-check one worker per profile.

The supervisor holds the master key. A worker can ask it to check a grant
for its own profile and to record an event. It cannot ask for another
profile's data, a new worker, or the master key.

Idle workers exit and start again on the next request. A crash waits
through exponential backoff before the next start.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from praxis_prime.accounts.db import AccountStore
from praxis_prime.accounts.roles import can_chat, sees_all_profiles
from praxis_prime.profiles.home import list_profiles
from praxis_prime.profiles.ids import profile_id
from praxis_prime.supervisor import credentials, migrate
from praxis_prime.supervisor.ipc import (
    EVENT_KINDS,
    WORKER_METHODS,
    IpcError,
    recv_message,
    same_user,
    send_message,
)
from praxis_prime.supervisor.redact import redact_value

Clock = Callable[[], float]
_DROPPED_ENV = frozenset(
    {
        "PRAXIS_PRIME_WORKER_MASTER",
        "PRAXIS_PRIME_TELEGRAM_BOT_TOKEN",
        "PRAXIS_PRIME_SECRETS_FILE",
    }
)


class WorkerUnavailable(RuntimeError):
    """The profile's worker is not running and cannot be started yet."""


@dataclass
class WorkerSlot:
    profile: str
    generation: int
    credential: str
    socket_path: Path
    process: subprocess.Popen[bytes] | None = None
    last_used: float = 0.0
    failures: int = 0
    next_start: float = 0.0
    state: str = "stopped"
    wanted: bool = False
    log_path: Path | None = None


@dataclass
class Supervisor:
    """Owns worker processes for one data directory."""

    data_root: Path
    runtime_dir: Path
    state_dir: Path
    env: Mapping[str, str]
    config_path: Path | None = None
    accounts: AccountStore | None = None
    clock: Clock = time.monotonic
    idle_after: float = 900.0
    backoff_base: float = 0.5
    backoff_cap: float = 30.0
    start_timeout: float = 20.0
    use_slice: bool = False
    command: list[str] | None = None
    on_event: Callable[[str, str, dict[str, object]], None] | None = None
    _slots: dict[str, WorkerSlot] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None
    _control: socket.socket | None = None
    _control_thread: threading.Thread | None = None
    _approval_profile: dict[str, str] = field(default_factory=dict)
    _paused: set[str] = field(default_factory=set)
    _master: bytes = b""
    _migrated: bool = False
    _sock_tag: str = ""
    _socket_dir: Path | None = None

    def __post_init__(self) -> None:
        self.data_root = Path(self.data_root)
        self.runtime_dir = Path(self.runtime_dir)
        self.state_dir = Path(self.state_dir)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.runtime_dir, 0o700)
        self._sock_tag = uuid.uuid4().hex[:8]
        self._master = credentials.load_or_create_master(self.master_path)

    @property
    def master_path(self) -> Path:
        return self.runtime_dir / "worker-master.key"

    @property
    def generation_path(self) -> Path:
        return self.state_dir / "worker-generations.json"

    @property
    def control_path(self) -> Path:
        return self._socket_file("supervisor")

    def start(self) -> None:
        """Listen for worker calls and watch process health."""
        with self._lock:
            self._migrated = migrate.migrate_install(self.data_root) or self._migrated
            for name in self.profiles():
                self._reserve_socket(name)
            if self._control is None:
                self._control = _bind_unix(self.control_path)
                self._control_thread = threading.Thread(
                    target=self._accept_control,
                    name="praxis-supervisor",
                    daemon=True,
                )
                self._control_thread.start()
            if self._thread is None:
                self._stop.clear()
                self._thread = threading.Thread(
                    target=self._loop,
                    name="praxis-workers",
                    daemon=True,
                )
                self._thread.start()

    def close(self) -> None:
        self._stop.set()
        with self._lock:
            names = list(self._slots)
        for name in names:
            self.stop(name, reason="shutdown")
        control = self._control
        self._control = None
        if control is not None:
            try:
                control.close()
            except OSError:
                pass
        if self._socket_dir is not None and self.control_path.exists():
            self.control_path.unlink(missing_ok=True)
        directory = self._socket_dir
        if directory is not None and directory != self.runtime_dir:
            shutil.rmtree(directory, ignore_errors=True)
        elif directory is not None:
            for name in self.profiles():
                (directory / f"{self._sock_tag}-{name}.sock").unlink(missing_ok=True)

    def profiles(self) -> list[str]:
        return list_profiles(self.data_root)

    def running(self) -> list[str]:
        with self._lock:
            names = []
            for name, slot in self._slots.items():
                process = slot.process
                alive = process is not None and process.poll() is None
                if slot.state == "running" and alive:
                    names.append(name)
            return names

    def snapshot(self) -> list[dict[str, object]]:
        """Public worker rows. Credentials are not included."""
        with self._lock:
            rows = []
            for name, slot in sorted(self._slots.items()):
                process = slot.process
                alive = process is not None and process.poll() is None
                pid = process.pid if process is not None and alive else 0
                rows.append(
                    {
                        "profile": name,
                        "pid": pid,
                        "state": slot.state,
                        "generation": slot.generation,
                        "failures": slot.failures,
                    }
                )
            return rows

    def pause(self, profile: str) -> None:
        checked = _require_profile(profile)
        with self._lock:
            self._paused.add(checked)
        if checked in self.running():
            try:
                self.call(checked, "revoke", {"actor": "paused"}, timeout=2)
            except (IpcError, WorkerUnavailable):
                return

    def resume(self, profile: str) -> None:
        with self._lock:
            self._paused.discard(_require_profile(profile))

    def bump(self, profile: str) -> int:
        """Invalidate one profile's credential and stop its worker."""
        checked = _require_profile(profile)
        generation = credentials.bump_generation(self.generation_path, checked)
        self.stop(checked, reason="rotated")
        return generation

    def rotate_master(self) -> None:
        """Replace the master key and stop every worker."""
        with self._lock:
            self._master = credentials.rotate_master(self.master_path)
            names = list(self._slots)
        for name in names:
            self.stop(name, reason="rotated")

    def ensure(self, profile: str) -> WorkerSlot:
        checked = _require_profile(profile)
        if checked not in self.profiles():
            raise WorkerUnavailable(f"no profile {checked}")
        owner = False
        with self._lock:
            slot = self._slots.get(checked)
            now = self.clock()
            if _alive(slot):
                assert slot is not None
                slot.wanted = True
                return slot
            if (
                slot is not None
                and slot.state == "starting"
                and slot.process is not None
                and slot.process.poll() is None
            ):
                pass
            elif slot is not None and slot.state == "backoff" and slot.next_start > now:
                raise WorkerUnavailable("worker restart is backing off")
            else:
                slot = self._spawn_unlocked(checked)
                owner = True
        assert slot is not None
        if owner:
            return self._wait_ready(slot)
        return self._wait_for_peer(slot)

    def call(
        self,
        profile: str,
        method: str,
        params: Mapping[str, object] | None = None,
        *,
        timeout: float = 30.0,
    ) -> dict[str, object]:
        if method not in {
            "health",
            "shutdown",
            "status",
            "chat",
            "approvals.list",
            "approvals.get",
            "approvals.decide",
            "approvals.deny_all",
            "session.drop",
            "session.owner",
            "model.set",
            "routine.fire",
            "revoke",
            "memory.remember",
            "memory.list",
            "events.pull",
        }:
            raise IpcError("method is not allowed")
        slot = self.ensure(profile)
        if method != "health":
            slot.last_used = self.clock()
        result = self._rpc(slot, method, dict(params or {}), timeout=timeout)
        return _as_dict(redact_value(result, self._secret_strings()))

    def stop(self, profile: str, *, reason: str = "stop") -> None:
        with self._lock:
            slot = self._slots.get(profile)
            if slot is None or slot.process is None:
                if slot is not None:
                    slot.state = "idle" if reason == "idle" else "stopped"
                    slot.wanted = False
                return
            proc = slot.process
        try:
            self._rpc(slot, "shutdown", {"reason": reason}, timeout=1)
        except (IpcError, OSError):
            pass
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        with self._lock:
            slot.process = None
            slot.state = "idle" if reason == "idle" else "stopped"
            slot.wanted = False
            if reason == "idle":
                slot.next_start = 0
            if slot.socket_path.exists():
                slot.socket_path.unlink(missing_ok=True)

    def tick(self) -> None:
        """Health-check running workers and apply idle exit and backoff."""
        now = self.clock()
        with self._lock:
            items = list(self._slots.items())
        for profile, slot in items:
            proc = slot.process
            if proc is not None and proc.poll() is not None:
                self._note_failure(profile)
                continue
            if slot.state == "running" and now - slot.last_used >= self.idle_after:
                self.stop(profile, reason="idle")
                continue
            if slot.state == "running" and proc is not None:
                try:
                    self._rpc(slot, "health", {}, timeout=2)
                    pulled = self._rpc(slot, "events.pull", {}, timeout=2)
                except (IpcError, OSError):
                    self._note_failure(profile)
                    continue
                self._take_events(profile, pulled)
            if slot.state == "backoff" and slot.wanted and now >= slot.next_start:
                try:
                    self.ensure(profile)
                except WorkerUnavailable:
                    if slot.state != "backoff":
                        self._note_failure(profile)

    def _take_events(self, profile: str, pulled: Mapping[str, object]) -> None:
        events = pulled.get("events")
        if not isinstance(events, list):
            return
        for event in events:
            if not isinstance(event, dict):
                continue
            kind = str(event.get("kind", ""))
            if kind == "approval":
                body: dict[str, object] = {"approval": event.get("approval")}
            else:
                body = dict(event)
            self._worker_request(
                profile,
                "event",
                {"kind": kind, "profile": profile, "body": body},
            )

    def approval_profile(self, approval_id: str) -> str:
        with self._lock:
            return self._approval_profile.get(approval_id, "")

    def note_approval(self, profile: str, approval_id: str) -> None:
        """Remember which profile created an approval. A later profile cannot replace it."""
        if not approval_id:
            return
        checked = profile_id(profile)
        if checked is None:
            return
        with self._lock:
            self._approval_profile.setdefault(approval_id, checked)

    def account_allowed(self, profile: str, account_id: str) -> bool:
        """True when ``account_id`` may still act on ``profile``."""
        if profile in self._paused:
            return False
        if self.accounts is None or not account_id:
            return self.accounts is None
        account = self.accounts.get_id(account_id)
        if account is None or account.status != "active":
            return False
        if sees_all_profiles(account.role):
            return True
        membership = self.accounts.membership(account_id, profile)
        if membership is None:
            return False
        return can_chat(account.role, membership)

    def worker_env(self, profile: str) -> dict[str, str]:
        """Environment passed to a worker. The master key is not in it."""
        env = {key: value for key, value in self.env.items() if key not in _DROPPED_ENV}
        env["PRAXIS_PRIME_WORKER_PROFILE"] = profile
        env["PRAXIS_PRIME_WORKER_DATA"] = str(self.data_root)
        env["PRAXIS_PRIME_SUPERVISOR_PID"] = str(os.getpid())
        env.pop("PRAXIS_PRIME_WORKER_MASTER", None)
        return env

    def _secret_strings(self) -> list[str]:
        values = [self._master.hex()]
        with self._lock:
            values.extend(slot.credential for slot in self._slots.values())
        return values

    def _spawn_unlocked(self, profile: str) -> WorkerSlot:
        """Start the process. The caller holds ``_lock`` and waits outside it."""
        try:
            generation = credentials.generation_for(self.generation_path, profile)
            token = credentials.derive(self._master, profile, generation)
        except credentials.CredentialError as exc:
            raise WorkerUnavailable("worker generations file is corrupt") from exc
        slot = self._slots.get(profile)
        if slot is None:
            slot = WorkerSlot(
                profile=profile,
                generation=generation,
                credential=token,
                socket_path=self._socket_file(profile),
            )
            self._slots[profile] = slot
        slot.generation = generation
        slot.credential = token
        slot.socket_path = self._socket_file(profile)
        slot.wanted = True
        slot.last_used = self.clock()
        if slot.socket_path.exists():
            slot.socket_path.unlink(missing_ok=True)
        log_path = self.state_dir / f"worker-{profile}.log"
        slot.log_path = log_path
        handle = _open_log(log_path)
        try:
            proc = subprocess.Popen(
                self._argv(profile, generation),
                stdin=subprocess.PIPE,
                stdout=handle,
                stderr=handle,
                env=self.worker_env(profile),
                start_new_session=True,
            )
        finally:
            handle.close()
        assert proc.stdin is not None
        proc.stdin.write((token + "\n").encode())
        proc.stdin.close()
        slot.process = proc
        slot.state = "starting"
        return slot

    def _wait_ready(self, slot: WorkerSlot) -> WorkerSlot:
        proc = slot.process
        profile = slot.profile
        deadline = time.monotonic() + self.start_timeout
        while time.monotonic() < deadline:
            if proc is None or proc.poll() is not None:
                self._note_failure(profile)
                raise WorkerUnavailable(f"worker {profile} exited during start")
            try:
                self._rpc(slot, "health", {}, timeout=0.5)
            except (IpcError, OSError):
                time.sleep(0.05)
                continue
            with self._lock:
                if slot.process is proc:
                    slot.state = "running"
                    slot.failures = 0
                    slot.next_start = 0
                    return slot
            if _alive(slot):
                return slot
            raise WorkerUnavailable(f"worker {profile} exited during start")
        self._note_failure(profile)
        raise WorkerUnavailable(f"worker {profile} did not become ready")

    def _wait_for_peer(self, slot: WorkerSlot) -> WorkerSlot:
        """Another caller is already starting this profile."""
        deadline = time.monotonic() + self.start_timeout
        while time.monotonic() < deadline:
            if _alive(slot):
                return slot
            if slot.state == "backoff":
                raise WorkerUnavailable("worker restart is backing off")
            time.sleep(0.05)
        raise WorkerUnavailable(f"worker {slot.profile} did not become ready")

    def _note_failure(self, profile: str) -> None:
        with self._lock:
            slot = self._slots.get(profile)
            if slot is None or slot.process is None:
                return
            proc = slot.process
            if proc.poll() is None:
                proc.kill()
            slot.process = None
            slot.failures += 1
            delay = min(self.backoff_cap, self.backoff_base * (2 ** (slot.failures - 1)))
            slot.next_start = self.clock() + delay
            slot.state = "backoff"
            if slot.socket_path.exists():
                slot.socket_path.unlink(missing_ok=True)

    def _argv(self, profile: str, generation: int) -> list[str]:
        if self.command:
            base = list(self.command)
        else:
            base = [sys.executable, "-m", "praxis_prime.worker"]
        base.extend(
            [
                "--profile",
                profile,
                "--socket",
                str(self._socket_file(profile)),
                "--supervisor-socket",
                str(self.control_path),
                "--data-dir",
                str(self.data_root),
                "--generation",
                str(generation),
            ]
        )
        if self.config_path is not None:
            base.extend(["--config", str(self.config_path)])
        if not self.use_slice:
            return base
        systemd = shutil.which("systemd-run")
        if not systemd:
            return base
        return [
            systemd,
            "--user",
            "--scope",
            "--collect",
            "--quiet",
            "--slice=praxis-prime-workers.slice",
            "--property=MemoryMax=512M",
            "--property=CPUQuota=50%",
            "--property=TasksMax=64",
            *base,
        ]

    def _rpc(
        self,
        slot: WorkerSlot,
        method: str,
        params: dict[str, object],
        *,
        timeout: float,
    ) -> dict[str, object]:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(str(slot.socket_path))
            if not same_user(sock):
                raise IpcError("peer uid rejected")
            send_message(
                sock,
                {
                    "id": "auth",
                    "method": "auth",
                    "profile": slot.profile,
                    "generation": slot.generation,
                    "token": slot.credential,
                },
            )
            auth = recv_message(sock)
            if not auth.get("ok"):
                raise IpcError("worker rejected the credential")
            send_message(
                sock,
                {"id": uuid.uuid4().hex, "method": method, "params": params},
            )
            reply = recv_message(sock)
        finally:
            sock.close()
        if not reply.get("ok"):
            raise IpcError(str(reply.get("error") or "worker call failed"))
        result = reply.get("result")
        if isinstance(result, dict):
            return result
        return {}

    def _loop(self) -> None:
        while not self._stop.wait(0.2):
            try:
                self.tick()
            except Exception:
                continue

    def _accept_control(self) -> None:
        listen = self._control
        if listen is None:
            return
        while not self._stop.is_set():
            try:
                conn, _addr = listen.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(
                target=self._serve_control,
                args=(conn,),
                name="praxis-worker-call",
                daemon=True,
            ).start()

    def _serve_control(self, conn: socket.socket) -> None:
        conn.settimeout(5)
        profile = ""
        generation = 0
        token = ""
        try:
            if not same_user(conn):
                return
            first = recv_message(conn)
            profile = self._authenticate_worker(first)
            if not profile:
                send_message(conn, {"id": first.get("id", ""), "ok": False, "error": "rejected"})
                return
            try:
                generation = int(first.get("generation", 0))
            except (TypeError, ValueError):
                generation = 0
            token = str(first.get("token", ""))
            send_message(conn, {"id": first.get("id", ""), "ok": True, "result": {}})
            while not self._stop.is_set():
                message = recv_message(conn)
                if not self._credential_current(profile, generation, token):
                    send_message(
                        conn,
                        {"id": message.get("id", ""), "ok": False, "error": "rejected"},
                    )
                    continue
                method = str(message.get("method", ""))
                if method not in WORKER_METHODS:
                    send_message(
                        conn,
                        {"id": message.get("id", ""), "ok": False, "error": "forbidden"},
                    )
                    continue
                result = self._worker_request(profile, method, message)
                send_message(
                    conn,
                    {"id": message.get("id", ""), "ok": True, "result": result},
                )
        except IpcError:
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _authenticate_worker(self, message: Mapping[str, object]) -> str:
        if message.get("method") != "auth":
            return ""
        profile = str(message.get("profile", ""))
        try:
            generation = int(message.get("generation", 0))
        except (TypeError, ValueError):
            return ""
        token = str(message.get("token", ""))
        try:
            current = credentials.generation_for(self.generation_path, profile)
        except credentials.CredentialError:
            return ""
        if generation != current or profile_id(profile) is None:
            return ""
        try:
            expected = credentials.derive(self._master, profile, current)
        except credentials.CredentialError:
            return ""
        if not credentials.credential_matches(token, expected):
            return ""
        return profile

    def _credential_current(self, profile: str, generation: int, token: str) -> bool:
        """True when this connection's credential still matches the current generation."""
        try:
            current = credentials.generation_for(self.generation_path, profile)
            expected = credentials.derive(self._master, profile, current)
        except credentials.CredentialError:
            return False
        if generation != current:
            return False
        return credentials.credential_matches(token, expected)

    def _worker_request(
        self,
        profile: str,
        method: str,
        message: Mapping[str, object],
    ) -> dict[str, object]:
        if method == "grant.check":
            account = str(message.get("account", ""))
            return {"allowed": self.account_allowed(profile, account)}
        claimed = str(message.get("profile", "") or profile)
        if claimed != profile:
            return {"accepted": False, "error": "profile mismatch"}
        kind = str(message.get("kind", ""))
        if kind not in EVENT_KINDS:
            return {"accepted": False, "error": "unknown event"}
        body = message.get("body")
        payload = dict(body) if isinstance(body, dict) else {}
        payload["profile"] = profile
        cleaned = _as_dict(redact_value(payload, self._secret_strings()))
        approval = cleaned.get("approval")
        if kind == "approval" and isinstance(approval, dict):
            self.note_approval(profile, str(approval.get("id", "")))
        if self.on_event is not None:
            try:
                self.on_event(profile, kind, cleaned)
            except Exception:
                pass
        return {"accepted": True}

    def _reserve_socket(self, name: str) -> None:
        """Create the profile socket path before a worker binds it.

        The name exists, mode 0600, inside a 0700 directory, so another uid
        cannot pre-bind it. The worker unlinks and binds when it starts.
        """
        path = self._socket_file(name)
        if path.exists():
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return
        held = _bind_unix(path)
        held.close()

    def _socket_directory(self) -> Path:
        if self._socket_dir is not None:
            return self._socket_dir
        sample = self.runtime_dir / f"{self._sock_tag}-supervisor.sock"
        if len(os.fsencode(sample)) <= 100:
            self._socket_dir = self.runtime_dir
            return self.runtime_dir
        directory = Path(tempfile.mkdtemp(prefix="praxis-prime-socks-"))
        os.chmod(directory, 0o700)
        self._socket_dir = directory
        return directory

    def _socket_file(self, name: str) -> Path:
        return self._socket_directory() / f"{self._sock_tag}-{name}.sock"


def _require_profile(profile: str) -> str:
    checked = profile_id(profile)
    if checked is None:
        raise WorkerUnavailable("invalid profile id")
    return checked


def _alive(slot: WorkerSlot | None) -> bool:
    return (
        slot is not None
        and slot.state == "running"
        and slot.process is not None
        and slot.process.poll() is None
    )


def _as_dict(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return value
    return {}


def _open_log(path: Path):
    """Append to a worker log. The file is mode 0600."""
    fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    try:
        os.chmod(path, 0o600)
        return os.fdopen(fd, "ab")
    except Exception:
        os.close(fd)
        raise


def _bind_unix(path: Path) -> socket.socket:
    if path.exists():
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(str(path))
    except OSError:
        sock.close()
        raise
    os.chmod(path, 0o600)
    sock.listen(16)
    sock.settimeout(0.5)
    return sock
