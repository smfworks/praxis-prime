"""``praxis-primed`` — kernel, loopback gateway, and optional Telegram adapter.

The process binds 127.0.0.1 only, writes a bearer token under the XDG
runtime directory, and appends JSON logs under the XDG state directory.
SIGTERM and SIGINT deny pending approvals and close the sockets.

ARCHITECTURE §3.1, §4, §12, and §26.
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import threading
import time
import tomllib
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from praxis_prime import __version__
from praxis_prime.accounts.db import AccountStore
from praxis_prime.approvals.queue import ApprovalQueue
from praxis_prime.channels.secrets import load_telegram_token
from praxis_prime.channels.telegram import (
    HttpTelegramTransport,
    PairingStore,
    TelegramAdapter,
)
from praxis_prime.gateway.auth import load_or_create_token
from praxis_prime.gateway.client import GatewayClient, GatewayError
from praxis_prime.gateway.discover import (
    clear_discovery,
    discover,
    gateway_paths,
    log_path,
    pid_is_daemon,
    read_info,
    write_discovery,
)
from praxis_prime.gateway.protocol import DEFAULT_LISTEN, ListenError, parse_listen, request_id_var
from praxis_prime.gateway.server import GatewayServer
from praxis_prime.host import Host
from praxis_prime.observe import JsonLogger
from praxis_prime.paths import config_dir, data_dir, runtime_dir, state_dir
from praxis_prime.runtime import build_runtime
from praxis_prime.scheduler.service import scheduler_for
from praxis_prime.service import daemon_exec


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="praxis-primed",
        description="Praxis Prime daemon. Listens on loopback only.",
    )
    parser.add_argument("--version", action="store_true", help="Print the version and exit.")
    parser.add_argument("--config", default=None, help="Path to config.toml.")
    parser.add_argument(
        "--listen",
        default=None,
        help="Loopback bind address. Default 127.0.0.1:18790. Refuses any other host.",
    )
    args = parser.parse_args(argv)
    if args.version:
        print(f"praxis-primed {__version__}")
        return 0
    stop = threading.Event()

    def _handle(signum: int, _frame: object) -> None:
        del signum
        stop.set()

    try:
        signal.signal(signal.SIGTERM, _handle)
        signal.signal(signal.SIGINT, _handle)
    except ValueError:
        pass
    return serve(stop=stop, listen=args.listen, config=args.config)


def serve(
    *,
    stop: threading.Event | None = None,
    listen: str | None = None,
    config: str | None = None,
) -> int:
    """Run until ``stop`` is set. Returns a process exit code."""
    environ = os.environ
    stop = stop or threading.Event()
    try:
        host, port = resolve_listen(listen, environ)
    except ListenError as exc:
        print(f"praxis-primed: {exc}", file=sys.stderr)
        return 2
    try:
        ttl = resolve_ttl(environ)
    except ListenError:
        ttl = 900.0

    logger = JsonLogger(log_path(environ))
    runtime_root = runtime_dir(environ)
    runtime_root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(runtime_root, 0o700)
    except OSError:
        pass
    token = load_or_create_token(gateway_paths(environ)[1])
    logger.add_secret(token)
    telegram_token = load_telegram_token(environ)
    if telegram_token:
        logger.add_secret(telegram_token)

    queue = ApprovalQueue(ttl=ttl)
    config_path = Path(config) if config else None
    root = data_dir(environ)
    try:
        runtime = build_runtime(env=environ, config_path=config_path, approver=queue.authorize)
    except (OSError, ValueError) as exc:
        logger.error("runtime_failed", error=type(exc).__name__)
        print(f"praxis-primed: {exc}", file=sys.stderr)
        return 1
    queue.profile_id = runtime.profile_id
    accounts: AccountStore | None = AccountStore(root / "accounts.db")
    agent = Host(runtime, queue)
    adapter = _telegram(environ, agent, queue, logger, telegram_token)
    socket_path = str(runtime_root / "prime.sock")
    server = GatewayServer(
        host=host,
        port=port,
        token=token,
        agent=agent,
        approvals=queue,
        logger=logger,
        socket_path=socket_path,
        decider=runtime.engine,
        accounts=accounts,
        audit=runtime.audit,
        data_root=root,
        bearer_enabled=bearer_auth_enabled(environ),
    )

    def on_pending(item: dict[str, object]) -> None:
        server.publish(
            {
                "type": "event",
                "id": request_id_var.get(),
                "payload": {"kind": "approval", "approval": item},
            }
        )
        if adapter is not None:
            adapter.notify_pending(item)

    def on_resolved(item: dict[str, object]) -> None:
        if adapter is not None:
            adapter.notify_resolved(item)
        logger.info(
            "approval_resolved",
            approval=str(item.get("id", "")),
            state=str(item.get("state", "")),
            actor=str(item.get("actor", "")),
        )

    queue.on_pending = on_pending
    queue.on_resolved = on_resolved
    scheduler = None

    def deliver_result(text: str) -> None:
        if adapter is not None:
            adapter.send_owner(text)

    try:
        server.start()
    except OSError as exc:
        logger.error("bind_failed", error=type(exc).__name__)
        print(f"praxis-primed: {exc}", file=sys.stderr)
        agent.close()
        if accounts is not None:
            accounts.close()
            accounts = None
        return 1
    started = datetime.now(UTC).isoformat(timespec="seconds")
    write_discovery(
        env=environ,
        pid=os.getpid(),
        port=server.bound_port,
        socket_path=server.socket_path,
        version=__version__,
        started_at=started,
    )
    logger.info("listen", host="127.0.0.1", port=server.bound_port)
    scheduler = scheduler_for(
        runtime,
        deliver=deliver_result,
        logger=logger,
        lane=agent._lock,
    )
    server.routine_fire = scheduler.fire_http
    scheduler.start()
    logger.info("routines_started")
    if adapter is not None:
        adapter.start()
    else:
        logger.info("telegram_disabled")
    try:
        while not stop.wait(0.5):
            pass
    finally:
        logger.info("shutdown")
        if scheduler is not None:
            scheduler.request_stop()
        queue.deny_all(actor="shutdown")
        if scheduler is not None:
            scheduler.join()
        if adapter is not None:
            adapter.stop()
        agent.close()
        server.shutdown()
        if accounts is not None:
            accounts.close()
        clear_discovery(environ)
    return 0


def start_detached() -> int:
    """Spawn ``praxis-primed`` in its own session and wait until it is healthy."""
    if discover() is not None:
        print("praxis-primed is already running")
        return status()
    data_dir().mkdir(parents=True, exist_ok=True)
    state_dir().mkdir(parents=True, exist_ok=True)
    stderr_path = state_dir() / "daemon.stderr.log"
    handle = stderr_path.open("ab")
    try:
        subprocess.Popen(
            daemon_exec(),
            start_new_session=True,
            stdout=handle,
            stderr=handle,
            stdin=subprocess.DEVNULL,
            env=os.environ.copy(),
        )
    finally:
        handle.close()
    for _ in range(50):
        time.sleep(0.1)
        if discover() is not None:
            return status()
    print(f"praxis-primed failed to start. See {stderr_path}", file=sys.stderr)
    return 1


def stop_running() -> int:
    info = read_info()
    pid = info.get("pid") if info else None
    if not isinstance(pid, int) or not pid_is_daemon(pid):
        clear_discovery()
        print("praxis-primed is not running")
        return 0
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        print(f"praxis-primed: {exc}", file=sys.stderr)
        return 1
    for _ in range(50):
        if not pid_is_daemon(pid):
            clear_discovery()
            print("praxis-primed stopped")
            return 0
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    clear_discovery()
    print("praxis-primed stopped")
    return 0


def status() -> int:
    endpoint = discover()
    if endpoint is None:
        print("praxis-primed is not running")
        return 1
    try:
        client = GatewayClient.connect(endpoint)
    except (OSError, GatewayError, TimeoutError) as exc:
        print(f"praxis-primed is not running ({exc})")
        return 1
    try:
        body = client.status()
    finally:
        client.close()
    print("praxis-primed running")
    print(f"pid {body.get('pid', '')}")
    print(f"listen {body.get('listen', '')}")
    if body.get("socket"):
        print(f"socket {body.get('socket')}")
    print(f"version {body.get('version', '')}")
    print(f"model {body.get('model', '')}")
    print(f"pending approvals {body.get('pendingApprovals', 0)}")
    return 0


def show_logs(lines: int = 80) -> int:
    path = log_path()
    if not path.is_file():
        print(f"no daemon log at {path}")
        return 1
    content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    sys.stdout.write("\n".join(content[-lines:]) + ("\n" if content else ""))
    return 0


def resolve_listen(explicit: str | None, env: Mapping[str, str]) -> tuple[str, int]:
    raw = explicit or env.get("PRAXIS_PRIME_GATEWAY_LISTEN") or _config_value(env, "listen")
    return parse_listen(raw or DEFAULT_LISTEN)


def resolve_ttl(env: Mapping[str, str]) -> float:
    raw = (
        env.get("PRAXIS_PRIME_APPROVAL_TTL")
        or _config_value(env, "approval_ttl_seconds")
        or "900"
    )
    try:
        number = float(raw)
    except (TypeError, ValueError):
        return 900.0
    if number <= 0 or number > 86400:
        return 900.0
    return number


def bearer_auth_enabled(env: Mapping[str, str]) -> bool:
    """True unless ``gateway.bearer`` is explicitly off.

    The flag is consulted only after an account exists. The default config
    leaves it on, so the loopback token stays an owner credential.
    """
    raw = _config_value(env, "bearer").strip().lower()
    if raw in {"false", "0", "no", "off"}:
        return False
    return True


def _config_value(env: Mapping[str, str], key: str) -> str:
    path = config_dir(env) / "config.toml"
    if not path.is_file():
        return ""
    try:
        loaded = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return ""
    gateway = loaded.get("gateway") if isinstance(loaded, dict) else None
    if not isinstance(gateway, dict):
        return ""
    value = gateway.get(key)
    if value is None:
        return ""
    return str(value)


def _telegram(
    env: Mapping[str, str],
    agent: Host,
    queue: ApprovalQueue,
    logger: JsonLogger,
    token: str,
) -> TelegramAdapter | None:
    if not token:
        return None
    pairing = PairingStore(
        state_dir(env) / "telegram-pairing.json",
        data_dir(env) / "telegram-owner.json",
    )
    return TelegramAdapter(
        HttpTelegramTransport(token),
        pairing,
        agent,
        queue,
        logger,
        offset_path=state_dir(env) / "telegram-offset.txt",
        policy=agent.runtime.policy,
    )
