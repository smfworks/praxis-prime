"""Regressions for the security follow-ups that have to land before M1d."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pyotp
import pytest
from cryptography.exceptions import InvalidTag
from tests.test_m1c import _supervisor
from webauthn.helpers import base64url_to_bytes

from praxis_prime.accounts.db import AccountStore
from praxis_prime.accounts.factors import _SIGNIN_AAD, Factors
from praxis_prime.accounts.seal import challenge_key, unseal
from praxis_prime.approvals.gate import ApprovalDecision, ApprovalRequest
from praxis_prime.mcp.client import McpClient, _host_launch_approved
from praxis_prime.mcp.config import ServerSpec
from praxis_prime.mcp.sandbox import (
    audit_mcp_mount,
    build_mcp_bwrap_argv,
    mcp_mount_decision,
    popen_stdio,
)
from praxis_prime.policy import boundary as inode_boundary
from praxis_prime.policy.boundary import clear_data_inode_cache
from praxis_prime.policy.engine import PolicyEngine
from praxis_prime.router.settings import load_settings
from praxis_prime.sandbox.bwrap import (
    SandboxError,
    bind_profile,
    build_bwrap_argv,
    bwrap_available,
    run_bwrap,
)
from praxis_prime.state import StateDB, refuse_misplaced_database
from praxis_prime.supervisor.leases import LeaseStore
from praxis_prime.supervisor.routing import RoutingHost
from praxis_prime.supervisor.socketdir import ensure_private_dir
from praxis_prime.supervisor.supervisor import (
    _SOCKET_PATH_MAX,
    _bind_unix,
    _encoded_len,
    _lock_socket_sweep,
    _names_fit,
    _socket_basename,
    _sweep_stale_socket_dirs,
)
from praxis_prime.worker import _bind

_PASSWORD = "correct-horse"
_SECRET = "SECRET-HARDLINK-BODY\n"
_FORMS = (
    ("dd", "dd if=notes.txt bs=1 count=64", "dd"),
    ("python", 'python3 -c \'print(open("not"+"es.txt").read())\'', "python3"),
    ("sh", "sh run.sh", "sh"),
    ("bash", "bash -c 'cat notes.txt'", "bash"),
    ("subst", "cat $(ls | grep notes)", "cat"),
    ("xargs", "ls | xargs cat", "xargs"),
    ("grep", "grep -r . .", "grep"),
    ("tar", "tar cf - notes.txt | tar -xO", "tar"),
    ("cp", "cp -r . /tmp/out && cat /tmp/out/notes.txt", "cp"),
    ("git", "git grep --no-index HARDLINK-BODY", "git"),
    ("rg", "rg HARDLINK-BODY", "rg"),
)


def test_step_up_token_is_spent_on_first_use(tmp_path: Path) -> None:
    store = AccountStore(tmp_path / "accounts.db")
    try:
        account = store.create_account(
            username_text="ada", password=_PASSWORD, display_name="Ada"
        )
        factors = Factors(store)
        token = factors.prove_password(account.id, _PASSWORD, "", session_id="sess-1")
        assert factors.step_up_valid(account.id, token, "other-session") is False
        assert factors.step_up_valid(account.id, token, "sess-1") is True
        assert factors.step_up_valid(account.id, token, "sess-1") is False
    finally:
        store.close()


def test_step_up_delete_lets_only_one_caller_through(tmp_path: Path) -> None:
    store = AccountStore(tmp_path / "accounts.db")
    other = AccountStore(tmp_path / "accounts.db")
    try:
        account = store.create_account(
            username_text="ada", password=_PASSWORD, display_name="Ada"
        )
        token = Factors(store)._mint_step_up(account.id, "sess-1")
        barrier = threading.Barrier(2)
        results: list[bool] = []

        def spend(src: AccountStore) -> None:
            barrier.wait()
            results.append(Factors(src).step_up_valid(account.id, token, "sess-1"))

        threads = [threading.Thread(target=spend, args=(src,)) for src in (store, other)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert sorted(results) == [False, True]
    finally:
        other.close()
        store.close()


def test_confirming_totp_deletes_pending_step_up_rows(tmp_path: Path) -> None:
    store = AccountStore(tmp_path / "accounts.db")
    try:
        account = store.create_account(
            username_text="ada", password=_PASSWORD, display_name="Ada"
        )
        factors = Factors(store)
        enrolled = factors.begin_totp(account.id)
        token = factors._mint_step_up(account.id, "sess-1")
        factors.confirm_totp(account.id, pyotp.TOTP(enrolled.secret).now())
        left = store.conn.execute(
            "SELECT count(*) FROM step_up WHERE account_id = ?",
            (account.id,),
        ).fetchone()
        assert left is not None and int(left[0]) == 0
        assert factors.step_up_valid(account.id, token, "sess-1") is False
    finally:
        store.close()


def test_anonymous_passkey_options_skip_the_write_lock_and_use_a_subkey(tmp_path: Path) -> None:
    store = AccountStore(tmp_path / "accounts.db")
    try:
        factors = Factors(store)
        origin = "http://127.0.0.1:18790"
        factors.begin_authentication("", origin_header=origin, port=18790)
        seen: list[str] = []
        store.conn.set_trace_callback(seen.append)
        try:
            options = factors.begin_authentication("", origin_header=origin, port=18790)
        finally:
            store.conn.set_trace_callback(None)
        assert not any(item.strip().upper().startswith("BEGIN") for item in seen)
        challenge = options["challenge"]
        assert isinstance(challenge, str)
        raw = base64url_to_bytes(challenge)
        key = factors._read_key()
        assert key is not None
        opened = unseal(challenge_key(key), raw, aad=_SIGNIN_AAD)
        assert opened
        with pytest.raises(InvalidTag):
            unseal(key, raw, aad=_SIGNIN_AAD)
    finally:
        store.close()


def test_mcp_host_start_fails_closed_when_account_data_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _isolate(tmp_path, monkeypatch)
    data = home / ".local" / "share" / "praxis-prime"
    data.mkdir(parents=True)
    (data / "accounts.db").write_text("SECRET-ACC\n", encoding="utf-8")
    project = home / "proj"
    project.mkdir()
    events: list[dict[str, object]] = []

    class _Audit:
        def append(self, **kwargs: object) -> str:
            events.append(kwargs)
            return "1"

    with pytest.raises(RuntimeError, match="account data"):
        popen_stdio(
            sys.executable,
            ("-c", "pass"),
            cwd=project,
            allow=(),
            explicit={},
            parent={"PATH": "/usr/bin:/bin"},
            sandbox="off",
            network="off",
            audit=_Audit(),
            server="notes",
            host_approved=True,
        )
    payload = events[0]["payload"]
    assert isinstance(payload, dict)
    assert payload["mount"] == "host"
    assert payload["decision"] == "deny"


def test_mcp_host_start_asks_when_no_account_data_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _isolate(tmp_path, monkeypatch)
    project = home / "proj"
    project.mkdir()
    events: list[dict[str, object]] = []

    class _Audit:
        def append(self, **kwargs: object) -> str:
            events.append(kwargs)
            return "1"

    with pytest.raises(RuntimeError, match="not approved"):
        popen_stdio(
            sys.executable,
            ("-c", "pass"),
            cwd=project,
            allow=(),
            explicit={},
            parent={"PATH": "/usr/bin:/bin"},
            sandbox="off",
            network="off",
            audit=_Audit(),
            server="notes",
        )
    denied = events[0]["payload"]
    assert isinstance(denied, dict)
    assert denied["decision"] == "deny"

    class _Gate:
        def authorize(self, request: ApprovalRequest) -> ApprovalDecision:
            assert request.grant_key == "mcp-host:notes"
            assert request.mount == "host"
            assert request.sandboxed is False
            return ApprovalDecision.ALLOW_ONCE

    spec = ServerSpec(name="notes", transport="stdio", command=sys.executable, sandbox="off")
    client = McpClient(spec, cwd=project, gate=_Gate())
    assert _host_launch_approved(client) is True
    proc = popen_stdio(
        sys.executable,
        ("-c", "pass"),
        cwd=project,
        allow=(),
        explicit={},
        parent={"PATH": "/usr/bin:/bin"},
        sandbox="off",
        network="off",
        audit=_Audit(),
        server="notes",
        host_approved=True,
    )
    proc.wait(timeout=30)
    allowed = events[1]["payload"]
    assert isinstance(allowed, dict)
    assert allowed["mount"] == "host"
    assert allowed["decision"] == "allow"


def test_misplaced_database_uses_the_resolved_path_and_inode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _isolate(tmp_path, monkeypatch)
    root = home / ".local" / "share" / "praxis-prime"
    profiles = root / "profiles"
    (profiles / "ada").mkdir(parents=True)
    (root / "accounts.db").write_text("x", encoding="utf-8")
    refuse_misplaced_database(profiles / "ada" / "prime.db")
    with pytest.raises(ValueError, match="profiles directory"):
        refuse_misplaced_database(profiles / "ada" / ".." / "prime.db")
    linked = tmp_path / "linked-profiles"
    linked.symlink_to(profiles)
    with pytest.raises(ValueError, match="profiles directory"):
        refuse_misplaced_database(linked / "prime.db")
    alias = tmp_path / "elsewhere"
    alias.mkdir()
    try:
        subprocess.run(
            ["mount", "--bind", str(profiles), str(alias)],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return
    try:
        with pytest.raises(ValueError, match="profiles directory"):
            refuse_misplaced_database(alias / "prime.db")
        with pytest.raises(ValueError, match="invalid profile id"):
            refuse_misplaced_database(alias / "Bad_Name" / "prime.db")
    finally:
        subprocess.run(["umount", str(alias)], check=False)


def test_mcp_hard_link_in_the_cwd_is_covered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, secret = _private_file(tmp_path, monkeypatch)
    project = home / "proj"
    project.mkdir()
    alias = project / "alias.db"
    os.link(secret, alias)
    clear_data_inode_cache()
    argv = build_mcp_bwrap_argv(
        sys.executable,
        (str(alias),),
        cwd=project,
        env={"PATH": "/usr/bin:/bin"},
        network="off",
    )
    assert ["--ro-bind", "/dev/null", str(alias.resolve())] == _cover(argv, str(alias.resolve()))
    if not bwrap_available():
        return
    script = project / "read.py"
    script.write_text(
        "from pathlib import Path\nimport sys\n"
        "print(Path(sys.argv[1]).read_text())\n",
        encoding="utf-8",
    )
    ran = subprocess.run(
        build_mcp_bwrap_argv(
            sys.executable,
            (str(script), str(alias)),
            cwd=project,
            env={"PATH": "/usr/bin:/bin"},
            network="off",
        ),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert _SECRET not in ran.stdout
    assert secret.read_text(encoding="utf-8") == _SECRET


def test_approved_worktree_is_writable_after_the_data_mask(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, secret = _private_file(tmp_path, monkeypatch)
    data = secret.parent
    (data / "profiles").mkdir()
    worktree = data / "worktrees" / "ada" / "repo" / "task"
    worktree.mkdir(parents=True)
    (worktree / ".git").write_text("gitdir: /tmp/unused\n", encoding="utf-8")
    (worktree / "f.txt").write_text("kept\n", encoding="utf-8")
    project = home / "proj"
    project.mkdir()
    bind_profile(None)
    clear_data_inode_cache()
    decision = mcp_mount_decision(
        home, worktree, write_approved=True, main_checkout=project
    )
    assert decision.mode == "rw"
    assert decision.decision == "allow"
    events: list[dict[str, object]] = []

    class _Audit:
        def append(self, **kwargs: object) -> str:
            events.append(kwargs)
            return "1"

    audit_mcp_mount(_Audit(), server="notes", mount=decision, main_checkout=project)
    payload = events[0]["payload"]
    assert isinstance(payload, dict)
    assert payload["mount"] == "rw"
    argv = build_mcp_bwrap_argv(
        sys.executable,
        ("-c", "pass"),
        cwd=home,
        env={"PATH": "/usr/bin:/bin"},
        network="off",
        write_scope=worktree,
        write_approved=True,
        main_checkout=project,
    )
    mask_at = _flag_at(argv, "--tmpfs", str(data.resolve()))
    rebind_at = _last_bind(argv, str(worktree.resolve()))
    assert mask_at >= 0
    assert rebind_at > mask_at
    if not bwrap_available():
        return
    script = worktree / "write.py"
    script.write_text(
        "from pathlib import Path\nimport sys\n"
        "target = Path(sys.argv[1])\n"
        "(target / 'wrote.txt').write_text('yes\\n')\n"
        "try:\n"
        "    print(Path(sys.argv[2]).read_text())\n"
        "except OSError:\n"
        "    print('noread')\n",
        encoding="utf-8",
    )
    ran = subprocess.run(
        build_mcp_bwrap_argv(
            sys.executable,
            (str(script), str(worktree), str(secret)),
            cwd=home,
            env={"PATH": "/usr/bin:/bin"},
            network="off",
            write_scope=worktree,
            write_approved=True,
            main_checkout=project,
        ),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert ran.returncode == 0, ran.stderr
    assert _SECRET not in ran.stdout
    assert (worktree / "wrote.txt").read_text(encoding="utf-8") == "yes\n"
    assert secret.read_text(encoding="utf-8") == _SECRET


def test_private_hard_links_are_covered_for_shell_readers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, secret = _private_file(tmp_path, monkeypatch)
    work = home / "work"
    work.mkdir()
    os.link(secret, work / "notes.txt")
    (work / "run.sh").write_text("cat notes.txt\n", encoding="utf-8")
    clear_data_inode_cache()
    argv = build_bwrap_argv("true", work)
    covered = ["--ro-bind", "/dev/null", "/workspace/notes.txt"]
    assert _cover(argv, "/workspace/notes.txt") == covered
    real_scan = inode_boundary._cached_private_inodes
    monkeypatch.setattr(
        inode_boundary, "_cached_private_inodes", lambda root: (set(), "stopped")
    )
    with pytest.raises(SandboxError, match="did not finish"):
        build_bwrap_argv("true", work)
    monkeypatch.setattr(inode_boundary, "_cached_private_inodes", real_scan)
    if not bwrap_available():
        return
    clear_data_inode_cache()
    ran: list[str] = []
    for name, command, tool in _FORMS:
        if not _sandbox_tool(tool):
            continue
        output = run_bwrap(command, work, lambda: False)
        assert _SECRET.strip() not in output, name
        ran.append(name)
    assert {"dd", "sh", "bash", "grep", "tar", "cp"} <= set(ran)


def test_bogus_session_drop_does_not_wake_every_profile(tmp_path: Path) -> None:
    accounts = AccountStore(tmp_path / "accounts.db")
    try:
        accounts.create_account(username_text="owner", password=_PASSWORD, display_name="Owner")
        operator = accounts.create_account(
            username_text="op", password=_PASSWORD, display_name="Op", role="operator"
        )
        accounts.set_membership(operator.id, "ada", "operator")
        supervisor = _supervisor(
            tmp_path,
            names=("ada", "bea"),
            accounts=accounts,
            env_extra={
                "STUB_SESSION_ID": "sess-ada",
                "STUB_SESSION_PROFILE": "ada",
                "STUB_SESSION_ACCOUNT": "acct-ada",
            },
        )
        host = RoutingHost(supervisor, PolicyEngine({}), load_settings({}))
        try:
            supervisor.start()
            assert host.session_owner("missing", account_id="acc_nope") is None
            assert supervisor.running() == []
            assert host.session_owner("missing", account_id=operator.id) is None
            assert set(supervisor.running()) == {"ada"}
            slot = supervisor._slots["ada"]
            slot.last_used = 1.0
            assert host.session_owner("sess-ada", account_id=operator.id) == ("acct-ada", "ada")
            assert slot.last_used == 1.0
            assert "bea" not in supervisor.running()
        finally:
            supervisor.close()
    finally:
        accounts.close()


def test_session_owner_lookup_does_not_keep_a_woken_worker(tmp_path: Path) -> None:
    accounts = AccountStore(tmp_path / "accounts.db")
    try:
        accounts.create_account(username_text="owner", password=_PASSWORD, display_name="Owner")
        operator = accounts.create_account(
            username_text="op", password=_PASSWORD, display_name="Op", role="operator"
        )
        accounts.set_membership(operator.id, "bea", "operator")
        supervisor = _supervisor(
            tmp_path,
            names=("ada", "bea"),
            accounts=accounts,
            env_extra={
                "STUB_SESSION_ID": "sess-bea",
                "STUB_SESSION_PROFILE": "bea",
                "STUB_SESSION_ACCOUNT": "acct-bea",
            },
        )
        host = RoutingHost(supervisor, PolicyEngine({}), load_settings({}))
        try:
            supervisor.start()
            assert host.session_owner("sess-bea", account_id=operator.id) == ("acct-bea", "bea")
            assert set(supervisor.running()) == {"bea"}
            slot = supervisor._slots["bea"]
            assert slot.last_used <= supervisor.clock() - supervisor.idle_after + 1
        finally:
            supervisor.close()
    finally:
        accounts.close()


def test_socket_sweep_skips_young_dirs_and_waits_for_the_lock(tmp_path: Path) -> None:
    current = tmp_path / "current"
    current.mkdir()
    young = Path(tempfile.mkdtemp(prefix="praxis-prime-socks-"))
    os.chmod(young, 0o700)
    (young / "aaaaaaaa-supervisor.sock").write_bytes(b"")
    try:
        _sweep_stale_socket_dirs(current, None)
        assert young.exists()
    finally:
        if young.exists():
            for child in young.iterdir():
                child.unlink()
            young.rmdir()
    stale = Path(tempfile.mkdtemp(prefix="praxis-prime-socks-"))
    os.chmod(stale, 0o700)
    (stale / "bbbbbbbb-supervisor.sock").write_bytes(b"")
    aged = time.time() - 60
    os.utime(stale, (aged, aged))
    held = _lock_socket_sweep()
    try:
        started = threading.Event()

        def sweep() -> None:
            started.set()
            _sweep_stale_socket_dirs(current, None)

        thread = threading.Thread(target=sweep)
        thread.start()
        assert started.wait(2)
        time.sleep(0.3)
        assert stale.exists()
        assert thread.is_alive()
    finally:
        os.close(held)
    thread.join(5)
    assert not thread.is_alive()
    assert not stale.exists()


def test_socket_directories_are_created_private(tmp_path: Path) -> None:
    linked = tmp_path / "linked"
    linked.symlink_to(tmp_path)
    with pytest.raises(OSError):
        ensure_private_dir(linked)
    wide = tmp_path / "wide"
    wide.mkdir()
    os.chmod(wide, 0o755)
    ensure_private_dir(wide)
    assert stat.S_IMODE(wide.stat().st_mode) == 0o700
    worker_dir = tmp_path / "worker-socks"
    sock = _bind(worker_dir / "worker.sock")
    try:
        assert stat.S_IMODE(worker_dir.stat().st_mode) == 0o700
    finally:
        sock.close()
    control_dir = tmp_path / "supervisor-socks"
    control = _bind_unix(control_dir / "supervisor.sock")
    try:
        assert stat.S_IMODE(control_dir.stat().st_mode) == 0o700
    finally:
        control.close()


def test_long_profile_id_fits_under_the_tmp_socket_fallback(tmp_path: Path) -> None:
    del tmp_path
    long_id = "p" + ("x" * 63)
    directory = Path(tempfile.mkdtemp(prefix="praxis-prime-socks-"))
    try:
        tag = "abcd1234"
        assert _names_fit(directory, tag, ["supervisor", long_id])
        hashed = _socket_basename(directory, tag, long_id)
        assert hashed != f"{tag}-{long_id}.sock"
        assert _encoded_len(directory / hashed) <= _SOCKET_PATH_MAX
        supervisor = _socket_basename(directory, tag, "supervisor")
        assert supervisor == f"{tag}-supervisor.sock"
    finally:
        directory.rmdir()


def test_lease_token_is_required_and_acquire_is_serialized(tmp_path: Path) -> None:
    path = tmp_path / "prime.db"
    db = StateDB(path)
    try:
        store = LeaseStore(db, clock=lambda: 0.0, ttl=30)
        decision, token = store.acquire("routine", "owner-a")
        assert decision == "run"
        assert token
        assert store.renew("routine", "owner-a", "0" * 32) is False
        assert store.release("routine", "owner-a", "0" * 32) is False
        assert store.release("routine", "owner-a", "") is False
        skipped, empty = store.acquire("routine", "owner-b")
        assert skipped == "skip"
        assert empty == ""
        assert store.release("routine", "owner-a", token) is True
    finally:
        db.close()

    left = StateDB(path)
    right = StateDB(path)
    try:
        first = LeaseStore(left, clock=lambda: 0.0, ttl=30)
        second = LeaseStore(right, clock=lambda: 0.0, ttl=30)
        barrier = threading.Barrier(2)
        results: list[str] = []

        def race(store: LeaseStore) -> None:
            barrier.wait()
            results.append(store.acquire("other", "owner")[0])

        threads = [
            threading.Thread(target=race, args=(store,)) for store in (first, second)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert sorted(results) == ["run", "skip"]
    finally:
        right.close()
        left.close()


def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    share = home / ".local" / "share"
    share.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(share))
    bind_profile(None)
    clear_data_inode_cache()
    return home


def _private_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    home = _isolate(tmp_path, monkeypatch)
    secret = home / ".local" / "share" / "praxis-prime" / "accounts.db"
    secret.parent.mkdir(parents=True)
    secret.write_text(_SECRET, encoding="utf-8")
    return home, secret


def _cover(argv: list[str], sandbox: str) -> list[str]:
    for index, item in enumerate(argv[:-2]):
        if item == "--ro-bind" and argv[index + 1] == "/dev/null" and argv[index + 2] == sandbox:
            return argv[index : index + 3]
    raise AssertionError(f"no /dev/null cover for {sandbox}")


def _flag_at(argv: list[str], flag: str, target: str) -> int:
    for index, item in enumerate(argv[:-1]):
        if item == flag and argv[index + 1] == target:
            return index
    return -1


def _last_bind(argv: list[str], path: str) -> int:
    found = -1
    for index, item in enumerate(argv[:-2]):
        if item == "--bind" and argv[index + 1] == path and argv[index + 2] == path:
            found = index
    return found


def _sandbox_tool(name: str) -> bool:
    return any((Path(root) / name).exists() for root in ("/bin", "/usr/bin"))
