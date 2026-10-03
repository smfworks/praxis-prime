"""Regressions for the security follow-ups that have to land before M1d."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
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
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from praxis_prime.accounts.db import AccountStore
from praxis_prime.accounts.factors import _SIGNIN_AAD, FactorError, Factors
from praxis_prime.accounts.seal import challenge_key, unseal
from praxis_prime.approvals.gate import ApprovalDecision, ApprovalRequest
from praxis_prime.gateway.authz import Principal
from praxis_prime.gateway.factors import authed_factor
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
from praxis_prime.profiles.home import create_profile
from praxis_prime.router.settings import load_settings
from praxis_prime.sandbox.bwrap import (
    SandboxError,
    _skip_hardlink_scan,
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


def test_anonymous_passkey_options_skip_the_write_lock_and_use_a_subkey(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = AccountStore(tmp_path / "accounts.db")
    try:
        factors = Factors(store)
        origin = "http://127.0.0.1:18790"
        factors.begin_authentication("", origin_header=origin, port=18790)

        def refuse_key_insert() -> bytes:
            raise AssertionError("anonymous options took the key insert path")

        reads = {"n": 0}
        real_read = factors._read_key

        def counting_read() -> bytes | None:
            reads["n"] += 1
            return real_read()

        class _LockSpy:
            def __init__(self, inner: threading.Lock) -> None:
                self.inner = inner
                self.entered = 0

            def __enter__(self) -> None:
                self.entered += 1
                self.inner.acquire()

            def __exit__(self, *exc: object) -> None:
                self.inner.release()

        spy = _LockSpy(store._lock)
        monkeypatch.setattr(factors, "_key", refuse_key_insert)
        monkeypatch.setattr(factors, "_read_key", counting_read)
        monkeypatch.setattr(store, "_lock", spy)
        options = factors.begin_authentication("", origin_header=origin, port=18790)
        assert reads["n"] >= 1
        assert spy.entered >= 1
        challenge = options["challenge"]
        assert isinstance(challenge, str)
        raw = base64url_to_bytes(challenge)
        key = real_read()
        assert key is not None
        opened = unseal(challenge_key(key), raw, aad=_SIGNIN_AAD)
        assert opened
        with pytest.raises(InvalidTag):
            unseal(key, raw, aad=_SIGNIN_AAD)
    finally:
        store.close()


def test_passkey_enrollment_spends_one_step_up_on_its_ceremony(tmp_path: Path) -> None:
    store = AccountStore(tmp_path / "accounts.db")
    try:
        account = store.create_account(
            username_text="ada", password=_PASSWORD, display_name="Ada"
        )
        factors = Factors(store)
        origin = "http://127.0.0.1:18790"
        token = factors.prove_password(account.id, _PASSWORD, "", session_id="sess-1")
        assert factors.step_up_valid(account.id, token, "sess-1") is True
        options = factors.begin_registration(
            account, origin_header=origin, port=18790, session_id="sess-1"
        )
        assert factors.step_up_valid(account.id, token, "sess-1") is False
        challenge = options["challenge"]
        assert isinstance(challenge, str)
        raw = base64url_to_bytes(challenge)
        credential = {
            "response": {
                "clientDataJSON": bytes_to_base64url(
                    json.dumps(
                        {
                            "type": "webauthn.create",
                            "challenge": challenge,
                            "origin": origin,
                        }
                    ).encode()
                )
            },
            "rawId": "AAAA",
        }
        with pytest.raises(FactorError):
            factors.finish_registration(account, credential, session_id="sess-2")
        kept = store.conn.execute(
            "SELECT used, session_id FROM webauthn_challenges WHERE challenge = ?",
            (raw,),
        ).fetchone()
        assert kept is not None
        assert int(kept["used"]) == 0
        assert str(kept["session_id"]) == "sess-1"
        with pytest.raises(FactorError):
            factors.finish_registration(account, credential, session_id="sess-1")
        spent = store.conn.execute(
            "SELECT used FROM webauthn_challenges WHERE challenge = ?",
            (raw,),
        ).fetchone()
        assert spent is not None and int(spent["used"]) == 1
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

    spec = ServerSpec(
        name="notes",
        transport="stdio",
        command=sys.executable,
        sandbox="off",
        trust="untrusted",
    )
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


def test_trusted_sandbox_off_starts_without_a_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _isolate(tmp_path, monkeypatch)
    project = home / "proj"
    project.mkdir()
    spec = ServerSpec(
        name="prime",
        transport="stdio",
        command=sys.executable,
        sandbox="off",
        trust="trusted",
    )
    client = McpClient(spec, cwd=project)
    assert client.gate is None
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
        server="prime",
        host_approved=True,
    )
    proc.wait(timeout=30)
    monkeypatch.setattr("praxis_prime.mcp.client.bwrap_available", lambda: False)
    asked = ServerSpec(
        name="prime",
        transport="stdio",
        command=sys.executable,
        sandbox="bwrap",
        trust="trusted",
    )
    assert _host_launch_approved(McpClient(asked, cwd=project)) is False


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


def test_opt_workspace_hard_link_is_covered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del tmp_path
    assert _skip_hardlink_scan("/usr") is True
    assert _skip_hardlink_scan("/bin") is True
    assert _skip_hardlink_scan("/opt/project") is False
    assert _skip_hardlink_scan("/usr/local/src") is False
    opt = _opt_workspace()
    try:
        home = opt / "home"
        share = home / ".local" / "share"
        share.mkdir(parents=True)
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("XDG_DATA_HOME", str(share))
        bind_profile(None)
        clear_data_inode_cache()
        secret = share / "praxis-prime" / "accounts.db"
        secret.parent.mkdir(parents=True)
        secret.write_text(_SECRET, encoding="utf-8")
        work = opt / "work"
        work.mkdir()
        alias = work / "notes.txt"
        os.link(secret, alias)
        clear_data_inode_cache()
        argv = build_bwrap_argv("true", work)
        covered = ["--ro-bind", "/dev/null", "/workspace/notes.txt"]
        assert _cover(argv, "/workspace/notes.txt") == covered
        mcp = build_mcp_bwrap_argv(
            sys.executable,
            (str(alias),),
            cwd=work,
            env={"PATH": "/usr/bin:/bin"},
            network="off",
        )
        assert _cover(mcp, str(alias.resolve())) == [
            "--ro-bind",
            "/dev/null",
            str(alias.resolve()),
        ]
    finally:
        shutil.rmtree(opt, ignore_errors=True)


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


def test_socket_sweep_skips_young_dirs_and_a_held_lock(tmp_path: Path) -> None:
    runtime = tmp_path / "run"
    runtime.mkdir()
    current = tmp_path / "current"
    current.mkdir()
    young = Path(tempfile.mkdtemp(prefix="praxis-prime-socks-"))
    os.chmod(young, 0o700)
    (young / "aaaaaaaa-supervisor.sock").write_bytes(b"")
    try:
        _sweep_stale_socket_dirs(current, None, runtime=runtime)
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
    held = _lock_socket_sweep(runtime)
    assert held >= 0
    try:
        _sweep_stale_socket_dirs(current, None, runtime=runtime)
        assert stale.exists()
    finally:
        os.close(held)
    _sweep_stale_socket_dirs(current, None, runtime=runtime)
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
        digest = hashlib.sha256(long_id.encode()).hexdigest()[:16]
        assert hashed == f"{tag}-_{digest}.sock"
        assert hashed != f"{tag}-{digest}.sock"
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


def test_bad_origin_does_not_spend_the_registration_step_up(tmp_path: Path) -> None:
    store = AccountStore(tmp_path / "accounts.db")
    try:
        account = store.create_account(
            username_text="ada", password=_PASSWORD, display_name="Ada"
        )
        factors = Factors(store)
        token = factors.prove_password(account.id, _PASSWORD, "", session_id="sess-1")
        principal = Principal(
            kind="session",
            account_id=account.id,
            username="ada",
            role="owner",
            session_id="sess-1",
        )
        status, body, _headers = authed_factor(
            store,
            principal,
            "POST",
            "/v1/auth/passkey/register/options",
            json.dumps({"stepUpToken": token}).encode(),
            None,
            origin="http://evil.example",
            port=18790,
        )
        assert status == 400
        assert body["error"]["message"] == "origin is not allowed"
        assert factors.step_up_valid(account.id, token, "sess-1") is True
        bearer = Principal(
            kind="bootstrap",
            account_id=account.id,
            username="ada",
            role="owner",
        )
        bearer_token = factors._mint_step_up(account.id, "")
        status, body, _headers = authed_factor(
            store,
            bearer,
            "POST",
            "/v1/auth/passkey/register/options",
            json.dumps({"stepUpToken": bearer_token}).encode(),
            None,
            origin="http://localhost:18790",
            port=18790,
        )
        assert status == 401
        assert factors.step_up_valid(account.id, bearer_token, "") is True
    finally:
        store.close()


def test_lease_clock_skew_does_not_start_a_second_run(tmp_path: Path) -> None:
    path = tmp_path / "prime.db"
    winner_db = StateDB(path)
    waiter_db = StateDB(path)
    try:
        winner = LeaseStore(winner_db, clock=lambda: 1000.001)
        waiter = LeaseStore(waiter_db, clock=lambda: 1000.000)
        assert winner.acquire("r", "B")[0] == "run"
        assert waiter.acquire("r", "A")[0] == "skip"
    finally:
        waiter_db.close()
        winner_db.close()


def test_hashed_socket_name_cannot_match_a_profile_id(tmp_path: Path) -> None:
    index = 0
    long_id = ""
    digest = ""
    while index < 64:
        long_id = ("p" + str(index)).ljust(64, "x")
        digest = hashlib.sha256(long_id.encode()).hexdigest()[:16]
        if digest[0].isalpha():
            break
        index += 1
    assert digest[0].isalpha()
    directory = Path("/tmp") / ("d" * 40)
    tag = "abcd1234"
    assert _socket_basename(directory, tag, long_id) == f"{tag}-_{digest}.sock"
    assert _socket_basename(directory, tag, digest) == f"{tag}-{digest}.sock"
    root = tmp_path / "data"
    create_profile(root, long_id)
    create_profile(root, digest)
    runtime = Path("/tmp") / f"r53-{os.getpid()}-{'y' * 24}"
    supervisor = _supervisor(tmp_path, names=(), data_root=root)
    supervisor.runtime_dir = runtime
    runtime.mkdir(parents=True)
    os.chmod(runtime, 0o700)
    try:
        supervisor.start()
        long_name = _socket_basename(supervisor._socket_directory(), supervisor._sock_tag, long_id)
        short_name = _socket_basename(supervisor._socket_directory(), supervisor._sock_tag, digest)
        assert long_name != short_name
        supervisor.call(long_id, "memory.remember", {"content": "LONG-SECRET"})
        assert supervisor.call(digest, "memory.list")["entries"] == []
        remembered = supervisor.call(long_id, "memory.list")["entries"]
        assert remembered and "LONG-SECRET" in str(remembered)
    finally:
        supervisor.close()
        shutil.rmtree(runtime, ignore_errors=True)


def test_sweep_lock_stays_out_of_the_shared_tmp_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tempfile, "tempdir", None)
    sticky = tmp_path / "sticky"
    sticky.mkdir()
    os.chmod(sticky, 0o1777)
    monkeypatch.setenv("TMPDIR", str(sticky))
    hostile = sticky / "praxis-prime-socks.lock"
    hostile.write_text("owned\n", encoding="utf-8")
    os.chmod(hostile, 0o000)
    supervisor = _supervisor(tmp_path, names=("ada",))
    held = _lock_socket_sweep(supervisor.runtime_dir)
    assert held >= 0
    try:
        outcome: dict[str, object] = {}

        def go() -> None:
            try:
                supervisor.start()
                outcome["ok"] = supervisor.call("ada", "memory.list")["entries"] == []
            except Exception as exc:
                outcome["ok"] = exc

        thread = threading.Thread(target=go)
        thread.start()
        thread.join(8)
        assert not thread.is_alive()
        assert outcome.get("ok") is True
    finally:
        os.close(held)
        supervisor.close()
    assert stat.S_IMODE(hostile.stat().st_mode) == 0
    os.chmod(hostile, 0o600)
    assert hostile.read_text(encoding="utf-8") == "owned\n"
    lock = supervisor.runtime_dir / "socks.lock"
    assert lock.is_file()
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600


def test_sweep_lock_symlink_does_not_stop_start(tmp_path: Path) -> None:
    supervisor = _supervisor(tmp_path, names=("ada",))
    target = tmp_path / "elsewhere"
    target.write_text("x", encoding="utf-8")
    (supervisor.runtime_dir / "socks.lock").symlink_to(target)
    try:
        supervisor.start()
        assert supervisor.call("ada", "memory.list")["entries"] == []
    finally:
        supervisor.close()
    assert target.read_text(encoding="utf-8") == "x"


def test_database_sidecars_and_root_files_are_hardlink_covered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _isolate(tmp_path, monkeypatch)
    root = home / ".local" / "share" / "praxis-prime"
    (root / "profiles" / "bob").mkdir(parents=True)
    (root / "profiles" / "bob" / "SOUL.md").write_text("SECRET-PSOUL\n", encoding="utf-8")
    bodies = {
        "accounts.db": "SECRET-DB\n",
        "accounts.db-wal": "SECRET-WAL-ROW\n",
        "audit.db": "SECRET-AUDIT\n",
        "prime.db": "SECRET-PRIMEDB\n",
        "SOUL.md": "SECRET-RSOUL\n",
        "worker-master.key": "SECRET-KEY\n",
    }
    for name, text in bodies.items():
        (root / name).write_text(text, encoding="utf-8")
    work = home / "proj"
    work.mkdir()
    for name in bodies:
        os.link(root / name, work / name)
    os.link(root / "profiles" / "bob" / "SOUL.md", work / "notes.txt")
    (work / "node_modules").mkdir()
    os.link(root / "audit.db", work / "node_modules" / "hidden")
    objects = work / ".git" / "objects"
    objects.mkdir(parents=True)
    os.link(root / "prime.db", objects / "aa")
    (work / "padding").write_text("ordinary\n", encoding="utf-8")
    clear_data_inode_cache()
    argv = build_bwrap_argv("true", work)
    for name in (*bodies, "notes.txt"):
        assert _cover(argv, f"/workspace/{name}")[:2] == ["--ro-bind", "/dev/null"]
    assert _cover(argv, "/workspace/node_modules/hidden")[:2] == ["--ro-bind", "/dev/null"]
    assert _cover(argv, "/workspace/.git/objects/aa")[:2] == ["--ro-bind", "/dev/null"]
    monkeypatch.setattr("praxis_prime.sandbox.bwrap._HARDLINK_SCAN_CAP", 0)
    clear_data_inode_cache()
    with pytest.raises(SandboxError, match="accounts.db-wal"):
        build_bwrap_argv("true", work)


def test_project_mcp_json_cannot_grant_a_host_start(tmp_path: Path) -> None:
    from praxis_prime.mcp.config import load_servers, spec_from_mapping

    project = tmp_path / "proj"
    (project / ".prime").mkdir(parents=True)
    (project / ".prime" / "mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "notes": {
                        "command": "python3",
                        "trust": "trusted",
                        "sandbox": "off",
                        "network": "on",
                        "envAllow": ["HOME", "SSH_AUTH_SOCK"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    loaded = load_servers(None, project)
    assert loaded[0].source == "project"
    assert loaded[0].trust == "untrusted"
    assert loaded[0].sandbox == "bwrap"
    assert loaded[0].network == "off"
    assert loaded[0].env_allow is None
    user = spec_from_mapping(
        "notes",
        {
            "command": "python3",
            "trust": "trusted",
            "sandbox": "off",
            "network": "on",
            "env_allow": ["HOME"],
        },
        source="config",
    )
    assert user.trust == "trusted"
    assert user.sandbox == "off"
    assert user.network == "on"
    assert user.env_allow == ("HOME",)


def test_unreadable_directory_refuses_shell_and_mcp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _isolate(tmp_path, monkeypatch)
    root = home / ".local" / "share" / "praxis-prime"
    root.mkdir(parents=True)
    wal = root / "accounts.db-wal"
    wal.write_text("SECRET-WAL\n", encoding="utf-8")
    work = home / "proj"
    hidden = work / "d"
    hidden.mkdir(parents=True)
    os.link(wal, hidden / "known")
    os.chmod(hidden, 0o300)
    clear_data_inode_cache()
    try:
        with pytest.raises(SandboxError, match="could not be scanned"):
            build_bwrap_argv("true", work)
        with pytest.raises(SandboxError, match="could not be scanned"):
            build_mcp_bwrap_argv(
                "/bin/sh",
                ("-c", "strings d/known"),
                cwd=work,
                env={"PATH": "/usr/bin:/bin"},
                network="off",
            )
        if bwrap_available():
            from praxis_prime.tools.registry import ToolContext
            from praxis_prime.tools.shell import execute_shell

            ctx = ToolContext(cwd=str(work), cancelled=lambda: False, shell_approved=True)
            with pytest.raises(RuntimeError, match="could not be scanned"):
                execute_shell(
                    {"command": "python3 -c \"open('d/'+'kno'+'wn').read()\""},
                    ctx,
                )
    finally:
        os.chmod(hidden, 0o700)


def test_unreadable_directory_inside_node_modules_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _isolate(tmp_path, monkeypatch)
    root = home / ".local" / "share" / "praxis-prime"
    root.mkdir(parents=True)
    wal = root / "accounts.db-wal"
    wal.write_text("SECRET-WAL\n", encoding="utf-8")
    work = home / "proj"
    hidden = work / "node_modules" / "pkg"
    hidden.mkdir(parents=True)
    os.link(wal, hidden / "known")
    os.chmod(hidden, 0o300)
    clear_data_inode_cache()
    try:
        with pytest.raises(SandboxError, match="could not be scanned"):
            build_bwrap_argv("true", work)
        with pytest.raises(SandboxError, match="could not be scanned"):
            build_mcp_bwrap_argv(
                "/bin/sh",
                ("-c", "echo ok"),
                cwd=work,
                env={"PATH": "/usr/bin:/bin"},
                network="off",
            )
    finally:
        os.chmod(hidden, 0o700)


def test_vanished_directory_refuses_the_hardlink_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _isolate(tmp_path, monkeypatch)
    root = home / ".local" / "share" / "praxis-prime"
    root.mkdir(parents=True)
    wal = root / "accounts.db-wal"
    wal.write_text("SECRET-WAL\n", encoding="utf-8")
    work = home / "proj"
    gone = work / "gone"
    gone.mkdir(parents=True)
    os.link(wal, gone / "known")
    real_scandir = os.scandir

    def scanning(path: object) -> object:
        if Path(path).name == "gone":
            raise FileNotFoundError(2, "No such file or directory", str(path))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", scanning)
    clear_data_inode_cache()
    with pytest.raises(SandboxError, match="could not be scanned"):
        build_bwrap_argv("true", work)


def test_deep_workspace_refuses_the_hardlink_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from praxis_prime.policy.boundary import _SCAN_DEPTH_LIMIT

    home = _isolate(tmp_path, monkeypatch)
    root = home / ".local" / "share" / "praxis-prime"
    root.mkdir(parents=True)
    wal = root / "accounts.db-wal"
    wal.write_text("SECRET-WAL\n", encoding="utf-8")
    work = home / "proj"
    work.mkdir()
    current = work
    for _ in range(_SCAN_DEPTH_LIMIT + 1):
        current = current / "n"
        current.mkdir()
    os.link(wal, current / "known")
    clear_data_inode_cache()
    with pytest.raises(SandboxError, match="too deep"):
        build_bwrap_argv("true", work)


def test_runtime_gateway_token_is_hardlink_covered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _isolate(tmp_path, monkeypatch)
    xdg = tmp_path / "xdg-run"
    runtime = xdg / "praxis-prime"
    runtime.mkdir(parents=True)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))
    token = runtime / "gateway.token"
    token.write_text("SECRET-GWTOKEN\n", encoding="utf-8")
    (home / ".local" / "share" / "praxis-prime").mkdir(parents=True)
    work = home / "proj"
    work.mkdir()
    os.link(token, work / "tok.bin")
    clear_data_inode_cache()
    argv = build_bwrap_argv("true", work)
    assert _cover(argv, "/workspace/tok.bin")[:2] == ["--ro-bind", "/dev/null"]
    mcp = build_mcp_bwrap_argv(
        "/bin/sh",
        ("-c", "echo ok"),
        cwd=work,
        env={"PATH": "/usr/bin:/bin"},
        network="off",
    )
    assert _cover(mcp, str(work / "tok.bin"))[:2] == ["--ro-bind", "/dev/null"]


def test_orphaned_sidecar_link_is_not_covered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _isolate(tmp_path, monkeypatch)
    root = home / ".local" / "share" / "praxis-prime"
    root.mkdir(parents=True)
    wal = root / "accounts.db-wal"
    wal.write_text("SECRET-WAL\n", encoding="utf-8")
    work = home / "proj"
    work.mkdir()
    orphan = work / "old-wal"
    os.link(wal, orphan)
    wal.unlink()
    clear_data_inode_cache()
    argv = build_bwrap_argv("true", work)
    covered = [
        argv[index + 2]
        for index, item in enumerate(argv[:-2])
        if item == "--ro-bind" and argv[index + 1] == "/dev/null"
    ]
    assert "/workspace/old-wal" not in covered


def test_second_supervisor_refuses_instead_of_killing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.test_m1c import _child_env

    from praxis_prime.supervisor.supervisor import Supervisor, WorkerUnavailable

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg-state"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "xdg-run"))
    root = tmp_path / "data" / "praxis-prime"
    create_profile(root, "ada")
    env = _child_env()
    first = Supervisor(
        data_root=root,
        runtime_dir=tmp_path / "rA",
        state_dir=tmp_path / "sA",
        env=env,
        start_timeout=20,
    )
    second = Supervisor(
        data_root=root,
        runtime_dir=tmp_path / "rB",
        state_dir=tmp_path / "sB",
        env=env,
        start_timeout=20,
    )
    try:
        first.start()
        assert first.call("ada", "memory.list")["entries"] == []
        holder = first._slots["ada"].process
        assert holder is not None and holder.poll() is None
        pid = holder.pid
        second.start()
        with pytest.raises(WorkerUnavailable):
            second.call("ada", "memory.list")
        time.sleep(0.4)
        assert holder.poll() is None
        assert first.call("ada", "memory.list")["entries"] == []
        again = first._slots["ada"].process
        assert again is not None and again.pid == pid
    finally:
        second.close()
        first.close()


def _opt_workspace() -> Path:
    """A writable directory under ``/opt``.

    The CI image keeps ``/opt`` root-owned. Passwordless sudo is how that
    image installs bubblewrap, so the test uses it only when mkdir fails.
    """
    path = Path("/opt") / f"praxis-prime-hl-{os.getpid()}"
    shutil.rmtree(path, ignore_errors=True)
    try:
        path.mkdir(mode=0o700)
    except OSError:
        subprocess.run(["sudo", "-n", "mkdir", "-m", "0700", str(path)], check=True)
        subprocess.run(
            ["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", str(path)],
            check=True,
        )
    os.chmod(path, 0o700)
    return path


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
