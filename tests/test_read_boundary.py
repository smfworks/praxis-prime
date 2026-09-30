"""Read tools stay in the workspace and do not return secrets or private URLs."""

from __future__ import annotations

import logging
import os
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
from tests.fakes import ScriptedProvider

from praxis_prime.approvals.gate import ApprovalGate
from praxis_prime.audit.log import AuditLog
from praxis_prime.coding.tools import execute_glob, execute_grep
from praxis_prime.loop.engine import AgentLoop
from praxis_prime.loop.events import StatusEvent
from praxis_prime.policy.boundary import (
    InodeScanCache,
    ReadAccess,
    ReadDenied,
    _inode_candidates,
    fetch_public,
    is_secret_path,
    secret_inode_set,
)
from praxis_prime.policy.dials import default_positions
from praxis_prime.policy.engine import HookPoint, PolicyContext, PolicyEngine
from praxis_prime.router.router import ModelRouter
from praxis_prime.router.types import AssistantFinal, ModelRef, ToolCall
from praxis_prime.state import StateDB
from praxis_prime.tools.builtin import (
    builtin_registry,
    execute_list_dir,
    execute_read_file,
    execute_web_fetch,
)
from praxis_prime.tools.registry import Risk, Tool, ToolContext

SECRET = "SUPERSECRETVALUE"


def _ctx(root: Path, access: ReadAccess | None = None) -> ToolContext:
    return ToolContext(
        cwd=str(root),
        cancelled=lambda: False,
        read_access=access,
    )


def _workspace(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "ws"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text(SECRET, encoding="utf-8")
    return root, outside


def _denied(func, *args) -> ReadDenied:
    with pytest.raises(ReadDenied) as caught:
        func(*args)
    assert SECRET not in str(caught.value)
    return caught.value


def test_reads_reject_parent_absolute_and_symlink_escapes(tmp_path: Path):
    root, outside = _workspace(tmp_path)
    (root / "note.txt").write_text("alpha\n", encoding="utf-8")
    (root / "link").symlink_to(outside)
    nested = root / "sub"
    nested.mkdir()
    (nested / "up").symlink_to(outside)
    ctx = _ctx(root)

    assert execute_read_file({"path": "note.txt"}, ctx) == "alpha\n"
    assert execute_read_file({"path": str(root / "note.txt")}, ctx) == "alpha\n"

    for raw in ("../outside.txt", str(outside), "link", "sub/up", str(tmp_path)):
        denial = _denied(execute_read_file, {"path": raw}, ctx)
        assert denial.code == "outside_workspace"

    escape = root / "escape"
    escape.symlink_to(tmp_path)
    assert _denied(execute_list_dir, {"path": "escape"}, ctx).code == "outside_workspace"
    assert _denied(execute_grep, {"pattern": SECRET, "path": ".."}, ctx).code == "outside_workspace"
    assert _denied(execute_glob, {"pattern": "*", "path": str(tmp_path)}, ctx).code == (
        "outside_workspace"
    )
    listed = execute_glob({"pattern": "../*", "path": "."}, ctx)
    assert "outside.txt" not in listed
    assert SECRET not in listed


def test_internal_symlink_and_ordinary_hardlink_still_read(tmp_path: Path):
    root, _outside = _workspace(tmp_path)
    target = root / "note.txt"
    target.write_text("alpha\n", encoding="utf-8")
    (root / "alias").symlink_to(target)
    os.link(target, root / "same.txt")
    ctx = _ctx(root)
    assert execute_read_file({"path": "alias"}, ctx) == "alpha\n"
    assert execute_read_file({"path": "same.txt"}, ctx) == "alpha\n"


def test_secret_names_inside_the_workspace_are_unreadable(tmp_path: Path):
    root = tmp_path / "ws"
    root.mkdir()
    ctx = _ctx(root)
    samples = {
        ".env": "API_KEY=SUPERSECRETVALUE\n",
        ".env.local": "TOKEN=SUPERSECRETVALUE\n",
        "secrets.env": "TOKEN=SUPERSECRETVALUE\n",
        "secrets.env.age": "TOKEN=SUPERSECRETVALUE\n",
        "credentials": "password=SUPERSECRETVALUE\n",
        "credentials.txt": "password=SUPERSECRETVALUE\n",
        "netrc": "machine example login SUPERSECRETVALUE\n",
        ".netrc": "machine example login SUPERSECRETVALUE\n",
        ".git-credentials": "https://user:SUPERSECRETVALUE@example.test\n",
        "gateway.token": "SUPERSECRETVALUE\n",
        "server.pem": "-----BEGIN CERT-----\n",
        "device.key": "-----BEGIN PRIVATE KEY-----\n",
        "id_rsa": "SUPERSECRETVALUE\n",
        "id_rsa.pub": "ssh-ed25519 SUPERSECRETVALUE\n",
        "id_ed25519": "SUPERSECRETVALUE\n",
        "id_ed25519_backup": "SUPERSECRETVALUE\n",
        "login.keyring": "SUPERSECRETVALUE\n",
        ".envrc": "export TOKEN=SUPERSECRETVALUE\n",
        "client.p12": "SUPERSECRETVALUE\n",
        "client.pfx": "SUPERSECRETVALUE\n",
        "service_account.json": '{"private_key": "SUPERSECRETVALUE"}\n',
        "service-account.json": '{"private_key": "SUPERSECRETVALUE"}\n',
        "prod-service-account.json": '{"private_key": "SUPERSECRETVALUE"}\n',
        "prod-service_account.json": '{"private_key": "SUPERSECRETVALUE"}\n',
        ".boto": "aws_secret_access_key = SUPERSECRETVALUE\n",
    }
    for name, body in samples.items():
        path = root / name
        path.write_text(body, encoding="utf-8")
        denial = _denied(execute_read_file, {"path": name}, ctx)
        assert denial.code == "secret_path"
        assert body.strip() not in str(denial)
        found = execute_grep({"pattern": "SUPERSECRETVALUE", "path": "."}, ctx)
        assert "SUPERSECRETVALUE" not in found

    nested = {
        ".ssh/id_rsa": "SUPERSECRETVALUE\n",
        ".aws/credentials": "aws_secret=SUPERSECRETVALUE\n",
        ".config/gcloud/application_default_credentials.json": "{}\n",
        ".kube/config": "token: SUPERSECRETVALUE\n",
        ".docker/config.json": '{"auths": "SUPERSECRETVALUE"}\n',
        ".gnupg/private-keys-v1.d/key": "SUPERSECRETVALUE\n",
        ".local/share/keyrings/login.keyring": "SUPERSECRETVALUE\n",
        ".config/google-chrome/Default/Cookies": "SUPERSECRETVALUE\n",
        ".config/chromium/Default/Login Data": "SUPERSECRETVALUE\n",
        ".mozilla/firefox/profile/logins.json": "SUPERSECRETVALUE\n",
    }
    for rel, body in nested.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        denial = _denied(execute_read_file, {"path": rel}, ctx)
        assert denial.code == "secret_path"
        assert "SUPERSECRETVALUE" not in str(denial)

    (root / "notes.txt").symlink_to(root / ".env")
    link_denial = _denied(execute_read_file, {"path": "notes.txt"}, ctx)
    assert link_denial.code == "secret_path"
    assert "API_KEY" not in str(link_denial)

    (root / "notes.envrc").write_text("export SAFE=1\n", encoding="utf-8")
    assert execute_read_file({"path": "notes.envrc"}, ctx) == "export SAFE=1\n"

    listed = execute_list_dir({"path": "."}, ctx)
    assert ".env" not in listed.splitlines()
    assert ".envrc" not in listed.splitlines()
    assert ".boto" not in listed.splitlines()
    assert "service_account.json" not in listed.splitlines()
    assert _denied(execute_list_dir, {"path": ".ssh"}, ctx).code == "secret_path"
    assert "id_rsa" not in execute_glob({"pattern": "**/*", "path": "."}, ctx)
    assert is_secret_path(Path("/etc/shadow"))
    assert is_secret_path(Path("/proc/self/environ"))
    assert is_secret_path(Path("/proc/1/environ"))
    assert is_secret_path(Path("/proc/1/task/1/environ"))
    for blocked in ("/etc/shadow", "/proc/self/environ", "/proc/1/environ"):
        denial = _denied(execute_read_file, {"path": blocked}, ctx)
        assert denial.code in {"outside_workspace", "secret_path"}
        assert "root:" not in str(denial)


def test_hardlink_to_a_known_secret_is_rejected(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    key = home / ".ssh" / "id_rsa"
    key.parent.mkdir(parents=True)
    key.write_text(SECRET, encoding="utf-8")
    root = tmp_path / "ws"
    root.mkdir()
    alias = root / "notes.txt"
    os.link(key, alias)
    monkeypatch.setenv("HOME", str(home))
    denial = _denied(execute_read_file, {"path": "notes.txt"}, _ctx(root))
    assert denial.code == "secret_path"
    assert SECRET not in str(denial)


def test_inode_scan_cap_denies_the_read(tmp_path: Path, monkeypatch, caplog):
    ssh = tmp_path / "ssh"
    ssh.mkdir()
    for name in ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"):
        (ssh / name).write_text("x", encoding="utf-8")
    root = tmp_path / "ws"
    root.mkdir()
    (root / "note.txt").write_text("hello\n", encoding="utf-8")
    monkeypatch.setattr("praxis_prime.policy.boundary._inode_candidates", lambda: [ssh])
    monkeypatch.setattr("praxis_prime.policy.boundary._MAX_INODE_FILES", 2)
    with caplog.at_level(logging.WARNING, logger="praxis_prime.policy.boundary"):
        denial = _denied(execute_read_file, {"path": "note.txt"}, _ctx(root))
    assert denial.code == "inode_scan_capped"
    assert "hello" not in str(denial)
    assert "cap" in caplog.text.lower()
    assert "denying the read" in caplog.text.lower()

    monkeypatch.setattr("praxis_prime.policy.boundary._MAX_INODE_FILES", 4)
    assert execute_read_file({"path": "note.txt"}, _ctx(root)) == "hello\n"


def test_profile_cache_does_not_trip_the_inode_cap(tmp_path: Path, monkeypatch):
    profile = tmp_path / "google-chrome"
    cache = profile / "Default" / "Cache"
    cache.mkdir(parents=True)
    for index in range(20):
        (cache / f"data_{index}").write_text("cache", encoding="utf-8")
    secret = profile / "Default" / "Cookies"
    secret.write_text(SECRET, encoding="utf-8")
    root = tmp_path / "ws"
    root.mkdir()
    (root / "hello.txt").write_text("hello\n", encoding="utf-8")
    os.link(secret, root / "notes.txt")
    monkeypatch.setattr("praxis_prime.policy.boundary._inode_candidates", lambda: [profile])
    monkeypatch.setattr("praxis_prime.policy.boundary._MAX_INODE_FILES", 3)
    ctx = _ctx(root)
    assert execute_read_file({"path": "hello.txt"}, ctx) == "hello\n"
    denial = _denied(execute_read_file, {"path": "notes.txt"}, ctx)
    assert denial.code == "secret_path"
    assert SECRET not in str(denial)


def test_skipped_profile_secret_still_fails_closed(tmp_path: Path, monkeypatch, caplog):
    profile = tmp_path / "chromium"
    profile.mkdir()
    for name in ("Login Data", "Cookies", "Web Data", "key4.db"):
        (profile / name).write_text("x", encoding="utf-8")
    for index in range(10):
        (profile / f"cache-{index}").write_text("x", encoding="utf-8")
    root = tmp_path / "ws"
    root.mkdir()
    (root / "note.txt").write_text("hello\n", encoding="utf-8")
    monkeypatch.setattr("praxis_prime.policy.boundary._inode_candidates", lambda: [profile])
    monkeypatch.setattr("praxis_prime.policy.boundary._MAX_INODE_FILES", 2)
    with caplog.at_level(logging.WARNING, logger="praxis_prime.policy.boundary"):
        denial = _denied(execute_read_file, {"path": "note.txt"}, _ctx(root))
    assert denial.code == "inode_scan_capped"
    assert "hello" not in str(denial)
    assert "secret-file cap" in caplog.text


def test_kube_cache_does_not_trip_the_inode_cap(tmp_path: Path, monkeypatch):
    kube = tmp_path / ".kube"
    discovery = kube / "cache" / "discovery"
    discovery.mkdir(parents=True)
    http_cache = kube / "http-cache"
    http_cache.mkdir()
    for index in range(600):
        (discovery / f"item-{index}.json").write_text("{}", encoding="utf-8")
        (http_cache / f"item-{index}.json").write_text("{}", encoding="utf-8")
    config = kube / "config"
    config.write_text("apiVersion: v1\n", encoding="utf-8")
    root = tmp_path / "ws"
    root.mkdir()
    (root / "hello.txt").write_text("hello\n", encoding="utf-8")
    os.link(config, root / "notes.txt")
    monkeypatch.setattr("praxis_prime.policy.boundary._inode_candidates", lambda: [kube])
    monkeypatch.setattr("praxis_prime.policy.boundary._MAX_CREDENTIAL_FILES", 500)
    ctx = _ctx(root)
    assert execute_read_file({"path": "hello.txt"}, ctx) == "hello\n"
    denial = _denied(execute_read_file, {"path": "notes.txt"}, ctx)
    assert denial.code == "secret_path"
    assert SECRET not in str(denial)


def test_gcloud_logs_do_not_hide_named_credentials(tmp_path: Path, monkeypatch):
    gcloud = tmp_path / "gcloud"
    logs = gcloud / "logs"
    logs.mkdir(parents=True)
    for index in range(40):
        (logs / f"log-{index}.txt").write_text("x", encoding="utf-8")
    legacy = gcloud / "legacy_credentials" / "user"
    legacy.mkdir(parents=True)
    adc = legacy / "adc.json"
    adc.write_text(SECRET, encoding="utf-8")
    (gcloud / "access_tokens.db").write_text("tokens", encoding="utf-8")
    (gcloud / "credentials.db").write_text("creds", encoding="utf-8")
    (gcloud / "application_default_credentials.json").write_text("{}\n", encoding="utf-8")
    root = tmp_path / "ws"
    root.mkdir()
    (root / "hello.txt").write_text("hello\n", encoding="utf-8")
    os.link(adc, root / "notes.txt")
    os.link(gcloud / "access_tokens.db", root / "tokens.txt")
    monkeypatch.setattr("praxis_prime.policy.boundary._inode_candidates", lambda: [gcloud])
    monkeypatch.setattr("praxis_prime.policy.boundary._MAX_INODE_FILES", 4)
    ctx = _ctx(root)
    assert execute_read_file({"path": "hello.txt"}, ctx) == "hello\n"
    assert _denied(execute_read_file, {"path": "notes.txt"}, ctx).code == "secret_path"
    assert _denied(execute_read_file, {"path": "tokens.txt"}, ctx).code == "secret_path"


_PACKAGED_BROWSER_ROOTS = (
    "snap/chromium/common/chromium",
    "snap/firefox/common/.mozilla",
    ".var/app/com.google.Chrome/config/google-chrome",
    ".var/app/org.chromium.Chromium/config/chromium",
    ".var/app/org.mozilla.firefox/.mozilla",
    ".config/vivaldi",
    ".config/opera",
    ".config/google-chrome-beta",
)


def test_packaged_browser_roots_are_inode_candidates(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    found = set(_inode_candidates())
    for relative in _PACKAGED_BROWSER_ROOTS:
        assert tmp_path.joinpath(*relative.split("/")) in found


@pytest.mark.parametrize("relative", _PACKAGED_BROWSER_ROOTS)
def test_packaged_browser_root_hardlink_is_denied(tmp_path: Path, monkeypatch, relative: str):
    profile = tmp_path.joinpath(*relative.split("/"))
    profile.mkdir(parents=True)
    secret = profile / "Cookies"
    secret.write_text(SECRET, encoding="utf-8")
    (profile / "Cache").mkdir()
    for index in range(8):
        (profile / "Cache" / f"data_{index}").write_text("x", encoding="utf-8")
    root = tmp_path / "ws"
    root.mkdir()
    (root / "hello.txt").write_text("hello\n", encoding="utf-8")
    os.link(secret, root / "notes.txt")
    monkeypatch.setattr("praxis_prime.policy.boundary._inode_candidates", lambda: [profile])
    ctx = _ctx(root)
    assert execute_read_file({"path": "hello.txt"}, ctx) == "hello\n"
    denial = _denied(execute_read_file, {"path": "notes.txt"}, ctx)
    assert denial.code == "secret_path"
    assert SECRET not in str(denial)


def test_symlinked_profile_root_still_catches_a_hardlink(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    real = home / "real-chromium"
    real.mkdir(parents=True)
    secret = real / "Login Data"
    secret.write_text(SECRET, encoding="utf-8")
    linked = home / "chromium"
    linked.symlink_to(real, target_is_directory=True)
    root = tmp_path / "ws"
    root.mkdir()
    (root / "hello.txt").write_text("hello\n", encoding="utf-8")
    os.link(secret, root / "notes.txt")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr("praxis_prime.policy.boundary._inode_candidates", lambda: [linked])
    ctx = _ctx(root)
    assert execute_read_file({"path": "hello.txt"}, ctx) == "hello\n"
    denial = _denied(execute_read_file, {"path": "notes.txt"}, ctx)
    assert denial.code == "secret_path"
    assert SECRET not in str(denial)


def test_firefox_session_backups_are_secret_inodes(tmp_path: Path, monkeypatch):
    profile = tmp_path / "firefox"
    profile.mkdir()
    backups = {
        "logins-backup.json": SECRET,
        "sessionstore.jsonlz4": SECRET,
    }
    root = tmp_path / "ws"
    root.mkdir()
    (root / "hello.txt").write_text("hello\n", encoding="utf-8")
    for name, body in backups.items():
        source = profile / name
        source.write_text(body, encoding="utf-8")
        os.link(source, root / f"copy-{name}")
    monkeypatch.setattr("praxis_prime.policy.boundary._inode_candidates", lambda: [profile])
    ctx = _ctx(root)
    assert execute_read_file({"path": "hello.txt"}, ctx) == "hello\n"
    for name in backups:
        denial = _denied(execute_read_file, {"path": f"copy-{name}"}, ctx)
        assert denial.code == "secret_path"
        assert SECRET not in str(denial)


def test_inode_scan_cache_reuses_until_cleared(monkeypatch):
    calls = {"n": 0}
    real = _inode_candidates

    def counted():
        calls["n"] += 1
        return real()

    monkeypatch.setattr("praxis_prime.policy.boundary._inode_candidates", counted)
    cache = InodeScanCache()
    secret_inode_set(cache)
    secret_inode_set(cache)
    assert calls["n"] == 1
    cache.clear()
    secret_inode_set(cache)
    assert calls["n"] == 2


@pytest.mark.parametrize(
    "relative",
    [
        ".ssh/github",
        ".ssh/work_ed25519",
        ".aws/sso/cache/token.json",
        ".aws/cli/cache/session.json",
        ".gnupg/secring.gpg",
        ".kube/config-staging",
        ".kube/configs/prod.yaml",
        ".local/share/keyrings/default.bin",
    ],
)
def test_credential_dir_file_hardlink_is_denied(tmp_path: Path, monkeypatch, relative: str):
    home = tmp_path / "home"
    secret = home.joinpath(*relative.split("/"))
    secret.parent.mkdir(parents=True)
    secret.write_text(SECRET, encoding="utf-8")
    root = tmp_path / "ws"
    root.mkdir()
    (root / "hello.txt").write_text("hello\n", encoding="utf-8")
    os.link(secret, root / "notes.txt")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    ctx = _ctx(root)
    assert execute_read_file({"path": "hello.txt"}, ctx) == "hello\n"
    denial = _denied(execute_read_file, {"path": "notes.txt"}, ctx)
    assert denial.code == "secret_path"
    assert SECRET not in str(denial)


def test_boto_hardlink_is_denied(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    boto = home / ".boto"
    boto.write_text(SECRET, encoding="utf-8")
    root = tmp_path / "ws"
    root.mkdir()
    (root / "hello.txt").write_text("hello\n", encoding="utf-8")
    os.link(boto, root / "notes.txt")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    ctx = _ctx(root)
    assert execute_read_file({"path": "hello.txt"}, ctx) == "hello\n"
    denial = _denied(execute_read_file, {"path": "notes.txt"}, ctx)
    assert denial.code == "secret_path"
    assert SECRET not in str(denial)


def test_profile_symlink_outside_home_is_not_walked(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    opera = home / ".config" / "opera"
    opera.parent.mkdir(parents=True)
    opera.symlink_to("/")
    root = tmp_path / "ws"
    root.mkdir()
    (root / "hello.txt").write_text("hello\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr("praxis_prime.policy.boundary._inode_candidates", lambda: [opera])
    monkeypatch.setattr("praxis_prime.policy.boundary._MAX_INODE_FILES", 1)
    real_walk = os.walk

    def guarded(top, *args, **kwargs):
        if Path(top).resolve() == Path("/"):
            raise AssertionError("inode scan walked /")
        return real_walk(top, *args, **kwargs)

    monkeypatch.setattr("praxis_prime.policy.boundary.os.walk", guarded)
    assert execute_read_file({"path": "hello.txt"}, _ctx(root)) == "hello\n"


@pytest.mark.parametrize(
    ("link", "filename"),
    [
        (".ssh", "id_rsa"),
        (".config/chromium", "Cookies"),
    ],
)
def test_symlink_outside_home_still_denies_secret_hardlink(
    tmp_path: Path, monkeypatch, link: str, filename: str
):
    home = tmp_path / "home"
    outside = tmp_path / "outside"
    real = outside / "store"
    real.mkdir(parents=True)
    secret = real / filename
    secret.write_text(SECRET, encoding="utf-8")
    linked = home.joinpath(*link.split("/"))
    linked.parent.mkdir(parents=True, exist_ok=True)
    linked.symlink_to(real, target_is_directory=True)
    root = tmp_path / "ws"
    root.mkdir()
    (root / "hello.txt").write_text("hello\n", encoding="utf-8")
    os.link(secret, root / "notes.txt")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr("praxis_prime.policy.boundary._inode_candidates", lambda: [linked])
    ctx = _ctx(root)
    assert execute_read_file({"path": "hello.txt"}, ctx) == "hello\n"
    denial = _denied(execute_read_file, {"path": "notes.txt"}, ctx)
    assert denial.code == "secret_path"
    assert SECRET not in str(denial)


def test_outside_home_entry_budget_fails_closed(tmp_path: Path, monkeypatch, caplog):
    home = tmp_path / "home"
    real = tmp_path / "outside" / "ssh"
    real.mkdir(parents=True)
    (real / "id_rsa").write_text(SECRET, encoding="utf-8")
    for index in range(5):
        (real / f"extra-{index}").write_text("x", encoding="utf-8")
    linked = home / ".ssh"
    linked.parent.mkdir(parents=True)
    linked.symlink_to(real, target_is_directory=True)
    root = tmp_path / "ws"
    root.mkdir()
    (root / "hello.txt").write_text("hello\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr("praxis_prime.policy.boundary._inode_candidates", lambda: [linked])
    monkeypatch.setattr("praxis_prime.policy.boundary._MAX_SCAN_ENTRIES", 1)
    with caplog.at_level(logging.WARNING, logger="praxis_prime.policy.boundary"):
        denial = _denied(execute_read_file, {"path": "hello.txt"}, _ctx(root))
    assert denial.code == "inode_scan_capped"
    assert "hello" not in str(denial)
    assert "directory-entry cap" in caplog.text


def test_credential_root_allows_more_than_500_files(tmp_path: Path, monkeypatch):
    aws = tmp_path / ".aws"
    cache = aws / "cli" / "cache"
    cache.mkdir(parents=True)
    for index in range(600):
        (cache / f"session-{index}.json").write_text("{}", encoding="utf-8")
    known = aws / "known_hosts.d"
    known.mkdir()
    (known / "work").write_text("host", encoding="utf-8")
    creds = aws / "credentials"
    creds.write_text(SECRET, encoding="utf-8")
    root = tmp_path / "ws"
    root.mkdir()
    (root / "hello.txt").write_text("hello\n", encoding="utf-8")
    os.link(creds, root / "notes.txt")
    os.link(cache / "session-0.json", root / "alias.txt")
    monkeypatch.setattr("praxis_prime.policy.boundary._inode_candidates", lambda: [aws])
    ctx = _ctx(root)
    assert execute_read_file({"path": "hello.txt"}, ctx) == "hello\n"
    assert _denied(execute_read_file, {"path": "notes.txt"}, ctx).code == "secret_path"
    assert _denied(execute_read_file, {"path": "alias.txt"}, ctx).code == "secret_path"


def test_credential_file_cap_still_fails_closed(tmp_path: Path, monkeypatch, caplog):
    aws = tmp_path / ".aws"
    aws.mkdir()
    for index in range(20):
        (aws / f"file-{index}").write_text("x", encoding="utf-8")
    root = tmp_path / "ws"
    root.mkdir()
    (root / "hello.txt").write_text("hello\n", encoding="utf-8")
    monkeypatch.setattr("praxis_prime.policy.boundary._inode_candidates", lambda: [aws])
    monkeypatch.setattr("praxis_prime.policy.boundary._MAX_CREDENTIAL_FILES", 10)
    with caplog.at_level(logging.WARNING, logger="praxis_prime.policy.boundary"):
        denial = _denied(execute_read_file, {"path": "hello.txt"}, _ctx(root))
    assert denial.code == "inode_scan_capped"
    assert "hello" not in str(denial)
    assert "secret-file cap" in caplog.text


def test_kube_nested_cache_file_is_still_a_secret_inode(tmp_path: Path, monkeypatch):
    kube = tmp_path / ".kube"
    nested = kube / "configs" / "cache"
    nested.mkdir(parents=True)
    secret = nested / "prod.yaml"
    secret.write_text(SECRET, encoding="utf-8")
    root = tmp_path / "ws"
    root.mkdir()
    (root / "hello.txt").write_text("hello\n", encoding="utf-8")
    os.link(secret, root / "notes.txt")
    monkeypatch.setattr("praxis_prime.policy.boundary._inode_candidates", lambda: [kube])
    ctx = _ctx(root)
    assert execute_read_file({"path": "hello.txt"}, ctx) == "hello\n"
    denial = _denied(execute_read_file, {"path": "notes.txt"}, ctx)
    assert denial.code == "secret_path"
    assert SECRET not in str(denial)


def test_inode_cache_publishes_found_before_ready():
    class Tracing(InodeScanCache):
        def __init__(self) -> None:
            self.events: list[str] = []
            super().__init__()

        def __setattr__(self, name: str, value: object) -> None:
            if name == "events":
                object.__setattr__(self, name, value)
                return
            events = getattr(self, "events", None)
            if events is not None and name in {"found", "ready", "error"}:
                events.append(name)
            super().__setattr__(name, value)

    cache = Tracing()
    secret_inode_set(cache)
    assert cache.events[-2:] == ["found", "ready"]


def test_two_loops_keep_separate_inode_caches(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    ssh = home / ".ssh"
    ssh.mkdir(parents=True)
    root_a = tmp_path / "a"
    root_b = tmp_path / "b"
    root_a.mkdir()
    root_b.mkdir()
    (root_a / "hello.txt").write_text("hello-a\n", encoding="utf-8")
    (root_b / "hello.txt").write_text("hello-b\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr("praxis_prime.policy.boundary._inode_candidates", lambda: [ssh])

    positions = default_positions()
    positions["hipaa"] = "enforce"
    engine = PolicyEngine(positions)

    def make_loop(root: Path, provider: ScriptedProvider) -> AgentLoop:
        return AgentLoop(
            router=ModelRouter([ModelRef("ollama", "fake")], {"ollama": provider}),
            registry=builtin_registry(),
            policy=engine,
            gate=ApprovalGate(None),
            cwd=root,
            max_iterations=4,
        )

    provider_a = ScriptedProvider(
        [
            AssistantFinal(
                content="",
                tool_calls=(
                    ToolCall(id="a1", name="read_file", arguments={"path": "hello.txt"}),
                ),
            ),
            AssistantFinal(content="done-a"),
        ]
    )
    loop_a = make_loop(root_a, provider_a)
    list(loop_a.run_turn("read hello"))
    scanned = set(loop_a.inode_cache.found or ())

    secret = ssh / "id_rsa"
    secret.write_text(SECRET, encoding="utf-8")
    os.link(secret, root_b / "notes.txt")
    provider_b = ScriptedProvider(
        [
            AssistantFinal(
                content="",
                tool_calls=(
                    ToolCall(id="b1", name="read_file", arguments={"path": "notes.txt"}),
                ),
            ),
            AssistantFinal(content="done-b"),
        ]
    )
    loop_b = make_loop(root_b, provider_b)
    assert loop_a.inode_cache is not loop_b.inode_cache
    list(loop_b.run_turn("read the alias"))
    assert loop_a.inode_cache.found == scanned
    assert not hasattr(engine, "inode_cache")

    text_a = [
        message.content
        for message in provider_a.requests[-1].messages
        if message.role == "tool"
    ]
    text_b = [
        message.content
        for message in provider_b.requests[-1].messages
        if message.role == "tool"
    ]
    assert any("hello-a" in text for text in text_a)
    assert any("secret" in text.lower() for text in text_b)
    assert all(SECRET not in text for text in text_a + text_b)

    stale = InodeScanCache()
    stale.found = set()
    stale.ready = True
    allowed = engine.evaluate(
        PolicyContext(
            hook=HookPoint.H3_PRE_TOOL,
            tool="read_file",
            risk=Risk.READ,
            arguments={"path": "notes.txt"},
            workspace_root=str(root_b),
            inode_cache=stale,
        )
    )
    denied = engine.evaluate(
        PolicyContext(
            hook=HookPoint.H3_PRE_TOOL,
            tool="read_file",
            risk=Risk.READ,
            arguments={"path": "notes.txt"},
            workspace_root=str(root_b),
            inode_cache=loop_b.inode_cache,
        )
    )
    assert allowed.decision == "allow"
    assert denied.decision == "deny"
    assert SECRET not in denied.reason


def test_secret_created_mid_turn_then_hardlinked_is_denied(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    ssh = home / ".ssh"
    ssh.mkdir(parents=True)
    root = tmp_path / "ws"
    root.mkdir()
    (root / "hello.txt").write_text("hello\n", encoding="utf-8")
    alias = root / "notes.txt"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr("praxis_prime.policy.boundary._inode_candidates", lambda: [ssh])

    def plant(_arguments, _context):
        secret = ssh / "github"
        secret.write_text(SECRET, encoding="utf-8")
        os.link(secret, alias)
        return "planted"

    registry = builtin_registry()
    registry.register(
        Tool(
            name="plant_secret",
            description="Create a secret and hardlink it into the workspace.",
            parameters={"type": "object", "properties": {}},
            risk=Risk.READ,
            execute=plant,
        )
    )
    provider = ScriptedProvider(
        [
            AssistantFinal(
                content="",
                tool_calls=(
                    ToolCall(id="c1", name="read_file", arguments={"path": "hello.txt"}),
                ),
            ),
            AssistantFinal(
                content="",
                tool_calls=(ToolCall(id="c2", name="plant_secret", arguments={}),),
            ),
            AssistantFinal(
                content="",
                tool_calls=(
                    ToolCall(id="c3", name="read_file", arguments={"path": "notes.txt"}),
                ),
            ),
            AssistantFinal(content="done"),
        ]
    )
    loop = AgentLoop(
        router=ModelRouter([ModelRef("ollama", "fake")], {"ollama": provider}),
        registry=registry,
        policy=PolicyEngine(),
        gate=ApprovalGate(None),
        cwd=root,
        max_iterations=6,
    )
    list(loop.run_turn("read, plant a secret, read the alias"))
    assert isinstance(loop.inode_cache, InodeScanCache)
    assert not hasattr(loop.policy, "inode_cache")
    tool_text = [
        message.content
        for message in provider.requests[-1].messages
        if message.role == "tool"
    ]
    assert any("hello" in text for text in tool_text)
    assert any("planted" in text for text in tool_text)
    assert any("notes.txt" in text and "secret" in text.lower() for text in tool_text)
    assert all(SECRET not in text for text in tool_text)


def test_allowlist_is_explicit_and_does_not_unlock_secrets(tmp_path: Path):
    root, outside = _workspace(tmp_path)
    granted = ReadAccess(allow_paths=(str(outside),))
    assert execute_read_file({"path": str(outside)}, _ctx(root, granted)) == SECRET

    relative = ReadAccess(allow_paths=("outside.txt",))
    denial = _denied(execute_read_file, {"path": str(outside)}, _ctx(root, relative))
    assert denial.code == "outside_workspace"

    secret = tmp_path / ".env"
    secret.write_text(f"TOKEN={SECRET}\n", encoding="utf-8")
    allowed_secret = ReadAccess(allow_paths=(str(secret),))
    secret_denial = _denied(
        execute_read_file, {"path": str(secret)}, _ctx(root, allowed_secret)
    )
    assert secret_denial.code == "secret_path"


def test_fetch_blocks_private_metadata_and_redirects(tmp_path: Path):
    del tmp_path

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/ok":
                body = b"page body"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            locations = {
                "/to-ok": "/ok",
                "/meta": "http://169.254.169.254/latest/meta-data",
                "/file": "file:///etc/passwd",
                "/priv": "http://10.1.2.3/secret",
                "/link": "http://169.254.1.1/",
                "/ula": "http://[fc00::1]/",
                "/loop": f"http://{self.headers.get('Host')}/loop",
            }
            if path not in locations:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(302)
            self.send_header("Location", locations[path])
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, fmt, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    allow = frozenset({"loopback"})
    try:
        base = f"http://127.0.0.1:{port}"
        with pytest.raises(ReadDenied) as blocked:
            execute_web_fetch({"url": f"{base}/ok"}, _ctx(Path(".")))
        assert blocked.value.code == "fetch_loopback"

        text = execute_web_fetch(
            {"url": f"{base}/to-ok"},
            _ctx(Path("."), ReadAccess(fetch_allow=allow)),
        )
        assert "page body" in text
        cases = {
            f"{base}/meta": "fetch_metadata",
            f"{base}/file": "fetch_scheme",
            f"{base}/priv": "fetch_private",
            f"{base}/link": "fetch_link_local",
            f"{base}/ula": "fetch_private",
            f"{base}/loop": "fetch_redirect",
        }
        for url, code in cases.items():
            with pytest.raises(ReadDenied) as caught:
                fetch_public(url, fetch_allow=allow)
            assert caught.value.code == code
    finally:
        server.shutdown()

    blocked_urls = (
        "file:///etc/passwd",
        "ftp://example.com/a",
        "http://169.254.169.254/latest",
        "http://[::ffff:169.254.169.254]/",
        "http://2852039166/",
        "http://0251.0376.0251.0376/",
        "http://0xa9fea9fe/",
        "http://127.0.0.1/",
        "http://127.1/",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
        "http://2130706433/",
        "http://[::1]/",
        "http://localhost/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://192.168.0.1/",
        "http://[fc00::1]/",
        "http://[fe80::1]/",
        "http://169.254.1.1/",
        "http://metadata.google.internal/",
        "http://0.0.0.0/",
    )
    for url in blocked_urls:
        with pytest.raises(ReadDenied):
            fetch_public(url)

    with pytest.raises(ReadDenied) as metadata:
        fetch_public(
            "http://169.254.169.254/",
            fetch_allow=frozenset({"loopback", "private", "link_local"}),
        )
    assert metadata.value.code == "fetch_metadata"


def test_redirect_hops_re_resolve_dns(monkeypatch):
    lookups: list[str] = []

    def resolve(host, port, *args, **kwargs):
        del args, kwargs
        lookups.append(host)
        ip = "1.1.1.1" if lookups.count(host) == 1 else "169.254.169.254"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 80))]

    def exchange(url, pinned, timeout, user_agent, max_bytes):
        del url, timeout, user_agent, max_bytes
        assert pinned == "1.1.1.1"
        return 302, {"location": "http://rebind.test/secret"}, b""

    with pytest.raises(ReadDenied) as caught:
        fetch_public(
            "http://rebind.test/start",
            resolve=resolve,
            exchange=exchange,
        )
    assert caught.value.code == "fetch_metadata"
    assert lookups == ["rebind.test", "rebind.test"]

    calls = {"n": 0}

    def always_public(host, port, *args, **kwargs):
        del host, args, kwargs
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", port or 80))]

    def looping(url, pinned, timeout, user_agent, max_bytes):
        del url, pinned, timeout, user_agent, max_bytes
        calls["n"] += 1
        return 302, {"location": "http://1.1.1.1/again"}, b""

    with pytest.raises(ReadDenied) as limited:
        fetch_public("http://1.1.1.1/start", resolve=always_public, exchange=looping)
    assert limited.value.code == "fetch_redirect"
    assert calls["n"] == 6

    def to_loopback(url, pinned, timeout, user_agent, max_bytes):
        del url, pinned, timeout, user_agent, max_bytes
        return 302, {"location": "http://127.0.0.1/latest"}, b""

    with pytest.raises(ReadDenied) as loopback:
        fetch_public("http://1.1.1.1/start", exchange=to_loopback)
    assert loopback.value.code == "fetch_loopback"


def test_explicit_metadata_allow_is_required_to_pass_classification():
    def exchange(url, pinned, timeout, user_agent, max_bytes):
        del url, timeout, user_agent, max_bytes
        assert pinned == "169.254.169.254"
        return 200, {"content-type": "text/plain"}, b"metadata body"

    result = fetch_public(
        "http://169.254.169.254/latest",
        fetch_allow=frozenset({"metadata"}),
        exchange=exchange,
    )
    assert result.body == b"metadata body"


def test_enforce_mode_fails_closed_and_audits_denied_reads(tmp_path: Path, monkeypatch):
    root, outside = _workspace(tmp_path)
    db = StateDB(tmp_path / "prime.db")
    audit = AuditLog(db)
    positions = default_positions()
    positions["hipaa"] = "enforce"
    engine = PolicyEngine(positions, audit=audit, workspace_root=str(root))
    verdict = engine.evaluate(
        PolicyContext(
            hook=HookPoint.H3_PRE_TOOL,
            tool="read_file",
            risk=Risk.READ,
            arguments={"path": str(outside)},
            workspace_root=str(root),
        )
    )
    assert verdict.decision == "deny"
    assert SECRET not in verdict.reason
    rows = db.conn.execute(
        "SELECT kind, summary, payload_json FROM audit_events"
    ).fetchall()
    assert any(row["kind"] == "read_denied" for row in rows)
    blob = " ".join(row["payload_json"] + row["summary"] for row in rows)
    assert SECRET not in blob
    assert "outside_workspace" in blob
    assert '"decision":"deny"' in blob

    secret = root / "gateway.token"
    secret.write_text(SECRET, encoding="utf-8")
    secret_verdict = engine.evaluate(
        PolicyContext(
            hook=HookPoint.H3_PRE_TOOL,
            tool="read_file",
            risk=Risk.READ,
            arguments={"path": "gateway.token"},
            workspace_root=str(root),
        )
    )
    assert secret_verdict.decision == "deny"

    def explode(*_args, **_kwargs):
        raise RuntimeError("boundary failed")

    monkeypatch.setattr("praxis_prime.policy.boundary.confine_path", explode)
    failed = engine.evaluate(
        PolicyContext(
            hook=HookPoint.H3_PRE_TOOL,
            tool="read_file",
            risk=Risk.READ,
            arguments={"path": "note.txt"},
            workspace_root=str(root),
        )
    )
    assert failed.decision == "deny"
    assert "failed closed" in failed.reason

    watched = default_positions()
    watched["hipaa"] = "monitor"
    monitor = PolicyEngine(watched, audit=AuditLog(StateDB(tmp_path / "mon.db")))
    monitored = monitor.evaluate(
        PolicyContext(
            hook=HookPoint.H3_PRE_TOOL,
            tool="read_file",
            risk=Risk.READ,
            arguments={"path": str(outside)},
            workspace_root=str(root),
        )
    )
    assert monitored.decision == "allow"
    assert _denied(execute_read_file, {"path": str(outside)}, _ctx(root)).code == (
        "outside_workspace"
    )

    off = PolicyEngine()
    allowed = off.evaluate(
        PolicyContext(
            hook=HookPoint.H3_PRE_TOOL,
            tool="read_file",
            risk=Risk.READ,
            arguments={"path": str(outside)},
            workspace_root=str(root),
        )
    )
    assert allowed.decision == "allow"


def test_loop_enforce_does_not_return_an_outside_read(tmp_path: Path):
    root, outside = _workspace(tmp_path)
    db = StateDB(tmp_path / "prime.db")
    audit = AuditLog(db)
    positions = default_positions()
    positions["hipaa"] = "enforce"
    provider = ScriptedProvider(
        [
            AssistantFinal(
                content="",
                tool_calls=(
                    ToolCall(
                        id="c1",
                        name="read_file",
                        arguments={"path": str(outside)},
                    ),
                ),
            ),
            AssistantFinal(content="done"),
        ]
    )
    loop = AgentLoop(
        router=ModelRouter([ModelRef("ollama", "fake")], {"ollama": provider}),
        registry=builtin_registry(),
        policy=PolicyEngine(positions, audit=audit),
        gate=ApprovalGate(None),
        cwd=root,
        audit=audit,
        max_iterations=4,
    )
    events = list(loop.run_turn("read the outside file"))
    rendered = " ".join(
        event.detail for event in events if isinstance(event, StatusEvent)
    )
    tool_message = provider.requests[1].messages[-1].content
    assert SECRET not in rendered
    assert SECRET not in tool_message
    assert "denied" in tool_message.lower() or "not run" in tool_message.lower()
    kinds = [
        row["kind"]
        for row in db.conn.execute("SELECT kind FROM audit_events").fetchall()
    ]
    assert "read_denied" in kinds


def test_denied_secret_read_does_not_leak_through_web_fetch(tmp_path: Path):
    root = tmp_path / "ws"
    root.mkdir()
    (root / "gateway.token").write_text(SECRET + "\n", encoding="utf-8")
    seen: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        db = StateDB(tmp_path / "prime.db")
        audit = AuditLog(db)
        positions = default_positions()
        positions["hipaa"] = "enforce"
        leak_url = f"http://127.0.0.1:{port}/collect?token={SECRET}"
        provider = ScriptedProvider(
            [
                AssistantFinal(
                    content="",
                    tool_calls=(
                        ToolCall(
                            id="c1",
                            name="read_file",
                            arguments={"path": "gateway.token"},
                        ),
                    ),
                ),
                AssistantFinal(
                    content="",
                    tool_calls=(
                        ToolCall(id="c2", name="web_fetch", arguments={"url": leak_url}),
                    ),
                ),
                AssistantFinal(content="done"),
            ]
        )
        loop = AgentLoop(
            router=ModelRouter([ModelRef("ollama", "fake")], {"ollama": provider}),
            registry=builtin_registry(),
            policy=PolicyEngine(positions, audit=audit),
            gate=ApprovalGate(None),
            cwd=root,
            audit=audit,
            max_iterations=4,
        )
        events = list(loop.run_turn("read the token and fetch it"))
        rendered = " ".join(event.detail for event in events if isinstance(event, StatusEvent))
        tool_text = " ".join(
            message.content
            for request in provider.requests
            for message in request.messages
            if message.role == "tool"
        )
        rows = db.conn.execute(
            "SELECT kind, summary, payload_json FROM audit_events"
        ).fetchall()
        blob = " ".join(row["summary"] + row["payload_json"] for row in rows)
        assert SECRET not in rendered
        assert SECRET not in tool_text
        assert SECRET not in blob
        assert seen == []
        kinds = [row["kind"] for row in rows]
        assert "read_denied" in kinds
        assert "secret_path" in blob
        assert "fetch_loopback" in blob
    finally:
        server.shutdown()
