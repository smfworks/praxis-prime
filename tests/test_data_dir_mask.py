"""Data-directory shell denylist: globs, cd, and the bubblewrap mask."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from praxis_prime.approvals.card import HOST_FULL_WRITE, HOST_NEEDS_BWRAP
from praxis_prime.policy.boundary import bind_data_root, private_data_command
from praxis_prime.sandbox.bwrap import SandboxError, build_bwrap_argv, bwrap_available, run_bwrap
from praxis_prime.tools.registry import ToolContext
from praxis_prime.tools.shell import execute_shell

_SECRET = "WORK-SOUL-SECRET"
_BACKUP = "BACKUP-TEXT"
_HASH = "argon2id-test-hash"


def _tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    home = tmp_path / "home"
    share = home / ".local" / "share"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(share))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    private = share / "praxis-prime"
    (private / "profiles" / "work").mkdir(parents=True)
    (private / "backups").mkdir()
    (private / "org").mkdir()
    (private / "profiles" / "work" / "SOUL.md").write_text(_SECRET + "\n", encoding="utf-8")
    (private / "backups" / "notes.txt").write_text(_BACKUP + "\n", encoding="utf-8")
    (private / "org" / "policy.toml").write_text("[org]\n", encoding="utf-8")
    (private / "accounts.db").write_text(_HASH + "\n", encoding="utf-8")
    bind_data_root(None)
    return home, private


def _leaks(home: Path) -> tuple[str, ...]:
    data = ".local/share/praxis-prime"
    return (
        f"cd {data} && strings accounts.db",
        f"cd {data} && cat profiles/work/SOUL.md",
        f"cd {data} && cat backups/notes.txt",
        f"cat {data}/p*/work/S*",
        "cat .local/share/praxis-*/profiles/work/SOUL.md",
        "cat .local/share/pra?is-prime/profiles/work/SOUL.md",
        "cd .local/share && grep -rh SECRET praxis-prime",
        "git grep --no-index SECRET .local",
        "zip -r z.zip .local/share",
        "ag SECRET .local/share",
    )


def test_cd_globs_and_git_grep_are_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, _private = _tree(tmp_path, monkeypatch)
    for command in _leaks(home):
        assert private_data_command(command, home), command
    assert not private_data_command("echo hello", home)
    assert not private_data_command("grep -r SECRET notes", home)
    assert private_data_command("cd -", home)
    assert private_data_command(
        "cd .local/share/praxis-prime;cat profiles/work/SOUL.md",
        home,
    )
    assert private_data_command(
        "cd .local/share/praxis-prime&&cat profiles/work/SOUL.md",
        home,
    )
    org = "cat .local/share/praxis-prime/org/policy.toml"
    assert not private_data_command(org, home)
    context = ToolContext(cwd=str(home), cancelled=lambda: False, shell_approved=True)
    for command in _leaks(home):
        with pytest.raises(RuntimeError, match="protected"):
            execute_shell({"command": command}, context)


def test_bwrap_tmpfs_hides_the_data_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not bwrap_available():
        pytest.skip("bubblewrap is not installed")
    home, _private = _tree(tmp_path, monkeypatch)
    argv = build_bwrap_argv("echo hi", home)
    masked = "/workspace/.local/share/praxis-prime"
    assert argv[argv.index(masked) - 1] == "--tmpfs"
    commands = (
        "cd .local/share/praxis-prime && cat profiles/work/SOUL.md",
        "cd .local/share/praxis-prime && strings accounts.db",
        "cat .local/share/praxis-prime/p*/work/S*",
        "cd .local/share && grep -rh SECRET praxis-prime",
        "git grep --no-index SECRET .local",
        "python3 -c \"print(open('.local/share/praxis-prime/profiles/work/SOUL.md').read())\"",
    )
    for command in commands:
        output = run_bwrap(command, home, lambda: False)
        assert _SECRET not in output, command
        assert _BACKUP not in output, command
        assert _HASH not in output, command
    innocent = run_bwrap("echo hello", home, lambda: False)
    assert "hello" in innocent


def test_host_card_refuses_a_data_dir_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from praxis_prime.approvals.gate import ApprovalDecision, ApprovalGate, ApprovalRequest
    from praxis_prime.loop.engine import AgentLoop
    from praxis_prime.policy.engine import PolicyEngine
    from praxis_prime.router.router import ModelRouter
    from praxis_prime.router.types import AssistantFinal, ModelRef, ToolCall
    from praxis_prime.tools.builtin import builtin_registry

    home, _private = _tree(tmp_path, monkeypatch)
    monkeypatch.setattr("praxis_prime.tools.shell.bwrap_available", lambda: False)
    command = "cd .local/share/praxis-prime && cat profiles/work/SOUL.md"
    seen: list[ApprovalRequest] = []

    def approver(request: ApprovalRequest) -> ApprovalDecision:
        seen.append(request)
        return ApprovalDecision.ALLOW_ONCE

    provider_calls = [
        AssistantFinal(
            content="",
            tool_calls=(ToolCall(id="c1", name="shell", arguments={"command": command}),),
        ),
        AssistantFinal(content="done"),
    ]
    from tests.fakes import ScriptedProvider

    loop = AgentLoop(
        router=ModelRouter(
            [ModelRef("ollama", "fake")],
            {"ollama": ScriptedProvider(provider_calls)},
        ),
        registry=builtin_registry(),
        policy=PolicyEngine(),
        gate=ApprovalGate(approver),
        cwd=home,
        max_iterations=4,
    )
    list(loop.run_turn("read the persona"))
    assert seen
    assert seen[0].mount == HOST_NEEDS_BWRAP
    context = ToolContext(
        cwd=str(home),
        cancelled=lambda: False,
        shell_approved=True,
        host_shell_approved=True,
    )
    for host_command in (command, "echo hello", "ls"):
        with pytest.raises(RuntimeError, match="install bubblewrap to run shell commands"):
            execute_shell({"command": host_command}, context)
    assert (home / ".local" / "share" / "praxis-prime" / "profiles" / "work" / "SOUL.md").read_text(
        encoding="utf-8"
    ).startswith(_SECRET)


def test_fresh_install_keeps_host_shell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    monkeypatch.setattr("praxis_prime.tools.shell.bwrap_available", lambda: False)
    monkeypatch.setattr(
        "praxis_prime.tools.shell.run_host_shell",
        lambda command, cwd, cancelled, timeout=30, env=None: "hello",
    )
    bind_data_root(None)
    from tests.fakes import ScriptedProvider

    from praxis_prime.approvals.gate import ApprovalDecision, ApprovalGate, ApprovalRequest
    from praxis_prime.loop.engine import AgentLoop
    from praxis_prime.policy.engine import PolicyEngine
    from praxis_prime.router.router import ModelRouter
    from praxis_prime.router.types import AssistantFinal, ModelRef, ToolCall
    from praxis_prime.tools.builtin import builtin_registry

    seen: list[ApprovalRequest] = []

    def approver(request: ApprovalRequest) -> ApprovalDecision:
        seen.append(request)
        return ApprovalDecision.ALLOW_ONCE

    loop = AgentLoop(
        router=ModelRouter(
            [ModelRef("ollama", "fake")],
            {
                "ollama": ScriptedProvider(
                    [
                        AssistantFinal(
                            content="",
                            tool_calls=(
                                ToolCall(
                                    id="c1",
                                    name="shell",
                                    arguments={"command": "echo hello"},
                                ),
                            ),
                        ),
                        AssistantFinal(content="done"),
                    ]
                )
            },
        ),
        registry=builtin_registry(),
        policy=PolicyEngine(),
        gate=ApprovalGate(approver),
        cwd=home,
        max_iterations=4,
    )
    list(loop.run_turn("say hello"))
    assert seen
    assert seen[0].mount == HOST_FULL_WRITE
    assert (
        execute_shell(
            {"command": "echo hello"},
            ToolContext(
                cwd=str(home),
                cancelled=lambda: False,
                shell_approved=True,
                host_shell_approved=True,
            ),
        )
        == "hello"
    )


def test_bind_inside_the_data_dir_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, private = _tree(tmp_path, monkeypatch)
    with pytest.raises(SandboxError, match="inside the account data directory"):
        build_bwrap_argv("cat work/SOUL.md", private / "profiles")
    project = home / "proj"
    project.mkdir()
    with pytest.raises(SandboxError, match="inside the account data directory"):
        build_bwrap_argv(
            "echo hi",
            project,
            ro_binds=[(str(private / "profiles"), "/opt/profiles")],
        )
    worktree = private / "worktrees" / "repo" / "task"
    worktree.mkdir(parents=True)
    argv = build_bwrap_argv("echo hi", worktree)
    assert "/workspace" in argv


def test_inode_alias_of_home_is_masked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, _private = _tree(tmp_path, monkeypatch)
    alias = tmp_path / "alias"
    alias.mkdir()
    real_stat = os.stat
    home_stat = real_stat(home)

    def fake_stat(path, follow_symlinks=True):
        if Path(path) == alias:
            return home_stat
        return real_stat(path, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "stat", fake_stat)
    argv = build_bwrap_argv("echo hi", alias)
    masked = "/workspace/.local/share/praxis-prime"
    assert argv[argv.index(masked) - 1] == "--tmpfs"
