"""Regression tests for issue #8: shell deletes and the read-write bind.

The old classifier treated a regex miss as READ and skipped approval inside
bubblewrap. The old launcher mounted the workspace with ``--bind``. Both
paths now fail closed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from praxis_prime.audit.log import AuditLog
from praxis_prime.policy.dials import default_positions
from praxis_prime.policy.engine import HookPoint, PolicyContext, PolicyEngine
from praxis_prime.sandbox.bwrap import (
    SandboxError,
    build_bwrap_argv,
    bwrap_available,
    run_bwrap,
    run_bwrap_status,
)
from praxis_prime.state import StateDB
from praxis_prime.tools.registry import Risk, ToolContext
from praxis_prime.tools.shell import classify_command, execute_shell
from praxis_prime.tools.shellclass import (
    GitProbe,
    ShellClass,
    build_name_only_command,
    classify_shell,
    command_for_sandbox,
)

# Delete and overwrite forms that the old denylist did not force into approval
# when bubblewrap was present. Interpreter bodies, append redirects, find -exec,
# command/env indirection, and alias syntax are the ones that stayed READ.
_DELETE_VARIANTS = (
    "python -c 'import os; os.remove(\"note.txt\")'",
    "python3 -c 'open(\"note.txt\",\"w\").write(\"x\")'",
    "perl -e 'unlink \"note.txt\"'",
    "ruby -e 'File.delete(\"note.txt\")'",
    "find . -exec rm {} +",
    "find . -name note.txt -delete",
    "command rm -rf note.txt",
    "busybox rm note.txt",
    "echo hi >> note.txt",
    "echo hi > note.txt",
    "tee note.txt",
    "sed -i 's/a/b/' note.txt",
    "truncate -s 0 note.txt",
    "dd if=/dev/zero of=note.txt",
    "shred -u note.txt",
    "mv other.txt note.txt",
    "cp other.txt note.txt",
    "git clean -fd",
    "git reset --hard",
    "git checkout -- note.txt",
    "chmod 777 note.txt",
    "chown root note.txt",
    "echo hi | bash",
    "echo hi | python",
    "echo x | xargs rm",
    "eval 'rm note.txt'",
    "`rm note.txt`",
    "$(rm note.txt)",
    "$CMD note.txt",
    "alias rm='rm -rf'",
    "shopt -s expand_aliases",
    "FOO=rm ls",
)


def _ctx(tmp_path: Path, **kwargs: object) -> ToolContext:
    return ToolContext(cwd=str(tmp_path), cancelled=lambda: False, **kwargs)  # type: ignore[arg-type]


def _live_bwrap() -> bool:
    """Run the bubblewrap section. In CI, missing bubblewrap is a failure."""
    in_ci = os.environ.get("CI") == "true" or os.environ.get("GITHUB_ACTIONS") == "true"
    if bwrap_available():
        return True
    if in_ci:
        raise AssertionError("bubblewrap must be installed in CI")
    return False


def _note_live_bwrap(section: str) -> None:
    """Record that a live bubblewrap assertion passed, for the CI log."""
    line = f"live bwrap: {section}"
    print(line, flush=True)
    path = os.environ.get("PRAXIS_PRIME_BWRAP_LOG")
    if not path and (
        os.environ.get("CI") == "true" or os.environ.get("GITHUB_ACTIONS") == "true"
    ):
        root = os.environ.get("RUNNER_TEMP", "/tmp")
        path = str(Path(root) / "live-bwrap.txt")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def _workspace_mount(argv: list[str]) -> tuple[str, str]:
    for index, token in enumerate(argv):
        if token == "/workspace" and index >= 2 and argv[index - 2] in {"--bind", "--ro-bind"}:
            return argv[index - 2], argv[index - 1]
    raise AssertionError("workspace mount missing")


def test_delete_variants_that_bypassed_the_classifier_require_approval():
    for command in _DELETE_VARIANTS:
        prepared = classify_command(command, sandbox_ready=True)
        assert prepared.force_approval is True, command
        assert prepared.write_capable is True, command
        verdict = PolicyEngine().evaluate(
            PolicyContext(
                hook=HookPoint.H3_PRE_TOOL,
                tool="shell",
                risk=prepared.risk,
                sandboxed=True,
                force_approval=False,
                summary=prepared.summary,
                arguments={"command": command},
            )
        )
        assert verdict.decision == "ask", command


def _git(*args: str, cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def _track_note(root: Path) -> None:
    """Commit ``note.txt`` so a content diff's name-only probe can succeed."""
    _git("init", "-q", cwd=root)
    _git("add", "--", "note.txt", cwd=root)
    _git(
        "-c",
        "user.email=tester@example.com",
        "-c",
        "user.name=tester",
        "commit",
        "-q",
        "-m",
        "init",
        cwd=root,
    )


def test_read_only_allowlist_skips_approval_inside_the_workspace(tmp_path: Path):
    (tmp_path / "note.txt").write_text("alpha\n", encoding="utf-8")
    _track_note(tmp_path)
    allowed = (
        "ls",
        "ls -la",
        "cat note.txt",
        "head -n 5 note.txt",
        "git status",
        "git diff --stat",
        "git diff --name-only",
        "git diff --name-status",
        "git diff note.txt",
        "git log --oneline",
        "git log --stat",
        "pytest --collect-only",
        "python -m pytest --collect-only",
        "ls && git status",
    )
    for command in allowed:
        prepared = classify_command(command, sandbox_ready=True, workspace=tmp_path)
        assert prepared.force_approval is False, command
        assert prepared.risk.value == "READ", command
        assert prepared.write_capable is False, command
    outside = classify_command("cat /etc/passwd", sandbox_ready=True, workspace=tmp_path)
    assert outside.force_approval is True
    escape = classify_command("cat ../note.txt", sandbox_ready=True, workspace=tmp_path)
    assert escape.force_approval is True
    running = classify_command("pytest", sandbox_ready=True, workspace=tmp_path)
    assert running.force_approval is True
    secret = classify_command("cat secrets.env", sandbox_ready=True, workspace=tmp_path)
    assert secret.force_approval is True


def test_git_operands_use_the_shared_secret_denylist(tmp_path: Path):
    (tmp_path / "note.txt").write_text("alpha\n", encoding="utf-8")
    (tmp_path / "README").write_text("hi\n", encoding="utf-8")
    _track_note(tmp_path)
    blocked = (
        "git diff secrets.env",
        "git log -p .env",
        "git diff -- secrets.env",
        "git log -p -- .env",
        "git diff -- .env.local",
        "git status -- id_rsa",
        "git diff -- subdir/credentials.json",
        "git log -p -- :(literal).env",
        "git diff -- .ssh/config",
    )
    for command in blocked:
        prepared = classify_command(command, sandbox_ready=True, workspace=tmp_path)
        assert prepared.force_approval is True, command
        assert classify_shell(command, workspace=tmp_path).allowlisted is False, command
    allowed = (
        "git diff note.txt",
        "git diff -- note.txt",
        "git diff HEAD -- note.txt",
        "git log --name-only -- README",
        "git diff --stat",
        "git diff --name-status note.txt",
    )
    for command in allowed:
        prepared = classify_command(command, sandbox_ready=True, workspace=tmp_path)
        assert prepared.force_approval is False, command
        assert classify_shell(command, workspace=tmp_path).allowlisted is True, command


def test_globs_rev_paths_and_patch_dumps_require_approval(tmp_path: Path):
    (tmp_path / "note.txt").write_text("alpha\n", encoding="utf-8")
    (tmp_path / "README").write_text("hi\n", encoding="utf-8")
    (tmp_path / "subdir").mkdir()
    _track_note(tmp_path)
    blocked = (
        "git diff -- '*.env'",
        "git diff -- 'secrets.en?'",
        "git diff -- '.en[v]'",
        "git diff '*'",
        "git diff -- ':(top,glob)*.env'",
        "cat *.env",
        "cat '*.env'",
        "head *.env",
        "tail '*.env'",
        "git diff HEAD:secrets.env HEAD:note.txt",
        "git diff HEAD:.env",
        "git diff -- ':(exclude)note.txt'",
        "git diff -- ':^note.txt'",
        "git diff -- ':(top,literal)note.txt'",
        "git diff",
        "git diff .",
        "git diff HEAD",
        "git diff subdir",
        "git log -p",
        "git log -p --all",
        "git log -p README",
        "git log -p -- README",
    )
    for command in blocked:
        prepared = classify_command(command, sandbox_ready=True, workspace=tmp_path)
        assert prepared.force_approval is True, command
        assert classify_shell(command, workspace=tmp_path).allowlisted is False, command
    allowed = (
        "git diff --stat",
        "git diff --name-only",
        "git diff --name-status",
        "git diff note.txt",
        "git diff -- note.txt",
        "git log --stat",
        "git log --name-only",
        "git log --name-status",
        "git log --oneline",
        "cat note.txt",
    )
    for command in allowed:
        prepared = classify_command(command, sandbox_ready=True, workspace=tmp_path)
        assert prepared.force_approval is False, command
        assert classify_shell(command, workspace=tmp_path).allowlisted is True, command


def test_revision_names_and_deleted_dirs_are_not_safe_files(tmp_path: Path):
    (tmp_path / "note.txt").write_text("alpha\n", encoding="utf-8")
    _track_note(tmp_path)
    blocked = (
        "git diff origin/main",
        "git diff feature/x",
        "git diff v1.0",
        "git diff v1.0 v2.0",
        "git diff v1.0..v2.0",
        "git diff main..feature/x",
        "git diff --word-diff v1.0",
        "git diff --color v1.0 v2.0",
        "git diff -U5 origin/main",
        "git diff -- cfg.d",
        "git diff HEAD -- cfg.d",
        "git diff HEAD -- sub/old",
    )
    for command in blocked:
        prepared = classify_command(command, sandbox_ready=True, workspace=tmp_path)
        assert prepared.force_approval is True, command
        assert classify_shell(command, workspace=tmp_path).allowlisted is False, command
    stat = classify_command("git diff --stat origin/main", sandbox_ready=True, workspace=tmp_path)
    assert stat.force_approval is False
    named = classify_command("git diff note.txt", sandbox_ready=True, workspace=tmp_path)
    assert named.force_approval is False


def test_directory_beside_a_file_requires_approval(tmp_path: Path):
    (tmp_path / "note.txt").write_text("alpha\n", encoding="utf-8")
    (tmp_path / "config").mkdir()
    (tmp_path / "sub").mkdir()
    blocked = (
        "git diff config note.txt",
        "git diff note.txt config",
        "git diff note.txt config/",
        "git diff note.txt .",
        "git diff note.txt ./",
        "git diff note.txt sub",
        "git diff HEAD note.txt config",
        "git diff HEAD~1 note.txt config",
        "git diff v1.0 note.txt config",
        "git diff --cached note.txt config",
    )
    for command in blocked:
        prepared = classify_command(command, sandbox_ready=True, workspace=tmp_path)
        assert prepared.force_approval is True, command
        assert classify_shell(command, workspace=tmp_path).allowlisted is False, command
    stat = classify_command(
        "git diff --stat note.txt config",
        sandbox_ready=True,
        workspace=tmp_path,
    )
    assert stat.force_approval is False
    assert classify_shell("git diff --stat note.txt config", workspace=tmp_path).allowlisted is True


def test_icase_magic_and_dangling_symlinks_require_approval(tmp_path: Path):
    (tmp_path / "note.txt").write_text("alpha\n", encoding="utf-8")
    (tmp_path / "lnk").symlink_to("missing")
    blocked = (
        "git diff note.txt ':(icase)CONFIG'",
        "git diff ':(icase)upper'",
        "git diff HEAD note.txt ':(icase)CONFIG'",
        "git diff note.txt lnk",
        "git diff HEAD note.txt lnk",
        "git diff ':(icase)note.txt'",
    )
    for command in blocked:
        prepared = classify_command(command, sandbox_ready=True, workspace=tmp_path)
        assert prepared.force_approval is True, command
        assert classify_shell(command, workspace=tmp_path).allowlisted is False, command
    for command in (
        "git diff ':(literal)note.txt'",
        "git diff ':(top)note.txt'",
        "git diff ':/note.txt'",
    ):
        assert classify_shell(command, workspace=tmp_path).allowlisted is True, command


def _repo_with_secret_diffs(root: Path) -> None:
    (root / "note.txt").write_text("alpha\n", encoding="utf-8")
    (root / "config").mkdir()
    (root / "config" / ".env").write_text("one\n", encoding="utf-8")
    (root / "Upper").mkdir()
    (root / "Upper" / "creds.txt").write_text("one\n", encoding="utf-8")
    (root / "lnk").mkdir()
    (root / "lnk" / ".env").write_text("one\n", encoding="utf-8")
    _git("init", "-q", cwd=root)
    _git("add", "--", "note.txt", "config/.env", "Upper/creds.txt", "lnk/.env", cwd=root)
    _git(
        "-c",
        "user.email=tester@example.com",
        "-c",
        "user.name=tester",
        "commit",
        "-q",
        "-m",
        "init",
        cwd=root,
    )
    (root / "note.txt").write_text("beta\n", encoding="utf-8")
    (root / "config" / ".env").write_text("two\n", encoding="utf-8")
    (root / "Upper" / "creds.txt").write_text("two\n", encoding="utf-8")
    shutil.rmtree(root / "lnk")
    (root / "lnk").symlink_to("missing")


def test_name_only_backstop_catches_a_fooled_classifier(tmp_path: Path, monkeypatch):
    if not _live_bwrap():
        return
    _repo_with_secret_diffs(tmp_path)

    def fooled(command: str, *, workspace: Path | None = None) -> ShellClass:
        del workspace
        probe = build_name_only_command(command)
        assert probe is not None, command
        return ShellClass(True, Risk.READ, "", False, (GitProbe(probe, frozenset({"note.txt"})),))

    monkeypatch.setattr("praxis_prime.tools.shell.classify_shell", fooled)
    blocked = (
        "git diff note.txt ':(icase)CONFIG'",
        "git diff ':(icase)upper'",
        "git diff HEAD note.txt ':(icase)CONFIG'",
        "git diff note.txt lnk",
        "git diff HEAD note.txt lnk",
    )
    for command in blocked:
        prepared = classify_command(command, sandbox_ready=True, workspace=tmp_path)
        assert prepared.force_approval is True, command
    allowed = classify_command("git diff note.txt", sandbox_ready=True, workspace=tmp_path)
    assert allowed.force_approval is False


def test_repo_git_drivers_are_not_auto_approved(tmp_path: Path):
    (tmp_path / "note.txt").write_text("alpha\n", encoding="utf-8")
    _track_note(tmp_path)
    config = tmp_path / ".git" / "config"
    original = config.read_text(encoding="utf-8")
    hardened = command_for_sandbox("git status")
    assert "core.fsmonitor=false" in hardened
    assert "--no-ext-diff" not in hardened
    diff = command_for_sandbox("git diff note.txt")
    assert "--no-ext-diff" in diff
    assert "--no-textconv" in diff
    assert "diff.external=" in diff

    def ask(command: str) -> bool:
        prepared = classify_command(command, sandbox_ready=True, workspace=tmp_path)
        return prepared.force_approval is True

    config.write_text(original + "\n[core]\n\tfsmonitor = ./pwn.sh\n", encoding="utf-8")
    assert ask("git status")
    assert ask("git diff note.txt")
    assert ask("git diff --stat")
    config.write_text(original + "\n[diff]\n\texternal = ./pwn.sh\n", encoding="utf-8")
    assert ask("git diff note.txt")
    config.write_text(
        original + '\n[diff "leak"]\n\ttextconv = ./pwn.sh\n\tcommand = ./pwn.sh\n',
        encoding="utf-8",
    )
    assert ask("git diff note.txt")
    config.write_text(original + '\n[filter "secret"]\n\tclean = ./pwn.sh\n', encoding="utf-8")
    assert ask("git status")
    config.write_text(original + "\n[include]\n\tpath = ../other\n", encoding="utf-8")
    assert ask("git status")
    config.write_text(original, encoding="utf-8")
    (tmp_path / ".gitattributes").write_text("* diff=leak\n*.bin filter=secret\n", encoding="utf-8")
    assert ask("git diff note.txt")
    assert ask("git diff --stat")
    status = classify_command("git status", sandbox_ready=True, workspace=tmp_path)
    assert status.force_approval is False


def test_repo_git_config_does_not_run_inside_bwrap(tmp_path: Path):
    if not _live_bwrap():
        return
    sentinel = "SENTINEL-SECRET-VALUE"
    (tmp_path / "note.txt").write_text("alpha\n", encoding="utf-8")
    (tmp_path / "secrets.env").write_text(sentinel + "\n", encoding="utf-8")
    script = tmp_path / "pwn.sh"
    script.write_text(
        "#!/bin/sh\necho PWNED\ncat secrets.env\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    (tmp_path / ".gitconfig").write_text(
        "\n".join(
            [
                "[core]",
                "    fsmonitor = ./pwn.sh",
                "[diff]",
                "    external = ./pwn.sh",
                '[diff "leak"]',
                "    textconv = ./pwn.sh",
                "    command = ./pwn.sh",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / ".config" / "git").mkdir(parents=True)
    (tmp_path / ".config" / "git" / "config").write_text(
        (tmp_path / ".gitconfig").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (tmp_path / ".gitattributes").write_text("* diff=leak\n", encoding="utf-8")
    _git("init", "-q", cwd=tmp_path)
    _git(
        "add",
        "--",
        "note.txt",
        "secrets.env",
        "pwn.sh",
        ".gitconfig",
        ".gitattributes",
        ".config/git/config",
        cwd=tmp_path,
    )
    _git(
        "-c",
        "user.email=tester@example.com",
        "-c",
        "user.name=tester",
        "commit",
        "-q",
        "-m",
        "init",
        cwd=tmp_path,
    )
    (tmp_path / "note.txt").write_text("beta\n", encoding="utf-8")
    commands = ("git diff note.txt", "git status", "git diff --stat")
    for command in commands:
        output = run_bwrap(command_for_sandbox(command), tmp_path, lambda: False)
        assert sentinel not in output, command
        assert "PWNED" not in output, command
    diff = classify_command("git diff note.txt", sandbox_ready=True, workspace=tmp_path)
    assert diff.force_approval is True
    status = classify_command("git status", sandbox_ready=True, workspace=tmp_path)
    assert status.force_approval is False
    ran = execute_shell({"command": "git status"}, _ctx(tmp_path))
    assert sentinel not in ran
    assert "PWNED" not in ran

    config = tmp_path / ".git" / "config"
    config.write_text(
        config.read_text(encoding="utf-8") + "\n[core]\n\tfsmonitor = ./pwn.sh\n",
        encoding="utf-8",
    )
    for command in commands:
        prepared = classify_command(command, sandbox_ready=True, workspace=tmp_path)
        assert prepared.force_approval is True, command
        try:
            execute_shell({"command": command}, _ctx(tmp_path))
        except RuntimeError as exc:
            assert "not run" in str(exc)
        else:
            raise AssertionError(command)
        output = run_bwrap(command_for_sandbox(command), tmp_path, lambda: False)
        assert sentinel not in output, command
        assert "PWNED" not in output, command
    _note_live_bwrap("repo git config did not run")


def _asks(workspace: Path, command: str) -> bool:
    """True when the classifier itself refuses, before the name-only probe."""
    return not classify_shell(command, workspace=workspace).allowlisted


def _linked_worktree(tmp_path: Path) -> tuple[Path, Path]:
    main = tmp_path / "main"
    work = tmp_path / "wt"
    main.mkdir()
    (main / "note.txt").write_text("alpha\n", encoding="utf-8")
    _track_note(main)
    _git("worktree", "add", "-q", str(work), "HEAD", cwd=main)
    return main, work


def _worktree_git_dirs(work: Path) -> tuple[Path, Path]:
    text = (work / ".git").read_text(encoding="utf-8")
    raw = text.split(":", 1)[1].strip()
    gitdir = Path(raw)
    if not gitdir.is_absolute():
        gitdir = (work / gitdir).resolve()
    common_raw = (gitdir / "commondir").read_text(encoding="utf-8").strip()
    common = Path(common_raw)
    if not common.is_absolute():
        common = (gitdir / common).resolve()
    return gitdir, common


def _assert_not_run(workspace: Path, commands: tuple[str, ...], sentinel: str) -> None:
    for command in commands:
        assert _asks(workspace, command), command
        prepared = classify_command(command, sandbox_ready=True, workspace=workspace)
        assert prepared.force_approval is True, command
        try:
            execute_shell({"command": command}, _ctx(workspace))
        except RuntimeError as exc:
            assert "not run" in str(exc)
        else:
            raise AssertionError(command)
        output = run_bwrap(command_for_sandbox(command), workspace, lambda: False)
        assert sentinel not in output, command
        assert "PWNED" not in output, command


def test_linked_worktree_common_config_and_attributes_ask(tmp_path: Path):
    _main, work = _linked_worktree(tmp_path)
    gitdir, common = _worktree_git_dirs(work)
    assert _asks(work, "git status") is False
    assert _asks(work, "git diff --stat") is False

    (common / "info").mkdir(exist_ok=True)
    (common / "info" / "attributes").write_text("note.txt filter=x\n", encoding="utf-8")
    assert _asks(work, "git diff note.txt")
    assert _asks(work, "git diff --stat")
    assert _asks(work, "git status") is False
    (common / "info" / "attributes").unlink()

    (gitdir / "info").mkdir(exist_ok=True)
    (gitdir / "info" / "attributes").write_text("note.txt diff=leak\n", encoding="utf-8")
    assert _asks(work, "git diff note.txt")
    assert _asks(work, "git status") is False
    (gitdir / "info" / "attributes").unlink()

    (gitdir / "config").write_text('[filter "x"]\n\tclean = ./pwn.sh\n', encoding="utf-8")
    assert _asks(work, "git status")
    (gitdir / "config").unlink()
    assert _asks(work, "git status") is False

    config = common / "config"
    original = config.read_text(encoding="utf-8")
    config.write_text(original + '\n[filter "x"]\n\tclean = ./pwn.sh\n', encoding="utf-8")
    assert _asks(work, "git status")
    assert _asks(work, "git diff note.txt")
    assert _asks(work, "git diff --stat")
    config.write_text(original, encoding="utf-8")

    pointer = gitdir / "commondir"
    pointer.unlink()
    pointer.mkdir()
    assert _asks(work, "git status")


def test_worktree_config_and_attributes_file_ask(tmp_path: Path):
    (tmp_path / "note.txt").write_text("alpha\n", encoding="utf-8")
    _track_note(tmp_path)
    config = tmp_path / ".git" / "config"
    original = config.read_text(encoding="utf-8")
    assert _asks(tmp_path, "git status") is False

    worktree_config = tmp_path / ".git" / "config.worktree"
    worktree_config.write_text("# worktree\n", encoding="utf-8")
    assert _asks(tmp_path, "git status")
    assert _asks(tmp_path, "git diff --stat")
    worktree_config.unlink()
    assert _asks(tmp_path, "git status") is False

    config.write_text(
        original + "\n[extensions]\n\tworktreeConfig = true\n",
        encoding="utf-8",
    )
    assert _asks(tmp_path, "git status")
    config.write_text(original, encoding="utf-8")

    attrs = tmp_path / "attrs.txt"
    attrs.write_text("note.txt filter=x\n", encoding="utf-8")
    config.write_text(
        original + f"\n[core]\n\tattributesFile = {attrs}\n",
        encoding="utf-8",
    )
    assert _asks(tmp_path, "git diff note.txt")
    assert _asks(tmp_path, "git status")
    config.write_text(original, encoding="utf-8")
    assert _asks(tmp_path, "git status") is False


def test_unreadable_or_oversized_git_config_asks(tmp_path: Path, monkeypatch):
    (tmp_path / "note.txt").write_text("alpha\n", encoding="utf-8")
    _track_note(tmp_path)
    config = tmp_path / ".git" / "config"
    original = config.read_text(encoding="utf-8")
    real_read = Path.read_text

    def denied(self: Path, *args: object, **kwargs: object) -> str:
        if self.resolve() == config.resolve():
            raise PermissionError("denied")
        return real_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", denied)
    assert _asks(tmp_path, "git status")
    monkeypatch.setattr(Path, "read_text", real_read)

    config.write_bytes(b"x" * 1_000_001)
    assert _asks(tmp_path, "git status")
    config.write_text(original, encoding="utf-8")
    assert _asks(tmp_path, "git status") is False

    config.unlink()
    assert _asks(tmp_path, "git status") is False


def test_attr_source_pin_follows_git_version(monkeypatch):
    monkeypatch.setattr(
        "praxis_prime.tools.shellclass._git_supports_attr_source",
        lambda: True,
    )
    pinned = command_for_sandbox("git diff note.txt")
    assert "--attr-source=HEAD" in pinned
    assert "core.attributesFile=/dev/null" in pinned
    assert "--no-textconv" in pinned
    status = command_for_sandbox("git status")
    assert "--attr-source=HEAD" in status
    assert "--no-ext-diff" not in status
    assert "diff.ignoreSubmodules=all" in status
    assert "--ignore-submodules=all" in status
    assert "--ignore-submodules=all" in pinned
    logged = command_for_sandbox("git log")
    assert "diff.ignoreSubmodules=all" in logged
    assert "--ignore-submodules" not in logged

    monkeypatch.setattr(
        "praxis_prime.tools.shellclass._git_supports_attr_source",
        lambda: False,
    )
    plain = command_for_sandbox("git diff note.txt")
    assert "--attr-source" not in plain
    assert "core.attributesFile=/dev/null" not in plain
    assert "core.fsmonitor=false" in plain


def test_worktree_common_filter_does_not_run_inside_bwrap(tmp_path: Path):
    if not _live_bwrap():
        return
    sentinel = "SENTINEL-SECRET-VALUE"
    main = tmp_path / "main"
    work = tmp_path / "wt"
    main.mkdir()
    (main / "note.txt").write_text("alpha\n", encoding="utf-8")
    (main / "secrets.env").write_text(sentinel + "\n", encoding="utf-8")
    script = main / "pwn.sh"
    script.write_text("#!/bin/sh\necho PWNED\ncat secrets.env\n", encoding="utf-8")
    script.chmod(0o755)
    _git("init", "-q", cwd=main)
    _git("add", "--", "note.txt", "secrets.env", "pwn.sh", cwd=main)
    _git(
        "-c",
        "user.email=tester@example.com",
        "-c",
        "user.name=tester",
        "commit",
        "-q",
        "-m",
        "init",
        cwd=main,
    )
    _git("worktree", "add", "-q", str(work), "HEAD", cwd=main)
    (work / "note.txt").write_text("beta\n", encoding="utf-8")
    _gitdir, common = _worktree_git_dirs(work)
    config = common / "config"
    config.write_text(
        config.read_text(encoding="utf-8") + '\n[filter "x"]\n\tclean = ./pwn.sh\n',
        encoding="utf-8",
    )
    (common / "info").mkdir(exist_ok=True)
    (common / "info" / "attributes").write_text("note.txt filter=x\n", encoding="utf-8")
    _assert_not_run(work, ("git diff note.txt", "git diff --stat"), sentinel)
    _note_live_bwrap("worktree common config filter did not run")


def test_config_worktree_attributes_file_does_not_run_inside_bwrap(tmp_path: Path):
    if not _live_bwrap():
        return
    sentinel = "SENTINEL-SECRET-VALUE"
    (tmp_path / "note.txt").write_text("alpha\n", encoding="utf-8")
    (tmp_path / "secrets.env").write_text(sentinel + "\n", encoding="utf-8")
    script = tmp_path / "pwn.sh"
    script.write_text("#!/bin/sh\necho PWNED\ncat secrets.env\n", encoding="utf-8")
    script.chmod(0o755)
    attrs = tmp_path / "attrs.txt"
    attrs.write_text("note.txt filter=x\n", encoding="utf-8")
    _git("init", "-q", cwd=tmp_path)
    _git("add", "--", "note.txt", "secrets.env", "pwn.sh", "attrs.txt", cwd=tmp_path)
    _git(
        "-c",
        "user.email=tester@example.com",
        "-c",
        "user.name=tester",
        "commit",
        "-q",
        "-m",
        "init",
        cwd=tmp_path,
    )
    config = tmp_path / ".git" / "config"
    config.write_text(
        config.read_text(encoding="utf-8")
        + "\n[extensions]\n\tworktreeConfig = true\n"
        + f"[core]\n\tattributesFile = {attrs}\n",
        encoding="utf-8",
    )
    (tmp_path / ".git" / "config.worktree").write_text(
        '[filter "x"]\n\tclean = ./pwn.sh\n',
        encoding="utf-8",
    )
    (tmp_path / "note.txt").write_text("beta\n", encoding="utf-8")
    _assert_not_run(tmp_path, ("git diff note.txt", "git diff --stat"), sentinel)
    _note_live_bwrap("config.worktree attributes file did not run")


def test_submodule_metadata_asks(tmp_path: Path):
    (tmp_path / "note.txt").write_text("alpha\n", encoding="utf-8")
    _track_note(tmp_path)
    assert _asks(tmp_path, "git status") is False
    (tmp_path / ".gitmodules").write_text("[submodule \"sm\"]\n", encoding="utf-8")
    assert _asks(tmp_path, "git status")
    assert _asks(tmp_path, "git diff --stat")
    assert _asks(tmp_path, "git diff note.txt")
    (tmp_path / ".gitmodules").unlink()
    assert _asks(tmp_path, "git status") is False
    modules = tmp_path / ".git" / "modules"
    modules.mkdir()
    assert _asks(tmp_path, "git status")
    modules.rmdir()
    assert _asks(tmp_path, "git status") is False


def test_head_gitattributes_driver_asks(tmp_path: Path, monkeypatch):
    (tmp_path / "note.txt").write_text("alpha\n", encoding="utf-8")
    (tmp_path / ".gitattributes").write_text("note.txt filter=x\n", encoding="utf-8")
    nested = tmp_path / "sub"
    nested.mkdir()
    (nested / ".gitattributes").write_text("f.txt diff=leak\n", encoding="utf-8")
    _git("init", "-q", cwd=tmp_path)
    _git("add", "--", "note.txt", ".gitattributes", "sub/.gitattributes", cwd=tmp_path)
    _git(
        "-c",
        "user.email=tester@example.com",
        "-c",
        "user.name=tester",
        "commit",
        "-q",
        "-m",
        "init",
        cwd=tmp_path,
    )
    (tmp_path / ".gitattributes").unlink()
    (nested / ".gitattributes").unlink()
    monkeypatch.setattr(
        "praxis_prime.tools.shellclass._git_supports_attr_source",
        lambda: False,
    )
    assert _asks(tmp_path, "git status") is False
    monkeypatch.setattr(
        "praxis_prime.tools.shellclass._git_supports_attr_source",
        lambda: True,
    )
    assert _asks(tmp_path, "git status")
    assert _asks(tmp_path, "git diff note.txt")


def test_submodule_filter_does_not_run_inside_bwrap(tmp_path: Path):
    if not _live_bwrap():
        return
    sentinel = "SENTINEL-SECRET-VALUE"
    origin = tmp_path / "smrepo"
    super_repo = tmp_path / "super"
    origin.mkdir()
    (origin / "f.txt").write_text("aaaa\n", encoding="utf-8")
    _git("init", "-q", cwd=origin)
    _git("add", "--", "f.txt", cwd=origin)
    _git(
        "-c",
        "user.email=tester@example.com",
        "-c",
        "user.name=tester",
        "commit",
        "-q",
        "-m",
        "sm",
        cwd=origin,
    )
    super_repo.mkdir()
    (super_repo / "note.txt").write_text("alpha\n", encoding="utf-8")
    _git("init", "-q", cwd=super_repo)
    _git("add", "--", "note.txt", cwd=super_repo)
    _git(
        "-c",
        "user.email=tester@example.com",
        "-c",
        "user.name=tester",
        "commit",
        "-q",
        "-m",
        "init",
        cwd=super_repo,
    )
    _git(
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "-q",
        str(origin),
        "sm",
        cwd=super_repo,
    )
    _git(
        "-c",
        "user.email=tester@example.com",
        "-c",
        "user.name=tester",
        "commit",
        "-q",
        "-m",
        "add-sm",
        cwd=super_repo,
    )
    (super_repo / "secrets.env").write_text(sentinel + "\n", encoding="utf-8")
    script = super_repo / "sm" / "pwn.sh"
    script.write_text(
        "#!/bin/sh\necho PWNED >&2\ncat ../secrets.env >&2\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    module = super_repo / ".git" / "modules" / "sm"
    (module / "info").mkdir(exist_ok=True)
    config = module / "config"
    config.write_text(
        config.read_text(encoding="utf-8") + '\n[filter "x"]\n\tclean = ./pwn.sh\n',
        encoding="utf-8",
    )
    (module / "info" / "attributes").write_text("f.txt filter=x\n", encoding="utf-8")
    target = super_repo / "sm" / "f.txt"
    target.write_text("bbbb\n", encoding="utf-8")
    os.utime(target, (946684800, 946684800))
    assert _asks(super_repo, "git diff note.txt")
    _assert_not_run(super_repo, ("git status", "git diff --stat"), sentinel)
    _note_live_bwrap("submodule filter did not run")


def test_name_only_backstop_asks_when_the_probe_fails(tmp_path: Path, monkeypatch):
    (tmp_path / "note.txt").write_text("alpha\n", encoding="utf-8")

    def boom(*_args, **_kwargs):
        raise SandboxError("probe failed")

    monkeypatch.setattr("praxis_prime.tools.shell.run_bwrap_status", boom)
    prepared = classify_command("git diff note.txt", sandbox_ready=True, workspace=tmp_path)
    assert prepared.force_approval is True
    assert "approved files" in prepared.force_reason


def test_unapproved_delete_does_not_run_and_ro_bind_blocks_the_write(tmp_path: Path):
    target = tmp_path / "note.txt"
    target.write_text("safe\n", encoding="utf-8")
    try:
        execute_shell(
            {"command": "python3 -c 'import os; os.remove(\"note.txt\")'"},
            _ctx(tmp_path),
        )
    except RuntimeError as exc:
        assert "not run" in str(exc)
    else:
        raise AssertionError("unapproved delete ran")
    assert target.read_text(encoding="utf-8") == "safe\n"

    argv = build_bwrap_argv("python3 -c 'import os; os.remove(\"note.txt\")'", tmp_path)
    flag, source = _workspace_mount(argv)
    assert flag == "--ro-bind"
    assert source == str(tmp_path.resolve())
    assert "--bind" not in argv
    assert "--noprofile" in argv

    if not _live_bwrap():
        return
    status = run_bwrap_status(
        "python3 -c 'import os; os.remove(\"note.txt\")'",
        tmp_path,
        lambda: False,
    )
    assert status.code != 0
    assert "Read-only file system" in status.output
    assert target.read_text(encoding="utf-8") == "safe\n"
    _note_live_bwrap("read-only bind blocked the delete")


def test_approved_write_is_rw_only_for_that_worktree(tmp_path: Path):
    work = tmp_path / "worktree"
    main = tmp_path / "repo"
    work.mkdir()
    main.mkdir()
    target = work / "note.txt"
    target.write_text("safe\n", encoding="utf-8")

    argv = build_bwrap_argv(
        "python3 -c 'open(\"note.txt\",\"w\").write(\"changed\\n\")'",
        work,
        writable=True,
        scope=work,
        main_checkout=main,
    )
    flag, source = _workspace_mount(argv)
    assert flag == "--bind"
    assert source == str(work.resolve())

    for bad_cwd, bad_scope, checkout in (
        (Path.home(), Path.home(), None),
        (main, main, main),
        (work, main, main),
        (main, work, main),
    ):
        try:
            build_bwrap_argv(
                "rm note.txt",
                bad_cwd,
                writable=True,
                scope=bad_scope,
                main_checkout=checkout,
            )
        except SandboxError as exc:
            assert "not run" in str(exc)
        else:
            raise AssertionError(f"read-write bind was allowed for {bad_cwd}")

    if not _live_bwrap():
        return
    run_bwrap(
        "python3 -c 'open(\"note.txt\",\"w\").write(\"changed\\n\")'",
        work,
        lambda: False,
        writable=True,
        scope=work,
        main_checkout=main,
    )
    assert target.read_text(encoding="utf-8") == "changed\n"
    assert not (main / "note.txt").exists()
    _note_live_bwrap("approved write changed only the worktree")


def test_approved_write_does_not_mount_the_main_checkout(tmp_path: Path):
    main = tmp_path / "repo"
    main.mkdir()
    target = main / "note.txt"
    target.write_text("safe\n", encoding="utf-8")
    try:
        execute_shell(
            {"command": "rm -f note.txt"},
            ToolContext(
                cwd=str(main),
                cancelled=lambda: False,
                shell_approved=True,
                session_write_approved=True,
                write_scope=str(main),
                main_checkout=str(main),
            ),
        )
    except RuntimeError as exc:
        assert "not run" in str(exc)
    assert target.read_text(encoding="utf-8") == "safe\n"


def test_dial_modes_log_every_shell_decision_and_enforce_blocks_bypass(tmp_path: Path):
    db = StateDB(tmp_path / "prime.db")
    audit = AuditLog(db)
    command = "python3 -c 'import os; os.remove(\"note.txt\")'"
    ctx = PolicyContext(
        hook=HookPoint.H3_PRE_TOOL,
        tool="shell",
        risk=Risk.READ,
        sandboxed=True,
        force_approval=False,
        summary=command,
        arguments={"command": command},
    )
    try:
        for mode, dial in (("off", None), ("monitor", "monitor"), ("enforce", "enforce")):
            positions = default_positions()
            if dial is not None:
                positions["hipaa"] = dial
            engine = PolicyEngine(positions=positions, audit=audit)
            engine.session_id = mode
            verdict = engine.evaluate(ctx)
            assert verdict.decision == "ask", mode
            if mode == "enforce":
                assert "no bypass" in verdict.reason
            events = audit.for_session(mode)
            assert events, mode
            assert events[-1]["kind"] == "shell_policy"
            payload = events[-1]["payload"]
            assert payload["decision"] == "ask"
            assert payload["dial_mode"] == mode
            assert payload["mount"] == "ro"
            assert payload["allowlisted"] is False
            assert "os.remove" in payload["command"]
            if mode == "monitor":
                assert events[-1]["summary"].startswith("monitor:")
            if mode == "enforce":
                assert payload["bypass_blocked"] is True
        allowed = PolicyEngine(audit=audit)
        allowed.session_id = "allow"
        status = allowed.evaluate(
            PolicyContext(
                hook=HookPoint.H3_PRE_TOOL,
                tool="shell",
                sandboxed=True,
                summary="git status",
                arguments={"command": "git status"},
            )
        )
        assert status.decision == "allow"
        logged = audit.for_session("allow")
        assert logged[-1]["payload"]["allowlisted"] is True
        assert logged[-1]["payload"]["mount"] == "ro"
    finally:
        db.close()
