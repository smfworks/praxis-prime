"""Regression tests for issue #8: shell deletes and the read-write bind.

The old classifier treated a regex miss as READ and skipped approval inside
bubblewrap. The old launcher mounted the workspace with ``--bind``. Both
paths now fail closed.
"""

from __future__ import annotations

import os
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
from praxis_prime.tools.shellclass import classify_shell

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


def test_read_only_allowlist_skips_approval_inside_the_workspace(tmp_path: Path):
    (tmp_path / "note.txt").write_text("alpha\n", encoding="utf-8")
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
