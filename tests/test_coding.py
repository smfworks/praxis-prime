"""Coding mode: instructions, worktrees, edits, hooks, and push gates."""

import json
import subprocess
from pathlib import Path

from tests.fakes import ScriptedProvider

from praxis_prime.approvals.gate import ApprovalDecision, ApprovalGate
from praxis_prime.cli import build_parser, main
from praxis_prime.coding.instructions import discover_instructions
from praxis_prime.coding.session import run_coding_task
from praxis_prime.coding.tools import (
    classify_run_command,
    classify_write,
    coding_registry,
    execute_edit_file,
    execute_glob,
    execute_grep,
)
from praxis_prime.loop.engine import AgentLoop
from praxis_prime.loop.events import StatusEvent
from praxis_prime.loop.prompt import SYSTEM_PROMPT
from praxis_prime.policy.engine import HookPoint, PolicyContext, PolicyEngine
from praxis_prime.repl import run_repl
from praxis_prime.router.router import ModelRouter
from praxis_prime.router.types import AssistantFinal, ModelRef, ToolCall
from praxis_prime.runtime import build_runtime
from praxis_prime.tools.registry import Risk, ToolContext
from praxis_prime.tools.shell import classify_command


def _init_repo(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=path, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=path,
        check=True,
        capture_output=True,
    )
    (path / "hello.txt").write_text("one\n", encoding="utf-8")
    subprocess.run(["git", "add", "hello.txt"], cwd=path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=path,
        check=True,
        capture_output=True,
    )


def _runtime(tmp_path: Path, repo: Path, replies: list[AssistantFinal]):
    provider = ScriptedProvider(replies)
    runtime = build_runtime(
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=tmp_path / "prime.db",
        cwd=repo,
        providers={"ollama": provider},
    )
    return runtime, provider


def _edit_reply(old: str, new: str) -> AssistantFinal:
    return AssistantFinal(
        content="",
        tool_calls=(
            ToolCall(
                id="c1",
                name="edit_file",
                arguments={"path": "hello.txt", "old_string": old, "new_string": new},
            ),
        ),
    )


def test_instruction_precedence_and_cap(tmp_path: Path):
    global_dir = tmp_path / "config"
    global_dir.mkdir()
    (global_dir / "AGENTS.md").write_text("GLOBAL\n", encoding="utf-8")
    (global_dir / "AGENTS.override.md").write_text("GLOBAL-OVERRIDE\n", encoding="utf-8")
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "AGENTS.md").write_text("ROOT-AGENTS\n", encoding="utf-8")
    (repo / "AGENTS.override.md").write_text("ROOT-OVERRIDE\n", encoding="utf-8")
    (repo / "CLAUDE.md").write_text("ROOT-CLAUDE\n", encoding="utf-8")
    cursor = repo / ".cursor" / "rules"
    cursor.mkdir(parents=True)
    (cursor / "always.mdc").write_text(
        "---\ndescription: always on\nalwaysApply: true\n---\nCURSOR-ALWAYS\n",
        encoding="utf-8",
    )
    (cursor / "py.mdc").write_text(
        "---\ndescription: python files\nglobs: *.py\nalwaysApply: false\n---\nCURSOR-PY\n",
        encoding="utf-8",
    )
    (repo / ".github").mkdir()
    (repo / ".github" / "copilot-instructions.md").write_text("COPILOT\n", encoding="utf-8")
    (repo / ".prime" / "rules").mkdir(parents=True)
    (repo / ".prime" / "rules" / "style.md").write_text("PRIME-RULE\n", encoding="utf-8")
    (repo / ".prime" / "environment.toml").write_text(
        'name = "demo"\napi_key = "should-not-appear"\n',
        encoding="utf-8",
    )
    (repo / "pkg" / "AGENTS.md").write_text("PKG-AGENTS\n", encoding="utf-8")
    (repo / "pkg" / "CLAUDE.md").write_text("PKG-CLAUDE\n", encoding="utf-8")

    bundle = discover_instructions(repo, cwd=repo / "pkg", global_dir=global_dir)
    text = bundle.text
    assert "ROOT-AGENTS" not in text
    assert not any(source.kind == "global AGENTS.md" for source in bundle.sources)
    assert any(source.kind == "global AGENTS.override.md" for source in bundle.sources)
    assert "should-not-appear" not in text
    assert "[redacted]" in text
    order = [
        "GLOBAL-OVERRIDE",
        "ROOT-OVERRIDE",
        "ROOT-CLAUDE",
        "CURSOR-ALWAYS",
        "Apply only when files match globs: *.py",
        "CURSOR-PY",
        "COPILOT",
        "PRIME-RULE",
        "PKG-AGENTS",
        "PKG-CLAUDE",
    ]
    positions = [text.index(marker) for marker in order]
    assert positions == sorted(positions)
    assert bundle.sources[0].kind.startswith("global")
    kinds = [source.kind for source in bundle.sources]
    assert kinds.index("AGENTS.override.md") < kinds.index("CLAUDE.md")

    huge = repo / "pkg" / "AGENTS.md"
    huge.write_text("Z" * 500, encoding="utf-8")
    capped = discover_instructions(repo, cwd=repo / "pkg", global_dir=global_dir, cap=80)
    assert capped.truncated
    assert "truncated" in capped.report
    assert len(capped.text.encode("utf-8")) <= 80


def test_worktree_leaves_the_checkout_until_accept(tmp_path: Path):
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "hello.txt").write_text("local edit\n", encoding="utf-8")
    (repo / "notes.md").write_text("keep me\n", encoding="utf-8")
    runtime, provider = _runtime(
        tmp_path,
        repo,
        [_edit_reply("one\n", "two\n"), AssistantFinal(content="edited the greeting")],
    )
    try:
        result = run_coding_task(
            "change hello",
            runtime,
            disposition="keep",
            global_dir=tmp_path / "no-global",
        )
    finally:
        runtime.close()
    assert (repo / "hello.txt").read_text(encoding="utf-8") == "local edit\n"
    added = next(
        command for command in result.commands if "worktree" in command and "add" in command
    )
    worktree_path = Path(added[-2]).resolve()
    assert not worktree_path.is_relative_to(repo.resolve())
    assert (repo / "notes.md").read_text(encoding="utf-8") == "keep me\n"
    assert result.disposition == "keep"
    assert result.branch.startswith("prime/")
    shown = subprocess.run(
        ["git", "-C", str(repo), "show", f"{result.branch}:hello.txt"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert shown.stdout == "two\n"
    assert all("push" != arg for command in result.commands for arg in command)
    assert provider.requests
    joined = provider.requests[0].messages[-1].content
    assert "change hello" in joined
    assert "hello.txt" in joined
    assert provider.requests[0].messages[0].content == SYSTEM_PROMPT


def test_accept_merges_and_discard_deletes_the_branch(tmp_path: Path):
    repo = tmp_path / "repo"
    _init_repo(repo)
    runtime, _provider = _runtime(
        tmp_path,
        repo,
        [_edit_reply("one\n", "two\n"), AssistantFinal(content="done")],
    )
    try:
        accepted = run_coding_task(
            "change hello",
            runtime,
            disposition="accept",
            global_dir=tmp_path / "no-global",
        )
    finally:
        runtime.close()
    assert (repo / "hello.txt").read_text(encoding="utf-8") == "two\n"
    assert all(arg != "push" for command in accepted.commands for arg in command)
    upstream = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--abbrev-ref", "@{upstream}"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert upstream.returncode != 0

    runtime, _provider = _runtime(
        tmp_path,
        repo,
        [_edit_reply("two\n", "three\n"), AssistantFinal(content="again")],
    )
    try:
        discarded = run_coding_task(
            "another change",
            runtime,
            disposition="discard",
            global_dir=tmp_path / "no-global",
        )
    finally:
        runtime.close()
    assert (repo / "hello.txt").read_text(encoding="utf-8") == "two\n"
    ref = f"refs/heads/{discarded.branch}"
    exists = subprocess.run(
        ["git", "-C", str(repo), "show-ref", "--verify", "--quiet", ref],
        check=False,
    )
    assert exists.returncode != 0


def test_edit_file_requires_one_exact_match(tmp_path: Path):
    target = tmp_path / "hello.txt"
    target.write_text("alpha\nbeta\nalpha\n", encoding="utf-8")
    ctx = ToolContext(cwd=str(tmp_path), cancelled=lambda: False)
    try:
        execute_edit_file(
            {"path": "hello.txt", "old_string": "alpha\n", "new_string": "gamma\n"},
            ctx,
        )
    except ValueError as exc:
        message = str(exc)
    else:
        raise AssertionError("ambiguous edit was applied")
    assert "matched 2 times" in message
    assert "not modified" in message
    assert target.read_text(encoding="utf-8") == "alpha\nbeta\nalpha\n"

    try:
        execute_edit_file(
            {"path": "hello.txt", "old_string": "missing", "new_string": "nope"},
            ctx,
        )
    except ValueError as exc:
        missing = str(exc)
    else:
        raise AssertionError("missing edit was applied")
    assert "not found" in missing
    assert "not modified" in missing
    assert target.read_text(encoding="utf-8") == "alpha\nbeta\nalpha\n"

    result = execute_edit_file(
        {"path": "hello.txt", "old_string": "beta\n", "new_string": "BETA\n"},
        ctx,
    )
    assert "edited" in result
    assert target.read_text(encoding="utf-8") == "alpha\nBETA\nalpha\n"


def test_hook_blocks_a_tool_before_it_writes(tmp_path: Path):
    repo = tmp_path / "repo"
    _init_repo(repo)
    prime = repo / ".prime"
    prime.mkdir()
    (prime / "hooks.toml").write_text(
        "\n".join(
            [
                "[[hook]]",
                'event = "PreToolUse"',
                'matcher = "write_file"',
                'command = "python3 -c \'import sys; print(\\"blocked-by-hook\\"); sys.exit(2)\'"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    reply = AssistantFinal(
        content="",
        tool_calls=(
            ToolCall(
                id="c1",
                name="write_file",
                arguments={"path": "hello.txt", "content": "hacked\n"},
            ),
        ),
    )
    runtime, provider = _runtime(tmp_path, repo, [reply, AssistantFinal(content="stopped")])
    calls: list[str] = []

    def spy(*_args, **_kwargs):
        calls.append("ran")
        return "should-not-run"

    try:
        result = run_coding_task(
            "overwrite hello",
            runtime,
            disposition="keep",
            global_dir=tmp_path / "no-global",
        )
    finally:
        runtime.close()
    assert (repo / "hello.txt").read_text(encoding="utf-8") == "one\n"
    tool_message = provider.requests[1].messages[-1].content
    assert "Hook blocked" in tool_message
    assert "blocked-by-hook" in tool_message
    assert "hacked" not in (repo / "hello.txt").read_text(encoding="utf-8")
    assert result.disposition == "keep"
    assert calls == []


def test_push_force_and_tracked_delete_always_ask(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    _init_repo(repo)
    calls: list[str] = []

    def spy(*_args, **_kwargs):
        calls.append("ran")
        return "should-not-run"

    monkeypatch.setattr("praxis_prime.tools.shell.run_bwrap", spy)
    monkeypatch.setattr("praxis_prime.tools.shell.run_host_shell", spy)
    monkeypatch.setattr("praxis_prime.tools.shell.bwrap_available", lambda: True)

    cases = {
        "git push origin main": Risk.SEND,
        "git push --force": Risk.DESTRUCTIVE,
        "git push -f": Risk.DESTRUCTIVE,
        "git reset --hard HEAD": Risk.DESTRUCTIVE,
        "git rm hello.txt": Risk.DESTRUCTIVE,
        "rm hello.txt": Risk.DESTRUCTIVE,
    }
    policy = PolicyEngine()
    for command, risk in cases.items():
        prepared = classify_run_command({"command": command}, root=repo, sandbox_ready=True)
        assert prepared.risk == risk
        assert prepared.force_approval is True
        for mode in ("ask", "full"):
            verdict = policy.evaluate(
                PolicyContext(
                    hook=HookPoint.H3_PRE_TOOL,
                    tool="run_command",
                    risk=prepared.risk,
                    sandboxed=prepared.sandboxed,
                    force_approval=prepared.force_approval,
                    force_reason=prepared.force_reason,
                    mode=mode,
                    summary=prepared.summary,
                )
            )
            assert verdict.decision == "ask", command

    outside = classify_write({"path": str(tmp_path / "outside.txt"), "content": "x"}, root=repo)
    assert outside.force_approval is True
    assert outside.risk == Risk.DESTRUCTIVE
    outside_verdict = policy.evaluate(
        PolicyContext(
            hook=HookPoint.H3_PRE_TOOL,
            tool="write_file",
            risk=outside.risk,
            sandboxed=outside.sandboxed,
            force_approval=outside.force_approval,
            force_reason=outside.force_reason,
            mode="ask",
            summary=outside.summary,
        )
    )
    assert outside_verdict.decision == "ask"
    inside = classify_write({"path": "hello.txt", "content": "x"}, root=repo)
    assert inside.risk == Risk.DRAFT
    assert inside.force_approval is False
    protected = classify_write({"path": "AGENTS.md", "content": "x"}, root=repo)
    assert protected.force_approval is True

    provider = ScriptedProvider(
        [
            AssistantFinal(
                content="",
                tool_calls=(
                    ToolCall(id="c1", name="run_command", arguments={"command": "git push"}),
                ),
            ),
            AssistantFinal(content="did not push"),
        ]
    )
    loop = AgentLoop(
        router=ModelRouter([ModelRef("ollama", "fake")], {"ollama": provider}),
        registry=coding_registry(repo),
        policy=PolicyEngine(),
        gate=ApprovalGate(None),
        cwd=repo,
        max_iterations=4,
        mode="full",
    )
    events = list(loop.run_turn("push it"))
    assert calls == []
    denied = [
        event
        for event in events
        if isinstance(event, StatusEvent) and "approval denied" in event.detail
    ]
    assert denied
    shell_push = classify_command("git push", sandbox_ready=True)
    assert shell_push.risk == Risk.SEND
    assert shell_push.force_approval is True


def test_coding_session_write_grant_is_explicit(tmp_path: Path):
    repo = tmp_path / "repo"
    _init_repo(repo)
    denied, _provider = _runtime(
        tmp_path,
        repo,
        [_edit_reply("one\n", "two\n"), AssistantFinal(content="edited")],
    )
    try:
        run_coding_task(
            "change hello",
            denied,
            disposition="keep",
            global_dir=tmp_path / "no-global",
        )
        rows = denied.db.conn.execute(
            "SELECT payload_json FROM audit_events WHERE kind = 'shell_policy'"
        ).fetchall()
    finally:
        denied.close()
    assert rows
    payload = json.loads(rows[0]["payload_json"])
    assert payload["tool"] == "coding_session"
    assert payload["decision"] == "deny"
    assert payload["mount"] == "ro"
    assert Path(payload["worktree"]) != Path(payload["repo"])

    def allow_session(request):
        assert request.tool == "coding_session"
        assert request.arguments["worktree"] != request.arguments["repo"]
        return ApprovalDecision.ALLOW_ONCE

    allowed = build_runtime(
        env={},
        config_path=tmp_path / "missing-allow.toml",
        data_path=tmp_path / "allowed.db",
        cwd=repo,
        providers={"ollama": ScriptedProvider([AssistantFinal(content="done")])},
        approver=allow_session,
    )
    try:
        run_coding_task(
            "look only",
            allowed,
            disposition="keep",
            global_dir=tmp_path / "no-global-2",
        )
        rows = allowed.db.conn.execute(
            "SELECT payload_json FROM audit_events WHERE kind = 'shell_policy'"
        ).fetchall()
    finally:
        allowed.close()
    grant = json.loads(rows[0]["payload_json"])
    assert grant["decision"] == "allow"
    assert grant["mount"] == "rw"
    assert Path(grant["worktree"]) != repo.resolve()
    assert Path(grant["repo"]) == repo.resolve()


def test_grep_and_glob_see_the_worktree(tmp_path: Path):
    (tmp_path / "hello.txt").write_text("alpha beta\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('alpha')\n", encoding="utf-8")
    ctx = ToolContext(cwd=str(tmp_path), cancelled=lambda: False)
    found = execute_grep({"pattern": "alpha", "path": "."}, ctx)
    assert "hello.txt" in found
    listed = execute_glob({"pattern": "**/*.py", "path": "."}, ctx)
    assert "src/app.py" in listed


def test_code_command_requires_a_git_repo(tmp_path: Path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert "code" in build_parser().format_help()
    assert main(["code", "--discard", "do something"]) == 2
    assert "not a git repository" in capsys.readouterr().err


def test_chat_code_command_uses_a_worktree(tmp_path: Path):
    repo = tmp_path / "repo"
    _init_repo(repo)
    runtime, _provider = _runtime(
        tmp_path,
        repo,
        [_edit_reply("one\n", "two\n"), AssistantFinal(content="done")],
    )
    lines = iter(["/code", "/code change hello", "k", "/quit"])

    def read_line(prompt: str) -> str:
        del prompt
        return next(lines)

    chunks: list[str] = []
    try:
        code = run_repl(runtime, read_line=read_line, write=chunks.append, color=False)
    finally:
        runtime.close()
    text = "".join(chunks)
    assert code == 0
    assert "Usage: /code" in text
    assert "Kept branch" in text
    assert (repo / "hello.txt").read_text(encoding="utf-8") == "one\n"
