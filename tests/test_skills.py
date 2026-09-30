"""Skill discovery, progressive disclosure, and a gated git install."""

from __future__ import annotations

import sys
from pathlib import Path

from tests.fakes import ScriptedProvider

from praxis_prime.cli import main
from praxis_prime.loop.prompt import SYSTEM_PROMPT
from praxis_prime.router.types import AssistantFinal, ToolCall
from praxis_prime.runtime import build_runtime
from praxis_prime.skills.catalog import SkillCatalog
from praxis_prime.skills.install import install_skill


def test_project_skill_wins_and_the_index_hides_the_body(tmp_path: Path):
    bundled = tmp_path / "bundled"
    shared = tmp_path / "shared"
    user = tmp_path / "user"
    project = tmp_path / "project"
    _write(bundled, "notes", "bundled description", "BODY_BUNDLED")
    _write(shared, "notes", "shared description", "BODY_SHARED")
    _write(user, "notes", "user description", "BODY_USER")
    _write(project, "notes", "project description", "BODY_PROJECT")
    _write(shared, "only-shared", "shared only", "BODY_ONLY")
    catalog = SkillCatalog(project=project, user=user, shared=shared, bundled=bundled)
    skill = catalog.get("notes")
    assert skill is not None
    assert skill.source == "project"
    assert skill.description == "project description"
    index = catalog.index_text()
    assert "project description" in index
    assert "BODY_PROJECT" not in index
    assert "bundled description" not in index
    loaded = catalog.load_body("notes")
    assert "BODY_PROJECT" in loaded
    assert catalog.get("only-shared") is not None
    assert catalog.get("only-shared").source == "shared"


def test_use_skill_loads_the_body_and_does_not_fence_it(tmp_path: Path):
    provider = ScriptedProvider(
        [
            AssistantFinal(
                content="",
                tool_calls=(
                    ToolCall(id="c1", name="use_skill", arguments={"name": "morning-brief"}),
                ),
            ),
            AssistantFinal(content="Drafted."),
        ]
    )
    runtime = build_runtime(
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=tmp_path / "prime.db",
        cwd=tmp_path,
        providers={"ollama": provider},
    )
    try:
        runtime.memory.remember("User likes oolong")
        _session, loop = runtime.open_loop()
        list(loop.run_turn("Use the morning brief skill."))
        first = provider.requests[0]
        assert first.messages[0].content == SYSTEM_PROMPT
        visible = "\n".join(message.content for message in first.messages)
        assert "morning-brief:" in visible
        assert "User likes oolong" in visible
        body = "three bullets: calendar, unread messages, and one open loop"
        assert body not in visible
        tool_messages = [
            message for message in provider.requests[1].messages if message.role == "tool"
        ]
        assert tool_messages
        assert body in tool_messages[0].content
        assert "<<<UNTRUSTED" not in tool_messages[0].content
    finally:
        runtime.close()


def test_local_install_copies_scripts_and_git_install_is_gated(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    marker = tmp_path / "marker"
    (source / "SKILL.md").write_text(
        "---\nname: copied\ndescription: A local skill.\n---\n\nDo the thing.\n",
        encoding="utf-8",
    )
    (source / "install.sh").write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    dest = tmp_path / "skills"
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> None:
        calls.append(argv)
        target = Path(argv[-1])
        target.mkdir(parents=True)
        (target / "SKILL.md").write_text(
            "---\nname: cloned\ndescription: From git.\n---\n\nCloned body.\n",
            encoding="utf-8",
        )
        (target / "install.sh").write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")

    installed = install_skill(str(source), dest, approve=lambda _source: False, runner=runner)
    assert (installed / "install.sh").is_file()
    assert not marker.exists()
    assert calls == []

    try:
        install_skill(
            "https://example.invalid/skill.git",
            dest,
            approve=lambda _source: False,
            runner=runner,
        )
        raise AssertionError("git install without approval must fail")
    except PermissionError as exc:
        assert "approval" in str(exc)
    assert calls == []

    cloned = install_skill(
        "https://example.invalid/skill.git",
        dest,
        approve=lambda _source: True,
        runner=runner,
    )
    assert calls and calls[0][:4] == ["git", "clone", "--depth", "1"]
    assert "--" in calls[0]
    assert (cloned / "SKILL.md").is_file()
    assert (cloned / "install.sh").is_file()
    assert not marker.exists()


def test_skills_cli(tmp_path: Path, capsys, monkeypatch):
    cfg = tmp_path / "cfg"
    project = tmp_path / "project"
    cfg.mkdir()
    project.mkdir()
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    assert main(["skills", "list", "--config-dir", str(cfg), "--project", str(project)]) == 0
    listed = capsys.readouterr().out
    assert "morning-brief" in listed
    assert "project-notes" in listed
    assert "daily-standup" in listed
    assert main(["skills", "show", "morning-brief", "--config-dir", str(cfg)]) == 0
    shown = capsys.readouterr().out
    assert "three bullets: calendar, unread messages, and one open loop" in shown
    assert main(["skills", "new", "weekly-review", "--config-dir", str(cfg)]) == 0
    assert (cfg / "skills" / "weekly-review" / "SKILL.md").is_file()
    assert (
        main(
            [
                "skills",
                "install",
                "https://example.invalid/skill.git",
                "--config-dir",
                str(cfg),
            ]
        )
        == 1
    )
    assert "denied" in capsys.readouterr().err
    assert main(["skills", "remove", "weekly-review", "--config-dir", str(cfg)]) == 0
    assert not (cfg / "skills" / "weekly-review").exists()


def _write(root: Path, name: str, description: str, body: str) -> None:
    folder = root / name
    folder.mkdir(parents=True)
    (folder / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: {description}\n---\n\n{body}\n",
        encoding="utf-8",
    )
