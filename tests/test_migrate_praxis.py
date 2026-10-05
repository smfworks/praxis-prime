"""Import a synthetic SMF Praxis home. The source tree is only read."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import time
from pathlib import Path

import pytest

from praxis_prime.cli import main
from praxis_prime.migrate.apply import (
    MigrateError,
    migrate_from_praxis,
    render_summary,
    report_json,
)
from praxis_prime.migrate.source import file_sha256, source_fingerprint
from praxis_prime.profiles.home import ProfileHome, create_profile
from praxis_prime.profiles.migrate import MigrationBusy
from praxis_prime.state import StateDB

_OPENAI = "fixture-openai-key-value"
_CLOUD = "fixture-cloud-key-value"
_ENV = "fixture-env-anthropic-value"
_OUTSIDE = "SECRET-OUTSIDE-MARKER"
_ESC = "\x1b"


def _skill(name: str, description: str, body: str) -> str:
    return f"---\nname: {name}\ndescription: {description}\n---\n{body}\n"


def _pack(root: Path, name: str, vertical: str) -> None:
    root.mkdir(parents=True)
    (root / "pack.json").write_text(
        json.dumps(
            {
                "name": name,
                "version": "0.1.0",
                "vertical": vertical,
                "description": f"{name} fixture",
                "complianceMode": "enforced",
            }
        ),
        encoding="utf-8",
    )
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")


def _build(root: Path) -> None:
    """A small Praxis home using the hybridagent table shapes."""
    root.mkdir()
    database = sqlite3.connect(root / "praxis.db")
    database.executescript(
        """
        CREATE TABLE memory_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id TEXT NOT NULL DEFAULT '',
            tier TEXT NOT NULL,
            text TEXT NOT NULL,
            provenance TEXT NOT NULL DEFAULT 'agent',
            kind TEXT NOT NULL DEFAULT 'note',
            salience REAL NOT NULL DEFAULT 1.0,
            access_count INTEGER NOT NULL DEFAULT 0,
            last_access_ts REAL,
            expires_at REAL,
            ts REAL NOT NULL,
            bonus TEXT
        );
        CREATE TABLE vectors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ns TEXT NOT NULL,
            doc_id TEXT NOT NULL,
            chunk_idx INTEGER NOT NULL,
            text TEXT NOT NULL,
            provenance TEXT NOT NULL DEFAULT 'document',
            kind TEXT NOT NULL DEFAULT 'document',
            embedding BLOB NOT NULL,
            ts REAL NOT NULL
        );
        CREATE TABLE cron_jobs (
            job_id TEXT PRIMARY KEY,
            name TEXT NOT NULL DEFAULT '',
            goal TEXT NOT NULL,
            schedule TEXT NOT NULL,
            mode TEXT NOT NULL DEFAULT 'do',
            deliver TEXT NOT NULL DEFAULT 'local',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_ts REAL NOT NULL,
            updated_ts REAL NOT NULL
        );
        CREATE TABLE channel_threads (
            thread_key TEXT PRIMARY KEY,
            channel TEXT NOT NULL,
            chat_id TEXT NOT NULL,
            messages_json TEXT NOT NULL DEFAULT '[]',
            updated_ts REAL NOT NULL
        );
        CREATE TABLE skill_metadata (
            skill_name TEXT PRIMARY KEY,
            quarantined INTEGER NOT NULL DEFAULT 0,
            updated_ts REAL NOT NULL
        );
        CREATE TABLE compliance (
            name TEXT PRIMARY KEY,
            mode TEXT NOT NULL DEFAULT 'enforced',
            updated_ts REAL NOT NULL
        );
        CREATE TABLE board_cards (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL
        );
        CREATE TABLE "bad-name" (id INTEGER);
        """
    )
    now = time.time()
    rows = [
        ("", "durable", "The office opens at nine.", "fact", None, now),
        ("", "durable", "The office opens at nine.", "fact", None, now),
        ("", "durable", "Use the local model.", "decision", None, now),
        ("lab", "durable", "A note about the lab.", "note", None, now),
        ("", "episodic", "Talked about the schedule.", "note", None, now),
        ("", "episodic", "Short reminder.", "note", now + 86400 * 10, now),
        ("", "episodic", "Old reminder.", "note", now - 100, now),
        ("", "working", "scratch pad", "note", None, now),
        ("", "durable", "sk-abcdefghijklmnop", "fact", None, now),
        ("", "durable", f"Remember the bell {_ESC}[31m mark.", "note", None, now),
        ("../etc", "durable", "Path was odd.", "note", None, now),
        ("", "durable", "Prefer mornings.", "preference", None, now),
    ]
    database.executemany(
        """
        INSERT INTO memory_items (workspace_id, tier, text, kind, expires_at, ts, bonus)
        VALUES (?, ?, ?, ?, ?, ?, 'ignored')
        """,
        rows,
    )
    blob = b"\x00\x01"
    database.execute(
        """
        INSERT INTO vectors (ns, doc_id, chunk_idx, text, embedding, ts)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        ("docs", "supplies", 0, "A document chunk about supplies.", blob, now),
    )
    database.execute(
        """
        INSERT INTO vectors (ns, doc_id, chunk_idx, text, embedding, ts)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        ("docs", "lab", 0, "A note about the lab.", blob, now),
    )
    database.execute(
        """
        INSERT INTO cron_jobs (job_id, name, goal, schedule, deliver, created_ts, updated_ts)
        VALUES ('weekly', 'weekly', 'Send the weekly note', '15 9 * * 1', 'telegram', ?, ?)
        """,
        (now, now),
    )
    database.execute(
        """
        INSERT INTO cron_jobs (job_id, name, goal, schedule, deliver, created_ts, updated_ts)
        VALUES ('bad', 'bad', 'Do a thing', 'not a cron', 'local', ?, ?)
        """,
        (now, now),
    )
    database.execute(
        """
        INSERT INTO cron_jobs (job_id, name, goal, schedule, deliver, created_ts, updated_ts)
        VALUES ('empty', '', '', '0 0 * * *', 'local', ?, ?)
        """,
        (now, now),
    )
    messages = json.dumps(
        [
            {"role": "system", "content": "hidden"},
            {"role": "user", "content": f"Hello {_ESC}[2Jthere"},
            {"role": "assistant", "content": "Hi"},
        ]
    )
    database.execute(
        """
        INSERT INTO channel_threads (thread_key, channel, chat_id, messages_json, updated_ts)
        VALUES ('chat-1', 'telegram', '1', ?, ?)
        """,
        (messages, now),
    )
    database.execute(
        """
        INSERT INTO channel_threads (thread_key, channel, chat_id, messages_json, updated_ts)
        VALUES ('chat-2', 'telegram', '2', '{', ?)
        """,
        (now,),
    )
    database.execute(
        "INSERT INTO skill_metadata (skill_name, quarantined, updated_ts) VALUES (?, 0, ?)",
        ("good-skill", now),
    )
    database.execute(
        "INSERT INTO skill_metadata (skill_name, quarantined, updated_ts) VALUES (?, 1, ?)",
        ("locked-skill", now),
    )
    database.execute(
        "INSERT INTO compliance (name, mode, updated_ts) VALUES ('default', 'enforced', ?)",
        (now,),
    )
    database.execute("INSERT INTO board_cards (title) VALUES ('one'), ('two')")
    database.execute('INSERT INTO "bad-name" (id) VALUES (1)')
    database.commit()
    database.close()

    skills = root / "skills"
    good = skills / "good-skill"
    good.mkdir(parents=True)
    (good / "SKILL.md").write_text(
        _skill("good-skill", "A local note taker.", "Stay on this machine.\n"),
        encoding="utf-8",
    )
    script = good / "helper.sh"
    script.write_text("#!/bin/sh\necho nope\n", encoding="utf-8")
    os.chmod(script, 0o755)
    (good / "notes.md").write_text("keep this\n", encoding="utf-8")
    (good / "credentials.json").write_text('{"token":"skill-secret"}\n', encoding="utf-8")
    (good / "secrets.env").write_text("API_KEY=skill-secret\n", encoding="utf-8")
    (good / "cert.pem").write_text("-----BEGIN CERT-----\n", encoding="utf-8")
    (good / "id_ed25519").write_text("private-key\n", encoding="utf-8")
    outside = root.parent / "outside-secret"
    outside.mkdir()
    (outside / "secret.txt").write_text(_OUTSIDE, encoding="utf-8")
    (good / "escape.md").symlink_to(outside / "secret.txt")
    hostile = skills / "hostile-skill"
    hostile.mkdir()
    (hostile / "SKILL.md").write_text(
        _skill("hostile-skill", f"see the {_ESC} bell", f"Body {_ESC}[2J still data.\n"),
        encoding="utf-8",
    )
    locked = skills / "locked-skill"
    locked.mkdir()
    (locked / "SKILL.md").write_text(
        _skill("locked-skill", "Quarantined in the source.", "Do not load.\n"),
        encoding="utf-8",
    )
    broken = skills / "broken"
    broken.mkdir()
    (broken / "SKILL.md").write_text("no frontmatter\n", encoding="utf-8")
    (skills / "link-skill").symlink_to(outside, target_is_directory=True)

    _pack(root / "packs" / "homeschool", "homeschool", "homeschool")
    _pack(root / "packs" / "general", "general", "general")
    (root / "packs" / "loose").mkdir()
    (root / "praxis.json").write_text(
        json.dumps(
            {
                "configVersion": 1,
                "providers": {
                    "openai": {"keyRef": {"source": "auth-profile", "id": "openai"}},
                    "anthropic": {"keyRef": {"source": "env", "id": "ANTHROPIC_API_KEY"}},
                    "ollama-cloud": {"keyRef": {"source": "auth-profile", "id": "ollama-cloud"}},
                },
                "agents": {"defaults": {"model": "ollama:qwen3:8b"}},
            }
        ),
        encoding="utf-8",
    )
    auth = root / "auth-profiles.json"
    auth.write_text(
        json.dumps({"openai": {"apiKey": _OPENAI}, "ollama-cloud": {"apiKey": _CLOUD}}),
        encoding="utf-8",
    )
    os.chmod(auth, 0o600)


def _quiet() -> dict[str, bool]:
    return {"daemon_running": lambda: False}


def _import(source: Path, data: Path, config: Path, **kwargs: object):
    options = _quiet()
    options.update(kwargs)
    return migrate_from_praxis(source, data, config_dir=config, **options)  # type: ignore[arg-type]


def _printed(report: object) -> str:
    text = render_summary(report) + report_json(report)  # type: ignore[arg-type]
    assert _ESC not in text
    assert _OPENAI not in text
    assert _CLOUD not in text
    assert _ENV not in text
    assert _OUTSIDE not in text
    return text


def test_dry_run_plans_and_writes_nothing(tmp_path: Path) -> None:
    source = tmp_path / "praxis"
    _build(source)
    before = source_fingerprint(source)
    data = tmp_path / "data"
    report = _import(source, data, tmp_path / "config", dry_run=True)
    assert source_fingerprint(source) == before
    assert not data.exists()
    assert not (tmp_path / "config").exists()
    assert report.dry_run
    assert report.categories["memory"].imported == 10
    assert report.categories["memory"].skipped == 4
    assert report.categories["skills"].imported == 2
    assert report.categories["packs"].imported == 2
    assert report.categories["routines"].imported == 1
    assert report.categories["history"].imported == 1
    assert report.categories["settings"].imported == 0
    assert "secrets were not copied" in report.categories["settings"].reasons
    assert report.providers == ["anthropic", "ollama-cloud", "openai"]
    assert report.auth_profiles == ["ollama-cloud", "openai"]
    assert report.dials_to_monitor == ["ferpa", "coppa"]
    names = {str(row["name"]) for row in report.unknown_tables}
    assert "board_cards" in names
    assert "unnamed" in names
    assert "memory_items" not in names
    assert "sqlite_sequence" not in names
    text = _printed(report)
    assert "found 14" in text
    assert _OPENAI not in text


def test_import_is_idempotent_and_leaves_the_source_unchanged(tmp_path: Path) -> None:
    source = tmp_path / "praxis"
    _build(source)
    outside = tmp_path / "outside-secret" / "secret.txt"
    outside_before = (outside.stat().st_mtime_ns, outside.read_bytes())
    before = source_fingerprint(source)
    data = tmp_path / "data"
    config = tmp_path / "config"
    config.mkdir()
    (config / "config.toml").write_text(
        '[dials]\nhipaa = "enforce"\nferpa = "off"\n',
        encoding="utf-8",
    )
    home = create_profile(data, "work")
    policy = home.config_path.read_bytes()
    soul = home.soul_path.read_bytes()
    report = _import(source, data, config, profile="work")
    assert source_fingerprint(source) == before
    assert (outside.stat().st_mtime_ns, outside.read_bytes()) == outside_before
    assert not (source / "praxis.db-journal").exists()
    assert not (source / "praxis.db-wal").exists()
    assert home.config_path.read_bytes() == policy
    assert home.soul_path.read_bytes() == soul
    assert b"allow = []" in policy

    text = _printed(report)
    assert "compliance mode was not copied" in text
    assert "model was not selected" in text
    assert "delivery targets were not imported" in text
    assert report.categories["memory"].imported == 10
    assert report.dials_to_monitor == ["ferpa", "coppa"]

    db = StateDB(home.db_path)
    try:
        memory = db.conn.execute(
            "SELECT tier, scope, content, source, expires_at FROM memory_entries"
        ).fetchall()
        by_content = {row["content"]: row for row in memory}
        assert by_content["The office opens at nine."]["tier"] == "profile"
        assert by_content["The office opens at nine."]["scope"] == "global"
        assert by_content["The office opens at nine."]["source"] == "praxis"
        assert by_content["Use the local model."]["tier"] == "profile"
        assert by_content["Prefer mornings."]["tier"] == "profile"
        lab_rows = [row for row in memory if row["content"] == "A note about the lab."]
        assert {row["scope"] for row in lab_rows} == {"channel:praxis-lab", "global"}
        assert {row["tier"] for row in lab_rows} == {"semantic"}
        assert by_content["Path was odd."]["scope"] == "global"
        assert by_content["Talked about the schedule."]["tier"] == "episodic"
        assert by_content["Talked about the schedule."]["expires_at"]
        short = by_content["Short reminder."]["expires_at"]
        longer = by_content["Talked about the schedule."]["expires_at"]
        assert short < longer
        hostile = by_content[f"Remember the bell {_ESC}[31m mark."]
        assert _ESC in hostile["content"]
        assert len(memory) == 10
        routines = db.conn.execute("SELECT paused, deliver, prompt FROM routines").fetchall()
        assert len(routines) == 1
        assert routines[0]["paused"] == 1
        assert routines[0]["deliver"] == "none"
        assert routines[0]["prompt"] == "Send the weekly note"
        messages = db.conn.execute("SELECT role, content FROM messages ORDER BY id").fetchall()
        assert [row["role"] for row in messages] == ["user", "assistant"]
        assert _ESC not in messages[0]["content"]
        assert "\\x1b" in messages[0]["content"]
        provenance = db.conn.execute(
            """
            SELECT source, source_table, source_sha256
            FROM import_records WHERE source_table = 'memory_items'
            """
        ).fetchall()
        assert provenance
        assert {row["source"] for row in provenance} == {"praxis"}
        assert {row["source_sha256"] for row in provenance} == {file_sha256(source / "praxis.db")}
        audit = db.conn.execute(
            "SELECT kind, payload_json FROM audit_events WHERE kind = 'praxis.import'"
        ).fetchone()
        assert audit is not None
        assert _OPENAI not in audit["payload_json"]
        assert _ESC not in audit["payload_json"]
        dials = json.loads(
            db.conn.execute("SELECT positions_json FROM dial_positions WHERE id = 1").fetchone()[0]
        )
        assert dials["hipaa"] == "enforce"
        assert dials["ferpa"] == "monitor"
        assert dials["coppa"] == "monitor"
        changes = db.conn.execute(
            "SELECT payload_json FROM audit_events WHERE kind = 'dial_change'"
        ).fetchall()
        moved_dials: dict[str, object] = {}
        for event in changes:
            payload = json.loads(event["payload_json"])
            changed = payload.get("changed")
            if isinstance(changed, dict):
                moved_dials.update(changed)
        assert moved_dials["ferpa"] == {"from": "off", "to": "monitor"}
        assert moved_dials["coppa"] == {"from": "off", "to": "monitor"}
        assert "hipaa" not in moved_dials
    finally:
        db.close()

    skill = home.skills_dir / "good-skill"
    assert (skill / "SKILL.md").is_file()
    assert stat.S_IMODE((skill / "helper.sh").stat().st_mode) == 0o644
    assert (skill / "notes.md").read_text(encoding="utf-8") == "keep this\n"
    assert not (skill / "escape.md").exists()
    assert not (skill / "credentials.json").exists()
    assert not (skill / "secrets.env").exists()
    assert not (skill / "cert.pem").exists()
    assert not (skill / "id_ed25519").exists()
    assert (source / "skills" / "good-skill" / "credentials.json").is_file()
    assert any("Secret-named files" in note for note in report.notes)
    hostile_file = (home.skills_dir / "hostile-skill" / "SKILL.md").read_bytes()
    assert _ESC.encode() in hostile_file
    assert not (home.skills_dir / "locked-skill").exists()
    assert not (home.skills_dir / "link-skill").exists()
    assert (data / "vertical-packs" / "homeschool" / "pack.json").is_file()
    assert (data / "vertical-packs" / "general" / "pack.json").is_file()
    assert not (config / "secrets.env").exists()
    saved = (config / "config.toml").read_text(encoding="utf-8")
    assert 'hipaa = "enforce"' in saved
    assert 'ferpa = "monitor"' in saved
    assert 'coppa = "monitor"' in saved
    backups = list(config.glob("config.toml.bak-*"))
    assert backups
    assert any('ferpa = "off"' in item.read_text(encoding="utf-8") for item in backups)
    archive = Path(report.history_archive)
    assert stat.S_IMODE(archive.stat().st_mode) == 0o400
    assert stat.S_IMODE(archive.parent.stat().st_mode) == 0o700
    archive_text = archive.read_text(encoding="utf-8")
    assert _ESC.encode() not in archive.read_bytes()
    assert "\\u001b" not in archive_text
    assert "Hello" in archive_text
    summary = Path(report.summary_path).read_text(encoding="utf-8")
    assert _ESC not in summary
    assert _OPENAI not in summary

    pack_mtime = (data / "vertical-packs" / "homeschool" / "pack.json").stat().st_mtime_ns
    memory_count = 10
    again = _import(source, data, config, profile="work")
    assert again.categories["memory"].imported == 0
    assert again.categories["skills"].imported == 0
    assert again.categories["packs"].imported == 0
    assert "already imported" in again.categories["memory"].reasons
    assert (data / "vertical-packs" / "homeschool" / "pack.json").stat().st_mtime_ns == pack_mtime
    db = StateDB(home.db_path)
    try:
        count = db.conn.execute("SELECT COUNT(*) FROM memory_entries").fetchone()[0]
        dial_events = db.conn.execute(
            "SELECT COUNT(*) FROM audit_events WHERE kind = 'dial_change'"
        ).fetchone()[0]
    finally:
        db.close()
    assert count == memory_count
    assert dial_events == 1

    database = sqlite3.connect(source / "praxis.db")
    database.execute("UPDATE memory_items SET text = 'changed after import' WHERE id = 1")
    database.commit()
    database.close()
    after_edit = source_fingerprint(source)
    third = _import(source, data, config, profile="work")
    assert source_fingerprint(source) == after_edit
    assert third.categories["memory"].imported == 0
    db = StateDB(home.db_path)
    try:
        row = db.conn.execute(
            "SELECT content FROM memory_entries WHERE content = 'The office opens at nine.'"
        ).fetchone()
        changed = db.conn.execute(
            "SELECT content FROM memory_entries WHERE content = 'changed after import'"
        ).fetchone()
    finally:
        db.close()
    assert row is not None
    assert changed is None


def test_history_redacts_a_channel_thread_secret(tmp_path: Path) -> None:
    source = tmp_path / "praxis"
    source.mkdir()
    key = "sk-histsecretkeyvalue"
    ghp = "ghp_" + ("A" * 20)
    database = sqlite3.connect(source / "praxis.db")
    database.execute(
        """
        CREATE TABLE channel_threads (
            thread_key TEXT PRIMARY KEY,
            messages_json TEXT NOT NULL
        )
        """
    )
    payload = json.dumps(
        [
            {"role": "user", "content": f"token {key} and {ghp} {_ESC}]0;owned"},
            {"role": "assistant", "content": "ok"},
        ]
    )
    database.execute(
        "INSERT INTO channel_threads (thread_key, messages_json) VALUES ('thr', ?)",
        (payload,),
    )
    database.commit()
    database.close()
    report = _import(source, tmp_path / "data", tmp_path / "config", only={"history"})
    assert report.categories["history"].imported == 1
    assert report.history_archive
    home = ProfileHome(tmp_path / "data", "default")
    db = StateDB(home.db_path)
    try:
        stored = "\n".join(
            row["content"] for row in db.conn.execute("SELECT content FROM messages")
        )
        title = db.conn.execute("SELECT title FROM sessions").fetchone()["title"]
    finally:
        db.close()
    archive = Path(report.history_archive).read_text(encoding="utf-8")
    for blob in (stored, archive, title):
        assert key not in blob
        assert ghp not in blob
        assert _ESC not in blob
    assert "[redacted]" in stored
    assert "[redacted]" in archive
    assert "\\x1b" in stored
    assert "ok" in stored


def test_wal_rows_are_read_and_the_source_stays_unchanged(tmp_path: Path) -> None:
    source = tmp_path / "praxis"
    source.mkdir()
    db_path = source / "praxis.db"
    held = sqlite3.connect(db_path)
    held.execute("PRAGMA journal_mode=WAL")
    held.execute("PRAGMA wal_autocheckpoint=0")
    held.execute(
        """
        CREATE TABLE channel_threads (
            thread_key TEXT PRIMARY KEY,
            messages_json TEXT NOT NULL
        )
        """
    )
    held.execute(
        "INSERT INTO channel_threads VALUES ('kept', ?)",
        (json.dumps([{"role": "user", "content": "checkpointed"}]),),
    )
    held.commit()
    held.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    held.execute(
        "INSERT INTO channel_threads VALUES ('wal', ?)",
        (json.dumps([{"role": "user", "content": "only in the wal"}]),),
    )
    held.commit()
    assert (source / "praxis.db-wal").is_file()
    before = source_fingerprint(source)
    try:
        report = _import(source, tmp_path / "data", tmp_path / "config", only={"history"})
        assert source_fingerprint(source) == before
    finally:
        held.close()
    assert report.categories["history"].imported == 2
    home = ProfileHome(tmp_path / "data", "default")
    db = StateDB(home.db_path)
    try:
        stored = [row["content"] for row in db.conn.execute("SELECT content FROM messages")]
    finally:
        db.close()
    assert "only in the wal" in stored
    assert "checkpointed" in stored


def test_symlinked_source_is_refused(tmp_path: Path) -> None:
    source = tmp_path / "praxis"
    _build(source)
    link = tmp_path / "linked-praxis"
    link.symlink_to(source, target_is_directory=True)
    before = source_fingerprint(source)
    with pytest.raises(MigrateError, match="symlinked"):
        _import(link, tmp_path / "data", tmp_path / "config")
    assert source_fingerprint(source) == before
    assert not (tmp_path / "data").exists()


def test_only_memory_skips_skills_and_packs(tmp_path: Path) -> None:
    source = tmp_path / "praxis"
    _build(source)
    data = tmp_path / "data"
    report = _import(source, data, tmp_path / "config", only={"memory"})
    assert report.categories["memory"].imported == 10
    assert report.categories["skills"].imported == 0
    assert report.categories["packs"].imported == 0
    home = ProfileHome(data, "default")
    assert not any(home.skills_dir.iterdir())
    assert not (data / "vertical-packs").exists()


def test_include_secrets_writes_only_a_mapped_auth_profile_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "praxis"
    _build(source)
    monkeypatch.setenv("ANTHROPIC_API_KEY", _ENV)
    data = tmp_path / "data"
    config = tmp_path / "config"
    report = _import(source, data, config, include_secrets=True)
    _printed(report)
    secret_path = config / "secrets.env"
    mode = stat.S_IMODE(secret_path.stat().st_mode)
    assert mode == 0o600
    body = secret_path.read_text(encoding="utf-8")
    assert "PRAXIS_PRIME_OPENAI_API_KEY=" + _OPENAI in body
    assert _CLOUD not in body
    assert _ENV not in body
    assert "no secrets.env name for this provider" in report.categories["settings"].reasons
    assert report.categories["settings"].imported == 1


def test_default_import_does_not_copy_secrets(tmp_path: Path) -> None:
    source = tmp_path / "praxis"
    _build(source)
    config = tmp_path / "config"
    report = _import(source, data=tmp_path / "data", config=config)
    assert report.categories["settings"].imported == 0
    assert not (config / "secrets.env").exists()
    assert _OPENAI not in render_summary(report)


def test_daemon_and_lock_refuse_without_writing(tmp_path: Path) -> None:
    source = tmp_path / "praxis"
    _build(source)
    before = source_fingerprint(source)
    data = tmp_path / "data"
    with pytest.raises(MigrationBusy):
        _import(source, data, tmp_path / "config", daemon_running=lambda: True)
    assert source_fingerprint(source) == before
    assert not data.exists()

    home = create_profile(data, "default")
    policy = home.config_path.read_bytes()
    held = StateDB(home.db_path)
    try:
        with pytest.raises(MigrationBusy):
            _import(source, data, tmp_path / "config")
    finally:
        held.close()
    assert home.config_path.read_bytes() == policy
    assert source_fingerprint(source) == before
    probe = StateDB(home.db_path)
    try:
        count = probe.conn.execute("SELECT COUNT(*) FROM memory_entries").fetchone()[0]
    finally:
        probe.close()
    assert count == 0


def test_praxis_trigger_becomes_the_skill_description(tmp_path: Path) -> None:
    source = tmp_path / "praxis"
    source.mkdir()
    skill = source / "skills" / "lesson-plan"
    skill.mkdir(parents=True)
    original = (
        "---\n"
        "name: lesson-plan\n"
        "trigger: weekly schedule, multi-grade\n"
        "kind: skill\n"
        "---\n\n"
        "# lesson-plan\n\n"
        "Stay local.\n"
    )
    (skill / "SKILL.md").write_text(original, encoding="utf-8")
    before = (skill / "SKILL.md").read_bytes()
    report = _import(source, tmp_path / "data", tmp_path / "config", only={"skills"})
    assert report.categories["skills"].imported == 1
    assert (skill / "SKILL.md").read_bytes() == before
    copied = ProfileHome(tmp_path / "data", "default").skills_dir / "lesson-plan" / "SKILL.md"
    text = copied.read_text(encoding="utf-8")
    assert "description: weekly schedule, multi-grade" in text
    assert "trigger: weekly schedule, multi-grade" in text
    from praxis_prime.skills.format import parse_skill

    loaded = parse_skill(text, copied, "user")
    assert loaded.description == "weekly schedule, multi-grade"


def test_old_schema_and_unknown_shape_do_not_crash(tmp_path: Path) -> None:
    source = tmp_path / "old"
    source.mkdir()
    database = sqlite3.connect(source / "praxis.db")
    database.execute(
        """
        CREATE TABLE memory_items (
            id INTEGER PRIMARY KEY,
            tier TEXT NOT NULL,
            text TEXT NOT NULL,
            provenance TEXT NOT NULL DEFAULT 'agent',
            kind TEXT NOT NULL DEFAULT 'note',
            ts REAL NOT NULL
        )
        """
    )
    database.execute(
        """
        INSERT INTO memory_items (tier, text, kind, ts)
        VALUES ('durable', 'Early fact.', 'fact', 10)
        """
    )
    database.commit()
    database.close()
    report = _import(source, tmp_path / "data", tmp_path / "config")
    assert report.categories["memory"].imported == 1
    home = ProfileHome(tmp_path / "data", "default")
    db = StateDB(home.db_path)
    try:
        row = db.conn.execute("SELECT tier, content FROM memory_entries").fetchone()
    finally:
        db.close()
    assert row["tier"] == "profile"
    assert row["content"] == "Early fact."

    bare = tmp_path / "bare"
    bare.mkdir()
    database = sqlite3.connect(bare / "praxis.db")
    database.execute("CREATE TABLE memory_items (id INTEGER PRIMARY KEY, tier TEXT)")
    database.execute("INSERT INTO memory_items (tier) VALUES ('durable')")
    database.commit()
    database.close()
    skipped = _import(bare, tmp_path / "bare-data", tmp_path / "bare-config")
    assert "memory_items has no text column" in skipped.categories["memory"].reasons


def test_cli_dry_run_and_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    source = tmp_path / "praxis"
    _build(source)
    assert main(["migrate"]) == 2
    assert main(["migrate", "--from-praxis", "--only", "nope", "--source", str(source)]) == 2
    data = tmp_path / "data"
    config = tmp_path / "config"
    code = main(
        [
            "migrate",
            "--from-praxis",
            "--dry-run",
            "--json",
            "--source",
            str(source),
            "--data-dir",
            str(data),
            "--config-dir",
            str(config),
            "--only",
            "memory,skills",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert not data.exists()
    assert _ESC not in captured.out
    assert _OPENAI not in captured.out
    assert _OPENAI not in captured.err
    payload = json.loads(captured.out)
    assert payload["dry_run"] is True
    assert payload["categories"]["memory"]["imported"] == 10
    assert payload["categories"]["skills"]["imported"] == 2
    assert payload["categories"]["packs"]["found"] == 0
    code = main(
        [
            "migrate",
            "--from-praxis",
            "--source",
            str(tmp_path / "missing"),
            "--data-dir",
            str(data),
            "--config-dir",
            str(config),
        ]
    )
    assert code == 1
    assert not data.exists()


def test_parse_skill_rejects_a_name_past_64_characters(tmp_path: Path) -> None:
    from praxis_prime.skills.format import parse_skill

    path = tmp_path / "SKILL.md"
    accepted = "a" * 64
    loaded = parse_skill(
        f"---\nname: {accepted}\ndescription: ok\n---\nbody\n",
        path,
        "user",
    )
    assert loaded.name == accepted
    with pytest.raises(ValueError, match="name"):
        parse_skill(f"---\nname: {'a' * 65}\ndescription: ok\n---\nbody\n", path, "user")
