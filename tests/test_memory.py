"""Memory tiers: dedupe, redaction, BM25, decay, and prompt injection."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from tests.fakes import ScriptedProvider

from praxis_prime.cli import main
from praxis_prime.clock import load_time
from praxis_prime.loop.prompt import SYSTEM_PROMPT
from praxis_prime.memory.embed import NullEmbedder, OllamaEmbedder, embedder_for
from praxis_prime.memory.tiers import MemoryStore, memory_channel, project_scope
from praxis_prime.memory.tools import forget_tool, recall_tool, remember_tool
from praxis_prime.policy.dials import default_positions
from praxis_prime.router.types import AssistantFinal
from praxis_prime.runtime import build_runtime
from praxis_prime.state import StateDB
from praxis_prime.tools.registry import ToolContext


class Clock:
    def __init__(self, moment: datetime) -> None:
        self.now = moment

    def __call__(self) -> datetime:
        return self.now


class FakeEmbedder:
    def embed(self, text: str) -> list[float] | None:
        if "alpha" in text or "nearest" in text:
            return [1.0, 0.0]
        if "beta" in text:
            return [0.0, 1.0]
        return None


def test_dedupe_redaction_and_dials_stay_off_by_default(tmp_path: Path):
    assert default_positions()["hipaa"] == "off"
    assert default_positions()["ferpa"] == "off"
    assert default_positions()["gdpr"] == "off"

    store = _store(tmp_path / "dedupe.db")
    first = store.remember("User likes oolong")
    second = store.remember("user   likes   oolong")
    assert first.id == second.id
    assert len(store.list_entries(tier="profile")) == 1

    secrets = _store(tmp_path / "secrets.db", redact="secrets")
    kept = secrets.remember("token=sk-testfakevalue12345678 and ada@example.com")
    assert "sk-" not in kept.content
    assert "[redacted]" in kept.content
    assert "ada@example.com" in kept.content
    plain_ssn = secrets.remember("ssn 123-45-6789")
    assert "123-45-6789" in plain_ssn.content

    pii = _store(tmp_path / "pii.db", redact="pii")
    hidden = pii.remember("mail ada@example.com")
    assert "ada@example.com" not in hidden.content

    hipaa = _store(tmp_path / "hipaa.db", redact="secrets", dials={"hipaa": "enforce"})
    redacted = hipaa.remember("ssn 123-45-6789")
    assert "123-45-6789" not in redacted.content
    assert "[redacted]" in redacted.content


def test_gdpr_enforce_expires_episodes_and_monitor_does_not(tmp_path: Path):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    clock = Clock(start)
    enforce = _store(
        tmp_path / "gdpr.db",
        dials={"gdpr": "enforce"},
        clock=clock,
        episodic_ttl_days=90,
    )
    episode = enforce.record_episode("sess-1", "hello", "world")
    assert episode is not None
    expires = load_time(episode.expires_at)
    assert expires - start == timedelta(days=30)
    clock.now = expires + timedelta(seconds=1)
    assert enforce.apply_retention() == 1
    assert enforce.list_entries(tier="episodic") == []

    monitor_clock = Clock(start)
    monitor = _store(
        tmp_path / "monitor.db",
        dials={"gdpr": "monitor"},
        clock=monitor_clock,
        episodic_ttl_days=90,
        redact="secrets",
    )
    kept = monitor.record_episode("sess-2", "hello", "world")
    assert kept is not None
    assert load_time(kept.expires_at) - start == timedelta(days=90)
    mailed = monitor.remember("ada@example.com likes tea", tier="semantic")
    assert "ada@example.com" not in mailed.content


def test_recency_decay_and_embedding_fallback(tmp_path: Path):
    now = datetime(2026, 6, 1, tzinfo=UTC)
    clock = Clock(now)
    store = _store(tmp_path / "decay.db", clock=clock, half_life_days=14)
    store.record_episode(
        "old",
        "deployed api",
        "done",
        when=now - timedelta(days=14),
    )
    store.record_episode("new", "deployed api", "done", when=now)
    hits = store.search("deployed api")
    assert [hit.entry.session_id for hit in hits[:2]] == ["new", "old"]
    assert hits[0].score > hits[1].score

    vectors = _store(tmp_path / "vectors.db", embedder=FakeEmbedder())
    vectors.remember("alpha widget", tier="semantic")
    vectors.remember("beta widget", tier="semantic")
    found = vectors.search("nearest")
    assert found
    assert found[0].entry.content == "alpha widget"
    assert all(hit.entry.content != "beta widget" for hit in found)

    assert isinstance(embedder_for("local:bge-small", "http://127.0.0.1:11434"), NullEmbedder)
    down = OllamaEmbedder("http://127.0.0.1:1", "bge-small", timeout=0.2)
    assert down.embed("hello") is None


def test_profile_cap_scopes_and_tools(tmp_path: Path):
    store = _store(tmp_path / "cap.db", profile_cap=20)
    for index in range(25):
        store.remember(f"fact {index:02d}")
    block = store.profile_block()
    lines = [line for line in block.splitlines() if line.startswith("- ")]
    assert len(lines) == 20
    assert "fact 24" in lines[0]

    cwd = tmp_path / "repo"
    cwd.mkdir()
    scoped = _store(tmp_path / "scopes.db", cwd=cwd)
    scoped.remember("global fact", scope="global")
    ctx = ToolContext(cwd=str(cwd), cancelled=lambda: False)
    remember_tool(scoped).execute({"content": "project fact", "scope": "project"}, ctx)
    token = memory_channel.set("telegram")
    try:
        remember_tool(scoped).execute({"content": "channel fact", "scope": "channel"}, ctx)
        recalled = recall_tool(scoped).execute({"query": "channel fact"}, ctx)
    finally:
        memory_channel.reset(token)
    assert project_scope(cwd) in {entry.scope for entry in scoped.list_entries()}
    assert any(entry.scope == "channel:telegram" for entry in scoped.list_entries())
    assert "channel fact" in recalled
    removed = forget_tool(scoped).execute({"match": "global fact"}, ctx)
    assert removed.startswith("Forgot 1")
    assert scoped.list_entries(scope="global") == []


def test_profile_and_recall_are_injected_without_changing_the_system_prompt(tmp_path: Path):
    provider = ScriptedProvider([AssistantFinal(content="Noted the billing api.")])
    runtime = build_runtime(
        env={},
        config_path=tmp_path / "missing.toml",
        data_path=tmp_path / "prime.db",
        cwd=tmp_path,
        providers={"ollama": provider},
    )
    try:
        runtime.memory.remember("User likes oolong")
        runtime.memory.remember("deployed the billing api", tier="semantic")
        _session, loop = runtime.open_loop(skill="morning-brief")
        list(loop.run_turn("What happened with the billing api?"))
        request = provider.requests[0]
        assert request.messages[0].content == SYSTEM_PROMPT
        user = request.messages[1].content
        assert "User likes oolong" in user
        assert "morning-brief:" in user
        assert "three bullets: calendar, unread messages, and one open loop" not in user
        assert "deployed the billing api" in user
        episodes = runtime.memory.list_entries(tier="episodic")
        assert episodes
        assert "billing api" in episodes[0].content
    finally:
        runtime.close()


def test_memory_cli(tmp_path: Path, capsys):
    data = tmp_path / "data"
    cfg = tmp_path / "cfg"
    data.mkdir()
    cfg.mkdir()
    db = StateDB(data / "prime.db")
    MemoryStore(db).remember("User likes oolong")
    db.close()
    base = ["--data-dir", str(data), "--config-dir", str(cfg)]
    assert main(["memory", "list", *base]) == 0
    assert "oolong" in capsys.readouterr().out
    assert main(["memory", "search", "oolong", *base]) == 0
    assert "oolong" in capsys.readouterr().out
    assert main(["memory", "forget", "--match", "oolong", *base]) == 0
    assert "forgot 1" in capsys.readouterr().out
    assert main(["memory", "export", *base]) == 0
    assert capsys.readouterr().out.strip() == "[]"


def _store(
    path: Path,
    *,
    redact: str = "secrets",
    dials: dict[str, str] | None = None,
    clock: Clock | None = None,
    embedder: object | None = None,
    profile_cap: int = 20,
    half_life_days: float = 14,
    episodic_ttl_days: int = 90,
    cwd: Path | None = None,
) -> MemoryStore:
    return MemoryStore(
        StateDB(path),
        redact=redact,
        dials=dials,
        clock=clock,
        embedder=embedder,
        profile_cap=profile_cap,
        half_life_days=half_life_days,
        episodic_ttl_days=episodic_ttl_days,
        cwd=cwd,
    )
