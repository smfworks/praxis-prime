"""Built-in SMF Praxis regulated packs: data only, offline install, dials off."""

from __future__ import annotations

import json
import subprocess
import tomllib
from pathlib import Path

import pytest

from praxis_prime.audit.log import AuditLog
from praxis_prime.cli import main
from praxis_prime.packs.catalog import PUBLIC_PACKS, SUGGESTED_DIALS, SUGGESTED_POSITION
from praxis_prime.packs.install import (
    builtin_pack_dir,
    bundled_regulated_root,
    install_pack,
)
from praxis_prime.packs.legacy import load_legacy_pack
from praxis_prime.policy.dials import default_positions
from praxis_prime.state import StateDB

_REPO = Path(__file__).resolve().parents[1]
_REGULATED = _REPO / "packs" / "regulated"
_FORBIDDEN = {".py", ".js", ".mjs", ".wasm", ".css", ".html"}
_COMMITS = {
    "behavioral_health": "c3d1cc1d22a38d5d62ff1c71e6b68355ac79611d",
    "medical_office": "e19290c689156bc3a25de6627058392ba577eb68",
    "law_firm": "afc2340578138de71b9af6dc935dc288cf068fbe",
    "school_system": "421a7f26432315779247913da6c5f5386984b268",
    "homeschool": "d2adbbf997e14b74854e64552af06832da274868",
    "forensic": "ab1797920350a4f4ae21297da8d9cd3c8c5a3c92",
}
_SKILL = {
    "law_firm": "conflict-check",
    "forensic": "forensic-evidence-review",
    "medical_office": "ambient-documentation",
    "homeschool": "annual-home-education-setup",
    "behavioral_health": "duty-to-warn-gate",
    "school_system": "sped-draft-not-decide",
}


def _forbid_git(monkeypatch: pytest.MonkeyPatch) -> None:
    real = subprocess.run

    def guarded(argv, *args, **kwargs):
        if isinstance(argv, (list, tuple)) and argv and str(argv[0]).endswith("git"):
            raise AssertionError(f"git subprocess: {argv}")
        return real(argv, *args, **kwargs)

    monkeypatch.setattr("praxis_prime.packs.legacy.subprocess.run", guarded)
    monkeypatch.setattr("praxis_prime.packs.install.subprocess.run", guarded)


def test_vendored_tree_is_data_only() -> None:
    assert _REGULATED.is_dir()
    found = sorted(path.name for path in _REGULATED.iterdir() if (path / "pack.json").is_file())
    assert found == sorted(_COMMITS)
    for path in _REGULATED.rglob("*"):
        if path.is_file():
            assert path.suffix.lower() not in _FORBIDDEN
    for name, commit in _COMMITS.items():
        pack_dir = _REGULATED / name
        license_text = (pack_dir / "LICENSE").read_text(encoding="utf-8")
        assert "MIT License" in license_text
        assert "Permission is hereby granted, free of charge" in license_text
        assert "Copyright (c) 2026 SMF Works" in license_text
        assert (pack_dir / "NOTICE").is_file()
        meta = tomllib.loads((pack_dir / "SOURCE.toml").read_text(encoding="utf-8"))
        assert meta["commit"] == commit
        assert len(meta["commit"]) == 40
        assert meta["license"] == "MIT"
        manifest = json.loads((pack_dir / "pack.json").read_text(encoding="utf-8"))
        assert "model" not in manifest
        assert "provider" not in manifest
        blob = (pack_dir / "pack.json").read_text(encoding="utf-8")
        blob += (pack_dir / "knowledge.md").read_text(encoding="utf-8")
        assert "ollama-cloud" not in blob
        assert "ollama" not in blob.lower()
        removed = meta["upstream_model_removed"]
        if name == "homeschool":
            assert removed == ""
        else:
            assert removed.startswith("ollama-cloud/")
            assert removed not in blob


def test_loader_reads_every_builtin_pack() -> None:
    root = bundled_regulated_root()
    assert root is not None
    assert root.resolve() == _REGULATED.resolve()
    for public in PUBLIC_PACKS:
        directory = builtin_pack_dir(public)
        assert directory is not None
        pack = load_legacy_pack(
            directory,
            wanted_name=public.pack_name,
            repo=public.repo,
            commit=_COMMITS[public.pack_name],
            source="built-in",
        )
        assert pack.name == public.pack_name
        assert pack.persona.strip()
        assert pack.knowledge and pack.knowledge[0].text.strip()
        assert pack.knowledge[0].read_only is True
        assert pack.skills
        assert _SKILL[pack.name] in {skill.name for skill in pack.skills}
        assert all(skill.description.strip() for skill in pack.skills)
        assert pack.selected_model is None
        assert pack.selected_provider is None
        assert pack.model_suggestion == ""
        assert pack.provider_suggestion == ""
        assert pack.provenance.license == "MIT"
        assert pack.provenance.commit == _COMMITS[pack.name]
        assert pack.suggested_dials == tuple(
            (dial, SUGGESTED_POSITION) for dial in SUGGESTED_DIALS.get(pack.name, ())
        )
        assert all(rule.applied is False for rule in pack.rules)
        assert pack.ignored_javascript == ()
        assert pack.python_modules == ()


def test_install_alias_is_offline_and_leaves_dials_off(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _forbid_git(monkeypatch)

    def runner(argv: list[str]) -> None:
        raise AssertionError(f"git runner: {argv}")

    data = tmp_path / "data"
    db = StateDB(data / "prime.db")
    try:
        audit = AuditLog(db)
        for public in PUBLIC_PACKS:
            installed = install_pack(public.key, data, audit=audit, git_runner=runner)
            pack = installed.pack
            assert pack.name == public.pack_name
            assert pack.provenance.commit == _COMMITS[pack.name]
            assert pack.provenance.repo == public.repo
            assert pack.provenance.license == "MIT"
            assert pack.selected_model is None
            assert pack.model_suggestion == ""
            assert all(rule.applied is False for rule in pack.rules)
            assert not list(installed.path.rglob("*.py"))
            assert not list(installed.path.rglob("*.js"))
        rows = db.conn.execute("SELECT kind, payload_json FROM audit_events ORDER BY id").fetchall()
        assert len(rows) == len(PUBLIC_PACKS)
        commits = set()
        for row in rows:
            assert row["kind"] == "pack.install"
            payload = json.loads(row["payload_json"])
            assert payload["license"] == "MIT"
            assert payload["commit"] in _COMMITS.values()
            assert payload["model_ignored"] == ""
            commits.add(payload["commit"])
        assert commits == set(_COMMITS.values())
        count = db.conn.execute("SELECT COUNT(*) FROM dial_positions").fetchone()[0]
        assert count == 0
    finally:
        db.close()
    assert not (data / "config.toml").exists()
    assert set(default_positions().values()) == {"off"}


def test_cli_lists_and_describes_builtin_packs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _forbid_git(monkeypatch)
    data = tmp_path / "data"
    base = ["--data-dir", str(data)]
    assert main(["packs", "list", *base]) == 0
    listed = capsys.readouterr().out
    assert "Built-in regulated packs:" in listed
    for public in PUBLIC_PACKS:
        assert public.key in listed
    assert listed.count("built in") >= len(PUBLIC_PACKS)
    assert main(["packs", "info", "legal", *base]) == 0
    info = capsys.readouterr().out
    assert "name: law_firm" in info
    assert _COMMITS["law_firm"] in info
    assert "selected model: none" in info
    assert "compliance mode applied: no" in info
    assert "ollama-cloud" not in info
    assert main(["packs", "install", "education", *base]) == 0
    installed = capsys.readouterr()
    assert "installed school_system" in installed.out
    assert "ollama-cloud" not in installed.out
    assert "ollama-cloud" not in installed.err
    assert "Ignored pack model pin" not in installed.err
    assert main(["packs", "list", *base]) == 0
    again = capsys.readouterr().out
    assert "education  school_system  MIT  built in, installed" in again
    assert not (data / "config.toml").exists()
    assert set(default_positions().values()) == {"off"}
