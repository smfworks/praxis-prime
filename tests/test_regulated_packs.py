"""Built-in SMF Praxis regulated packs: data only, offline install, dials off."""

from __future__ import annotations

import json
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from praxis_prime.audit.log import AuditLog
from praxis_prime.cli import main
from praxis_prime.compliance.packs import bundled_pack_dir
from praxis_prime.packs.catalog import PUBLIC_PACKS, SUGGESTED_DIALS, SUGGESTED_POSITION
from praxis_prime.packs.cli import _format_info
from praxis_prime.packs.install import (
    _source_regulated_root,
    builtin_pack_dir,
    bundled_commit,
    bundled_regulated_root,
    install_pack,
)
from praxis_prime.packs.legacy import PackError, load_legacy_pack
from praxis_prime.paths import source_checkout_root
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


def _project_toml(name: str) -> str:
    return f'[project]\nname = "{name}"\n'


def _write_project(directory: Path, name: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "pyproject.toml").write_text(_project_toml(name), encoding="utf-8")


def _touch_start(directory: Path) -> Path:
    start = directory / "packages" / "prime-core" / "praxis_prime" / "install.py"
    start.parent.mkdir(parents=True, exist_ok=True)
    start.write_text("# start\n", encoding="utf-8")
    return start


def test_source_lookup_ignores_a_decoy_above_the_checkout(tmp_path: Path) -> None:
    decoy = tmp_path / "decoy"
    regulated = decoy / "packs" / "regulated" / "x"
    regulated.mkdir(parents=True)
    (regulated / "pack.json").write_text("{}\n", encoding="utf-8")
    compliance = decoy / "packs" / "compliance"
    compliance.mkdir(parents=True)
    (compliance / "a.toml").write_text('id = "a"\n', encoding="utf-8")
    repo = decoy / "repo"
    _write_project(repo, "praxis-prime")
    start = _touch_start(repo)
    assert source_checkout_root(start) == repo.resolve()
    assert _source_regulated_root(start) is None
    with pytest.raises(FileNotFoundError, match="packs/compliance"):
        bundled_pack_dir(start)


def test_source_lookup_skips_a_different_project_name(tmp_path: Path) -> None:
    above = tmp_path / "packs" / "regulated" / "x"
    above.mkdir(parents=True)
    (above / "pack.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "packs" / "compliance").mkdir(parents=True)
    (tmp_path / "packs" / "compliance" / "a.toml").write_text('id = "above"\n', encoding="utf-8")

    root = tmp_path / "repo"
    _write_project(root, "praxis-prime")
    real_regulated = root / "packs" / "regulated" / "law_firm"
    real_regulated.mkdir(parents=True)
    (real_regulated / "pack.json").write_text('{"name":"law_firm"}\n', encoding="utf-8")
    real_compliance = root / "packs" / "compliance"
    real_compliance.mkdir()
    (real_compliance / "hipaa.toml").write_text('id = "hipaa"\n', encoding="utf-8")

    nested = root / "nested"
    _write_project(nested, "other-project")
    decoy = nested / "packs" / "regulated" / "x"
    decoy.mkdir(parents=True)
    (decoy / "pack.json").write_text("{}\n", encoding="utf-8")
    (nested / "packs" / "compliance").mkdir(parents=True)
    (nested / "packs" / "compliance" / "a.toml").write_text('id = "nested"\n', encoding="utf-8")
    start = _touch_start(nested)

    assert source_checkout_root(start) == root.resolve()
    found = _source_regulated_root(start)
    assert found is not None
    assert found.resolve() == (root / "packs" / "regulated").resolve()
    assert bundled_pack_dir(start).resolve() == real_compliance.resolve()


def test_source_lookup_without_a_praxis_prime_pyproject(tmp_path: Path) -> None:
    root = tmp_path / "loose"
    _write_project(root, "other-project")
    decoy = root / "packs" / "regulated" / "x"
    decoy.mkdir(parents=True)
    (decoy / "pack.json").write_text("{}\n", encoding="utf-8")
    (root / "packs" / "compliance").mkdir(parents=True)
    (root / "packs" / "compliance" / "a.toml").write_text('id = "a"\n', encoding="utf-8")
    start = _touch_start(root)
    assert source_checkout_root(start) is None
    assert _source_regulated_root(start) is None
    with pytest.raises(FileNotFoundError, match="packs/compliance"):
        bundled_pack_dir(start)


def test_symlinked_pyproject_is_not_the_checkout_root(tmp_path: Path) -> None:
    payload = tmp_path / "payload.toml"
    payload.write_text(_project_toml("praxis-prime"), encoding="utf-8")
    linked = tmp_path / "linked"
    linked.mkdir()
    (linked / "pyproject.toml").symlink_to(payload)
    decoy = linked / "packs" / "regulated" / "x"
    decoy.mkdir(parents=True)
    (decoy / "pack.json").write_text("{}\n", encoding="utf-8")
    start = _touch_start(linked)
    assert source_checkout_root(start) is None
    assert _source_regulated_root(start) is None


def test_real_checkout_resolves_regulated_and_compliance_packs() -> None:
    assert source_checkout_root(Path(__file__)) == _REPO
    regulated = _source_regulated_root(Path(__file__))
    assert regulated is not None
    assert regulated.resolve() == _REGULATED.resolve()
    checkout = bundled_regulated_root()
    assert checkout is not None
    assert checkout.resolve() == _REGULATED.resolve()
    compliance = bundled_pack_dir()
    assert compliance.resolve() == (_REPO / "packs" / "compliance").resolve()
    assert any(compliance.glob("*.toml"))


def test_catalog_name_beats_a_local_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    git_calls: list[list[str]] = []
    real_run = subprocess.run

    def guarded(argv, *args, **kwargs):
        if isinstance(argv, (list, tuple)) and argv and str(argv[0]).endswith("git"):
            git_calls.append([str(part) for part in argv])
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr("praxis_prime.packs.legacy.subprocess.run", guarded)
    monkeypatch.setattr("praxis_prime.packs.install.subprocess.run", guarded)
    local = tmp_path / "legal"
    local.mkdir()
    (local / "pack.json").write_text(
        json.dumps(
            {
                "name": "not_law_firm",
                "version": "9.9.9",
                "description": "A local folder that must not win over the catalog name.",
                "systemPrompt": "Stay on this machine.",
            }
        ),
        encoding="utf-8",
    )
    (local / "knowledge.md").write_text("local notes\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    def runner(argv: list[str]) -> None:
        raise AssertionError(f"git runner: {argv}")

    data = tmp_path / "data"
    installed = install_pack("legal", data, git_runner=runner)
    assert installed.pack.name == "law_firm"
    assert installed.pack.provenance.repo == "https://github.com/smfworks/smf-praxis-legal.git"
    assert installed.pack.provenance.commit == _COMMITS["law_firm"]
    assert len(installed.pack.provenance.commit) == 40
    assert git_calls == []

    local_installed = install_pack("./legal", data)
    assert local_installed.pack.name == "not_law_firm"
    assert (local_installed.path / "pack.json").is_file()
    assert "not_law_firm" in (local_installed.path / "pack.json").read_text(encoding="utf-8")


def _break_source_toml(pack: Path, kind: str) -> None:
    path = pack / "SOURCE.toml"
    if kind == "missing":
        path.unlink()
    elif kind == "invalid":
        path.write_text("commit = [\n", encoding="utf-8")
    elif kind == "short":
        path.write_text('commit = "abc"\n', encoding="utf-8")
    elif kind == "symlink":
        path.unlink()
        path.symlink_to(pack / "pack.json")
    else:
        raise AssertionError(kind)


def test_bundled_commit_refuses_a_symlink_when_the_precheck_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The read itself must refuse the symlink, not only ``Path.is_symlink``."""
    pack = tmp_path / "law_firm"
    pack.mkdir()
    commit = "a" * 40
    target = tmp_path / "real.toml"
    target.write_text(f'commit = "{commit}"\n', encoding="utf-8")
    assert tomllib.loads(target.read_text(encoding="utf-8"))["commit"] == commit
    link = pack / "SOURCE.toml"
    link.symlink_to(target)
    real_is_symlink = Path.is_symlink

    def hide_this_link(self: Path) -> bool:
        if self == link:
            return False
        return real_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", hide_this_link)
    with pytest.raises(PackError, match="SOURCE.toml") as caught:
        bundled_commit(pack)
    assert commit not in str(caught.value)
    assert "symlink" in str(caught.value)


@pytest.mark.parametrize("kind", ["missing", "invalid", "short", "symlink"])
def test_builtin_pack_requires_a_real_source_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    _forbid_git(monkeypatch)
    pack = tmp_path / "regulated" / "law_firm"
    shutil.copytree(_REGULATED / "law_firm", pack)
    _break_source_toml(pack, kind)
    monkeypatch.setattr(
        "praxis_prime.packs.install.bundled_regulated_root",
        lambda: pack.parent,
    )
    data = tmp_path / "data"

    def runner(argv: list[str]) -> None:
        raise AssertionError(f"git runner: {argv}")

    with pytest.raises(PackError, match="law_firm") as install_error:
        install_pack("legal", data, git_runner=runner)
    assert "SOURCE.toml" in str(install_error.value)
    installed_root = data / "vertical-packs"
    assert installed_root.is_dir()
    assert list(installed_root.iterdir()) == []

    with pytest.raises(PackError, match="law_firm") as info_error:
        _format_info(data, "legal")
    assert "SOURCE.toml" in str(info_error.value)
    assert list(installed_root.iterdir()) == []

    loaded = load_legacy_pack(
        pack,
        source="built-in",
        repo="https://github.com/smfworks/smf-praxis-legal.git",
    )
    assert loaded.name == "law_firm"
    assert loaded.provenance.commit == ""
    assert main(["packs", "list", "--data-dir", str(data)]) == 0
