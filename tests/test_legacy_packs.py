"""Legacy pack.json loader: data only, model pins and JavaScript ignored."""

from __future__ import annotations

import json
import logging
import os
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from praxis_prime.audit.log import AuditLog
from praxis_prime.cli import main
from praxis_prime.packs.install import (
    _MAX_ZIP_FILES,
    _extract_zip,
    install_pack,
    load_installed,
)
from praxis_prime.packs.legacy import PackError, load_legacy_pack
from praxis_prime.skills.format import parse_skill
from praxis_prime.state import StateDB

_MIT = "MIT License\n\nPermission is hereby granted, free of charge, to any person\n"


def _write_pack(
    root: Path,
    *,
    name: str = "demo_pack",
    model: str | None = "ollama-cloud/kimi-k2.7-code:cloud",
    javascript: bool = True,
    python: bool = True,
) -> None:
    manifest: dict[str, object] = {
        "name": name,
        "version": "1.2.3",
        "vertical": "Demo",
        "description": "A fixture pack in the old praxis-agent format.",
        "systemPrompt": "You are a demo persona. Stay on this machine.",
        "complianceMode": "enforced",
        "tools": ["read_file", "list_dir", "send_email", "not_a_real_tool"],
        "riskPolicy": {
            "dualApprovalRisks": ["send", "destructive"],
            "autonomousRisks": ["read", "draft"],
            "egressCheck": True,
            "injectionCheck": True,
            "approvalTtlSeconds": 900,
        },
        "knowledge": ["knowledge.md"],
        "skills": [
            {
                "name": "demo-skill",
                "trigger": "when demonstrating the pack",
                "body": "1. Stay local.\n",
            }
        ],
        "theme": {
            "accent": "#112233",
            "panel": "#010203",
            "ok": "#00aa00",
            "warn": "javascript:alert(1)",
        },
    }
    if model is not None:
        manifest["model"] = model
        manifest["provider"] = "ollama-cloud"
    root.mkdir(parents=True, exist_ok=True)
    (root / "pack.json").write_text(json.dumps(manifest), encoding="utf-8")
    (root / "knowledge.md").write_text("# Demo\n\nLocal notes only.\n", encoding="utf-8")
    (root / "LICENSE").write_text(_MIT, encoding="utf-8")
    (root / "pyproject.toml").write_text(
        '[project.entry-points."praxis.verticals"]\ndemo = "side_effect:register"\n',
        encoding="utf-8",
    )
    if javascript:
        web = root / "web"
        web.mkdir()
        (web / "dashboard.js").write_text("alert(1)\n", encoding="utf-8")
        (web / "dashboard.css").write_text("body { color: red; }\n", encoding="utf-8")
    if python:
        (root / "side_effect.py").write_text(
            "from pathlib import Path\n"
            "Path(__file__).with_name('EXECUTED').write_text('yes', encoding='utf-8')\n",
            encoding="utf-8",
        )


def test_model_pin_and_javascript_are_ignored(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    root = tmp_path / "pack"
    _write_pack(root)
    with caplog.at_level(logging.WARNING):
        pack = load_legacy_pack(root)
    assert pack.selected_model is None
    assert pack.selected_provider is None
    assert pack.model_suggestion == "ollama-cloud/kimi-k2.7-code:cloud"
    assert pack.provider_suggestion == "ollama-cloud"
    assert "ollama-cloud/kimi-k2.7-code:cloud" in caplog.text
    assert "cannot select the LLM" in caplog.text
    assert any(item.code == "javascript_ignored" for item in pack.warnings)
    assert any(item.code == "dashboard_ignored" for item in pack.warnings)
    assert "web/dashboard.js" in caplog.text
    assert not (root / "EXECUTED").exists()
    assert "side_effect" not in sys.modules
    assert pack.provenance.license == "MIT"
    assert pack.knowledge[0].read_only is True
    assert "Local notes only." in pack.knowledge[0].text
    mapped = {tool.legacy_name: tool.praxis_tool for tool in pack.tools if tool.available}
    assert mapped["read_file"] == "read_file"
    assert mapped["list_dir"] == "list_dir"
    unavailable = pack.unavailable_tools()
    assert "send_email" in unavailable
    assert "not_a_real_tool" in unavailable
    assert pack.skills[0].name == "demo-skill"
    assert pack.skills[0].description == "when demonstrating the pack"
    assert pack.skills[0].meta["namespace"] == "pack/demo_pack/demo-skill"
    assert all(rule.applied is False for rule in pack.rules)
    assert pack.approval_ttl_seconds == 900
    assert pack.dual_approval_risks == ("SEND", "DESTRUCTIVE")
    assert pack.theme is not None
    assert ("warn",) not in {(token,) for token, _value in pack.theme.token_overrides}
    assert dict(pack.theme.token_overrides)["bgRaised"] == "#010203"


def test_pack_without_a_model_pin_does_not_warn(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    root = tmp_path / "plain"
    _write_pack(root, name="homeschool", model=None, javascript=False, python=False)
    with caplog.at_level(logging.WARNING):
        pack = load_legacy_pack(root)
    assert pack.model_suggestion == ""
    assert pack.selected_model is None
    assert not any(item.code == "model_ignored" for item in pack.warnings)
    assert not any(item.code == "javascript_ignored" for item in pack.warnings)
    assert "cannot select the LLM" not in caplog.text
    assert pack.suggested_dials == (("ferpa", "monitor"), ("coppa", "monitor"))
    assert all(rule.applied is False for rule in pack.rules)


def test_only_an_allowlisted_entry_point_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "pack"
    _write_pack(root)
    load_legacy_pack(root)
    assert not (root / "EXECUTED").exists()
    monkeypatch.setattr(
        "praxis_prime.packs.legacy.ALLOWLISTED_ENTRY_POINTS",
        frozenset({"side_effect:register"}),
    )
    pack = load_legacy_pack(root)
    assert (root / "EXECUTED").is_file()
    assert pack.executed_entry_points == ("side_effect:register",)
    assert "side_effect" not in sys.modules


def test_install_records_provenance_and_drops_code(tmp_path: Path):
    source = tmp_path / "source"
    _write_pack(source, model="ollama-cloud/demo:cloud")
    data = tmp_path / "data"
    db = StateDB(data / "prime.db")
    try:
        installed = install_pack(str(source), data, audit=AuditLog(db))
        dest = installed.path
        assert (dest / "pack.json").is_file()
        assert (dest / "knowledge.md").is_file()
        assert (dest / "LICENSE").is_file()
        assert not list(dest.rglob("*.js"))
        assert not list(dest.rglob("*.py"))
        assert not list(dest.rglob("*.css"))
        assert not (source / "EXECUTED").exists()
        skill_path = dest / "skills" / "pack" / "demo_pack" / "demo-skill" / "SKILL.md"
        parsed = parse_skill(skill_path.read_text(encoding="utf-8"), skill_path, "pack")
        assert parsed.name == "demo-skill"
        assert "Stay local." in parsed.body
        reloaded = load_installed(dest)
        assert reloaded.selected_model is None
        assert "web/dashboard.js" in reloaded.ignored_javascript
        assert any(item.code == "javascript_ignored" for item in reloaded.warnings)
        assert any(item.endswith("side_effect.py") for item in reloaded.python_modules)
        rows = db.conn.execute(
            "SELECT kind, summary, payload_json FROM audit_events"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["kind"] == "pack.install"
        payload = json.loads(rows[0]["payload_json"])
        assert payload["license"] == "MIT"
        assert payload["version"] == "1.2.3"
        assert payload["repo"]
        assert payload["model_ignored"] == "ollama-cloud/demo:cloud"
        assert "web/dashboard.js" in payload["javascript_ignored"]
        assert payload["commit"] == "" or isinstance(payload["commit"], str)
        assert not (data / "config.toml").exists()
    finally:
        db.close()


def test_git_install_clones_without_running_pack_code(tmp_path: Path):
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> None:
        calls.append(argv)
        assert argv[:4] == ["git", "clone", "--depth", "1"]
        assert "--" in argv
        target = Path(argv[-1])
        _write_pack(target, name="law_firm", model="ollama-cloud/kimi-k2.7-code:cloud")
        subprocess.run(["git", "init"], cwd=target, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "pack@example.com"],
            cwd=target,
            check=True,
        )
        subprocess.run(["git", "config", "user.name", "Pack Test"], cwd=target, check=True)
        subprocess.run(["git", "add", "."], cwd=target, check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "pack"],
            cwd=target,
            check=True,
            capture_output=True,
        )

    data = tmp_path / "data"
    db = StateDB(data / "prime.db")
    try:
        installed = install_pack(
            "https://example.invalid/demo-pack.git",
            data,
            audit=AuditLog(db),
            git_runner=runner,
        )
    finally:
        db.close()
    assert calls
    assert installed.pack.name == "law_firm"
    assert installed.pack.provenance.commit
    assert installed.pack.provenance.repo == "https://example.invalid/demo-pack.git"
    assert installed.pack.provenance.license == "MIT"
    assert installed.pack.selected_model is None
    assert not (installed.path / "side_effect.py").exists()
    assert not list(installed.path.rglob("*.js"))
    assert "web/dashboard.js" in installed.pack.ignored_javascript


def test_known_name_points_at_the_public_repo(tmp_path: Path):
    def runner(argv: list[str]) -> None:
        assert "https://github.com/smfworks/smf-praxis-legal.git" in argv
        target = Path(argv[-1])
        pack_dir = target / "hybridagent_praxis_legal" / "packs" / "law_firm"
        _write_pack(pack_dir, name="law_firm", model="ollama-cloud/kimi-k2.7-code:cloud")
        (target / "LICENSE").write_text(_MIT, encoding="utf-8")
        web = target / "hybridagent_praxis_legal" / "web"
        web.mkdir(parents=True)
        (web / "law_firm.js").write_text("/* dashboard */\n", encoding="utf-8")

    data = tmp_path / "data"
    installed = install_pack("legal", data, git_runner=runner)
    assert installed.pack.name == "law_firm"
    assert installed.pack.provenance.repo == "https://github.com/smfworks/smf-praxis-legal.git"
    assert installed.pack.suggested_dials == ()
    assert installed.pack.theme is not None
    assert installed.pack.theme.suggested_theme_id == "smf.legal-office"
    assert any(item.endswith("law_firm.js") for item in installed.pack.ignored_javascript)
    assert not list(installed.path.rglob("*.js"))


def test_unsafe_git_url_is_refused(tmp_path: Path):
    def runner(argv: list[str]) -> None:
        raise AssertionError(f"git must not run for {argv}")

    with pytest.raises(PackError, match="refusing"):
        install_pack("ext::sh -c touch /tmp/pwned.git", tmp_path / "data", git_runner=runner)


def test_cli_packs_list_install_and_info(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    source = tmp_path / "source"
    _write_pack(source, model="ollama-cloud/demo:cloud")
    data = tmp_path / "data"
    base = ["--data-dir", str(data)]
    assert main(["packs", "list", *base]) == 0
    listed = capsys.readouterr().out
    assert "legal" in listed
    assert "not installed" in listed
    assert "(none)" in listed
    assert main(["packs", "install", str(source), *base]) == 0
    installed_out = capsys.readouterr()
    assert "installed demo_pack 1.2.3 (MIT)" in installed_out.out
    assert "Ignored pack model pin" in installed_out.err
    assert "dashboard.js" in installed_out.err
    assert main(["packs", "info", "demo_pack", *base]) == 0
    info = capsys.readouterr().out
    assert "selected model: none" in info
    assert "ollama-cloud/demo:cloud" in info
    assert "send_email" in info
    assert "unavailable tools:" in info
    assert "demo-skill" in info
    assert "compliance mode applied: no" in info
    assert "MIT" in info
    assert main(["packs", "info", "missing", *base]) == 1
    assert main(["packs"]) == 2


_EVIL_NAMES = (
    "absolute",
    "../decoy",
    "../...",
    "a/b",
    "a\\b",
    "",
    ".",
    "..",
)


def _escape_path(tmp_path: Path) -> Path:
    return tmp_path / "escape-target"


def _pack_name(tmp_path: Path, name: str) -> str:
    if name == "absolute":
        return str(_escape_path(tmp_path))
    return name


def _outside_markers(tmp_path: Path, data: Path) -> tuple[Path, Path]:
    outside = tmp_path / "outside.txt"
    outside.write_text("keep", encoding="utf-8")
    decoy = data / "decoy"
    decoy.mkdir(parents=True)
    marker = decoy / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    return outside, marker


def _assert_contained(data: Path, outside: Path, marker: Path, escape: Path) -> None:
    assert outside.read_text(encoding="utf-8") == "keep"
    assert marker.is_file()
    assert marker.read_text(encoding="utf-8") == "keep"
    assert not escape.exists()
    packs = data / "vertical-packs"
    if not packs.exists():
        return
    root = packs.resolve()
    for path in packs.rglob("*"):
        assert path.resolve().is_relative_to(root)


@pytest.mark.parametrize("name", _EVIL_NAMES)
def test_local_install_refuses_a_path_escape(tmp_path: Path, name: str):
    source = tmp_path / "source"
    _write_pack(source, name=_pack_name(tmp_path, name), javascript=False, python=False)
    data = tmp_path / "data"
    outside, marker = _outside_markers(tmp_path, data)
    with pytest.raises(PackError, match="refusing"):
        install_pack(str(source), data)
    _assert_contained(data, outside, marker, _escape_path(tmp_path))


def test_zip_and_git_install_refuse_a_path_escape(tmp_path: Path):
    data = tmp_path / "data"
    outside, marker = _outside_markers(tmp_path, data)
    escape = _escape_path(tmp_path)
    staged = tmp_path / "staged"
    _write_pack(staged, name="../decoy", javascript=False, python=False)
    archive_path = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        for path in staged.rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(staged).as_posix())
    with pytest.raises(PackError, match="refusing"):
        install_pack(str(archive_path), data)
    _assert_contained(data, outside, marker, escape)

    def runner(argv: list[str]) -> None:
        target = Path(argv[-1])
        _write_pack(
            target,
            name=str(escape),
            javascript=False,
            python=False,
        )

    with pytest.raises(PackError, match="refusing"):
        install_pack(
            "https://example.invalid/evil-pack.git",
            data,
            git_runner=runner,
        )
    _assert_contained(data, outside, marker, escape)


def test_zip_members_cannot_escape_or_symlink(tmp_path: Path):
    outside = tmp_path / "outside.txt"
    absolute = tmp_path / "abs-member"
    dest = tmp_path / "extract"
    cases = (
        ("../outside.txt", "pwned", None),
        (str(absolute), "pwned", None),
        ("link", "target", (stat.S_IFLNK | 0o777) << 16),
    )
    for filename, payload, mode in cases:
        archive_path = tmp_path / f"{abs(hash(filename)) & 0xFFFF:x}.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            info = zipfile.ZipInfo(filename)
            if mode is not None:
                info.external_attr = mode
            archive.writestr(info, payload)
            archive.writestr("pack.json", "{}")
        with pytest.raises(PackError, match="archive"):
            _extract_zip(archive_path, dest)
        assert not outside.exists()
        assert not absolute.exists()
        if dest.exists():
            for path in dest.rglob("*"):
                assert not path.is_symlink()
                assert path.resolve().is_relative_to(dest.resolve())


def test_safe_zip_install_stays_under_vertical_packs(tmp_path: Path):
    staged = tmp_path / "staged"
    _write_pack(staged, name="demo_pack", javascript=False, python=False)
    archive_path = tmp_path / "ok.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        for path in staged.rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(staged).as_posix())
    data = tmp_path / "data"
    installed = install_pack(str(archive_path), data)
    root = (data / "vertical-packs").resolve()
    assert installed.path.resolve().is_relative_to(root)
    assert installed.path.name == "demo_pack"
    assert (installed.path / "pack.json").is_file()


_SECRET = "AKIASECRET-MARKER-not-for-pack"


def _guard_secret(monkeypatch: pytest.MonkeyPatch, secret: Path) -> None:
    """Fail the test if install opens the symlink target."""
    real_open = os.open
    nofollow = getattr(os, "O_NOFOLLOW", 0)

    def guarded(file: int | str | Path, flags: int, *args: object, **kwargs: object) -> int:
        opened = Path(file)
        try:
            points_at_secret = opened.resolve() == secret.resolve()
        except OSError:
            points_at_secret = False
        follows = not opened.is_symlink() or not bool(flags & nofollow)
        if points_at_secret and follows:
            raise AssertionError(f"secret file was read: {file}")
        return real_open(file, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", guarded)


def _assert_secret_stays(data: Path, secret: Path, exc: BaseException) -> None:
    assert _SECRET not in str(exc)
    assert secret.read_text(encoding="utf-8") == _SECRET
    root = data / "vertical-packs"
    if not root.exists():
        return
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        assert _SECRET not in text


@pytest.mark.parametrize("kind", ["LICENSE", "NOTICE", "pack.json"])
def test_symlinked_pack_file_is_not_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
):
    secret = tmp_path / "secret"
    secret.write_text(_SECRET, encoding="utf-8")
    source = tmp_path / "source"
    _write_pack(source, javascript=False, python=False)
    link = source / kind
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(secret)
    data = tmp_path / "data"
    _guard_secret(monkeypatch, secret)
    with pytest.raises(PackError, match="symlink") as caught:
        install_pack(str(source), data)
    monkeypatch.undo()
    _assert_secret_stays(data, secret, caught.value)


def test_symlink_install_directory_does_not_delete_its_target(tmp_path: Path):
    source = tmp_path / "source"
    _write_pack(source, name="demo_pack", javascript=False, python=False)
    data = tmp_path / "data"
    packs = data / "vertical-packs"
    other = packs / "other"
    other.mkdir(parents=True)
    keep = other / "keep.txt"
    keep.write_text("keep", encoding="utf-8")
    (packs / "demo_pack").symlink_to(other, target_is_directory=True)
    with pytest.raises(PackError, match="symlink"):
        install_pack(str(source), data)
    assert keep.is_file()
    assert keep.read_text(encoding="utf-8") == "keep"
    assert not (other / "pack.json").exists()
    assert (packs / "demo_pack").is_symlink()


@pytest.mark.parametrize("member", ["a\\b", "C:secret", "..\\outside.txt"])
def test_windows_style_zip_members_are_refused(tmp_path: Path, member: str):
    archive_path = tmp_path / "win.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(member, "pwned")
    with pytest.raises(PackError, match="archive"):
        _extract_zip(archive_path, tmp_path / "out")


def test_zip_member_count_and_size_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    many = tmp_path / "many.zip"
    with zipfile.ZipFile(many, "w") as archive:
        for index in range(_MAX_ZIP_FILES + 1):
            archive.writestr(f"f{index}.txt", "x")
    with pytest.raises(PackError, match="too many"):
        _extract_zip(many, tmp_path / "many-out")

    monkeypatch.setattr("praxis_prime.packs.install._MAX_ZIP_BYTES", 8)
    big = tmp_path / "big.zip"
    with zipfile.ZipFile(big, "w") as archive:
        archive.writestr("pack.json", "0123456789")
    with pytest.raises(PackError, match="too large"):
        _extract_zip(big, tmp_path / "big-out")


def test_bad_zip_and_duplicate_members_are_pack_errors(tmp_path: Path):
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"not a zip")
    with pytest.raises(PackError, match="valid zip"):
        _extract_zip(bad, tmp_path / "bad-out")
    duplicate = tmp_path / "dup.zip"
    with zipfile.ZipFile(duplicate, "w") as archive:
        archive.writestr("pack.json", "{}")
        archive.writestr("pack.json", "{}")
    with pytest.raises(PackError, match="duplicate"):
        _extract_zip(duplicate, tmp_path / "dup-out")
