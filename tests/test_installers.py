"""Debian and AUR installer metadata. Does not build or install a package."""

from __future__ import annotations

import subprocess
import tomllib
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO / "packaging" / "deb" / "build-deb.sh"
_PKGBUILD = _REPO / "packaging" / "aur" / "PKGBUILD"


def _version() -> str:
    init = _REPO / "packages" / "prime-core" / "praxis_prime" / "__init__.py"
    for line in init.read_text(encoding="utf-8").splitlines():
        if line.startswith("__version__ = "):
            return line.split('"')[1]
    raise AssertionError("missing __version__")


def _project_scripts() -> dict[str, str]:
    project = tomllib.loads((_REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    return project["scripts"]


def test_project_scripts_match_the_packaged_commands() -> None:
    scripts = _project_scripts()
    assert scripts == {
        "praxis-prime": "praxis_prime.cli:main",
        "pprime": "praxis_prime.cli:main",
        "praxis-primed": "praxis_prime.daemon:main",
    }
    assert _version() == "0.1.0"


def test_debian_control_describes_the_package() -> None:
    control = (_REPO / "packaging" / "deb" / "debian" / "control").read_text(encoding="utf-8")
    assert "Source: praxis-prime\n" in control
    assert "Package: praxis-prime\n" in control
    assert "Maintainer: SMF Works <maintainers@praxis-prime.invalid>" in control
    assert "Rules-Requires-Root: no" in control
    assert "python3 (>= 3.12)" in control
    assert "Architecture: any" in control
    assert "${python3:Depends}" not in control
    assert "debhelper-compat" not in control
    assert "0.0.1" not in control
    depends = [line for line in control.splitlines() if line.startswith("Depends:")]
    assert depends == ["Depends: python3 (>= 3.12), bubblewrap"]
    assert all("textual" not in line.lower() for line in depends)
    assert "textual" in control.lower()
    assert "ensurepip" in control


def test_debian_changelog_and_rules() -> None:
    changelog = (_REPO / "packaging" / "deb" / "debian" / "changelog").read_text(encoding="utf-8")
    assert changelog.startswith(f"praxis-prime ({_version()})")
    assert "0.0.1" not in changelog
    assert "maintainers@praxis-prime.invalid" in changelog
    rules = (_REPO / "packaging" / "deb" / "debian" / "rules").read_text(encoding="utf-8")
    assert "build-deb.sh" in rules
    assert "dh $@" not in rules
    copyright_path = _REPO / "packaging" / "deb" / "debian" / "copyright"
    copyright_text = copyright_path.read_text(encoding="utf-8")
    assert copyright_text.startswith("Format: https://www.debian.org/doc/packaging-manuals/")
    assert "copyright-format/1.0/" in copyright_text
    assert "License: MIT" in copyright_text


def test_build_deb_script_syntax_help_and_dry_run() -> None:
    subprocess.run(["bash", "-n", str(_SCRIPT)], check=True, cwd=_REPO)
    help_run = subprocess.run(
        ["bash", str(_SCRIPT), "--help"],
        check=True,
        cwd=_REPO,
        capture_output=True,
        text=True,
    )
    assert "dpkg-deb" in help_run.stdout
    assert "--dry-run" in help_run.stdout
    assert "--allow-dirty" in help_run.stdout
    assert "praxis-prime" in help_run.stdout
    assert "/opt/praxis-prime" in help_run.stdout
    unknown = subprocess.run(
        ["bash", str(_SCRIPT), "--not-a-flag"],
        cwd=_REPO,
        capture_output=True,
        text=True,
    )
    assert unknown.returncode == 2
    dist = _REPO / "dist"
    before = sorted(path.name for path in dist.glob("*.deb")) if dist.is_dir() else []
    dry = subprocess.run(
        ["bash", str(_SCRIPT), "--dry-run"],
        check=True,
        cwd=_REPO,
        capture_output=True,
        text=True,
    )
    after = sorted(path.name for path in dist.glob("*.deb")) if dist.is_dir() else []
    assert before == after
    text = dry.stdout
    assert "dry-run" in text
    assert f"version: {_version()}" in text
    assert "architecture:" in text
    assert "prefix: /opt/praxis-prime" in text
    assert "bubblewrap" in text
    assert "/usr/bin/praxis-prime" in text
    assert "/usr/bin/pprime" in text
    assert "/usr/bin/praxis-primed" in text
    assert "dpkg-deb: skipped" in text
    assert f"praxis-prime_{_version()}_" in text


def test_build_deb_does_not_enable_or_embed_secrets() -> None:
    text = _SCRIPT.read_text(encoding="utf-8")
    assert "enable-linger" not in text
    assert "systemctl" not in text
    assert "DEBIAN/postinst" not in text
    assert "must not ship maintainer scripts" in text
    assert "XAI_API_KEY" in text
    for command in _project_scripts():
        assert command in text


def test_pkgbuild_is_a_real_git_package() -> None:
    subprocess.run(["bash", "-n", str(_PKGBUILD)], check=True, cwd=_REPO)
    text = _PKGBUILD.read_text(encoding="utf-8")
    assert "pkgname=praxis-prime-git" in text
    assert "provides=('praxis-prime')" in text
    assert "conflicts=('praxis-prime-bin')" in text
    assert "return 1" not in text
    assert "/opt/praxis-prime" in text
    assert "python-build" in text
    assert "python-installer" in text
    assert "python-wheel" in text
    assert "python-hatchling" in text
    assert "python>=3.12" in text
    assert "enable-linger" not in text
    assert "systemctl" not in text
    assert "praxis-prime-bin" in text
    assert "not submitted" in text.lower()
    assert "arch=('x86_64' 'aarch64')" in text
    assert "arch=('any')" not in text
    assert "depends=('python>=3.12' 'bubblewrap')" in text
    assert "requirements-runtime.txt" in text
    assert "--require-hashes" in text
    assert "--no-deps" in text
    assert "CREDITS.md" in text
    assert "python-licenses.txt" in text
    assert "praxis-prime.service" in text
    assert "praxis-prime-workers.slice" in text
    assert "praxis-prime-voice.service" not in text
    assert "*.service" not in text
    assert "return 1" not in text
    for command in _project_scripts():
        assert command in text


def test_packages_depend_on_bubblewrap() -> None:
    control = (_REPO / "packaging" / "deb" / "debian" / "control").read_text(encoding="utf-8")
    depends = [line for line in control.splitlines() if line.startswith("Depends:")]
    assert depends == ["Depends: python3 (>= 3.12), bubblewrap"]
    script = _SCRIPT.read_text(encoding="utf-8")
    assert "Depends: $py_pkg, bubblewrap" in script
    pkgbuild = _PKGBUILD.read_text(encoding="utf-8")
    assert "bubblewrap" in pkgbuild
    assert "depends=('python>=3.12' 'bubblewrap')" in pkgbuild


def test_hashed_runtime_requirements_and_no_unpinned_pip() -> None:
    script = _SCRIPT.read_text(encoding="utf-8")
    pkgbuild = _PKGBUILD.read_text(encoding="utf-8")
    req_path = _REPO / "packaging" / "requirements-runtime.txt"
    req = req_path.read_text(encoding="utf-8")
    assert "requirements-runtime.txt" in script
    assert "--require-hashes" in script
    assert "--no-deps" in script
    assert "simple pip" not in script
    assert "install pip" not in script
    assert "status --porcelain" in script
    assert "--allow-dirty" in script
    assert "CREDITS.md" in script
    assert "for unit in praxis-prime.service praxis-prime-workers.slice" in script
    assert "package must not ship stub unit" in script
    assert "find \"$ROOT/packaging/systemd\"" not in script
    assert "--require-hashes" in pkgbuild
    assert "--hash=sha256:" in req
    for pin in (
        "argon2-cffi==",
        "argon2-cffi-bindings==",
        "cffi==",
        "cryptography==",
        "joserfc==",
        "pyotp==",
        "tinycss2==",
        "webauthn==",
    ):
        assert pin in req
    assert "textual" not in req.lower()
    assert "pip==" not in req
