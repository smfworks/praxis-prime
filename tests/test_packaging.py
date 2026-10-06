"""Compliance TOML packs ship in the wheel and sdist and still load."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from contextlib import chdir
from pathlib import Path

from praxis_prime.compliance import packs as pack_module
from praxis_prime.compliance.packs import bundled_packs
from praxis_prime.packs.catalog import PUBLIC_PACKS

_REPO = Path(__file__).resolve().parents[1]
_CHILD = """
import json
from praxis_prime.compliance.packs import bundled_packs
packs = list(bundled_packs())
hipaa = next(pack for pack in packs if pack.id == "hipaa")
assert "not legal advice" in hipaa.disclaimer.lower()
assert hipaa.detectors
print(json.dumps(sorted(pack.id for pack in packs)))
"""


def test_resource_texts_override_the_source_tree(monkeypatch):
    monkeypatch.setattr(pack_module, "_BUNDLED", None)
    sample = '[pack]\nid = "from-resource"\ndial = "from-resource"\ntitle = "Resource"\n'
    monkeypatch.setattr(
        pack_module,
        "_resource_pack_texts",
        lambda: (("praxis_prime/_data/packs/compliance/from-resource.toml", sample),),
    )
    loaded = bundled_packs()
    assert [pack.id for pack in loaded] == ["from-resource"]
    assert loaded[0].source.startswith("praxis_prime/_data/packs/compliance/")


def test_textual_is_an_optional_extra() -> None:
    project = tomllib.loads((_REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    required = project["dependencies"]
    extras = project["optional-dependencies"]
    assert all(not item.startswith("textual") for item in required)
    assert extras["tui"] == ["textual>=8.2,<9"]
    assert "textual>=8.2,<9" in extras["dev"]


_REGULATED_PACKS = (
    "behavioral_health",
    "forensic",
    "homeschool",
    "law_firm",
    "medical_office",
    "school_system",
)

_REGULATED_CHILD = """
from praxis_prime.packs.install import bundled_regulated_root
root = bundled_regulated_root()
assert root is not None, "installed wheel has no regulated packs"
text = str(root)
assert "_data/packs/regulated" in text
names = sorted(path.name for path in root.iterdir() if (path / "pack.json").is_file())
print("\\n".join(names))
"""


def test_pyproject_force_includes_regulated_packs() -> None:
    loaded = tomllib.loads((_REPO / "pyproject.toml").read_text(encoding="utf-8"))
    targets = loaded["tool"]["hatch"]["build"]["targets"]
    wheel = targets["wheel"]["force-include"]
    sdist = targets["sdist"]["force-include"]
    assert wheel["packs/regulated"] == "praxis_prime/_data/packs/regulated"
    assert sdist["packs/regulated"] == "packs/regulated"
    assert wheel["packs/compliance"] == "praxis_prime/_data/packs/compliance"


def test_wheel_and_sdist_ship_compliance_packs(tmp_path: Path):
    from hatchling.build import build_sdist, build_wheel

    expected = sorted(path.name for path in (_REPO / "packs" / "compliance").glob("*.toml"))
    assert "hipaa.toml" in expected
    sdist_dir = tmp_path / "sdist"
    wheel_dir = tmp_path / "wheel"
    sdist_dir.mkdir()
    wheel_dir.mkdir()
    with chdir(_REPO):
        sdist_name = build_sdist(str(sdist_dir))
    sdist_path = sdist_dir / sdist_name
    with tarfile.open(sdist_path) as archive:
        names = archive.getnames()
    for filename in expected:
        assert any(name.endswith(f"packs/compliance/{filename}") for name in names)
    for pack_name in _REGULATED_PACKS:
        assert any(name.endswith(f"packs/regulated/{pack_name}/pack.json") for name in names)
        assert any(name.endswith(f"packs/regulated/{pack_name}/knowledge.md") for name in names)
    regulated_sdist = [
        name for name in names if "/packs/regulated/" in name or name.endswith("/packs/regulated")
    ]
    for name in regulated_sdist:
        assert not name.endswith((".py", ".js", ".mjs", ".wasm", ".css", ".html"))

    extract = tmp_path / "src"
    extract.mkdir()
    with tarfile.open(sdist_path) as archive:
        archive.extractall(extract, filter="data")
    roots = [path for path in extract.iterdir() if path.is_dir()]
    assert len(roots) == 1
    with chdir(roots[0]):
        wheel_name = build_wheel(str(wheel_dir))
    wheel_path = wheel_dir / wheel_name
    with zipfile.ZipFile(wheel_path) as archive:
        archived = set(archive.namelist())
    for filename in expected:
        assert f"praxis_prime/_data/packs/compliance/{filename}" in archived
    for pack_name in _REGULATED_PACKS:
        assert f"praxis_prime/_data/packs/regulated/{pack_name}/pack.json" in archived
        assert f"praxis_prime/_data/packs/regulated/{pack_name}/knowledge.md" in archived
    regulated_wheel = [name for name in archived if "praxis_prime/_data/packs/regulated/" in name]
    assert regulated_wheel
    for name in regulated_wheel:
        assert not name.endswith((".py", ".js", ".mjs", ".wasm", ".css", ".html"))
    for theme_id in (
        "smf.classical",
        "smf.dental",
        "smf.education",
        "smf.forensic",
        "smf.high-contrast",
        "smf.legal-office",
        "smf.medical",
        "smf.praxis",
    ):
        assert f"praxis_prime/ui_themes/{theme_id}/theme.toml" in archived
    assert any(name.endswith("assets/fonts/OFL.txt") and "ui_themes" in name for name in archived)
    assert any(name.endswith(".woff2") and "ui_themes" in name for name in archived)
    assert any(name.endswith("meander.svg") and "ui_themes" in name for name in archived)

    target = tmp_path / "installed"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--target",
            str(target),
            str(wheel_path),
        ],
        check=True,
        cwd=tmp_path,
    )
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONPATH"] = str(target)
    completed = subprocess.run(
        [sys.executable, "-c", _CHILD],
        check=True,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env=env,
    )
    installed_ids = json.loads(completed.stdout)
    regulated = subprocess.run(
        [sys.executable, "-c", _REGULATED_CHILD],
        check=True,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env=env,
    )
    assert regulated.stdout.splitlines() == sorted(_REGULATED_PACKS)
    pack_module._BUNDLED = None
    checkout_ids = sorted(pack.id for pack in bundled_packs())
    assert installed_ids == checkout_ids
    assert "hipaa" in installed_ids
    assert "state_nc" in installed_ids
    assert "ferpa" in installed_ids
    assert "coppa" in installed_ids
    assert "gdpr" in installed_ids
    assert "pci" in installed_ids


_PACK_ARRAY = re.compile(r"regulated_packs=\(([^)]*)\)")


def _regulated_pack_array(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    matches = _PACK_ARRAY.findall(text)
    assert len(matches) == 1, path
    return matches[0].split()


def test_packaging_scripts_list_every_regulated_pack() -> None:
    expected = {pack.pack_name for pack in PUBLIC_PACKS}
    on_disk = {
        path.name
        for path in (_REPO / "packs" / "regulated").iterdir()
        if path.is_dir() and (path / "pack.json").is_file()
    }
    assert expected == on_disk == set(_REGULATED_PACKS)
    for relative in ("packaging/deb/build-deb.sh", "packaging/aur/PKGBUILD"):
        script = _REPO / relative
        names = _regulated_pack_array(script)
        assert set(names) == expected
        assert len(names) == len(expected)
        completed = subprocess.run(
            ["bash", "-n", str(script)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
