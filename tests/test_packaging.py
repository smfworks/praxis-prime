"""Compliance TOML packs ship in the wheel and sdist and still load."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tarfile
import zipfile
from contextlib import chdir
from pathlib import Path

from praxis_prime.compliance import packs as pack_module
from praxis_prime.compliance.packs import bundled_packs

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


def test_wheel_and_sdist_ship_compliance_packs(tmp_path: Path):
    from hatchling.build import build_sdist, build_wheel

    expected = sorted(
        path.name for path in (_REPO / "packs" / "compliance").glob("*.toml")
    )
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
    pack_module._BUNDLED = None
    checkout_ids = sorted(pack.id for pack in bundled_packs())
    assert installed_ids == checkout_ids
    assert "hipaa" in installed_ids
    assert "state_nc" in installed_ids
    assert "ferpa" in installed_ids
    assert "coppa" in installed_ids
    assert "gdpr" in installed_ids
    assert "pci" in installed_ids
