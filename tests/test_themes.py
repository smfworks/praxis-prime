"""Theme packages: validation, contrast, install, and legacy hints."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from praxis_prime.cli import build_parser
from praxis_prime.packs.model import ThemeHint
from praxis_prime.profiles.home import create_profile, org_policy_path
from praxis_prime.profiles.policy import load_layer
from praxis_prime.themes.archive import write_zip
from praxis_prime.themes.cli import dispatch_theme
from praxis_prime.themes.cssgen import render_css
from praxis_prime.themes.errors import ThemeError
from praxis_prime.themes.legacy import describe_hint, materialize_pack_theme, pack_theme_id
from praxis_prime.themes.lockfile import package_hash
from praxis_prime.themes.omarchy import live_theme
from praxis_prime.themes.select import resolve_theme, set_lock, set_profile_theme
from praxis_prime.themes.store import install_files, read_builtin_files, remove_theme
from praxis_prime.themes.validate import contrast_modes, validate_dir, validate_files, validate_zip

_ROOT = Path(__file__).resolve().parents[1]
_BUILTIN = _ROOT / "packages" / "prime-core" / "praxis_prime" / "ui_themes"


def _codes(exc: ThemeError) -> set[str]:
    return {issue.code for issue in exc.issues}


def _clone(theme_id: str = "lab.sample") -> dict[str, bytes]:
    files = read_builtin_files("smf.praxis")
    text = files["theme.toml"].decode("utf-8")
    text = text.replace('id = "smf.praxis"', f'id = "{theme_id}"', 1)
    text = text.replace('name = "Praxis"', "name = \"Lab\"", 1)
    files["theme.toml"] = text.encode("utf-8")
    return files


def _zipped(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, payload in files.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


def test_builtin_themes_meet_their_contrast_levels():
    praxis = validate_dir(_BUILTIN / "smf.praxis")
    contrast = validate_dir(_BUILTIN / "smf.high-contrast")
    assert praxis.theme_id == "smf.praxis"
    assert praxis.contrast == "AA"
    assert contrast_modes(praxis.modes, "AA") == []
    assert contrast.contrast == "AAA"
    assert contrast_modes(contrast.modes, "AAA") == []
    assert contrast_modes(contrast.modes, "AA") == []
    for package in (praxis, contrast):
        css = render_css(package, package_hash(package.files))
        assert "--pp-bg:" in css
        assert "--pp-ring:" in css
        assert "@font-face" in css
        assert "fonts.googleapis" not in css
        assert "http://" not in css
        assert "https://" not in css
        assert "assets/fonts/OFL.txt" in package.files
        fonts = [package.files[path] for path in package.files if path.endswith(".woff2")]
        assert fonts
        assert all(blob.startswith(b"wOF2") for blob in fonts)


def test_theme_css_rejects_active_content():
    cases = {
        "import": "@import url(\"assets/fonts/OFL.txt\");\n",
        "remote": ".pp-divider { background-image: url(https://evil.test/a.png); }\n",
        "display": ".pp-approval { display: none; }\n",
        "opacity": ".pp-approval { opacity: 0; }\n",
        "position": ".pp-approval { position: absolute; }\n",
        "attribute": "a[href] { color: red; }\n",
        "has": ":root:has(.x) { --pp-bg: #000000; }\n",
    }
    expected = {
        "import": "css_import",
        "remote": "css_url",
        "display": "css_selector",
        "opacity": "css_selector",
        "position": "css_selector",
        "attribute": "css_selector",
        "has": "css_selector",
    }
    for name, css in cases.items():
        files = _clone()
        files["theme.css"] = css.encode("utf-8")
        with pytest.raises(ThemeError) as caught:
            validate_files(files)
        assert expected[name] in _codes(caught.value), name


def test_javascript_svg_script_and_zip_traversal_are_rejected():
    scripted = _clone()
    scripted["app.js"] = b"alert(1)\n"
    with pytest.raises(ThemeError) as caught:
        validate_files(scripted)
    assert "file_type" in _codes(caught.value)

    svg = _clone()
    svg["assets/ornaments/meander.svg"] = (
        b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
    )
    with pytest.raises(ThemeError) as caught:
        validate_files(svg)
    assert "svg_rejected" in _codes(caught.value)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("../evil.toml", "id = 1\n")
    with pytest.raises(ThemeError) as caught:
        validate_zip(buffer.getvalue())
    assert "zip_traversal" in _codes(caught.value)


def test_oversize_zip_is_rejected():
    blob = b"PK\x03\x04" + (b"0" * (5 * 1024 * 1024))
    with pytest.raises(ThemeError) as caught:
        validate_zip(blob)
    assert "zip_too_large" in _codes(caught.value)


def test_cli_lint_pack_install_and_set(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    source = tmp_path / "src"
    source.mkdir()
    files = _clone("lab.sample")
    for name, payload in files.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    parser = build_parser()
    lint = parser.parse_args(["theme", "lint", str(source), "--json"])
    assert dispatch_theme(lint) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True
    assert report["id"] == "lab.sample"

    packed = tmp_path / "out"
    packed.mkdir()
    pack = parser.parse_args(["theme", "pack", str(source), "-o", str(packed / "lab.zip")])
    assert dispatch_theme(pack) == 0
    assert (packed / "lab.zip").is_file()

    data = tmp_path / "data"
    create_profile(data, "default")
    install = parser.parse_args(
        ["theme", "install", str(packed / "lab.zip"), "--data-dir", str(data)]
    )
    assert dispatch_theme(install) == 0
    choice = set_profile_theme(data, "default", "lab.sample", "dark")
    assert choice.theme_id == "lab.sample"
    assert choice.mode == "dark"
    listed = parser.parse_args(["theme", "list", "--data-dir", str(data)])
    assert dispatch_theme(listed) == 0
    assert "lab.sample" in capsys.readouterr().out


def test_lock_beats_profile_and_does_not_tighten_tools(tmp_path: Path):
    data = tmp_path / "data"
    create_profile(data, "default")
    set_profile_theme(data, "default", "smf.high-contrast", "dark")
    assert resolve_theme(data, "default").theme_id == "smf.high-contrast"
    set_lock(data, "smf.praxis", "light")
    choice = resolve_theme(data, "default")
    assert choice.locked
    assert choice.theme_id == "smf.praxis"
    assert choice.mode == "light"
    layer = load_layer(org_policy_path(data), table="org")
    assert layer.tools is None
    assert layer.dials == {}
    assert live_theme() is None


def test_legacy_hint_adjusts_or_refuses(tmp_path: Path):
    passing = ThemeHint("smf.legal-office", (("accent", "#102a43"), ("ok", "#1a6323")))
    ok = describe_hint(passing)
    assert ok.ok
    assert ok.theme_id == "smf.legal-office"
    refused = describe_hint(ThemeHint("smf.praxis", (("ok", "#ffff00"), ("warn", "#ffffee"))))
    assert refused.ok is False
    assert "contrast" in refused.message or "lightness" in refused.message
    data = tmp_path / "data"
    data.mkdir()
    wrote = materialize_pack_theme("law_firm", passing, data)
    assert wrote.ok
    assert pack_theme_id("law_firm") == "pack.law-firm"
    installed = resolve_theme(data, "")
    assert installed.theme_id == "smf.praxis"
    again = materialize_pack_theme(
        "law_firm",
        ThemeHint("smf.legal-office", (("ok", "#ffff00"),)),
        data,
    )
    assert again.ok is False
    with pytest.raises(ThemeError) as caught:
        remove_theme("smf.praxis", data)
    assert "forbidden" in _codes(caught.value)


def test_pack_round_trip_keeps_the_hash(tmp_path: Path):
    files = _clone("lab.round")
    dest = tmp_path / "lab.round-1.0.0.praxis-theme.zip"
    write_zip(files, dest)
    package = validate_zip(dest.read_bytes())
    assert package.theme_id == "lab.round"
    assert package_hash(package.files) == package_hash(files)
    installed = install_files(package.files, tmp_path / "data")
    assert installed.package_hash == package_hash(files)
    assert (tmp_path / "data" / "themes" / "lab.round" / "1.0.0" / "theme.lock.json").is_file()
