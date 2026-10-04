"""Theme packages: validation, contrast, install, and legacy hints."""

from __future__ import annotations

import io
import json
import re
import struct
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest
import tinycss2
from tinycss2.ast import AtRule, QualifiedRule

from praxis_prime.cli import build_parser
from praxis_prime.packs.model import ThemeHint
from praxis_prime.profiles.home import create_profile, org_policy_path
from praxis_prime.profiles.policy import load_layer
from praxis_prime.state import StateDB
from praxis_prime.themes.archive import MAX_PREVIEW_BYTES, read_dir, write_zip
from praxis_prime.themes.cli import dispatch_theme
from praxis_prime.themes.color import contrast_ratio
from praxis_prime.themes.cssgen import render_css
from praxis_prime.themes.errors import ThemeError
from praxis_prime.themes.legacy import describe_hint, materialize_pack_theme, pack_theme_id
from praxis_prime.themes.lockfile import package_hash, verify_lock
from praxis_prime.themes.model import FontFace
from praxis_prime.themes.omarchy import live_theme
from praxis_prime.themes.select import resolve_theme, set_lock, set_profile_theme
from praxis_prime.themes.store import (
    discard_stage,
    files_match_lock,
    find_theme,
    install_files,
    list_themes,
    read_builtin_files,
    remove_theme,
    stage_theme,
    sweep_stages,
    take_stage,
)
from praxis_prime.themes.svg import check_svg
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


_BUILTINS = (
    "smf.classical",
    "smf.dental",
    "smf.education",
    "smf.forensic",
    "smf.high-contrast",
    "smf.legal-office",
    "smf.medical",
    "smf.praxis",
)
_SVG_NAMESPACES = (
    "http://www.w3.org/2000/svg",
    "http://www.w3.org/1999/xlink",
)
_URL = re.compile(r"""url\(\s*(['"]?)([^)'"]+)\1\s*\)""", re.IGNORECASE)


def test_builtin_themes_meet_their_contrast_levels():
    found = sorted(
        path.name
        for path in _BUILTIN.iterdir()
        if path.is_dir() and not path.name.startswith((".", "_"))
    )
    assert found == list(_BUILTINS)
    for theme_id in _BUILTINS:
        package = validate_dir(_BUILTIN / theme_id)
        level = "AAA" if theme_id == "smf.high-contrast" else "AA"
        assert package.theme_id == theme_id
        assert package.contrast == level
        assert contrast_modes(package.modes, level) == []
        assert contrast_modes(package.modes, "AA") == []
        css = render_css(package, package_hash(package.files))
        assert "--pp-bg:" in css
        assert "--pp-ring:" in css
        assert "@font-face" in css
        assert "fonts.googleapis" not in css
        assert "http://" not in css
        assert "https://" not in css
        assert "assets/fonts/OFL.txt" in package.files
        licence = package.files["assets/fonts/OFL.txt"].decode("utf-8")
        assert "SIL Open Font License" in licence
        fonts = [package.files[path] for path in package.files if path.endswith(".woff2")]
        assert fonts
        assert all(blob.startswith(b"wOF2") for blob in fonts)


def test_every_bundled_font_is_credited():
    credits = (_ROOT / "CREDITS.md").read_text(encoding="utf-8")
    third = (_ROOT / "THIRD_PARTY.md").read_text(encoding="utf-8")
    copied = third.split("## Copied-file log", 1)[1]
    fonts = sorted(_BUILTIN.rglob("*.woff2"))
    assert len(fonts) >= 8
    for path in fonts:
        repo = path.relative_to(_ROOT).as_posix()
        packaged = path.relative_to(_ROOT / "packages" / "prime-core").as_posix()
        assert repo in credits, repo
        assert f"`{packaged}`" in copied, packaged

# OFL section 3: a modified font may not use a Reserved Font Name.
_FAMILY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
_RFN = re.compile(
    r"""Reserved Font Name\s+(?:["“']([^"”']+)["”']|([A-Za-z][^.\n]{0,80}?))(?=\.|$)""",
    re.MULTILINE,
)
_NEW_THEMES = (
    "smf.legal-office",
    "smf.forensic",
    "smf.education",
    "smf.classical",
    "smf.medical",
    "smf.dental",
)
_NAMED_RFN = {
    "smf.legal-office": {"Libre Baskerville", "Source"},
    "smf.classical": {"Source"},
    "smf.forensic": {"Plex"},
    "smf.education": {"RevReading Lexend"},
    "smf.medical": set(),
    "smf.dental": set(),
}
# Name ID 0 is the copyright notice. It keeps the author's name and the
# Reserved Font Name clause. Every other name record in a renamed subset
# must not contain these strings. Lexend is not in this set.
_RENAMED_FONTS = {
    "LibreBaskerville.woff2",
    "SourceSans3.woff2",
    "SourceCodePro.woff2",
    "IBMPlexSans.woff2",
    "IBMPlexMono-Regular.woff2",
    "IBMPlexMono-Bold.woff2",
}
_RFN_LEFTOVERS = (
    "Libre Baskerville",
    "LibreBaskerville",
    "Source",
    "IBM Plex",
    "IBMPlex",
)


def _reserved_font_names(text: str) -> set[str]:
    found: set[str] = set()
    for match in _RFN.finditer(text):
        name = (match.group(1) or match.group(2) or "").strip()
        if name:
            found.add(name)
    return found


def test_subset_fonts_drop_reserved_names():
    """A subset drops a Reserved Font Name. Lexend's reserved name is longer."""
    ttlib = pytest.importorskip("fontTools.ttLib")
    import tomllib

    third = (_ROOT / "THIRD_PARTY.md").read_text(encoding="utf-8")
    table = third.split("## Copied-file log", 1)[0]
    for theme_id in _NEW_THEMES:
        root = _BUILTIN / theme_id
        licence = (root / "assets" / "fonts" / "OFL.txt").read_text(encoding="utf-8")
        reserved = _reserved_font_names(licence)
        assert reserved == _NAMED_RFN[theme_id], theme_id
        meta = tomllib.loads((root / "theme.toml").read_text(encoding="utf-8"))
        for path in sorted((root / "assets" / "fonts").glob("*.woff2")):
            font = ttlib.TTFont(path)
            try:
                by_id: dict[int, list[str]] = {}
                for record in font["name"].names:
                    by_id.setdefault(record.nameID, []).append(record.toUnicode())
            finally:
                font.close()
            if path.name in _RENAMED_FONTS:
                for name_id, values in by_id.items():
                    if name_id == 0:
                        continue
                    for value in values:
                        leaked = [needle for needle in _RFN_LEFTOVERS if needle in value]
                        assert not leaked, (path.name, name_id, value, leaked)
            shown = [
                value
                for name_id in (1, 4, 6, 16)
                for value in by_id.get(name_id, [])
            ]
            for reserved_name in reserved:
                kept = [value for value in shown if reserved_name in value]
                assert not kept, (path.name, reserved_name, kept)
            family = by_id[1][0]
            assert _FAMILY_NAME.fullmatch(family), family
            packaged = path.relative_to(_ROOT / "packages" / "prime-core").as_posix()
            row = next(line for line in table.splitlines() if f"`{packaged}`" in line)
            cells = [cell.strip() for cell in row.strip("|").split("|")]
            assert cells[2] == by_id[0][0], packaged
            rel = path.relative_to(root).as_posix()
            declared = [
                str(slot["family"])
                for slot in meta["fonts"].values()
                if any(face.get("path") == rel for face in slot.get("files", []))
            ]
            assert declared, rel
            assert all(_FAMILY_NAME.fullmatch(name) for name in declared)
            if family.startswith("Praxis "):
                assert set(by_id[16]) == {family}
                assert set(declared) == {family}
                assert family in cells[0]
            if path.name == "Lexend.woff2":
                assert family == "Lexend"
                assert declared == ["Lexend"]


def test_builtin_theme_assets_have_no_remote_urls():
    for path in _BUILTIN.rglob("*"):
        if path.suffix not in {".toml", ".css", ".svg"} or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".svg":
            for namespace in _SVG_NAMESPACES:
                text = text.replace(namespace, "")
        assert "://" not in text, path
        assert not re.search(r"(?<!:)//[A-Za-z0-9]", text), path
        for match in _URL.finditer(text):
            target = match.group(2).strip()
            assert target.startswith("#") or target.startswith("assets/"), (path, target)


def test_new_ornaments_pass_the_sanitizer_unchanged():
    fresh = {"rule.svg", "grid.svg", "capital.svg"}
    seen = set()
    for path in _BUILTIN.rglob("*.svg"):
        raw = path.read_bytes()
        once, issue = check_svg(path.name, raw)
        assert issue is None, path
        twice, again = check_svg(path.name, once)
        assert again is None
        assert once == twice
        assert once.startswith(b"<?xml")
        if path.name in fresh:
            assert raw == once, path
            seen.add(path.name)
    assert seen == fresh


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


def test_lock_beats_profile_and_does_not_tighten_tools(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PRAXIS_PRIME_OMARCHY_THEME", str(tmp_path / "missing-omarchy.json"))
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
    again = validate_files(package.files)
    assert package_hash(again.files) == package_hash(package.files)
    installed = install_files(package.files, tmp_path / "data")
    assert installed.package_hash == package_hash(package.files)
    assert (tmp_path / "data" / "themes" / "lab.round" / "1.0.0" / "theme.lock.json").is_file()
    assert installed.root is not None
    verify_lock(read_dir(installed.root), "lab.round", "1.0.0")


_ORNAMENT_REPRO = 'assets/ornaments/x");} .pp-approval{display:none} :root{--z:url("y.svg'
_FONT_REPRO = (
    'assets/fonts/x");}html::after{content:\'\';position:fixed;inset:0;z-index:2147483647}.woff2'
)
_CONTRAST_REPRO = (
    ":root{--pp-fg:#f6f1e7;--pp-fgMuted:#efe7da}"
    " :root[data-mode=light]{--pp-fg:#231c17;--pp-fgMuted:#5e5247}\n"
)


def test_filename_css_breakout_is_rejected(tmp_path: Path):
    for name in (_ORNAMENT_REPRO, _FONT_REPRO):
        files = _clone()
        files[name] = b"wOF2"
        with pytest.raises(ThemeError) as caught:
            validate_files(files)
        assert "file_type" in _codes(caught.value), name
        with pytest.raises(ThemeError) as caught:
            validate_zip(_zipped(files))
        assert "file_type" in _codes(caught.value), name
        root = tmp_path / name.replace("/", "-")
        _write_tree(root, files)
        with pytest.raises(ThemeError) as caught:
            validate_dir(root)
        assert "file_type" in _codes(caught.value), name


def test_manifest_paths_must_match_the_schema():
    ornament = _clone()
    text = ornament["theme.toml"].decode("utf-8")
    ornament["theme.toml"] = text.replace(
        'divider = "assets/ornaments/meander.svg"',
        'divider = "assets/ornaments/../meander.svg"',
    ).encode("utf-8")
    with pytest.raises(ThemeError) as caught:
        validate_files(ornament)
    assert "file_type" in _codes(caught.value)

    font = _clone()
    text = font["theme.toml"].decode("utf-8")
    font["theme.toml"] = text.replace(
        'path = "assets/fonts/Inter.woff2"',
        "path = 'assets/fonts/not a font.woff2'",
    ).encode("utf-8")
    with pytest.raises(ThemeError) as caught:
        validate_files(font)
    assert "font_format" in _codes(caught.value)

    color = _clone()
    text = color["theme.toml"].decode("utf-8")
    color["theme.toml"] = text.replace('bg = "#f6f1e7"', 'bg = "red"', 1).encode("utf-8")
    with pytest.raises(ThemeError) as caught:
        validate_files(color)
    assert "bad_color" in _codes(caught.value)

    preview = _clone()
    preview["assets/not-a-preview.png"] = b"\x89PNG\r\n\x1a\n"
    with pytest.raises(ThemeError) as caught:
        validate_files(preview)
    assert "file_type" in _codes(caught.value)


def test_system_mode_uses_the_checked_tokens():
    files = _clone()
    files["theme.css"] = _CONTRAST_REPRO.encode("utf-8")
    package = validate_files(files)
    css = render_css(package, package_hash(package.files))
    compact = re.sub(r"\s+", "", css)
    assert compact.count(":root{") == 1
    assert "data-mode=light" not in css
    assert ".pp-approval" not in css
    states = {
        ("light", "light"): "light",
        ("dark", "dark"): "dark",
        ("system", "light"): "light",
        ("system", "dark"): "dark",
    }
    for (mode, scheme), which in states.items():
        values = _effective_colors(css, mode, scheme)
        colors = {name: values[name] for name in package.modes[which]}
        assert colors == package.modes[which], (mode, scheme)
        assert contrast_modes({which: colors}, "AA") == [], (mode, scheme)
    system_light = _effective_colors(css, "system", "light")
    assert system_light["fg"].lower() != "#f6f1e7"


def test_unquoted_package_urls_are_rewritten_and_breakouts_are_dropped():
    files = _clone()
    files["theme.css"] = (
        b".pp-divider { background-image: url(assets/ornaments/meander.svg); }\n"
        b".pp-header-band { background-image: url(./assets/ornaments/laurel.svg); }\n"
        b'.pp-ornament-rule { background-image: url("assets/ornaments/meander.svg"); }\n'
    )
    package = validate_files(files)
    digest = package_hash(package.files)
    rendered = render_css(package, digest)
    prefix = f"/themes/{package.theme_id}/{digest}/assets/ornaments/"
    assert f'url("{prefix}meander.svg")' in rendered
    assert f'url("{prefix}laurel.svg")' in rendered
    assert "url(assets/" not in rendered
    assert "url(./assets/" not in rendered

    shared = dict(package.shared)
    shared["ornamentHeader"] = 'url("x");} .pp-approval{display:none} :root{--z:url("y.svg")'
    escaped = render_css(replace(package, shared=shared), digest)
    assert ".pp-approval" not in escaped
    assert "display:none" not in escaped
    assert '");}' not in escaped
    face = FontFace(
        "Inter",
        "sans-serif",
        _FONT_REPRO,
        "400",
        "normal",
    )
    fonts = render_css(replace(package, font_faces=(face,)), digest)
    assert "html::after" not in fonts
    assert "z-index" not in fonts


def test_decorative_lengths_are_capped():
    good = _clone()
    good["theme.css"] = (
        b".pp-header-band { border-bottom: 16px solid #7a1f1f; "
        b"box-shadow: 0 0 4px 0 #7a1f1f; background: 0 0/16px; }\n"
    )
    package = validate_files(good)
    rendered = render_css(package, package_hash(package.files))
    assert "16px" in rendered
    assert "0 0/16px" in rendered or "0 0 / 16px" in rendered
    refused = {
        "wide": ".pp-header-band { border-bottom: 3000px solid #7a1f1f; }\n",
        "viewport": ".pp-header-band { background-size: 100vh; }\n",
        "calc": ".pp-header-band { letter-spacing: calc(2px); }\n",
        "var": ".pp-header-band { border-radius: var(--pp-radius); }\n",
        "negative": ".pp-header-band { letter-spacing: -2px; }\n",
        "percent": ".pp-header-band { background-position: 50%; }\n",
        "shorthand": ".pp-header-band { background: 0 0/9999px; }\n",
    }
    expected = {
        "wide": "css_property",
        "viewport": "css_property",
        "calc": "css_rejected",
        "var": "css_rejected",
        "negative": "css_property",
        "percent": "css_property",
        "shorthand": "css_property",
    }
    for name, css in refused.items():
        files = _clone()
        files["theme.css"] = css.encode("utf-8")
        with pytest.raises(ThemeError) as caught:
            validate_files(files)
        assert expected[name] in _codes(caught.value), name


def test_svg_external_references_are_rejected_and_clean_svg_is_stable():
    external = _clone()
    external["assets/ornaments/meander.svg"] = (
        b'<svg xmlns="http://www.w3.org/2000/svg">'
        b'<path fill="url(https://evil.test/a)" d="M0 0 H1"/></svg>'
    )
    with pytest.raises(ThemeError) as caught:
        validate_files(external)
    assert "svg_rejected" in _codes(caught.value)

    sheet = _clone()
    sheet["assets/ornaments/meander.svg"] = (
        b'<?xml-stylesheet href="https://evil.test/a.css"?>'
        b'<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0 H1"/></svg>'
    )
    with pytest.raises(ThemeError) as caught:
        validate_files(sheet)
    assert "svg_rejected" in _codes(caught.value)

    encoded = _clone()
    encoded["assets/ornaments/meander.svg"] = (
        b'<svg xmlns="http://www.w3.org/2000/svg">'
        b'<path fill="java&#115;cript:alert(1)" d="M0 0 H1"/></svg>'
    )
    with pytest.raises(ThemeError) as caught:
        validate_files(encoded)
    assert "svg_rejected" in _codes(caught.value)

    local = _clone()
    local["assets/ornaments/meander.svg"] = (
        b'<svg xmlns="http://www.w3.org/2000/svg"><defs>'
        b'<linearGradient id="g"><stop offset="0" stop-color="#111111"/></linearGradient>'
        b'</defs><rect width="4" height="4" fill="url(#g)"/></svg>'
    )
    accepted = validate_files(local)
    assert b"url(#g)" in accepted.files["assets/ornaments/meander.svg"]

    raw = (_BUILTIN / "smf.praxis" / "assets/ornaments/meander.svg").read_bytes()
    once, issue = check_svg("assets/ornaments/meander.svg", raw)
    assert issue is None
    twice, again = check_svg("assets/ornaments/meander.svg", once)
    assert again is None
    assert once == twice
    assert once.startswith(b"<?xml")


def test_svg_css_escaped_paint_urls_are_rejected():
    paints = [
        r'fill="u\72l(https://evil.example/x#p)"',
        r'fill="\75 rl(https://evil.example/x#p)"',
        r'stroke="ur\6c(https://evil.example/x#p)"',
        'fill="URL(https://evil.example/x#p)"',
        'fill="uRl(https://evil.example/x#p)"',
        'fill="url( https://evil.example/x )"',
        'fill="url(/*x*/https://evil.example/x)"',
        'stroke="url( /* c */ https://evil.example/x#p )"',
        'fill="image-set(url(https://evil.example/x) 1x)"',
        'fill="SRC(https://evil.example/x)"',
        "fill=\"@import 'https://evil.example/x'\"",
    ]
    for paint in paints:
        _reject_svg(f'<path {paint} d="M0 0 H1"/>', paint)

    allowed, issue = check_svg(
        "assets/ornaments/meander.svg",
        b'<svg xmlns="http://www.w3.org/2000/svg"><defs>'
        b'<linearGradient id="id"><stop offset="0" stop-color="#111111"/></linearGradient>'
        b'</defs><rect width="4" height="4" fill="url( &quot;#id&quot; )"/></svg>',
    )
    assert issue is None
    assert b"#id" in allowed


def test_svg_root_must_be_in_the_svg_namespace():
    refused = [
        b'<svg xmlns="http://www.w3.org/1999/xhtml"><path d="M0 0 H1"/></svg>',
        b'<svg><path d="M0 0 H1"/></svg>',
        b'<html xmlns="http://www.w3.org/1999/xhtml">'
        b'<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0 H1"/></svg></html>',
        b'<svg xmlns="http://www.w3.org/2000/svg">'
        b'<g xmlns="http://www.w3.org/1999/xhtml"><rect width="1" height="1"/></g></svg>',
        b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:e="http://evil.example/" e:fill="#111">'
        b'<path d="M0 0 H1"/></svg>',
    ]
    for blob in refused:
        _issue = check_svg("assets/ornaments/meander.svg", blob)[1]
        assert _issue is not None and _issue.code == "svg_rejected", blob

    allowed, issue = check_svg(
        "assets/ornaments/meander.svg",
        b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
        b'<use xlink:href="#a"/></svg>',
    )
    assert issue is None
    assert b"#a" in allowed


def test_preview_images_are_fixed_names_with_magic_bytes():
    png = b"\x89PNG\r\n\x1a\n"
    webp = b"RIFF\x04\x00\x00\x00WEBP"
    package = _clone()
    package["assets/preview.png"] = png
    accepted = validate_files(package)
    assert accepted.files["assets/preview.png"] == png
    css = render_css(accepted, package_hash(accepted.files))
    assert "preview.png" not in css
    assert "preview.webp" not in css

    web = _clone()
    web["assets/preview.webp"] = webp
    assert validate_files(web).files["assets/preview.webp"] == webp

    mismatched = _clone()
    mismatched["assets/preview.png"] = webp
    with pytest.raises(ThemeError) as caught:
        validate_files(mismatched)
    assert "file_type" in _codes(caught.value)

    swapped = _clone()
    swapped["assets/preview.webp"] = png
    with pytest.raises(ThemeError) as caught:
        validate_files(swapped)
    assert "file_type" in _codes(caught.value)

    for name in (
        "assets/preview.jpg",
        "assets/preview.jpeg",
        "assets/Preview.png",
        "assets/gallery.png",
        "assets/preview.png.bak",
        "preview.png",
    ):
        other = _clone()
        other[name] = png
        with pytest.raises(ThemeError) as caught:
            validate_files(other)
        assert "file_type" in _codes(caught.value), name

    huge = _clone()
    huge["assets/preview.png"] = png + b"\x00" * MAX_PREVIEW_BYTES
    with pytest.raises(ThemeError) as caught:
        validate_files(huge)
    assert "file_too_large" in _codes(caught.value)

    styled = _clone()
    styled["assets/preview.png"] = png
    styled["theme.css"] = b'.pp-divider { background-image: url("assets/preview.png"); }\n'
    with pytest.raises(ThemeError) as caught:
        validate_files(styled)
    assert "css_url" in _codes(caught.value)


def _reject_svg(inner: str, label: str) -> None:
    blob = ('<svg xmlns="http://www.w3.org/2000/svg">' + inner + "</svg>").encode("utf-8")
    _issue = check_svg("assets/ornaments/meander.svg", blob)[1]
    assert _issue is not None and _issue.code == "svg_rejected", label


def test_damaged_and_duplicate_zips_are_rejected():
    stored = _stored_zip("theme.toml", b"id = 1\n")
    blob = bytearray(stored)
    blob[_data_offset(blob)] ^= 0xFF
    with pytest.raises(ThemeError) as caught:
        validate_zip(bytes(blob))
    assert "zip_invalid" in _codes(caught.value)
    assert "damaged" in str(caught.value)

    renamed = bytearray(stored)
    renamed[30] = ord("T")
    with pytest.raises(ThemeError) as caught:
        validate_zip(bytes(renamed))
    assert "zip_invalid" in _codes(caught.value)

    deflated = bytearray(
        _stored_zip(
            "theme.toml",
            b"abcdefghijklmnopqrstuvwxyz" * 30,
            method=zipfile.ZIP_DEFLATED,
        )
    )
    deflated[_data_offset(deflated) + 1] ^= 0xFF
    with pytest.raises(ThemeError) as caught:
        validate_zip(bytes(deflated))
    assert "zip_invalid" in _codes(caught.value)

    with pytest.raises(ThemeError) as caught:
        validate_zip(b"this is not a zip")
    assert "zip_invalid" in _codes(caught.value)

    duplicate = io.BytesIO()
    with zipfile.ZipFile(duplicate, "w") as archive:
        archive.writestr("theme.toml", b"a = 1\n")
        archive.writestr("theme.toml", b"b = 2\n")
    with pytest.raises(ThemeError) as caught:
        validate_zip(duplicate.getvalue())
    assert "zip_duplicate" in _codes(caught.value)

    collapsed = io.BytesIO()
    with zipfile.ZipFile(collapsed, "w") as archive:
        archive.writestr("assets/fonts/OFL.txt", b"license\n")
        archive.writestr("assets/fonts/./OFL.txt", b"other\n")
    with pytest.raises(ThemeError) as caught:
        validate_zip(collapsed.getvalue())
    assert "zip_duplicate" in _codes(caught.value)


def test_translucent_page_colours_are_refused():
    files = _clone("lab.glass")
    text = files["theme.toml"].decode("utf-8").replace('bg = "#14110f"', 'bg = "#14110f10"', 1)
    files["theme.toml"] = text.encode("utf-8")
    with pytest.raises(ThemeError) as caught:
        validate_files(files)
    opaque = [issue.message for issue in caught.value.issues]
    assert any("must be fully opaque" in message and "bg" in message for message in opaque)

    for token in ("bg", "bgRaised", "codeBg"):
        issues = contrast_modes({"dark": {token: "#14110f10"}}, "AA")
        messages = [issue.message for issue in issues]
        assert any("must be fully opaque" in message and token in message for message in messages)

    # Dark ink on a nearly clear latte swatch. Over white this clears 4.5:1.
    # Over a black page it does not, and the validator has to use the worse one.
    ink = "#3f425b"
    wash = "#eff1f510"
    assert contrast_ratio(ink, wash) >= 4.5
    issues = contrast_modes({"dark": {"accent": wash, "accentFg": ink}}, "AA")
    assert any("accentFg" in issue.message and "accent" in issue.message for issue in issues)

    # selection is drawn on bg, so a translucent white highlight on a dark page
    # stays dark and light text still clears.
    glass = _clone("lab.selection")
    sheet = glass["theme.toml"].decode("utf-8")
    sheet = sheet.replace("[tokens.dark]\n", '[tokens.dark]\nselection = "#ffffff20"\n', 1)
    glass["theme.toml"] = sheet.encode("utf-8")
    package = validate_files(glass)
    assert package.modes["dark"]["selection"] == "#ffffff20"


def test_omarchy_live_id_cannot_be_installed(tmp_path: Path):
    files = _clone("omarchy.live")
    with pytest.raises(ThemeError) as caught:
        install_files(files, tmp_path)
    assert caught.value.issues[0].code == "bad_id"
    assert "omarchy.live" in caught.value.issues[0].message


def test_smf_namespace_cannot_shadow_a_builtin(tmp_path: Path):
    files = read_builtin_files("smf.praxis")
    with pytest.raises(ThemeError) as caught:
        install_files(files, tmp_path)
    assert "bad_id" in _codes(caught.value)
    exact = _clone("smf")
    with pytest.raises(ThemeError) as caught:
        install_files(exact, tmp_path)
    assert "bad_id" in _codes(caught.value)

    dest = tmp_path / "themes" / "smf.praxis" / "1.0.0"
    _write_tree(dest, files)
    found = find_theme(tmp_path, "smf.praxis")
    assert found is not None
    assert found.source == "builtin"
    listed = list_themes(tmp_path)
    assert all(item.source != "user" or item.package.theme_id != "smf.praxis" for item in listed)


def test_lock_mismatch_is_not_listed_or_servable(tmp_path: Path):
    installed = install_files(_clone("lab.lock"), tmp_path)
    assert installed.root is not None
    assert files_match_lock(installed, installed.package_hash)
    readme = installed.root / "THEME.md"
    readme.write_bytes(readme.read_bytes() + b"\n")
    assert files_match_lock(installed, installed.package_hash) is False
    assert all(item.package.theme_id != "lab.lock" for item in list_themes(tmp_path))
    with pytest.raises(ValueError):
        verify_lock(read_dir(installed.root), "lab.lock", "1.0.0")

    plain = tmp_path / "themes" / "lab.plain" / "1.0.0"
    _write_tree(plain, _clone("lab.plain"))
    assert all(item.package.theme_id != "lab.plain" for item in list_themes(tmp_path))


def test_stale_and_failed_stages_are_removed(tmp_path: Path):
    package = validate_files(_clone("lab.stage"))
    digest = stage_theme(package, tmp_path)
    root = tmp_path / "theme-stage"
    (root / f"{digest}.time").write_text("0", encoding="utf-8")
    sweep_stages(tmp_path)
    assert not (root / digest).exists()

    fresh = stage_theme(package, tmp_path)
    toml = root / fresh / "theme.toml"
    toml.write_text("not toml", encoding="utf-8")
    staged = take_stage(fresh, tmp_path)
    assert staged is not None
    with pytest.raises(ThemeError):
        try:
            install_files(staged, tmp_path)
        except Exception:
            discard_stage(fresh, tmp_path)
            raise
    assert not (root / fresh).exists()

    done = stage_theme(validate_files(_clone("lab.done")), tmp_path)
    committed = take_stage(done, tmp_path)
    assert committed is not None
    install_files(committed, tmp_path)
    discard_stage(done, tmp_path)
    assert not (root / done).exists()


def test_cli_remove_writes_an_audit_row(tmp_path: Path):
    data = tmp_path / "data"
    create_profile(data, "default")
    db = StateDB(data / "prime.db")
    db.close()
    installed = install_files(_clone("lab.audit"), data)
    parser = build_parser()
    remove = parser.parse_args(["theme", "remove", "lab.audit", "--data-dir", str(data)])
    assert dispatch_theme(remove) == 0
    db = StateDB(data / "prime.db")
    try:
        row = db.conn.execute(
            "SELECT payload_json FROM audit_events WHERE kind = 'theme.remove'"
        ).fetchone()
    finally:
        db.close()
    assert row is not None
    payload = json.loads(row["payload_json"])
    assert payload["id"] == "lab.audit"
    assert payload["version"] == "1.0.0"
    assert payload["packageHash"] == installed.package_hash


def _write_tree(root: Path, files: dict[str, bytes]) -> None:
    for name, payload in files.items():
        path = root.joinpath(*name.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


def _stored_zip(name: str, payload: bytes, *, method: int = zipfile.ZIP_STORED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo(filename=name, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = method
        archive.writestr(info, payload)
    return buffer.getvalue()


def _data_offset(blob: bytearray | bytes) -> int:
    name_len, extra_len = struct.unpack_from("<HH", blob, 26)
    return 30 + name_len + extra_len


def _effective_colors(css: str, mode: str, scheme: str) -> dict[str, str]:
    rules = tinycss2.parse_stylesheet(css, skip_comments=True, skip_whitespace=True)
    winning: dict[str, tuple[int, str]] = {}

    def consider(prelude: str, content: list[object], active: bool) -> None:
        if not active:
            return
        spec = _match_spec(prelude, mode)
        if spec is None:
            return
        declarations = tinycss2.parse_declaration_list(
            content, skip_comments=True, skip_whitespace=True
        )
        for item in declarations:
            if getattr(item, "type", "") != "declaration":
                continue
            name = str(getattr(item, "name", ""))
            if not name.startswith("--pp-"):
                continue
            value = tinycss2.serialize(getattr(item, "value", [])).strip()
            current = winning.get(name)
            if current is None or spec >= current[0]:
                winning[name] = (spec, value)

    def walk(nodes: list[object], scheme_ok: bool) -> None:
        for rule in nodes:
            if isinstance(rule, AtRule):
                compact = re.sub(r"\s+", "", tinycss2.serialize(rule.prelude))
                if "prefers-reduced-motion" in compact:
                    continue
                nested_ok = scheme_ok
                if "prefers-color-scheme:light" in compact:
                    nested_ok = scheme == "light"
                elif "prefers-color-scheme:dark" in compact:
                    nested_ok = scheme == "dark"
                nested = tinycss2.parse_rule_list(
                    rule.content, skip_comments=True, skip_whitespace=True
                )
                walk(nested, nested_ok)
            elif isinstance(rule, QualifiedRule):
                consider(tinycss2.serialize(rule.prelude), rule.content, scheme_ok)

    walk(rules, True)
    return {name.removeprefix("--pp-"): value for name, (_spec, value) in winning.items()}


def _match_spec(prelude: str, mode: str) -> int | None:
    best: int | None = None
    for part in prelude.split(","):
        text = re.sub(r"\s+", "", part)
        if not text:
            continue
        found = re.findall(
            r"""data-mode=(?:"([^"]+)"|'([^']+)'|([A-Za-z]+))""",
            text,
        )
        named = [left or middle or right for left, middle, right in found]
        if named and mode not in named:
            continue
        if ":root" not in text and not named:
            continue
        score = (1 if ":root" in text else 0) + text.count("[")
        if best is None or score > best:
            best = score
    return best
