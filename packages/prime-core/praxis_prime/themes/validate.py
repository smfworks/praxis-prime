"""Validate a praxis.theme/v1 package.

The same checks run for ``theme lint``, install, and the stylesheet route.
A failure is a ``ThemeError`` whose ``issues`` are safe to print as JSON.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Mapping

from praxis_prime.themes.archive import _check_layout, read_dir, read_zip
from praxis_prime.themes.color import contrast_ratio, parse_color
from praxis_prime.themes.css_restrict import check_theme_css
from praxis_prime.themes.errors import ThemeError, ThemeIssue
from praxis_prime.themes.model import FontFace, ThemePackage
from praxis_prime.themes.svg import check_svg
from praxis_prime.themes.tokens import (
    COLOR_TOKENS,
    CONTRAST_PAIRS,
    DENSITIES,
    FONT_LICENSES,
    MODES,
    MOTIONS,
    PACKAGE_LICENSES,
    REQUIRED_COLORS,
    SCHEMA,
    complete_colors,
    thresholds,
)

_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_FAMILY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
_WEIGHT = re.compile(r"^[1-9]00(?: [1-9]00)?$")
_WOFF2 = b"wOF2"
_PNG = b"\x89PNG\r\n\x1a\n"
_OFL_MARK = "SIL Open Font License"

_SHAPE_DEFAULTS: dict[str, object] = {
    "scale": 1.25,
    "baseSize": 16,
    "lineHeight": 1.5,
    "radius": 6,
    "density": "cozy",
    "borderWidth": 1,
    "motion": "subtle",
}


def validate_files(files: Mapping[str, bytes]) -> ThemePackage:
    """Validate an in-memory package. ``theme.lock.json`` is ignored."""
    cleaned = {path: payload for path, payload in files.items() if path != "theme.lock.json"}
    _check_layout(cleaned)
    issues: list[ThemeIssue] = []
    toml_text = _text(cleaned, "theme.toml", issues)
    readme = _text(cleaned, "THEME.md", issues)
    license_text = _text(cleaned, "LICENSE", issues)
    if "LICENSE" not in cleaned and "LICENSE.txt" in cleaned:
        license_text = _text(cleaned, "LICENSE.txt", issues)
    if not license_text.strip():
        issues.append(
            _fix(
                "missing_file",
                "A LICENSE file is required.",
                "LICENSE",
                "Add an MIT, Apache-2.0, CC-BY-4.0, or CC0-1.0 LICENSE file.",
            )
        )
    if not readme.strip():
        issues.append(_fix("missing_file",
            "THEME.md is required.",
            "THEME.md",
            "Describe the theme."))
    parsed: dict[str, object] = {}
    if toml_text:
        try:
            loaded = tomllib.loads(toml_text)
        except tomllib.TOMLDecodeError as exc:
            issues.append(_fix("schema",
                f"theme.toml is not valid TOML ({exc}).",
                "theme.toml",
                "Fix the TOML."))
            loaded = {}
        if not isinstance(loaded, dict):
            loaded = {}
        parsed = loaded
    if issues and not parsed:
        raise ThemeError(issues[0].message, tuple(issues))
    meta = _meta(parsed, issues)
    faces = _fonts(parsed, cleaned, issues)
    shared = _shared(parsed, cleaned, issues)
    modes = _modes(parsed, meta["contrast"], issues)
    extra = _css(cleaned, modes, shared, meta["contrast"], issues)
    _binaries(cleaned, issues)
    if issues:
        raise ThemeError(issues[0].message, tuple(issues))
    return ThemePackage(
        theme_id=meta["id"],
        name=meta["name"],
        version=meta["version"],
        license=meta["license"],
        description=meta["description"],
        author=meta["author"],
        min_praxis=meta["min_praxis"],
        contrast=meta["contrast"],
        modes=modes,
        shared=shared,
        font_faces=tuple(faces),
        files=dict(cleaned),
        extra_css=extra,
    )


def validate_dir(path) -> ThemePackage:
    from pathlib import Path

    return validate_files(read_dir(Path(path)))


def validate_zip(data: bytes) -> ThemePackage:
    return validate_files(read_zip(data))


def _meta(parsed: Mapping[str, object], issues: list[ThemeIssue]) -> dict[str, str]:
    schema = parsed.get("schema", "")
    if schema != SCHEMA:
        issues.append(
            _fix("schema", f"schema must be {SCHEMA}.", "schema", f'Set schema = "{SCHEMA}".')
        )
    theme_id = _short(parsed.get("id"), "id", issues, pattern=_ID)
    version = _short(parsed.get("version"), "version", issues, pattern=_VERSION)
    license_name = _short(parsed.get("license"), "license", issues)
    if license_name and license_name not in PACKAGE_LICENSES:
        issues.append(
            _fix(
                "bad_license",
                "license must be MIT, Apache-2.0, CC-BY-4.0, or CC0-1.0.",
                "license",
                "Pick one of those SPDX identifiers.",
            )
        )
    contrast = str(parsed.get("contrast", "AA") or "AA")
    if contrast not in {"AA", "AAA"}:
        issues.append(_fix("schema",
            "contrast must be AA or AAA.",
            "contrast",
            'Use contrast = "AA".'))
        contrast = "AA"
    return {
        "id": theme_id,
        "name": _short(parsed.get("name"), "name", issues, limit=80) or theme_id,
        "version": version or "0.0.0",
        "license": license_name,
        "description": _short(parsed.get("description"), "description", issues, limit=400),
        "author": _authors(parsed, issues),
        "min_praxis": _short(parsed.get("min_praxis", "0.1.0"),
            "min_praxis",
            issues,
            required=False)
        or "0.1.0",
        "contrast": contrast,
    }


def _fonts(
    parsed: Mapping[str, object],
    files: Mapping[str, bytes],
    issues: list[ThemeIssue],
) -> list[FontFace]:
    fonts = parsed.get("fonts", {})
    if fonts is None:
        fonts = {}
    if not isinstance(fonts, dict):
        issues.append(_fix("schema", "fonts must be a table.", "fonts", "Use [fonts.display]."))
        return []
    faces: list[FontFace] = []
    referenced: set[str] = set()
    needs_ofl = False
    defaults = (("display", "serif"), ("body", "sans-serif"), ("mono", "monospace"))
    for slot, fallback_default in defaults:
        table = fonts.get(slot, {})
        if table in (None, {}):
            faces.append(FontFace(fallback_default, fallback_default, "", "400", "normal"))
            continue
        if not isinstance(table, dict):
            issues.append(_fix("schema",
                f"fonts.{slot} must be a table.",
                f"fonts.{slot}",
                "Use a table."))
            continue
        family = _short(table.get("family"), f"fonts.{slot}.family", issues, pattern=_FAMILY)
        fallback = _font_fallback(
            table.get("fallback", fallback_default),
            fallback_default,
            f"fonts.{slot}.fallback",
            issues,
        )
        spdx = str(table.get("license", "OFL-1.1"))
        entries = table.get("files", [])
        if entries in (None, []):
            faces.append(FontFace(family or fallback, fallback, "", "400", "normal"))
            continue
        if spdx not in FONT_LICENSES:
            issues.append(
                _fix(
                    "font_license",
                    f"Font license {spdx} is not allowlisted.",
                    f"fonts.{slot}.license",
                    "Use OFL-1.1, Apache-2.0, MIT, CC0-1.0, or Ubuntu-font-1.0.",
                )
            )
        if not isinstance(entries, list):
            issues.append(_fix("schema",
                "font files must be an array.",
                f"fonts.{slot}.files",
                "Use an array."))
            continue
        for entry in entries:
            path, weight, style = _font_entry(slot, entry, issues)
            if not path:
                continue
            referenced.add(path)
            payload = files.get(path)
            if payload is None:
                issues.append(
                    _fix("asset_missing", f"Missing font file {path}.", path, "Add the WOFF2 file.")
                )
                continue
            if not payload.startswith(_WOFF2):
                issues.append(
                    _fix("font_magic", f"{path} is not a WOFF2 font.", path, "Subset a WOFF2 file.")
                )
            faces.append(FontFace(family or fallback, fallback, path, weight, style))
        if spdx == "OFL-1.1":
            needs_ofl = True
    if needs_ofl:
        _require_ofl(files, issues)
    for path in files:
        if path.startswith("assets/fonts/") and path.endswith(".woff2") and path not in referenced:
            issues.append(
                _fix(
                    "font_format",
                    f"{path} is not declared in theme.toml.",
                    path,
                    "Add it to a fonts.*.files list or remove it.",
                )
            )
    return faces


def _font_entry(slot: str, entry: object, issues: list[ThemeIssue]) -> tuple[str, str, str]:
    if isinstance(entry, str):
        return entry, "400", "normal"
    if not isinstance(entry, dict):
        issues.append(_fix("schema",
            "A font file must be a string or a table.",
            f"fonts.{slot}",
            "Fix files."))
        return "", "400", "normal"
    path = entry.get("path", "")
    if not isinstance(path, str) or not path.endswith(".woff2"):
        issues.append(
            _fix("font_format",
                "Bundled fonts must be .woff2.",
                f"fonts.{slot}",
                "Point path at a .woff2 file.")
        )
        return "", "400", "normal"
    weight = str(entry.get("weight", "400"))
    style = str(entry.get("style", "normal"))
    if not _WEIGHT.fullmatch(weight):
        issues.append(_fix("schema",
            f"Bad font weight {weight}.",
            f"fonts.{slot}",
            'Use "400" or "400 900".'))
        weight = "400"
    if style not in {"normal", "italic"}:
        issues.append(_fix("schema",
            "Font style must be normal or italic.",
            f"fonts.{slot}",
            'Use style = "normal".'))
        style = "normal"
    return path, weight, style


def _require_ofl(files: Mapping[str, bytes], issues: list[ThemeIssue]) -> None:
    for candidate in ("assets/fonts/OFL.txt", "OFL.txt"):
        payload = files.get(candidate)
        if payload is None:
            continue
        try:
            text = payload.decode("utf-8")
        except UnicodeError:
            issues.append(_fix("font_license",
                f"{candidate} must be UTF-8.",
                candidate,
                "Save OFL.txt as UTF-8."))
            return
        if _OFL_MARK not in text:
            issues.append(
                _fix(
                    "font_license",
                    "OFL.txt must contain the SIL Open Font License text.",
                    candidate,
                    "Copy the upstream OFL.txt next to the fonts.",
                )
            )
        return
    issues.append(
        _fix(
            "font_license",
            "Bundled OFL fonts need OFL.txt.",
            "assets/fonts/OFL.txt",
            "Add the SIL Open Font License text beside the WOFF2 files.",
        )
    )


def _shared(
    parsed: Mapping[str, object],
    files: Mapping[str, bytes],
    issues: list[ThemeIssue],
) -> dict[str, str]:
    shape = parsed.get("shape", {})
    if shape is None:
        shape = {}
    if not isinstance(shape, dict):
        issues.append(_fix("schema", "shape must be a table.", "shape", "Use [shape]."))
        shape = {}
    ornaments = parsed.get("ornaments", {})
    if ornaments is None:
        ornaments = {}
    if not isinstance(ornaments, dict):
        issues.append(_fix("schema", "ornaments must be a table.", "ornaments", "Use [ornaments]."))
        ornaments = {}
    values = dict(_SHAPE_DEFAULTS)
    values.update(shape)
    shared: dict[str, str] = {}
    scale = _float(values.get("scale"), "shape.scale", 1.125, 1.333, issues)
    base = _float(values.get("baseSize"), "shape.baseSize", 15, 18, issues)
    leading = _float(values.get("lineHeight"), "shape.lineHeight", 1.2, 2.0, issues)
    radius = _float(values.get("radius"), "shape.radius", 0, 16, issues)
    border = _float(values.get("borderWidth"), "shape.borderWidth", 1, 4, issues)
    density = str(values.get("density", "cozy"))
    motion = str(values.get("motion", "subtle"))
    if density not in DENSITIES:
        issues.append(_fix("schema",
            "density must be compact, cozy, or comfortable.",
            "shape.density",
            "Pick one."))
        density = "cozy"
    if motion not in MOTIONS:
        issues.append(_fix("schema",
            "motion must be none, subtle, or standard.",
            "shape.motion",
            "Pick one."))
        motion = "subtle"
    shared["scale"] = _trim(scale)
    shared["baseSize"] = f"{_trim(base)}px"
    shared["lineHeight"] = _trim(leading)
    shared["radius"] = f"{_trim(radius)}px"
    shared["borderWidth"] = f"{_trim(border)}px"
    shared["density"] = density
    shared["motion"] = motion
    fonts = parsed.get("fonts") if isinstance(parsed.get("fonts"), dict) else {}
    assert isinstance(fonts, dict)
    for slot, token, generic in (
        ("display", "fontDisplay", "serif"),
        ("body", "fontBody", "sans-serif"),
        ("mono", "fontMono", "monospace"),
    ):
        table = fonts.get(slot, {}) if isinstance(fonts.get(slot), dict) else {}
        assert isinstance(table, dict)
        family = str(table.get("family") or generic)
        fallback = str(table.get("fallback") or generic)
        shared[token] = _font_css(family, fallback)
    for key, token in (
        ("header", "ornamentHeader"),
        ("divider", "ornamentDivider"),
        ("watermark", "watermark"),
    ):
        raw = ornaments.get(key, "")
        if raw in ("", None):
            shared[token] = "none"
            continue
        if not isinstance(raw, str) or raw not in files:
            issues.append(
                _fix("asset_missing",
                    f"Missing ornament {raw}.",
                    f"ornaments.{key}",
                    "Point at a package file.")
            )
            shared[token] = "none"
            continue
        shared[token] = f'url("{raw}")'
    opacity = _float(ornaments.get("watermarkOpacity", 0),
        "ornaments.watermarkOpacity",
        0,
        0.06,
        issues)
    shared["watermarkOpacity"] = _trim(opacity)
    return shared


def _modes(
    parsed: Mapping[str, object],
    level: str,
    issues: list[ThemeIssue],
) -> dict[str, dict[str, str]]:
    raw_modes, label = _palette_tables(parsed)
    if raw_modes is None:
        issues.append(
            _fix(
                "schema",
                "tokens.light and tokens.dark are required.",
                "tokens",
                "Add [tokens.light] and [tokens.dark]. [modes.light] is the same shape.",
            )
        )
        return {}
    ready: dict[str, dict[str, str]] = {}
    for mode in MODES:
        table = raw_modes.get(mode)
        if not isinstance(table, dict):
            issues.append(
                _fix("schema",
                    f"{label}.{mode} is required.",
                    f"{label}.{mode}",
                    "Add the colour table.")
            )
            continue
        colors: dict[str, str] = {}
        unknown = [key for key in table if key not in COLOR_TOKENS]
        for key in unknown:
            issues.append(
                _fix(
                    "schema",
                    f"Unknown token {key}.",
                    f"{label}.{mode}.{key}",
                    "Remove it or rename it to a --pp-* token.",
                )
            )
        for name in COLOR_TOKENS:
            if name not in table:
                continue
            value = table[name]
            if not isinstance(value, str):
                issues.append(
                    _fix(
                        "bad_color",
                        f"{name} must be a colour string.",
                        f"{label}.{mode}.{name}",
                        "Use #rrggbb or oklch().",
                    )
                )
                continue
            try:
                colors[name] = parse_color(value).to_hex()
            except ValueError as exc:
                issues.append(
                    _fix(
                        "bad_color",
                        f"{mode} {name} is not a colour ({exc}).",
                        f"{label}.{mode}.{name}",
                        "Use #rrggbb or oklch().",
                    )
                )
        missing = [name for name in REQUIRED_COLORS if name not in colors]
        if missing:
            issues.append(
                _fix(
                    "schema",
                    f"{label}.{mode} is missing {', '.join(missing)}.",
                    f"{label}.{mode}",
                    "Set every required colour.",
                )
            )
            continue
        try:
            ready[mode] = complete_colors(colors, level=level)
        except ValueError as exc:
            issues.append(
                _fix(
                    "contrast",
                    f"Could not derive {mode} colours ({exc}).",
                    f"{label}.{mode}",
                    "Adjust the required palette.",
                )
            )
    return ready


def _css(
    files: Mapping[str, bytes],
    modes: dict[str, dict[str, str]],
    shared: dict[str, str],
    level: str,
    issues: list[ThemeIssue],
) -> str:
    payload = files.get("theme.css")
    if payload is None:
        issues.extend(_contrast_at(modes, level))
        return ""
    try:
        text = payload.decode("utf-8")
    except UnicodeError:
        issues.append(_fix("css_rejected",
            "theme.css must be UTF-8.",
            "theme.css",
            "Save it as UTF-8."))
        return ""
    assets = set(files)
    report = check_theme_css(text, assets)
    issues.extend(report.issues)
    _apply_overlays(modes, shared, report.root, report.light, report.dark, issues)
    if not report.issues:
        issues.extend(_contrast_at(modes, level))
    return report.css


def _apply_overlays(
    modes: dict[str, dict[str, str]],
    shared: dict[str, str],
    root: dict[str, str],
    light: dict[str, str],
    dark: dict[str, str],
    issues: list[ThemeIssue],
) -> None:
    for name, value in root.items():
        token = name.removeprefix("--pp-")
        if token in COLOR_TOKENS:
            for mode in modes:
                modes[mode][token] = parse_color(value).to_hex()
        elif token in shared:
            shared[token] = value
    for mode, overlay in (("light", light), ("dark", dark)):
        colors = modes.get(mode)
        if colors is None:
            continue
        for name, value in overlay.items():
            token = name.removeprefix("--pp-")
            if token in COLOR_TOKENS:
                try:
                    colors[token] = parse_color(value).to_hex()
                except ValueError as exc:
                    issues.append(_fix("bad_color",
                        str(exc),
                        "theme.css",
                        "Use a hex or oklch() colour."))


def contrast_modes(modes: Mapping[str, Mapping[str, str]], level: str) -> list[ThemeIssue]:
    """Public contrast check. ``level`` is ``AA`` or ``AAA`` for every mode."""
    return _contrast_at(modes, level)


def _contrast_at(modes: Mapping[str, Mapping[str, str]], level: str) -> list[ThemeIssue]:
    issues: list[ThemeIssue] = []
    text_min, ui_min = thresholds(level)
    for mode, colors in modes.items():
        parsed = {name: parse_color(value) for name, value in colors.items()}
        for foreground, background, kind in CONTRAST_PAIRS:
            ratio = contrast_ratio(parsed[foreground], parsed[background])
            minimum = text_min if kind == "text" else ui_min
            if ratio + 1e-9 < minimum:
                issues.append(
                    _fix(
                        "contrast",
                        f"{mode} {foreground} on {background} is {ratio:.2f}:1, needs {minimum}:1.",
                        f"modes.{mode}.{foreground}",
                        f"Change {foreground} or {background} until the ratio clears {minimum}:1.",
                    )
                )
    return issues


def _webp(payload: bytes) -> bool:
    return len(payload) >= 12 and payload.startswith(b"RIFF") and payload[8:12] == b"WEBP"


def _binaries(files: Mapping[str, bytes], issues: list[ThemeIssue]) -> None:
    for path, payload in files.items():
        if path.endswith(".svg"):
            found = check_svg(path, payload)
            if found is not None:
                issues.append(found)
        elif path.endswith(".png") and not payload.startswith(_PNG):
            issues.append(_fix("file_type", f"{path} is not a PNG.", path, "Export a PNG."))
        elif path.endswith(".webp") and not _webp(payload):
            issues.append(_fix("file_type", f"{path} is not a WebP.", path, "Export a WebP."))


def _text(files: Mapping[str, bytes], name: str, issues: list[ThemeIssue]) -> str:
    payload = files.get(name)
    if payload is None:
        if name == "LICENSE":
            return ""
        issues.append(_fix("missing_file", f"{name} is required.", name, f"Add {name}."))
        return ""
    try:
        text = payload.decode("utf-8")
    except UnicodeError:
        issues.append(_fix("schema", f"{name} must be UTF-8.", name, "Save the file as UTF-8."))
        return ""
    if "\x00" in text:
        issues.append(_fix("schema", f"{name} contains a NUL byte.", name, "Remove the NUL."))
    return text


def _short(
    value: object,
    path: str,
    issues: list[ThemeIssue],
    *,
    pattern: re.Pattern[str] | None = None,
    limit: int = 64,
    required: bool = True,
) -> str:
    if value is None or value == "":
        if required:
            issues.append(_fix("schema", f"{path} is required.", path, f"Set {path}."))
        return ""
    if not isinstance(value, str):
        issues.append(_fix("schema", f"{path} must be a string.", path, "Use a string."))
        return ""
    text = value.strip()
    if len(text) > limit or any(ord(char) < 32 for char in text):
        issues.append(_fix("schema", f"{path} is empty or too long.", path, "Shorten it."))
        return ""
    if pattern is not None and not pattern.fullmatch(text):
        issues.append(_fix("bad_id" if path == "id" else "schema",
            f"{path} has an illegal value.",
            path,
            "Use the documented shape."))
        return ""
    return text


def _float(
    value: object,
    path: str,
    low: float,
    high: float,
    issues: list[ThemeIssue],
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        issues.append(_fix("schema",
            f"{path} must be a number.",
            path,
            f"Use a number from {low} to {high}."))
        return low
    number = float(value)
    if number < low or number > high:
        issues.append(_fix("schema",
            f"{path} must be between {low} and {high}.",
            path,
            "Pick a value in range."))
        return low
    return number


def _palette_tables(parsed: Mapping[str, object]) -> tuple[Mapping[str, object] | None, str]:
    """Author tables are ``[tokens.light]``. ``[modes.light]`` is the same shape."""
    tokens = parsed.get("tokens")
    if isinstance(tokens, dict) and any(isinstance(tokens.get(mode), dict) for mode in MODES):
        return tokens, "tokens"
    modes = parsed.get("modes")
    if isinstance(modes, dict):
        return modes, "modes"
    return None, "tokens"


def _authors(parsed: Mapping[str, object], issues: list[ThemeIssue]) -> str:
    raw = parsed.get("authors")
    if isinstance(raw, list):
        names: list[str] = []
        for index, item in enumerate(raw):
            if not isinstance(item, str) or not item.strip() or len(item) > 80:
                issues.append(
                    _fix(
                        "schema",
                        "Each author must be a short string.",
                        f"authors[{index}]",
                        "Use a name.",
                    )
                )
                continue
            names.append(item.strip())
        joined = ", ".join(names)
        if len(joined) > 200:
            issues.append(_fix("schema", "authors is too long.", "authors", "Shorten the list."))
            return ""
        return joined
    return _short(parsed.get("author"), "author", issues, limit=80, required=False)


def _font_fallback(value: object, default: str, path: str, issues: list[ThemeIssue]) -> str:
    if value in (None, ""):
        return default
    if not isinstance(value, str) or not _fallback_ok(value.strip()):
        issues.append(
            _fix(
                "schema",
                f"{path} has an illegal value.",
                path,
                "Use family names separated by commas. No url(), parentheses, or semicolons.",
            )
        )
        return default
    return value.strip()


def _fallback_ok(text: str) -> bool:
    lowered = text.lower()
    if "url(" in lowered or "expression(" in lowered:
        return False
    if any(char in text for char in "();\\\"'"):
        return False
    parts = [part.strip() for part in text.split(",")]
    if not parts or any(not part for part in parts):
        return False
    return all(_FAMILY.fullmatch(part) for part in parts)


_GENERICS = frozenset(
    {
        "serif",
        "sans-serif",
        "monospace",
        "ui-monospace",
        "ui-sans-serif",
        "ui-serif",
        "system-ui",
        "cursive",
        "fantasy",
    }
)


def _font_css(family: str, fallback: str) -> str:
    parts: list[str] = []
    for name in (family, *(part.strip() for part in fallback.split(","))):
        if name and name not in parts:
            parts.append(name)

    def piece(name: str) -> str:
        if name in _GENERICS:
            return name
        return '"' + name + '"'

    return ", ".join(piece(name) for name in parts)


def _trim(number: float) -> str:
    text = f"{number:.4f}".rstrip("0").rstrip(".")
    return text or "0"


def _fix(code: str, message: str, path: str, fix: str) -> ThemeIssue:
    return ThemeIssue(code=code, message=message, path=path, fix=fix)
