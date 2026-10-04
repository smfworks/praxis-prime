"""Map a legacy pack ``theme`` hint onto the default theme.

``accent``, ``panel`` (as ``bgRaised``), ``ok``, and ``warn`` override
``smf.praxis``. Each override is checked with the same contrast rules as an
installed theme. Lightness may move by at most 0.25 in OKLCH. Past that the
hint is refused and the pack still installs. A hint is not applied when the
selected theme is ``smf.praxis`` itself. Suggested built-ins that are not
installed yet (the other six themes, M3b) fall back through this path.

``packs install`` from the CLI also writes ``pack.<name>`` when the hint
passes. ``install_pack`` does not, so library callers stay free of that side
effect.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from praxis_prime.packs.catalog import SUGGESTED_THEMES
from praxis_prime.packs.model import ThemeHint
from praxis_prime.themes.color import best_ink, contrast_ratio, parse_color
from praxis_prime.themes.errors import ThemeError, ThemeIssue
from praxis_prime.themes.model import ThemePackage
from praxis_prime.themes.store import InstalledTheme, builtin_theme, find_theme, install_files
from praxis_prime.themes.tokens import CONTRAST_PAIRS, REQUIRED_COLORS, complete_colors, thresholds
from praxis_prime.themes.validate import contrast_modes, validate_files

_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


@dataclass(frozen=True, slots=True)
class HintResult:
    ok: bool
    theme_id: str
    message: str
    adjusted: tuple[tuple[str, str, str], ...]


def pack_theme_id(pack_name: str) -> str:
    slug = pack_name.strip().lower().replace("_", "-")
    ident = f"pack.{slug}"
    if _ID.fullmatch(ident) is None:
        return ""
    return ident


def describe_hint(hint: ThemeHint | None) -> HintResult:
    """Contrast-check a hint against ``smf.praxis``. Does not write a package."""
    if hint is None or not hint.token_overrides:
        return HintResult(True, "", "no theme hint", ())
    try:
        base = _praxis()
    except ThemeError as exc:
        return HintResult(False, hint.suggested_theme_id, str(exc), ())
    adjusted, notes, refused = _adjust_modes(base, hint.token_overrides)
    if refused:
        return HintResult(False, hint.suggested_theme_id, refused, tuple(notes))
    if adjusted is None:
        return HintResult(False,
            hint.suggested_theme_id,
            "theme hint failed contrast",
            tuple(notes))
    return HintResult(True, hint.suggested_theme_id, "theme hint passes contrast", tuple(notes))


def hint_theme(data_root, theme_id: str) -> InstalledTheme | None:
    """A virtual package for a suggested id that is not installed.

    The colours are ``smf.praxis`` plus the installed pack's hint. Explicit
    selection of ``smf.praxis`` never comes here.
    """
    if theme_id == "smf.praxis" or theme_id not in set(SUGGESTED_THEMES.values()):
        return None
    if find_theme(data_root, theme_id) is not None:
        return None
    pack = _pack_suggesting(data_root, theme_id)
    if pack is None or pack.theme is None:
        return None
    base = _praxis()
    adjusted, _notes, refused = _adjust_modes(base, pack.theme.token_overrides)
    if refused or adjusted is None:
        return None
    package = _with_modes(base, theme_id, base.name, adjusted)
    digest = _virtual_hash(base, adjusted)
    return InstalledTheme(package, "hint", None, digest)


def materialize_pack_theme(pack_name: str, hint: ThemeHint | None, data_root) -> HintResult:
    """Write ``pack.<name>`` under the user theme directory when the hint passes."""
    result = describe_hint(hint)
    if hint is None or not hint.token_overrides:
        return result
    theme_id = pack_theme_id(pack_name)
    if not theme_id:
        return HintResult(False, "", f"pack name {pack_name!r} cannot become a theme id", ())
    if not result.ok:
        return result
    base = _praxis()
    adjusted, notes, refused = _adjust_modes(base, hint.token_overrides)
    if refused or adjusted is None:
        return HintResult(False, theme_id, refused or "theme hint failed contrast", tuple(notes))
    files = dict(base.files)
    files["theme.toml"] = _rewrite_id(files.get("theme.toml", b""),
        base.theme_id,
        theme_id,
        adjusted)
    files["THEME.md"] = (
        f"# {pack_name}\n\n"
        "Generated from a legacy pack theme hint applied to smf.praxis.\n"
        "Colours that missed WCAG 2.2 AA were nudged in OKLCH lightness by at most 0.25.\n"
    ).encode()
    try:
        validated = validate_files(files)
    except ThemeError as exc:
        return HintResult(False, theme_id, str(exc), tuple(notes))
    install_files(validated.files, data_root)
    return HintResult(True, theme_id, f"wrote theme {theme_id}", tuple(notes))


def _praxis() -> ThemePackage:
    loaded = builtin_theme("smf.praxis")
    if loaded is None:
        raise ThemeError(
            "default theme is missing",
            (ThemeIssue("not_found", "smf.praxis is not available.", "smf.praxis"),),
        )
    return loaded.package


def _adjust_modes(
    base: ThemePackage,
    overrides: tuple[tuple[str, str], ...],
) -> tuple[dict[str, dict[str, str]] | None, list[tuple[str, str, str]], str]:
    notes: list[tuple[str, str, str]] = []
    adjusted: dict[str, dict[str, str]] = {}
    level = base.contrast or "AA"
    for mode, colors in base.modes.items():
        tuned, mode_notes, refused = _tune(dict(colors), overrides, level, mode)
        notes.extend(mode_notes)
        if refused or tuned is None:
            return None, notes, refused or f"{mode} theme hint failed contrast"
        adjusted[mode] = tuned
    return adjusted, notes, ""


def _tune(
    colors: dict[str, str],
    overrides: tuple[tuple[str, str], ...],
    level: str,
    mode: str,
) -> tuple[dict[str, str] | None, list[tuple[str, str, str]], str]:
    notes: list[tuple[str, str, str]] = []
    names: list[str] = []
    for token, value in overrides:
        if token not in colors:
            continue
        try:
            parsed = parse_color(value).to_hex()
        except ValueError:
            return None, notes, f"{token} is not a colour"
        colors[token] = parsed
        names.append(token)
    try:
        colors = _rederive(colors, names, level)
    except ValueError as exc:
        return None, notes, f"{mode} {exc}"
    for _pass in range(3):
        if not contrast_modes({mode: colors}, level):
            return colors, notes, ""
        moved = False
        for token in names:
            nudged, changed = _nudge(colors, token, names, level)
            if nudged is None:
                return None, notes, (
                    f"{mode} {token} stays below the contrast floor after a 0.25 lightness change"
                )
            if changed:
                notes.append((mode, token, nudged[token]))
                colors = nudged
                moved = True
        if not moved:
            break
    if contrast_modes({mode: colors}, level):
        return None, notes, f"{mode} theme hint does not meet {level}"
    return colors, notes, ""


def _rederive(colors: dict[str, str], overridden: list[str], level: str) -> dict[str, str]:
    """Rebuild optional tokens from the required palette after a hint."""
    seed = {name: colors[name] for name in REQUIRED_COLORS}
    if "accent" in overridden:
        seed["accentFg"] = best_ink(parse_color(seed["accent"])).to_hex()
    return complete_colors(seed, level=level)


def _nudge(
    colors: dict[str, str],
    token: str,
    overridden: list[str],
    level: str,
) -> tuple[dict[str, str] | None, bool]:
    """Move one overridden colour at most 0.25 in OKLCH lightness."""
    if _token_clear(colors, token, level) and not contrast_modes({"check": colors}, level):
        return colors, False
    color = parse_color(colors[token])
    light, _chroma, _hue = color.oklch()
    for step in range(1, 51):
        delta = step * 0.005
        for sign in (-1.0, 1.0):
            candidate = color.with_lightness(min(1.0, max(0.0, light + sign * delta)))
            trial = dict(colors)
            trial[token] = candidate.to_hex()
            try:
                trial = _rederive(trial, overridden, level)
            except ValueError:
                continue
            if _token_clear(trial, token, level):
                return trial, True
    return None, False


def _token_clear(colors: dict[str, str], token: str, level: str) -> bool:
    text_min, ui_min = thresholds(level)
    parsed = {name: parse_color(value) for name, value in colors.items()}
    for foreground, background, kind in CONTRAST_PAIRS:
        if token not in {foreground, background}:
            continue
        if foreground not in parsed or background not in parsed:
            continue
        minimum = text_min if kind == "text" else ui_min
        if contrast_ratio(parsed[foreground], parsed[background]) + 1e-9 < minimum:
            return False
    return True


def _with_modes(base: ThemePackage,
    theme_id: str,
    name: str,
    modes: dict[str, dict[str, str]]) -> ThemePackage:
    return ThemePackage(
        theme_id=theme_id,
        name=name,
        version=base.version,
        license=base.license,
        description=base.description,
        author=base.author,
        min_praxis=base.min_praxis,
        contrast=base.contrast,
        modes=modes,
        shared=dict(base.shared),
        font_faces=base.font_faces,
        files=dict(base.files),
        extra_css=base.extra_css,
    )


def _virtual_hash(base: ThemePackage, modes: dict[str, dict[str, str]]) -> str:
    from praxis_prime.themes.lockfile import package_hash

    payload = json.dumps(
        {"base": package_hash(base.files), "modes": modes},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _rewrite_id(
    raw: bytes,
    old_id: str,
    new_id: str,
    modes: dict[str, dict[str, str]],
) -> bytes:
    text = raw.decode("utf-8")
    text = re.sub(
        rf'^id\s*=\s*"{re.escape(old_id)}"',
        f'id = "{new_id}"',
        text,
        count=1,
        flags=re.M,
    )
    for mode, colors in modes.items():
        text = _replace_mode(text, mode, colors)
    return text.encode("utf-8")


def _replace_mode(text: str, mode: str, colors: dict[str, str]) -> str:
    """Rewrite ``[tokens.<mode>]`` or the ``[modes.<mode>]`` alias."""
    for section in (f"tokens.{mode}", f"modes.{mode}"):
        pattern = re.compile(rf"(?ms)^\[{re.escape(section)}\]\n(.*?)(?=^\[|\Z)")
        if pattern.search(text) is None:
            continue

        def repl(match: re.Match[str], section: str = section) -> str:
            body = match.group(1)
            for token, value in colors.items():
                line = f'{token} = "{value}"'
                # [ \t] only: \s would swallow the newline and glue the next assignment on.
                updated, count = re.subn(
                    rf'^[ \t]*{re.escape(token)}[ \t]*=[ \t]*"[^"]*"[ \t]*$',
                    line,
                    body,
                    count=1,
                    flags=re.M,
                )
                if count:
                    body = updated
                    continue
                if body and not body.endswith("\n"):
                    body += "\n"
                body += line + "\n"
            if body and not body.endswith("\n"):
                body += "\n"
            return f"[{section}]\n{body}"

        return pattern.sub(repl, text, count=1)
    return text


def _pack_suggesting(data_root, theme_id: str):
    from praxis_prime.packs.install import installed_index

    seen: set[int] = set()
    for pack in installed_index(data_root).values():
        if id(pack) in seen:
            continue
        seen.add(id(pack))
        if pack.theme is not None and pack.theme.suggested_theme_id == theme_id:
            return pack
    return None


