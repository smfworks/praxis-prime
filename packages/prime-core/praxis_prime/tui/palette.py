"""Map ``GET /v1/themes/active`` and its stylesheet onto validated tokens.

The stylesheet is the one the daemon names. This module does not read the
Omarchy theme file and does not call ``themes.omarchy.live_theme``.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass

from praxis_prime.themes.color import contrast_ratio
from praxis_prime.themes.store import builtin_theme
from praxis_prime.themes.tokens import CONTRAST_PAIRS, REQUIRED_COLORS, thresholds
from praxis_prime.tui.gateway import HttpPort, active_theme_path

_DECL = re.compile(
    r"--pp-([A-Za-z][A-Za-z0-9]*)\s*:\s*(#[0-9A-Fa-f]{6}(?:[0-9A-Fa-f]{2})?)\b"
)
_LIGHT_SELECTORS = frozenset(
    {
        ":root",
        ':root, :root[data-mode="light"]',
        ':root[data-mode="light"]',
    }
)
_DARK_SELECTOR = ':root[data-mode="dark"]'


@dataclass(frozen=True, slots=True)
class Palette:
    """One mode of a theme, already checked against the theme's contrast level."""

    theme_id: str
    requested: str
    mode: str
    dark: bool
    source: str
    colors: dict[str, str]
    package_hash: str
    contrast: str


def resolve_mode(requested: str, environ: Mapping[str, str] | None = None) -> str:
    """``light``, ``dark``, or ``system`` via ``COLORFGBG``. Unknown becomes dark."""
    mode = (requested or "dark").strip().lower()
    if mode == "light":
        return "light"
    if mode == "dark":
        return "dark"
    if mode != "system":
        return "dark"
    env = os.environ if environ is None else environ
    return _mode_from_colorfgbg(env.get("COLORFGBG", ""))


def tokens_from_css(css: str, mode: str) -> dict[str, str]:
    """Colour tokens from the explicit light or dark block.

    ``@media`` blocks and ``data-mode="system"`` rules are skipped. System
    mode is resolved before this runs, then the matching explicit block is read.
    """
    wanted_dark = mode == "dark"
    found: dict[str, str] = {}
    for selector, body in _top_level_rules(css):
        sel = " ".join(selector.split())
        if "system" in sel:
            continue
        if wanted_dark:
            if sel != _DARK_SELECTOR:
                continue
        elif sel not in _LIGHT_SELECTORS:
            continue
        for name, value in _DECL.findall(body):
            found[name] = value
    return found


def acceptable(colors: Mapping[str, str], level: str) -> bool:
    """True when every present contrast pair meets the theme's AA or AAA floor."""
    if any(name not in colors for name in REQUIRED_COLORS):
        return False
    text_min, ui_min = thresholds(level if level in {"AA", "AAA"} else "AA")
    for foreground, background, kind in CONTRAST_PAIRS:
        if foreground not in colors or background not in colors:
            continue
        try:
            ratio = contrast_ratio(colors[foreground], colors[background])
        except (ValueError, ZeroDivisionError):
            return False
        need = text_min if kind == "text" else ui_min
        if ratio < need:
            return False
    return True


def fallback_palette(mode: str) -> Palette:
    """Built-in ``smf.praxis`` for ``mode`` (``light`` or ``dark``)."""
    resolved = "light" if mode == "light" else "dark"
    installed = builtin_theme("smf.praxis")
    if installed is None:
        raise RuntimeError("built-in theme smf.praxis is missing")
    colors = dict(installed.package.modes[resolved])
    level = installed.package.contrast if installed.package.contrast in {"AA", "AAA"} else "AA"
    return Palette(
        theme_id="smf.praxis",
        requested="smf.praxis",
        mode=resolved,
        dark=resolved == "dark",
        source="builtin",
        colors=colors,
        package_hash=installed.package_hash,
        contrast=level,
    )


def palette_from_http(
    http: HttpPort,
    profile: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> Palette:
    """Active theme over HTTP. Any failure uses ``smf.praxis``."""
    from praxis_prime.gateway.client import GatewayError

    mode = resolve_mode("system", environ)
    try:
        active = http.get_json(active_theme_path(profile))
        css_path = str(active.get("css") or "")
        css = http.get_text(css_path) if css_path else ""
    except GatewayError:
        return fallback_palette(mode)
    return palette_from_active(active, css, environ=environ)


def palette_from_active(
    active: Mapping[str, object],
    css: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> Palette:
    """Tokens from the active-theme payload. A failed check uses ``smf.praxis``."""
    mode = resolve_mode(str(active.get("mode") or "dark"), environ)
    level = str(active.get("contrast") or "AA")
    colors = tokens_from_css(css, mode)
    if not acceptable(colors, level):
        return fallback_palette(mode)
    contrast = level if level in {"AA", "AAA"} else "AA"
    theme_id = str(active.get("id") or "smf.praxis")
    requested = str(active.get("requested") or theme_id)
    return Palette(
        theme_id=theme_id,
        requested=requested,
        mode=mode,
        dark=mode == "dark",
        source=str(active.get("source") or ""),
        colors=dict(colors),
        package_hash=str(active.get("packageHash") or ""),
        contrast=contrast,
    )


def _mode_from_colorfgbg(value: str) -> str:
    """Background 7 or 15 is light. Anything else, including a missing value, is dark."""
    parts = [part.strip() for part in value.split(";") if part.strip()]
    background = parts[-1] if parts else ""
    if background in {"7", "15"}:
        return "light"
    return "dark"


def _top_level_rules(css: str) -> list[tuple[str, str]]:
    rules: list[tuple[str, str]] = []
    index = 0
    length = len(css)
    while index < length:
        while index < length and css[index].isspace():
            index += 1
        if index >= length:
            break
        if css.startswith("/*", index):
            end = css.find("*/", index + 2)
            index = length if end < 0 else end + 2
            continue
        if css[index] == "@":
            brace = css.find("{", index)
            semi = css.find(";", index)
            if brace < 0 or (0 <= semi < brace):
                index = length if semi < 0 else semi + 1
                continue
            index = _skip_block(css, brace)
            continue
        brace = css.find("{", index)
        if brace < 0:
            break
        selector = css[index:brace].strip()
        end = _skip_block(css, brace)
        rules.append((selector, css[brace + 1 : end - 1]))
        index = end
    return rules


def _skip_block(css: str, open_brace: int) -> int:
    depth = 0
    index = open_brace
    length = len(css)
    while index < length:
        if css.startswith("/*", index):
            end = css.find("*/", index + 2)
            index = length if end < 0 else end + 2
            continue
        char = css[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return length
