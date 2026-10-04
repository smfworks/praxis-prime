"""Design tokens for a praxis.theme/v1 package.

Names match Addendum A §1. CSS custom properties are ``--pp-<name>`` with the
camelCase intact. Optional colours are filled in OKLCH when the author omits
them. ``fgSubtle`` is decorative and is not a contrast pair.
"""

from __future__ import annotations

from praxis_prime.themes.color import (
    Color,
    adjust_lightness,
    best_ink,
    contrast_ratio,
    from_oklch,
    mix,
    parse_color,
)

SCHEMA = "praxis.theme/v1"
LOCK_SCHEMA = "praxis.theme.lock/v1"

REQUIRED_COLORS: tuple[str, ...] = (
    "bg",
    "bgRaised",
    "fg",
    "fgMuted",
    "accent",
    "accentFg",
    "border",
    "borderStrong",
    "ring",
    "ok",
    "warn",
    "danger",
)

OPTIONAL_COLORS: tuple[str, ...] = (
    "bgSunken",
    "overlay",
    "fgSubtle",
    "accentMuted",
    "info",
    "infoFg",
    "okFg",
    "warnFg",
    "dangerFg",
    "tool",
    "selection",
    "approval",
    "dialOff",
    "dialMonitor",
    "dialEnforce",
    "codeBg",
    "codeFg",
    "syn1",
    "syn2",
    "syn3",
    "syn4",
    "syn5",
    "syn6",
    "syn7",
    "syn8",
)

COLOR_TOKENS: frozenset[str] = frozenset(REQUIRED_COLORS + OPTIONAL_COLORS)

# (foreground, background, "text" | "ui"). Checked after derivation.
CONTRAST_PAIRS: tuple[tuple[str, str, str], ...] = (
    ("fg", "bg", "text"),
    ("fg", "bgRaised", "text"),
    ("fgMuted", "bg", "text"),
    ("fgMuted", "bgRaised", "text"),
    ("accentFg", "accent", "text"),
    ("ok", "bg", "text"),
    ("ok", "bgRaised", "text"),
    ("warn", "bg", "text"),
    ("warn", "bgRaised", "text"),
    ("danger", "bg", "text"),
    ("danger", "bgRaised", "text"),
    ("info", "bg", "text"),
    ("info", "bgRaised", "text"),
    ("okFg", "ok", "text"),
    ("warnFg", "warn", "text"),
    ("dangerFg", "danger", "text"),
    ("infoFg", "info", "text"),
    ("codeFg", "codeBg", "text"),
    ("fg", "selection", "text"),
    ("tool", "bg", "text"),
    ("syn1", "codeBg", "text"),
    ("syn2", "codeBg", "text"),
    ("syn3", "codeBg", "text"),
    ("syn4", "codeBg", "text"),
    ("syn5", "codeBg", "text"),
    ("syn6", "codeBg", "text"),
    ("syn7", "codeBg", "text"),
    ("syn8", "codeBg", "text"),
    ("borderStrong", "bg", "ui"),
    ("borderStrong", "bgRaised", "ui"),
    ("ring", "bg", "ui"),
    ("ring", "bgRaised", "ui"),
    ("accent", "bg", "ui"),
    ("accent", "bgRaised", "ui"),
    ("approval", "bg", "ui"),
    ("dialOff", "bg", "ui"),
    ("dialMonitor", "bg", "ui"),
    ("dialEnforce", "bg", "ui"),
)

TYPE_TOKENS: tuple[str, ...] = (
    "fontDisplay",
    "fontBody",
    "fontMono",
    "scale",
    "baseSize",
    "lineHeight",
    "radius",
    "density",
    "borderWidth",
    "motion",
    "ornamentHeader",
    "ornamentDivider",
    "watermark",
    "watermarkOpacity",
)

ALL_CUSTOM_PROPS: frozenset[str] = frozenset(
    f"--pp-{name}" for name in (*COLOR_TOKENS, *TYPE_TOKENS)
)

DENSITIES = frozenset({"compact", "cozy", "comfortable"})
MOTIONS = frozenset({"none", "subtle", "standard"})
MODES = ("light", "dark")
MODE_CHOICES = frozenset({"light", "dark", "system"})
PACKAGE_LICENSES = frozenset({"MIT", "Apache-2.0", "CC-BY-4.0", "CC0-1.0"})
FONT_LICENSES = frozenset({"OFL-1.1", "Apache-2.0", "MIT", "CC0-1.0", "Ubuntu-font-1.0"})

TEXT_AA = 4.5
TEXT_AAA = 7.0
UI_AA = 3.0
UI_AAA = 4.5

_SYN_HUES = (25.0, 80.0, 150.0, 200.0, 250.0, 290.0, 330.0, 50.0)


def thresholds(level: str) -> tuple[float, float]:
    """Text ratio, then non-text ratio.

    AAA uses 7:1 for text and 4.5:1 for non-text. The non-text floor is
    stricter than WCAG 1.4.11 so High Contrast stays unambiguous.
    """
    if level == "AAA":
        return TEXT_AAA, UI_AAA
    return TEXT_AA, UI_AA


def complete_colors(raw: dict[str, str], *, level: str) -> dict[str, str]:
    """Return every colour token. Author values win. The rest are derived.

    Raises ``ValueError`` when a required token is missing or a derived
    status colour cannot clear its contrast floor.
    """
    missing = [name for name in REQUIRED_COLORS if name not in raw]
    if missing:
        raise ValueError("missing " + ", ".join(missing))
    colors = dict(raw)
    authored = set(raw)
    text_min, ui_min = thresholds(level)
    bg = parse_color(colors["bg"])
    raised = parse_color(colors["bgRaised"])
    fg = parse_color(colors["fg"])
    muted = parse_color(colors["fgMuted"])
    accent = parse_color(colors["accent"])
    ok = parse_color(colors["ok"])
    warn = parse_color(colors["warn"])
    danger = parse_color(colors["danger"])

    _put(colors, "bgSunken", lambda: bg.with_lightness(_shift(bg, -0.06)))
    sunken = parse_color(colors["bgSunken"])
    _put(colors, "overlay", lambda: Color(bg.r, bg.g, bg.b, 0.92))
    _put(colors, "fgSubtle", lambda: mix(muted, bg, 0.45))
    _put(colors, "accentMuted", lambda: mix(accent, bg, 0.62))
    _put(
        colors,
        "info",
        lambda: _ink_for(_seed(bg, 250.0, 0.12), (bg, raised), text_min),
    )
    info = parse_color(colors["info"])
    _put(colors, "okFg", lambda: _ink_for(best_ink(ok), (ok,), text_min))
    _put(colors, "warnFg", lambda: _ink_for(best_ink(warn), (warn,), text_min))
    _put(colors, "dangerFg", lambda: _ink_for(best_ink(danger), (danger,), text_min))
    _put(colors, "infoFg", lambda: _ink_for(best_ink(info), (info,), text_min))
    _put(colors, "tool", lambda: _ink_for(_seed(bg, 190.0, 0.1), (bg,), text_min))
    _put(colors, "selection", lambda: _selection(bg, accent, fg, text_min))
    _put(colors, "approval", lambda: accent)
    _put(colors, "dialOff", lambda: muted)
    _put(colors, "dialMonitor", lambda: warn)
    _put(colors, "dialEnforce", lambda: danger)
    _put(colors, "codeBg", lambda: _code_bg(sunken, bg, fg, text_min))
    code_bg = parse_color(colors["codeBg"])
    _put(colors, "codeFg", lambda: _ink_for(fg, (code_bg,), text_min))
    for index, hue in enumerate(_SYN_HUES, start=1):
        _put(
            colors,
            f"syn{index}",
            lambda hue=hue: _ink_for(_seed(code_bg, hue, 0.12), (code_bg,), text_min),
        )
    # Derived approval and dial colours keep a UI-contrast floor. An author
    # value is left alone so the contrast check can refuse it in the open.
    for name in ("approval", "dialOff", "dialMonitor", "dialEnforce"):
        if name not in authored:
            _ensure(colors, name, (bg,), ui_min)
    return colors


def _put(colors: dict[str, str], name: str, factory) -> None:
    if name in colors:
        return
    colors[name] = factory().to_hex()


def _shift(color: Color, delta: float) -> float:
    light, _chroma, _hue = color.oklch()
    return min(1.0, max(0.0, light + delta))


def _seed(background: Color, hue: float, chroma: float) -> Color:
    light, _chroma, _hue = background.oklch()
    target = 0.28 if light > 0.6 else 0.82
    return from_oklch(target, chroma, hue)


def _ink_for(color: Color, backgrounds: tuple[Color, ...], minimum: float) -> Color:
    adjusted = adjust_lightness(color, backgrounds, minimum)
    if adjusted is None:
        raise ValueError("no contrasting colour within the lightness limit")
    return adjusted


def _selection(bg: Color, accent: Color, fg: Color, minimum: float) -> Color:
    for amount in (0.22, 0.14, 0.08, 0.0):
        mixed = mix(bg, accent, amount)
        if _ratio(fg, mixed) >= minimum:
            return mixed
    return bg


def _code_bg(sunken: Color, bg: Color, fg: Color, minimum: float) -> Color:
    if _ratio(fg, sunken) >= minimum:
        return sunken
    return bg


def _ensure(colors: dict[str, str],
    name: str,
    backgrounds: tuple[Color, ...],
    minimum: float) -> None:
    color = parse_color(colors[name])
    if all(_ratio(color, background) >= minimum for background in backgrounds):
        return
    adjusted = adjust_lightness(color, backgrounds, minimum)
    if adjusted is None:
        raise ValueError(f"{name} cannot meet the contrast floor")
    colors[name] = adjusted.to_hex()


def _ratio(foreground: Color, background: Color) -> float:
    return contrast_ratio(foreground, background)
