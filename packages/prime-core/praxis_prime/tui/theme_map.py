"""Turn a validated Praxis Prime palette into a Textual theme.

``luminosity_spread`` is 0 so Textual does not lighten the checked colours.
Exact hex values are also stored in ``Theme.variables`` for the text, border,
footer, and selection roles the contrast pairs already accepted.

Each palette is registered under its own name (theme, mode, and hash). Textual
repaints only when the theme name changes. ``NO_COLOR`` is left for Textual:
this module keeps the RGB theme, and Textual's filter drops the colours.
"""

from __future__ import annotations

import re

from textual.theme import Theme

from praxis_prime.tui.palette import Palette


def theme_for(palette: Palette, *, no_color: bool = False) -> Theme:
    """A Textual ``Theme`` whose name changes when the palette changes.

    ``no_color`` is accepted and ignored. Textual removes colour when
    ``NO_COLOR`` is set, which leaves the terminal's own foreground and
    background instead of painting black on black.
    """
    _ = no_color
    colors = palette.colors
    fg = _pick(colors, "fg")
    bg = _pick(colors, "bg")
    muted = _pick(colors, "fgMuted", fg)
    accent = _pick(colors, "accent", fg)
    accent_fg = _pick(colors, "accentFg", bg)
    border = _pick(colors, "borderStrong", _pick(colors, "border", fg))
    border_soft = _pick(colors, "border", border)
    selection = _pick(colors, "selection", accent)
    if selection.lower() == accent.lower():
        selection = _pick(colors, "bgSunken", border_soft)
    raised = _pick(colors, "bgRaised", bg)
    sunken = _pick(colors, "bgSunken", raised)
    variables = {
        "text": fg,
        "text-muted": muted,
        "text-disabled": muted,
        "foreground-muted": muted,
        "foreground-disabled": muted,
        "border": border,
        "border-blurred": border_soft,
        "footer-foreground": fg,
        "footer-background": raised,
        "footer-key-foreground": accent,
        "footer-description-foreground": muted,
        "block-cursor-foreground": accent_fg,
        "block-cursor-background": accent,
        "block-cursor-text-style": "bold",
        "block-cursor-blurred-foreground": fg,
        "block-cursor-blurred-background": selection,
        "block-cursor-blurred-text-style": "none",
        "screen-selection-background": selection,
        "screen-selection-foreground": fg,
        "input-selection-background": selection,
        "input-selection-foreground": fg,
        "scrollbar": border_soft,
        "scrollbar-hover": border,
        "scrollbar-background": sunken,
        "accent-fg": accent_fg,
        "row-focus": accent,
        "row-focus-text": accent_fg,
        "row-blur": selection,
        "row-blur-text": fg,
    }
    return Theme(
        name=theme_name(palette),
        primary=accent,
        secondary=_pick(colors, "info", accent),
        warning=_pick(colors, "warn", fg),
        error=_pick(colors, "danger", fg),
        success=_pick(colors, "ok", fg),
        accent=accent,
        foreground=fg,
        background=bg,
        surface=raised,
        panel=sunken,
        boost=None,
        dark=palette.dark,
        luminosity_spread=0,
        text_alpha=1.0,
        variables=variables,
    )


def theme_name(palette: Palette) -> str:
    """Unique theme id. Mode is included because light and dark share a hash."""
    raw = f"praxis-{palette.theme_id}-{palette.mode}-{palette.package_hash[:12]}"
    cleaned = re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")
    return cleaned[:64] or "praxis"


def _pick(colors: dict[str, str], name: str, fallback: str = "") -> str:
    value = colors.get(name, "")
    return value or fallback
