"""Turn a validated Praxis Prime palette into a Textual theme.

``luminosity_spread`` is 0 so Textual does not lighten the checked colours.
Exact hex values are also stored in ``Theme.variables`` for the text, border,
footer, and selection roles the contrast pairs already accepted.
``NO_COLOR`` selects a built-in ANSI theme and does not register RGB.
"""

from __future__ import annotations

from textual.theme import Theme

from praxis_prime.tui.palette import Palette

THEME_NAME = "praxis"


def theme_for(palette: Palette, *, no_color: bool) -> Theme | str:
    """A Textual ``Theme``, or ``ansi-dark`` / ``ansi-light`` when colour is off."""
    if no_color:
        return "ansi-light" if not palette.dark else "ansi-dark"
    colors = palette.colors
    fg = _pick(colors, "fg")
    bg = _pick(colors, "bg")
    muted = _pick(colors, "fgMuted", fg)
    accent = _pick(colors, "accent", fg)
    border = _pick(colors, "borderStrong", _pick(colors, "border", fg))
    border_soft = _pick(colors, "border", border)
    selection = _pick(colors, "selection", accent)
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
        "block-cursor-foreground": fg,
        "block-cursor-background": selection,
        "block-cursor-text-style": "none",
        "screen-selection-background": selection,
        "screen-selection-foreground": fg,
        "input-selection-background": selection,
        "input-selection-foreground": fg,
        "scrollbar": border_soft,
        "scrollbar-hover": border,
        "scrollbar-background": sunken,
    }
    return Theme(
        name=THEME_NAME,
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


def _pick(colors: dict[str, str], name: str, fallback: str = "") -> str:
    value = colors.get(name, "")
    return value or fallback
