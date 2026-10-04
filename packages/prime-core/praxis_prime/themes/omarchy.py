"""Omarchy live-theme hook.

M3b will read ``~/.local/state/omarchy/current/theme/praxis-prime.json`` and
pass those colours through this package's validator. M3a returns no live
theme, so selection falls through to ``smf.praxis``.

ARCHITECTURE §28.2. Addendum A §1.6.
"""

from __future__ import annotations


def live_theme() -> str | None:
    """Return a theme id supplied by Omarchy, or None when nothing is live.

    The return value is a theme id already installed on this machine. M3a
    does not parse the Omarchy template. The template stub stays at
    ``apps/omarchy/praxis-prime.json.tpl``.
    """
    return None
