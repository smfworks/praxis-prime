"""Compile a validated theme into one stylesheet.

``@font-face`` comes only from the manifest. Author ``theme.css`` is appended
after the token block, with package ``url()`` values rewritten to the hashed
asset prefix. The SPA swaps a ``<link>``; nothing here is inline in the page.
"""

from __future__ import annotations

from praxis_prime.themes.model import ThemePackage
from praxis_prime.themes.tokens import MODES

_LIGHT_KEYS = (
    "bg",
    "bgRaised",
    "bgSunken",
    "overlay",
    "fg",
    "fgMuted",
    "fgSubtle",
    "accent",
    "accentFg",
    "accentMuted",
    "border",
    "borderStrong",
    "ring",
    "ok",
    "warn",
    "danger",
    "info",
    "okFg",
    "warnFg",
    "dangerFg",
    "infoFg",
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


def render_css(package: ThemePackage, package_hash: str) -> str:
    """Return the stylesheet served at ``/themes/<id>/<hash>.css``."""
    prefix = f"/themes/{package.theme_id}/{package_hash}/"
    lines: list[str] = [
        "/* praxis.theme/v1 generated stylesheet. Appearance only. */",
        "",
    ]
    seen: set[tuple[str, str, str, str]] = set()
    for face in package.font_faces:
        if not face.path:
            continue
        key = (face.family, face.path, face.weight, face.style)
        if key in seen:
            continue
        seen.add(key)
        family = _quote(face.family)
        lines.extend(
            [
                "@font-face {",
                f"  font-family: {family};",
                f'  src: url("{prefix}{face.path}") format("woff2");',
                f"  font-weight: {face.weight};",
                f"  font-style: {face.style};",
                "  font-display: swap;",
                "}",
                "",
            ]
        )
    light = package.modes["light"]
    dark = package.modes["dark"]
    lines.append(':root, :root[data-mode="light"] {')
    lines.extend(_decls(light, package.shared, prefix))
    lines.append("  color-scheme: light;")
    lines.append("}")
    lines.append("")
    lines.append(':root[data-mode="dark"] {')
    lines.extend(_decls(dark, {}, prefix))
    lines.append("  color-scheme: dark;")
    lines.append("}")
    lines.append("")
    lines.append("@media (prefers-color-scheme: dark) {")
    lines.append('  :root[data-mode="system"] {')
    lines.extend(_decls(dark, {}, prefix, indent="    "))
    lines.append("    color-scheme: dark;")
    lines.append("  }")
    lines.append("}")
    lines.append("")
    lines.append("@media (prefers-reduced-motion: reduce) {")
    lines.append("  :root { --pp-motion: none; }")
    lines.append("}")
    extra = _rewrite(package.extra_css, prefix)
    if extra.strip():
        lines.append("")
        lines.append(extra.rstrip())
        lines.append("")
    return "\n".join(lines)


def _decls(
    colors: dict[str, str],
    shared: dict[str, str],
    prefix: str,
    *,
    indent: str = "  ",
) -> list[str]:
    lines: list[str] = []
    for name in _LIGHT_KEYS:
        if name in colors:
            lines.append(f"{indent}--pp-{name}: {colors[name]};")
    for name, value in shared.items():
        lines.append(f"{indent}--pp-{name}: {_rewrite(value, prefix)};")
    return lines


def _rewrite(text: str, prefix: str) -> str:
    return text.replace('url("assets/', f'url("{prefix}assets/')


def _quote(family: str) -> str:
    if family in {"serif", "sans-serif", "monospace"}:
        return family
    return '"' + family.replace('"', "") + '"'


def covered_modes() -> tuple[str, ...]:
    return MODES
