"""Compile a validated theme into one stylesheet.

``@font-face`` comes only from the manifest. Author ``theme.css`` custom
properties are not copied: the validator has already folded them into the
token maps. Decorative rules are appended after those blocks, with package
``url()`` values rewritten from the parser's URL tokens. The SPA swaps a
``<link>``; nothing here is inline in the page.
"""

from __future__ import annotations

import re

import tinycss2
from tinycss2.ast import URLToken
from tinycss2.serializer import serialize_string_value

from praxis_prime.themes.archive import FONT_PATH
from praxis_prime.themes.model import ThemePackage
from praxis_prime.themes.tokens import MODES

_HEX = re.compile(r"^#[0-9a-fA-F]{6}(?:[0-9a-fA-F]{2})?$")
_SAFE_ASSET = re.compile(r"^assets/(?:fonts|ornaments)/[A-Za-z0-9._-]+$")
_FAMILY_BAD = set(";{}()<>\\\"")

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
    """Return the stylesheet served at ``/themes/<id>/<hash>.css``.

    Light, dark, system-light, and system-dark each name the tokens the
    contrast check accepted. An author ``:root`` rule is not appended, so it
    cannot override system mode.
    """
    prefix = f"/themes/{package.theme_id}/{package_hash}/"
    lines: list[str] = [
        "/* praxis.theme/v1 generated stylesheet. Appearance only. */",
        "",
    ]
    lines.extend(_font_faces(package, prefix))
    light = package.modes["light"]
    dark = package.modes["dark"]
    shared = package.shared
    lines.extend(_block(':root, :root[data-mode="light"]', light, shared, prefix, "light"))
    lines.append("")
    lines.extend(_block(':root[data-mode="dark"]', dark, shared, prefix, "dark"))
    lines.append("")
    lines.extend(
        _media(
            "light",
            ':root[data-mode="system"]',
            light,
            shared,
            prefix,
        )
    )
    lines.append("")
    lines.extend(
        _media(
            "dark",
            ':root[data-mode="system"]',
            dark,
            shared,
            prefix,
        )
    )
    lines.append("")
    lines.append("@media (prefers-reduced-motion: reduce) {")
    lines.append("  :root { --pp-motion: none; }")
    lines.append("}")
    extra = _rewrite_stylesheet(package.extra_css, prefix)
    if extra.strip():
        lines.append("")
        lines.append(extra.rstrip())
        lines.append("")
    return "\n".join(lines)


def _font_faces(package: ThemePackage, prefix: str) -> list[str]:
    lines: list[str] = []
    seen: set[tuple[str, str, str, str]] = set()
    for face in package.font_faces:
        if not face.path or FONT_PATH.fullmatch(face.path) is None:
            continue
        if not re.fullmatch(r"[1-9]00(?: [1-9]00)?", face.weight):
            continue
        if face.style not in {"normal", "italic"}:
            continue
        key = (face.family, face.path, face.weight, face.style)
        if key in seen:
            continue
        seen.add(key)
        src = 'url("' + serialize_string_value(prefix + face.path) + '")'
        lines.extend(
            [
                "@font-face {",
                f"  font-family: {_quote(face.family)};",
                f"  src: {src} format(\"woff2\");",
                f"  font-weight: {face.weight};",
                f"  font-style: {face.style};",
                "  font-display: swap;",
                "}",
                "",
            ]
        )
    return lines


def _media(
    scheme: str,
    selector: str,
    colors: dict[str, str],
    shared: dict[str, str],
    prefix: str,
) -> list[str]:
    lines = [f"@media (prefers-color-scheme: {scheme}) {{"]
    lines.extend(_block(selector, colors, shared, prefix, scheme, pad="  "))
    lines.append("}")
    return lines


def _block(
    selector: str,
    colors: dict[str, str],
    shared: dict[str, str],
    prefix: str,
    scheme: str,
    *,
    pad: str = "",
) -> list[str]:
    indent = pad + "  "
    lines = [f"{pad}{selector} {{"]
    lines.extend(_decls(colors, shared, prefix, indent=indent))
    lines.append(f"{indent}color-scheme: {scheme};")
    lines.append(f"{pad}}}")
    return lines


def _decls(
    colors: dict[str, str],
    shared: dict[str, str],
    prefix: str,
    *,
    indent: str = "  ",
) -> list[str]:
    lines: list[str] = []
    for name in _LIGHT_KEYS:
        value = colors.get(name, "")
        if _HEX.fullmatch(value):
            lines.append(f"{indent}--pp-{name}: {value};")
    for name, value in shared.items():
        rendered = _safe_value(_rewrite_value(value, prefix))
        lines.append(f"{indent}--pp-{name}: {rendered};")
    return lines


def _rewrite(text: str, prefix: str) -> str:
    """Rewrite package urls in one declaration value or a stylesheet snippet."""
    if "{" in text:
        return _rewrite_stylesheet(text, prefix)
    return _rewrite_value(text, prefix)


def _rewrite_stylesheet(text: str, prefix: str) -> str:
    if "url(" not in text.casefold():
        return text
    rules = tinycss2.parse_stylesheet(text, skip_comments=True, skip_whitespace=True)
    for rule in rules:
        for attr in ("prelude", "content"):
            tokens = getattr(rule, attr, None)
            if isinstance(tokens, list):
                _rewrite_tokens(tokens, prefix)
    return tinycss2.serialize(rules).strip()


def _rewrite_value(text: str, prefix: str) -> str:
    if "url(" not in text.casefold():
        return text
    tokens = tinycss2.parse_component_value_list(text, skip_comments=True)
    _rewrite_tokens(tokens, prefix)
    return tinycss2.serialize(tokens).strip()


def _rewrite_tokens(tokens: list[object], prefix: str) -> None:
    for index, token in enumerate(list(tokens)):
        kind = getattr(token, "type", "")
        if kind == "url":
            tokens[index] = _url_token(token, prefix, getattr(token, "value", ""))
        elif kind == "function" and getattr(token, "lower_name", "") == "url":
            tokens[index] = _url_token(token, prefix, _function_url(token))
        else:
            arguments = getattr(token, "arguments", None)
            if isinstance(arguments, list):
                _rewrite_tokens(arguments, prefix)
            nested = getattr(token, "content", None)
            if isinstance(nested, list):
                _rewrite_tokens(nested, prefix)


def _function_url(token: object) -> str:
    text = tinycss2.serialize(getattr(token, "arguments", [])).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def _url_token(token: object, prefix: str, raw: str) -> URLToken:
    value = _package_url(raw, prefix)
    line = getattr(token, "source_line", 1)
    column = getattr(token, "source_column", 1)
    quoted = '"' + serialize_string_value(value) + '"'
    return URLToken(line, column, value, f"url({quoted})")


def _package_url(raw: str, prefix: str) -> str:
    text = raw.strip()
    if text.startswith("./"):
        text = text[2:]
    if _SAFE_ASSET.fullmatch(text):
        return prefix + text
    return ""


def _safe_value(text: str) -> str:
    """Drop a declaration value that can escape its property."""
    if _breakout(text):
        return "unset"
    return text


def _breakout(text: str) -> bool:
    index = 0
    size = len(text)
    while index < size:
        char = text[index]
        if char in "\"'":
            quote = char
            index += 1
            while index < size:
                if text[index] == "\\":
                    index += 2
                    continue
                if text[index] == quote:
                    index += 1
                    break
                if ord(text[index]) < 32 or ord(text[index]) == 127:
                    return True
                index += 1
            else:
                return True
            continue
        if char in ";{}<>\\" or ord(char) < 32 or ord(char) == 127:
            return True
        index += 1
    return False


def _quote(family: str) -> str:
    if family in {"serif", "sans-serif", "monospace"}:
        return family
    if any(ord(char) < 32 or ord(char) == 127 or char in _FAMILY_BAD for char in family):
        return "sans-serif"
    return '"' + serialize_string_value(family) + '"'


def covered_modes() -> tuple[str, ...]:
    return MODES
