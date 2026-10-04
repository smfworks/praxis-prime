"""Allowlist for an optional theme.css.

tinycss2 parses the file. The bytes that are served are a re-serialization of
the rules that passed, so a comment or an unparsed tail cannot survive.
Addendum A §1.4.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import tinycss2
from tinycss2.ast import AtRule, ParseError, QualifiedRule

from praxis_prime.themes.color import parse_color
from praxis_prime.themes.errors import ThemeIssue
from praxis_prime.themes.tokens import (
    ALL_CUSTOM_PROPS,
    COLOR_TOKENS,
    DENSITIES,
    MOTIONS,
)

_RAW = (
    ("@import", "css_import", "@import is not allowed. Themes cannot load other stylesheets."),
    ("@font-face", "css_rejected", "@font-face is not allowed. Declare fonts in theme.toml."),
    ("@namespace", "css_rejected", "@namespace is not allowed."),
    ("javascript:", "css_rejected", "javascript: URLs are not allowed."),
    ("expression(", "css_rejected", "CSS expressions are not allowed."),
    ("!important", "css_rejected", "!important is not allowed."),
    (":has(", "css_selector", ":has() is not allowed."),
    (".pp-approval", "css_selector", "Themes cannot target .pp-approval*."),
    (".pp-dial", "css_selector", "Themes cannot target .pp-dial*."),
    (".pp-audit", "css_selector", "Themes cannot target .pp-audit*."),
    ("http://", "css_url", "Remote URLs are not allowed."),
    ("https://", "css_url", "Remote URLs are not allowed."),
    ("data:", "css_url", "data: URLs are not allowed."),
)

_CUSTOM = re.compile(
    r"^(?::root(?:\[data-mode=(?:light|dark|\"light\"|\"dark\"|'light'|'dark')\])?"
    r"|\[data-mode=(?:light|dark|\"light\"|\"dark\"|'light'|'dark')\])$"
)
_DECOR = re.compile(
    r"^\.(?:pp-header-band|pp-sidebar-texture|pp-divider|pp-ornament-[a-z0-9-]+)$"
)
_DECOR_PROPS = frozenset(
    {
        "color",
        "background",
        "background-color",
        "background-image",
        "background-repeat",
        "background-position",
        "background-size",
        "border",
        "border-color",
        "border-style",
        "border-width",
        "border-radius",
        "border-top",
        "border-right",
        "border-bottom",
        "border-left",
        "border-top-color",
        "border-right-color",
        "border-bottom-color",
        "border-left-color",
        "border-top-style",
        "border-right-style",
        "border-bottom-style",
        "border-left-style",
        "border-top-width",
        "border-right-width",
        "border-bottom-width",
        "border-left-width",
        "border-top-left-radius",
        "border-top-right-radius",
        "border-bottom-right-radius",
        "border-bottom-left-radius",
        "box-shadow",
        "letter-spacing",
        "text-transform",
        "font-feature-settings",
    }
)
_BANNED_PROPS = frozenset(
    {
        "content",
        "display",
        "visibility",
        "opacity",
        "position",
        "z-index",
        "transform",
        "pointer-events",
        "clip",
        "clip-path",
        "filter",
    }
)
_PROTECTED = ("pp-approval", "pp-dial", "pp-audit")
_LENGTH = re.compile(r"^([0-9]+(?:\.[0-9]+)?)(px)?$")


@dataclass
class CssReport:
    css: str
    root: dict[str, str] = field(default_factory=dict)
    light: dict[str, str] = field(default_factory=dict)
    dark: dict[str, str] = field(default_factory=dict)
    issues: tuple[ThemeIssue, ...] = ()


def check_theme_css(text: str, assets: set[str]) -> CssReport:
    """Parse ``theme.css``. ``assets`` is the set of package-relative paths."""
    issues = list(_raw_issues(text))
    if len(text.encode("utf-8")) > 32 * 1024:
        issues.append(_issue("css_rejected", "theme.css must be 32 KiB or smaller.", "theme.css"))
    try:
        rules = tinycss2.parse_stylesheet(text, skip_comments=True, skip_whitespace=True)
    except ValueError as exc:
        issues.append(_issue("css_rejected",
            f"theme.css could not be parsed ({exc}).",
            "theme.css"))
        return CssReport("", issues=tuple(issues))
    blocks: list[str] = []
    root: dict[str, str] = {}
    light: dict[str, str] = {}
    dark: dict[str, str] = {}
    for rule in rules:
        if isinstance(rule, ParseError):
            issues.append(_issue("css_rejected", f"CSS parse error: {rule.message}", "theme.css"))
            continue
        if isinstance(rule, AtRule):
            code = "css_import" if rule.lower_at_keyword == "import" else "css_rejected"
            issues.append(
                _issue(code, f"@{rule.at_keyword} is not allowed in theme.css.", "theme.css")
            )
            continue
        if not isinstance(rule, QualifiedRule):
            issues.append(_issue("css_rejected", "Unsupported CSS rule.", "theme.css"))
            continue
        rendered, found = _rule(rule, assets)
        issues.extend(found)
        if rendered is None:
            continue
        blocks.append(rendered[0])
        bucket, props = rendered[1], rendered[2]
        if bucket == "light":
            light.update(props)
        elif bucket == "dark":
            dark.update(props)
        elif bucket == "root":
            root.update(props)
    css = "\n".join(blocks)
    if css:
        css += "\n"
    return CssReport(css, root, light, dark, tuple(issues))


def _rule(
    rule: QualifiedRule,
    assets: set[str],
) -> tuple[tuple[str, str, dict[str, str]] | None, list[ThemeIssue]]:
    issues: list[ThemeIssue] = []
    if _has_combinator(rule.prelude) or _bad_prelude(rule.prelude):
        issues.append(
            _issue(
                "css_selector",
                "Only :root, [data-mode], and the decorative hooks are allowed.",
                "theme.css",
            )
        )
        return None, issues
    selector = re.sub(r"\s+", "", tinycss2.serialize(rule.prelude))
    lowered = selector.casefold()
    for needle in _PROTECTED:
        if needle in lowered:
            issues.append(
                _issue("css_selector", f"Themes cannot target .{needle}*.", "theme.css")
            )
            return None, issues
    decorative = _DECOR.fullmatch(selector) is not None
    custom = _CUSTOM.fullmatch(selector) is not None
    if not decorative and not custom:
        issues.append(
            _issue(
                "css_selector",
                f"Selector {selector!r} is not on the theme.css allowlist.",
                "theme.css",
            )
        )
        return None, issues
    declarations = tinycss2.parse_declaration_list(
        rule.content, skip_comments=True, skip_whitespace=True
    )
    lines: list[str] = []
    props: dict[str, str] = {}
    for item in declarations:
        if isinstance(item, ParseError):
            issues.append(_issue("css_rejected", f"CSS parse error: {item.message}", "theme.css"))
            continue
        if item.important:
            issues.append(_issue("css_rejected", "!important is not allowed.", "theme.css"))
            continue
        name = item.name
        lower = item.lower_name
        if lower in _BANNED_PROPS or lower.startswith("clip") or lower.startswith("animation"):
            issues.append(
                _issue(
                    "css_property",
                    f"{name} is not allowed. Themes cannot hide or move UI.",
                    "theme.css",
                )
            )
            continue
        value_issues = _value_issues(item.value, assets, allow_url=decorative)
        issues.extend(value_issues)
        if value_issues:
            continue
        value = tinycss2.serialize(item.value).strip()
        if custom:
            if name not in ALL_CUSTOM_PROPS:
                issues.append(
                    _issue(
                        "css_property",
                        f"{name} is not a --pp-* token.",
                        "theme.css",
                    )
                )
                continue
            checked = _check_token(name, value, assets)
            if checked is not None:
                issues.append(checked)
                continue
            props[name] = value
        elif lower not in _DECOR_PROPS:
            issues.append(
                _issue(
                    "css_property",
                    f"{name} is not allowed on a decorative hook.",
                    "theme.css",
                )
            )
            continue
        lines.append(f"  {name}: {_rewrite_urls(value, assets)};")
    if issues and not lines:
        return None, issues
    body = selector + " {\n" + "\n".join(lines) + "\n}"
    bucket = "root"
    dark = ("data-mode=dark", 'data-mode="dark"', "data-mode='dark'")
    light = ("data-mode=light", 'data-mode="light"', "data-mode='light'")
    if any(token in selector for token in dark):
        bucket = "dark"
    elif any(token in selector for token in light):
        bucket = "light"
    elif decorative:
        bucket = ""
    return (body, bucket, props), issues


def _check_token(name: str, value: str, assets: set[str]) -> ThemeIssue | None:
    token = name.removeprefix("--pp-")
    if token in COLOR_TOKENS:
        try:
            parse_color(value)
        except ValueError as exc:
            return _issue("bad_color",
                f"{name} must be a hex or oklch() colour ({exc}).",
                "theme.css")
        return None
    if token in {"fontDisplay", "fontBody", "fontMono"}:
        if _unsafe_family(value):
            return _issue("css_property", f"{name} has an unsafe font value.", "theme.css")
        return None
    if token in {"density"}:
        if value not in DENSITIES:
            return _issue("css_property",
                f"{name} must be compact, cozy, or comfortable.",
                "theme.css")
        return None
    if token == "motion":
        if value not in MOTIONS:
            return _issue("css_property", f"{name} must be none, subtle, or standard.", "theme.css")
        return None
    if token in {"ornamentHeader", "ornamentDivider", "watermark"}:
        if value == "none":
            return None
        match = re.fullmatch(r'url\("([^"]+)"\)', value)
        if match is None or match.group(1) not in assets:
            return _issue("css_url", f"{name} must be none or a package url().", "theme.css")
        return None
    number = _number(token, value)
    if number is None:
        return _issue("css_property", f"{name} has a value outside its range.", "theme.css")
    return None


def _number(token: str, value: str) -> float | None:
    limits = {
        "scale": (1.125, 1.333, False),
        "baseSize": (15, 18, True),
        "lineHeight": (1.2, 2.0, False),
        "radius": (0, 16, True),
        "borderWidth": (1, 4, True),
        "watermarkOpacity": (0, 0.06, False),
    }
    if token not in limits:
        return None
    low, high, length = limits[token]
    match = _LENGTH.fullmatch(value) if length else re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", value)
    if match is None:
        return None
    number = float(match.group(1) if length else value)
    if number < low or number > high:
        return None
    return number


def _rewrite_urls(value: str, assets: set[str]) -> str:
    """Normalize a declaration value. Package urls stay relative for now."""
    del assets
    return value


def _value_issues(tokens: list[object], assets: set[str], *, allow_url: bool) -> list[ThemeIssue]:
    issues: list[ThemeIssue] = []
    for token in tokens:
        kind = getattr(token, "type", "")
        if kind == "url":
            issues.extend(_one_url(getattr(token, "value", ""), assets, allow_url=allow_url))
        elif kind == "function":
            name = getattr(token, "lower_name", "")
            arguments = getattr(token, "arguments", [])
            if name == "url":
                text = tinycss2.serialize(arguments).strip().strip("\"'")
                issues.extend(_one_url(text, assets, allow_url=allow_url))
            elif name != "oklch":
                issues.append(_issue("css_rejected", f"{name}() is not allowed.", "theme.css"))
            else:
                issues.extend(_value_issues(arguments, assets, allow_url=allow_url))
        elif kind in {"() block", "[] block", "{} block"}:
            issues.extend(_value_issues(getattr(token, "content", []), assets, allow_url=allow_url))
        elif kind == "ident" and getattr(token, "lower_value", "") in {"expression", "behavior"}:
            issues.append(_issue("css_rejected", "CSS expressions are not allowed.", "theme.css"))
        elif kind == "error":
            issues.append(_issue("css_rejected", "CSS parse error in a value.", "theme.css"))
    return issues


def _one_url(value: str, assets: set[str], *, allow_url: bool) -> list[ThemeIssue]:
    text = value.strip().strip("\"'")
    lowered = text.casefold()
    if (
        "://" in lowered
        or lowered.startswith("//")
        or lowered.startswith("data:")
        or lowered.startswith("javascript:")
        or "\\" in text
    ):
        return [_issue("css_url", "Remote or data URLs are not allowed.", "theme.css")]
    if ".." in text.split("/"):
        return [_issue("css_url", "Theme URLs cannot contain '..'.", "theme.css")]
    if not allow_url:
        return [_issue("css_url", "url() is only allowed on decorative hooks.", "theme.css")]
    relative = text[2:] if text.startswith("./") else text
    if relative.startswith("/") or relative not in assets:
        return [
            _issue(
                "css_url",
                f"url({text}) does not match a file in this package.",
                "theme.css",
            )
        ]
    return []


def _raw_issues(text: str) -> list[ThemeIssue]:
    lowered = text.casefold()
    found: list[ThemeIssue] = []
    for needle, code, message in _RAW:
        if needle.casefold() in lowered:
            found.append(_issue(code, message, "theme.css"))
    if "url(" in lowered and "//" in lowered:
        found.append(_issue("css_url", "Remote URLs are not allowed.", "theme.css"))
    return found


def _has_combinator(tokens: list[object]) -> bool:
    seen = False
    spaced = False
    for token in tokens:
        kind = getattr(token, "type", "")
        if kind == "whitespace":
            if seen:
                spaced = True
            continue
        if kind == "literal" and getattr(token, "value", "") in {">", "+", "~", ","}:
            return True
        if spaced and seen:
            return True
        seen = True
        spaced = False
    return False


def _bad_prelude(tokens: list[object]) -> bool:
    for token in tokens:
        kind = getattr(token, "type", "")
        if kind == "function" and getattr(token, "lower_name", "") in {"has", "not", "is", "where"}:
            return True
        value = str(getattr(token, "value", "")).casefold()
        if any(needle in value for needle in _PROTECTED):
            return True
        nested = getattr(token, "content", None) or getattr(token, "arguments", None)
        if isinstance(nested, list) and _bad_prelude(nested):
            return True
    return False


def _unsafe_family(value: str) -> bool:
    if len(value) > 120:
        return True
    lowered = value.casefold()
    return any(needle in lowered for needle in ("url(", "expression", ";", "{", "}", "@", "\\"))


def _issue(code: str, message: str, path: str) -> ThemeIssue:
    return ThemeIssue(
        code=code,
        message=message,
        path=path,
        fix="Keep theme.css to --pp-* tokens and the decorative hooks listed in the addendum.",
    )
