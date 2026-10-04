"""Reject unsafe SVG ornaments.

A clean SVG is kept byte for byte so the package hash stays stable.
Anything with a script, an event handler, ``foreignObject``, an external
reference, or an element outside the ornament allowlist is refused.
ElementTree does not resolve external entities on Python 3.12. A DOCTYPE
or ``ENTITY`` is still refused before parsing.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from praxis_prime.themes.errors import ThemeIssue

_ELEMENTS = frozenset(
    {
        "svg",
        "g",
        "path",
        "rect",
        "circle",
        "ellipse",
        "line",
        "polyline",
        "polygon",
        "title",
        "desc",
        "defs",
        "lineargradient",
        "radialgradient",
        "stop",
        "use",
    }
)
_ATTRS = frozenset(
    {
        "xmlns",
        "viewbox",
        "width",
        "height",
        "fill",
        "stroke",
        "stroke-width",
        "stroke-linecap",
        "stroke-linejoin",
        "stroke-miterlimit",
        "d",
        "x",
        "y",
        "x1",
        "y1",
        "x2",
        "y2",
        "cx",
        "cy",
        "r",
        "rx",
        "ry",
        "points",
        "id",
        "offset",
        "stop-color",
        "stop-opacity",
        "gradientunits",
        "gradienttransform",
        "role",
        "aria-hidden",
        "href",
        "xlink:href",
    }
)
_BANNED_ELEMENTS = frozenset(
    {"script", "foreignobject", "image", "filter", "style", "iframe", "animate", "set"}
)


def check_svg(path: str, data: bytes) -> ThemeIssue | None:
    """Return one issue, or None when the SVG is safe to keep."""
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        return _issue(path, "SVG must be UTF-8")
    lowered = text.lower()
    if "<!" in text or "<script" in lowered:
        return _issue(path, "SVG must not contain a DOCTYPE, entity, or script")
    if "javascript:" in lowered:
        return _issue(path, "SVG must not contain a javascript URL")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        return _issue(path, f"SVG is not well-formed XML ({exc})")
    return _walk(path, root)


def _walk(path: str, node: ET.Element) -> ThemeIssue | None:
    tag = _local(node.tag)
    if tag in _BANNED_ELEMENTS:
        return _issue(path, f"SVG element <{tag}> is not allowed")
    if tag not in _ELEMENTS:
        return _issue(path, f"SVG element <{tag}> is not on the ornament allowlist")
    for key, value in node.attrib.items():
        name = _local(key)
        if name.startswith("on"):
            return _issue(path, f"SVG event handler {name} is not allowed")
        if name not in _ATTRS and not name.startswith("aria-"):
            return _issue(path, f"SVG attribute {name} is not on the ornament allowlist")
        if name in {"href", "xlink:href"} and not _fragment(value):
            return _issue(path, "SVG references must be fragments inside the file")
        if name == "style":
            return _issue(path, "SVG style attributes are not allowed")
    for child in list(node):
        found = _walk(path, child)
        if found is not None:
            return found
    return None


def _fragment(value: str) -> bool:
    text = value.strip()
    return text.startswith("#") and ":" not in text and "//" not in text and "\\" not in text


def _local(tag: str) -> str:
    if tag.startswith("{"):
        tag = tag.split("}", 1)[-1]
    return tag.lower()


def _issue(path: str, message: str) -> ThemeIssue:
    return ThemeIssue(
        code="svg_rejected",
        message=message,
        path=path,
        fix="Use a static SVG of paths and shapes, with no script, style, or external URL.",
    )
