"""Reject unsafe SVG ornaments and re-serialize the ones that pass.

ElementTree does not resolve external entities on Python 3.12. A DOCTYPE,
comment, or ``ENTITY`` is still refused before parsing. Processing
instructions other than one leading XML declaration are refused from the
raw text, because the parser drops them. Attribute checks run on the
entity-decoded values. A clean SVG is written back from the parsed tree so
the bytes that are stored are the bytes that were checked.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from praxis_prime.themes.errors import ThemeIssue

_SVG_NS = "http://www.w3.org/2000/svg"
_XLINK_NS = "http://www.w3.org/1999/xlink"
ET.register_namespace("", _SVG_NS)
ET.register_namespace("xlink", _XLINK_NS)

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
_XML_DECL = re.compile(
    r"""<\?xml\s+version\s*=\s*(['"])1\.[0-9]\1"""
    r"""(?:\s+encoding\s*=\s*(['"])[A-Za-z0-9._-]+\2)?"""
    r"""(?:\s+standalone\s*=\s*(['"])(?:yes|no)\3)?\s*\?>"""
)
_LOCAL_URL = re.compile(
    r"""url\(\s*(['"]?)#([^'")\s]+)\1\s*\)""",
    re.IGNORECASE,
)


def check_svg(path: str, data: bytes) -> tuple[bytes, ThemeIssue | None]:
    """Return sanitized SVG bytes, or an issue and empty bytes.

    Calling this on its own output returns the same bytes.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        return b"", _issue(path, "SVG must be UTF-8")
    if "<!" in text or "<script" in text.lower():
        return b"", _issue(path, "SVG must not contain a DOCTYPE, entity, or script")
    found = _processing_instruction(path, text)
    if found is not None:
        return b"", found
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        return b"", _issue(path, f"SVG is not well-formed XML ({exc})")
    found = _walk(path, root)
    if found is not None:
        return b"", found
    payload = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    return payload, None


def _processing_instruction(path: str, text: str) -> ThemeIssue | None:
    matches = list(re.finditer(r"<\?", text))
    if not matches:
        return None
    first = matches[0]
    prefix = text[: first.start()]
    if prefix.strip("\ufeff \t\r\n"):
        return _issue(path, "SVG processing instructions are not allowed")
    end = text.find("?>", first.start())
    if end < 0:
        return _issue(path, "SVG processing instructions are not allowed")
    declaration = text[first.start() : end + 2]
    if _XML_DECL.fullmatch(declaration) is None or len(matches) != 1:
        return _issue(path, "SVG processing instructions are not allowed")
    return None


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
        if name == "style":
            return _issue(path, "SVG style attributes are not allowed")
        bad = _bad_value(name, value)
        if bad:
            return _issue(path, bad)
    for child in list(node):
        found = _walk(path, child)
        if found is not None:
            return found
    return None


def _bad_value(name: str, value: str) -> str:
    compact = "".join(char for char in value if char > " " and ord(char) != 127).casefold()
    if "javascript:" in compact or "data:" in compact:
        return "SVG must not contain a javascript or data URL"
    stripped = _LOCAL_URL.sub("", value)
    if "url(" in stripped.casefold():
        return "SVG url() must be a local url(#id)"
    for match in _LOCAL_URL.finditer(value):
        ident = match.group(2)
        if any(char in ident for char in ":/\\"):
            return "SVG url() must be a local url(#id)"
    if name in {"href", "xlink:href"} and not _fragment(value):
        return "SVG references must be fragments inside the file"
    return ""


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
