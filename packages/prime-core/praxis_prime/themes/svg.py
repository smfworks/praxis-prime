"""Reject unsafe SVG ornaments and re-serialize the ones that pass.

ElementTree does not resolve external entities on Python 3.12. A DOCTYPE,
comment, or ``ENTITY`` is still refused before parsing. Processing
instructions other than one leading XML declaration are refused from the
raw text, because the parser drops them. Attribute checks run on the
entity-decoded values. The root must be an ``svg`` element in the SVG
namespace, and every other element must be in that namespace too. A
backslash in an attribute value is refused. Paint values are parsed with
tinycss2 after CSS unescaping. A clean SVG is written back from the parsed
tree so the bytes that are stored are the bytes that were checked.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

import tinycss2

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
# Presentation attributes whose value is CSS. marker-* is the marker-start,
# marker-mid, and marker-end family. Any other value that could carry CSS
# is parsed too.
_PAINT_ATTRS = frozenset(
    {
        "fill",
        "stroke",
        "stop-color",
        "flood-color",
        "lighting-color",
        "color",
        "clip-path",
        "mask",
        "filter",
        "cursor",
        "marker",
    }
)
_BANNED_FUNCS = frozenset({"image-set", "src"})
_FRAGMENT_BAD = set(" \t\r\n\"'\\/:?#()")


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
    found = _walk(path, root, root=True)
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


def _walk(path: str, node: ET.Element, *, root: bool = False) -> ThemeIssue | None:
    namespace, tag = _split_name(node.tag)
    if root:
        if tag != "svg" or namespace != _SVG_NS:
            return _issue(path, "SVG root must be an svg element in the SVG namespace")
    elif namespace != _SVG_NS:
        return _issue(path, f"SVG element <{tag}> is not in the SVG namespace")
    if tag in _BANNED_ELEMENTS:
        return _issue(path, f"SVG element <{tag}> is not allowed")
    if tag not in _ELEMENTS:
        return _issue(path, f"SVG element <{tag}> is not on the ornament allowlist")
    for key, value in node.attrib.items():
        attr_ns, name = _split_name(key)
        if attr_ns not in {"", _SVG_NS, _XLINK_NS}:
            return _issue(path, f"SVG attribute {name} uses a foreign namespace")
        qualified = f"xlink:{name}" if attr_ns == _XLINK_NS else name
        if name.startswith("on"):
            return _issue(path, f"SVG event handler {name} is not allowed")
        if "\\" in value:
            return _issue(path, "SVG attribute values cannot contain a backslash")
        if _css_attribute(qualified, value):
            paint = _paint_problem(value)
            if paint:
                return _issue(path, paint)
        if qualified not in _ATTRS and not qualified.startswith("aria-"):
            return _issue(path, f"SVG attribute {qualified} is not on the ornament allowlist")
        if qualified == "style":
            return _issue(path, "SVG style attributes are not allowed")
        bad = _bad_value(qualified, value)
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
    if name in {"href", "xlink:href"} and not _fragment(value):
        return "SVG references must be fragments inside the file"
    return ""


def _css_attribute(name: str, value: str) -> bool:
    """Paint attributes, plus any other value that could be a CSS reference."""
    if name in _PAINT_ATTRS or name.startswith("marker-"):
        return True
    folded = value.casefold()
    return "url" in folded or "image-set" in folded or "src(" in folded or "@" in folded


def _paint_problem(value: str) -> str:
    """Reject a remote url() after CSS unescaping. Comparison is case-insensitive."""
    try:
        tokens = tinycss2.parse_component_value_list(value, skip_comments=True)
    except ValueError:
        return "SVG url() must be a local url(#id)"
    return _tokens_problem(tokens)


def _tokens_problem(tokens: list[object]) -> str:
    for token in tokens:
        kind = getattr(token, "type", "")
        if kind == "error":
            return "SVG url() must be a local url(#id)"
        if kind == "url":
            if not _same_document(str(getattr(token, "value", ""))):
                return "SVG url() must be a local url(#id)"
            continue
        if kind == "at-keyword" or (kind == "literal" and getattr(token, "value", "") == "@"):
            return "SVG paint values cannot contain @import"
        if kind == "ident" and str(getattr(token, "value", "")).casefold().startswith("@"):
            return "SVG paint values cannot contain @import"
        if kind == "function":
            name = str(getattr(token, "lower_name", ""))
            if name == "src" or name.endswith("image-set"):
                return f"SVG {name}() is not allowed"
            if name == "url":
                target = _url_target(getattr(token, "arguments", []))
                if target is None or not _same_document(target):
                    return "SVG url() must be a local url(#id)"
                continue
            nested = _tokens_problem(getattr(token, "arguments", []))
            if nested:
                return nested
            continue
        if kind in {"() block", "[] block", "{} block"}:
            nested = _tokens_problem(getattr(token, "content", []))
            if nested:
                return nested
    return ""


def _url_target(arguments: list[object]) -> str | None:
    """The unescaped target of ``url("...")``. Whitespace around it is ignored."""
    parts = [token for token in arguments if getattr(token, "type", "") != "whitespace"]
    if len(parts) != 1 or getattr(parts[0], "type", "") != "string":
        return None
    return str(getattr(parts[0], "value", ""))


def _same_document(value: str) -> bool:
    """True when the CSS-unescaped target is a same-document ``#id``."""
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1].strip()
    if len(text) < 2 or not text.startswith("#"):
        return False
    ident = text[1:]
    if not ident:
        return False
    return all(char not in _FRAGMENT_BAD and ord(char) > 32 and ord(char) != 127 for char in ident)


def _fragment(value: str) -> bool:
    text = value.strip()
    return text.startswith("#") and ":" not in text and "//" not in text and "\\" not in text


def _split_name(tag: str) -> tuple[str, str]:
    if tag.startswith("{") and "}" in tag:
        namespace, local = tag[1:].split("}", 1)
        return namespace, local.lower()
    return "", tag.lower()


def _issue(path: str, message: str) -> ThemeIssue:
    return ThemeIssue(
        code="svg_rejected",
        message=message,
        path=path,
        fix="Use a static SVG of paths and shapes, with no script, style, or external URL.",
    )
