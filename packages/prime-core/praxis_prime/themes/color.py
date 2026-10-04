"""Colour parsing and WCAG 2.x contrast.

Accepted forms are ``#rgb``, ``#rgba``, ``#rrggbb``, ``#rrggbbaa``, and
``oklch()``. Nothing else is a colour, so a token cannot carry ``url()``,
``var()``, or ``expression()``.

The contrast math is the WCAG 2.x relative-luminance formula. ``scripts/contrast_check.py``
calls ``contrast_ratio`` so the palette check and the installer share one implementation.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

_HEX = re.compile(r"^#([0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$")
_OKLCH = re.compile(
    r"^oklch\(\s*([^\s/)]+|\bnone\b)\s+([^\s/)]+|\bnone\b)\s+([^\s/)]+|\bnone\b)"
    r"(?:\s*/\s*([^\s)]+|\bnone\b))?\s*\)$",
    re.IGNORECASE,
)

# CSS Color 4 matrices (Björn Ottosson). Linear sRGB ↔ OKLab.
_TO_LMS = (
    (0.4122214708, 0.5363325363, 0.0514459929),
    (0.2119034982, 0.6806995451, 0.1073969566),
    (0.0883024619, 0.2817188376, 0.6299787005),
)
_TO_OKLAB = (
    (0.2104542553, 0.7936177850, -0.0040720468),
    (1.9779984951, -2.4285922050, 0.4505937099),
    (0.0259040371, 0.7827717662, -0.8086757660),
)
_FROM_OKLAB = (
    (1.0, 0.3963377774, 0.2158037573),
    (1.0, -0.1055613458, -0.0638541728),
    (1.0, -0.0894841775, -1.2914855480),
)
_FROM_LMS = (
    (4.0767416621, -3.3077115913, 0.2309699292),
    (-1.2684380046, 2.6097574011, -0.3413193965),
    (-0.0041960863, -0.7034186147, 1.7076147010),
)


@dataclass(frozen=True, slots=True)
class Color:
    """A colour in gamma-encoded sRGB, channels 0–1, plus alpha."""

    r: float
    g: float
    b: float
    a: float = 1.0

    def to_hex(self) -> str:
        def byte(channel: float) -> int:
            return max(0, min(255, round(channel * 255)))

        red, green, blue = byte(self.r), byte(self.g), byte(self.b)
        if self.a >= 0.999:
            return f"#{red:02x}{green:02x}{blue:02x}"
        alpha = byte(self.a)
        return f"#{red:02x}{green:02x}{blue:02x}{alpha:02x}"

    def oklch(self) -> tuple[float, float, float]:
        return _srgb_to_oklch(self.r, self.g, self.b)

    def with_lightness(self, lightness: float) -> Color:
        _light, chroma, hue = self.oklch()
        return from_oklch(lightness, chroma, hue, self.a)


def parse_color(text: str) -> Color:
    """Parse one token colour. Raises ``ValueError`` with the reason."""
    raw = text.strip()
    hex_match = _HEX.fullmatch(raw)
    if hex_match:
        return _parse_hex(hex_match.group(1))
    oklch_match = _OKLCH.fullmatch(raw)
    if oklch_match:
        return _parse_oklch(oklch_match)
    raise ValueError(
        f"{text!r} is not a colour. Use #rgb, #rrggbb, #rrggbbaa, or oklch(L C H)."
    )


def composite(front: Color, back: Color) -> Color:
    """Porter-Duff source-over. Opaque ``back`` makes the result opaque."""
    return _over(front, back)


def contrast_ratio(left: str | Color, right: str | Color) -> float:
    """WCAG contrast of the two colours as they composite.

    A translucent colour is drawn over the other. When both are translucent,
    the background is first drawn over white. Opaque colours use the plain ratio.
    """
    fg = left if isinstance(left, Color) else parse_color(left)
    bg = right if isinstance(right, Color) else parse_color(right)
    if bg.a < 0.999:
        bg = _over(bg, Color(1, 1, 1, 1))
    if fg.a < 0.999:
        fg = _over(fg, bg)
    lighter, darker = sorted((_luminance(fg), _luminance(bg)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def relative_luminance(hex_color: str) -> float:
    """sRGB relative luminance. Kept for ``scripts/contrast_check.py``."""
    return _luminance(parse_color(hex_color))


def from_oklch(lightness: float, chroma: float, hue: float, alpha: float = 1.0) -> Color:
    """Convert OKLCH to sRGB, dropping chroma until the colour fits the gamut."""
    light = _clamp(lightness, 0.0, 1.0)
    for scale in (1.0, 0.85, 0.7, 0.5, 0.3, 0.15, 0.0):
        red, green, blue = _oklch_to_srgb(light, max(0.0, chroma) * scale, hue)
        if _in_gamut(red, green, blue):
            return Color(_clamp(red), _clamp(green), _clamp(blue), _clamp(alpha))
    red, green, blue = _oklch_to_srgb(light, 0.0, hue)
    return Color(_clamp(red), _clamp(green), _clamp(blue), _clamp(alpha))


def mix(a: Color, b: Color, amount: float) -> Color:
    """OKLCH mix. ``amount`` is the weight of ``b`` (0 keeps ``a``)."""
    weight = _clamp(amount, 0.0, 1.0)
    a_l, a_c, a_h = a.oklch()
    b_l, b_c, b_h = b.oklch()
    return from_oklch(
        a_l + (b_l - a_l) * weight,
        a_c + (b_c - a_c) * weight,
        _lerp_hue(a_h, b_h, weight),
        a.a + (b.a - a.a) * weight,
    )


def best_ink(background: Color) -> Color:
    """Black or white, whichever contrasts more with ``background``."""
    black = Color(0, 0, 0)
    white = Color(1, 1, 1)
    if contrast_ratio(white, background) >= contrast_ratio(black, background):
        return white
    return black


def adjust_lightness(
    color: Color,
    backgrounds: tuple[Color, ...],
    minimum: float,
    *,
    max_delta: float = 0.25,
) -> Color | None:
    """Move OKLCH lightness until ``color`` clears ``minimum`` on every background.

    The search stays within ``max_delta``. ``None`` means no such colour, which
    the legacy-hint mapper treats as a refusal.
    """
    if _clears(color, backgrounds, minimum):
        return color
    light, _chroma, _hue = color.oklch()
    steps = int(max_delta / 0.005)
    for step in range(1, steps + 1):
        delta = step * 0.005
        for sign in (-1.0, 1.0):
            candidate = color.with_lightness(_clamp(light + sign * delta, 0.0, 1.0))
            if _clears(candidate, backgrounds, minimum):
                return candidate
    return None


def _clears(color: Color, backgrounds: tuple[Color, ...], minimum: float) -> bool:
    return all(contrast_ratio(color, background) + 1e-9 >= minimum for background in backgrounds)


def _parse_hex(digits: str) -> Color:
    if len(digits) in {3, 4}:
        digits = "".join(char * 2 for char in digits)
    red = int(digits[0:2], 16) / 255
    green = int(digits[2:4], 16) / 255
    blue = int(digits[4:6], 16) / 255
    alpha = int(digits[6:8], 16) / 255 if len(digits) == 8 else 1.0
    return Color(red, green, blue, alpha)


def _parse_oklch(match: re.Match[str]) -> Color:
    lightness = _oklch_lightness(match.group(1))
    chroma = _oklch_chroma(match.group(2))
    hue = _angle(match.group(3))
    alpha = 1.0 if match.group(4) is None else _alpha(match.group(4))
    return from_oklch(lightness, chroma, hue, alpha)


def _oklch_lightness(token: str) -> float:
    if token.lower() == "none":
        return 0.0
    if token.endswith("%"):
        return _clamp(float(token[:-1]) / 100, 0.0, 1.0)
    return _clamp(float(token), 0.0, 1.0)


def _oklch_chroma(token: str) -> float:
    if token.lower() == "none":
        return 0.0
    if token.endswith("%"):
        # CSS Color 4: 100% chroma in oklch is 0.4.
        return max(0.0, float(token[:-1]) / 100 * 0.4)
    return max(0.0, float(token))


def _alpha(token: str) -> float:
    if token.lower() == "none":
        return 0.0
    if token.endswith("%"):
        return _clamp(float(token[:-1]) / 100, 0.0, 1.0)
    return _clamp(float(token), 0.0, 1.0)


def _angle(token: str) -> float:
    if token.lower() == "none":
        return 0.0
    lower = token.lower()
    if lower.endswith("deg"):
        value = float(lower[:-3])
    elif lower.endswith("turn"):
        value = float(lower[:-4]) * 360
    elif lower.endswith("rad"):
        value = math.degrees(float(lower[:-3]))
    elif lower.endswith("grad"):
        value = float(lower[:-4]) * 0.9
    else:
        value = float(lower)
    return value % 360


def _luminance(color: Color) -> float:
    def linearize(channel: float) -> float:
        if channel <= 0.04045:
            return channel / 12.92
        return ((channel + 0.055) / 1.055) ** 2.4

    return (
        0.2126 * linearize(color.r)
        + 0.7152 * linearize(color.g)
        + 0.0722 * linearize(color.b)
    )


def _over(fg: Color, bg: Color) -> Color:
    alpha = fg.a + bg.a * (1 - fg.a)
    if alpha <= 0:
        return Color(0, 0, 0, 0)

    def channel(front: float, back: float) -> float:
        return (front * fg.a + back * bg.a * (1 - fg.a)) / alpha

    return Color(channel(fg.r, bg.r), channel(fg.g, bg.g), channel(fg.b, bg.b), 1.0)


def _srgb_to_oklch(red: float, green: float, blue: float) -> tuple[float, float, float]:
    linear = tuple(_to_linear(channel) for channel in (red, green, blue))
    lms = tuple(
        math.cbrt(sum(coef * channel for coef, channel in zip(row, linear, strict=True)))
        for row in _TO_LMS
    )
    lab = tuple(
        sum(coef * channel for coef, channel in zip(row, lms, strict=True)) for row in _TO_OKLAB
    )
    chroma = math.hypot(lab[1], lab[2])
    hue = math.degrees(math.atan2(lab[2], lab[1])) % 360
    return lab[0], chroma, hue


def _oklch_to_srgb(lightness: float, chroma: float, hue: float) -> tuple[float, float, float]:
    radians = math.radians(hue)
    a = chroma * math.cos(radians)
    b = chroma * math.sin(radians)
    lms_ = tuple(
        lightness * row[0] + a * row[1] + b * row[2] for row in _FROM_OKLAB
    )
    lms = tuple(channel**3 for channel in lms_)
    linear = tuple(
        sum(coef * channel for coef, channel in zip(row, lms, strict=True)) for row in _FROM_LMS
    )
    return tuple(_from_linear(channel) for channel in linear)


def _to_linear(channel: float) -> float:
    if channel <= 0.04045:
        return channel / 12.92
    return ((channel + 0.055) / 1.055) ** 2.4


def _from_linear(channel: float) -> float:
    if channel <= 0.0031308:
        return 12.92 * channel
    return 1.055 * (channel ** (1 / 2.4)) - 0.055


def _in_gamut(red: float, green: float, blue: float) -> bool:
    return all(-0.001 <= channel <= 1.001 for channel in (red, green, blue))


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _lerp_hue(start: float, end: float, amount: float) -> float:
    delta = (end - start) % 360
    if delta > 180:
        delta -= 360
    return (start + delta * amount) % 360
