#!/usr/bin/env python3
"""WCAG 2.x contrast check for the seven built-in theme palettes.

Reproduces the pairs in docs/blueprint-addendum-2026-09.md §1.7 and Appendix B.
Text pairs must be at least 4.5:1. The decorative border pair is reported only.
Ratios come from ``praxis_prime.themes.color``, the same math the theme
validator uses.

Run: python scripts/contrast_check.py
"""

from __future__ import annotations

import sys
from pathlib import Path

_CORE = Path(__file__).resolve().parents[1] / "packages" / "prime-core"
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))

PALETTES: dict[str, dict[str, str]] = {
    "praxis-dark": {
        "bg": "#14110f",
        "bgRaised": "#1e1a17",
        "fg": "#efe7da",
        "fgMuted": "#b3a894",
        "accent": "#c08a3e",
        "accentFg": "#14110f",
        "danger": "#e0655a",
        "ok": "#6fbf73",
        "warn": "#e0b04a",
        "border": "#3a322b",
    },
    "praxis-light": {
        "bg": "#f6f1e7",
        "bgRaised": "#fffdf8",
        "fg": "#231c17",
        "fgMuted": "#5e5247",
        "accent": "#7a1f1f",
        "accentFg": "#fff8ee",
        "danger": "#a3261d",
        "ok": "#2f6b35",
        "warn": "#8a5a00",
        "border": "#d8ccb8",
    },
    "legal-light": {
        "bg": "#f7f3ea",
        "bgRaised": "#ffffff",
        "fg": "#1b2233",
        "fgMuted": "#4d5566",
        "accent": "#1f3a68",
        "accentFg": "#ffffff",
        "danger": "#8c1c2b",
        "ok": "#2e6b3f",
        "warn": "#8a5a00",
        "border": "#d6cfbf",
    },
    "legal-dark": {
        "bg": "#0f1522",
        "bgRaised": "#172033",
        "fg": "#ece6d8",
        "fgMuted": "#a9b0bf",
        "accent": "#c9a45c",
        "accentFg": "#0f1522",
        "danger": "#e57373",
        "ok": "#7cc48a",
        "warn": "#e0b04a",
        "border": "#2a3550",
    },
    "forensic-dark": {
        "bg": "#121416",
        "bgRaised": "#1b1f23",
        "fg": "#e6e9ec",
        "fgMuted": "#9aa4ae",
        "accent": "#f2a900",
        "accentFg": "#121416",
        "danger": "#ff6b5e",
        "ok": "#5ccf8a",
        "warn": "#f2a900",
        "border": "#2d333a",
    },
    "forensic-light": {
        "bg": "#f4f6f8",
        "bgRaised": "#ffffff",
        "fg": "#15191d",
        "fgMuted": "#4f5a65",
        "accent": "#0b5c8c",
        "accentFg": "#ffffff",
        "danger": "#b3261e",
        "ok": "#1f7a45",
        "warn": "#8a5a00",
        "border": "#cfd6dd",
    },
    "education-light": {
        "bg": "#f8fafc",
        "bgRaised": "#ffffff",
        "fg": "#0f172a",
        "fgMuted": "#475569",
        "accent": "#1d4ed8",
        "accentFg": "#ffffff",
        "danger": "#b91c1c",
        "ok": "#15803d",
        "warn": "#92400e",
        "border": "#cbd5e1",
    },
    "education-dark": {
        "bg": "#0f172a",
        "bgRaised": "#1e293b",
        "fg": "#f1f5f9",
        "fgMuted": "#a3b1c6",
        "accent": "#60a5fa",
        "accentFg": "#0f172a",
        "danger": "#f87171",
        "ok": "#4ade80",
        "warn": "#fbbf24",
        "border": "#334155",
    },
    "classical-dark": {
        "bg": "#0a0a0f",
        "bgRaised": "#13131a",
        "fg": "#f3eadc",
        "fgMuted": "#b5a48c",
        "accent": "#c9a96e",
        "accentFg": "#0a0a0f",
        "danger": "#e57368",
        "ok": "#9cc28a",
        "warn": "#d9b25f",
        "border": "#2a2a35",
    },
    "classical-light": {
        "bg": "#f5efe3",
        "bgRaised": "#fcf8f0",
        "fg": "#221d16",
        "fgMuted": "#5b5041",
        "accent": "#5b6b2f",
        "accentFg": "#fcf8f0",
        "danger": "#9b2c20",
        "ok": "#3f6b2a",
        "warn": "#7d5a00",
        "border": "#d9ceb8",
    },
    "medical-light": {
        "bg": "#f7fafa",
        "bgRaised": "#ffffff",
        "fg": "#10222a",
        "fgMuted": "#46606a",
        "accent": "#0e7490",
        "accentFg": "#ffffff",
        "danger": "#b42318",
        "ok": "#1b7a4b",
        "warn": "#8a5a00",
        "border": "#cfdfe3",
    },
    "medical-dark": {
        "bg": "#0c1a1f",
        "bgRaised": "#13262d",
        "fg": "#e8f2f4",
        "fgMuted": "#9db7bf",
        "accent": "#4fc3d9",
        "accentFg": "#0c1a1f",
        "danger": "#f28b82",
        "ok": "#6fd3a0",
        "warn": "#f2c14e",
        "border": "#24424b",
    },
    "dental-light": {
        "bg": "#f6fbfa",
        "bgRaised": "#ffffff",
        "fg": "#12302c",
        "fgMuted": "#4a6661",
        "accent": "#0f766e",
        "accentFg": "#ffffff",
        "danger": "#b42318",
        "ok": "#1b7a4b",
        "warn": "#8a5a00",
        "border": "#cde5e1",
    },
    "dental-dark": {
        "bg": "#0d1b1a",
        "bgRaised": "#142826",
        "fg": "#e9f6f4",
        "fgMuted": "#9fc2bc",
        "accent": "#5eead4",
        "accentFg": "#0d1b1a",
        "danger": "#f28b82",
        "ok": "#86efac",
        "warn": "#fcd34d",
        "border": "#24403c",
    },
}

# (label, foreground key, background key, minimum ratio). Border is reported, not gated.
PAIRS: tuple[tuple[str, str, str, float], ...] = (
    ("fg/bg", "fg", "bg", 4.5),
    ("fg/raised", "fg", "bgRaised", 4.5),
    ("muted/bg", "fgMuted", "bg", 4.5),
    ("muted/raised", "fgMuted", "bgRaised", 4.5),
    ("accentFg/accent", "accentFg", "accent", 4.5),
    ("accent/bg", "accent", "bg", 4.5),
    ("danger/bg", "danger", "bg", 4.5),
    ("ok/bg", "ok", "bg", 4.5),
    ("warn/bg", "warn", "bg", 4.5),
    ("border/bg(ui 3:1 not req)", "border", "bg", 0.0),
)


def main() -> int:
    # Imported after the path insert above so the script runs without an install.
    from praxis_prime.themes.color import contrast_ratio

    failures = 0
    for name, palette in PALETTES.items():
        parts: list[str] = []
        for label, foreground, background, minimum in PAIRS:
            ratio = contrast_ratio(palette[foreground], palette[background])
            flag = "" if ratio >= minimum else " FAIL"
            if flag:
                failures += 1
            parts.append(f"{label}={ratio:.2f}{flag}")
        print(f"{name:16s} " + "  ".join(parts))
    print("failures:", failures)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
