"""Loaded shape of a praxis.theme/v1 package.

The bytes are the package the author shipped, minus ``theme.lock.json``.
Generated CSS is not part of the package.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class FontFace:
    family: str
    fallback: str
    path: str
    weight: str
    style: str


@dataclass(frozen=True, slots=True)
class ThemePackage:
    theme_id: str
    name: str
    version: str
    license: str
    description: str
    author: str
    min_praxis: str
    contrast: str
    modes: dict[str, dict[str, str]]
    shared: dict[str, str]
    font_faces: tuple[FontFace, ...]
    files: dict[str, bytes] = field(default_factory=dict)
    extra_css: str = ""

    def version_tuple(self) -> tuple[int, int, int]:
        major, minor, patch = self.version.split(".")
        return int(major), int(minor), int(patch)
