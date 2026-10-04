"""THEME-AUTHORING.md stays aligned with the validator."""

from __future__ import annotations

import re
from pathlib import Path

from praxis_prime.themes.archive import (
    MAX_CSS_BYTES,
    MAX_EXPANDED_BYTES,
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_ORNAMENT_BYTES,
    MAX_PREVIEW_BYTES,
    MAX_ZIP_BYTES,
)
from praxis_prime.themes.css_restrict import _DECOR
from praxis_prime.themes.svg import _BANNED_ELEMENTS, _ELEMENTS
from praxis_prime.themes.tokens import FONT_LICENSES, PACKAGE_LICENSES, REQUIRED_COLORS, thresholds
from praxis_prime.themes.validate import validate_files

_ROOT = Path(__file__).resolve().parents[1]
_DOC = _ROOT / "docs" / "THEME-AUTHORING.md"


def _facts(text: str) -> dict[str, str]:
    section = text.split("## Checker facts", 1)[1].split("\n## ", 1)[0]
    found: dict[str, str] = {}
    for line in section.splitlines():
        if line.startswith("- ") and ": " in line:
            key, value = line[2:].split(": ", 1)
            found[key] = value.strip()
    return found


def _fence(text: str, filename: str) -> str:
    marker = f"```text\n# {filename}\n"
    start = text.index(marker) + len(marker)
    end = text.index("```", start)
    return text[start:end]


def test_authoring_facts_match_the_validator():
    facts = _facts(_DOC.read_text(encoding="utf-8"))
    assert tuple(facts["Required colour tokens"].split()) == REQUIRED_COLORS
    assert set(facts["Font licences"].split(", ")) == FONT_LICENSES
    assert set(facts["Package licences"].split(", ")) == PACKAGE_LICENSES
    assert int(facts["Zip compressed bytes"]) == MAX_ZIP_BYTES
    assert int(facts["Zip expanded bytes"]) == MAX_EXPANDED_BYTES
    assert int(facts["Zip max files"]) == MAX_FILES
    assert int(facts["Zip max file bytes"]) == MAX_FILE_BYTES
    assert int(facts["Ornament max bytes"]) == MAX_ORNAMENT_BYTES
    assert int(facts["Theme css max bytes"]) == MAX_CSS_BYTES
    assert int(facts["Preview max bytes"]) == MAX_PREVIEW_BYTES
    text_aa, ui_aa = thresholds("AA")
    text_aaa, ui_aaa = thresholds("AAA")
    assert float(facts["Text contrast AA"]) == text_aa
    assert float(facts["UI contrast AA"]) == ui_aa
    assert float(facts["Text contrast AAA"]) == text_aaa
    assert float(facts["UI contrast AAA"]) == ui_aaa
    inner = re.search(r"\(\?:(.+)\)", _DECOR.pattern)
    assert inner is not None
    assert facts["Decorative selectors"].split() == inner.group(1).split("|")
    assert set(facts["SVG elements"].split(", ")) == _ELEMENTS
    assert set(facts["SVG banned elements"].split(", ")) == _BANNED_ELEMENTS


def test_worked_example_lints():
    text = _DOC.read_text(encoding="utf-8")
    files = {
        "theme.toml": _fence(text, "theme.toml").encode("utf-8"),
        "THEME.md": _fence(text, "THEME.md").encode("utf-8"),
        "LICENSE": _fence(text, "LICENSE").encode("utf-8"),
    }
    package = validate_files(files)
    assert package.theme_id == "lab.calm-mint"
    assert package.contrast == "AA"
    assert package.modes["light"]["accent"] == "#0f766e"
    assert package.modes["dark"]["bg"] == "#0d1b1a"
