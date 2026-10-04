"""A model writes a theme package. Lint is the judge. The live call is opt-in."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from praxis_prime.cli import build_parser
from praxis_prime.themes.cli import dispatch_theme
from praxis_prime.themes.errors import ThemeError
from praxis_prime.themes.roundtrip import (
    RouterModel,
    parse_package,
    run_roundtrip,
)
from praxis_prime.themes.validate import validate_files

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "theme_roundtrip"
_BRIEF = "dental office, calm mint"


class _Stub:
    def __init__(self, first: str, second: str) -> None:
        self.first = first
        self.second = second
        self.prompts: list[str] = []

    def complete(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if len(self.prompts) == 1:
            return self.first
        if "contrast" not in prompt:
            raise AssertionError("the fix-up prompt did not include the lint error")
        return self.second


def test_recorded_model_fixes_contrast_and_packs(tmp_path: Path):
    stub = _Stub(
        (_FIXTURES / "first.txt").read_text(encoding="utf-8"),
        (_FIXTURES / "second.txt").read_text(encoding="utf-8"),
    )
    dest = tmp_path / "pkg"
    result = run_roundtrip(stub, _BRIEF, dest)
    assert result.ok
    assert result.rounds == 2
    assert result.theme_id == "lab.calm-mint"
    assert "Required colour tokens" in stub.prompts[0]
    assert _BRIEF in stub.prompts[0]
    assert "contrast" in stub.prompts[1]
    assert (dest / "theme.toml").is_file()
    assert 'fg = "#12302c"' in (dest / "theme.toml").read_text(encoding="utf-8")

    packed = tmp_path / "lab.calm-mint-1.0.0.praxis-theme.zip"
    parser = build_parser()
    pack = parser.parse_args(["theme", "pack", str(dest), "-o", str(packed)])
    assert dispatch_theme(pack) == 0
    data = tmp_path / "data"
    data.mkdir()
    install = parser.parse_args(["theme", "install", str(packed), "--data-dir", str(data)])
    assert dispatch_theme(install) == 0
    assert (data / "themes" / "lab.calm-mint" / "1.0.0" / "theme.toml").is_file()


def test_first_fixture_fails_lint_on_its_own():
    files = parse_package((_FIXTURES / "first.txt").read_text(encoding="utf-8"))
    encoded = {name: text.encode("utf-8") for name, text in files.items()}
    with pytest.raises(ThemeError) as caught:
        validate_files(encoded)
    assert any(issue.code == "contrast" for issue in caught.value.issues)


def test_model_cannot_write_outside_the_temp_dir(tmp_path: Path):
    class _Escape:
        def complete(self, prompt: str) -> str:
            return json.dumps(
                {
                    "../secret.txt": "no",
                    "/etc/passwd": "no",
                    "assets/fonts/../../outside.txt": "no",
                    "theme.toml": "schema = \"no\"",
                }
            )

    dest = tmp_path / "pkg"
    result = run_roundtrip(_Escape(), _BRIEF, dest, rounds=1)
    assert result.ok is False
    assert not (tmp_path / "secret.txt").exists()
    assert not (tmp_path / "outside.txt").exists()
    assert not (dest / "theme.toml").exists()


@pytest.mark.skipif(
    os.environ.get("PRAXIS_PRIME_AI_ROUNDTRIP") != "1",
    reason="set PRAXIS_PRIME_AI_ROUNDTRIP=1 to call the configured provider",
)
def test_live_roundtrip_uses_the_router(tmp_path: Path):
    result = run_roundtrip(RouterModel(), _BRIEF, tmp_path / "pkg")
    assert result.ok
    assert result.theme_id
    assert not result.theme_id.startswith("smf")
