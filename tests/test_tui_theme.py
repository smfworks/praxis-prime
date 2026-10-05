"""Theme mapping for the TUI. Palettes come from CSS the daemon already validated."""

from __future__ import annotations

import pytest

from praxis_prime.themes.color import contrast_ratio
from praxis_prime.themes.cssgen import render_css
from praxis_prime.themes.store import builtin_theme
from praxis_prime.themes.tokens import TEXT_AA
from praxis_prime.tui.palette import (
    fallback_palette,
    palette_from_active,
    resolve_mode,
    tokens_from_css,
)
from praxis_prime.tui.theme_map import theme_for


def _installed():
    installed = builtin_theme("smf.praxis")
    assert installed is not None
    return installed


def _active(installed, *, mode: str, theme_id: str = "smf.praxis", requested: str = "smf.praxis"):
    return {
        "id": theme_id,
        "requested": requested,
        "mode": mode,
        "source": "builtin",
        "contrast": installed.package.contrast,
        "packageHash": installed.package_hash,
    }


def test_smf_praxis_dark_and_light_keep_contrast() -> None:
    installed = _installed()
    css = render_css(installed.package, installed.package_hash)
    for mode in ("dark", "light"):
        palette = palette_from_active(_active(installed, mode=mode), css)
        colors = installed.package.modes[mode]
        assert palette.theme_id == "smf.praxis"
        assert palette.mode == mode
        assert palette.dark is (mode == "dark")
        assert palette.colors["bg"] == colors["bg"]
        assert palette.colors["fg"] == colors["fg"]
        assert contrast_ratio(palette.colors["fg"], palette.colors["bg"]) >= TEXT_AA
        mapped = theme_for(palette, no_color=False)
        assert mapped.background.lower() == colors["bg"].lower()
        assert mapped.foreground.lower() == colors["fg"].lower()
        assert mapped.luminosity_spread == 0
        generated = mapped.to_color_system().generate()
        assert generated["background"].lower() == colors["bg"].lower()
        assert generated["foreground"].lower() == colors["fg"].lower()
        assert generated["text"].lower() == colors["fg"].lower()
        assert generated["text-muted"].lower() == colors["fgMuted"].lower()
        assert contrast_ratio(generated["text"], generated["background"]) >= TEXT_AA


def test_bad_contrast_falls_back_to_smf_praxis() -> None:
    installed = _installed()
    colors = dict(installed.package.modes["light"])
    colors["fg"] = "#ffffff"
    colors["bg"] = "#ffffff"
    body = " ".join(
        f"--pp-{name}: {value};" for name, value in colors.items() if str(value).startswith("#")
    )
    css = f':root, :root[data-mode="light"] {{ {body} }}'
    palette = palette_from_active(
        {"id": "custom.bad", "requested": "custom.bad", "mode": "light", "contrast": "AA"},
        css,
    )
    assert palette.theme_id == "smf.praxis"
    assert palette.colors["fg"] == installed.package.modes["light"]["fg"]
    assert palette.colors["bg"] == installed.package.modes["light"]["bg"]
    assert palette.colors == fallback_palette("light").colors


def test_no_color_keeps_a_distinct_rgb_theme() -> None:
    dark_palette = fallback_palette("dark")
    light_palette = fallback_palette("light")
    dark = theme_for(dark_palette, no_color=True)
    light = theme_for(light_palette, no_color=True)
    assert dark.background.lower() == dark_palette.colors["bg"].lower()
    assert light.background.lower() == light_palette.colors["bg"].lower()
    assert dark.name != light.name
    assert dark.foreground.lower() != dark.background.lower()
    assert light.foreground.lower() != light.background.lower()


def test_system_mode_uses_colorfgbg() -> None:
    assert resolve_mode("system", {"COLORFGBG": "0;15"}) == "light"
    assert resolve_mode("system", {"COLORFGBG": "15;7"}) == "light"
    assert resolve_mode("system", {"COLORFGBG": "15;0"}) == "dark"
    assert resolve_mode("system", {}) == "dark"
    assert resolve_mode("light", {"COLORFGBG": "0;0"}) == "light"
    assert resolve_mode("nope", {}) == "dark"


def test_explicit_blocks_win_over_the_system_media_query() -> None:
    css = """
    :root, :root[data-mode="light"] { --pp-bg: #111111; --pp-fg: #eeeeee; }
    :root[data-mode="dark"] { --pp-bg: #000000; --pp-fg: #ffffff; }
    @media (prefers-color-scheme: dark) {
      :root[data-mode="system"] { --pp-bg: #123456; --pp-fg: #abcdef; }
    }
    """
    assert tokens_from_css(css, "dark")["bg"] == "#000000"
    assert tokens_from_css(css, "light")["bg"] == "#111111"


def test_system_mode_reads_the_explicit_block_for_colorfgbg() -> None:
    installed = _installed()
    css = render_css(installed.package, installed.package_hash)
    dark = palette_from_active(
        _active(installed, mode="system"),
        css,
        environ={"COLORFGBG": "15;0"},
    )
    light = palette_from_active(
        _active(installed, mode="system"),
        css,
        environ={"COLORFGBG": "0;15"},
    )
    assert dark.mode == "dark"
    assert dark.colors["bg"] == installed.package.modes["dark"]["bg"]
    assert light.mode == "light"
    assert light.colors["bg"] == installed.package.modes["light"]["bg"]


def test_omarchy_palette_comes_from_the_stylesheet(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    def boom(*_args: object, **_kwargs: object) -> None:
        calls["n"] += 1
        raise AssertionError("live_theme was called")

    monkeypatch.setattr("praxis_prime.themes.omarchy.live_theme", boom)
    installed = _installed()
    css = render_css(installed.package, "a" * 64)
    palette = palette_from_active(
        {
            "id": "omarchy.live",
            "requested": "omarchy",
            "mode": "dark",
            "contrast": installed.package.contrast,
            "packageHash": "a" * 64,
            "source": "live",
        },
        css,
    )
    assert calls["n"] == 0
    assert palette.theme_id == "omarchy.live"
    assert palette.requested == "omarchy"
    assert palette.colors["bg"] == installed.package.modes["dark"]["bg"]
    assert palette.colors["fg"] == installed.package.modes["dark"]["fg"]
