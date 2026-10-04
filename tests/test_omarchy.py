"""Omarchy rendered theme: map, check, serve, or fall back to smf.praxis."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from praxis_prime.gateway.themes import load_theme_asset
from praxis_prime.profiles.home import create_profile
from praxis_prime.themes.color import contrast_ratio
from praxis_prime.themes.errors import ThemeError
from praxis_prime.themes.omarchy import (
    ENV_PATH,
    LIVE_ID,
    MAX_BYTES,
    installed,
    live_theme,
    theme_file,
    watch_backend,
)
from praxis_prime.themes.select import resolve_theme, set_lock, set_profile_theme
from praxis_prime.themes.store import list_themes

_DARK = {
    "mode": "dark",
    "bg": "#14110f",
    "bgRaised": "#1e1a17",
    "fg": "#efe7da",
    "fgMuted": "#b3a894",
    "accent": "#c08a3e",
    "border": "#3a322b",
    "ok": "#6fbf73",
    "warn": "#e0b04a",
    "danger": "#e0655a",
    "tool": "#7ec8c3",
    "selection": "#1e1a17",
    "ignored": "https://evil.example/theme.css",
    "not-a-token": {"nested": True},
}

_LIGHT = {
    "mode": "light",
    "bg": "#f6f1e7",
    "bgRaised": "#fffdf8",
    "fg": "#231c17",
    "fgMuted": "#5e5247",
    "accent": "#7a1f1f",
    "border": "#d8ccb8",
    "ok": "#2f6b35",
    "warn": "#8a5a00",
    "danger": "#a3261d",
}


def _point(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    monkeypatch.setenv(ENV_PATH, str(path))


def _write(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_valid_render_maps_and_serves_both_modes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "praxis-prime.json"
    _point(monkeypatch, path)
    _write(path, _DARK)
    assert live_theme() == LIVE_ID
    theme = installed()
    assert theme is not None
    assert theme.root is None
    assert theme.source == "omarchy"
    assert theme.package.theme_id == LIVE_ID
    light = theme.package.modes["light"]
    dark = theme.package.modes["dark"]
    assert light["bg"] == dark["bg"] == "#14110f"
    assert light["accent"] == "#c08a3e"
    assert "https://evil.example" not in theme.package.files["theme.toml"].decode("utf-8")
    assert "ornaments" not in theme.package.files["theme.toml"].decode("utf-8")
    css_path = f"/themes/{LIVE_ID}/{theme.package_hash}.css"
    loaded = load_theme_asset(tmp_path, css_path)
    assert loaded is not None
    body, content_type = loaded
    assert content_type.startswith("text/css")
    assert b"#14110f" in body
    assert b"https://" not in body
    assert b"fonts.googleapis" not in body
    font = f"/themes/{LIVE_ID}/{theme.package_hash}/assets/fonts/Inter.woff2"
    font_loaded = load_theme_asset(tmp_path, font)
    assert font_loaded is not None
    assert font_loaded[0].startswith(b"wOF2")
    assert all(item.package.theme_id != LIVE_ID for item in list_themes(tmp_path))
    assert watch_backend() in {"inotify", "poll"}


def test_short_hex_and_illegal_mode_are_accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "praxis-prime.json"
    _point(monkeypatch, path)
    payload = dict(_LIGHT)
    payload["bg"] = "#fff"
    payload["mode"] = "sideways"
    _write(path, payload)
    theme = installed()
    assert theme is not None
    assert theme.package.modes["dark"]["bg"] == "#ffffff"


def test_low_contrast_is_refused_and_a_near_miss_is_nudged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    path = tmp_path / "praxis-prime.json"
    _point(monkeypatch, path)
    refused = dict(_DARK)
    refused["bg"] = "#ffffff"
    refused["bgRaised"] = "#ffffff"
    refused["fg"] = "#ffffff"
    refused["fgMuted"] = "#ffffff"
    refused["accent"] = "#ffffff"
    refused["border"] = "#ffffff"
    refused["ok"] = "#ffffff"
    refused["warn"] = "#ffffff"
    refused["danger"] = "#ffffff"
    _write(path, refused)
    with caplog.at_level(logging.WARNING, logger="praxis_prime.themes.omarchy"):
        assert live_theme() is None
    assert "smf.praxis" in caplog.text

    nudged = dict(_DARK)
    nudged["fg"] = "#5a534c"
    assert contrast_ratio(nudged["fg"], nudged["bg"]) < 4.5
    _write(path, nudged)
    theme = installed()
    assert theme is not None
    fg = theme.package.modes["light"]["fg"]
    assert fg != "#5a534c"
    assert contrast_ratio(fg, theme.package.modes["light"]["bg"]) >= 4.5
    assert contrast_ratio(fg, theme.package.modes["dark"]["bg"]) >= 4.5


def test_malformed_oversize_and_non_hex_are_ignored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    path = tmp_path / "praxis-prime.json"
    _point(monkeypatch, path)
    path.write_text("{", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="praxis_prime.themes.omarchy"):
        assert live_theme() is None
    assert "JSON" in caplog.text

    path.write_bytes(b"{" + b" " * MAX_BYTES)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="praxis_prime.themes.omarchy"):
        assert installed() is None
    assert "cap" in caplog.text

    bad = dict(_DARK)
    bad["accent"] = "rgb(10, 20, 30)"
    _write(path, bad)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="praxis_prime.themes.omarchy"):
        assert live_theme() is None
    assert "hex" in caplog.text

    short_alpha = dict(_DARK)
    short_alpha["accent"] = "#c08a"
    _write(path, short_alpha)
    assert live_theme() is None


def test_symlink_is_not_followed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    real = tmp_path / "real.json"
    _write(real, _DARK)
    link = tmp_path / "praxis-prime.json"
    link.symlink_to(real)
    _point(monkeypatch, link)
    assert live_theme() is None
    assert installed() is None


def test_missing_file_is_silent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    _point(monkeypatch, tmp_path / "missing.json")
    with caplog.at_level(logging.WARNING, logger="praxis_prime.themes.omarchy"):
        assert live_theme() is None
    assert caplog.text == ""


def test_rewrite_changes_the_served_hash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "praxis-prime.json"
    _point(monkeypatch, path)
    _write(path, _DARK)
    first = installed()
    assert first is not None
    _write(path, _LIGHT)
    second = installed()
    assert second is not None
    assert second.package_hash != first.package_hash
    assert second.package.modes["light"]["bg"] == "#f6f1e7"
    stale = load_theme_asset(tmp_path, f"/themes/{LIVE_ID}/{first.package_hash}.css")
    assert stale is None
    fresh = load_theme_asset(tmp_path, f"/themes/{LIVE_ID}/{second.package_hash}.css")
    assert fresh is not None
    assert b"#f6f1e7" in fresh[0]


def test_precedence_uses_omarchy_only_when_the_profile_chose_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = tmp_path / "praxis-prime.json"
    _point(monkeypatch, path)
    _write(path, _DARK)
    data = tmp_path / "data"
    create_profile(data, "default")
    create_profile(data, "other")
    untouched = resolve_theme(data, "default")
    assert untouched.theme_id == "smf.praxis"
    assert untouched.requested == "smf.praxis"
    public = resolve_theme(data, "")
    assert public.theme_id == "smf.praxis"

    chosen = set_profile_theme(data, "default", "omarchy", "light")
    assert chosen.requested == "omarchy"
    assert chosen.theme_id == LIVE_ID
    assert chosen.mode == "light"
    assert resolve_theme(data, "other").theme_id == "smf.praxis"

    fixed = set_profile_theme(data, "default", "smf.high-contrast", "dark")
    assert fixed.theme_id == "smf.high-contrast"
    assert fixed.requested == "smf.high-contrast"

    set_profile_theme(data, "default", "omarchy", "system")
    set_lock(data, "smf.praxis", "light")
    locked = resolve_theme(data, "default")
    assert locked.locked
    assert locked.theme_id == "smf.praxis"
    assert locked.mode == "light"

    path.unlink()
    set_lock(data, "")
    fallen = resolve_theme(data, "default")
    assert fallen.theme_id == "smf.praxis"
    assert fallen.requested == "omarchy"


def test_omarchy_cannot_be_locked(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    with pytest.raises(ThemeError) as caught:
        set_lock(data, "omarchy")
    assert caught.value.issues[0].code == "bad_id"
    assert "fixed theme" in caught.value.issues[0].message
    with pytest.raises(ThemeError):
        set_lock(data, LIVE_ID)


def test_path_respects_xdg_state_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(ENV_PATH, raising=False)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    expected = tmp_path / "state" / "omarchy" / "current" / "theme" / "praxis-prime.json"
    assert theme_file() == expected
    expected.parent.mkdir(parents=True)
    _write(expected, _LIGHT)
    assert live_theme() == LIVE_ID

    monkeypatch.delenv("XDG_STATE_HOME")
    monkeypatch.setattr("praxis_prime.themes.omarchy.Path.home", lambda: tmp_path)
    home = tmp_path / ".local" / "state" / "omarchy" / "current" / "theme" / "praxis-prime.json"
    assert theme_file() == home
