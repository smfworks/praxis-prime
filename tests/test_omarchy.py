"""Omarchy rendered theme: map, check, serve, or fall back to smf.praxis."""

from __future__ import annotations

import json
import logging
import os
import shutil
import threading
import time
from pathlib import Path

import pytest
from tests.test_web_api import _accounts, _raw, _raw_bytes

from praxis_prime.gateway.themes import load_theme_asset
from praxis_prime.profiles.home import ProfileHome, create_profile
from praxis_prime.state import StateDB
from praxis_prime.themes import omarchy
from praxis_prime.themes.color import contrast_ratio, from_oklch, parse_color
from praxis_prime.themes.errors import ThemeError
from praxis_prime.themes.omarchy import (
    ENV_PATH,
    LIVE_ID,
    MAX_BYTES,
    _read_capped,
    installed,
    live_theme,
    theme_file,
    watch_backend,
)
from praxis_prime.themes.select import resolve_theme, set_lock, set_profile_theme
from praxis_prime.themes.store import builtin_theme, list_themes

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

# Education's dark palette. A third distinct page colour for a directory swap.
_NORD = {
    "mode": "dark",
    "bg": "#0f172a",
    "bgRaised": "#1e293b",
    "fg": "#f1f5f9",
    "fgMuted": "#a3b1c6",
    "accent": "#60a5fa",
    "border": "#334155",
    "ok": "#4ade80",
    "warn": "#fbbf24",
    "danger": "#f87171",
    "selection": "#1e293b",
}


def _point(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    monkeypatch.setenv(ENV_PATH, str(path))


def _write(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def _choose(data_root: Path) -> None:
    create_profile(data_root, "default")
    set_profile_theme(data_root, "default", "omarchy", "dark")


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
    _choose(tmp_path)
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
    _choose(tmp_path)
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


def test_eight_digit_hex_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog):
    path = tmp_path / "praxis-prime.json"
    _point(monkeypatch, path)
    latte = {
        "bg": "#eff1f510",
        "bgRaised": "#e6e9ef10",
        "fg": "#3f425b",
        "accent": "#1e66f5",
    }
    _write(path, latte)
    with caplog.at_level(logging.WARNING, logger="praxis_prime.themes.omarchy"):
        assert live_theme() is None
    assert "hex" in caplog.text
    caplog.clear()
    latte["bg"] = "#eff1f528"
    latte["bgRaised"] = "#e6e9ef28"
    _write(path, latte)
    with caplog.at_level(logging.WARNING, logger="praxis_prime.themes.omarchy"):
        assert installed() is None
    assert "hex" in caplog.text


def test_symlinked_parent_is_followed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    real = tmp_path / "real"
    real.mkdir()
    _write(real / "praxis-prime.json", _DARK)
    parent = tmp_path / "current"
    parent.symlink_to(real, target_is_directory=True)
    _point(monkeypatch, parent / "praxis-prime.json")
    assert live_theme() == LIVE_ID


def test_deep_json_and_a_huge_int_are_cached_and_ignored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    path = tmp_path / "praxis-prime.json"
    _point(monkeypatch, path)
    path.write_text("[" * 30000, encoding="utf-8")
    calls = {"n": 0}
    real = omarchy._parse_colors

    def wrapped(raw: bytes):
        calls["n"] += 1
        return real(raw)

    monkeypatch.setattr(omarchy, "_parse_colors", wrapped)
    with caplog.at_level(logging.WARNING, logger="praxis_prime.themes.omarchy"):
        assert installed() is None
    assert calls["n"] == 1
    assert installed() is None
    assert calls["n"] == 1
    assert "JSON" in caplog.text

    path.write_text('{"bg": ' + ("1" * 5000) + "}", encoding="utf-8")
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="praxis_prime.themes.omarchy"):
        assert live_theme() is None
    assert calls["n"] == 2
    assert live_theme() is None
    assert calls["n"] == 2
    assert "JSON" in caplog.text


def test_malformed_omarchy_file_still_answers_every_theme_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = tmp_path / "praxis-prime.json"
    _point(monkeypatch, path)
    server, host, _runtime = _accounts(tmp_path, profile="default")
    try:
        port = server.bound_port
        headers = {
            "Authorization": "Bearer test-token",
            "Content-Type": "application/json",
            "X-Praxis-Profile": "default",
        }
        for payload in ("[" * 30000, '{"bg": ' + ("1" * 5000) + "}"):
            path.write_text(payload, encoding="utf-8")
            body = json.dumps({"id": "omarchy", "mode": "dark", "profile": "default"}).encode()
            status, _headers, selected = _raw(
                port, "POST", "/v1/themes/select", payload=body, extra=headers
            )
            assert status == 200
            assert selected["requested"] == "omarchy"
            assert selected["id"] == "smf.praxis"
            status, _headers, active = _raw(
                port, "GET", "/v1/themes/active", extra=headers
            )
            assert status == 200
            assert active["id"] == "smf.praxis"
            status, _headers, catalog = _raw(port, "GET", "/v1/themes", extra=headers)
            assert status == 200
            assert catalog["ok"] is True
            status, _headers, raw = _raw_bytes(
                port, "GET", f"/themes/{LIVE_ID}/{'ab' * 32}.css"
            )
            assert status == 404
            assert raw
    finally:
        server.shutdown()
        host.close()


def test_live_css_is_unread_until_a_profile_chooses_omarchy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = tmp_path / "praxis-prime.json"
    _point(monkeypatch, path)
    path.write_text("[" * 30000, encoding="utf-8")
    opened = {"n": 0}
    real_open = os.open

    def spy(file, flags, *args, **kwargs):
        if os.fsdecode(file) == str(path):
            opened["n"] += 1
        return real_open(file, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", spy)
    digest = "ab" * 32
    assert load_theme_asset(tmp_path, f"/themes/{LIVE_ID}/{digest}.css") is None
    assert opened["n"] == 0
    create_profile(tmp_path, "default")
    set_profile_theme(tmp_path, "default", "omarchy", "dark")
    assert opened["n"] >= 1
    assert load_theme_asset(tmp_path, f"/themes/{LIVE_ID}/{digest}.css") is None


def test_fifo_open_does_not_block(tmp_path: Path):
    fifo = tmp_path / "praxis-prime.json"
    os.mkfifo(fifo)
    found: dict[str, object] = {}

    def read() -> None:
        found["value"] = _read_capped(fifo)

    worker = threading.Thread(target=read)
    worker.start()
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert found["value"] is None


def test_lightness_budget_is_total_not_per_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = tmp_path / "praxis-prime.json"
    _point(monkeypatch, path)
    nudged = dict(_DARK)
    nudged["fg"] = "#5a534c"
    original = parse_color("#5a534c").oklch()[0]
    _write(path, nudged)
    theme = installed()
    assert theme is not None
    moved = parse_color(theme.package.modes["light"]["fg"]).oklch()[0]
    assert abs(moved - original) <= 0.25 + 1e-6

    background = parse_color(_DARK["bg"])
    passing: float | None = None
    for step in range(201):
        light = step / 200
        if contrast_ratio(from_oklch(light, 0.02, 70), background) >= 4.5:
            passing = light
            break
    assert passing is not None
    supplied = passing - 0.40
    assert supplied > 0
    far = dict(_DARK)
    far["fg"] = from_oklch(supplied, 0.02, 70).to_hex()
    far["fgMuted"] = far["fg"]
    _write(path, far)
    assert live_theme() is None


def test_refused_palette_compiles_quickly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "praxis-prime.json"
    _point(monkeypatch, path)
    refused = {key: "#ffffff" for key in _DARK if key not in {"mode", "ignored", "not-a-token"}}
    refused["mode"] = "dark"
    _write(path, refused)
    started = time.perf_counter()
    assert installed() is None
    assert time.perf_counter() - started < 2.0


def test_derived_bg_raised_moves_lighter_than_the_page(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = tmp_path / "praxis-prime.json"
    _point(monkeypatch, path)

    def lifted(payload: dict[str, object]) -> tuple[float, float, str]:
        _write(path, payload)
        theme = installed()
        assert theme is not None
        colours = theme.package.modes["dark"]
        bg_l = parse_color(colours["bg"]).oklch()[0]
        raised_l = parse_color(colours["bgRaised"]).oklch()[0]
        return bg_l, raised_l, colours["bgRaised"]

    mid = dict(_DARK)
    del mid["bgRaised"]
    mid["bg"] = "#5a5a5a"
    bg_l, raised_l, _raised = lifted(mid)
    assert bg_l < 0.5
    assert raised_l > bg_l

    light = dict(_LIGHT)
    del light["bgRaised"]
    bg_l, raised_l, _raised = lifted(light)
    assert bg_l >= 0.5
    assert raised_l > bg_l

    dark = dict(_DARK)
    del dark["bgRaised"]
    bg_l, raised_l, _raised = lifted(dark)
    assert raised_l > bg_l

    _write(path, _DARK)
    theme = installed()
    assert theme is not None
    assert theme.package.modes["dark"]["bgRaised"] == "#1e1a17"


def test_partial_dark_palette_fills_from_the_dark_praxis_palette(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = tmp_path / "praxis-prime.json"
    _point(monkeypatch, path)
    _write(path, {"bg": "#14110f", "fg": "#efe7da", "accent": "#c08a3e"})
    theme = installed()
    assert theme is not None
    assert theme.package.theme_id == LIVE_ID
    muted = theme.package.modes["dark"]["fgMuted"]
    assert muted != "#5e5247"
    base = builtin_theme("smf.praxis")
    assert base is not None
    assert muted == base.package.modes["dark"]["fgMuted"]


def test_unchanged_signature_does_not_recompile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = tmp_path / "praxis-prime.json"
    _point(monkeypatch, path)
    _write(path, _DARK)
    assert installed() is not None
    watcher = omarchy._watcher()
    previous_backend = watcher.backend
    watcher.backend = "inotify"
    watcher._dirty.clear()
    watcher._overflow = False
    signatures = {"n": 0}
    loads = {"n": 0}
    real_signature = omarchy._signature
    real_load = omarchy._load

    def wrapped_signature(candidate: Path) -> str:
        signatures["n"] += 1
        return real_signature(candidate)

    def wrapped_load(candidate: Path):
        loads["n"] += 1
        return real_load(candidate)

    monkeypatch.setattr(omarchy, "_signature", wrapped_signature)
    monkeypatch.setattr(omarchy, "_load", wrapped_load)
    try:
        assert installed() is not None
        assert signatures["n"] == 1
        assert loads["n"] == 0
    finally:
        watcher.backend = previous_backend


def test_hot_swap_is_audited_and_the_first_sight_is_not(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = tmp_path / "praxis-prime.json"
    _point(monkeypatch, path)
    _write(path, _DARK)
    data = tmp_path / "data"
    create_profile(data, "default")
    StateDB(data / "prime.db").close()
    set_profile_theme(data, "default", "omarchy", "dark")
    db = StateDB(data / "prime.db")
    try:
        assert db.conn.execute("SELECT kind FROM audit_events").fetchall() == []
        _write(path, _LIGHT)
        choice = resolve_theme(data, "default")
        assert choice.theme_id == LIVE_ID
        row = db.conn.execute(
            "SELECT kind, payload_json FROM audit_events WHERE kind = 'theme.activate'"
        ).fetchone()
        assert row is not None
        payload = json.loads(row["payload_json"])
        assert payload["id"] == LIVE_ID
        assert payload["mode"] == "dark"
        assert payload["packageHash"] == choice.installed.package_hash
        assert payload["locked"] is False
    finally:
        db.close()


def test_select_omarchy_live_normalises_and_serves_css(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = tmp_path / "praxis-prime.json"
    _point(monkeypatch, path)
    _write(path, _DARK)
    server, host, _runtime = _accounts(tmp_path, profile="default")
    try:
        port = server.bound_port
        headers = {
            "Authorization": "Bearer test-token",
            "Content-Type": "application/json",
            "X-Praxis-Profile": "default",
        }
        body = json.dumps(
            {"id": "omarchy.live", "mode": "dark", "profile": "default"}
        ).encode()
        status, _headers, selected = _raw(
            port, "POST", "/v1/themes/select", payload=body, extra=headers
        )
        assert status == 200
        assert selected["requested"] == "omarchy"
        assert selected["id"] == LIVE_ID
        css = selected["css"]
        assert isinstance(css, str)
        status, _headers, raw = _raw_bytes(port, "GET", css)
        assert status == 200
        assert b"#14110f" in raw
        stored = ProfileHome(tmp_path / "data", "default").config_path.read_text(encoding="utf-8")
        assert 'id = "omarchy"' in stored
        assert "omarchy.live" not in stored
    finally:
        server.shutdown()
        host.close()


def _replace_theme_dir(current: Path, payload: dict[str, object]) -> Path:
    """Delete ``current/theme`` and move a new directory into its place.

    This is what ``omarchy-theme-set`` does: the theme path is a real
    directory, not a symlink that is re-pointed.
    """
    theme = current / "theme"
    if theme.is_symlink():
        theme.unlink()
    elif theme.exists():
        shutil.rmtree(theme)
    incoming = current / "incoming"
    if incoming.exists():
        shutil.rmtree(incoming)
    incoming.mkdir(parents=True)
    _write(incoming / "praxis-prime.json", payload)
    incoming.rename(theme)
    return theme / "praxis-prime.json"


def _serve(data_root: Path, bg: str) -> str:
    theme = installed()
    assert theme is not None
    assert theme.package.modes["dark"]["bg"] == bg
    css_path = f"/themes/{LIVE_ID}/{theme.package_hash}.css"
    loaded = load_theme_asset(data_root, css_path)
    assert loaded is not None
    body, content_type = loaded
    assert content_type.startswith("text/css")
    assert bg.encode("ascii") in body
    choice = resolve_theme(data_root, "default")
    assert choice.theme_id == LIVE_ID
    assert choice.installed.package.modes["dark"]["bg"] == bg
    return css_path


@pytest.mark.parametrize("backend", ["inotify", "poll"])
def test_theme_directory_swaps_serve_each_palette(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
):
    current = tmp_path / "omarchy" / "current"
    current.mkdir(parents=True)
    json_path = _replace_theme_dir(current, _DARK)
    _point(monkeypatch, json_path)
    _choose(tmp_path)
    watcher = omarchy._watcher()
    if backend == "inotify" and watcher.backend != "inotify":
        pytest.skip("this kernel has no inotify")
    previous = watcher.backend
    watcher.backend = backend
    palettes = (_DARK, _LIGHT, _NORD, _DARK)
    previous_css = ""
    try:
        for payload in palettes:
            json_path = _replace_theme_dir(current, payload)
            css_path = _serve(tmp_path, str(payload["bg"]))
            if previous_css:
                assert css_path != previous_css
                assert load_theme_asset(tmp_path, previous_css) is None
            previous_css = css_path
        if backend != "inotify":
            return
        theme = current / "theme"
        assert str(theme) in watcher._armed
        assert str(current) in watcher._armed
        watcher._dirty.clear()
        json_path.write_text(json_path.read_text(encoding="utf-8"), encoding="utf-8")
        watcher._drain()
        assert str(json_path) in watcher._dirty
    finally:
        watcher.backend = previous


@pytest.mark.parametrize("backend", ["inotify", "poll"])
def test_refused_palette_recovers_on_the_next_directory_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
):
    current = tmp_path / "omarchy" / "current"
    current.mkdir(parents=True)
    refused = {
        "bg": "#ffffff",
        "bgRaised": "#ffffff",
        "fg": "#ffffff",
        "fgMuted": "#ffffff",
        "accent": "#ffffff",
        "border": "#ffffff",
        "ok": "#ffffff",
        "warn": "#ffffff",
        "danger": "#ffffff",
    }
    json_path = _replace_theme_dir(current, refused)
    _point(monkeypatch, json_path)
    _choose(tmp_path)
    watcher = omarchy._watcher()
    if backend == "inotify" and watcher.backend != "inotify":
        pytest.skip("this kernel has no inotify")
    previous = watcher.backend
    watcher.backend = backend
    try:
        assert installed() is None
        choice = resolve_theme(tmp_path, "default")
        assert choice.requested == "omarchy"
        assert choice.theme_id == "smf.praxis"
        for payload in (_DARK, _LIGHT, _NORD, _LIGHT):
            _replace_theme_dir(current, payload)
            _serve(tmp_path, str(payload["bg"]))
    finally:
        watcher.backend = previous


@pytest.mark.parametrize("backend", ["inotify", "poll"])
def test_repointed_theme_symlink_is_noticed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
):
    current = tmp_path / "omarchy" / "current"
    current.mkdir(parents=True)
    first = tmp_path / "themes" / "latte"
    second = tmp_path / "themes" / "mocha"
    first.mkdir(parents=True)
    second.mkdir()
    _write(first / "praxis-prime.json", _LIGHT)
    _write(second / "praxis-prime.json", _DARK)
    link = current / "theme"
    link.symlink_to(first, target_is_directory=True)
    _point(monkeypatch, link / "praxis-prime.json")
    _choose(tmp_path)
    watcher = omarchy._watcher()
    if backend == "inotify" and watcher.backend != "inotify":
        pytest.skip("this kernel has no inotify")
    previous = watcher.backend
    watcher.backend = backend
    try:
        _serve(tmp_path, "#f6f1e7")
        link.unlink()
        link.symlink_to(second, target_is_directory=True)
        _serve(tmp_path, "#14110f")
        if backend != "inotify":
            return
        watcher._dirty.clear()
        (second / "praxis-prime.json").write_text(
            (second / "praxis-prime.json").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        watcher._drain()
        assert str(link / "praxis-prime.json") in watcher._dirty
    finally:
        watcher.backend = previous
