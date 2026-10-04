"""Omarchy live-theme adapter.

Reads the rendered file ``~/.local/state/omarchy/current/theme/praxis-prime.json``
(override with ``PRAXIS_PRIME_OMARCHY_THEME``; ``XDG_STATE_HOME`` is honoured).
The file is untrusted: size is capped, only the template's keys are read,
and colour values must be hex. Missing required tokens are derived in OKLCH.
The result goes through the same contrast check as a package. Lightness may
move by at most 0.25. If it still fails AA, the adapter logs the reason and
returns nothing, so selection falls through to ``smf.praxis``.

The compiled package is kept in memory as ``omarchy.live``. It is not
installed and it cannot be locked. Nothing here calls the network or opens
any path other than that one file.

ARCHITECTURE §28.2. Addendum A §1.6.
"""

from __future__ import annotations

import json
import logging
import os
import re
import stat
import threading
from pathlib import Path

from praxis_prime.scheduler.watch import DirectoryWatcher
from praxis_prime.statfile import StatKind, lstat_kind
from praxis_prime.themes.color import (
    adjust_lightness,
    best_ink,
    contrast_ratio,
    parse_color,
)
from praxis_prime.themes.errors import ThemeError
from praxis_prime.themes.lockfile import package_hash
from praxis_prime.themes.store import InstalledTheme, builtin_theme
from praxis_prime.themes.tokens import (
    CONTRAST_PAIRS,
    REQUIRED_COLORS,
    TEXT_AA,
    UI_AA,
    complete_colors,
    thresholds,
)
from praxis_prime.themes.validate import contrast_modes, validate_files

_LOG = logging.getLogger("praxis_prime.themes.omarchy")

LIVE_ID = "omarchy.live"
ENV_PATH = "PRAXIS_PRIME_OMARCHY_THEME"
MAX_BYTES = 64 * 1024
_FILENAME = "praxis-prime.json"
# #rgb, #rrggbb, #rrggbbaa. Four-digit #rgba and oklch() are not accepted.
_HEX = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$")
_COLOR_KEYS = (
    "bg",
    "bgRaised",
    "fg",
    "fgMuted",
    "accent",
    "border",
    "ok",
    "warn",
    "danger",
    "tool",
    "selection",
)
# Foregrounds move before backgrounds so a nudge repairs text first.
_NUDGE_ORDER = (
    "fg",
    "fgMuted",
    "accent",
    "ok",
    "warn",
    "danger",
    "tool",
    "selection",
    "border",
    "bg",
    "bgRaised",
)
_SECTION = re.compile(r"(?ms)^\[(?P<name>tokens\.(?:light|dark))\]\n.*?(?=^\[|\Z)")
_ORNAMENTS = re.compile(r"(?ms)^\[ornaments\]\n.*?(?=^\[|\Z)")
_LOCK = threading.Lock()
_CACHE: dict[str, tuple[str, InstalledTheme | None]] = {}
_WATCHER: DirectoryWatcher | None = None


def live_theme(path: Path | None = None) -> str | None:
    """Return ``omarchy.live`` when the rendered file compiles, else None.

    A missing file is normal outside Omarchy and is not logged. A present
    file that cannot be used is logged, and the caller falls back to
    ``smf.praxis``.
    """
    theme = installed(path)
    if theme is None:
        return None
    return LIVE_ID


def installed(path: Path | None = None) -> InstalledTheme | None:
    """The in-memory package for the current file, or None.

    Checked on each call from the file's mtime and size, so a rewrite is
    visible to the next ``/v1/themes/active`` without a background thread.
    inotify is armed on the parent directory when the kernel provides it;
    the mtime poll still decides.
    """
    source = theme_file(path)
    _arm(source)
    signature = _signature(source)
    key = str(source)
    with _LOCK:
        cached = _CACHE.get(key)
        if cached is not None and cached[0] == signature:
            return cached[1]
    compiled = _load(source)
    with _LOCK:
        _CACHE[key] = (signature, compiled)
    return compiled


def theme_file(path: Path | None = None) -> Path:
    """Resolved path of the rendered Omarchy theme. Does not touch the disk."""
    if path is not None:
        return path
    override = os.environ.get(ENV_PATH, "").strip()
    if override:
        return Path(override)
    state = os.environ.get("XDG_STATE_HOME", "").strip()
    base = Path(state) if state else Path.home() / ".local" / "state"
    return base / "omarchy" / "current" / "theme" / _FILENAME


def watch_backend() -> str:
    """``inotify`` or ``poll``. Used by tests to see that the watcher is armed."""
    return _watcher().backend


def _arm(path: Path) -> None:
    try:
        _watcher().observe(path, "", startup=True)
    except OSError:
        return


def _watcher() -> DirectoryWatcher:
    global _WATCHER
    if _WATCHER is None:
        _WATCHER = DirectoryWatcher()
    return _WATCHER


def _signature(path: Path) -> str:
    kind = lstat_kind(path)
    if kind is not StatKind.FILE:
        return kind.value
    try:
        info = os.lstat(path)
    except OSError:
        return "unreadable"
    return f"f:{info.st_mtime_ns}:{info.st_size}"


def _load(path: Path) -> InstalledTheme | None:
    kind = lstat_kind(path)
    if kind is StatKind.MISSING:
        return None
    if kind is not StatKind.FILE:
        _LOG.warning(
            "Omarchy theme path is %s, not a regular file. Ignoring it and using smf.praxis.",
            kind.value,
        )
        return None
    raw = _read_capped(path)
    if raw is None:
        return None
    colors = _parse_colors(raw)
    if colors is None:
        return None
    return _compile(colors)


def _read_capped(path: Path) -> bytes | None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        _LOG.warning("Omarchy theme file could not be opened (%s). Using smf.praxis.", exc.strerror)
        return None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            _LOG.warning("Omarchy theme path is not a regular file. Using smf.praxis.")
            return None
        if info.st_size > MAX_BYTES:
            _LOG.warning(
                "Omarchy theme file is %s bytes, over the %s byte cap. "
                "Ignoring it and using smf.praxis.",
                info.st_size,
                MAX_BYTES,
            )
            return None
        return os.read(descriptor, MAX_BYTES)
    finally:
        os.close(descriptor)


def _parse_colors(raw: bytes) -> dict[str, str] | None:
    try:
        loaded = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        _LOG.warning("Omarchy theme file is not UTF-8 JSON. Ignoring it and using smf.praxis.")
        return None
    if not isinstance(loaded, dict):
        _LOG.warning("Omarchy theme file is not a JSON object. Ignoring it and using smf.praxis.")
        return None
    colors: dict[str, str] = {}
    for key, value in loaded.items():
        if not isinstance(key, str) or key == "mode" or key not in _COLOR_KEYS:
            continue
        if not isinstance(value, str) or _HEX.fullmatch(value.strip()) is None:
            _LOG.warning(
                "Omarchy theme key %s is not a hex colour (#rgb, #rrggbb, or #rrggbbaa). "
                "Refusing the file and using smf.praxis.",
                key,
            )
            return None
        colors[key] = parse_color(value).to_hex()
    if not colors:
        _LOG.warning("Omarchy theme file has no colour keys. Ignoring it and using smf.praxis.")
        return None
    return colors


def _compile(supplied: dict[str, str]) -> InstalledTheme | None:
    base = builtin_theme("smf.praxis")
    if base is None:
        _LOG.warning("smf.praxis is not available, so the Omarchy palette was not compiled.")
        return None
    seed = {name: base.package.modes["light"][name] for name in REQUIRED_COLORS}
    tuned = _nudge(supplied, seed)
    if tuned is None:
        _LOG.warning(
            "Omarchy palette cannot meet WCAG AA within a 0.25 OKLCH lightness change. "
            "Using smf.praxis."
        )
        return None
    files = dict(base.package.files)
    text = files["theme.toml"].decode("utf-8")
    text = text.replace('id = "smf.praxis"', f'id = "{LIVE_ID}"', 1)
    text = text.replace('name = "Praxis"', 'name = "Omarchy"', 1)
    text = text.replace(
        'description = "Marble, oxblood, and bronze. The default Praxis Prime theme."',
        'description = "Live colours from the Omarchy theme file, checked for WCAG AA."',
        1,
    )
    text = _ORNAMENTS.sub("", text)
    authored = {name: tuned[name] for name in REQUIRED_COLORS}
    for name in ("tool", "selection"):
        if name in supplied:
            authored[name] = tuned[name]
    text = _write_tokens(text, authored)
    files["theme.toml"] = text.encode("utf-8")
    try:
        package = validate_files(files)
    except ThemeError as exc:
        _LOG.warning("Omarchy palette failed validation (%s). Using smf.praxis.", exc)
        return None
    return InstalledTheme(
        package=package,
        source="omarchy",
        root=None,
        package_hash=package_hash(package.files),
    )


def _write_tokens(text: str, colors: dict[str, str]) -> str:
    keys = [name for name in (*REQUIRED_COLORS, "tool", "selection") if name in colors]
    body = "".join(f'{name} = "{colors[name]}"\n' for name in keys)

    def repl(match: re.Match[str]) -> str:
        return f"[{match.group('name')}]\n{body}"

    return _SECTION.sub(repl, text)


def _nudge(supplied: dict[str, str], seed: dict[str, str]) -> dict[str, str] | None:
    """Return a palette that passes AA, moving supplied colours by at most 0.25."""
    current = dict(supplied)
    full = _assemble(current, seed)
    if full is not None and _clear(full):
        return full
    keys = [key for key in _NUDGE_ORDER if key in current]
    for _pass in range(3):
        moved = False
        for key in keys:
            updated = _search(key, current, seed)
            if updated is None or updated == current[key]:
                continue
            current[key] = updated
            moved = True
        if not moved:
            break
    full = _assemble(current, seed)
    if full is not None and _clear(full):
        return full
    return None


def _search(key: str, current: dict[str, str], seed: dict[str, str]) -> str | None:
    color = parse_color(current[key])
    light, _chroma, _hue = color.oklch()
    for step in range(0, 51):
        delta = step * 0.005
        signs = (0.0,) if step == 0 else (-1.0, 1.0)
        for sign in signs:
            candidate = color.with_lightness(min(1.0, max(0.0, light + sign * delta)))
            trial = dict(current)
            trial[key] = candidate.to_hex()
            full = _assemble(trial, seed)
            if full is None:
                continue
            if _token_clear(full, key):
                return candidate.to_hex()
    return None


def _assemble(supplied: dict[str, str], seed: dict[str, str]) -> dict[str, str] | None:
    required = {name: seed[name] for name in REQUIRED_COLORS}
    for key, value in supplied.items():
        if key in required:
            required[key] = value
    derived = _derive(required)
    if derived is None:
        return None
    required.update(derived)
    try:
        full = complete_colors({name: required[name] for name in REQUIRED_COLORS}, level="AA")
    except ValueError:
        return None
    for key in ("tool", "selection"):
        if key in supplied:
            full[key] = supplied[key]
    return full


def _derive(required: dict[str, str]) -> dict[str, str] | None:
    background = parse_color(required["bg"])
    raised = parse_color(required["bgRaised"])
    accent = parse_color(required["accent"])
    border = parse_color(required["border"])
    muted = parse_color(required["fgMuted"])
    accent_fg = adjust_lightness(best_ink(accent), (accent,), TEXT_AA, max_delta=0.25)
    border_strong = adjust_lightness(border, (background, raised), UI_AA, max_delta=0.25)
    if border_strong is None:
        border_strong = adjust_lightness(muted, (background, raised), UI_AA, max_delta=0.25)
    ring = adjust_lightness(accent, (background, raised), UI_AA, max_delta=0.25)
    if accent_fg is None or border_strong is None or ring is None:
        return None
    return {
        "accentFg": accent_fg.to_hex(),
        "borderStrong": border_strong.to_hex(),
        "ring": ring.to_hex(),
    }


def _clear(colors: dict[str, str]) -> bool:
    return not contrast_modes({"light": colors, "dark": colors}, "AA")


def _token_clear(colors: dict[str, str], token: str) -> bool:
    text_min, ui_min = thresholds("AA")
    for foreground, background, kind in CONTRAST_PAIRS:
        if token not in {foreground, background}:
            continue
        if foreground not in colors or background not in colors:
            return False
        minimum = text_min if kind == "text" else ui_min
        ratio = contrast_ratio(colors[foreground], colors[background])
        if ratio + 1e-9 < minimum:
            return False
    return True
