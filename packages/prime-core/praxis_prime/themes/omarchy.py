"""Omarchy live-theme adapter.

Reads the rendered file ``~/.local/state/omarchy/current/theme/praxis-prime.json``
(override with ``PRAXIS_PRIME_OMARCHY_THEME``; ``XDG_STATE_HOME`` is honoured).
The file is untrusted: size is capped, only the template's keys are read,
and a colour must be ``#rgb`` or ``#rrggbb``. Missing required tokens are
derived in OKLCH from the dark ``smf.praxis`` palette when ``bg`` is dark,
otherwise from the light palette. A seeded ``bgRaised`` that is not already
lighter than ``bg`` is lifted. The result goes through the same contrast
check as a package. Lightness may move by at most 0.25 in total. If it still
fails AA, the adapter logs the reason and returns nothing, so selection falls
through to ``smf.praxis``.

The compiled package is kept in memory as ``omarchy.live``. It is not
installed and it cannot be locked. Nothing here calls the network.
``O_NOFOLLOW`` covers the final path component. Omarchy theme-set deletes
the real directory ``current/theme`` and moves a new directory into its
place. A symlinked parent is still followed. The watch is re-armed when
that directory goes away, and every check stats the file and its parent.

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
# #rgb or #rrggbb. Eight-digit hex is translucent and is refused: a dark
# color-scheme paints that colour over a dark canvas, which the white-page
# contrast math does not see. Four-digit #rgba and oklch() are not accepted.
_HEX = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
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
_WATCH_TOKEN: dict[str, str] = {}
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

    The watcher is armed on the theme directory and on its parent, and it
    is re-armed when that directory is replaced. Every check still stats
    the file inode, mtime, and size and the parent directory inode. A
    dirty or overflowed watch re-reads the file even when that signature
    matches. A clean watch reuses the cached package, including a cached
    refusal, when the signature matches, and does not compile again.
    """
    source = theme_file(path)
    key = str(source)
    with _LOCK:
        previous = _WATCH_TOKEN.get(key, "")
    try:
        seen = _watcher().observe(source, previous, startup=not previous)
    except OSError:
        changed, token = True, previous
    else:
        # A dirty or overflowed watch bypasses the signature cache.
        changed = seen.token_changed or seen.dirty or seen.overflowed
        token = seen.token
    with _LOCK:
        _WATCH_TOKEN[key] = token
    signature = _signature(source)
    with _LOCK:
        cached = _CACHE.get(key)
        if not changed and cached is not None and cached[0] == signature:
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


def _watcher() -> DirectoryWatcher:
    global _WATCHER
    if _WATCHER is None:
        _WATCHER = DirectoryWatcher()
    return _WATCHER


def _signature(path: Path) -> str:
    """File inode, mtime, and size, plus the parent directory inode.

    A replaced ``current/theme`` is a new directory inode even when the
    queue that was watching the old one has gone quiet. A symlinked parent
    also records its target, so re-pointing it changes the signature.
    """
    parent = _parent_token(path)
    kind = lstat_kind(path)
    if kind is not StatKind.FILE:
        return f"{kind.value}:{parent}"
    try:
        info = os.lstat(path)
    except OSError:
        return f"unreadable:{parent}"
    return f"f:{info.st_ino}:{info.st_mtime_ns}:{info.st_size}:{parent}"


def _parent_token(path: Path) -> str:
    try:
        info = os.lstat(path.parent)
    except OSError:
        return "absent"
    token = str(info.st_ino)
    if stat.S_ISLNK(info.st_mode):
        try:
            token = f"{token}:{os.readlink(path.parent)}"
        except OSError:
            token = f"{token}:unread"
    return token


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
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
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
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
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
                "Omarchy theme key %s is not a hex colour (#rgb or #rrggbb). "
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
    seed_mode = "light"
    if "bg" in supplied and parse_color(supplied["bg"]).oklch()[0] < 0.5:
        seed_mode = "dark"
    seed = {name: base.package.modes[seed_mode][name] for name in REQUIRED_COLORS}
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
    """Return a palette that passes AA, moving supplied colours by at most 0.25.

    The 0.25 OKLCH lightness budget is measured from the colour in the file,
    across every pass. A later pass cannot spend the budget again.
    """
    current = dict(supplied)
    original = {key: parse_color(value).oklch()[0] for key, value in supplied.items()}
    full = _assemble(current, seed)
    if full is not None and _clear(full):
        return full
    keys = [key for key in _NUDGE_ORDER if key in current]
    for _pass in range(3):
        moved = False
        for key in keys:
            updated = _search(key, current, seed, original[key])
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


def _search(
    key: str,
    current: dict[str, str],
    seed: dict[str, str],
    original_light: float,
) -> str | None:
    """Smallest lightness move that clears this token, inside the original band."""
    color = parse_color(current[key])
    light, _chroma, _hue = color.oklch()
    low = max(0.0, original_light - 0.25)
    high = min(1.0, original_light + 0.25)

    def attempt(target: float) -> str | None:
        if target < low - 1e-9 or target > high + 1e-9:
            return None
        candidate = color.with_lightness(min(high, max(low, target)))
        trial = dict(current)
        trial[key] = candidate.to_hex()
        full = _assemble(trial, seed)
        if full is None or not _token_clear(full, key):
            return None
        return candidate.to_hex()

    found = attempt(light)
    if found is not None:
        return found
    best: tuple[float, str] | None = None
    for sign in (-1.0, 1.0):
        reach = (light - low) if sign < 0 else (high - light)
        if reach <= 1e-9:
            continue
        hit: float | None = None
        for step in range(1, 9):
            delta = reach * (step / 8)
            if attempt(light + sign * delta) is not None:
                hit = delta
                break
        if hit is None:
            continue
        lo_delta, hi_delta = 0.0, hit
        winner = hit
        for _step in range(8):
            mid = (lo_delta + hi_delta) / 2
            if attempt(light + sign * mid) is not None:
                winner = mid
                hi_delta = mid
            else:
                lo_delta = mid
        chosen = attempt(light + sign * winner) or attempt(light + sign * hit)
        if chosen is None:
            continue
        moved = abs(parse_color(chosen).oklch()[0] - original_light)
        if best is None or moved < best[0]:
            best = (moved, chosen)
    if best is None:
        return None
    return best[1]


def _assemble(supplied: dict[str, str], seed: dict[str, str]) -> dict[str, str] | None:
    required = {name: seed[name] for name in REQUIRED_COLORS}
    for key, value in supplied.items():
        if key in required:
            required[key] = value
    if "bgRaised" not in supplied:
        required["bgRaised"] = _raised_above(required["bg"], required["bgRaised"])
    _retint_status(required, supplied)
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


def _retint_status(required: dict[str, str], supplied: dict[str, str]) -> None:
    """Move unsupplied status colours onto the page and the raised surface.

    Lifting ``bgRaised`` can put the dark seed's danger, warning, or success
    under 4.5:1. Those colours are not in the file, so the 0.25 budget does
    not apply. ``info`` is derived afterwards against the same two surfaces.
    A supplied colour is left for that budget.
    """
    backgrounds = (parse_color(required["bg"]), parse_color(required["bgRaised"]))
    pairs = (
        ("ok", TEXT_AA),
        ("warn", TEXT_AA),
        ("danger", TEXT_AA),
        ("accent", UI_AA),
    )
    for name, minimum in pairs:
        if name in supplied:
            continue
        adjusted = adjust_lightness(
            parse_color(required[name]),
            backgrounds,
            minimum,
            max_delta=0.4,
        )
        if adjusted is None:
            continue
        required[name] = adjusted.to_hex()


def _raised_above(background: str, raised: str) -> str:
    """Lift a seeded raised surface when it is not already lighter than the page.

    Both Praxis palettes raise that surface. A mid-grey page is dark enough
    to seed from the dark palette, whose raised colour is then darker than
    the page. A supplied ``bgRaised`` is not passed here.
    """
    page_l = parse_color(background).oklch()[0]
    surface = parse_color(raised)
    if surface.oklch()[0] > page_l + 0.015:
        return raised
    step = 0.06 if page_l >= 0.5 else 0.04
    return surface.with_lightness(min(1.0, page_l + step)).to_hex()


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
