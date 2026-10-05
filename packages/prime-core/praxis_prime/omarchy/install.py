"""Install the Omarchy theme template and the Super+Alt+A keybind.

Omarchy reads ``$HOME/.config/omarchy/themed`` (``omarchy-theme-set-templates``)
and loads ``hypr.bindings`` from ``$HOME/.config`` (``default/hypr/bootstrap.lua``).
Omarchy 3.1.0 sources ``~/.config/hypr/bindings.conf`` from hyprland.conf.
``$XDG_CONFIG_HOME`` is not used for these files. A different config home
would put them where Omarchy does not look.

The key runs the TUI. A ``{ tui = "praxis-prime tui" }`` table would take
``basename`` of a multi-word command, so the bind is one command string with
``--app-id=org.omarchy.praxis-prime``.

Nothing here uses the network or root. ARCHITECTURE §27.2.
"""

from __future__ import annotations

import difflib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from praxis_prime.statfile import StatKind, lstat_kind
from praxis_prime.themes.omarchy import LIVE_ID, installed, theme_file

TEMPLATE_NAME = "praxis-prime.json.tpl"
APP_ID = "org.omarchy.praxis-prime"
LAUNCHER = "omarchy-launch-or-focus-tui"
THEME_SET_HINT = "praxis-prime theme set omarchy --profile NAME"
THEME_CLEAR_HINT = "praxis-prime theme set smf.praxis --profile …"
_PREFIX = "praxis-prime omarchy:"

LUA_BEGIN = "-- >>> praxis-prime keybind (managed by `praxis-prime omarchy`) >>>"
LUA_END = "-- <<< praxis-prime keybind <<<"
CONF_BEGIN = "# >>> praxis-prime keybind (managed by `praxis-prime omarchy`) >>>"
CONF_END = "# <<< praxis-prime keybind <<<"
_MANAGED_MARK = "praxis-prime keybind (managed by `praxis-prime omarchy`)"

_TARGET_CHORD = (frozenset({"SUPER", "ALT"}), "A")
_SAFE_SHELL = re.compile(r"^[A-Za-z0-9_./:@+=-]+$")
_LUA_BIND = re.compile(
    r"""(?m)^[ \t]*(?!--)(?:o\.(?:bind|rebind)|hl\.bind)\s*\(\s*(['"])(?P<keys>[^'"]+)\1"""
)
_CONF_BIND = re.compile(
    r"(?m)^[ \t]*(?!#)(?P<kind>unbind|bind[A-Za-z0-9]*)[ \t]*=[ \t]*"
    r"(?P<mods>[^,]+),[ \t]*(?P<key>\S+)"
)
_TEXTUAL_HINT = (
    f"{_PREFIX} Textual is not installed, so the full-screen TUI will not start.\n"
    f"{_PREFIX} Install it with: pip install 'praxis-prime[tui]'\n"
    f"{_PREFIX} For the /opt/praxis-prime package:\n"
    f"{_PREFIX}   /opt/praxis-prime/bin/python -m ensurepip --upgrade\n"
    f"{_PREFIX}   /opt/praxis-prime/bin/python -m pip install 'textual>=8.2,<9'"
)


class OmarchyInstallError(Exception):
    """A step was refused. Nothing in that step was written."""


@dataclass(frozen=True, slots=True)
class Host:
    detected: bool
    version: str
    layout: str  # ``lua``, ``conf``, or ``unknown``


def shipped_template() -> bytes:
    """Bytes of the template inside the wheel."""
    return files("praxis_prime.omarchy").joinpath(TEMPLATE_NAME).read_bytes()


def status_command() -> int:
    """Print the Omarchy setup. Always exits 0."""
    try:
        sys.stdout.write(format_status() + "\n")
    except OSError as exc:
        print(f"{_PREFIX} {exc}", file=sys.stderr)
    return 0


def format_status(env: Mapping[str, str] | None = None) -> str:
    environ = os.environ if env is None else env
    host = detect_host(environ)
    home = _home(environ)
    lines = [f"Omarchy: {_host_phrase(host)}"]
    if home is None:
        lines.append("Template: HOME is unset")
        lines.append("Keybind: HOME is unset")
    else:
        lines.append(_template_phrase(template_path(environ)))
        lines.append(_keybind_phrase(environ, host))
    lines.append(_rendered_phrase())
    lines.append(_profile_phrase())
    return "\n".join(lines)


def doctor_setup(env: Mapping[str, str]) -> tuple[str, str]:
    """``(status, detail)`` for an Omarchy host. Status is ``ok`` or ``warn``."""
    home = _home(env)
    if home is None:
        return "warn", "HOME is unset. Run `praxis-prime omarchy install`."
    host = detect_host(env)
    template = _template_state(template_path(env))
    key_text, key_ok = _doctor_key(env, host)
    if template == "match":
        template_text = "template matches the shipped copy"
    elif template == "differ":
        template_text = "template differs from the shipped copy"
    elif template == "symlink":
        template_text = "template path is a symlink"
    else:
        template_text = "template is not installed"
    ready = template == "match" and key_ok
    detail = f"{template_text}; {key_text}."
    if not ready:
        detail += " Run `praxis-prime omarchy install`."
    return ("ok" if ready else "warn"), detail


def install_omarchy(
    *,
    theme: bool,
    keybind: bool,
    yes: bool,
    dry_run: bool,
    profile: str,
    force: bool,
) -> int:
    do_theme, do_key = _scope(theme, keybind)
    try:
        return _install(
            do_theme=do_theme,
            do_key=do_key,
            yes=yes,
            dry_run=dry_run,
            profile=profile.strip(),
            force=force,
        )
    except OmarchyInstallError as exc:
        print(f"{_PREFIX} {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"{_PREFIX} {exc}", file=sys.stderr)
        return 1


def uninstall_omarchy(
    *,
    theme: bool,
    keybind: bool,
    yes: bool,
    dry_run: bool,
    force: bool,
) -> int:
    do_theme, do_key = _scope(theme, keybind)
    try:
        return _uninstall(
            do_theme=do_theme,
            do_key=do_key,
            yes=yes,
            dry_run=dry_run,
            force=force,
        )
    except OmarchyInstallError as exc:
        print(f"{_PREFIX} {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"{_PREFIX} {exc}", file=sys.stderr)
        return 1


def detect_host(env: Mapping[str, str] | None = None) -> Host:
    """Whether this home looks like Omarchy, and which keybind file it uses."""
    environ = os.environ if env is None else env
    version = _read_version(environ)
    layout = _layout_from_version(version)
    if layout == "unknown":
        layout = _layout_from_tree(environ)
    detected = bool(version) or layout != "unknown" or _home_config_present(environ)
    detected = detected or _outside_home_signals(environ)
    if not detected:
        layout = "unknown"
    return Host(detected=detected, version=version, layout=layout)


def template_path(env: Mapping[str, str] | None = None) -> Path:
    home = _require_home(os.environ if env is None else env)
    return home / ".config" / "omarchy" / "themed" / TEMPLATE_NAME


def bindings_path(env: Mapping[str, str], layout: str) -> Path:
    home = _require_home(env)
    name = "bindings.lua" if layout != "conf" else "bindings.conf"
    return home / ".config" / "hypr" / name


def praxis_prime_command() -> str:
    """The ``praxis-prime`` on PATH, or this process's absolute ``argv[0]``."""
    found = shutil.which("praxis-prime")
    if found:
        return os.path.abspath(found)
    raw = sys.argv[0]
    if not raw or raw.startswith("-"):
        raise OmarchyInstallError(
            "praxis-prime is not on PATH, and this process has no usable argv[0]"
        )
    return os.path.abspath(raw)


def launch_command() -> str:
    """Shell command the key runs. Refuses a path that cannot be quoted."""
    binary = praxis_prime_command()
    _reject_unsafe(binary)
    return f"{LAUNCHER} --app-id={APP_ID} {_shell_quote(binary)} tui"


def textual_installed() -> bool:
    try:
        import importlib

        importlib.import_module("textual")
    except ImportError:
        return False
    return True


def _install(
    *,
    do_theme: bool,
    do_key: bool,
    yes: bool,
    dry_run: bool,
    profile: str,
    force: bool,
) -> int:
    env = os.environ
    host = detect_host(env)
    print(f"{_PREFIX} {_host_phrase(host)}")
    command = ""
    layout = host.layout
    if do_key:
        if not textual_installed():
            print(_TEXTUAL_HINT)
        command = launch_command()
        layout = _layout_for_write(host, force=force)
        _refuse_symlink(bindings_path(env, layout), force=force)
        _refuse_incomplete(env, layout)
        _refuse_key_conflict(env, layout)
    if do_theme:
        _refuse_symlink(template_path(env), force=force)
        _refuse_different_template(template_path(env), force=force)

    theme_action = _theme_action(template_path(env)) if do_theme else "skip"
    key_action = _key_action(env, layout, command) if do_key else "skip"
    refresh = shutil.which("omarchy-theme-refresh") if do_theme else None
    hyprctl = shutil.which("hyprctl") if do_key else None
    profile_action = _profile_action(profile) if profile else "skip"

    _print_plan(
        do_theme=do_theme,
        do_key=do_key,
        theme_action=theme_action,
        key_action=key_action,
        layout=layout,
        command=command,
        refresh=refresh,
        hyprctl=hyprctl,
        profile=profile,
        profile_action=profile_action,
        dry_run=dry_run,
    )
    if dry_run:
        if do_theme:
            _print_diff(template_path(env), shipped_template().decode("utf-8"), theme_action)
        if do_key:
            _print_key_diff(env, layout, command, key_action)
        print(f"{_PREFIX} dry-run: wrote nothing")
        return 0

    needs_user = _needs_user(
        theme_action=theme_action,
        key_action=key_action,
        refresh=refresh,
        hyprctl=hyprctl if key_action != "noop" else None,
        profile_action=profile_action,
    )
    if needs_user and not yes and not _isatty():
        print(
            f"{_PREFIX} no terminal, so nothing was changed. "
            "Re-run with --yes to apply, or --dry-run to preview.",
            file=sys.stderr,
        )
        return 1

    failed = False
    wrote_template = theme_action == "noop" and do_theme
    if do_theme and theme_action != "noop":
        if _allow("Write the theme template?", yes=yes):
            _write_template(template_path(env), force=force)
            wrote_template = True
        else:
            print(f"{_PREFIX} skipped the theme template")
    elif do_theme:
        print(f"{_PREFIX} template already matches the shipped copy")

    if do_theme:
        offer = wrote_template or _template_matches()
        failed = _maybe_refresh(refresh, yes=yes, offer=offer) or failed

    if profile:
        if profile_action == "noop":
            print(f"{_PREFIX} profile {profile} already uses omarchy")
        elif _allow(f"Set profile {profile} to omarchy?", yes=yes):
            try:
                _select_profile(profile)
            except OmarchyInstallError as exc:
                print(f"{_PREFIX} {exc}", file=sys.stderr)
                failed = True
        else:
            print(f"{_PREFIX} skipped profile {profile}")
    elif do_theme:
        print(f"{_PREFIX} {THEME_SET_HINT}")

    wrote_key = False
    if do_key and key_action != "noop":
        if _allow("Write the Super+Alt+A keybind?", yes=yes):
            _write_keybind(env, layout, command, force=force)
            wrote_key = True
        else:
            print(f"{_PREFIX} skipped the keybind")
    elif do_key:
        print(f"{_PREFIX} keybind already matches")

    if do_key and wrote_key:
        failed = _maybe_reload(hyprctl, yes=yes) or failed
    elif do_key and key_action == "noop" and not hyprctl:
        pass
    return 1 if failed else 0


def _uninstall(
    *,
    do_theme: bool,
    do_key: bool,
    yes: bool,
    dry_run: bool,
    force: bool,
) -> int:
    env = os.environ
    host = detect_host(env)
    print(f"{_PREFIX} {_host_phrase(host)}")
    theme_remove = False
    theme_keep = False
    if do_theme:
        state = _template_state(template_path(env))
        if state == "symlink" and not force:
            raise OmarchyInstallError(
                f"{template_path(env)} is a symlink. Refusing to remove it without --force."
            )
        if state == "match":
            theme_remove = True
        elif state == "differ" and force:
            theme_remove = True
        elif state == "differ":
            theme_keep = True
            print(
                f"{_PREFIX} template differs from the shipped copy. "
                "Left it in place. Re-run with --force to remove it."
            )
        elif state == "absent":
            print(f"{_PREFIX} template is not installed")
        elif state == "symlink" and force:
            theme_remove = True

    key_hits: list[Path] = []
    key_unlinks: list[Path] = []
    if do_key:
        key_hits, key_unlinks = _plan_key_removal(env, force=force)
        if not key_hits and not key_unlinks:
            print(f"{_PREFIX} keybind block is not installed")

    if dry_run:
        if theme_remove:
            removing = template_path(env)
            kind = "symlink " if lstat_kind(removing) is StatKind.SYMLINK else ""
            print(f"{_PREFIX} dry-run: would remove {kind}{removing}")
        for path in key_unlinks:
            print(f"{_PREFIX} dry-run: would remove symlink {path}")
        for path in key_hits:
            print(f"{_PREFIX} dry-run: would remove the managed block from {path}")
        print(f"{_PREFIX} dry-run: wrote nothing")
        print(f"{_PREFIX} {THEME_CLEAR_HINT}")
        return 0

    needs = theme_remove or bool(key_hits) or bool(key_unlinks)
    if needs and not yes and not _isatty():
        print(
            f"{_PREFIX} no terminal, so nothing was changed. "
            "Re-run with --yes to apply, or --dry-run to preview.",
            file=sys.stderr,
        )
        return 1

    if theme_remove and _allow("Remove the theme template?", yes=yes):
        _remove_template(template_path(env), force=force)
    elif theme_remove:
        print(f"{_PREFIX} skipped the theme template")

    for path in key_unlinks:
        if _allow(f"Remove the symlink {path.name}? The file it points at stays.", yes=yes):
            path.unlink()
            print(f"{_PREFIX} removed symlink {path}")
        else:
            print(f"{_PREFIX} skipped {path}")
    for path in key_hits:
        if _allow(f"Remove the managed keybind block from {path.name}?", yes=yes):
            _strip_keybind(path, force=force)
        else:
            print(f"{_PREFIX} skipped {path}")

    if do_theme or do_key:
        print(f"{_PREFIX} profile selections were left unchanged")
        print(f"{_PREFIX} {THEME_CLEAR_HINT}")
    if theme_keep:
        return 0
    return 0


def _print_plan(
    *,
    do_theme: bool,
    do_key: bool,
    theme_action: str,
    key_action: str,
    layout: str,
    command: str,
    refresh: str | None,
    hyprctl: str | None,
    profile: str,
    profile_action: str,
    dry_run: bool,
) -> None:
    label = "dry-run: " if dry_run else ""
    if do_theme:
        path = template_path()
        if theme_action == "noop":
            print(f"{_PREFIX} {label}template already matches {path}")
        elif theme_action == "create":
            print(f"{_PREFIX} {label}would write {path}" if dry_run else f"{_PREFIX} write {path}")
        else:
            verb = "would replace" if dry_run else "replace"
            print(f"{_PREFIX} {label}{verb} {path}")
        if refresh:
            if dry_run:
                print(f"{_PREFIX} {label}would run {refresh}")
            else:
                print(f"{_PREFIX} omarchy-theme-refresh is on PATH")
        else:
            print(
                f"{_PREFIX} omarchy-theme-refresh is not on PATH. "
                "Switch themes once so Omarchy renders the template."
            )
    if profile:
        if profile_action == "noop":
            print(f"{_PREFIX} {label}profile {profile} already uses omarchy")
        else:
            print(f"{_PREFIX} {label}would select omarchy for profile {profile}")
    elif do_theme and dry_run:
        print(f"{_PREFIX} {THEME_SET_HINT}")
    if do_key:
        path = bindings_path(os.environ, layout)
        print(f"{_PREFIX} {label}keybind file {path} ({key_action})")
        if command:
            print(f"{_PREFIX} {label}command: {command}")
        if hyprctl and key_action != "noop":
            verb = "would run" if dry_run else "can run"
            print(f"{_PREFIX} {label}{verb} hyprctl reload")
        elif key_action != "noop":
            print(f"{_PREFIX} the keybind applies the next time Hyprland reloads")


def _needs_user(
    *,
    theme_action: str,
    key_action: str,
    refresh: str | None,
    hyprctl: str | None,
    profile_action: str,
) -> bool:
    if theme_action not in {"skip", "noop"}:
        return True
    if key_action not in {"skip", "noop"}:
        return True
    if refresh and theme_action != "skip":
        return True
    if hyprctl and key_action not in {"skip", "noop"}:
        return True
    return profile_action not in {"skip", "noop"}


def _allow(prompt: str, *, yes: bool) -> bool:
    if yes:
        return True
    print(f"{_PREFIX} {prompt}")
    try:
        answer = input("[y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in {"y", "yes"}


def _isatty() -> bool:
    check = getattr(sys.stdin, "isatty", None)
    return bool(check and check())


def _maybe_refresh(refresh: str | None, *, yes: bool, offer: bool) -> bool:
    """Run ``omarchy-theme-refresh`` when it is installed and the user agrees.

    Returns True when the command ran and failed.
    """
    if not refresh or not offer:
        return False
    if not _allow("Run omarchy-theme-refresh so the current theme renders now?", yes=yes):
        print(
            f"{_PREFIX} skipped omarchy-theme-refresh. "
            "Switch themes once to render the template."
        )
        return False
    print(f"{_PREFIX} running {refresh}")
    completed = subprocess.run([refresh], check=False)
    if completed.returncode != 0:
        print(
            f"{_PREFIX} omarchy-theme-refresh exited {completed.returncode}",
            file=sys.stderr,
        )
        return True
    print(f"{_PREFIX} omarchy-theme-refresh finished")
    return False


def _maybe_reload(hyprctl: str | None, *, yes: bool) -> bool:
    if not hyprctl:
        print(f"{_PREFIX} the keybind applies the next time Hyprland reloads")
        return False
    if not _allow("Reload Hyprland with hyprctl reload?", yes=yes):
        print(
            f"{_PREFIX} skipped hyprctl reload. "
            "The keybind applies the next time Hyprland reloads."
        )
        return False
    print(f"{_PREFIX} running {hyprctl} reload")
    completed = subprocess.run([hyprctl, "reload"], check=False)
    if completed.returncode != 0:
        print(f"{_PREFIX} hyprctl reload exited {completed.returncode}", file=sys.stderr)
        return True
    print(f"{_PREFIX} hyprctl reload finished")
    return False


def _write_template(path: Path, *, force: bool) -> None:
    destination = _destination(path, force=force)
    current = _read_regular(destination)
    payload = shipped_template()
    if current == payload:
        print(f"{_PREFIX} template already matches the shipped copy")
        return
    if current is not None and current != payload:
        backup = _backup(destination)
        print(f"{_PREFIX} backed up {backup}")
    _atomic_write(destination, payload)
    print(f"{_PREFIX} wrote {destination}")


def _remove_template(path: Path, *, force: bool) -> None:
    # A symlinked template is the link itself. --force drops that link and
    # leaves the file it names. A symlinked parent is followed only with --force.
    if lstat_kind(path) is StatKind.SYMLINK:
        if not force:
            raise OmarchyInstallError(
                f"{path} is a symlink ({_link_target(path)}). "
                "Refusing to remove it without --force."
            )
        path.unlink()
        print(f"{_PREFIX} removed symlink {path}")
        return
    destination = _destination(path, force=force)
    current = _read_regular(destination)
    if current is None:
        print(f"{_PREFIX} template is not installed")
        return
    if current != shipped_template():
        backup = _backup(destination)
        print(f"{_PREFIX} backed up {backup}")
    destination.unlink()
    print(f"{_PREFIX} removed {destination}")


def _write_keybind(env: Mapping[str, str], layout: str, command: str, *, force: bool) -> None:
    path = bindings_path(env, layout)
    destination = _destination(path, force=force)
    block = _block(layout, command)
    begin, end = _markers(layout)
    current = _read_text(destination)
    updated, action = _splice(current, block, begin, end)
    if action == "noop":
        print(f"{_PREFIX} keybind already matches")
        return
    if current:
        backup = _backup(destination)
        print(f"{_PREFIX} backed up {backup}")
    _atomic_write(destination, updated.encode("utf-8"))
    print(f"{_PREFIX} wrote {destination}")


def _strip_keybind(path: Path, *, force: bool) -> None:
    destination = _destination(path, force=force)
    layout = "conf" if destination.name.endswith(".conf") else "lua"
    begin, end = _markers(layout)
    current = _read_text(destination)
    updated, removed = _drop_blocks(current, begin, end)
    if not removed:
        print(f"{_PREFIX} keybind block is not in {destination}")
        return
    backup = _backup(destination)
    print(f"{_PREFIX} backed up {backup}")
    _atomic_write(destination, updated.encode("utf-8"))
    print(f"{_PREFIX} removed the managed block from {destination}")


def _select_profile(profile: str) -> None:
    from praxis_prime.paths import data_dir
    from praxis_prime.themes.cli import _audit_choice
    from praxis_prime.themes.errors import ThemeError
    from praxis_prime.themes.select import set_profile_theme

    data = data_dir()
    try:
        choice = set_profile_theme(data, profile, "omarchy", "system")
    except ThemeError as exc:
        raise OmarchyInstallError(str(exc)) from exc
    _audit_choice(
        data,
        choice.theme_id,
        choice.mode,
        choice.installed.package_hash,
        profile=profile,
    )
    print(f"set {profile} theme {choice.theme_id} mode {choice.mode}")


def _profile_action(profile: str) -> str:
    if not profile:
        return "skip"
    from praxis_prime.paths import data_dir
    from praxis_prime.themes.select import _profile_choice

    choice_id, choice_mode = _profile_choice(data_dir(), profile)
    if choice_id == "omarchy" and (choice_mode or "system") == "system":
        return "noop"
    return "set"


def _theme_action(path: Path) -> str:
    destination = path
    kind = lstat_kind(path)
    if kind is StatKind.SYMLINK:
        destination = path.resolve()
    current = _read_regular(destination) if lstat_kind(destination) is StatKind.FILE else None
    if current is None and kind is StatKind.MISSING:
        return "create"
    if current == shipped_template():
        return "noop"
    return "replace"


def _template_matches() -> bool:
    try:
        path = template_path()
    except OmarchyInstallError:
        return False
    return _template_state(path) == "match"


def _key_action(env: Mapping[str, str], layout: str, command: str) -> str:
    path = _followed_bindings(bindings_path(env, layout))
    if lstat_kind(path) is StatKind.MISSING:
        return "create"
    current = _read_text(path) if lstat_kind(path) is StatKind.FILE else ""
    block = _block(layout, command)
    begin, end = _markers(layout)
    _updated, action = _splice(current, block, begin, end)
    return action


def _layout_for_write(host: Host, *, force: bool) -> str:
    if host.layout in {"lua", "conf"}:
        return host.layout
    if force:
        print(f"{_PREFIX} Omarchy layout is unknown. --force writes bindings.lua.")
        return "lua"
    if not host.detected:
        raise OmarchyInstallError(
            "Omarchy was not detected, so bindings.lua was not created. "
            "Re-run with --force to write it anyway."
        )
    raise OmarchyInstallError(
        "Omarchy was detected but the version is unknown, so the keybind file "
        "was not chosen. Re-run with --force to write bindings.lua."
    )


def _refuse_different_template(path: Path, *, force: bool) -> None:
    state = _template_state(path)
    if state == "differ" and not force:
        raise OmarchyInstallError(
            f"{path} differs from the shipped template. "
            "Left it in place. Re-run with --force to replace it. "
            "A copy is saved as a .bak file when --force is set."
        )


def _refuse_incomplete(env: Mapping[str, str], layout: str) -> None:
    path = _followed_bindings(bindings_path(env, layout))
    if lstat_kind(path) is not StatKind.FILE:
        return
    text = _read_text(path)
    begin, end = _markers(layout)
    if begin not in text and end not in text:
        return
    if _block_pattern(begin, end).search(text):
        return
    raise OmarchyInstallError(
        "the managed keybind block is incomplete. Edit the bindings file before re-running."
    )


def _refuse_key_conflict(env: Mapping[str, str], layout: str) -> None:
    path = _followed_bindings(bindings_path(env, layout))
    if lstat_kind(path) is not StatKind.FILE:
        return
    conflict = find_conflict(_read_text(path), layout)
    if conflict:
        raise OmarchyInstallError(
            f"SUPER + ALT + A is already bound outside the managed block in {path}: "
            f"{conflict}. The keybind was not changed."
        )


def _refuse_symlink(path: Path, *, force: bool) -> None:
    if force:
        return
    link = _first_symlink(path)
    if link is not None:
        raise OmarchyInstallError(
            f"{link} is a symlink ({_link_target(link)}). "
            "Refusing to follow it. Re-run with --force to write through the link."
        )


def find_conflict(text: str, layout: str) -> str | None:
    """A line outside the managed block that already binds Super+Alt+A."""
    begin, end = _markers(layout)
    cleaned = _without_blocks(text, begin, end)
    if layout == "conf":
        for match in _CONF_BIND.finditer(cleaned):
            if match.group("kind").startswith("unbind"):
                continue
            if _conf_chord(match.group("mods"), match.group("key")) == _TARGET_CHORD:
                return match.group(0).strip()
        return None
    for match in _LUA_BIND.finditer(cleaned):
        if _lua_chord(match.group("keys")) == _TARGET_CHORD:
            return match.group(0).strip()
    return None


def _block(layout: str, command: str) -> str:
    if layout == "conf":
        return f"{CONF_BEGIN}\nbindd = SUPER ALT, A, Praxis Prime, exec, {command}\n{CONF_END}\n"
    return (
        f"{LUA_BEGIN}\n"
        f'o.bind("SUPER + ALT + A", "Praxis Prime", "{command}")\n'
        f"{LUA_END}\n"
    )


def _markers(layout: str) -> tuple[str, str]:
    if layout == "conf":
        return CONF_BEGIN, CONF_END
    return LUA_BEGIN, LUA_END


def _splice(text: str, block: str, begin: str, end: str) -> tuple[str, str]:
    pattern = _block_pattern(begin, end)
    if begin in text or end in text:
        if not pattern.search(text):
            raise OmarchyInstallError(
                "the managed keybind block is incomplete. Edit the bindings file before re-running."
            )
    found = list(pattern.finditer(text))
    if not found:
        return _append_block(text, block), "append"
    if len(found) == 1 and found[0].group(0) == block:
        return text, "noop"
    updated = text[: found[0].start()] + block + text[found[0].end() :]
    again = list(pattern.finditer(updated))
    if len(again) <= 1:
        return updated, "replace"
    pieces = [updated[: again[0].end()]]
    cursor = again[0].end()
    for match in again[1:]:
        pieces.append(updated[cursor : match.start()])
        cursor = match.end()
    pieces.append(updated[cursor:])
    return "".join(pieces), "replace"


def _drop_blocks(text: str, begin: str, end: str) -> tuple[str, bool]:
    pattern = _block_pattern(begin, end)
    if (begin in text or end in text) and not pattern.search(text):
        raise OmarchyInstallError(
            "the managed keybind block is incomplete. Edit the bindings file before re-running."
        )
    if not pattern.search(text):
        return text, False
    return pattern.sub("", text), True


def _append_block(text: str, block: str) -> str:
    if not text:
        return block
    if not text.endswith("\n"):
        text += "\n"
    if not text.endswith("\n\n"):
        text += "\n"
    return text + block


def _block_pattern(begin: str, end: str) -> re.Pattern[str]:
    return re.compile(re.escape(begin) + r".*?" + re.escape(end) + r"\n?", re.DOTALL)


def _without_blocks(text: str, begin: str, end: str) -> str:
    return _block_pattern(begin, end).sub("", text)


def _lua_chord(keys: str) -> tuple[frozenset[str], str] | None:
    parts = [part.strip().upper() for part in keys.split("+") if part.strip()]
    if len(parts) < 2:
        return None
    key = parts[-1].split()[0].rstrip(",")
    return frozenset(parts[:-1]), key


def _conf_chord(mods: str, key: str) -> tuple[frozenset[str], str]:
    modifiers = frozenset(part.upper() for part in mods.split() if part.strip())
    token = key.strip().upper().rstrip(",").split()[0]
    return modifiers, token


def _reject_unsafe(token: str) -> None:
    if not token:
        raise OmarchyInstallError("the praxis-prime path is empty")
    for char in token:
        if char in "\"'\\#," or ord(char) < 32 or ord(char) == 127:
            raise OmarchyInstallError(
                "the praxis-prime path cannot be quoted safely "
                f"for the Hyprland config: {token!r}"
            )


def _shell_quote(token: str) -> str:
    if _SAFE_SHELL.fullmatch(token):
        return token
    return "'" + token + "'"


def _template_state(path: Path) -> str:
    kind = lstat_kind(path)
    if kind is StatKind.MISSING:
        return "absent"
    if kind is StatKind.SYMLINK:
        return "symlink"
    if kind is not StatKind.FILE:
        return "other"
    current = _read_regular(path)
    if current is None:
        return "absent"
    if current == shipped_template():
        return "match"
    return "differ"


def _template_phrase(path: Path) -> str:
    state = _template_state(path)
    if state == "match":
        return f"Template: installed, matches the shipped copy ({path})"
    if state == "differ":
        return f"Template: installed, differs from the shipped copy ({path})"
    if state == "symlink":
        return f"Template: symlink, left unread ({path})"
    if state == "other":
        return f"Template: not a regular file ({path})"
    return f"Template: not installed ({path})"


def _keybind_phrase(env: Mapping[str, str], host: Host) -> str:
    paths = _status_key_paths(env, host)
    for path in paths:
        state = _key_state(path)
        if state:
            return f"Keybind: {state} ({path})"
    path = paths[0] if paths else bindings_path(env, "lua")
    return f"Keybind: not installed ({path})"


def _key_state(path: Path) -> str:
    kind = lstat_kind(path)
    if kind is not StatKind.FILE:
        return ""
    text = _read_text(path)
    if _MANAGED_MARK not in text:
        return ""
    layout = "conf" if path.name.endswith(".conf") else "lua"
    try:
        command = launch_command()
    except OmarchyInstallError:
        return "installed"
    block = _block(layout, command)
    begin, end = _markers(layout)
    if _block_pattern(begin, end).search(text) and block in text:
        return "installed"
    return "installed, block differs"


def _doctor_key(env: Mapping[str, str], host: Host) -> tuple[str, bool]:
    for path in _status_key_paths(env, host):
        if lstat_kind(path) is StatKind.SYMLINK:
            return "keybind path is a symlink", False
        state = _key_state(path)
        if state == "installed":
            return "keybind is installed", True
        if state:
            return "keybind block differs", False
    return "keybind is not installed", False


def _file_has_mark(path: Path) -> bool:
    if lstat_kind(path) is not StatKind.FILE:
        return False
    return _MANAGED_MARK in _read_text(path)


def _status_key_paths(env: Mapping[str, str], host: Host) -> list[Path]:
    if host.layout == "conf":
        return [bindings_path(env, "conf")]
    if host.layout == "lua":
        return [bindings_path(env, "lua")]
    return [bindings_path(env, "lua"), bindings_path(env, "conf")]


def _uninstall_key_paths(env: Mapping[str, str], host: Host) -> list[Path]:
    # Remove our block from both files when it is present. A 3.x file can
    # still be on disk after an upgrade to Omarchy 4.
    del host
    return [bindings_path(env, "lua"), bindings_path(env, "conf")]


def _plan_key_removal(env: Mapping[str, str], *, force: bool) -> tuple[list[Path], list[Path]]:
    """Regular files to edit, and symlinks to unlink.

    A leaf symlink is not followed into its target. ``--force`` removes the
    link when the target contains the managed block. A symlinked parent is
    refused unless ``--force``, and then the block is edited in place.
    """
    edits: list[Path] = []
    unlinks: list[Path] = []
    for path in _uninstall_key_paths(env, detect_host(env)):
        if lstat_kind(path) is StatKind.SYMLINK:
            if not _symlink_contains_mark(path):
                continue
            if not force:
                raise OmarchyInstallError(
                    f"{path} is a symlink ({_link_target(path)}). "
                    "Refusing to remove it without --force. "
                    "--force removes the symlink and leaves the file it points at."
                )
            unlinks.append(path)
            continue
        if not _file_has_mark(path):
            continue
        _refuse_symlink(path, force=force)
        edits.append(path)
    return edits, unlinks


def _symlink_contains_mark(path: Path) -> bool:
    """Whether the file a leaf symlink names contains the managed block.

    This reads the target and does not write it.
    """
    try:
        target = path.resolve()
    except (OSError, RuntimeError):
        return False
    if lstat_kind(target) is not StatKind.FILE:
        return False
    try:
        return _MANAGED_MARK in _read_text(target)
    except OmarchyInstallError:
        return False


def _rendered_phrase() -> str:
    path = theme_file()
    try:
        compiled = installed(path)
    except OSError:
        return f"Rendered: unreadable ({path})"
    if compiled is not None and compiled.package.theme_id == LIVE_ID:
        return f"Rendered: present, compiles to {LIVE_ID} ({path})"
    if lstat_kind(path) is StatKind.MISSING:
        return f"Rendered: absent ({path})"
    return f"Rendered: present, does not compile ({path})"


def _profile_phrase() -> str:
    from praxis_prime.paths import data_dir
    from praxis_prime.profiles.home import list_profiles
    from praxis_prime.themes.select import _profile_choice

    try:
        names = [
            name
            for name in list_profiles(data_dir())
            if _profile_choice(data_dir(), name)[0] == "omarchy"
        ]
    except OSError:
        return "Profiles: unreadable"
    if not names:
        return "Profiles: none chose omarchy"
    return "Profiles: " + ", ".join(names)


def _host_phrase(host: Host) -> str:
    if not host.detected:
        return "not detected"
    if host.layout == "lua":
        kind = "4.x Lua"
    elif host.layout == "conf":
        kind = "3.x conf"
    else:
        kind = "unknown"
    if host.version:
        return f"detected, {host.version} ({kind})"
    return f"detected, {kind}"


def _read_version(env: Mapping[str, str]) -> str:
    for path in _version_candidates(env):
        text = _read_version_file(path)
        if text:
            return text
    return ""


def _version_candidates(env: Mapping[str, str]) -> list[Path]:
    paths: list[Path] = []
    root = _omarchy_path(env)
    if root is not None:
        paths.append(root / "version")
    home = _home(env)
    if home is not None:
        paths.append(home / ".local" / "share" / "omarchy" / "version")
    if root is None:
        paths.append(_packaged_version_path())
    return paths


def _packaged_version_path() -> Path:
    """Omarchy 4's default ``OMARCHY_PATH`` when the variable is unset."""
    return Path("/usr/share/omarchy/version")


def _read_version_file(path: Path) -> str:
    if lstat_kind(path) is not StatKind.FILE:
        return ""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ""
    return text.strip().splitlines()[0].strip() if text.strip() else ""


def _layout_from_version(version: str) -> str:
    text = version.strip().lstrip("vV")
    major = text.split(".", 1)[0]
    if major == "4":
        return "lua"
    if major == "3":
        return "conf"
    return "unknown"


def _layout_from_tree(env: Mapping[str, str]) -> str:
    root = _omarchy_path(env)
    homes = []
    if root is not None:
        homes.append(root / "default" / "hypr")
    home = _home(env)
    if home is not None:
        homes.append(home / ".local" / "share" / "omarchy" / "default" / "hypr")
    if root is None:
        homes.append(Path("/usr/share/omarchy/default/hypr"))
    saw_conf = False
    for directory in homes:
        if _dir_has_suffix(directory, ".lua"):
            return "lua"
        if _dir_has_suffix(directory, ".conf"):
            saw_conf = True
    if saw_conf:
        return "conf"
    return "unknown"


def _dir_has_suffix(directory: Path, suffix: str) -> bool:
    if lstat_kind(directory) is not StatKind.DIR:
        return False
    try:
        children = list(directory.iterdir())
    except OSError:
        return False
    return any(child.is_file() and child.suffix == suffix for child in children)


def _home_config_present(env: Mapping[str, str]) -> bool:
    home = _home(env)
    if home is None:
        return False
    kind = lstat_kind(home / ".config" / "omarchy")
    return kind in {StatKind.DIR, StatKind.SYMLINK}


def _outside_home_signals(env: Mapping[str, str]) -> bool:
    """Host-wide Omarchy markers that do not live under ``$HOME``.

    Tests patch this so a developer machine that has Omarchy installed does
    not make an empty temp home look detected.
    """
    del env
    if shutil.which("omarchy"):
        return True
    if lstat_kind(Path("/usr/bin/omarchy")) is not StatKind.MISSING:
        return True
    if _os_release_says_omarchy():
        return True
    return False


def _os_release_says_omarchy() -> bool:
    from praxis_prime.doctor import _is_omarchy, parse_os_release

    text = ""
    release = Path("/etc/os-release")
    if lstat_kind(release) is StatKind.FILE:
        try:
            text = release.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            text = ""
    return _is_omarchy(parse_os_release(text), {}, lambda _name: None, lambda _path: False)


def _omarchy_path(env: Mapping[str, str]) -> Path | None:
    raw = env.get("OMARCHY_PATH", "").strip()
    if not raw:
        return None
    return Path(raw)


def _home(env: Mapping[str, str]) -> Path | None:
    raw = env.get("HOME", "").strip()
    if not raw:
        return None
    return Path(raw)


def _require_home(env: Mapping[str, str]) -> Path:
    home = _home(env)
    if home is None:
        raise OmarchyInstallError("HOME is unset")
    return home


def _scope(theme: bool, keybind: bool) -> tuple[bool, bool]:
    if not theme and not keybind:
        return True, True
    return theme, keybind


def _destination(path: Path, *, force: bool) -> Path:
    link = _first_symlink(path)
    if link is None:
        return path
    if not force:
        raise OmarchyInstallError(
            f"{link} is a symlink ({_link_target(link)}). "
            "Refusing to follow it. Re-run with --force to write through the link."
        )
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError) as exc:
        raise OmarchyInstallError(f"cannot resolve symlink {link}: {exc}") from exc
    print(f"{_PREFIX} following symlink {link} -> {_link_target(link)}; writing {resolved}")
    return resolved


def _first_symlink(path: Path) -> Path | None:
    home = _home(os.environ)
    current = path
    while True:
        if home is not None and current == home:
            return None
        if current == current.parent:
            return None
        kind = lstat_kind(current)
        if kind is StatKind.SYMLINK:
            return current
        if kind is StatKind.UNREADABLE:
            raise OmarchyInstallError(f"{current} is not readable")
        current = current.parent


def _link_target(path: Path) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return "unreadable"


def _read_regular(path: Path) -> bytes | None:
    if lstat_kind(path) is not StatKind.FILE:
        return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise OmarchyInstallError(f"cannot read {path}: {exc.strerror}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise OmarchyInstallError(f"{path} is not a regular file")
        return os.read(descriptor, info.st_size)
    finally:
        os.close(descriptor)


def _read_text(path: Path) -> str:
    if lstat_kind(path) is StatKind.MISSING:
        return ""
    data = _read_regular(path)
    if data is None:
        raise OmarchyInstallError(f"{path} is not a regular file")
    try:
        return data.decode("utf-8")
    except UnicodeError as exc:
        raise OmarchyInstallError(f"{path} is not UTF-8") from exc


def _backup(path: Path) -> Path:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    candidate = path.with_name(f"{path.name}.bak-{stamp}")
    suffix = 0
    while lstat_kind(candidate) is not StatKind.MISSING:
        suffix += 1
        candidate = path.with_name(f"{path.name}.bak-{stamp}-{suffix}")
    data = _read_regular(path)
    if data is None:
        raise OmarchyInstallError(f"cannot back up {path}")
    _atomic_write(candidate, data)
    return candidate


def _atomic_write(path: Path, data: bytes) -> None:
    _ensure_dir(path.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    os.chmod(path, 0o644)


def _ensure_dir(path: Path) -> None:
    missing: list[Path] = []
    current = path
    while lstat_kind(current) is StatKind.MISSING:
        missing.append(current)
        if current == current.parent:
            break
        current = current.parent
    path.mkdir(parents=True, exist_ok=True)
    for directory in missing:
        if lstat_kind(directory) is StatKind.DIR:
            os.chmod(directory, 0o755)


def _print_diff(path: Path, new: str, action: str) -> None:
    if action == "noop":
        print(f"{_PREFIX} dry-run: {path} unchanged")
        return
    old = ""
    if lstat_kind(path) is StatKind.FILE:
        old = _read_text(path)
    _emit_diff(path, old, new)


def _followed_bindings(path: Path) -> Path:
    """The file a leaf symlink names. A missing path stays as given."""
    if lstat_kind(path) is StatKind.SYMLINK:
        try:
            return path.resolve()
        except (OSError, RuntimeError):
            return path
    return path


def _print_key_diff(env: Mapping[str, str], layout: str, command: str, action: str) -> None:
    logical = bindings_path(env, layout)
    path = _followed_bindings(logical)
    if action == "noop":
        print(f"{_PREFIX} dry-run: {logical} unchanged")
        return
    old = _read_text(path) if lstat_kind(path) is StatKind.FILE else ""
    block = _block(layout, command)
    begin, end = _markers(layout)
    new, _action = _splice(old, block, begin, end)
    _emit_diff(path, old, new)


def _emit_diff(path: Path, old: str, new: str) -> None:
    diff = difflib.unified_diff(
        old.splitlines(keepends=True),
        new.splitlines(keepends=True),
        fromfile=f"{path} (current)",
        tofile=f"{path} (planned)",
    )
    text = "".join(diff)
    if not text:
        print(f"{_PREFIX} dry-run: {path} unchanged")
        return
    sys.stdout.write(text if text.endswith("\n") else text + "\n")
