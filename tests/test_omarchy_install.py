"""``praxis-prime omarchy`` installs a theme template and a Super+Alt+A keybind.

Every path is under the temp HOME from ``conftest``. Omarchy's own files are
``$HOME/.config``, not ``$XDG_CONFIG_HOME``. Stubs stand in for
``omarchy-theme-refresh`` and ``hyprctl``. Nothing here calls the real tools.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
from pathlib import Path

import pytest

from praxis_prime.cli import build_parser, main
from praxis_prime.doctor import collect_checks
from praxis_prime.omarchy import install as omarchy_install
from praxis_prime.omarchy.install import (
    TEMPLATE_NAME,
    THEME_CLEAR_HINT,
    THEME_SET_HINT,
    find_conflict,
    format_status,
    shipped_template,
)
from praxis_prime.paths import data_dir
from praxis_prime.profiles.home import create_profile
from praxis_prime.themes.omarchy import _COLOR_KEYS, LIVE_ID, installed, theme_file
from praxis_prime.themes.select import _profile_choice, lock_state, set_lock, set_profile_theme

_REAL_COMMAND = omarchy_install.praxis_prime_command
_REPO = Path(__file__).resolve().parents[1]

_TOKYO = {
    "mode": "dark",
    "background": "#1a1b26",
    "lighter_background": "#24283b",
    "foreground": "#a9b1d6",
    "dark_foreground": "#565f89",
    "accent": "#7aa2f7",
    "muted": "#414868",
    "green": "#9ece6a",
    "yellow": "#e0af68",
    "red": "#f7768e",
    "cyan": "#449dab",
    "selection": "#292e42",
}
_LATTE = {
    "mode": "light",
    "background": "#eff1f5",
    "lighter_background": "#dce0e8",
    "foreground": "#4c4f69",
    "dark_foreground": "#9ca0b0",
    "accent": "#1e66f5",
    "muted": "#acb0be",
    "green": "#40a02b",
    "yellow": "#df8e1d",
    "red": "#d20f39",
    "cyan": "#179299",
    "selection": "#ccd0da",
}
_OMARCHY_RELEASE = 'ID=omarchy\nID_LIKE=arch\nPRETTY_NAME="Omarchy"\n'
_UBUNTU_RELEASE = 'ID=ubuntu\nPRETTY_NAME="Ubuntu 24.04"\n'


@pytest.fixture(autouse=True)
def _isolate_omarchy_tools(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """A private PATH, and no host-wide Omarchy signal."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.delenv("OMARCHY_PATH", raising=False)
    monkeypatch.setattr(omarchy_install, "praxis_prime_command", lambda: "/usr/bin/praxis-prime")
    monkeypatch.setattr(omarchy_install, "_outside_home_signals", lambda _env: False)
    return bin_dir


def _home() -> Path:
    return Path(os.environ["HOME"])


def _template() -> Path:
    return _home() / ".config" / "omarchy" / "themed" / TEMPLATE_NAME


def _bindings(name: str = "bindings.lua") -> Path:
    return _home() / ".config" / "hypr" / name


def _version(text: str) -> None:
    path = _home() / ".local" / "share" / "omarchy" / "version"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")


def _baks(path: Path) -> list[Path]:
    return sorted(path.parent.glob(path.name + ".bak-*"))


def _install(**kwargs: object) -> int:
    values = {
        "theme": False,
        "keybind": False,
        "yes": False,
        "dry_run": False,
        "profile": "",
        "force": False,
    }
    values.update(kwargs)
    return omarchy_install.install_omarchy(**values)  # type: ignore[arg-type]


def _uninstall(**kwargs: object) -> int:
    values = {
        "theme": False,
        "keybind": False,
        "yes": False,
        "dry_run": False,
        "force": False,
    }
    values.update(kwargs)
    return omarchy_install.uninstall_omarchy(**values)  # type: ignore[arg-type]


def _stub(bin_dir: Path, name: str, body: str) -> Path:
    path = bin_dir / name
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


def _render(values: dict[str, str]) -> str:
    text = shipped_template().decode("utf-8")
    for key, value in values.items():
        text = text.replace("{{ " + key + " }}", value)
    assert "{{" not in text
    return text


def _tty(monkeypatch: pytest.MonkeyPatch, answer: str) -> None:
    monkeypatch.setattr(omarchy_install, "_isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt="": answer)


def test_shipped_template_matches_the_apps_copy_and_compiles() -> None:
    packaged = shipped_template()
    apps = (_REPO / "apps" / "omarchy" / "praxis-prime.json.tpl").read_bytes()
    assert packaged == apps
    assert set(json.loads(_render(_TOKYO))) == set(_COLOR_KEYS) | {"mode"}
    for values in (_TOKYO, _LATTE):
        rendered = json.loads(_render(values))
        path = theme_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(rendered) + "\n", encoding="utf-8")
        compiled = installed(path)
        assert compiled is not None
        assert compiled.package.theme_id == LIVE_ID


def test_theme_install_is_atomic_idempotent_and_refuses_a_different_file(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert _install(theme=True, dry_run=True) == 0
    assert not _template().exists()
    preview = capsys.readouterr().out
    assert "dry-run: wrote nothing" in preview
    assert THEME_SET_HINT in preview

    monkeypatch.setattr(omarchy_install, "_isatty", lambda: False)
    assert _install(theme=True) == 1
    assert not _template().exists()
    assert "--yes" in capsys.readouterr().err

    assert _install(theme=True, yes=True) == 0
    path = _template()
    assert path.read_bytes() == shipped_template()
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o755
    assert not _baks(path)
    xdg = Path(os.environ["XDG_CONFIG_HOME"])
    assert not (xdg / "omarchy").exists()
    first = path.stat().st_mtime_ns
    assert _install(theme=True, yes=True) == 0
    assert path.stat().st_mtime_ns == first
    assert "already matches" in capsys.readouterr().out

    path.write_text("{}\n", encoding="utf-8")
    assert _install(theme=True, yes=True) == 1
    assert path.read_text(encoding="utf-8") == "{}\n"
    assert "differs" in capsys.readouterr().err
    assert _install(theme=True, yes=True, dry_run=True) == 1
    assert path.read_text(encoding="utf-8") == "{}\n"

    original = path.read_bytes()
    assert _install(theme=True, yes=True, force=True) == 0
    assert path.read_bytes() == shipped_template()
    backups = _baks(path)
    assert len(backups) == 1
    assert backups[0].read_bytes() == original
    assert ".bak-" in backups[0].name


def test_failed_replace_keeps_the_previous_template(monkeypatch: pytest.MonkeyPatch) -> None:
    path = _template()
    path.parent.mkdir(parents=True)
    path.write_bytes(b'{"kept": true}\n')

    def _fail_replace(src: str, dst: str) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr(omarchy_install.os, "replace", _fail_replace)
    assert _install(theme=True, yes=True, force=True) == 1
    assert path.read_bytes() == b'{"kept": true}\n'
    assert list(path.parent.glob(".praxis-prime.json.tpl.*")) == []


def test_existing_config_mode_is_left_alone() -> None:
    config = _home() / ".config"
    config.mkdir()
    os.chmod(config, 0o700)
    assert _install(theme=True, yes=True) == 0
    assert stat.S_IMODE(config.stat().st_mode) == 0o700
    assert stat.S_IMODE((_template().parent).stat().st_mode) == 0o755


def test_refresh_runs_only_when_present_and_confirmed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert _install(theme=True, yes=True) == 0
    assert "Switch themes once" in capsys.readouterr().out

    log = tmp_path / "refresh.log"
    bin_dir = Path(os.environ["PATH"])
    _stub(bin_dir, "omarchy-theme-refresh", f"#!/bin/sh\necho ran >> {log}\nexit 0\n")
    _tty(monkeypatch, "n")
    assert _install(theme=True) == 0
    assert not log.exists()
    assert "Switch themes once" in capsys.readouterr().out

    assert _install(theme=True, yes=True) == 0
    assert log.read_text(encoding="utf-8").strip() == "ran"

    log.write_text("", encoding="utf-8")
    _stub(bin_dir, "omarchy-theme-refresh", "#!/bin/sh\nexit 3\n")
    assert _install(theme=True, yes=True) == 1
    assert _template().read_bytes() == shipped_template()
    assert "exited 3" in capsys.readouterr().err


def test_profile_selects_omarchy_and_leaves_the_lock(
    capsys: pytest.CaptureFixture[str],
) -> None:
    create_profile(data_dir(), "desk")
    set_lock(data_dir(), "smf.praxis", "dark")
    assert _install(theme=True, yes=True, profile="desk") == 0
    assert _profile_choice(data_dir(), "desk") == ("omarchy", "system")
    assert lock_state(data_dir()) == ("smf.praxis", "dark")
    assert "set desk theme smf.praxis mode dark" in capsys.readouterr().out

    assert _install(keybind=False, theme=True, yes=True, profile="desk") == 0
    assert "already uses omarchy" in capsys.readouterr().out
    _version("4.0.0")
    assert _install(keybind=True, yes=True, profile="desk") == 0
    assert _profile_choice(data_dir(), "desk") == ("omarchy", "system")
    assert lock_state(data_dir()) == ("smf.praxis", "dark")

    assert _install(theme=True, yes=True) == 0
    assert THEME_SET_HINT in capsys.readouterr().out
    assert _install(theme=True, yes=True, profile="missing") == 1


def test_keybind_lua_is_idempotent_and_refuses_a_conflict(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _version("4.0.0")
    user = 'o.bind("SUPER + SHIFT + ALT + A", "Grok", "true")\n'
    path = _bindings()
    path.parent.mkdir(parents=True)
    path.write_text(user, encoding="utf-8")
    before = path.stat().st_mtime_ns
    assert _install(keybind=True, yes=True) == 0
    text = path.read_text(encoding="utf-8")
    assert text.count("praxis-prime keybind") == 2
    assert 'o.bind("SUPER + ALT + A", "Praxis Prime", "omarchy-launch-or-focus-tui ' in text
    assert "--app-id=org.omarchy.praxis-prime /usr/bin/praxis-prime tui" in text
    assert user.strip() in text
    assert len(_baks(path)) == 1
    assert _baks(path)[0].read_text(encoding="utf-8") == user
    assert not _bindings("bindings.conf").exists()

    again = path.stat().st_mtime_ns
    assert again != before
    assert _install(keybind=True, yes=True) == 0
    assert path.stat().st_mtime_ns == again
    assert len(_baks(path)) == 1

    changed = text.replace("/usr/bin/praxis-prime", "/elsewhere/praxis-prime")
    path.write_text(changed, encoding="utf-8")
    assert _install(keybind=True, yes=True) == 0
    replaced = path.read_text(encoding="utf-8")
    assert replaced.count('o.bind("SUPER + ALT + A"') == 1
    assert "/usr/bin/praxis-prime tui" in replaced
    assert "/elsewhere/praxis-prime" not in replaced

    doubled = replaced + "\n" + replaced[replaced.index("-- >>>") :]
    path.write_text(doubled, encoding="utf-8")
    assert _install(keybind=True, yes=True) == 0
    assert path.read_text(encoding="utf-8").count('o.bind("SUPER + ALT + A"') == 1

    broken = path.read_text(encoding="utf-8").replace("-- <<< praxis-prime keybind <<<\n", "")
    path.write_text(broken, encoding="utf-8")
    assert _install(keybind=True, yes=True) == 1
    assert path.read_text(encoding="utf-8") == broken
    assert "incomplete" in capsys.readouterr().err


def test_existing_super_alt_a_outside_the_block_is_refused() -> None:
    _version("4.0.0")
    path = _bindings()
    path.parent.mkdir(parents=True)
    original = 'o.bind("SUPER + ALT + A", "Other", "true")\n'
    path.write_text(original, encoding="utf-8")
    assert _install(keybind=True, yes=True, dry_run=True) == 1
    assert path.read_text(encoding="utf-8") == original
    assert find_conflict('o.bind("SUPER + SHIFT + CTRL + A", "Pick", "true")\n', "lua") is None
    assert find_conflict('o.bind("SUPER + CTRL + A", "Audio", "true")\n', "lua") is None
    assert find_conflict('-- o.bind("SUPER + ALT + A", "Hidden", "true")\n', "lua") is None
    assert find_conflict('hl.unbind("SUPER + ALT + A")\n', "lua") is None
    assert find_conflict("unbind = SUPER ALT, A\n", "conf") is None
    assert find_conflict("# bindd = SUPER ALT, A, Hidden, exec, true\n", "conf") is None
    assert find_conflict("bindd = SUPER SHIFT ALT, A, Grok, exec, true\n", "conf") is None
    assert find_conflict("bindd = SUPER ALT, A, Other, exec, true\n", "conf") is not None


def test_omarchy_3_writes_bindings_conf() -> None:
    _version("3.1.0")
    assert _install(keybind=True, yes=True) == 0
    path = _bindings("bindings.conf")
    text = path.read_text(encoding="utf-8")
    assert text.startswith("# >>> praxis-prime keybind")
    assert "bindd = SUPER ALT, A, Praxis Prime, exec, " in text
    assert "omarchy-launch-or-focus-tui --app-id=org.omarchy.praxis-prime" in text
    assert not _bindings().exists()
    assert _install(keybind=True, yes=True) == 0
    assert path.read_text(encoding="utf-8") == text


def test_symlink_is_refused_unless_force(capsys: pytest.CaptureFixture[str]) -> None:
    real = _home() / "real-template.json"
    real.write_bytes(b'{"other": true}\n')
    link = _template()
    link.parent.mkdir(parents=True)
    link.symlink_to(real)
    assert _install(theme=True, yes=True) == 1
    assert real.read_bytes() == b'{"other": true}\n'
    assert "symlink" in capsys.readouterr().err

    assert _install(theme=True, yes=True, force=True) == 0
    assert link.is_symlink()
    assert real.read_bytes() == shipped_template()
    assert "following symlink" in capsys.readouterr().out

    target = _home() / "real-bindings.lua"
    target.write_text("-- user\n", encoding="utf-8")
    _version("4.0.0")
    bindings = _bindings()
    bindings.parent.mkdir(parents=True, exist_ok=True)
    bindings.symlink_to(target)
    assert _install(keybind=True, yes=True) == 1
    assert target.read_text(encoding="utf-8") == "-- user\n"
    assert _install(keybind=True, yes=True, force=True) == 0
    assert bindings.is_symlink()
    assert "SUPER + ALT + A" in target.read_text(encoding="utf-8")

    config = _home() / ".config"
    if config.is_symlink():
        config.unlink()
    elif config.exists():
        shutil.rmtree(config)
    real_config = _home() / "real-config"
    real_config.mkdir()
    config.symlink_to(real_config)
    assert _install(theme=True, yes=True) == 1
    assert not (real_config / "omarchy").exists()
    assert _install(theme=True, yes=True, force=True) == 0
    assert config.is_symlink()
    written = real_config / "omarchy" / "themed" / TEMPLATE_NAME
    assert written.is_file()
    assert not written.is_symlink()
    assert written.read_bytes() == shipped_template()


def test_unsafe_path_is_refused_and_a_space_is_quoted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _version("4.0.0")
    monkeypatch.setattr(omarchy_install, "praxis_prime_command", lambda: '/opt/bad"prime')
    assert _install(keybind=True, yes=True) == 1
    assert not _bindings().exists()

    monkeypatch.setattr(
        omarchy_install,
        "praxis_prime_command",
        lambda: "/home/me/My Programs/praxis-prime",
    )
    assert _install(keybind=True, yes=True) == 0
    text = _bindings().read_text(encoding="utf-8")
    assert "'/home/me/My Programs/praxis-prime'" in text
    assert '"' + "/home/me/My Programs/praxis-prime" + '"' not in text


def test_command_resolution_uses_path_then_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(omarchy_install, "praxis_prime_command", _REAL_COMMAND)
    monkeypatch.setattr(
        omarchy_install.shutil,
        "which",
        lambda name: "/usr/local/bin/praxis-prime" if name == "praxis-prime" else None,
    )
    assert _REAL_COMMAND() == "/usr/local/bin/praxis-prime"
    monkeypatch.setattr(omarchy_install.shutil, "which", lambda _name: None)
    monkeypatch.setattr(sys, "argv", ["/tmp/from-argv/praxis-prime"])
    assert _REAL_COMMAND() == "/tmp/from-argv/praxis-prime"
    monkeypatch.setattr(sys, "argv", ["-"])
    with pytest.raises(omarchy_install.OmarchyInstallError):
        _REAL_COMMAND()


def test_non_omarchy_does_not_create_bindings_without_force() -> None:
    assert _install(keybind=True, yes=True) == 1
    assert not _bindings().exists()
    assert _install(keybind=True, yes=True, force=True) == 0
    assert _bindings().is_file()
    (_home() / ".config" / "omarchy").mkdir()
    _bindings().unlink()
    assert _install(keybind=True, yes=True) == 1
    assert not _bindings().exists()


def test_hyprctl_reload_is_offered_only_after_a_write(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _version("4.0.0")
    log = tmp_path / "hypr.log"
    _stub(Path(os.environ["PATH"]), "hyprctl", f"#!/bin/sh\necho reload >> {log}\n")
    answers = iter(["y", "n"])
    monkeypatch.setattr(omarchy_install, "_isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
    assert _install(keybind=True) == 0
    assert _bindings().is_file()
    assert not log.exists()
    path = _bindings()
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "/usr/bin/praxis-prime",
            "/elsewhere/praxis-prime",
        ),
        encoding="utf-8",
    )
    assert _install(keybind=True, yes=True) == 0
    assert log.read_text(encoding="utf-8").strip() == "reload"
    log.write_text("", encoding="utf-8")
    assert _install(keybind=True, yes=True) == 0
    assert log.read_text(encoding="utf-8") == ""


def test_textual_warning_names_both_install_hints(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _version("4.0.0")
    monkeypatch.setattr(omarchy_install, "textual_installed", lambda: False)
    assert _install(keybind=True, dry_run=True) == 0
    out = capsys.readouterr().out
    assert "pip install 'praxis-prime[tui]'" in out
    assert "/opt/praxis-prime/bin/python -m ensurepip --upgrade" in out
    assert "textual>=8.2,<9" in out
    assert not _bindings().exists()


def test_uninstall_removes_only_our_bytes(capsys: pytest.CaptureFixture[str]) -> None:
    _version("4.0.0")
    create_profile(data_dir(), "desk")
    assert _install(yes=True, profile="desk") == 0
    assert _profile_choice(data_dir(), "desk") == ("omarchy", "system")
    user = 'o.bind("SUPER + SHIFT + R", "SSH", "alacritty")\n'
    path = _bindings()
    path.write_text(user + path.read_text(encoding="utf-8"), encoding="utf-8")
    assert _uninstall(yes=True) == 0
    assert not _template().exists()
    left = path.read_text(encoding="utf-8")
    assert "praxis-prime keybind" not in left
    assert "SSH" in left
    assert _profile_choice(data_dir(), "desk") == ("omarchy", "system")
    assert THEME_CLEAR_HINT in capsys.readouterr().out

    _template().parent.mkdir(parents=True, exist_ok=True)
    _template().write_text("{}\n", encoding="utf-8")
    assert _uninstall(theme=True, yes=True) == 0
    assert _template().read_text(encoding="utf-8") == "{}\n"
    assert "differs" in capsys.readouterr().out
    assert _uninstall(theme=True, yes=True, force=True) == 0
    assert not _template().exists()
    assert _baks(_template())

    real = _home() / "kept.json"
    real.write_bytes(shipped_template())
    link = _template()
    link.symlink_to(real)
    assert _uninstall(theme=True, yes=True) == 1
    assert link.is_symlink()
    assert real.read_bytes() == shipped_template()
    assert _uninstall(theme=True, yes=True, force=True) == 0
    assert not link.exists()
    assert real.read_bytes() == shipped_template()

    target = _home() / "kept-bindings.lua"
    marker = omarchy_install.LUA_BEGIN + "\n" + omarchy_install.LUA_END + "\n"
    target.write_text(marker, encoding="utf-8")
    bindings = _bindings()
    if bindings.exists() or bindings.is_symlink():
        bindings.unlink()
    bindings.symlink_to(target)
    assert _uninstall(keybind=True, yes=True) == 1
    assert bindings.is_symlink()
    assert _uninstall(keybind=True, yes=True, force=True) == 0
    assert not bindings.exists()
    assert target.read_text(encoding="utf-8") == marker


def test_status_on_omarchy_and_elsewhere(capsys: pytest.CaptureFixture[str]) -> None:
    plain = format_status()
    assert "Omarchy: not detected" in plain
    assert "Template: not installed" in plain
    assert "Keybind: not installed" in plain
    assert "Rendered: absent" in plain
    assert "Profiles: none chose omarchy" in plain
    assert omarchy_install.status_command() == 0

    _version("4.0.0")
    assert _install(yes=True) == 0
    rendered = json.loads(_render(_TOKYO))
    path = theme_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rendered) + "\n", encoding="utf-8")
    create_profile(data_dir(), "desk")
    set_profile_theme(data_dir(), "desk", "omarchy", "system")
    text = format_status()
    assert "Omarchy: detected, 4.0.0 (4.x Lua)" in text
    assert "Template: installed, matches the shipped copy" in text
    assert "Keybind: installed (" in text
    assert f"Rendered: present, compiles to {LIVE_ID}" in text
    assert "Profiles: desk" in text

    _version("3.1.0")
    assert "3.x conf" in format_status()
    _template().write_text("{}\n", encoding="utf-8")
    assert "differs from the shipped copy" in format_status()
    assert main(["omarchy", "status"]) == 0
    assert "Omarchy:" in capsys.readouterr().out


def test_doctor_line_is_omarchy_only() -> None:
    def _checks(release: str) -> list[object]:
        return collect_checks(
            version_info=(3, 12, 0),
            os_release_text=release,
            env={"HOME": str(_home())},
            which=lambda _name: None,
            path_exists=lambda _path: False,
            ollama_reachable=False,
        )

    ubuntu = _checks(_UBUNTU_RELEASE)
    assert [check.name for check in ubuntu] == [  # type: ignore[attr-defined]
        "Python",
        "OS",
        "Session",
        "Provider",
        "Local servers",
        "Sandbox",
        "Browser",
    ]
    _version("4.0.0")
    warned = _checks(_OMARCHY_RELEASE)
    setup = warned[-1]
    assert setup.name == "Omarchy setup"  # type: ignore[attr-defined]
    assert setup.status == "warn"  # type: ignore[attr-defined]
    assert "praxis-prime omarchy install" in setup.detail  # type: ignore[attr-defined]
    assert _install(yes=True) == 0
    ready = _checks(_OMARCHY_RELEASE)[-1]
    assert ready.status == "ok"  # type: ignore[attr-defined]
    assert "template matches" in ready.detail  # type: ignore[attr-defined]
    assert "keybind is installed" in ready.detail  # type: ignore[attr-defined]


def test_cli_registers_install_and_requires_a_subcommand() -> None:
    parser = build_parser()
    args = parser.parse_args(["omarchy", "install", "--theme", "--dry-run", "--profile", "desk"])
    assert args.command == "omarchy"
    assert args.theme is True
    assert args.dry_run is True
    assert args.profile == "desk"
    assert main(["omarchy"]) == 2
    remove = parser.parse_args(["omarchy", "uninstall", "--keybind", "--force"])
    assert remove.keybind is True
    assert remove.force is True
