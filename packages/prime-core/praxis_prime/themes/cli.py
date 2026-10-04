"""CLI for theme packages: lint, pack, install, list, remove, and set.

The CLI is the local data-directory owner, the same way ``packs install`` is.
The daemon is where account roles are enforced.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from praxis_prime.audit.log import AuditLog
from praxis_prime.paths import data_dir
from praxis_prime.profiles.home import list_profiles, resolve_runtime_layout
from praxis_prime.state import StateDB
from praxis_prime.statfile import StatKind, lstat_kind
from praxis_prime.themes.archive import read_dir, write_zip
from praxis_prime.themes.errors import ThemeError
from praxis_prime.themes.legacy import describe_hint
from praxis_prime.themes.select import lock_state, resolve_theme, set_lock, set_profile_theme
from praxis_prime.themes.store import install_files, list_themes, remove_theme, winners
from praxis_prime.themes.validate import validate_dir, validate_files


def add_theme_parser(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--data-dir",
        help="Data directory. Defaults to $XDG_DATA_HOME/praxis-prime.",
    )
    theme = commands.add_parser("theme", help="Install, check, and select appearance packages.")
    sub = theme.add_subparsers(dest="theme_command")
    install = sub.add_parser("install", parents=[common], help="Install a theme zip or directory.")
    install.add_argument("source", help="Path to a .zip or a theme directory.")
    install.add_argument(
        "--system",
        action="store_true",
        help="Write under /var/lib/praxis-prime/themes instead of the user data directory.",
    )
    sub.add_parser("list", parents=[common], help="List built-in, system, and user themes.")
    lint = sub.add_parser("lint", help="Validate a theme directory.")
    lint.add_argument("directory", help="Theme directory.")
    lint.add_argument("--json", action="store_true", help="Print machine-readable issues.")
    pack = sub.add_parser("pack", help="Write <id>-<version>.praxis-theme.zip.")
    pack.add_argument("directory", help="Theme directory.")
    pack.add_argument("-o", "--output", help="Zip path to write.")
    remove = sub.add_parser("remove", parents=[common], help="Remove an installed theme id.")
    remove.add_argument("theme_id")
    remove.add_argument("--system", action="store_true", help="Remove the system copy.")
    set_theme = sub.add_parser(
        "set",
        parents=[common],
        help="Select a theme for a profile, or lock it for every profile.",
    )
    set_theme.add_argument("theme_id", nargs="?", help="Theme id. Omit this with --unlock.")
    set_theme.add_argument("--mode", choices=("light", "dark", "system"), default="system")
    set_theme.add_argument("--profile",
        help="Profile id. Defaults to default when that profile exists.")
    set_theme.add_argument("--lock", action="store_true", help="Lock this theme for every profile.")
    set_theme.add_argument("--unlock", action="store_true", help="Clear the admin theme lock.")


def dispatch_theme(args: argparse.Namespace) -> int | None:
    if getattr(args, "command", None) != "theme":
        return None
    command = getattr(args, "theme_command", None)
    try:
        if command == "install":
            return _install(args)
        if command == "list":
            print(_format_list(_data(args)))
            return 0
        if command == "lint":
            return _lint(args)
        if command == "pack":
            return _pack(args)
        if command == "remove":
            return _remove(args)
        if command == "set":
            return _set(args)
    except ThemeError as exc:
        if getattr(args, "json", False):
            print(json.dumps(exc.to_json(), indent=2))
        else:
            print(f"theme: {exc}", file=sys.stderr)
            for issue in exc.issues:
                where = f" ({issue.path})" if issue.path else ""
                print(f"  {issue.code}{where}: {issue.message}", file=sys.stderr)
                if issue.fix:
                    print(f"    fix: {issue.fix}", file=sys.stderr)
        return 1
    print(
        "usage: praxis-prime theme {install|list|lint|pack|remove|set}",
        file=sys.stderr,
    )
    return 2


def _install(args: argparse.Namespace) -> int:
    source = Path(args.source)
    files = _read_source(source)
    installed = install_files(files, _data(args), system=bool(args.system))
    _audit(
        _data(args),
        "theme.install",
        f"installed theme {installed.package.theme_id}",
        {
            "id": installed.package.theme_id,
            "version": installed.package.version,
            "packageHash": installed.package_hash,
            "source": installed.source,
        },
    )
    print(
        f"installed {installed.package.theme_id} {installed.package.version} "
        f"({installed.package_hash[:12]})"
    )
    return 0


def _lint(args: argparse.Namespace) -> int:
    try:
        package = validate_dir(args.directory)
    except ThemeError as exc:
        if args.json:
            print(json.dumps(exc.to_json(), indent=2))
        else:
            raise
        return 1
    if args.json:
        print(
            json.dumps(
                {
                    "ok": True,
                    "id": package.theme_id,
                    "version": package.version,
                    "contrast": package.contrast,
                },
                indent=2,
            )
        )
    else:
        print(f"{package.theme_id} {package.version} contrast {package.contrast}")
    return 0


def _pack(args: argparse.Namespace) -> int:
    files = read_dir(Path(args.directory))
    package = validate_files(files)
    name = f"{package.theme_id}-{package.version}.praxis-theme.zip"
    dest = Path(args.output) if args.output else Path.cwd() / name
    write_zip(package.files, dest)
    print(dest)
    return 0


def _remove(args: argparse.Namespace) -> int:
    remove_theme(args.theme_id, _data(args), system=bool(args.system))
    print(f"removed {args.theme_id}")
    return 0


def _set(args: argparse.Namespace) -> int:
    data = _data(args)
    if args.lock and args.unlock:
        print("theme: use either --lock or --unlock", file=sys.stderr)
        return 2
    if args.unlock:
        set_lock(data, "")
        print("unlocked themes")
        return 0
    if not args.theme_id:
        print("theme: a theme id is required", file=sys.stderr)
        return 2
    if args.lock:
        set_lock(data, args.theme_id, args.mode)
        choice = resolve_theme(data, _profile_name(args, data))
        _audit_choice(data,
            choice.theme_id,
            choice.mode,
            choice.installed.package_hash,
            locked=True)
        print(f"locked {args.theme_id} mode {args.mode or 'unchanged'}")
        return 0
    profile = _profile_name(args, data)
    choice = set_profile_theme(data, profile, args.theme_id, args.mode)
    _audit_choice(data,
        choice.theme_id,
        choice.mode,
        choice.installed.package_hash,
        profile=profile)
    print(f"set {profile} theme {choice.theme_id} mode {choice.mode}")
    return 0


def _format_list(data: Path) -> str:
    rows = list_themes(data)
    chosen = winners(data)
    lock_id, lock_mode = lock_state(data)
    lines = ["Themes:"]
    if not rows:
        lines.append("  (none)")
    for item in rows:
        mark = "*" if chosen.get(item.package.theme_id) is item else " "
        lines.append(
            f" {mark} {item.package.theme_id}  {item.package.version}  "
            f"{item.source}  {item.package.contrast}  {item.package_hash[:12]}"
        )
    if lock_id:
        lines.append(f"lock: {lock_id} mode {lock_mode or 'profile'}")
    else:
        lines.append("lock: none")
    lines.append("Install with: praxis-prime theme install <zip-or-directory>")
    return "\n".join(lines)


def format_hint_lines(hint) -> list[str]:
    """Lines for ``packs info``. Contrast is checked. Nothing is written."""
    result = describe_hint(hint)
    if hint is None:
        return []
    lines = [f"theme hint: {hint.suggested_theme_id}", f"theme hint contrast: {result.message}"]
    for mode, token, value in result.adjusted:
        lines.append(f"  adjusted {mode} {token} = {value}")
    return lines


def _read_source(source: Path) -> dict[str, bytes]:
    if lstat_kind(source) is StatKind.DIR:
        return read_dir(source)
    payload = source.read_bytes()
    from praxis_prime.themes.archive import read_zip

    return read_zip(payload)


def _profile_name(args: argparse.Namespace, data: Path) -> str:
    named = getattr(args, "profile", None)
    if named:
        return str(named)
    profiles = list_profiles(data)
    if "default" in profiles:
        return "default"
    if len(profiles) == 1:
        return profiles[0]
    raise ThemeError("pass --profile")


def _data(args: argparse.Namespace) -> Path:
    if getattr(args, "data_dir", None):
        return Path(args.data_dir)
    return data_dir()


def _audit_choice(
    data: Path,
    theme_id: str,
    mode: str,
    package_hash: str,
    *,
    profile: str = "",
    locked: bool = False,
) -> None:
    payload: dict[str, object] = {
        "id": theme_id,
        "mode": mode,
        "packageHash": package_hash,
        "locked": locked,
    }
    if profile:
        payload["profile"] = profile
    _audit(data, "theme.activate", f"activated theme {theme_id}", payload)


def _audit(data: Path, kind: str, summary: str, payload: dict[str, object]) -> None:
    layout = resolve_runtime_layout(None, data_file=data / "prime.db", profile=None)
    if lstat_kind(layout.db_path) is not StatKind.FILE:
        return
    db = StateDB(layout.db_path)
    try:
        AuditLog(db).append(session_id=None, kind=kind, summary=summary, payload=payload)
    finally:
        db.close()
