"""CLI for vertical packs: list, install, and info.

Install copies pack data only. It logs and prints a warning when a model pin
or dashboard JavaScript is ignored, and it records provenance in the audit log.

TODO: ARCHITECTURE §24 and §32. Addendum A §7.5.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from praxis_prime.audit.log import AuditLog
from praxis_prime.packs.catalog import PUBLIC_PACKS, known_names, resolve_public
from praxis_prime.packs.install import install_pack, installed_index, list_installed
from praxis_prime.packs.legacy import PackError
from praxis_prime.packs.model import PERSONA_BOUNDARY, LegacyPack
from praxis_prime.paths import data_dir
from praxis_prime.profiles.home import resolve_runtime_layout
from praxis_prime.state import StateDB


def add_packs_parsers(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--data-dir",
        help="Directory for prime.db and installed packs. Defaults to the XDG data path.",
    )
    packs = commands.add_parser(
        "packs",
        help="List, install, or inspect vertical packs. Pack code is not executed.",
    )
    sub = packs.add_subparsers(dest="packs_command")
    sub.add_parser("list", parents=[common], help="List installed packs and the public catalog.")
    install = sub.add_parser(
        "install",
        parents=[common],
        help="Install a catalog name, directory, zip, or git URL as data.",
    )
    install.add_argument("source", help="Name, path, or git URL.")
    info = sub.add_parser(
        "info",
        parents=[common],
        help="Show the mapping report for an installed pack.",
    )
    info.add_argument("name", help="Pack name or catalog alias.")


def dispatch_packs(args: argparse.Namespace) -> int | None:
    if getattr(args, "command", None) != "packs":
        return None
    command = getattr(args, "packs_command", None)
    if command not in {"list", "install", "info"}:
        print("usage: praxis-prime packs {list|install|info}", file=sys.stderr)
        return 2
    try:
        if command == "list":
            print(_format_list(_data(args)))
            return 0
        if command == "install":
            return _install(args)
        print(_format_info(_data(args), args.name))
        return 0
    except PackError as exc:
        print(f"packs: {exc}", file=sys.stderr)
        return 1


def _install(args: argparse.Namespace) -> int:
    data = _data(args)
    path = resolve_runtime_layout(None, data_file=data / "prime.db", profile=None).db_path
    db = StateDB(path)
    try:
        installed = install_pack(args.source, data, audit=AuditLog(db))
    finally:
        db.close()
    pack = installed.pack
    print(f"installed {pack.name} {pack.version} ({pack.provenance.license})")
    print(f"path: {installed.path}")
    for warning in pack.warnings:
        print(f"warning: {warning.message}", file=sys.stderr)
    return 0


def _format_list(data: Path) -> str:
    installed = list_installed(data)
    lines = ["Installed vertical packs:"]
    if not installed:
        lines.append("  (none)")
    for pack in installed:
        commit = pack.provenance.commit[:12] if pack.provenance.commit else "-"
        lines.append(
            f"  {pack.name}  {pack.version}  {pack.provenance.license}  commit {commit}"
        )
    lines.append("")
    lines.append("Public MIT packs:")
    have = {pack.name for pack in installed}
    for public in PUBLIC_PACKS:
        state = "installed" if public.pack_name in have or public.key in have else "not installed"
        lines.append(f"  {public.key}  {public.pack_name}  {public.license}  {state}")
    lines.append("")
    lines.append("Install with: praxis-prime packs install <name|path|git-url>")
    return "\n".join(lines)


def _format_info(data: Path, name: str) -> str:
    index = installed_index(data)
    pack = index.get(name) or index.get(name.strip())
    if pack is None:
        public = resolve_public(name)
        if public is not None and public.pack_name in index:
            pack = index[public.pack_name]
    if pack is None:
        known = ", ".join(known_names())
        raise PackError(f"pack {name!r} is not installed. Known names: {known}")
    return _report(pack)


def _report(pack: LegacyPack) -> str:
    provenance = pack.provenance
    lines = [
        f"name: {pack.name}",
        f"version: {provenance.version or pack.version}",
        f"vertical: {pack.vertical}",
        f"description: {pack.description}",
        f"license: {provenance.license}",
        f"repo: {provenance.repo}",
        f"commit: {provenance.commit or '-'}",
        f"source: {provenance.source}",
        "selected model: none",
        f"model suggestion: {pack.model_suggestion or '-'}",
        f"provider suggestion: {pack.provider_suggestion or '-'}",
        f"compliance mode: {pack.compliance_mode or '-'}",
        "compliance mode applied: no",
        "suggested dials: "
        + (
            ", ".join(f"{dial}={position}" for dial, position in pack.suggested_dials)
            if pack.suggested_dials
            else "-"
        ),
        f"approval ttl seconds: {pack.approval_ttl_seconds}",
        "dual approval: " + (", ".join(pack.dual_approval_risks) or "-"),
        "autonomous: " + (", ".join(pack.autonomous_risks) or "-"),
        "tool allowlist: " + (", ".join(pack.tool_allowlist()) or "-"),
        "unavailable tools: " + (", ".join(pack.unavailable_tools()) or "-"),
        "javascript ignored: " + (", ".join(pack.ignored_javascript) or "-"),
        "dashboard ignored: " + (", ".join(pack.ignored_dashboard) or "-"),
        "python not executed: " + (", ".join(pack.python_modules) or "-"),
        "declared entry points: " + (", ".join(pack.declared_entry_points) or "-"),
        "executed entry points: " + (", ".join(pack.executed_entry_points) or "-"),
        f"persona: {PERSONA_BOUNDARY}",
        "",
        "skills:",
    ]
    if pack.skills:
        for skill in pack.skills:
            namespace = skill.meta.get("namespace", skill.name)
            lines.append(f"  {namespace}: {skill.description}")
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append("rules:")
    for rule in pack.rules:
        state = "applied" if rule.applied else "recorded"
        lines.append(f"  {rule.id}  {state}  {rule.effect}")
    if pack.theme is not None:
        lines.append("")
        lines.append(f"theme hint: {pack.theme.suggested_theme_id}")
        for token, value in pack.theme.token_overrides:
            lines.append(f"  {token} = {value}")
    if pack.warnings:
        lines.append("")
        lines.append("warnings:")
        for warning in pack.warnings:
            lines.append(f"  {warning.code}: {warning.message}")
    return "\n".join(lines)


def _data(args: argparse.Namespace) -> Path:
    if getattr(args, "data_dir", None):
        return Path(args.data_dir)
    return data_dir()
