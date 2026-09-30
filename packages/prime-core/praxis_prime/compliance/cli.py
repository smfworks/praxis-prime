"""CLI for compliance status, GDPR export/erase, and breach records.

Commands read the local config and ``prime.db``. They do not call a model.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from praxis_prime.audit.log import AuditLog
from praxis_prime.compliance.breach import list_breaches, record_breach
from praxis_prime.compliance.detectors import detect
from praxis_prime.compliance.packs import PolicyPack, load_packs
from praxis_prime.compliance.providers import ProviderFlags
from praxis_prime.compliance.report import collect_events, explain_event, render_report
from praxis_prime.compliance.subject import dumps_export, erase_subject, export_subject
from praxis_prime.paths import config_dir
from praxis_prime.policy.dials import DIALS, default_positions
from praxis_prime.profiles.home import resolve_runtime_layout
from praxis_prime.router.settings import load_settings
from praxis_prime.state import StateDB


def add_compliance_parsers(
    commands: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    store = argparse.ArgumentParser(add_help=False)
    store.add_argument("--data-dir", help="Directory that contains prime.db.")
    store.add_argument("--config-dir", help="Config directory.")
    store.add_argument("--project", help="Project root for .prime/packs. Defaults to the cwd.")

    compliance = commands.add_parser(
        "compliance",
        help="Show dial positions, packs, and audit reports. Starter policy, not legal advice.",
    )
    compliance_commands = compliance.add_subparsers(dest="compliance_command")
    compliance_commands.add_parser("status", parents=[store], help="Show dial positions and flags.")
    compliance_commands.add_parser("packs", parents=[store], help="List loaded policy packs.")
    explain = compliance_commands.add_parser(
        "explain",
        parents=[store],
        help="Explain one audit event by id.",
    )
    explain.add_argument("event", help="Audit event id.")
    probe = compliance_commands.add_parser(
        "test",
        parents=[store],
        help="Run detectors on text. Does not change config.",
    )
    probe.add_argument("text", nargs="+", help="Text to scan.")
    report = compliance_commands.add_parser(
        "report",
        parents=[store],
        help="Summarize detections, blocks, approvals, and retention actions.",
    )
    report.add_argument(
        "--since",
        default="",
        help="Include events at or after this ISO timestamp.",
    )
    report.add_argument("--format", choices=("md", "html"), default="md")

    gdpr = commands.add_parser(
        "gdpr",
        help="Export or erase stored text for a data subject. Not legal advice.",
    )
    gdpr_commands = gdpr.add_subparsers(dest="gdpr_command")
    for name, help_text in (
        ("export", "Print stored rows whose text contains the subject."),
        ("erase", "Delete stored rows whose text contains the subject."),
    ):
        command = gdpr_commands.add_parser(name, parents=[store], help=help_text)
        command.add_argument("--subject", required=True, help="Name, email, or other subject key.")

    breach = commands.add_parser(
        "breach",
        help="Record or list local breach-workflow rows. Nothing is sent.",
    )
    breach_commands = breach.add_subparsers(dest="breach_command")
    record = breach_commands.add_parser(
        "record",
        parents=[store],
        help="Store a breach record and a notice draft.",
    )
    record.add_argument("--pack", default="state_nc", help="Pack id. Default: state_nc.")
    record.add_argument("--summary", required=True, help="What happened. Stored locally.")
    record.add_argument("--affected", type=int, default=1, help="How many persons are recorded.")
    breach_commands.add_parser("list", parents=[store], help="List breach records.")


def dispatch_compliance(args: argparse.Namespace) -> int | None:
    if args.command == "compliance":
        return _compliance(args)
    if args.command == "gdpr":
        return _gdpr(args)
    if args.command == "breach":
        return _breach(args)
    return None


def _compliance(args: argparse.Namespace) -> int:
    command = args.compliance_command
    if command not in {"status", "packs", "explain", "test", "report"}:
        print(
            "usage: praxis-prime compliance {status|packs|explain|test|report}",
            file=sys.stderr,
        )
        return 2
    try:
        packs = _packs(args)
        settings = _settings(args)
    except (OSError, ValueError) as exc:
        print(f"praxis-prime compliance: {exc}", file=sys.stderr)
        return 2
    if command == "status":
        _print_status(settings.dials, settings.provider_flags, packs)
        return 0
    if command == "packs":
        if not packs:
            print("no packs loaded")
            return 0
        for pack in packs:
            print(f"{pack.id}  dial={pack.dial}  {pack.title}")
            print(f"  {pack.disclaimer}")
        return 0
    if command == "test":
        text = " ".join(args.text)
        _print_probe(text, settings.dials, packs)
        return 0
    db = _db(args)
    try:
        audit = AuditLog(db)
        if command == "explain":
            by_dial = {pack.dial: pack for pack in packs}
            try:
                sys.stdout.write(explain_event(audit, args.event, by_dial))
            except (LookupError, ValueError) as exc:
                print(f"praxis-prime compliance explain: {exc}", file=sys.stderr)
                return 2
            return 0
        events = collect_events(audit, since=args.since)
        sys.stdout.write(render_report(events, fmt=args.format))
        return 0
    finally:
        db.close()


def _gdpr(args: argparse.Namespace) -> int:
    if args.gdpr_command not in {"export", "erase"}:
        print("usage: praxis-prime gdpr {export|erase} --subject ...", file=sys.stderr)
        return 2
    db = _db(args)
    try:
        note = ""
        for pack in _packs(args):
            if pack.dial == "gdpr" and pack.lawful_basis_note:
                note = pack.lawful_basis_note
        if args.gdpr_command == "export":
            payload = export_subject(db, args.subject, lawful_basis_note=note)
            sys.stdout.write(dumps_export(payload))
            return 0
        audit = AuditLog(db)
        result = erase_subject(db, args.subject, audit=audit)
    except ValueError as exc:
        print(f"praxis-prime gdpr: {exc}", file=sys.stderr)
        return 2
    finally:
        db.close()
    print(
        f"erased memory={result['memory_deleted']} messages={result['messages_deleted']}"
    )
    return 0


def _breach(args: argparse.Namespace) -> int:
    if args.breach_command not in {"record", "list"}:
        print("usage: praxis-prime breach {record|list}", file=sys.stderr)
        return 2
    db = _db(args)
    try:
        if args.breach_command == "list":
            rows = list_breaches(db)
            if not rows:
                print("no breach records")
                return 0
            for row in rows:
                print(
                    f"{row['id']}  {row['created_at']}  {row['pack']}  "
                    f"affected={row['affected']}  {row['status']}  {row['summary']}"
                )
            return 0
        packs = {pack.id: pack for pack in _packs(args)}
        pack = packs.get(args.pack)
        if pack is None:
            print(f"praxis-prime breach: unknown pack {args.pack}", file=sys.stderr)
            return 2
        record = record_breach(
            db,
            pack=pack,
            summary=args.summary,
            affected=args.affected,
            audit=AuditLog(db),
        )
    except ValueError as exc:
        print(f"praxis-prime breach: {exc}", file=sys.stderr)
        return 2
    finally:
        db.close()
    print(record["id"])
    print(record["draft"])
    return 0


def _print_status(
    dials: dict[str, str],
    flags: dict[str, ProviderFlags],
    packs: tuple[PolicyPack, ...],
) -> None:
    print("Compliance dials (starter policy, not legal advice):")
    known = {dial.id: dial.title for dial in DIALS}
    for dial_id, position in dials.items():
        title = known.get(dial_id, dial_id)
        print(f"  {dial_id}  {position}  {title}")
    print("Provider flags:")
    if not flags:
        print("  (defaults apply when a model call is routed)")
    for name, meta in flags.items():
        print(
            f"  {name}  local={str(meta.local).lower()} baa={str(meta.baa).lower()} "
            f"eu_region={str(meta.eu_region).lower()} "
            f"zero_retention={str(meta.zero_retention).lower()}"
        )
    active = [dial_id for dial_id, position in dials.items() if position != "off"]
    if not active:
        print("Every dial is off. Behavior matches a fresh install.")
    print(f"Packs loaded: {len(packs)}")


def _print_probe(text: str, dials: dict[str, str], packs: tuple[PolicyPack, ...]) -> None:
    positions = dict(default_positions())
    positions.update(dials)
    print("Detector probe. Starter policy, not legal advice.")
    any_hit = False
    for pack in packs:
        hits = detect(text, pack.detectors)
        if not hits:
            continue
        any_hit = True
        position = positions.get(pack.dial, "off")
        state = position if position != "off" else "off (would detect only)"
        classes = sorted({hit.data_class for hit in hits})
        print(f"- {pack.dial} [{state}]: {', '.join(classes)}")
    if not any_hit:
        print("no detector matched")


def _packs(args: argparse.Namespace) -> tuple[PolicyPack, ...]:
    config = _config_dir(args)
    project = Path(args.project) if getattr(args, "project", None) else Path.cwd()
    return load_packs(config_dir=config, project_root=project)


def _settings(args: argparse.Namespace):
    path = _config_dir(args) / "config.toml"
    if path.is_file():
        return load_settings({}, config_path=path)
    return load_settings({})


def _config_dir(args: argparse.Namespace) -> Path:
    if getattr(args, "config_dir", None):
        return Path(args.config_dir)
    return config_dir()


def _db(args: argparse.Namespace) -> StateDB:
    raw = getattr(args, "data_dir", None)
    data_file = Path(raw) / "prime.db" if raw else None
    path = resolve_runtime_layout(None, data_file=data_file, profile=None).db_path
    return StateDB(path)
