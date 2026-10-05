"""``praxis-prime migrate --from-praxis``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from praxis_prime.migrate.apply import (
    MigrateError,
    migrate_from_praxis,
    public_text,
    render_summary,
    report_json,
)
from praxis_prime.migrate.source import SourceError
from praxis_prime.paths import config_dir, data_dir
from praxis_prime.profiles.migrate import MigrationBusy


def add_migrate_parser(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    migrate = commands.add_parser(
        "migrate",
        help="Import a SMF Praxis home. Requires --from-praxis.",
    )
    migrate.add_argument(
        "--from-praxis",
        action="store_true",
        help="Read a Praxis home (default ~/.praxis) into one profile.",
    )
    migrate.add_argument(
        "--source",
        default="~/.praxis",
        help="Praxis home directory. Default ~/.praxis. It is only read.",
    )
    migrate.add_argument("--profile", default="default", help="Target profile. Default default.")
    migrate.add_argument(
        "--dry-run",
        action="store_true",
        help="Print counts, skips, and conflicts. Write nothing.",
    )
    migrate.add_argument("--json", action="store_true", help="Print the plan as JSON.")
    migrate.add_argument(
        "--only",
        default="",
        help="Comma list: memory, skills, packs, routines, history, settings.",
    )
    migrate.add_argument(
        "--include-secrets",
        action="store_true",
        help="Copy a mapped auth-profile key into secrets.env. Off by default.",
    )
    migrate.add_argument("--data-dir", default="", help="Praxis Prime data root.")
    migrate.add_argument("--config-dir", default="", help="Praxis Prime config directory.")


def migrate_command(args: argparse.Namespace) -> int:
    if not getattr(args, "from_praxis", False):
        print(
            "usage: praxis-prime migrate --from-praxis [--source PATH] [--dry-run]",
            file=sys.stderr,
        )
        return 2
    only = _only(getattr(args, "only", ""))
    if only is False:
        print(
            "praxis-prime migrate: only accepts memory, skills, packs, routines, history, settings",
            file=sys.stderr,
        )
        return 2
    data = Path(args.data_dir) if getattr(args, "data_dir", "") else data_dir()
    config = Path(args.config_dir) if getattr(args, "config_dir", "") else config_dir()
    try:
        report = migrate_from_praxis(
            Path(args.source),
            data,
            profile=str(args.profile),
            config_dir=config,
            dry_run=bool(args.dry_run),
            only=only,
            include_secrets=bool(args.include_secrets),
        )
    except MigrationBusy as exc:
        _error(exc)
        return 1
    except MigrateError as exc:
        _error(exc)
        text = str(exc)
        if text.startswith("profile id") or text.startswith("only accepts"):
            return 2
        return 1
    except SourceError as exc:
        _error(exc)
        return 1
    if args.json:
        sys.stdout.write(report_json(report))
    else:
        sys.stdout.write(render_summary(report))
    return 0


def _only(text: str) -> set[str] | None | bool:
    raw = text.strip()
    if not raw:
        return None
    selected = {part.strip() for part in raw.split(",") if part.strip()}
    if not selected:
        return False
    return selected


def _error(exc: BaseException) -> None:
    print(f"praxis-prime migrate: {public_text(exc)}", file=sys.stderr)
