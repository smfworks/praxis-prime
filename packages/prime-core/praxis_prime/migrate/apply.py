"""Import a SMF Praxis home into one Praxis Prime profile.

Imported skills, memory, and packs stay untrusted data. Tools and grants are
not enabled. Routines are inserted paused. Regulated packs move mapped dials
from off to monitor and never to enforce. Secrets stay out unless
``include_secrets`` is set, and even then only a known provider key that
``secrets.env`` already accepts is written. Channel messages are redacted with
the memory secret patterns and sanitized before they are stored.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from praxis_prime.audit.log import AuditLog
from praxis_prime.clock import dump_time, utcnow
from praxis_prime.memory.redact import redact_text, retention_days
from praxis_prime.memory.store import SessionStore
from praxis_prime.migrate.source import (
    PraxisDB,
    SourceError,
    file_sha256,
    read_regular_text,
    source_fingerprint,
)
from praxis_prime.onboarding.service import KEY_NAMES
from praxis_prime.packs.catalog import PUBLIC_PACKS, SUGGESTED_DIALS
from praxis_prime.packs.install import install_pack, vertical_packs_dir
from praxis_prime.packs.legacy import PackError, load_legacy_pack
from praxis_prime.policy.dials import default_positions, dial_ids
from praxis_prime.profiles.home import ProfileHome, create_profile
from praxis_prime.profiles.ids import profile_id
from praxis_prime.profiles.migrate import MigrationBusy, daemon_is_running
from praxis_prime.router.types import ChatMessage
from praxis_prime.sanitize import sanitize
from praxis_prime.scheduler.cron import ScheduleError, parse_cron, parse_every
from praxis_prime.skills.format import parse_skill
from praxis_prime.state import DatabaseBusy, StateDB
from praxis_prime.statfile import StatKind, lstat_kind

CATEGORIES = ("memory", "skills", "packs", "routines", "history", "settings")
_PROFILE_KINDS = frozenset({"fact", "preference", "decision"})
_SAFE_SCOPE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")
_CHAT_ROLES = frozenset({"user", "assistant", "tool"})
_KNOWN_TABLES = frozenset(
    {
        "memory_items",
        "vectors",
        "cron_jobs",
        "channel_threads",
        "skill_metadata",
        "skill_outcomes",
        "compliance",
        "sqlite_sequence",
    }
)
_REGULATED = frozenset(SUGGESTED_DIALS) | frozenset(
    name
    for pack in PUBLIC_PACKS
    for name in (pack.key, pack.pack_name, pack.distribution.replace("-", "_"))
)
_REGULATED_VERTICALS = frozenset(
    {
        "medical",
        "dental",
        "legal",
        "law",
        "law_firm",
        "education",
        "school",
        "school_system",
        "homeschool",
        "forensic",
        "behavioral_health",
        "behavioral health",
    }
)
_PACK_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SKIP_DIRS = frozenset({".git", "__pycache__", ".venv", "venv", "node_modules"})
_MAX_SKILL_FILE = 1024 * 1024
_MAX_SKILL_TREE = 8 * 1024 * 1024
_MAX_TEXT = 100_000
_SETUP_NOTE = "Provider keys were not copied. Run `praxis-prime setup` to choose a provider."


class MigrateError(ValueError):
    """The import cannot run."""


@dataclass
class Tally:
    found: int = 0
    imported: int = 0
    skipped: int = 0
    reasons: dict[str, int] = field(default_factory=dict)

    def add(self, imported: bool, reason: str = "") -> None:
        self.found += 1
        if imported:
            self.imported += 1
            return
        self.skipped += 1
        if reason:
            self.reasons[reason] = self.reasons.get(reason, 0) + 1

    def public(self) -> dict[str, object]:
        return {
            "found": self.found,
            "imported": self.imported,
            "skipped": self.skipped,
            "reasons": {key: self.reasons[key] for key in sorted(self.reasons)},
        }


@dataclass
class MigrationReport:
    run_id: str
    imported_at: str
    dry_run: bool
    source: str
    profile: str
    db_sha256: str
    categories: dict[str, Tally]
    unknown_tables: list[dict[str, object]]
    providers: list[str]
    auth_profiles: list[str]
    notes: list[str]
    dials_to_monitor: list[str]
    report_path: str = ""
    summary_path: str = ""
    history_archive: str = ""

    def public(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "imported_at": self.imported_at,
            "dry_run": self.dry_run,
            "source": self.source,
            "profile": self.profile,
            "db_sha256": self.db_sha256,
            "categories": {name: tally.public() for name, tally in self.categories.items()},
            "unknown_tables": self.unknown_tables,
            "providers": self.providers,
            "auth_profiles": self.auth_profiles,
            "notes": self.notes,
            "dials_to_monitor": self.dials_to_monitor,
            "report_path": self.report_path,
            "summary_path": self.summary_path,
            "history_archive": self.history_archive,
        }


def migrate_from_praxis(
    source: Path,
    data_root: Path,
    *,
    profile: str = "default",
    config_dir: Path | None = None,
    dry_run: bool = False,
    only: set[str] | None = None,
    include_secrets: bool = False,
    daemon_running: Callable[[], bool] | None = None,
) -> MigrationReport:
    """Import ``source`` into ``data_root``. A dry run writes nothing."""
    checked = profile_id(profile)
    if checked is None:
        raise MigrateError("profile id must be 1 to 64 characters: a-z, 0-9, hyphen")
    selected = set(CATEGORIES if only is None else only)
    unknown = selected - set(CATEGORIES)
    if unknown or not selected:
        raise MigrateError("only accepts memory, skills, packs, routines, history, settings")
    root = Path(source).expanduser()
    if lstat_kind(root) is not StatKind.DIR:
        raise MigrateError("praxis source is not a directory")
    data = Path(data_root)
    if _same_tree(root, data):
        raise MigrateError("source and the data directory must be different")
    running = daemon_is_running if daemon_running is None else daemon_running
    if running():
        raise MigrationBusy(
            "stop praxis-primed before praxis-prime migrate; it may hold the profile database"
        )
    if not dry_run:
        _refuse_if_profile_busy(data, checked)
        if running():
            raise MigrationBusy(
                "stop praxis-primed before praxis-prime migrate; it may hold the profile database"
            )
    home = ProfileHome(data, checked)
    if dry_run:
        db = None
        audit = None
    else:
        if not home.exists():
            create_profile(data, checked, display_name=checked)
        held = StateDB(home.db_path, exclusive=True)
        db = held
        audit = AuditLog(held)
    try:
        return _run(
            root,
            data,
            home,
            db,
            audit,
            checked,
            selected,
            dry_run=dry_run,
            include_secrets=include_secrets,
            config_dir=config_dir,
        )
    finally:
        if audit is not None:
            audit.close()
        if db is not None:
            db.close()


def _run(
    root: Path,
    data: Path,
    home: ProfileHome,
    db: StateDB | None,
    audit: AuditLog | None,
    profile: str,
    selected: set[str],
    *,
    dry_run: bool,
    include_secrets: bool,
    config_dir: Path | None,
) -> MigrationReport:
    now = dump_time(utcnow())
    run_id = uuid.uuid4().hex
    categories = {name: Tally() for name in CATEGORIES}
    notes = [
        "Each imported row records source praxis, the original table and id, "
        "the source file sha256, this run id, and the time.",
        "A second run skips rows already recorded. "
        "Skills and packs do not change the profile allow list.",
        _SETUP_NOTE,
    ]
    db_path = root / "praxis.db"
    db_sha = ""
    unknown_tables: list[dict[str, object]] = []
    providers: list[str] = []
    auth_names: list[str] = []
    dials: list[str] = []
    archive = ""
    ledger = _Ledger(db, dry_run=dry_run, run_id=run_id, now=now)
    if lstat_kind(db_path) is StatKind.FILE:
        with PraxisDB(db_path) as source_db:
            db_sha = source_db.sha256
            unknown_tables = _unknown_tables(source_db)
            if "memory" in selected:
                hashes = _import_memory(source_db, db, ledger, categories["memory"], now)
                _import_vectors(source_db, db, ledger, categories["memory"], now, hashes)
            if "routines" in selected:
                if _import_routines(source_db, db, ledger, categories["routines"], db_sha, now):
                    notes.append(
                        "Routine delivery targets were not imported. Imported routines are paused."
                    )
            if "history" in selected:
                archive = _import_history(
                    source_db,
                    db,
                    ledger,
                    categories["history"],
                    data,
                    run_id,
                    db_sha,
                    now,
                    dry_run=dry_run,
                )
            if "skills" in selected:
                quarantined = _quarantined(source_db)
            else:
                quarantined = frozenset()
            if "settings" in selected:
                _import_compliance(source_db, categories["settings"])
    else:
        notes.append("praxis.db is not a regular file. Database rows were not read.")
        quarantined = frozenset()
    if "skills" in selected:
        _import_skills(
            root,
            home,
            ledger,
            categories["skills"],
            quarantined,
            dry_run=dry_run,
        )
    if "packs" in selected:
        dials = _import_packs(
            root,
            data,
            ledger,
            categories["packs"],
            dry_run=dry_run,
        )
        if dials:
            notes.append(
                "Regulated packs map to monitor on "
                + ", ".join(dials)
                + ". Existing enforce positions are left alone."
            )
        if dials and not dry_run and config_dir is not None:
            _apply_monitor(config_dir, db, audit, dials)
        elif dials and not dry_run:
            notes.append("Dials were not written because no config directory was given.")
    if "settings" in selected:
        found_providers, found_auth = _import_settings(
            root,
            ledger,
            categories["settings"],
            config_dir=config_dir,
            include_secrets=include_secrets,
            dry_run=dry_run,
        )
        providers = found_providers
        auth_names = found_auth
    ledger.flush()
    report = MigrationReport(
        run_id=run_id,
        imported_at=now,
        dry_run=dry_run,
        source=str(root),
        profile=profile,
        db_sha256=db_sha,
        categories=categories,
        unknown_tables=unknown_tables,
        providers=providers,
        auth_profiles=auth_names,
        notes=notes,
        dials_to_monitor=dials,
        history_archive=archive,
    )
    if not dry_run:
        json_path, summary_path = _write_report(data, report)
        report.report_path = str(json_path)
        report.summary_path = str(summary_path)
        if audit is not None:
            audit.append(
                session_id=None,
                kind="praxis.import",
                summary=f"imported from praxis run {run_id}",
                payload={
                    "run_id": run_id,
                    "source": "praxis",
                    "profile": profile,
                    "db_sha256": db_sha,
                    "dry_run": False,
                    "counts": {name: tally.public() for name, tally in categories.items()},
                    "providers": providers,
                    "auth_profiles": auth_names,
                    "dials_to_monitor": dials,
                    "unknown_tables": [row["name"] for row in unknown_tables],
                },
                profile=profile,
            )
    return report


class _Ledger:
    def __init__(self, db: StateDB | None, *, dry_run: bool, run_id: str, now: str) -> None:
        self.db = db
        self.dry_run = dry_run
        self.run_id = run_id
        self.now = now
        self.pending = 0
        self.seen: set[tuple[str, str]] = set()
        if db is not None and not dry_run:
            db.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS import_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    imported_at TEXT NOT NULL,
                    category TEXT NOT NULL,
                    source TEXT NOT NULL,
                    source_table TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    source_sha256 TEXT NOT NULL,
                    target_kind TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    UNIQUE (source, source_table, source_id)
                )
                """
            )
            db.conn.commit()
            rows = db.conn.execute(
                "SELECT source_table, source_id FROM import_records WHERE source = 'praxis'"
            ).fetchall()
            self.seen = {(str(row[0]), str(row[1])) for row in rows}

    def has(self, table: str, source_id: object) -> bool:
        return (table, str(source_id)) in self.seen

    def add(
        self,
        *,
        category: str,
        table: str,
        source_id: object,
        sha256: str,
        target_kind: str,
        target_id: str,
    ) -> None:
        key = (table, str(source_id))
        self.seen.add(key)
        if self.dry_run or self.db is None:
            return
        self.db.conn.execute(
            """
            INSERT INTO import_records (
                run_id, imported_at, category, source, source_table, source_id,
                source_sha256, target_kind, target_id
            ) VALUES (?, ?, ?, 'praxis', ?, ?, ?, ?, ?)
            """,
            (
                self.run_id,
                self.now,
                category,
                table,
                str(source_id),
                sha256,
                target_kind,
                target_id,
            ),
        )
        self.pending += 1
        if self.pending >= 400:
            self.flush()

    def flush(self) -> None:
        if self.dry_run or self.db is None or self.pending == 0:
            self.pending = 0
            return
        self.db.conn.commit()
        self.pending = 0


def _import_memory(
    source_db: PraxisDB,
    db: StateDB | None,
    ledger: _Ledger,
    tally: Tally,
    now: str,
) -> dict[tuple[str, str, str], str]:
    hashes = _existing_hashes(db)
    if "memory_items" not in source_db.table_names():
        return hashes
    columns = source_db.columns("memory_items")
    if "text" not in columns:
        tally.add(False, "memory_items has no text column")
        return hashes
    wanted = [
        name
        for name in ("tier", "text", "provenance", "kind", "expires_at", "ts", "workspace_id")
        if name in columns
    ]
    id_expr = "id" if "id" in columns else "rowid"
    selected = [id_expr, *wanted]
    clock = datetime.now(UTC).timestamp()
    for row in source_db.stream("memory_items", selected):
        source_id = row[id_expr]
        if ledger.has("memory_items", source_id):
            tally.add(False, "already imported")
            continue
        tier_name = _text(row, "tier") if "tier" in columns else ""
        kind = _text(row, "kind") if "kind" in columns else "note"
        mapped = _prime_tier(tier_name, kind)
        if mapped is None:
            tally.add(False, "working memory is not imported")
            continue
        if "expires_at" in columns and _expired(row["expires_at"], clock):
            tally.add(False, "expired")
            continue
        raw = _text(row, "text")
        if len(raw) > _MAX_TEXT:
            tally.add(False, "text is too large")
            continue
        cleaned = redact_text(raw, mode="secrets", dials=default_positions()).strip()
        if not cleaned or cleaned == "[redacted]":
            tally.add(False, "redacted")
            continue
        scope = _scope(row["workspace_id"] if "workspace_id" in columns else "")
        digest = _content_hash(mapped, scope, cleaned)
        if (mapped, scope, digest) in hashes:
            target = hashes[(mapped, scope, digest)]
            ledger.add(
                category="memory",
                table="memory_items",
                source_id=source_id,
                sha256=source_db.sha256,
                target_kind="memory_entry",
                target_id=target,
            )
            tally.add(False, "duplicate content")
            continue
        created = _iso(_number(row, "ts") if "ts" in columns else None) or now
        expires = _memory_expiry(mapped, row, columns, created)
        entry_id = f"mem_{uuid.uuid4().hex[:16]}"
        if db is not None and not ledger.dry_run:
            db.conn.execute(
                """
                INSERT INTO memory_entries (
                    id, tier, scope, content, content_hash, source, session_id, channel,
                    created_at, updated_at, expires_at, embedding_json
                ) VALUES (?, ?, ?, ?, ?, 'praxis', '', '', ?, ?, ?, '')
                """,
                (entry_id, mapped, scope, cleaned, digest, created, created, expires),
            )
        hashes[(mapped, scope, digest)] = entry_id
        ledger.add(
            category="memory",
            table="memory_items",
            source_id=source_id,
            sha256=source_db.sha256,
            target_kind="memory_entry",
            target_id=entry_id,
        )
        tally.add(True)
    return hashes


def _import_vectors(
    source_db: PraxisDB,
    db: StateDB | None,
    ledger: _Ledger,
    tally: Tally,
    now: str,
    hashes: dict[tuple[str, str, str], str],
) -> None:
    if "vectors" not in source_db.table_names():
        return
    columns = source_db.columns("vectors")
    if "text" not in columns:
        return
    id_expr = "id" if "id" in columns else "rowid"
    selected = [id_expr, "text"]
    if "ts" in columns:
        selected.append("ts")
    for row in source_db.stream("vectors", selected):
        source_id = row[id_expr]
        if ledger.has("vectors", source_id):
            tally.add(False, "already imported")
            continue
        raw = _text(row, "text")
        if len(raw) > _MAX_TEXT:
            tally.add(False, "text is too large")
            continue
        cleaned = redact_text(raw, mode="secrets", dials=default_positions()).strip()
        if not cleaned or cleaned == "[redacted]":
            tally.add(False, "redacted")
            continue
        digest = _content_hash("semantic", "global", cleaned)
        if ("semantic", "global", digest) in hashes:
            ledger.add(
                category="memory",
                table="vectors",
                source_id=source_id,
                sha256=source_db.sha256,
                target_kind="memory_entry",
                target_id=hashes[("semantic", "global", digest)],
            )
            tally.add(False, "duplicate content")
            continue
        created = _iso(_number(row, "ts") if "ts" in columns else None) or now
        entry_id = f"mem_{uuid.uuid4().hex[:16]}"
        if db is not None and not ledger.dry_run:
            db.conn.execute(
                """
                INSERT INTO memory_entries (
                    id, tier, scope, content, content_hash, source, session_id, channel,
                    created_at, updated_at, expires_at, embedding_json
                ) VALUES (?, 'semantic', 'global', ?, ?, 'praxis', '', '', ?, ?, '', '')
                """,
                (entry_id, cleaned, digest, created, created),
            )
        hashes[("semantic", "global", digest)] = entry_id
        ledger.add(
            category="memory",
            table="vectors",
            source_id=source_id,
            sha256=source_db.sha256,
            target_kind="memory_entry",
            target_id=entry_id,
        )
        tally.add(True)


def _import_skills(
    root: Path,
    home: ProfileHome,
    ledger: _Ledger,
    tally: Tally,
    quarantined: frozenset[str],
    *,
    dry_run: bool,
) -> None:
    skills_root = root / "skills"
    if lstat_kind(skills_root) is StatKind.MISSING:
        return
    if lstat_kind(skills_root) is not StatKind.DIR:
        tally.add(False, "skills path is not a directory")
        return
    try:
        children = sorted(skills_root.iterdir(), key=lambda path: path.name)
    except OSError:
        tally.add(False, "skills directory could not be listed")
        return
    for child in children:
        source_id = child.name
        if ledger.has("skills", source_id):
            tally.add(False, "already imported")
            continue
        if lstat_kind(child) is not StatKind.DIR:
            tally.add(False, "skill path is not a directory")
            continue
        skill_file = child / "SKILL.md"
        if lstat_kind(skill_file) is not StatKind.FILE:
            tally.add(False, "SKILL.md is missing")
            continue
        try:
            text = read_regular_text(skill_file, limit=_MAX_SKILL_FILE)
            adapted = _describe_praxis_skill(text)
            skill = parse_skill(adapted, skill_file, "user")
            digest = file_sha256(skill_file)
        except (OSError, SourceError, ValueError):
            tally.add(False, "SKILL.md did not load")
            continue
        if skill.name in quarantined or child.name in quarantined:
            tally.add(False, "quarantined in praxis")
            continue
        dest = home.skills_dir / skill.name
        if lstat_kind(dest) is not StatKind.MISSING:
            tally.add(False, "skill name already exists")
            continue
        if not dry_run:
            try:
                _copy_skill_tree(child, dest)
                if adapted != text:
                    _replace_regular(dest / "SKILL.md", adapted.encode("utf-8"))
            except (OSError, SourceError, MigrateError):
                if lstat_kind(dest) is StatKind.DIR:
                    shutil.rmtree(dest)
                tally.add(False, "skill tree was not copied")
                continue
        ledger.add(
            category="skills",
            table="skills",
            source_id=source_id,
            sha256=digest,
            target_kind="skill",
            target_id=skill.name,
        )
        tally.add(True)


def _import_packs(
    root: Path,
    data: Path,
    ledger: _Ledger,
    tally: Tally,
    *,
    dry_run: bool,
) -> list[str]:
    packs_root = root / "packs"
    dials: list[str] = []
    if lstat_kind(packs_root) is StatKind.MISSING:
        return dials
    if lstat_kind(packs_root) is not StatKind.DIR:
        tally.add(False, "packs path is not a directory")
        return dials
    try:
        children = sorted(packs_root.iterdir(), key=lambda path: path.name)
    except OSError:
        tally.add(False, "packs directory could not be listed")
        return dials
    for child in children:
        if lstat_kind(child) is not StatKind.DIR:
            tally.add(False, "pack path is not a directory")
            continue
        manifest = child / "pack.json"
        if lstat_kind(manifest) is not StatKind.FILE:
            tally.add(False, "pack.json is missing")
            continue
        source_id = child.name
        if ledger.has("packs", source_id):
            tally.add(False, "already imported")
            continue
        try:
            digest = file_sha256(manifest)
            loaded = load_legacy_pack(child, source=str(child))
        except (SourceError, PackError):
            tally.add(False, "pack.json did not load")
            continue
        name = loaded.name
        if not _PACK_NAME.fullmatch(name):
            tally.add(False, "pack name was rejected")
            continue
        dest = vertical_packs_dir(data) / name
        if lstat_kind(dest) is not StatKind.MISSING:
            tally.add(False, "pack name already exists")
            continue
        if not dry_run:
            try:
                installed = install_pack(str(child), data)
            except PackError:
                tally.add(False, "pack.json did not load")
                continue
            loaded = installed.pack
            name = loaded.name
        if _regulated(loaded.name, loaded.vertical):
            for dial, _position in loaded.suggested_dials:
                if dial not in dials and dial in dial_ids():
                    dials.append(dial)
        ledger.add(
            category="packs",
            table="packs",
            source_id=source_id,
            sha256=digest,
            target_kind="pack",
            target_id=name,
        )
        tally.add(True)
    return dials


def _import_routines(
    source_db: PraxisDB,
    db: StateDB | None,
    ledger: _Ledger,
    tally: Tally,
    sha256: str,
    now: str,
) -> bool:
    """Import routines paused. Returns true when a delivery target was dropped."""
    if "cron_jobs" not in source_db.table_names():
        return False
    columns = source_db.columns("cron_jobs")
    id_expr = "job_id" if "job_id" in columns else "rowid"
    selected = [id_expr]
    dropped_delivery = False
    for name in ("name", "goal", "schedule", "deliver"):
        if name in columns:
            selected.append(name)
    for row in source_db.stream("cron_jobs", selected):
        source_id = row[id_expr]
        if ledger.has("cron_jobs", source_id):
            tally.add(False, "already imported")
            continue
        prompt = _text(row, "goal") if "goal" in columns else ""
        if not prompt:
            prompt = _text(row, "name") if "name" in columns else ""
        schedule = _text(row, "schedule") if "schedule" in columns else ""
        if not prompt or not schedule:
            tally.add(False, "routine has no prompt or schedule")
            continue
        kind, expr = _schedule(schedule)
        if kind is None:
            tally.add(False, "unrecognized schedule")
            continue
        deliver = _text(row, "deliver") if "deliver" in columns else ""
        if deliver and deliver not in {"local", "none"}:
            dropped_delivery = True
        routine_id = f"rt_{uuid.uuid4().hex[:16]}"
        raw_name = _text(row, "name") if "name" in columns else ""
        label = raw_name or "imported routine"
        if len(label) > 80:
            label = label[:80]
        if db is not None and not ledger.dry_run:
            db.conn.execute(
                """
                INSERT INTO routines (
                    id, name, prompt, trigger_kind, trigger_expr, timezone, missed_policy,
                    min_interval_seconds, max_iterations, max_usd, skill, deliver, paused,
                    scope, created_at, updated_at, next_fire_at, last_fire_at, watch_token
                ) VALUES (?, ?, ?, ?, ?, 'UTC', 'skip', 60, 20, NULL, '', 'none', 1,
                          'global', ?, ?, '', '', '')
                """,
                (routine_id, label, prompt, kind, expr, now, now),
            )
        ledger.add(
            category="routines",
            table="cron_jobs",
            source_id=source_id,
            sha256=sha256,
            target_kind="routine",
            target_id=routine_id,
        )
        tally.add(True)
    return dropped_delivery


def _import_history(
    source_db: PraxisDB,
    db: StateDB | None,
    ledger: _Ledger,
    tally: Tally,
    data: Path,
    run_id: str,
    sha256: str,
    now: str,
    *,
    dry_run: bool,
) -> str:
    if "channel_threads" not in source_db.table_names():
        tally.add(False, "no conversation table")
        return ""
    columns = source_db.columns("channel_threads")
    if "messages_json" not in columns:
        tally.add(False, "channel_threads has no messages")
        return ""
    id_expr = "thread_key" if "thread_key" in columns else "rowid"
    selected = [id_expr, "messages_json"]
    for name in ("channel", "chat_id"):
        if name in columns:
            selected.append(name)
    lines: list[str] = []
    store = SessionStore(db) if db is not None and not dry_run else None
    for row in source_db.stream("channel_threads", selected):
        source_id = row[id_expr]
        if ledger.has("channel_threads", source_id):
            tally.add(False, "already imported")
            continue
        try:
            payload = json.loads(row["messages_json"] or "[]")
        except (TypeError, json.JSONDecodeError):
            tally.add(False, "messages were not a list")
            continue
        if not isinstance(payload, list):
            tally.add(False, "messages were not a list")
            continue
        messages = [(role, _display_history(content)) for role, content in _chat_messages(payload)]
        messages = [(role, content) for role, content in messages if content.strip()]
        visible_id = _display_history(str(source_id))
        for role, content in messages:
            lines.append(
                json.dumps(
                    {
                        "source_table": "channel_threads",
                        "source_id": visible_id,
                        "role": role,
                        "content": content,
                    },
                    ensure_ascii=True,
                )
            )
        if not messages:
            tally.add(False, "no chat messages")
            continue
        session_id = ""
        if store is not None:
            session_id = store.create(model="imported", preamble="")
            for role, content in messages:
                store.append(session_id, ChatMessage(role=role, content=content))
            store.note_title(session_id, visible_id[:80])
        else:
            session_id = f"dry-{source_id}"
        ledger.add(
            category="history",
            table="channel_threads",
            source_id=source_id,
            sha256=sha256,
            target_kind="session",
            target_id=session_id,
        )
        tally.add(True)
    if not lines:
        return ""
    if dry_run:
        return ""
    path = data / "migrations" / "praxis" / run_id / "history.jsonl"
    _write_private(path, ("\n".join(lines) + "\n").encode("utf-8"), mode=0o400)
    return str(path)


def _import_compliance(source_db: PraxisDB, tally: Tally) -> None:
    if "compliance" not in source_db.table_names():
        return
    columns = source_db.columns("compliance")
    if "mode" not in columns:
        tally.add(False, "compliance mode was not copied")
        return
    for row in source_db.stream("compliance", ["mode"]):
        tally.add(False, "compliance mode was not copied")
        del row


def _import_settings(
    root: Path,
    ledger: _Ledger,
    tally: Tally,
    *,
    config_dir: Path | None,
    include_secrets: bool,
    dry_run: bool,
) -> tuple[list[str], list[str]]:
    providers: list[str] = []
    auth_names: list[str] = []
    config_path = root / "praxis.json"
    document: dict[str, object] = {}
    config_sha = ""
    if lstat_kind(config_path) is StatKind.FILE:
        try:
            config_sha = file_sha256(config_path)
            loaded = json.loads(read_regular_text(config_path, limit=1_000_000))
        except (OSError, SourceError, json.JSONDecodeError):
            tally.add(False, "praxis.json could not be read")
            loaded = None
        if isinstance(loaded, dict):
            document = loaded
            providers = _provider_names(document.get("providers"))
            model = _suggested_model(document)
            if model:
                tally.add(False, "model was not selected; run praxis-prime setup")
            else:
                tally.add(False, "no safe model setting")
        elif loaded is not None:
            tally.add(False, "praxis.json could not be read")
    auth_path = root / "auth-profiles.json"
    auth: dict[str, object] = {}
    if lstat_kind(auth_path) is StatKind.FILE:
        try:
            loaded_auth = json.loads(read_regular_text(auth_path, limit=1_000_000))
        except (OSError, SourceError, json.JSONDecodeError):
            tally.add(False, "auth profiles could not be read")
            loaded_auth = None
        if isinstance(loaded_auth, dict):
            auth = loaded_auth
            auth_names = _provider_names(auth)
    if not include_secrets:
        if providers or auth_names:
            tally.add(False, "secrets were not copied")
        return providers, auth_names
    if config_dir is None or dry_run:
        tally.add(False, "secrets were not copied")
        return providers, auth_names
    from praxis_prime.channels.secrets import write_secret

    provider_table = document.get("providers")
    if not isinstance(provider_table, dict):
        provider_table = {}
    for name in providers:
        if ledger.has("settings", f"secret:{name}"):
            tally.add(False, "already imported")
            continue
        key_name = KEY_NAMES.get(name, "")
        if not key_name:
            tally.add(False, "no secrets.env name for this provider")
            continue
        secret = _stored_secret(provider_table.get(name), auth.get(name))
        if secret is None:
            tally.add(False, "secret is an environment reference or missing")
            continue
        try:
            write_secret(Path(config_dir) / "secrets.env", key_name, secret)
        except ValueError:
            tally.add(False, "secret value was rejected")
            continue
        ledger.add(
            category="settings",
            table="settings",
            source_id=f"secret:{name}",
            sha256=config_sha,
            target_kind="secret",
            target_id=key_name,
        )
        tally.add(True)
    return providers, auth_names


def _unknown_tables(source_db: PraxisDB) -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    for name in source_db.table_names():
        if name in _KNOWN_TABLES:
            continue
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            found.append({"name": "unnamed", "rows": None, "reason": "table name was not queried"})
            continue
        try:
            count = source_db.count(name)
        except sqlite3.Error:
            found.append({"name": name, "rows": None, "reason": "count failed"})
            continue
        found.append({"name": name, "rows": count})
    return found


def _quarantined(source_db: PraxisDB) -> frozenset[str]:
    if "skill_metadata" not in source_db.table_names():
        return frozenset()
    columns = source_db.columns("skill_metadata")
    if "skill_name" not in columns or "quarantined" not in columns:
        return frozenset()
    names: set[str] = set()
    for row in source_db.stream("skill_metadata", ["skill_name", "quarantined"]):
        if row["quarantined"]:
            names.add(str(row["skill_name"]))
    return frozenset(names)


def _apply_monitor(
    config: Path,
    db: StateDB | None,
    audit: AuditLog | None,
    dials: list[str],
) -> None:
    """Move listed dials from off to monitor and audit that move.

    Enforce stays put. A missing ``dial_positions`` row is seeded with the
    positions from before this move, so ``sync_dial_positions`` records
    ``dial_change`` for the off-to-monitor step. ``config.toml`` is backed
    up before it is rewritten.
    """
    from praxis_prime.compliance.positions import sync_dial_positions
    from praxis_prime.config import write_default_config
    from praxis_prime.onboarding.configio import backup_config, load_document, write_document

    root = Path(config)
    write_default_config(root, force=False)
    path = root / "config.toml"
    previous = path.read_text(encoding="utf-8") if path.is_file() else ""
    document = load_document(path)
    table = document.get("dials")
    if not isinstance(table, dict):
        table = {}
    moved: list[str] = []
    for dial in dials:
        current = table.get(dial, "off")
        if current == "off":
            table[dial] = "monitor"
            moved.append(dial)
    if moved:
        document["dials"] = table
        backup_config(path)
        write_document(path, document, previous=previous)
    if db is None or audit is None:
        return
    desired = default_positions()
    row = db.conn.execute("SELECT positions_json FROM dial_positions WHERE id = 1").fetchone()
    if row is not None:
        stored = json.loads(row["positions_json"])
        if isinstance(stored, dict):
            for dial, position in stored.items():
                if dial in desired and position in {"off", "monitor", "enforce"}:
                    desired[str(dial)] = str(position)
    for dial, position in table.items():
        if dial not in desired or position not in {"off", "monitor", "enforce"}:
            continue
        if desired[dial] == "enforce":
            continue
        desired[str(dial)] = str(position)
    if row is None and moved:
        baseline = dict(desired)
        for dial in moved:
            if desired.get(dial) == "monitor":
                baseline[dial] = "off"
        sync_dial_positions(db, audit, baseline)
    sync_dial_positions(db, audit, desired)


def _write_report(data: Path, report: MigrationReport) -> tuple[Path, Path]:
    directory = data / "migrations" / "praxis" / report.run_id
    body = json.dumps(_scrub(report.public()), indent=2, sort_keys=True) + "\n"
    summary = _summary(report)
    json_path = directory / "report.json"
    text_path = directory / "summary.txt"
    _write_private(json_path, body.encode("utf-8"), mode=0o600)
    _write_private(text_path, summary.encode("utf-8"), mode=0o600)
    return json_path, text_path


def render_summary(report: MigrationReport) -> str:
    """Human summary. Source-derived text is sanitized and secrets are redacted."""
    return _summary(report)


def report_json(report: MigrationReport) -> str:
    """JSON plan. Source-derived strings are sanitized and secrets are redacted."""
    return json.dumps(_scrub(report.public()), indent=2, sort_keys=True) + "\n"


def _summary(report: MigrationReport) -> str:
    lines = [
        "Praxis import (dry-run)" if report.dry_run else "Praxis import",
        f"run: {report.run_id}",
        f"profile: {report.profile}",
        f"source db sha256: {report.db_sha256 or '-'}",
    ]
    for name in CATEGORIES:
        tally = report.categories[name]
        lines.append(f"{name}: found {tally.found}, import {tally.imported}, skip {tally.skipped}")
        for reason, count in sorted(tally.reasons.items()):
            lines.append(f"  {reason}: {count}")
    if report.providers:
        lines.append("providers: " + ", ".join(report.providers))
    if report.auth_profiles:
        lines.append("auth profiles: " + ", ".join(report.auth_profiles))
    if report.dials_to_monitor:
        lines.append("dials set to monitor: " + ", ".join(report.dials_to_monitor))
    if report.unknown_tables:
        lines.append("unknown tables:")
        for row in report.unknown_tables:
            lines.append(f"  {row.get('name')}: {row.get('rows')}")
    if report.history_archive:
        lines.append(
            "conversation archive: history.jsonl under the migration directory (mode 0400)"
        )
    for note in report.notes:
        lines.append(note)
    text = "\n".join(public_text(line) for line in lines) + "\n"
    return text


def public_text(value: object) -> str:
    """Printable form of a migration string. Controls and secrets are removed."""
    return redact_text(sanitize(value), mode="secrets", dials=default_positions())


def _scrub(value: object) -> object:
    if isinstance(value, str):
        return public_text(value)
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _scrub(item) for key, item in value.items()}
    return value


def _refuse_if_profile_busy(data: Path, profile: str) -> None:
    home = ProfileHome(data, profile)
    if lstat_kind(home.db_path) is StatKind.MISSING and not home.exists():
        return
    try:
        probe = StateDB(home.db_path, exclusive=True)
    except DatabaseBusy as exc:
        raise MigrationBusy(str(exc)) from exc
    probe.close()


def _prime_tier(tier: str, kind: str) -> str | None:
    """Map a Praxis memory tier onto profile, episodic, or semantic."""
    name = tier.strip().lower()
    kind_name = (kind or "note").strip().lower()
    if name == "working":
        return None
    if name == "episodic":
        return "episodic"
    if name == "durable" and kind_name in _PROFILE_KINDS:
        return "profile"
    if name == "durable":
        return "semantic"
    if name in {"profile", "semantic"}:
        return name
    if kind_name in _PROFILE_KINDS:
        return "profile"
    if name:
        return "semantic"
    return "semantic"


def _content_hash(tier: str, scope: str, content: str) -> str:
    normalized = " ".join(content.split()).casefold()
    return hashlib.sha256(f"{tier}\n{scope}\n{normalized}".encode()).hexdigest()


def _existing_hashes(db: StateDB | None) -> dict[tuple[str, str, str], str]:
    found: dict[tuple[str, str, str], str] = {}
    if db is None:
        return found
    rows = db.conn.execute("SELECT id, tier, scope, content_hash FROM memory_entries").fetchall()
    for row in rows:
        found[(str(row["tier"]), str(row["scope"]), str(row["content_hash"]))] = str(row["id"])
    return found


def _memory_expiry(tier: str, row: sqlite3.Row, columns: set[str], created: str) -> str:
    """Earlier of a future Praxis expiry and this tier's retention window."""
    candidates: list[datetime] = []
    if "expires_at" in columns:
        stamp = _number(row, "expires_at")
        if stamp is not None and stamp > 0:
            moment = _moment(stamp)
            if moment is not None:
                candidates.append(moment)
    days = retention_days(tier, default_positions(), episodic_ttl_days=90)
    if days is not None:
        try:
            start = datetime.fromisoformat(created)
        except ValueError:
            start = datetime.now(UTC)
        if start.tzinfo is None:
            start = start.replace(tzinfo=UTC)
        candidates.append(start + timedelta(days=days))
    if not candidates:
        return ""
    return dump_time(min(candidates))


def _scope(workspace: object) -> str:
    if not isinstance(workspace, str):
        return "global"
    text = workspace.strip().lower()
    if _SAFE_SCOPE.fullmatch(text):
        return f"channel:praxis-{text}"
    return "global"


def _expired(value: object, now: float) -> bool:
    try:
        stamp = float(value)
    except (TypeError, ValueError):
        return False
    return stamp > 0 and stamp < now


def _schedule(expression: str) -> tuple[str, str] | tuple[None, None]:
    text = " ".join(expression.split())
    try:
        if text.lower().startswith("@every") or (
            len(text) >= 2 and text[-1] in {"s", "m", "h", "d"} and text[:-1].isdigit()
        ):
            parse_every(text if text.lower().startswith("@every") else f"@every {text}")
            expr = text if text.lower().startswith("@every") else f"@every {text}"
            return "interval", expr
        parse_cron(text)
    except ScheduleError:
        return None, None
    return "cron", text


def _display_history(text: str) -> str:
    """Redact secrets the way memory does, then make controls visible."""
    cleaned = redact_text(text, mode="secrets", dials=default_positions())
    return sanitize(cleaned)


def _chat_messages(payload: list[object]) -> list[tuple[str, str]]:
    messages: list[tuple[str, str]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        role = item.get("role")
        content = item.get("content")
        if role not in _CHAT_ROLES or not isinstance(content, str) or not content.strip():
            continue
        if len(content) > _MAX_TEXT:
            continue
        messages.append((str(role), content))
    return messages


def _regulated(name: str, vertical: str) -> bool:
    folded = {name.strip().lower().replace("-", "_"), vertical.strip().lower()}
    if folded & _REGULATED or folded & _REGULATED_VERTICALS:
        return True
    compact = vertical.strip().lower().replace(" ", "_").replace("-", "_")
    return compact in _REGULATED or compact in _REGULATED_VERTICALS


def _provider_names(value: object) -> list[str]:
    if not isinstance(value, dict):
        return []
    names: list[str] = []
    for key in value:
        if isinstance(key, str) and re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,80}", key):
            names.append(key)
    return sorted(names)


def _suggested_model(document: Mapping[str, object]) -> str:
    agents = document.get("agents")
    if not isinstance(agents, dict):
        return ""
    defaults = agents.get("defaults")
    if not isinstance(defaults, dict):
        return ""
    model = defaults.get("model")
    if isinstance(model, str) and re.fullmatch(r"[A-Za-z0-9_.:/+-]{1,120}", model):
        return model
    return ""


def _stored_secret(entry: object, auth_entry: object) -> str | None:
    """Return a file-stored key. Environment references are not read."""
    if isinstance(entry, dict):
        ref = entry.get("keyRef")
        if isinstance(ref, dict) and ref.get("source") == "env":
            return None
    if isinstance(auth_entry, dict):
        secret = auth_entry.get("apiKey")
        if isinstance(secret, str) and secret.strip():
            return secret.strip()
    return None


def _copy_skill_tree(source: Path, dest: Path) -> None:
    files: list[Path] = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(source, followlinks=False):
        dirnames[:] = [
            name for name in dirnames if name not in _SKIP_DIRS and not name.startswith(".")
        ]
        for name in filenames:
            if name.startswith("."):
                continue
            path = Path(dirpath) / name
            if lstat_kind(path) is not StatKind.FILE:
                continue
            size = path.lstat().st_size
            if size > _MAX_SKILL_FILE:
                raise MigrateError("skill file is too large")
            total += size
            if total > _MAX_SKILL_TREE:
                raise MigrateError("skill tree is too large")
            files.append(path)
    if lstat_kind(dest) is not StatKind.MISSING:
        raise MigrateError("skill destination exists")
    dest.mkdir(parents=True, exist_ok=False)
    os.chmod(dest, 0o755)
    for path in files:
        relative = path.relative_to(source)
        if any(part in {"", ".", ".."} for part in relative.parts):
            continue
        target = dest.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(target.parent, 0o755)
        _copy_regular(path, target)


def _copy_regular(source: Path, dest: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(source, flags)
    try:
        info = os.fstat(descriptor)
        if not stat_is_reg(info.st_mode):
            raise SourceError(f"refusing non-file {source.name}")
        blob = os.read(descriptor, _MAX_SKILL_FILE + 1)
    finally:
        os.close(descriptor)
    if len(blob) > _MAX_SKILL_FILE:
        raise MigrateError("skill file is too large")
    out_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        out_flags |= os.O_NOFOLLOW
    out = os.open(dest, out_flags, 0o644)
    try:
        os.write(out, blob)
        os.fchmod(out, 0o644)
    except Exception:
        os.close(out)
        dest.unlink(missing_ok=True)
        raise
    os.close(out)


def stat_is_reg(mode: int) -> bool:
    return stat.S_ISREG(mode)


def _describe_praxis_skill(text: str) -> str:
    """Fill ``description`` from Praxis ``trigger`` so the Prime loader can read it.

    The source file is not changed. A skill that already has a description is
    returned as it was read.
    """
    if not text.startswith("---"):
        return text
    lines = text.splitlines(keepends=True)
    end = None
    for index, line in enumerate(lines):
        if index and line.strip() == "---":
            end = index
            break
    if end is None:
        return text
    fields: dict[str, str] = {}
    for line in lines[1:end]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        fields[key.strip()] = value.strip().strip("\"'")
    if fields.get("description", "").strip():
        return text
    trigger = " ".join(fields.get("trigger", "").split())
    if not trigger or len(trigger) > 2000:
        return text
    lines.insert(end, f"description: {trigger}\n")
    return "".join(lines)


def _replace_regular(path: Path, blob: bytes) -> None:
    flags = os.O_WRONLY | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise SourceError(f"refusing non-file {path.name}")
        os.write(descriptor, blob)
        os.fchmod(descriptor, 0o644)
    except Exception:
        os.close(descriptor)
        raise
    os.close(descriptor)


def _write_private(path: Path, blob: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        os.write(descriptor, blob)
        os.fchmod(descriptor, mode)
    except Exception:
        os.close(descriptor)
        path.unlink(missing_ok=True)
        raise
    os.close(descriptor)


def _text(row: sqlite3.Row, name: str) -> str:
    if name not in row.keys():
        return ""
    value = row[name]
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return str(value)


def _number(row: sqlite3.Row, name: str) -> float | None:
    if name not in row.keys():
        return None
    value = row[name]
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _moment(stamp: float) -> datetime | None:
    if stamp <= 0 or stamp > 4_000_000_000:
        return None
    return datetime.fromtimestamp(stamp, UTC)


def _iso(stamp: float | None) -> str:
    if stamp is None:
        return ""
    moment = _moment(stamp)
    if moment is None:
        return ""
    return moment.isoformat()


def _same_tree(left: Path, right: Path) -> bool:
    try:
        a = left.resolve()
        b = right.resolve()
    except OSError:
        return False
    return a == b or a in b.parents or b in a.parents


# Imported so a caller can prove a run did not touch the source tree.
__all__ = [
    "CATEGORIES",
    "MigrateError",
    "MigrationReport",
    "migrate_from_praxis",
    "public_text",
    "render_summary",
    "report_json",
    "source_fingerprint",
]
