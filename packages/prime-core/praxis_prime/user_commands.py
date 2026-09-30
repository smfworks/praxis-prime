"""CLI for routines, memory, and skills.

These commands talk to the local SQLite file. ``routines run`` executes in
this process. The daemon runs the same rows on its own schedule.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path

from praxis_prime.approvals.gate import ApprovalDecision
from praxis_prime.paths import config_dir
from praxis_prime.profiles.home import resolve_runtime_layout
from praxis_prime.scheduler.cron import ScheduleError, parse_every
from praxis_prime.scheduler.store import RoutineStore
from praxis_prime.scheduler.watch import file_token
from praxis_prime.state import StateDB


def add_user_commands(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    store_args = argparse.ArgumentParser(add_help=False)
    store_args.add_argument("--data-dir", help="Directory that contains prime.db.")
    store_args.add_argument("--config-dir", help="Config directory. Used for skills and timezone.")
    store_args.add_argument(
        "--project",
        help="Project root for .prime/skills. Defaults to the cwd.",
    )

    routines = commands.add_parser("routines", help="Saved prompts that praxis-primed runs.")
    routine_commands = routines.add_subparsers(dest="routines_command")
    routine_commands.add_parser("list", parents=[store_args], help="List saved routines.")
    add = routine_commands.add_parser("add", parents=[store_args], help="Save a routine.")
    _routine_fields(add, required=True)
    edit = routine_commands.add_parser("edit", parents=[store_args], help="Change a routine.")
    edit.add_argument("routine_id")
    _routine_fields(edit, required=False)
    for name, help_text in (
        ("pause", "Stop a routine from firing."),
        ("resume", "Let a routine fire again."),
        ("delete", "Delete a routine. Run history is kept."),
        ("run", "Run a routine once in this process."),
    ):
        command = routine_commands.add_parser(name, parents=[store_args], help=help_text)
        command.add_argument("routine_id")
    history = routine_commands.add_parser(
        "history", parents=[store_args], help="Show routine run outcomes."
    )
    history.add_argument("routine_id", nargs="?")

    memory = commands.add_parser("memory", help="List, search, forget, or export memory.")
    memory_commands = memory.add_subparsers(dest="memory_command")
    listing = memory_commands.add_parser("list", parents=[store_args], help="List stored rows.")
    listing.add_argument("--tier", choices=["profile", "episodic", "semantic"])
    listing.add_argument("--scope")
    search = memory_commands.add_parser("search", parents=[store_args], help="Search memory.")
    search.add_argument("query")
    forget = memory_commands.add_parser("forget", parents=[store_args], help="Delete memory rows.")
    forget.add_argument("entry_id", nargs="?")
    forget.add_argument("--match")
    forget.add_argument("--before", help="Delete rows created before this ISO timestamp.")
    forget.add_argument("--scope")
    memory_commands.add_parser("export", parents=[store_args], help="Print memory as JSON.")

    skills = commands.add_parser("skills", help="List, show, create, install, or remove skills.")
    skill_commands = skills.add_subparsers(dest="skills_command")
    skill_commands.add_parser("list", parents=[store_args], help="List skills, project first.")
    show = skill_commands.add_parser("show", parents=[store_args], help="Print one skill body.")
    show.add_argument("name")
    new = skill_commands.add_parser("new", parents=[store_args], help="Write a SKILL.md template.")
    new.add_argument("name")
    install = skill_commands.add_parser(
        "install",
        parents=[store_args],
        help="Install a local folder or a git URL. Git clones need approval.",
    )
    install.add_argument("source")
    remove = skill_commands.add_parser(
        "remove", parents=[store_args], help="Remove a skill from the user directory."
    )
    remove.add_argument("name")


def dispatch_user_command(args: argparse.Namespace) -> int | None:
    if args.command == "routines":
        return _routines(args)
    if args.command == "memory":
        return _memory(args)
    if args.command == "skills":
        return _skills(args)
    return None


def _routine_fields(parser: argparse.ArgumentParser, *, required: bool) -> None:
    parser.add_argument("--name", required=required)
    parser.add_argument("--prompt", required=required)
    parser.add_argument("--cron", help="5-field cron, or @every 15m.")
    parser.add_argument("--every", help="Interval such as 15m. Minimum 1 minute.")
    parser.add_argument("--interval", help="Same as --every.")
    parser.add_argument("--watch", help="File or directory to watch.")
    parser.add_argument(
        "--webhook",
        action="store_true",
        help="Fire only from POST /v1/routines/<id>/fire.",
    )
    parser.add_argument("--missed", choices=["skip", "once"])
    parser.add_argument("--skill", help="Skill name this routine should load with use_skill.")
    parser.add_argument("--deliver", choices=["none", "telegram"])
    parser.add_argument("--max-iterations", type=int)
    parser.add_argument("--max-usd", type=float)
    parser.add_argument("--scope", default=None)
    parser.add_argument("--timezone")
    parser.add_argument("--min-interval", help="Minimum gap between runs. Default 1m.")


def _routines(args: argparse.Namespace) -> int:
    command = args.routines_command
    if command not in {"list", "add", "edit", "pause", "resume", "delete", "run", "history"}:
        print(
            "usage: praxis-prime routines {list|add|edit|pause|resume|delete|run|history}",
            file=sys.stderr,
        )
        return 2
    db = _db(args)
    try:
        store = RoutineStore(db)
        if command == "list":
            rows = store.list_routines()
            if not rows:
                print("no routines")
                return 0
            for routine in rows:
                state = "paused" if routine.paused else "active"
                print(
                    f"{routine.id}  {routine.name}  {routine.trigger_kind} {routine.trigger_expr}  "
                    f"next {routine.next_fire_at or '-'}  {state}"
                )
            return 0
        if command == "history":
            runs = store.history(args.routine_id or "")
            if not runs:
                print("no runs")
                return 0
            for run in runs:
                print(f"{run.id}  {run.started_at}  {run.outcome}  {run.trigger}  {run.summary}")
            return 0
        if command == "add":
            fields = _routine_values(args, creating=True)
            routine = store.add(**fields)
            print(routine.id)
            if routine.trigger_kind == "webhook":
                print(f"POST /v1/routines/{routine.id}/fire")
            return 0
        if command == "edit":
            fields = _routine_values(args, creating=False)
            routine = store.update(args.routine_id, **fields)
            print(routine.id)
            return 0
        if command == "pause":
            store.set_paused(args.routine_id, True)
            print(f"paused {args.routine_id}")
            return 0
        if command == "resume":
            store.set_paused(args.routine_id, False)
            print(f"resumed {args.routine_id}")
            return 0
        if command == "delete":
            store.delete(args.routine_id)
            print(f"deleted {args.routine_id}")
            return 0
        return _run_routine(args, store)
    except (ScheduleError, LookupError, ValueError, OSError) as exc:
        print(f"praxis-prime routines: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()


def _run_routine(args: argparse.Namespace, store: RoutineStore) -> int:
    from praxis_prime.runtime import build_runtime
    from praxis_prime.scheduler.runner import execute_routine

    routine = store.get(args.routine_id)
    config_path = _config_path(args)
    data_path = _data_path(args)
    runtime = build_runtime(
        env=os.environ,
        config_path=config_path,
        data_path=data_path,
        cwd=_project(args),
        approver=lambda _request: ApprovalDecision.DENY,
    )
    try:
        run = execute_routine(runtime, routine, trigger="manual", store=store)
        store.mark_fired(routine, store.clock())
    finally:
        runtime.close()
    print(f"{run.outcome} {run.id}")
    if run.summary:
        print(run.summary)
    return 0 if run.outcome == "ok" else 1


def _routine_values(args: argparse.Namespace, *, creating: bool) -> dict[str, object]:
    fields: dict[str, object] = {}
    if creating or _chosen_trigger(args):
        kind, expr, token = _trigger(args)
        fields["trigger_kind"] = kind
        fields["trigger_expr"] = expr
        if token:
            fields["watch_token"] = token
    if args.name:
        fields["name"] = args.name
    if args.prompt:
        fields["prompt"] = args.prompt
    if creating and "prompt" not in fields:
        raise ScheduleError("a routine needs --prompt")
    if args.missed:
        fields["missed_policy"] = args.missed
    elif creating:
        fields["missed_policy"] = "skip"
    if args.skill is not None:
        fields["skill"] = args.skill
    if args.deliver:
        fields["deliver"] = args.deliver
    elif creating:
        fields["deliver"] = "none"
    if args.max_iterations is not None:
        if args.max_iterations < 1:
            raise ScheduleError("--max-iterations must be at least 1")
        fields["max_iterations"] = args.max_iterations
    elif creating:
        fields["max_iterations"] = 20
    if args.max_usd is not None:
        fields["max_usd"] = args.max_usd
    if args.scope:
        fields["scope"] = args.scope
    elif creating:
        fields["scope"] = "global"
    if args.min_interval:
        fields["min_interval_seconds"] = parse_every(args.min_interval)
    elif creating:
        fields["min_interval_seconds"] = 60
    fields["timezone_name"] = args.timezone or _timezone(args)
    if creating and "name" not in fields:
        raise ScheduleError("a routine needs --name")
    return fields


def _chosen_trigger(args: argparse.Namespace) -> bool:
    return bool(args.cron or args.every or args.interval or args.watch or args.webhook)


def _trigger(args: argparse.Namespace) -> tuple[str, str, str]:
    chosen: list[tuple[str, str]] = []
    if args.cron:
        expr = args.cron.strip()
        if expr.lower().startswith("@every"):
            chosen.append(("interval", expr))
        else:
            chosen.append(("cron", expr))
    if args.every:
        chosen.append(("interval", args.every.strip()))
    if args.interval:
        chosen.append(("interval", args.interval.strip()))
    if args.watch:
        path = Path(args.watch).expanduser().resolve()
        chosen.append(("file", str(path)))
    if args.webhook:
        chosen.append(("webhook", "webhook"))
    if len(chosen) != 1:
        raise ScheduleError("choose one trigger: --cron, --every, --watch, or --webhook")
    kind, expr = chosen[0]
    token = file_token(Path(expr)) if kind == "file" else ""
    return kind, expr, token


def _memory(args: argparse.Namespace) -> int:
    from praxis_prime.memory.tiers import MemoryStore
    from praxis_prime.runtime import build_runtime

    command = args.memory_command
    if command not in {"list", "search", "forget", "export"}:
        print("usage: praxis-prime memory {list|search|forget|export}", file=sys.stderr)
        return 2
    runtime = build_runtime(
        env=os.environ,
        config_path=_config_path(args),
        data_path=_data_path(args),
        cwd=_project(args),
    )
    try:
        store: MemoryStore = runtime.memory
        if command == "list":
            rows = store.list_entries(tier=args.tier or "", scope=args.scope or "")
            if not rows:
                print("no memory")
                return 0
            for entry in rows:
                print(f"{entry.id}  {entry.tier}  {entry.scope}  {entry.content}")
            return 0
        if command == "search":
            hits = store.search(args.query, scopes=store.scopes())
            if not hits:
                print("no matches")
                return 0
            for hit in hits:
                print(f"{hit.entry.id}  {hit.entry.tier}  {hit.score:.3f}  {hit.entry.content}")
            return 0
        if command == "forget":
            removed = store.forget(
                entry_id=args.entry_id or "",
                match=args.match or "",
                before=args.before or "",
                scope=args.scope or "",
            )
            print(f"forgot {removed}")
            return 0
        json.dump(store.export_entries(), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    except (LookupError, ValueError, OSError) as exc:
        print(f"praxis-prime memory: {exc}", file=sys.stderr)
        return 1
    finally:
        runtime.close()


def _skills(args: argparse.Namespace) -> int:
    from praxis_prime.skills.catalog import SkillCatalog, bundled_skills_dir
    from praxis_prime.skills.format import parse_skill
    from praxis_prime.skills.install import (
        InstallError,
        install_skill,
        remove_skill,
        write_new_skill,
    )

    command = args.skills_command
    if command not in {"list", "show", "new", "install", "remove"}:
        print("usage: praxis-prime skills {list|show|new|install|remove}", file=sys.stderr)
        return 2
    project = _project(args) / ".prime" / "skills"
    user = _user_skills(args)
    catalog = SkillCatalog(
        project=project,
        user=user,
        shared=_shared_skills(),
        bundled=bundled_skills_dir(),
    )
    try:
        if command == "list":
            skills = catalog.ordered()
            if not skills:
                print("no skills")
                return 0
            for skill in skills:
                print(f"{skill.name}  {skill.source}  {skill.description}")
            return 0
        if command == "show":
            skill = catalog.get(args.name)
            if skill is None:
                print(f"praxis-prime skills: unknown skill {args.name}", file=sys.stderr)
                return 1
            print(f"name: {skill.name}")
            print(f"source: {skill.source}")
            print(f"description: {skill.description}")
            print()
            sys.stdout.write(skill.body)
            if not skill.body.endswith("\n"):
                print()
            return 0
        if command == "new":
            preview = f"---\nname: {args.name}\ndescription: placeholder\n---\n\n"
            parse_skill(preview, Path("."), "user")
            path = write_new_skill(args.name, user)
            print(path)
            return 0
        if command == "install":
            path = install_skill(args.source, user, approve=_approve_git)
            print(path)
            return 0
        remove_skill(args.name, user)
        print(f"removed {args.name}")
        return 0
    except (InstallError, PermissionError, ValueError, OSError) as exc:
        print(f"praxis-prime skills: {exc}", file=sys.stderr)
        return 1


def _approve_git(source: str) -> bool:
    if not sys.stdin.isatty():
        print("git skill install needs approval; no terminal, denied", file=sys.stderr)
        return False
    answer = input(f"Clone skill from {source}? [y/N] ")
    return answer.strip().lower() in {"y", "yes"}


def _db(args: argparse.Namespace) -> StateDB:
    return StateDB(_data_path(args))


def _data_path(args: argparse.Namespace) -> Path:
    """Database for this command, including one that already moved."""
    raw = getattr(args, "data_dir", None)
    data_file = Path(raw) / "prime.db" if raw else None
    return resolve_runtime_layout(None, data_file=data_file, profile=None).db_path


def _config_path(args: argparse.Namespace) -> Path:
    if args.config_dir:
        return Path(args.config_dir) / "config.toml"
    return config_dir() / "config.toml"


def _project(args: argparse.Namespace) -> Path:
    if getattr(args, "project", None):
        return Path(args.project)
    return Path.cwd()


def _user_skills(args: argparse.Namespace) -> Path:
    if args.config_dir:
        return Path(args.config_dir) / "skills"
    return config_dir() / "skills"


def _shared_skills() -> Path | None:
    home = Path.home()
    path = home / ".agents" / "skills"
    if path.is_dir():
        return path
    return None


def _timezone(args: argparse.Namespace) -> str:
    from praxis_prime.router.settings import load_settings

    env: Mapping[str, str] = {}
    if args.config_dir:
        settings = load_settings(env, config_path=Path(args.config_dir) / "config.toml")
        return settings.timezone
    return "America/New_York"
