"""Read a legacy praxis-agent pack without executing it.

The old format is ``pack.json`` plus ``knowledge.md`` and optional Python
modules. This adapter maps that manifest onto Praxis Prime skills, knowledge
records, and compliance rules. It does not import pack Python unless the
entry point is both declared in the pack and listed in
``ALLOWLISTED_ENTRY_POINTS`` (empty by default).

TODO: ARCHITECTURE §17 and §32. Addendum A §7.3.
"""

from __future__ import annotations

import importlib
import json
import logging
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

from praxis_prime.packs.catalog import SUGGESTED_DIALS, SUGGESTED_POSITION, SUGGESTED_THEMES
from praxis_prime.packs.model import (
    PERSONA_BOUNDARY,
    LegacyPack,
    MappedRule,
    PackKnowledge,
    PackWarning,
    Provenance,
    ThemeHint,
    ToolMapping,
)
from praxis_prime.skills.format import Skill, parse_skill

logger = logging.getLogger(__name__)

# Declared entry points that may be imported. Empty on purpose: a pack must
# not run code, or choose a model, just by being loaded.
ALLOWLISTED_ENTRY_POINTS: frozenset[str] = frozenset()

# Legacy tool name -> Praxis Prime tool. Anything else is reported and kept
# unavailable. Names are not dropped.
_TOOL_MAP: dict[str, str] = {
    "read_file": "read_file",
    "list_dir": "list_dir",
    "fetch_url": "web_fetch",
    "search_web": "web_fetch",
    "query_knowledge": "recall",
    "save_private_note": "remember",
}

_RISKS = {
    "read": "READ",
    "draft": "DRAFT",
    "send": "SEND",
    "destructive": "DESTRUCTIVE",
    "spend": "SPEND",
    "share": "SHARE",
}

_PIN_KEYS = ("model", "provider", "llm", "base_url", "baseUrl", "endpoint")
_SECRET_KEYS = {"api_key", "apikey", "token", "secret", "password", "authorization"}
_JS_SUFFIXES = {".js", ".mjs", ".cjs", ".wasm"}
_DASHBOARD_SUFFIXES = {".css", ".html", ".htm"}
_SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".pytest_cache"}
_HEX = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$")
_SKILL_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_MODULE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_ATTR = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _pin_message(kind: str, value: str) -> str:
    return (
        f"Ignored pack {kind} pin {value}; a pack cannot select the LLM "
        "or send data to a provider"
    )


class PackError(ValueError):
    """The pack could not be read."""


def load_legacy_pack(
    root: Path,
    *,
    wanted_name: str = "",
    repo: str = "",
    commit: str = "",
    source: str = "",
) -> LegacyPack:
    """Load ``pack.json`` under ``root``. Does not import pack modules."""
    base = Path(root).resolve()
    if not base.is_dir():
        raise PackError(f"pack path is not a directory: {root}")
    manifest_path = _choose_manifest(base, wanted_name)
    raw = _read_manifest(manifest_path)
    warnings: list[PackWarning] = []
    pack_dir = manifest_path.parent
    # An explicit empty name stays empty so install can reject it. A missing
    # name falls back to the directory, which is not a path from the manifest.
    if "name" not in raw or raw.get("name") is None:
        name = pack_dir.name
    else:
        name = _text(raw.get("name"))
    version = _text(raw.get("version")) or "0"
    model_suggestion, provider_suggestion = _ignore_pins(raw, warnings)
    javascript, dashboard, modules = _scan_tree(base)
    _warn_assets(javascript, dashboard, modules, warnings)
    declared = _declared_entry_points(base)
    executed = _run_allowlisted(base, declared, warnings)
    skills = _skills(raw.get("skills"), name, pack_dir, warnings)
    tools = _tools(raw.get("tools"), warnings)
    rules, ttl, dual, autonomous = _rules(
        raw.get("riskPolicy"),
        raw.get("complianceMode"),
        warnings,
    )
    theme = _theme(raw.get("theme"), name, warnings)
    knowledge = _knowledge(pack_dir, raw.get("knowledge"), warnings)
    suggested = tuple((dial, SUGGESTED_POSITION) for dial in SUGGESTED_DIALS.get(name, ()))
    if _text(raw.get("complianceMode")):
        warnings.append(
            PackWarning(
                "compliance_mode_not_applied",
                (
                    f"Pack complianceMode {_text(raw.get('complianceMode'))!r} "
                    "was recorded and was not written to the dial config"
                ),
            )
        )
    provenance = Provenance(
        repo=repo or _git_remote(base) or str(base),
        version=version,
        commit=commit or _git_commit(base),
        license=_license(base, pack_dir),
        source=source or str(base),
    )
    try:
        relative_manifest = manifest_path.resolve().relative_to(base).as_posix()
    except ValueError:
        relative_manifest = manifest_path.name
    return LegacyPack(
        name=name,
        version=version,
        vertical=_text(raw.get("vertical")),
        description=_text(raw.get("description")),
        persona=_text(raw.get("systemPrompt")),
        knowledge=knowledge,
        skills=skills,
        tools=tools,
        rules=rules,
        theme=theme,
        compliance_mode=_text(raw.get("complianceMode")),
        suggested_dials=suggested,
        model_suggestion=model_suggestion,
        provider_suggestion=provider_suggestion,
        selected_model=None,
        selected_provider=None,
        warnings=tuple(warnings),
        provenance=provenance,
        ignored_javascript=javascript,
        ignored_dashboard=dashboard,
        python_modules=modules,
        declared_entry_points=declared,
        executed_entry_points=executed,
        approval_ttl_seconds=ttl,
        dual_approval_risks=dual,
        autonomous_risks=autonomous,
        manifest_path=relative_manifest,
    )


def find_manifests(root: Path) -> list[Path]:
    found: list[Path] = []
    base = Path(root)
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [
            name
            for name in dirnames
            if name not in _SKIP_DIRS and not name.startswith(".")
        ]
        if "pack.json" in filenames:
            found.append(Path(dirpath) / "pack.json")
    return sorted(found)


def skill_markdown(skill: Skill) -> str:
    """Render a mapped skill back to ``SKILL.md`` text."""
    lines = ["---", f"name: {skill.name}", f"description: {_one_line(skill.description)}"]
    for key in ("pack", "namespace"):
        value = skill.meta.get(key, "")
        if value:
            lines.append(f"{key}: {_one_line(value)}")
    lines.extend(["---", ""])
    body = skill.body.rstrip("\n")
    if body:
        lines.append(body)
    lines.append("")
    return "\n".join(lines)


def _choose_manifest(root: Path, wanted_name: str) -> Path:
    files = find_manifests(root)
    if not files:
        raise PackError(f"no pack.json under {root}")
    if wanted_name:
        matches: list[Path] = []
        for path in files:
            try:
                data = _read_manifest(path)
            except PackError:
                continue
            if _text(data.get("name")) == wanted_name or path.parent.name == wanted_name:
                matches.append(path)
        if len(matches) == 1:
            return matches[0]
        if not matches and len(files) == 1:
            return files[0]
        if len(matches) > 1:
            raise PackError(f"multiple pack.json files named {wanted_name}")
    if len(files) == 1:
        return files[0]
    listed = ", ".join(str(path) for path in files)
    raise PackError(f"multiple pack.json files: {listed}")


def _read_manifest(path: Path) -> dict[str, object]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PackError(f"could not read {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise PackError(f"{path} is not a JSON object")
    return loaded


def _ignore_pins(raw: dict[str, object], warnings: list[PackWarning]) -> tuple[str, str]:
    model = _public_value(raw.get("model")) if "model" in raw else ""
    provider = _public_value(raw.get("provider")) if "provider" in raw else ""
    if model:
        message = _pin_message("model", model)
        logger.warning("%s", message)
        warnings.append(PackWarning("model_ignored", message))
    if provider:
        message = _pin_message("provider", provider)
        logger.warning("%s", message)
        warnings.append(PackWarning("provider_ignored", message))
    for key in _PIN_KEYS:
        if key in {"model", "provider"} or key not in raw:
            continue
        value = _public_value(raw.get(key))
        if not value:
            continue
        message = _pin_message(key, value)
        logger.warning("%s", message)
        warnings.append(PackWarning("model_ignored", message))
    return model, provider


def _public_value(value: object) -> str:
    if isinstance(value, dict):
        cleaned: dict[str, object] = {}
        for key, item in value.items():
            if str(key).lower() in _SECRET_KEYS:
                cleaned[str(key)] = "[redacted]"
            else:
                cleaned[str(key)] = item
        return json.dumps(cleaned, sort_keys=True)[:200]
    if value is None:
        return ""
    return str(value).strip()[:200]


def _scan_tree(root: Path) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    javascript: list[str] = []
    dashboard: list[str] = []
    modules: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            name
            for name in dirnames
            if name not in _SKIP_DIRS and not name.startswith(".")
        ]
        current = Path(dirpath)
        for name in filenames:
            path = current / name
            try:
                relative = path.resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                continue
            suffix = path.suffix.lower()
            parts = path.parts
            if suffix in _JS_SUFFIXES:
                javascript.append(relative)
            elif suffix in _DASHBOARD_SUFFIXES and "web" in parts:
                dashboard.append(relative)
            elif suffix == ".py":
                modules.append(relative)
    return tuple(javascript), tuple(dashboard), tuple(modules)


def _warn_assets(
    javascript: tuple[str, ...],
    dashboard: tuple[str, ...],
    modules: tuple[str, ...],
    warnings: list[PackWarning],
) -> None:
    for relative in javascript:
        message = (
            f"Ignored pack JavaScript {relative}; dashboard code is not loaded or served"
        )
        logger.warning("%s", message)
        warnings.append(PackWarning("javascript_ignored", message))
    for relative in dashboard:
        message = f"Ignored pack dashboard file {relative}; it is not loaded or served"
        logger.warning("%s", message)
        warnings.append(PackWarning("dashboard_ignored", message))
    if modules:
        shown = ", ".join(modules[:8])
        if len(modules) > 8:
            shown = f"{shown}, ..."
        message = f"Ignored {len(modules)} pack Python module(s); they were not executed: {shown}"
        logger.warning("%s", message)
        warnings.append(PackWarning("python_not_executed", message))


def _declared_entry_points(root: Path) -> tuple[str, ...]:
    path = _find_pyproject(root)
    if path is None:
        return ()
    try:
        loaded = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return ()
    project = loaded.get("project")
    if not isinstance(project, dict):
        return ()
    groups = project.get("entry-points")
    if not isinstance(groups, dict):
        return ()
    verticals = groups.get("praxis.verticals")
    if not isinstance(verticals, dict):
        return ()
    values: list[str] = []
    for item in verticals.values():
        text = _text(item)
        if text:
            values.append(text)
    return tuple(values)


def _find_pyproject(root: Path) -> Path | None:
    direct = root / "pyproject.toml"
    if direct.is_file():
        return direct
    matches = [
        path
        for path in root.glob("*/pyproject.toml")
        if ".git" not in path.parts
    ]
    if len(matches) == 1:
        return matches[0]
    return None


def _run_allowlisted(
    root: Path,
    declared: tuple[str, ...],
    warnings: list[PackWarning],
) -> tuple[str, ...]:
    executed: list[str] = []
    for value in declared:
        if value not in ALLOWLISTED_ENTRY_POINTS:
            message = f"Ignored declared pack entry point {value}; it is not allowlisted"
            logger.warning("%s", message)
            warnings.append(PackWarning("entry_point_not_executed", message))
            continue
        _import_allowlisted(root, value)
        executed.append(value)
    return tuple(executed)


def _import_allowlisted(root: Path, value: str) -> None:
    """Import one entry point that is already on ``ALLOWLISTED_ENTRY_POINTS``.

    The allowlist is empty, so this does not run for installed packs. Any
    future non-empty allowlist must run this import inside the sandbox, not
    in the daemon process.
    """
    module_name, separator, attr = value.partition(":")
    if not separator or not _MODULE.fullmatch(module_name) or (attr and not _ATTR.fullmatch(attr)):
        raise PackError(f"refusing entry point {value!r}")
    inserted = str(root.resolve())
    sys.path.insert(0, inserted)
    try:
        module = importlib.import_module(module_name)
        if attr:
            target = getattr(module, attr, None)
            if callable(target):
                target()
    finally:
        sys.path[:] = [item for item in sys.path if item != inserted]
        for loaded in list(sys.modules):
            if loaded == module_name or loaded.startswith(module_name + "."):
                if loaded not in sys.stdlib_module_names:
                    sys.modules.pop(loaded, None)


def _skills(
    raw: object,
    pack_name: str,
    pack_dir: Path,
    warnings: list[PackWarning],
) -> tuple[Skill, ...]:
    if not isinstance(raw, list):
        return ()
    skills: list[Skill] = []
    used: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        original = _text(item.get("name"))
        name = _skill_slug(original)
        if not name or not _SKILL_NAME.fullmatch(name):
            warnings.append(PackWarning("skill_skipped", f"Skipped skill {original!r}"))
            continue
        if name in used:
            name = _unique_skill(name, used)
        used.add(name)
        if name != original:
            warnings.append(
                PackWarning("skill_renamed", f"Skill {original!r} is loaded as {name}")
            )
        trigger = _one_line(_text(item.get("trigger"))) or f"Skill {name} from pack {pack_name}"
        body = item.get("body")
        body_text = body if isinstance(body, str) else ""
        namespace = f"pack/{pack_name}/{name}"
        path = pack_dir / "skills" / "pack" / pack_name / name / "SKILL.md"
        front = "\n".join(
            [
                "---",
                f"name: {name}",
                f"description: {trigger}",
                f"pack: {pack_name}",
                f"namespace: {namespace}",
                "---",
                "",
                body_text.strip(),
                "",
            ]
        )
        skills.append(parse_skill(front, path, "pack"))
    return tuple(skills)


def _tools(raw: object, warnings: list[PackWarning]) -> tuple[ToolMapping, ...]:
    if not isinstance(raw, list):
        return ()
    mapped: list[ToolMapping] = []
    missing: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            continue
        legacy = item.strip()
        praxis = _TOOL_MAP.get(legacy, "")
        available = bool(praxis)
        mapped.append(ToolMapping(legacy, praxis, available))
        if not available:
            missing.append(legacy)
    if missing:
        message = "Pack tools unavailable in Praxis Prime: " + ", ".join(missing)
        logger.warning("%s", message)
        warnings.append(PackWarning("tool_unavailable", message))
    return tuple(mapped)


def _rules(
    raw: object,
    compliance_mode: object,
    warnings: list[PackWarning],
) -> tuple[tuple[MappedRule, ...], int, tuple[str, ...], tuple[str, ...]]:
    policy = raw if isinstance(raw, dict) else {}
    dual = _risk_list(policy.get("dualApprovalRisks"), warnings)
    autonomous = _risk_list(policy.get("autonomousRisks"), warnings)
    egress = bool(policy.get("egressCheck", False))
    injection = bool(policy.get("injectionCheck", False))
    ttl_raw = policy.get("approvalTtlSeconds", 0)
    ttl = ttl_raw if isinstance(ttl_raw, int) and ttl_raw > 0 else 0
    mode = _text(compliance_mode)
    rules = [
        MappedRule(
            "compliance-mode",
            "complianceMode",
            (
                f"complianceMode {mode or 'unset'} is a suggestion. "
                "Dial positions stay unchanged until an admin confirms them. "
                f"{PERSONA_BOUNDARY}"
            ),
            False,
        ),
        MappedRule(
            "dual-approval",
            "riskPolicy.dualApprovalRisks",
            "Dual approval requested for " + (", ".join(dual) if dual else "no risks"),
            False,
        ),
        MappedRule(
            "autonomous",
            "riskPolicy.autonomousRisks",
            "Autonomous risk classes recorded: "
            + (", ".join(autonomous) if autonomous else "none"),
            False,
        ),
        MappedRule(
            "egress-check",
            "riskPolicy.egressCheck",
            (
                "Decision Engine egress template requested"
                if egress
                else "Egress check was not requested"
            ),
            False,
        ),
        MappedRule(
            "injection-check",
            "riskPolicy.injectionCheck",
            (
                "Decision Engine injection template requested"
                if injection
                else "Injection check was not requested"
            ),
            False,
        ),
        MappedRule(
            "approval-ttl",
            "riskPolicy.approvalTtlSeconds",
            f"Approval TTL recorded as {ttl} seconds" if ttl else "No approval TTL recorded",
            False,
        ),
    ]
    return tuple(rules), ttl, dual, autonomous


def _risk_list(raw: object, warnings: list[PackWarning]) -> tuple[str, ...]:
    if not isinstance(raw, list):
        return ()
    values: list[str] = []
    for item in raw:
        text = _text(item).lower()
        if not text:
            continue
        mapped = _RISKS.get(text)
        if mapped is None:
            warnings.append(PackWarning("unknown_risk", f"Unknown risk class {text!r}"))
            values.append(text)
        else:
            values.append(mapped)
    return tuple(values)


def _theme(raw: object, pack_name: str, warnings: list[PackWarning]) -> ThemeHint | None:
    if not isinstance(raw, dict):
        return None
    pairs = (
        ("accent", "accent"),
        ("panel", "bgRaised"),
        ("ok", "ok"),
        ("warn", "warn"),
    )
    overrides: list[tuple[str, str]] = []
    for source_key, token in pairs:
        if source_key not in raw:
            continue
        value = _text(raw.get(source_key))
        if _HEX.fullmatch(value):
            overrides.append((token, value.lower()))
        elif value:
            warnings.append(
                PackWarning(
                    "theme_ignored",
                    f"Ignored theme {source_key} value; only hex colors are kept",
                )
            )
    if not overrides and not raw:
        return None
    theme_id = SUGGESTED_THEMES.get(pack_name, "smf.praxis")
    return ThemeHint(theme_id, tuple(overrides))


def _knowledge(
    pack_dir: Path,
    raw: object,
    warnings: list[PackWarning],
) -> tuple[PackKnowledge, ...]:
    names: list[str] = []
    if isinstance(raw, str) and raw.strip():
        names.append(raw.strip())
    elif isinstance(raw, list):
        names.extend(item.strip() for item in raw if isinstance(item, str) and item.strip())
    records: list[PackKnowledge] = []
    for name in names:
        path = _safe_child(pack_dir, name)
        if path is None or not path.is_file():
            warnings.append(PackWarning("knowledge_missing", f"Missing knowledge file {name}"))
            continue
        records.append(
            PackKnowledge(name, path.read_text(encoding="utf-8"), True)
        )
    return tuple(records)


def _safe_child(root: Path, relative: str) -> Path | None:
    if not relative or relative.startswith(("/", "\\")):
        return None
    parts = Path(relative).parts
    if ".." in parts:
        return None
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return None
    return candidate


def _license(root: Path, pack_dir: Path) -> str:
    current = pack_dir.resolve()
    stop = root.resolve()
    while True:
        for name in ("LICENSE", "LICENSE.txt", "LICENSE.md"):
            path = current / name
            if path.is_file():
                return _classify_license(path)
        if current == stop:
            break
        parent = current.parent
        if parent == current or stop not in current.parents and current != stop:
            break
        current = parent
    return "unknown"


def _classify_license(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")[:4000]
    except OSError:
        return "unknown"
    if "MIT License" in text or "Permission is hereby granted, free of charge" in text:
        return "MIT"
    return "unknown"


def _git_remote(root: Path) -> str:
    return _git(root, ["remote", "get-url", "origin"])


def _git_commit(root: Path) -> str:
    return _git(root, ["rev-parse", "HEAD"])


def _git(root: Path, args: list[str]) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return ""
    return completed.stdout.strip()


def _skill_slug(name: str) -> str:
    text = name.strip().lower().replace("_", "-")
    text = re.sub(r"[^a-z0-9-]+", "-", text)
    text = re.sub(r"-{2,}", "-", text).strip("-")
    return text


def _unique_skill(name: str, used: set[str]) -> str:
    index = 2
    while f"{name}-{index}" in used:
        index += 1
    return f"{name}-{index}"


def _one_line(value: str) -> str:
    return " ".join(value.split())


def _text(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()
