"""Load compliance packs from TOML.

Bundled packs ship inside the wheel at
``praxis_prime/_data/packs/compliance`` and are read with
``importlib.resources``. A source checkout that has not been packaged still
loads ``packs/compliance`` by walking up from this file.

A file in ``~/.config/praxis-prime/packs`` or ``.prime/packs`` with the same
pack id replaces the bundled one. Packs are starter policy, not legal advice.

TODO: ARCHITECTURE §17 and §32. Vertical packs in the old ``pack.json``
format load through ``praxis_prime.packs`` and are not copied into this tree.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from praxis_prime.compliance.detectors import DetectorSpec

_ACTIONS = frozenset(
    {"block", "require_approval", "redact", "route_local", "egress_deny"}
)
_STYLES = frozenset({"mask", "last4"})
_BUNDLED: tuple[PolicyPack, ...] | None = None


@dataclass(frozen=True, slots=True)
class RuleSpec:
    id: str
    action: str
    data_classes: tuple[str, ...]
    hooks: tuple[str, ...]
    tools: tuple[str, ...] = ()
    provider_flags: tuple[str, ...] = ()
    style: str = "mask"


@dataclass(frozen=True, slots=True)
class PolicyPack:
    id: str
    dial: str
    title: str
    disclaimer: str
    legal_references: tuple[str, ...]
    detectors: tuple[DetectorSpec, ...]
    rules: tuple[RuleSpec, ...]
    retention_days: int | None = None
    required_events: tuple[str, ...] = ()
    breach_enabled: bool = False
    breach_sla_days: int = 30
    breach_sla_is_legal_deadline: bool = False
    lawful_basis_note: str = ""
    starter: bool = True
    source: str = ""


def bundled_pack_dir() -> Path:
    """Find a source-tree ``packs/compliance`` directory.

    Installed wheels do not have that directory. They use
    :func:`_resource_pack_texts` instead.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "packs" / "compliance"
        if candidate.is_dir() and any(candidate.glob("*.toml")):
            return candidate
    raise FileNotFoundError("bundled packs/compliance directory was not found")


def bundled_packs() -> tuple[PolicyPack, ...]:
    global _BUNDLED
    if _BUNDLED is None:
        texts = _resource_pack_texts()
        if texts:
            loaded: list[PolicyPack] = []
            for label, text in texts:
                loaded.extend(parse_pack_text(text, label))
            _BUNDLED = tuple(loaded)
        else:
            _BUNDLED = _read_dir(bundled_pack_dir())
    return _BUNDLED


def _resource_pack_texts() -> tuple[tuple[str, str], ...]:
    """TOML shipped inside the installed package, if this install has any."""
    root = files("praxis_prime").joinpath("_data", "packs", "compliance")
    try:
        if not root.is_dir():
            return ()
        entries = list(root.iterdir())
    except (FileNotFoundError, NotADirectoryError, OSError):
        return ()
    texts: list[tuple[str, str]] = []
    for item in sorted(entries, key=lambda entry: entry.name):
        if not item.name.endswith(".toml"):
            continue
        label = f"praxis_prime/_data/packs/compliance/{item.name}"
        texts.append((label, item.read_text(encoding="utf-8")))
    return tuple(texts)


def load_packs(
    *roots: Path | None,
    config_dir: Path | None = None,
    project_root: Path | None = None,
) -> tuple[PolicyPack, ...]:
    """Bundled packs, then user packs, then project packs. Later ids win."""
    merged: dict[str, PolicyPack] = {pack.id: pack for pack in bundled_packs()}
    directories: list[Path] = [path for path in roots if path is not None]
    if config_dir is not None:
        directories.append(Path(config_dir) / "packs")
    if project_root is not None:
        directories.append(Path(project_root) / ".prime" / "packs")
    for directory in directories:
        for pack in _read_dir(directory):
            merged[pack.id] = pack
    return tuple(sorted(merged.values(), key=lambda pack: (pack.dial, pack.id)))


def packs_for_dials(
    packs: tuple[PolicyPack, ...],
    positions: dict[str, str],
) -> tuple[PolicyPack, ...]:
    active = {
        dial_id
        for dial_id, position in positions.items()
        if position in {"monitor", "enforce"}
    }
    return tuple(pack for pack in packs if pack.dial in active)


def parse_pack_file(path: Path) -> tuple[PolicyPack, ...]:
    return parse_pack_text(path.read_text(encoding="utf-8"), str(path))


def parse_pack_text(text: str, source: str) -> tuple[PolicyPack, ...]:
    loaded = tomllib.loads(text)
    if not isinstance(loaded, dict):
        raise ValueError(f"{source} is not a TOML document")
    raw_pack = loaded.get("pack")
    if isinstance(raw_pack, list):
        return tuple(
            _one_pack(item, source) for item in raw_pack if isinstance(item, dict)
        )
    if isinstance(raw_pack, dict):
        body = dict(raw_pack)
        body.setdefault("detectors", loaded.get("detectors", []))
        body.setdefault("rules", loaded.get("rules", []))
        for key in ("meta", "retention", "audit", "breach", "gdpr"):
            if key in loaded and key not in body:
                body[key] = loaded[key]
        return (_one_pack(body, source),)
    raise ValueError(f"{source} needs a [pack] table or [[pack]] entries")


def _read_dir(directory: Path) -> tuple[PolicyPack, ...]:
    if not directory.is_dir():
        return ()
    packs: list[PolicyPack] = []
    for path in sorted(directory.glob("*.toml")):
        packs.extend(parse_pack_file(path))
    return tuple(packs)


def _one_pack(raw: dict[str, object], source: str) -> PolicyPack:
    meta = _table(raw.get("meta"))
    retention = _table(raw.get("retention"))
    audit = _table(raw.get("audit"))
    breach = _table(raw.get("breach"))
    gdpr = _table(raw.get("gdpr"))
    pack_id = _text(raw.get("id")) or Path(source).stem
    dial = _text(raw.get("dial")) or pack_id
    days = retention.get("days", raw.get("retention_days"))
    retention_days = int(days) if isinstance(days, int) and days > 0 else None
    disclaimer = _text(raw.get("disclaimer")) or (
        "Starter policy. Technical controls only. Not legal advice."
    )
    return PolicyPack(
        id=pack_id,
        dial=dial,
        title=_text(raw.get("title")) or pack_id,
        disclaimer=disclaimer,
        legal_references=_strings(meta.get("legal_references")),
        detectors=tuple(
            _detector(item) for item in _rows(raw.get("detectors")) if _detector(item)
        ),
        rules=tuple(_rule(item) for item in _rows(raw.get("rules")) if _rule(item)),
        retention_days=retention_days,
        required_events=_strings(audit.get("required_events")),
        breach_enabled=bool(breach.get("enabled", False)),
        breach_sla_days=_int(breach.get("sla_days"), 30),
        breach_sla_is_legal_deadline=bool(breach.get("sla_is_legal_deadline", False)),
        lawful_basis_note=_text(gdpr.get("lawful_basis_note")),
        starter=bool(meta.get("starter", raw.get("starter", True))),
        source=source,
    )


def _detector(raw: object) -> DetectorSpec | None:
    if not isinstance(raw, dict):
        return None
    kind = _text(raw.get("kind"))
    if not kind:
        return None
    classes = _strings(raw.get("data_classes")) or _strings(raw.get("data_class"))
    if not classes:
        return None
    return DetectorSpec(
        id=_text(raw.get("id")) or kind,
        kind=kind,
        data_classes=classes,
        context=_strings(raw.get("context")),
        pattern=_text(raw.get("pattern")),
        terms=_strings(raw.get("terms")),
        window=_int(raw.get("window"), 96),
    )


def _rule(raw: object) -> RuleSpec | None:
    if not isinstance(raw, dict):
        return None
    action = _text(raw.get("action"))
    if action not in _ACTIONS:
        return None
    classes = _strings(raw.get("data_classes")) or _strings(raw.get("data_class"))
    if not classes:
        return None
    style = _text(raw.get("style")) or "mask"
    if style not in _STYLES:
        style = "mask"
    return RuleSpec(
        id=_text(raw.get("id")) or action,
        action=action,
        data_classes=classes,
        hooks=_strings(raw.get("hooks")),
        tools=_strings(raw.get("tools")),
        provider_flags=_strings(raw.get("provider_flags")),
        style=style,
    )


def _rows(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _table(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return value
    return {}


def _strings(value: object) -> tuple[str, ...]:
    if isinstance(value, str) and value.strip():
        return (value.strip(),)
    if isinstance(value, list):
        return tuple(str(item).strip() for item in value if str(item).strip())
    return ()


def _text(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _int(value: object, default: int) -> int:
    if isinstance(value, int):
        return value
    return default
