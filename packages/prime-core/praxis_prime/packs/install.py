"""Install a legacy pack as data.

A local directory is copied. A git URL is cloned with ``git clone --depth 1``
and no pack script is run. JavaScript, dashboard files, and Python modules
are recorded and left out of the install directory.

TODO: ARCHITECTURE §17 and §32. Addendum A §7.
"""

from __future__ import annotations

import json
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

from praxis_prime.audit.log import AuditLog
from praxis_prime.packs.catalog import PublicPack, known_names, resolve_public
from praxis_prime.packs.legacy import PackError, find_manifests, load_legacy_pack, skill_markdown
from praxis_prime.packs.model import LegacyPack, PackWarning, Provenance

GitRunner = Callable[[list[str]], None]

_SCAN_CODES = frozenset(
    {
        "javascript_ignored",
        "dashboard_ignored",
        "python_not_executed",
        "entry_point_not_executed",
    }
)
_GIT_URL = re.compile(r"^(https://|http://|ssh://|git@)[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$")
_MAX_ZIP_FILES = 200
_MAX_ZIP_BYTES = 15 * 1024 * 1024
_PROVENANCE = "provenance.json"


@dataclass(frozen=True, slots=True)
class InstalledPack:
    pack: LegacyPack
    path: Path


def vertical_packs_dir(data: Path) -> Path:
    return Path(data) / "vertical-packs"


def install_pack(
    source: str,
    data: Path,
    *,
    audit: AuditLog | None = None,
    git_runner: GitRunner | None = None,
) -> InstalledPack:
    """Install one pack under ``data/vertical-packs/<name>``."""
    text = source.strip()
    if not text:
        raise PackError("pack source is empty")
    root = vertical_packs_dir(data)
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="praxis-pack-") as tmp:
        staged, repo, commit, wanted = _stage(text, Path(tmp), git_runner or _default_git)
        loaded = load_legacy_pack(
            staged,
            wanted_name=wanted,
            repo=repo,
            commit=commit,
            source=text,
        )
        if not loaded.provenance.license:
            loaded = replace(
                loaded,
                provenance=replace(loaded.provenance, license="unknown"),
            )
        destination = root / loaded.name
        if destination.exists():
            shutil.rmtree(destination)
        destination.mkdir(parents=True)
        _copy_data(staged, destination, loaded)
        _write_skills(destination, loaded)
        _write_provenance(destination, loaded)
        installed = load_installed(destination)
    if audit is not None:
        record_provenance(audit, installed)
    return InstalledPack(installed, destination)


def list_installed(data: Path) -> tuple[LegacyPack, ...]:
    root = vertical_packs_dir(data)
    if not root.is_dir():
        return ()
    packs: list[LegacyPack] = []
    for child in sorted(path for path in root.iterdir() if path.is_dir()):
        if find_manifests(child):
            packs.append(load_installed(child))
    return tuple(packs)


def load_installed(directory: Path) -> LegacyPack:
    """Load an installed pack and restore the source-tree scan."""
    saved = _read_provenance(directory)
    pack = load_legacy_pack(
        directory,
        repo=str(saved.get("repo", "")),
        commit=str(saved.get("commit", "")),
        source=str(saved.get("source", "")),
    )
    return _restore_scan(pack, saved)


def record_provenance(audit: AuditLog, pack: LegacyPack) -> str:
    """Append pack repo, version or commit, and license to the audit log."""
    provenance = pack.provenance
    return audit.append(
        session_id=None,
        kind="pack.install",
        summary=f"installed pack {pack.name} {provenance.version} ({provenance.license})",
        payload={
            "name": pack.name,
            "repo": provenance.repo,
            "version": provenance.version,
            "commit": provenance.commit,
            "license": provenance.license,
            "source": provenance.source,
            "model_ignored": pack.model_suggestion,
            "provider_ignored": pack.provider_suggestion,
            "javascript_ignored": list(pack.ignored_javascript),
            "python_not_executed": list(pack.python_modules),
        },
    )


def _stage(
    source: str,
    tmp: Path,
    runner: GitRunner,
) -> tuple[Path, str, str, str]:
    local = Path(source).expanduser()
    if local.exists():
        if local.is_file() and local.suffix.lower() == ".zip":
            extracted = tmp / "zip"
            extracted.mkdir()
            _extract_zip(local, extracted)
            return extracted, "", "", ""
        if local.is_dir():
            return local.resolve(), "", "", ""
        raise PackError(f"pack source is not a directory or zip: {source}")
    public = resolve_public(source)
    if public is not None:
        dist_root = _materialize_distribution(public, tmp / "dist")
        if dist_root is not None:
            return dist_root, public.repo, "", public.pack_name
        cloned = tmp / "repo"
        url = _safe_git_url(public.repo)
        _clone(url, cloned, runner)
        commit = _rev_parse(cloned)
        return cloned, url, commit, public.pack_name
    if _looks_like_git(source):
        cloned = tmp / "repo"
        url = _safe_git_url(source)
        _clone(url, cloned, runner)
        commit = _rev_parse(cloned)
        known = resolve_public(url)
        wanted = known.pack_name if known is not None else ""
        return cloned, url, commit, wanted
    known_list = ", ".join(known_names())
    raise PackError(f"unknown pack source {source!r}. Known names: {known_list}")


def _looks_like_git(source: str) -> bool:
    text = source.strip()
    return text.startswith(("https://", "http://", "ssh://", "git@")) or text.endswith(".git")


def _safe_git_url(url: str) -> str:
    text = url.strip()
    if "::" in text or text.startswith("-") or not _GIT_URL.fullmatch(text):
        raise PackError(f"refusing git URL {url!r}")
    return text


def _clone(url: str, target: Path, runner: GitRunner) -> None:
    runner(["git", "clone", "--depth", "1", "--", url, str(target)])
    if not target.is_dir() or not find_manifests(target):
        raise PackError("git clone produced no pack.json")


def _default_git(argv: list[str]) -> None:
    if not argv or argv[0] != "git" or "clone" not in argv:
        raise PackError("pack install only runs git clone")
    try:
        subprocess.run(argv, check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = exc.stderr if isinstance(exc, subprocess.CalledProcessError) else str(exc)
        raise PackError(f"git clone failed: {detail}") from exc


def _rev_parse(root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return ""
    return completed.stdout.strip()


def _materialize_distribution(public: PublicPack, dest: Path) -> Path | None:
    """Copy an installed distribution's files without importing it."""
    dist = _find_distribution(public)
    if dist is None:
        return None
    files = list(getattr(dist, "files", None) or [])
    if not any(path.name == "pack.json" for path in files):
        return None
    dest.mkdir(parents=True, exist_ok=True)
    copied = 0
    for file in files:
        relative = Path(*file.parts)
        if relative.is_absolute() or ".." in relative.parts:
            continue
        if "__pycache__" in relative.parts or relative.suffix == ".pyc":
            continue
        source = Path(str(dist.locate_file(file)))
        if not source.is_file():
            continue
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        copied += 1
    if copied == 0 or not find_manifests(dest):
        return None
    return dest


def _find_distribution(public: PublicPack) -> object | None:
    from importlib.metadata import distributions, entry_points

    want = public.distribution.lower().replace("_", "-")
    for dist in distributions():
        name = str(dist.metadata["Name"] or "").lower().replace("_", "-")
        if name == want:
            return dist
    for entry in entry_points(group="praxis.verticals"):
        # EntryPoint.load() would import and run the pack. Never call it.
        if entry.name in {public.key, public.pack_name} and entry.dist is not None:
            return entry.dist
    return None


def _copy_data(source: Path, dest: Path, pack: LegacyPack) -> None:
    manifest = _manifest_file(source, pack)
    shutil.copy2(manifest, dest / "pack.json")
    pack_dir = manifest.parent
    for record in pack.knowledge:
        relative = Path(record.filename)
        if relative.is_absolute() or ".." in relative.parts:
            continue
        origin = pack_dir / relative
        if not origin.is_file():
            continue
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(origin, target)
    license_file = _find_named(source, pack_dir, ("LICENSE", "LICENSE.txt", "LICENSE.md"))
    if license_file is not None:
        shutil.copy2(license_file, dest / license_file.name)
    notice = _find_named(source, pack_dir, ("NOTICE", "NOTICE.md"))
    if notice is not None:
        shutil.copy2(notice, dest / notice.name)


def _manifest_file(source: Path, pack: LegacyPack) -> Path:
    candidate = source / pack.manifest_path
    if candidate.is_file():
        return candidate
    matches = [path for path in find_manifests(source) if path.parent.name == pack.name]
    if matches:
        return matches[0]
    found = find_manifests(source)
    if len(found) == 1:
        return found[0]
    raise PackError(f"installed manifest for {pack.name} was not found")


def _find_named(root: Path, pack_dir: Path, names: tuple[str, ...]) -> Path | None:
    current = pack_dir.resolve()
    stop = root.resolve()
    while True:
        for name in names:
            path = current / name
            if path.is_file():
                return path
        if current == stop:
            return None
        parent = current.parent
        if parent == current:
            return None
        current = parent


def _write_skills(dest: Path, pack: LegacyPack) -> None:
    for skill in pack.skills:
        folder = dest / "skills" / "pack" / pack.name / skill.name
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "SKILL.md").write_text(skill_markdown(skill), encoding="utf-8")


def _write_provenance(dest: Path, pack: LegacyPack) -> None:
    provenance = pack.provenance
    payload = {
        "repo": provenance.repo,
        "version": provenance.version,
        "commit": provenance.commit,
        "license": provenance.license,
        "source": provenance.source,
        "ignored_javascript": list(pack.ignored_javascript),
        "ignored_dashboard": list(pack.ignored_dashboard),
        "python_modules": list(pack.python_modules),
        "declared_entry_points": list(pack.declared_entry_points),
        "warnings": [{"code": item.code, "message": item.message} for item in pack.warnings],
    }
    (dest / _PROVENANCE).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _read_provenance(directory: Path) -> dict[str, object]:
    path = directory / _PROVENANCE
    if not path.is_file():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if isinstance(loaded, dict):
        return loaded
    return {}


def _restore_scan(pack: LegacyPack, saved: dict[str, object]) -> LegacyPack:
    if not saved:
        return pack
    extra: list[PackWarning] = []
    seen = {(item.code, item.message) for item in pack.warnings}
    raw_warnings = saved.get("warnings", [])
    if isinstance(raw_warnings, list):
        for item in raw_warnings:
            if not isinstance(item, dict):
                continue
            code = str(item.get("code", ""))
            message = str(item.get("message", ""))
            if code not in _SCAN_CODES or (code, message) in seen:
                continue
            extra.append(PackWarning(code, message))
            seen.add((code, message))
    javascript = pack.ignored_javascript or _strings(saved.get("ignored_javascript"))
    dashboard = pack.ignored_dashboard or _strings(saved.get("ignored_dashboard"))
    modules = pack.python_modules or _strings(saved.get("python_modules"))
    declared = pack.declared_entry_points or _strings(saved.get("declared_entry_points"))
    license_name = pack.provenance.license
    saved_license = str(saved.get("license", "")).strip()
    if license_name == "unknown" and saved_license:
        license_name = saved_license
    provenance = Provenance(
        repo=pack.provenance.repo or str(saved.get("repo", "")),
        version=pack.provenance.version or str(saved.get("version", "")),
        commit=pack.provenance.commit or str(saved.get("commit", "")),
        license=license_name,
        source=pack.provenance.source or str(saved.get("source", "")),
    )
    return replace(
        pack,
        warnings=pack.warnings + tuple(extra),
        ignored_javascript=javascript,
        ignored_dashboard=dashboard,
        python_modules=modules,
        declared_entry_points=declared,
        provenance=provenance,
    )


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(item) for item in value if str(item).strip())


def _extract_zip(path: Path, dest: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > _MAX_ZIP_FILES:
            raise PackError("pack archive has too many files")
        total = 0
        for info in infos:
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise PackError("pack archive contains a symlink")
            name = info.filename
            relative = Path(name)
            if name.startswith("/") or ".." in relative.parts:
                raise PackError("pack archive path escapes the archive")
            total += info.file_size
            if total > _MAX_ZIP_BYTES:
                raise PackError("pack archive is too large")
        archive.extractall(dest)


def installed_index(data: Path) -> dict[str, LegacyPack]:
    """Map pack name and catalog aliases to an installed pack."""
    found: dict[str, LegacyPack] = {}
    for pack in list_installed(data):
        found[pack.name] = pack
        public = resolve_public(pack.name)
        if public is not None:
            for alias in public.aliases():
                found.setdefault(alias, pack)
    return found
