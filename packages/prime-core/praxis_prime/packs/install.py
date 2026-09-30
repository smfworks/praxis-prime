"""Install a legacy pack as data.

A local directory is copied. A git URL is cloned with ``git clone --depth 1``
and no pack script is run. JavaScript, dashboard files, and Python modules
are recorded and left out of the install directory.

TODO: ARCHITECTURE §17 and §32. Addendum A §7.
"""

from __future__ import annotations

import json
import os
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
from praxis_prime.packs.legacy import (
    PackError,
    assert_pack_file,
    find_manifests,
    find_pack_file,
    load_legacy_pack,
    skill_markdown,
)
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
# One path segment. Underscore is included because public pack.json names use it
# (law_firm, school_system). No leading dot, no slash, no backslash, max 64 chars.
_PACK_DIR_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
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
        # Reject the name, and a symlink already sitting at that name, before
        # rmtree or mkdir. rmtree follows a directory symlink and would delete
        # the link target (another pack).
        destination = contained_child(root, loaded.name, pack_dir=True)
        lexical = root.resolve() / loaded.name
        if lexical.is_symlink() or destination.is_symlink() or destination.name != loaded.name:
            raise PackError(f"refusing symlink pack directory {loaded.name!r}")
        if lexical.exists():
            shutil.rmtree(lexical)
        lexical.mkdir(parents=True)
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
    _copy_pack_file(source, manifest, contained_child(dest, "pack.json"))
    pack_dir = manifest.parent
    for record in pack.knowledge:
        relative = Path(record.filename)
        if not record.filename or relative.is_absolute() or ".." in relative.parts:
            raise PackError(f"refusing knowledge path {record.filename!r}")
        origin = pack_dir / relative
        stage = Path(source).resolve()
        try:
            chain = origin.relative_to(stage)
        except ValueError as exc:
            raise PackError(f"refusing knowledge path {record.filename!r}") from exc
        current = stage
        for part in chain.parts:
            current = current / part
            if current.is_symlink():
                raise PackError(f"refusing symlink {part}")
        if not origin.is_file():
            continue
        target = contained_child(dest, *relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        _copy_pack_file(source, origin, target)
    license_file = find_pack_file(source, pack_dir, ("LICENSE", "LICENSE.txt", "LICENSE.md"))
    if license_file is not None:
        _copy_pack_file(source, license_file, contained_child(dest, license_file.name))
    notice = find_pack_file(source, pack_dir, ("NOTICE", "NOTICE.md"))
    if notice is not None:
        _copy_pack_file(source, notice, contained_child(dest, notice.name))


def _copy_pack_file(root: Path, source: Path, dest: Path) -> None:
    """Copy one regular file. Refuse symlinks and paths outside ``root``."""
    assert_pack_file(root, source)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        src_fd = os.open(source, flags)
    except OSError as exc:
        raise PackError(f"refusing to read {Path(source).name}") from exc
    try:
        with os.fdopen(src_fd, "rb") as src:
            blob = src.read()
    except OSError as exc:
        raise PackError(f"refusing to read {Path(source).name}") from exc
    out_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        out_flags |= os.O_NOFOLLOW
    try:
        out_fd = os.open(dest, out_flags, 0o644)
    except FileExistsError as exc:
        raise PackError(f"refusing to write {dest.name}") from exc
    except OSError as exc:
        raise PackError(f"refusing to write {dest.name}") from exc
    with os.fdopen(out_fd, "wb") as out:
        out.write(blob)


def _manifest_file(source: Path, pack: LegacyPack) -> Path:
    candidate = source / pack.manifest_path
    if candidate.is_symlink() or candidate.is_file():
        assert_pack_file(source, candidate)
        return candidate
    matches = [path for path in find_manifests(source) if path.parent.name == pack.name]
    if matches:
        assert_pack_file(source, matches[0])
        return matches[0]
    found = find_manifests(source)
    if len(found) == 1:
        assert_pack_file(source, found[0])
        return found[0]
    raise PackError(f"installed manifest for {pack.name} was not found")


def _write_skills(dest: Path, pack: LegacyPack) -> None:
    for skill in pack.skills:
        folder = contained_child(dest, "skills", "pack", pack.name, skill.name)
        folder.mkdir(parents=True, exist_ok=True)
        skill_file = contained_child(folder, "SKILL.md")
        skill_file.write_text(skill_markdown(skill), encoding="utf-8")


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
    contained_child(dest, _PROVENANCE).write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )


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
    """Extract members one by one under ``dest``. Refuse escapes and symlinks."""
    root = dest.resolve()
    root.mkdir(parents=True, exist_ok=True)
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise PackError("pack archive is not a valid zip") from exc
    with archive:
        try:
            infos = archive.infolist()
        except zipfile.BadZipFile as exc:
            raise PackError("pack archive is not a valid zip") from exc
        if len(infos) > _MAX_ZIP_FILES:
            raise PackError("pack archive has too many files")
        planned: list[tuple[zipfile.ZipInfo, Path]] = []
        total = 0
        for info in infos:
            _reject_zip_member(info)
            total += info.file_size
            if total > _MAX_ZIP_BYTES:
                raise PackError("pack archive is too large")
            target = _zip_member_path(root, info.filename)
            planned.append((info, target))
        for info, target in planned:
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                _write_zip_member(archive, info, target)
            except FileExistsError as exc:
                raise PackError("pack archive has a duplicate member") from exc
            except zipfile.BadZipFile as exc:
                raise PackError("pack archive is not a valid zip") from exc


def _reject_zip_member(info: zipfile.ZipInfo) -> None:
    mode = (info.external_attr >> 16) & 0xFFFF
    if stat.S_ISLNK(mode):
        raise PackError("pack archive contains a symlink")
    name = info.filename
    if not name or "\x00" in name:
        raise PackError("pack archive path escapes the archive")
    if name.startswith(("/", "\\")) or "\\" in name:
        raise PackError("pack archive path escapes the archive")
    head = name.split("/", 1)[0]
    if len(head) >= 2 and head[1] == ":":
        raise PackError("pack archive path escapes the archive")
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise PackError("pack archive path escapes the archive")


def _zip_member_path(root: Path, name: str) -> Path:
    relative = Path(name)
    parts = [part for part in relative.parts if part not in {"", "."}]
    if not parts:
        raise PackError("pack archive path escapes the archive")
    return contained_child(root, *parts)


def _write_zip_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, target: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(target, flags, 0o644)
    with os.fdopen(descriptor, "wb") as out, archive.open(info, "r") as src:
        shutil.copyfileobj(src, out)


def contained_child(root: Path, *parts: str, pack_dir: bool = False) -> Path:
    """Resolve ``root/parts`` and refuse anything that is not a strict child.

    ``pack_dir=True`` is the install directory name. It must match
    ``^[a-z0-9][a-z0-9._-]{0,63}$`` (no leading dot). Call this before
    ``rmtree``, ``mkdir``, or skill writes.
    """
    if not parts:
        raise PackError("refusing empty pack path")
    if pack_dir:
        if len(parts) != 1:
            raise PackError("refusing pack path")
        _require_pack_name(parts[0])
    for part in parts:
        _reject_segment(part)
    base = Path(root).resolve()
    lexical = base.joinpath(*parts)
    current = base
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise PackError(f"refusing symlink {part!r}")
    candidate = lexical.resolve()
    if candidate == base or base not in candidate.parents or candidate.name != parts[-1]:
        raise PackError("refusing pack path outside the install directory")
    return candidate


def _require_pack_name(name: str) -> None:
    if not isinstance(name, str) or not _PACK_DIR_NAME.fullmatch(name):
        raise PackError(f"refusing pack name {name!r}")
    if name.startswith(".") or "/" in name or "\\" in name or Path(name).is_absolute():
        raise PackError(f"refusing pack name {name!r}")
    if name in {".", ".."} or ".." in Path(name).parts:
        raise PackError(f"refusing pack name {name!r}")


def _reject_segment(segment: str) -> None:
    if (
        not isinstance(segment, str)
        or not segment
        or segment in {".", ".."}
        or "/" in segment
        or "\\" in segment
        or "\x00" in segment
        or Path(segment).is_absolute()
        or ".." in Path(segment).parts
    ):
        raise PackError(f"refusing path segment {segment!r}")


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
