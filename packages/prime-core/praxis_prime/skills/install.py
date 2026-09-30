"""Install a skill folder.

A local directory is copied. A git URL is cloned only after ``approve``
returns true, with ``git clone --depth 1``, and no script in the tree is
executed.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

from praxis_prime.skills.format import parse_skill

GitRunner = Callable[[list[str]], None]


class InstallError(ValueError):
    """The skill could not be installed."""


def is_git_source(source: str) -> bool:
    text = source.strip()
    return text.startswith(("https://", "http://", "ssh://", "git@", "git+")) or text.endswith(
        ".git"
    )


def install_skill(
    source: str,
    dest_root: Path,
    *,
    approve: Callable[[str], bool],
    runner: GitRunner | None = None,
) -> Path:
    """Copy one skill into ``dest_root/<name>``. Git clones need approval."""
    text = source.strip()
    local = Path(text).expanduser()
    if local.exists():
        return _copy_skill(local, dest_root)
    if is_git_source(text):
        if not approve(text):
            raise PermissionError("git skill install needs approval and was denied")
        return _clone(text, dest_root, runner or _default_git)
    raise InstallError(f"skill source not found: {source}")


def remove_skill(name: str, dest_root: Path) -> Path:
    folder = dest_root / name
    skill_file = folder / "SKILL.md"
    if not skill_file.is_file():
        raise InstallError(f"no installed skill {name}")
    shutil.rmtree(folder)
    return folder


def write_new_skill(name: str, dest_root: Path) -> Path:
    folder = dest_root / name
    if folder.exists():
        raise InstallError(f"skill {name} already exists")
    folder.mkdir(parents=True, exist_ok=False)
    body = (
        f"---\nname: {name}\ndescription: Describe when to use this skill.\n---\n\n"
        f"# {name}\n\n"
        "Write the instructions the agent should follow when this skill is loaded.\n"
    )
    path = folder / "SKILL.md"
    path.write_text(body, encoding="utf-8")
    parse_skill(body, path, "user")
    return path


def _copy_skill(source: Path, dest_root: Path) -> Path:
    skill_file = _find_skill_file(source)
    skill = parse_skill(skill_file.read_text(encoding="utf-8"), skill_file, "user")
    return _copy_tree(skill_file.parent, dest_root / skill.name)


def _clone(url: str, dest_root: Path, runner: GitRunner) -> Path:
    with tempfile.TemporaryDirectory(prefix="praxis-skill-") as tmp:
        target = Path(tmp) / "repo"
        runner(["git", "clone", "--depth", "1", "--", url, str(target)])
        if not target.exists():
            raise InstallError("git clone produced no files")
        return _copy_skill(target, dest_root)


def _find_skill_file(root: Path) -> Path:
    if root.is_file() and root.name == "SKILL.md":
        return root
    direct = root / "SKILL.md"
    if direct.is_file():
        return direct
    found = sorted(path for path in root.glob("*/SKILL.md") if ".git" not in path.parts)
    if not found:
        raise InstallError(f"no SKILL.md under {root}")
    return found[0]


def _copy_tree(source: Path, dest: Path) -> Path:
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)

    def _ignore(directory: str, names: list[str]) -> set[str]:
        del directory
        return {name for name in names if name == ".git" or name == "__pycache__"}

    shutil.copytree(source, dest, ignore=_ignore)
    return dest


def _default_git(argv: list[str]) -> None:
    if not argv or argv[0] != "git" or "clone" not in argv:
        raise InstallError("skill install only runs git clone")
    try:
        subprocess.run(argv, check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise InstallError("git clone failed") from exc
