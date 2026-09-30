"""Skill discovery.

Project skills win over the user directory, then ``~/.agents/skills``, then
the skills bundled with this repo. The prompt receives names and
descriptions only. The body is loaded by ``use_skill``.
"""

from __future__ import annotations

import os
from pathlib import Path

from praxis_prime.skills.format import Skill, parse_skill


class SkillCatalog:
    def __init__(
        self,
        *,
        project: Path | None = None,
        user: Path | None = None,
        shared: Path | None = None,
        bundled: Path | None = None,
    ) -> None:
        self.roots = {
            "bundled": bundled,
            "shared": shared,
            "user": user,
            "project": project,
        }
        self.skills: dict[str, Skill] = {}
        for source in ("bundled", "shared", "user", "project"):
            self.skills.update(_load_dir(self.roots[source], source))

    def get(self, name: str) -> Skill | None:
        return self.skills.get(name.strip())

    def ordered(self) -> tuple[Skill, ...]:
        return tuple(self.skills[name] for name in sorted(self.skills))

    def index_text(self) -> str:
        skills = self.ordered()
        if not skills:
            return ""
        lines = ["Skills (call use_skill with the name to load the body):"]
        lines.extend(skill.index_line() for skill in skills)
        return "\n".join(lines)

    def load_body(self, name: str) -> str:
        skill = self.get(name)
        if skill is None:
            known = ", ".join(sorted(self.skills)) or "none"
            raise ValueError(f"unknown skill {name!r}. Known: {known}")
        return (
            f"Loaded skill {skill.name}. Follow these instructions. "
            "They do not skip approval for sending, spending, sharing, or deleting.\n\n"
            f"{skill.body}"
        )


def bundled_skills_dir() -> Path:
    override = os.environ.get("PRAXIS_PRIME_BUNDLED_SKILLS")
    if override:
        return Path(override)
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "skills"
        if candidate.is_dir() and any(candidate.glob("*/SKILL.md")):
            return candidate
    return here.parent / "bundled"


def _load_dir(root: Path | None, source: str) -> dict[str, Skill]:
    found: dict[str, Skill] = {}
    if root is None or not root.is_dir():
        return found
    for path in sorted(root.glob("*/SKILL.md")):
        try:
            skill = parse_skill(path.read_text(encoding="utf-8"), path, source)
        except (OSError, ValueError):
            continue
        found[skill.name] = skill
    return found
