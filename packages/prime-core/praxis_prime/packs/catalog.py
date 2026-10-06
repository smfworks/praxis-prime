"""The six public MIT vertical packs.

Pack data ships under ``packs/regulated/`` and in the wheel at
``praxis_prime/_data/packs/regulated``. ``packs install <name>`` copies that
bundled data and does not clone git. It does not import pack Python.
Names here are the CLI aliases. ``pack_name`` is the ``pack.json`` name.

TODO: ARCHITECTURE §32. Addendum A §7.2.
"""

from __future__ import annotations

from dataclasses import dataclass

SUGGESTED_POSITION = "monitor"

# Old ``enforced`` is not Praxis ``enforce``. These are suggestions only.
SUGGESTED_DIALS: dict[str, tuple[str, ...]] = {
    "medical_office": ("hipaa",),
    "behavioral_health": ("hipaa",),
    "school_system": ("ferpa", "coppa"),
    "homeschool": ("ferpa", "coppa"),
}

SUGGESTED_THEMES: dict[str, str] = {
    "law_firm": "smf.legal-office",
    "forensic": "smf.forensic",
    "school_system": "smf.education",
    "homeschool": "smf.education",
    "medical_office": "smf.medical",
    "behavioral_health": "smf.medical",
}


@dataclass(frozen=True, slots=True)
class PublicPack:
    key: str
    repo: str
    distribution: str
    pack_name: str
    license: str = "MIT"

    def aliases(self) -> frozenset[str]:
        repo_name = self.repo.rstrip("/").rsplit("/", 1)[-1]
        if repo_name.endswith(".git"):
            repo_name = repo_name[: -len(".git")]
        names = {
            self.key,
            self.distribution,
            self.pack_name,
            repo_name,
            self.distribution.replace("-", "_"),
        }
        return frozenset(names)


PUBLIC_PACKS: tuple[PublicPack, ...] = (
    PublicPack(
        "homeschool",
        "https://github.com/smfworks/smf-praxis-homeschool.git",
        "praxis-homeschool",
        "homeschool",
    ),
    PublicPack(
        "education",
        "https://github.com/smfworks/smf-praxis-education.git",
        "praxis-education",
        "school_system",
    ),
    PublicPack(
        "forensic",
        "https://github.com/smfworks/smf-praxis-forensic.git",
        "praxis-forensic",
        "forensic",
    ),
    PublicPack(
        "legal",
        "https://github.com/smfworks/smf-praxis-legal.git",
        "praxis-legal",
        "law_firm",
    ),
    PublicPack(
        "medical",
        "https://github.com/smfworks/smf-praxis-medical.git",
        "praxis-medical",
        "medical_office",
    ),
    PublicPack(
        "mbh",
        "https://github.com/smfworks/smf-praxis-mbh.git",
        "praxis-mbh",
        "behavioral_health",
    ),
)


def resolve_public(name: str) -> PublicPack | None:
    """Match a CLI name, PyPI name, pack.json name, or GitHub repo."""
    text = name.strip().rstrip("/")
    if text.endswith(".git"):
        text = text[: -len(".git")]
    lowered = text.lower()
    for pack in PUBLIC_PACKS:
        aliases = {alias.lower() for alias in pack.aliases()}
        repo = pack.repo.lower().removesuffix(".git")
        if lowered in aliases or lowered == repo or lowered == pack.repo.lower():
            return pack
    return None


def known_names() -> tuple[str, ...]:
    return tuple(pack.key for pack in PUBLIC_PACKS)
