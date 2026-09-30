"""Provider flags used when an enforce dial pins model routing.

Flags are metadata on the owner's config. They are not a claim that a
vendor has signed a BAA or hosts data in the EU.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from praxis_prime.router.types import ModelRef


@dataclass(frozen=True, slots=True)
class ProviderFlags:
    local: bool = False
    baa: bool = False
    eu_region: bool = False
    zero_retention: bool = False

    def allows(self, required: Sequence[str]) -> bool:
        """True when no flag is required, or any required flag is set."""
        if not required:
            return True
        current = {
            "local": self.local,
            "baa": self.baa,
            "eu_region": self.eu_region,
            "zero_retention": self.zero_retention,
        }
        return any(current.get(name, False) for name in required)

    def as_dict(self) -> dict[str, bool]:
        return {
            "local": self.local,
            "baa": self.baa,
            "eu_region": self.eu_region,
            "zero_retention": self.zero_retention,
        }


def flags_from_config(
    name: str,
    table: Mapping[str, object] | None = None,
    *,
    base_url: str = "",
) -> ProviderFlags:
    """Defaults: Ollama is local. A loopback OpenAI-compatible URL is local."""
    raw = table or {}
    local_default = name == "ollama" or (
        name == "openai-compatible" and _loopback(base_url)
    )
    return ProviderFlags(
        local=_bool(raw.get("local"), local_default),
        baa=_bool(raw.get("baa"), False),
        eu_region=_bool(raw.get("eu_region"), False),
        zero_retention=_bool(raw.get("zero_retention"), False),
    )


def resolve_flags(
    provider: str,
    configured: Mapping[str, ProviderFlags] | None,
) -> ProviderFlags:
    if configured and provider in configured:
        return configured[provider]
    return flags_from_config(provider)


def filter_chain(
    chain: Sequence[ModelRef],
    groups: Sequence[Sequence[str]],
    configured: Mapping[str, ProviderFlags] | None,
) -> list[ModelRef]:
    """Keep providers that satisfy every flag group. A group is OR."""
    if not groups:
        return list(chain)
    kept: list[ModelRef] = []
    for ref in chain:
        meta = resolve_flags(ref.provider, configured)
        if all(meta.allows(group) for group in groups):
            kept.append(ref)
    return kept


def _bool(value: object, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    return default


def _loopback(url: str) -> bool:
    if not url.strip():
        return False
    host = (urlparse(url).hostname or "").lower()
    return host in {"127.0.0.1", "localhost", "::1"}
