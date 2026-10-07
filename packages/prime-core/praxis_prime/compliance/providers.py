"""Provider flags used when an enforce dial pins model routing.

Flags are metadata on the owner's config. They are not a claim that a
vendor has signed a BAA or hosts data in the EU.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

from praxis_prime.locality import host_of, locality

if TYPE_CHECKING:
    from praxis_prime.router.types import ModelRef

# Local-section adapter ids. Every other provider stays non-local and must
# not resolve DNS from this module.
_ADDRESS_LOCAL = frozenset(
    {
        "ollama",
        "openai-compatible",
        "llamacpp",
        "vllm",
        "lmstudio",
        "network",
    }
)


@dataclass(frozen=True, slots=True)
class ProviderFlags:
    local: bool = False
    baa: bool = False
    eu_region: bool = False
    zero_retention: bool = False
    # Metadata for the request-time re-check. Not part of equality or repr,
    # and not part of ``as_dict``.
    base_url: str = field(default="", compare=False, repr=False)
    trusted_hosts: tuple[str, ...] = field(default=(), compare=False, repr=False)
    local_explicit: bool = field(default=False, compare=False, repr=False)

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
    trusted_hosts: Sequence[str] = (),
) -> ProviderFlags:
    """Owner flags, with a locality default for local-section adapters.

    An explicit boolean ``local`` in the owner's table wins. Otherwise
    ``ollama``, ``openai-compatible``, and the other local-section adapter
    ids are local only when the base URL is loopback (or unspecified), or
    when it is lan and its host is in ``trusted_hosts``. A trusted host
    that classifies as cloud is still not local. An empty base URL is not
    local. Every other provider defaults to not local and is not resolved.
    """
    raw = table or {}
    explicit = isinstance(raw.get("local"), bool)
    hosts = _normalize_trusted(trusted_hosts)
    if explicit:
        local = bool(raw.get("local"))
    elif name in _ADDRESS_LOCAL:
        local = _address_is_local(base_url, hosts)
    else:
        local = False
    return ProviderFlags(
        local=local,
        baa=_bool(raw.get("baa"), False),
        eu_region=_bool(raw.get("eu_region"), False),
        zero_retention=_bool(raw.get("zero_retention"), False),
        base_url=base_url,
        trusted_hosts=hosts,
        local_explicit=explicit,
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
    """Keep providers that satisfy every flag group. A group is OR.

    When a group requires ``local`` and that flag came from the address
    default (not an explicit boolean), a hostname is classified again.
    An IP literal is not looked up. DNS can still change between this
    check and the socket the HTTP client opens. A strict deployment should
    use an IP-literal base URL, or list a static name in
    ``trusted_inference_hosts`` and pin that name outside the public resolver.
    """
    if not groups:
        return list(chain)
    needs_local = any("local" in group for group in groups)
    kept: list[ModelRef] = []
    for ref in chain:
        meta = resolve_flags(ref.provider, configured)
        if needs_local:
            meta = _recheck_local(meta)
        if all(meta.allows(group) for group in groups):
            kept.append(ref)
    return kept


def _bool(value: object, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    return default


def _address_is_local(base_url: str, trusted: tuple[str, ...]) -> bool:
    """True when the base is loopback, or lan and listed as trusted."""
    if not base_url.strip():
        return False
    kind = locality(base_url)
    if kind == "local":
        return True
    if kind != "lan":
        return False
    return host_of(base_url) in trusted


def _recheck_local(meta: ProviderFlags) -> ProviderFlags:
    """Drop a stale local default when a hostname no longer qualifies."""
    if not meta.local or meta.local_explicit:
        return meta
    host = host_of(meta.base_url)
    if not host or _is_ip_literal(host):
        return meta
    if _address_is_local(meta.base_url, meta.trusted_hosts):
        return meta
    return replace(meta, local=False)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return False
    return True


def _normalize_trusted(hosts: Sequence[str]) -> tuple[str, ...]:
    found: list[str] = []
    for item in hosts:
        if not isinstance(item, str):
            continue
        text = item.strip().lower().rstrip(".")
        if text.startswith("[") and text.endswith("]") and len(text) >= 2:
            text = text[1:-1].strip()
        if "%" in text:
            text = text.split("%", 1)[0]
        if not text or text in found:
            continue
        found.append(text)
    return tuple(found)
