"""Provider catalog for setup. Pure data: no I/O, no secrets, no network.

The legacy names (``CLOUD_PROVIDERS``, ``LOCAL_PROVIDERS``, ``KEY_NAMES``,
``CLOUD_BASES``, ``REQUIRED_KEY``, ``local_servers``, ``lane_for``) are
derived from this catalog. They stay equal to the values shipped before the
picker so existing imports keep working. ``network`` and
``openai-compatible-cloud`` share the ``openai-compatible`` adapter and key.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

AuthId = Literal["none", "api_key", "oauth"]
Section = Literal["local", "cloud"]
Parser = Literal["openai", "ollama"]


@dataclass(frozen=True)
class OAuthSpec:
    """Declared for later sign-in work. No PR1 entry fills this in."""

    issuer: str
    client_id: str
    scopes: tuple[str, ...]
    flows: tuple[str, ...]
    referrer: str
    allowed_hosts: tuple[str, ...]
    inference_base_url: str
    inference_hosts: tuple[str, ...]


@dataclass(frozen=True)
class AuthMethod:
    id: AuthId
    label: str
    note: str
    secret_name: str = ""
    env_names: tuple[str, ...] = ()
    oauth: OAuthSpec | None = None
    experimental: bool = False
    regulated_ok: bool = True
    available: bool = True


@dataclass(frozen=True)
class ModelList:
    supported: bool
    path: str
    parser: Parser
    by_auth: Mapping[str, str] | None = None
    curated: tuple[str, ...] = ()


@dataclass(frozen=True)
class DetectSpec:
    base: str
    models_path: str
    props_path: str = ""


@dataclass(frozen=True)
class ProviderEntry:
    id: str
    adapter: str
    display_name: str
    aliases: tuple[str, ...]
    section: Section
    description: str
    auth_methods: tuple[AuthMethod, ...]
    default_base_url: str
    base_url_editable: bool
    detect: DetectSpec | None
    model_list: ModelList
    default_models: Mapping[str, str]
    docs_url: str
    key_url: str = ""


def _none(label: str = "No API key") -> AuthMethod:
    return AuthMethod(id="none", label=label, note="")


def _key(
    secret: str,
    env_names: tuple[str, ...],
    *,
    label: str = "API key",
    note: str = "",
    available: bool = True,
) -> AuthMethod:
    return AuthMethod(
        id="api_key",
        label=label,
        note=note,
        secret_name=secret,
        env_names=env_names,
        available=available,
    )


_COMPAT_KEY = "PRAXIS_PRIME_OPENAI_COMPATIBLE_API_KEY"
_COMPAT_ENV = (_COMPAT_KEY,)
_XAI_CURATED = ("grok-4.7", "grok-4.6", "grok-4.5", "grok-build-0.1", "grok-4.3")
_XAI_BILLING = (
    "A SuperGrok or X Premium subscription does not include API credits. "
    "API-key usage is billed separately by xAI, even if you also subscribe."
)

PROVIDERS: tuple[ProviderEntry, ...] = (
    ProviderEntry(
        id="ollama",
        adapter="ollama",
        display_name="Ollama",
        aliases=("ollama",),
        section="local",
        description="This computer",
        auth_methods=(
            _none("No API key (a key is optional)"),
            _key("PRAXIS_PRIME_OLLAMA_API_KEY", ("PRAXIS_PRIME_OLLAMA_API_KEY",)),
        ),
        default_base_url="http://127.0.0.1:11434",
        base_url_editable=True,
        detect=DetectSpec("http://127.0.0.1:11434", "/api/tags", ""),
        model_list=ModelList(True, "/api/tags", "ollama"),
        default_models={},
        docs_url="",
    ),
    ProviderEntry(
        id="lmstudio",
        adapter="openai-compatible",
        display_name="LM Studio",
        aliases=("lm studio", "lmstudio", "lm-studio"),
        section="local",
        description="This computer",
        auth_methods=(_none(), _key(_COMPAT_KEY, _COMPAT_ENV)),
        default_base_url="http://127.0.0.1:1234",
        base_url_editable=True,
        detect=DetectSpec("http://127.0.0.1:1234", "/v1/models", ""),
        model_list=ModelList(True, "/v1/models", "openai"),
        default_models={},
        docs_url="",
    ),
    ProviderEntry(
        id="llamacpp",
        adapter="openai-compatible",
        display_name="llama.cpp server",
        aliases=("llama.cpp", "llamacpp", "llama cpp", "llama_cpp"),
        section="local",
        description="This computer",
        auth_methods=(_none(), _key(_COMPAT_KEY, _COMPAT_ENV)),
        default_base_url="http://127.0.0.1:8080",
        base_url_editable=True,
        detect=DetectSpec("http://127.0.0.1:8080", "/v1/models", "/props"),
        model_list=ModelList(True, "/v1/models", "openai"),
        default_models={},
        docs_url="",
    ),
    ProviderEntry(
        id="vllm",
        adapter="openai-compatible",
        display_name="vLLM",
        aliases=("vllm",),
        section="local",
        description="This computer",
        auth_methods=(_none(), _key(_COMPAT_KEY, _COMPAT_ENV)),
        default_base_url="http://127.0.0.1:8000",
        base_url_editable=True,
        detect=DetectSpec("http://127.0.0.1:8000", "/v1/models", ""),
        model_list=ModelList(True, "/v1/models", "openai"),
        default_models={},
        docs_url="",
    ),
    ProviderEntry(
        id="openai-compatible",
        adapter="openai-compatible",
        display_name="Other OpenAI-compatible server",
        aliases=("openai-compatible", "compatible", "custom"),
        section="local",
        description="This computer or your network",
        auth_methods=(
            _none(),
            _key(_COMPAT_KEY, _COMPAT_ENV, label="API key (optional)"),
        ),
        default_base_url="",
        base_url_editable=True,
        detect=None,
        model_list=ModelList(True, "/v1/models", "openai"),
        default_models={},
        docs_url="",
    ),
    ProviderEntry(
        id="network",
        adapter="openai-compatible",
        display_name="Network server (OpenAI-compatible)",
        aliases=(
            "network",
            "lan",
            "remote",
            "sglang",
            "vllm",
            "glm",
            "openai-compatible",
        ),
        section="local",
        description="Another machine on your network: vLLM, SGLang, llama.cpp, Ollama…",
        auth_methods=(
            _none(),
            _key(_COMPAT_KEY, _COMPAT_ENV, label="API key (optional)"),
        ),
        default_base_url="",
        base_url_editable=True,
        detect=None,
        model_list=ModelList(True, "/v1/models", "openai"),
        default_models={},
        docs_url="",
    ),
    ProviderEntry(
        id="xai",
        adapter="xai",
        display_name="xAI (Grok)",
        aliases=("grok", "x.ai", "xai", "grok-xai"),
        section="cloud",
        description="Sign in with Grok or API key",
        auth_methods=(
            _key(
                "PRAXIS_PRIME_XAI_API_KEY",
                ("XAI_API_KEY", "PRAXIS_PRIME_XAI_API_KEY"),
                label="API key (billed to your xAI API account)",
                note=_XAI_BILLING,
            ),
            AuthMethod(
                id="oauth",
                label="Sign in with Grok (SuperGrok / X Premium subscription)",
                note="Coming soon",
                available=False,
            ),
        ),
        default_base_url="https://api.x.ai/v1",
        base_url_editable=False,
        detect=None,
        model_list=ModelList(
            True,
            "/v1/models",
            "openai",
            by_auth={"api_key": "/v1/language-models"},
            curated=_XAI_CURATED,
        ),
        default_models={"primary": "grok-4.7"},
        docs_url="",
        key_url="https://console.x.ai/",
    ),
    ProviderEntry(
        id="openai",
        adapter="openai",
        display_name="OpenAI",
        aliases=("openai", "gpt", "chatgpt"),
        section="cloud",
        description="API key",
        auth_methods=(
            _key(
                "PRAXIS_PRIME_OPENAI_API_KEY",
                ("OPENAI_API_KEY", "PRAXIS_PRIME_OPENAI_API_KEY"),
            ),
        ),
        default_base_url="https://api.openai.com/v1",
        base_url_editable=False,
        detect=None,
        model_list=ModelList(True, "/v1/models", "openai"),
        default_models={},
        docs_url="",
        key_url="https://platform.openai.com/api-keys",
    ),
    ProviderEntry(
        id="anthropic",
        adapter="anthropic",
        display_name="Anthropic",
        aliases=("anthropic", "claude"),
        section="cloud",
        description="API key",
        auth_methods=(
            _key(
                "PRAXIS_PRIME_ANTHROPIC_API_KEY",
                ("ANTHROPIC_API_KEY", "PRAXIS_PRIME_ANTHROPIC_API_KEY"),
            ),
        ),
        default_base_url="https://api.anthropic.com",
        base_url_editable=False,
        detect=None,
        model_list=ModelList(True, "/v1/models", "openai"),
        default_models={},
        docs_url="",
        key_url="https://console.anthropic.com/settings/keys",
    ),
    ProviderEntry(
        id="openai-compatible-cloud",
        adapter="openai-compatible",
        display_name="Other OpenAI-compatible cloud",
        aliases=("openai-compatible-cloud", "compatible cloud", "custom cloud"),
        section="cloud",
        description="Base URL + API key",
        auth_methods=(_key(_COMPAT_KEY, _COMPAT_ENV),),
        default_base_url="",
        base_url_editable=True,
        detect=None,
        model_list=ModelList(True, "/v1/models", "openai"),
        default_models={},
        docs_url="",
    ),
)

# Ids that fold onto the shared OpenAI-compatible adapter and key slot.
_FOLDED = {
    "network": "openai-compatible",
    "openai-compatible-cloud": "openai-compatible",
}

# Historical order. New wizard ids fold away and do not extend these tuples.
_CLOUD_ORDER = ("openai", "anthropic", "xai", "openai-compatible")
_LOCAL_ORDER = ("ollama", "llamacpp", "vllm", "lmstudio", "openai-compatible")
_DETECT_ORDER = ("ollama", "llamacpp", "vllm", "lmstudio")
_ENV_ORDER = (
    "OPENAI_API_KEY",
    "PRAXIS_PRIME_OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "PRAXIS_PRIME_ANTHROPIC_API_KEY",
    "XAI_API_KEY",
    "PRAXIS_PRIME_XAI_API_KEY",
    "PRAXIS_PRIME_OPENAI_COMPATIBLE_API_KEY",
    "PRAXIS_PRIME_OLLAMA_API_KEY",
)
_LEGACY_KEY_IDS = frozenset(
    {
        "openai",
        "anthropic",
        "xai",
        "openai-compatible",
        "llamacpp",
        "vllm",
        "lmstudio",
        "ollama",
    }
)
_LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})
NO_GPU_NOTE = (
    "No GPU detected. Local models will run on the CPU and may be slow. "
    "A small model, a server on your network, or a cloud provider may work better."
)
NO_MATCH = (
    "No match. Use 'Other OpenAI-compatible server' for anything that speaks /v1/chat/completions."
)


def by_id(provider: str) -> ProviderEntry | None:
    text = provider.strip().lower()
    for entry in PROVIDERS:
        if entry.id == text:
            return entry
    return None


def resolve_alias(text: str) -> ProviderEntry | None:
    """Match an id, display name, or search alias. Case-insensitive."""
    raw = text.strip().lower()
    if not raw:
        return None
    for entry in PROVIDERS:
        if entry.id == raw or entry.display_name.lower() == raw:
            return entry
        if raw in {alias.lower() for alias in entry.aliases}:
            return entry
    return None


def storage_id(provider: str) -> str:
    """Id written to config. Folded entries use the shared adapter name."""
    text = provider.strip().lower()
    return _FOLDED.get(text, text)


def section_of(provider: str) -> str:
    entry = by_id(provider)
    if entry is not None:
        return entry.section
    if provider in {"openai", "anthropic", "xai"}:
        return "cloud"
    return "local"


def _cloud_ids() -> set[str]:
    found: set[str] = set()
    for entry in PROVIDERS:
        if entry.section == "cloud":
            found.add(storage_id(entry.id))
        if entry.id == "openai-compatible":
            found.add(entry.id)
    return found


def _local_ids() -> set[str]:
    found: set[str] = set()
    for entry in PROVIDERS:
        if entry.section == "local":
            found.add(storage_id(entry.id))
    return found


CLOUD_PROVIDERS: tuple[str, ...] = tuple(name for name in _CLOUD_ORDER if name in _cloud_ids())
LOCAL_PROVIDERS: tuple[str, ...] = tuple(name for name in _LOCAL_ORDER if name in _local_ids())


def _secret_for(entry: ProviderEntry) -> str:
    for method in entry.auth_methods:
        if method.id == "api_key" and method.secret_name:
            return method.secret_name
    return ""


def _key_names() -> dict[str, str]:
    names: dict[str, str] = {}
    for entry in PROVIDERS:
        secret = _secret_for(entry)
        if not secret:
            continue
        if entry.id in _LEGACY_KEY_IDS:
            names[entry.id] = secret
        legacy = storage_id(entry.id)
        if legacy in _LEGACY_KEY_IDS:
            names.setdefault(legacy, secret)
    return names


KEY_NAMES: dict[str, str] = _key_names()


def _cloud_bases() -> dict[str, str]:
    bases: dict[str, str] = {}
    for entry in PROVIDERS:
        if entry.section == "cloud" and entry.default_base_url and not entry.base_url_editable:
            bases[entry.id] = entry.default_base_url
    return bases


CLOUD_BASES: dict[str, str] = _cloud_bases()


def _required_key() -> set[str]:
    found: set[str] = set()
    for entry in PROVIDERS:
        if entry.section != "cloud":
            continue
        if entry.id not in {"openai", "anthropic", "xai"}:
            continue
        available = [method for method in entry.auth_methods if method.available]
        if any(method.id == "none" for method in available):
            continue
        if any(method.id == "api_key" for method in available):
            found.add(entry.id)
    return found


REQUIRED_KEY: set[str] = _required_key()


def local_servers() -> tuple[tuple[str, str, str, str], ...]:
    """``(provider, base, models path, props path)`` in the historical order."""
    found = {entry.id: entry for entry in PROVIDERS}
    rows: list[tuple[str, str, str, str]] = []
    for provider_id in _DETECT_ORDER:
        entry = found[provider_id]
        spec = entry.detect
        if spec is None:
            continue
        rows.append((entry.id, spec.base, spec.models_path, spec.props_path))
    return tuple(rows)


def key_env_names() -> tuple[str, ...]:
    present: set[str] = set()
    for entry in PROVIDERS:
        for method in entry.auth_methods:
            present.update(method.env_names)
    return tuple(name for name in _ENV_ORDER if name in present)


def lane_for(provider: str, base_url: str) -> str:
    """Lane derived from the provider section and the base host.

    Cloud-section entries are ``cloud``. Any other host outside loopback is
    ``lan``. An empty host stays ``local``. This matches the pre-picker
    ``_lane_for`` results for every provider id that existed then.
    """
    entry = by_id(provider)
    if entry is not None and entry.section == "cloud":
        return "cloud"
    if provider in {"openai", "anthropic", "xai"}:
        return "cloud"
    host = _lane_host(base_url)
    if host and host not in _LOOPBACK:
        return "lan"
    return "local"


def _lane_host(base_url: str) -> str:
    """Host split used by the historical lane helper."""
    return base_url.split("://", 1)[-1].split("/", 1)[0].split(":")[0].lower()


def curated_models(provider: str) -> tuple[str, ...]:
    entry = by_id(provider)
    if entry is None:
        return ()
    return entry.model_list.curated


def default_primary(provider: str) -> str:
    entry = by_id(provider)
    if entry is None:
        return ""
    return str(entry.default_models.get("primary", "") or "")


def models_path(provider: str) -> str:
    entry = by_id(provider) or by_id(storage_id(provider))
    if entry is None or not entry.model_list.path:
        return "/v1/models"
    return entry.model_list.path


def public_provider(entry: ProviderEntry) -> dict[str, object]:
    """JSON for the setup API. Names only. No key values and no OAuth client."""
    port = _port(entry.default_base_url)
    return {
        "id": entry.id,
        "adapter": entry.adapter,
        "displayName": entry.display_name,
        "aliases": list(entry.aliases),
        "section": entry.section,
        "description": entry.description,
        "authMethods": [
            {
                "id": method.id,
                "label": method.label,
                "note": method.note,
                "secretName": method.secret_name,
                "envNames": list(method.env_names),
                "experimental": method.experimental,
                "regulatedOk": method.regulated_ok,
                "available": method.available,
            }
            for method in entry.auth_methods
        ],
        "defaultBaseUrl": entry.default_base_url,
        "baseUrlEditable": entry.base_url_editable,
        "port": port,
        "modelList": {
            "supported": entry.model_list.supported,
            "path": entry.model_list.path,
            "parser": entry.model_list.parser,
            "curated": list(entry.model_list.curated),
        },
        "defaultModels": {key: str(value) for key, value in entry.default_models.items()},
        "docsUrl": entry.docs_url,
        "keyUrl": entry.key_url,
        "detected": entry.detect is not None,
    }


def _port(base: str) -> int | None:
    if ":" not in base:
        return None
    tail = base.rsplit(":", 1)[-1].split("/", 1)[0]
    if tail.isdigit():
        return int(tail)
    return None


def env_badge(entry: ProviderEntry, present: set[str]) -> str:
    """Env var name to show, or empty. Never a value."""
    for method in entry.auth_methods:
        if method.id != "api_key":
            continue
        for name in method.env_names:
            if name in present:
                return name
    return ""


def resolve_auth(provider: str, requested: str, lane: str) -> str:
    """``none`` or ``api_key``. OAuth is refused by the caller before this."""
    text = requested.strip().lower().replace("-", "_")
    if text in {"api_key", "none"}:
        return text
    entry = by_id(provider)
    if entry is not None and entry.section == "cloud":
        return "api_key"
    if lane == "cloud":
        return "api_key"
    return "none"
