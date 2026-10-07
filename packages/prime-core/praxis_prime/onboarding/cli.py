"""``praxis-prime setup`` — the terminal wizard. It calls the shared backend."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path

from praxis_prime.accounts.db import AccountError, AccountStore
from praxis_prime.onboarding.messages import cloud_warning
from praxis_prime.onboarding.registry import NO_GPU_NOTE, NO_MATCH, PROVIDERS, ProviderEntry
from praxis_prime.onboarding.registry import lane_for as _lane_for
from praxis_prime.onboarding.service import (
    OnboardingError,
    OnboardingService,
    Selection,
    normalize_server_base,
)
from praxis_prime.onboarding.token import ensure_first_run_token, invalidate_first_run_token
from praxis_prime.paths import config_dir, data_dir, runtime_dir

_SECTIONS = ("models", "owner", "dials", "oidc", "telegram")


def add_setup_parser(commands: argparse._SubParsersAction) -> None:
    setup = commands.add_parser(
        "setup",
        help="Choose an owner and a model provider. Nothing is selected for you.",
    )
    setup.add_argument("--non-interactive", action="store_true")
    setup.add_argument("--section", choices=_SECTIONS)
    setup.add_argument("--web", action="store_true", help="Print the local setup URL.")
    setup.add_argument("--provider", default="")
    setup.add_argument("--model", default="")
    setup.add_argument("--utility-model", default="")
    setup.add_argument("--vision-model", default="")
    setup.add_argument("--judge-model", default="")
    setup.add_argument("--base-url", default="")
    setup.add_argument("--tls-fingerprint", default="")
    setup.add_argument("--lane", choices=("local", "lan", "cloud", "skip"))
    setup.add_argument(
        "--auth",
        default="",
        help="api-key or none. Subscription sign-in is not available yet.",
    )
    setup.add_argument(
        "--list-providers",
        action="store_true",
        help="Print the provider catalog and detection. Changes nothing.",
    )
    setup.add_argument("--json", action="store_true", dest="as_json")
    setup.add_argument("--api-key-env", default="", help="Read the key from this variable.")
    setup.add_argument("--api-key-stdin", action="store_true")
    setup.add_argument("--owner", default="")
    setup.add_argument("--owner-password-stdin", action="store_true")
    setup.add_argument("--replace", action="store_true")
    setup.add_argument(
        "--skip-test",
        action="store_true",
        help="Refused. A skipped test cannot mark the provider ready.",
    )
    setup.add_argument("--config-dir")
    setup.add_argument("--data-dir")


def setup_command(
    args: argparse.Namespace,
    *,
    stdin=None,
    stdout=None,
    env: Mapping[str, str] | None = None,
    fetcher=None,
) -> int:
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    environ = os.environ if env is None else env
    if args.skip_test:
        stdout.write("praxis-prime setup: --skip-test cannot mark the provider ready.\n")
        return 2
    auth = getattr(args, "auth", "") or ""
    folded_auth = auth.strip().lower()
    if folded_auth == "oauth":
        stdout.write("praxis-prime setup: Subscription sign-in is coming in a later release.\n")
        return 2
    if folded_auth and folded_auth not in {"api-key", "api_key", "none"}:
        stdout.write("praxis-prime setup: --auth must be api-key or none.\n")
        return 2
    if args.web:
        return _web(args, stdout, environ)
    service = OnboardingService(
        config_dir=_config(args, environ),
        data_dir=_data(args, environ),
        env=environ,
        fetcher=fetcher,
    )
    if getattr(args, "list_providers", False):
        return _list_providers(service, stdout, bool(getattr(args, "as_json", False)))
    interactive = not args.non_interactive
    if interactive and not _isatty(stdin):
        stdout.write(
            "praxis-prime setup: no terminal. Re-run with --non-interactive,\n"
            "or start praxis-primed and open the web UI.\n"
        )
        return 2
    try:
        if interactive:
            return _interactive(args, service, stdin, stdout, environ)
        return _scripted(args, service, stdin, stdout, environ)
    except OnboardingError as exc:
        stdout.write(f"praxis-prime setup: {exc}\n")
        if exc.code in {"usage", "replace", "allowlist"}:
            return 2
        return 1


def _scripted(args, service: OnboardingService, stdin, stdout, env: Mapping[str, str]) -> int:
    section = args.section or ""
    if section in {"", "owner"} and args.owner:
        code = _create_scripted_owner(args, stdin, stdout, env)
        if code != 0:
            return code
        if section == "owner":
            return 0
    if section == "dials":
        stdout.write("praxis-prime setup: pass dial changes in the interactive wizard.\n")
        return 2
    if section in {"oidc", "telegram"}:
        stdout.write(f"praxis-prime setup: --section {section} is interactive.\n")
        return 2
    if section not in {"", "models"}:
        return 0
    provider = args.provider.strip().lower()
    if not provider:
        stdout.write("praxis-prime setup: --provider is required.\n")
        return 2
    if provider == "skip":
        result = service.save(Selection(lane="skip", replace=args.replace))
        stdout.write("Inference is not configured. Chat will say so until you choose a provider.\n")
        return 0 if result.get("ok") else 1
    key = _scripted_key(args, stdin, stdout, env)
    if key is None:
        return 2
    lane = args.lane or _lane_for(provider, args.base_url)
    result = service.save(
        Selection(
            lane=lane,
            provider=provider,
            model=args.model,
            utility_model=args.utility_model,
            vision_model=args.vision_model,
            judge_model=args.judge_model,
            base_url=args.base_url,
            api_key=key,
            tls_fingerprint=args.tls_fingerprint,
            replace=args.replace,
            auth_method=_auth_value(args),
        )
    )
    stdout.write(f"Inference ready ({result.get('spec', '')}).\n")
    for warning in result.get("warnings") or []:
        stdout.write(f"warning: {warning}\n")
    return 0


def _interactive(args, service: OnboardingService, stdin, stdout, env: Mapping[str, str]) -> int:
    section = args.section or ""
    status = service.status(owner_exists=_has_owner(args, env))
    stdout.write("Praxis Prime setup. Nothing is selected until you choose it.\n")
    stdout.write(
        "The daemon listens on 127.0.0.1 only. A cloud provider sends prompts off this machine.\n"
    )
    warning = cloud_warning(status["dials"])  # type: ignore[arg-type]
    if warning:
        stdout.write(warning + "\n")
    missing = ", ".join(item["id"] for item in status["missing"]) or "none"
    stdout.write(f"Missing: {missing}\n")
    if section in {"", "owner"}:
        code = _interactive_owner(args, stdin, stdout, env)
        if code != 0:
            return code
    if section in {"", "models"}:
        _interactive_models(service, stdin, stdout, status)
    if section in {"", "dials"}:
        _interactive_dials(service, stdin, stdout, status)
    if section in {"", "oidc"} and _yes(stdin, stdout, "Add an OIDC provider now? [y/N] "):
        stdout.write("Use `praxis-prime oidc add` for the full provider form.\n")
    if section in {"", "telegram"} and _yes(stdin, stdout, "Pair Telegram approvals now? [y/N] "):
        _telegram(args, stdout, env)
    ready = service.status(owner_exists=_has_owner(args, env))["inferenceReady"]
    if ready:
        stdout.write("Inference ready.\n")
    else:
        stdout.write(
            "Inference is not configured. Chat will say so until a provider passes its test.\n"
        )
    return 0


def _interactive_owner(args, stdin, stdout, env) -> int:
    if _has_owner(args, env):
        stdout.write("An owner account already exists. It was left in place.\n")
        return 0
    username = _ask(stdin, stdout, "Owner username: ")
    password = _secret(stdin, stdout, "Owner password: ")
    if not username or not password:
        stdout.write("Owner was not created.\n")
        return 2
    return _create_owner(args, env, username, password, stdout)


def _interactive_models(service, stdin, stdout, status: dict[str, object]) -> None:
    current = status["models"]["primary"]  # type: ignore[index]
    stdout.write(f"Primary model: {current or '(unset)'}\n")
    view = service.providers_view()
    detection = view.get("detection")
    if not isinstance(detection, dict):
        detection = {}
    policy = view.get("policy")
    warning = ""
    if isinstance(policy, dict):
        warning = str(policy.get("cloudWarning", "") or "")
    if not warning and status.get("cloudWarning"):
        warning = str(status["cloudWarning"])
    state = "picker"
    search = ""
    entry: ProviderEntry | None = None
    auth = ""
    base = ""
    key = ""
    model = ""
    utility = ""
    vision = ""
    judge = ""
    probed: list[str] = []
    while True:
        if state == "picker":
            shown = _print_picker(stdout, detection, search, warning)
            if not shown:
                stdout.write(NO_MATCH + "\n")
            answer = _ask(stdin, stdout, "Choice (nothing is preselected): ").strip()
            if answer == "b":
                stdout.write("Left the current provider in place.\n")
                return
            if answer == "0":
                if current and not _yes(stdin, stdout, "Leave inference unconfigured? [y/N] "):
                    stdout.write("Left the current provider in place.\n")
                    continue
                service.save(Selection(lane="skip", replace=bool(current)))
                stdout.write("Inference not configured\n")
                return
            if answer == "/":
                search = _ask(stdin, stdout, "Search: ").strip()
                continue
            picked = _entry_by_number(answer, search)
            if picked is None:
                stdout.write("That number is not in the list.\n")
                continue
            entry = picked
            search = ""
            auth = ""
            base = ""
            key = ""
            model = ""
            probed = []
            state = "auth" if entry.id == "xai" else "base"
            continue
        if entry is None:
            state = "picker"
            continue
        if state == "auth":
            _print_xai_auth(stdout)
            answer = _ask(stdin, stdout, "Choice (nothing is preselected): ").strip()
            if answer == "b":
                state = "picker"
                continue
            if answer != "1":
                stdout.write("Subscription sign-in is coming in a later release.\n")
                continue
            auth = "api_key"
            state = "key"
            continue
        if state == "base":
            preset = entry.default_base_url
            if not entry.base_url_editable and preset:
                base = preset
                state = "key"
                continue
            hint = "host:port or URL" if entry.id == "network" else "blank for the preset"
            answer = _ask(stdin, stdout, f"Base URL ({hint}): ")
            if answer.strip() == "b":
                state = "picker"
                continue
            typed = answer.strip() or preset
            if not typed:
                stdout.write("Enter a host and port, or a base URL.\n")
                continue
            try:
                if entry.id in {"openai", "anthropic", "xai"}:
                    base = typed
                else:
                    base = normalize_server_base(typed)
            except OnboardingError as exc:
                stdout.write(f"{exc}\n")
                continue
            state = "key"
            continue
        if state == "key":
            key = _secret(stdin, stdout, "API key (blank to keep the stored key): ")
            if not auth:
                auth = "api_key" if key.strip() and entry.section == "cloud" else ""
            state = "model"
            continue
        if state == "model":
            probed = _model_choices(service, stdout, entry, base)
            chosen = _ask_model(stdin, stdout, entry, probed)
            if chosen is None:
                state = "key"
                continue
            if not chosen:
                stdout.write("A primary model is required.\n")
                continue
            model = chosen
            state = "advanced"
            continue
        if state == "advanced":
            answer = _ask(stdin, stdout, "Advanced roles (utility, vision, judge)? [y/N] ").strip()
            if answer == "b":
                state = "model"
                continue
            if answer.lower() in {"y", "yes"}:
                state = "roles"
                continue
            if not _confirm_replace(stdin, stdout, current):
                return
            _save_interactive(
                service,
                stdout,
                entry,
                base,
                key,
                model,
                utility,
                vision,
                judge,
                auth,
                bool(current),
            )
            return
        if state == "roles":
            utility = _ask(stdin, stdout, "Utility model (blank to skip): ")
            if utility.strip() == "b":
                utility = ""
                state = "advanced"
                continue
            vision = _ask(stdin, stdout, "Vision model (blank to skip): ")
            judge = _ask(stdin, stdout, "Decision Engine judge (blank to skip): ")
            if not _confirm_replace(stdin, stdout, current):
                return
            _save_interactive(
                service,
                stdout,
                entry,
                base,
                key,
                model,
                utility,
                vision,
                judge,
                auth,
                bool(current),
            )
            return


def _list_providers(service: OnboardingService, stdout, as_json: bool) -> int:
    view = service.providers_view()
    if as_json:
        stdout.write(json.dumps(view, indent=2, sort_keys=True) + "\n")
        return 0
    detection = view.get("detection")
    servers: dict[str, object] = {}
    if isinstance(detection, dict):
        raw = detection.get("servers")
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict):
                    servers[str(item.get("provider", ""))] = item
    for section, title in (("local", "Local"), ("cloud", "Cloud")):
        stdout.write(f"{title}\n")
        for index, entry in enumerate(PROVIDERS, start=1):
            if entry.section != section:
                continue
            stdout.write(f"  {index} {entry.display_name} ({entry.id})\n")
            hit = servers.get(entry.id)
            if isinstance(hit, dict):
                models = hit.get("models")
                count = len(models) if isinstance(models, list) else 0
                stdout.write(f"     Running here · {count} models\n")
    return 0


def _auth_value(args) -> str:
    raw = (getattr(args, "auth", "") or "").strip().lower()
    return {"api-key": "api_key", "api_key": "api_key", "none": "none"}.get(raw, "")


def _print_picker(stdout, detection: dict[str, object], search: str, warning: str) -> bool:
    stdout.write("Choose where Praxis thinks\n")
    servers = _server_index(detection)
    env_keys = detection.get("envKeys")
    present = {str(item) for item in env_keys} if isinstance(env_keys, list) else set()
    hardware = detection.get("hardware")
    any_row = False
    for section, title in (("local", "Local"), ("cloud", "Cloud")):
        rows = [
            (index, entry)
            for index, entry in enumerate(PROVIDERS, start=1)
            if entry.section == section and _row_matches(entry, search)
        ]
        if not rows:
            continue
        any_row = True
        stdout.write(f"{title}\n")
        if section == "local" and isinstance(hardware, list) and not hardware:
            stdout.write(NO_GPU_NOTE + "\n")
        for index, entry in rows:
            stdout.write(f"  {index} {entry.display_name}\n")
            stdout.write(f"     {entry.description}\n")
            hit = servers.get(entry.id)
            if isinstance(hit, dict):
                models = hit.get("models")
                count = len(models) if isinstance(models, list) else 0
                stdout.write(f"     Running here · {count} models\n")
            elif entry.detect is not None:
                port = entry.default_base_url.rsplit(":", 1)[-1].split("/", 1)[0]
                if port.isdigit():
                    stdout.write(f"     Not detected (port {port})\n")
            badge = _env_badge(entry, present)
            if badge:
                stdout.write(f"     key found in {badge}\n")
            if section == "cloud" and warning:
                stdout.write(f"     {warning}\n")
    stdout.write("  0 Skip for now\n")
    stdout.write("  b Back, / search\n")
    return any_row


def _server_index(detection: dict[str, object]) -> dict[str, object]:
    found: dict[str, object] = {}
    raw = detection.get("servers")
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                found[str(item.get("provider", ""))] = item
    return found


def _row_matches(entry: ProviderEntry, search: str) -> bool:
    needle = search.strip().lower()
    if not needle:
        return True
    haystack = " ".join((entry.id, entry.display_name, *entry.aliases)).lower()
    return needle in haystack


def _entry_by_number(answer: str, search: str) -> ProviderEntry | None:
    """Stable catalog numbers. A filtered row cannot be chosen by its old number."""
    if not answer.isdigit() or answer == "0":
        return None
    number = int(answer)
    if number < 1 or number > len(PROVIDERS):
        return None
    entry = PROVIDERS[number - 1]
    if not _row_matches(entry, search):
        return None
    return entry


def _env_badge(entry: ProviderEntry, present: set[str]) -> str:
    for method in entry.auth_methods:
        if method.id != "api_key":
            continue
        for name in method.env_names:
            if name in present:
                return name
    return ""


def _print_xai_auth(stdout) -> None:
    stdout.write("How do you want to connect to Grok?\n")
    stdout.write("  Sign in with Grok (SuperGrok / X Premium subscription) [coming soon]\n")
    stdout.write("  1 API key (billed to your xAI API account)\n")
    stdout.write(
        "A SuperGrok or X Premium subscription does not include API credits. "
        "API-key usage is billed separately by xAI, even if you also subscribe.\n"
    )


def _model_choices(
    service: OnboardingService, stdout, entry: ProviderEntry, base: str
) -> list[str]:
    curated = list(entry.model_list.curated)
    if curated and entry.section == "cloud":
        return curated
    if not base:
        return []
    try:
        probed = service.probe_models(entry.id, base)
    except OnboardingError as exc:
        stdout.write(f"{exc}\n")
        return []
    models = probed.get("models")
    if probed.get("ok") and isinstance(models, list):
        return [str(item) for item in models if str(item).strip()]
    return []


def _ask_model(stdin, stdout, entry: ProviderEntry, models: list[str]) -> str | None:
    """Return a model id, or None when the user goes back."""
    default = ""
    if entry.section == "cloud":
        default = str(entry.default_models.get("primary", "") or "")
        if default and default not in models:
            default = ""
    elif len(models) == 1:
        default = models[0]
    if not models:
        stdout.write("The server did not return a model list. Type a model id.\n")
        typed = _ask(stdin, stdout, "Model id: ")
        if typed.strip() == "b":
            return None
        return typed.strip()
    while True:
        stdout.write("Models:\n")
        for index, name in enumerate(models, start=1):
            suffix = " (default)" if name == default else ""
            stdout.write(f"  {index} {name}{suffix}\n")
        stdout.write("  t Type a model id\n")
        if default:
            prompt = f"Choice [{models.index(default) + 1}]: "
        else:
            prompt = "Choice (nothing is preselected): "
        answer = _ask(stdin, stdout, prompt).strip()
        if answer == "b":
            return None
        if answer == "t":
            typed = _ask(stdin, stdout, "Model id: ")
            if typed.strip() == "b":
                return None
            return typed.strip()
        if not answer and default:
            return default
        if answer.isdigit():
            number = int(answer)
            if 1 <= number <= len(models):
                return models[number - 1]
        stdout.write("That number is not in the list.\n")


def _confirm_replace(stdin, stdout, current: object) -> bool:
    if not current:
        return True
    if _yes(stdin, stdout, "Replace the current provider? [y/N] "):
        return True
    stdout.write("Left the current provider in place.\n")
    return False


def _save_interactive(
    service: OnboardingService,
    stdout,
    entry: ProviderEntry,
    base: str,
    key: str,
    model: str,
    utility: str,
    vision: str,
    judge: str,
    auth: str,
    replace: bool,
) -> None:
    service.save(
        Selection(
            lane="",
            provider=entry.id,
            model=model,
            utility_model=utility.strip(),
            vision_model=vision.strip(),
            judge_model=judge.strip(),
            base_url=base,
            api_key=key,
            replace=replace,
            auth_method=auth,
        )
    )


def _interactive_dials(service, stdin, stdout, status: dict[str, object]) -> None:
    dials = status.get("dials")
    if not isinstance(dials, dict):
        return
    stdout.write("Compliance dials stay as they are unless you change one.\n")
    for dial_id, position in sorted(dials.items()):
        stdout.write(f"  {dial_id} = {position}\n")
    raw = _ask(stdin, stdout, "Change (dial=off|monitor|enforce, blank to keep): ")
    if not raw or "=" not in raw:
        return
    dial_id, position = raw.split("=", 1)
    service.set_dials({dial_id.strip(): position.strip()})


def _telegram(args, stdout, env: Mapping[str, str]) -> None:
    from praxis_prime.channels.telegram import PairingStore

    root = _data(args, env)
    store = PairingStore(_state(env), root / "telegram-owner.json")
    code = store.issue()
    stdout.write("Send this to your Praxis Prime bot within 10 minutes:\n")
    stdout.write(f"/pair {code}\n")
    stdout.write("The code was not written to config.toml.\n")


def _daemon_running(env: Mapping[str, str]) -> bool:
    from praxis_prime.gateway.discover import discover

    return discover(env) is not None


def _state(env: Mapping[str, str]) -> Path:
    from praxis_prime.paths import state_dir

    return state_dir(env) / "telegram-pairing.json"


def _create_scripted_owner(args, stdin, stdout, env: Mapping[str, str]) -> int:
    if not args.owner_password_stdin:
        stdout.write(
            "praxis-prime setup: pass --owner-password-stdin. The password is not an argument.\n"
        )
        return 2
    password = stdin.readline().rstrip("\n")
    return _create_owner(args, env, args.owner, password, stdout)


def _create_owner(args, env, username: str, password: str, stdout) -> int:
    from praxis_prime.onboarding.owner import create_owner_account
    from praxis_prime.profiles.migrate import MigrationBusy

    root = _data(args, env)
    config = _config(args, env)
    store = AccountStore(root / "accounts.db")
    try:
        if store.has_accounts():
            invalidate_first_run_token(config)
            stdout.write("praxis-prime setup: an owner already exists. It was left in place.\n")
            return 0
        create_owner_account(
            store,
            root,
            config,
            username=username,
            password=password,
            daemon_running=lambda: _daemon_running(env),
        )
    except (AccountError, MigrationBusy, OSError) as exc:
        stdout.write(f"praxis-prime setup: {exc}\n")
        return 2
    finally:
        store.close()
    invalidate_first_run_token(config)
    stdout.write(f"created owner {username}\n")
    return 0


def _scripted_key(args, stdin, stdout, env: Mapping[str, str]) -> str | None:
    if args.api_key_env and args.api_key_stdin:
        stdout.write("praxis-prime setup: pass only one of --api-key-env and --api-key-stdin.\n")
        return None
    if args.api_key_env:
        value = env.get(args.api_key_env, "").strip()
        if not value:
            stdout.write(f"praxis-prime setup: {args.api_key_env} is empty.\n")
            return None
        return value
    if args.api_key_stdin:
        return stdin.readline().rstrip("\n")
    return ""


def _web(args, stdout, env: Mapping[str, str]) -> int:
    info = runtime_dir(env) / "gateway.json"
    if not info.is_file():
        stdout.write("praxis-prime setup: start praxis-primed, then re-run setup --web.\n")
        return 2
    try:
        payload = json.loads(info.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        stdout.write("praxis-prime setup: the daemon did not publish a port.\n")
        return 2
    port = payload.get("port")
    if not isinstance(port, int):
        stdout.write("praxis-prime setup: the daemon did not publish a port.\n")
        return 2
    root = _data(args, env)
    store = AccountStore(root / "accounts.db")
    try:
        owner = store.has_accounts()
    finally:
        store.close()
    if owner:
        invalidate_first_run_token(_config(args, env))
        stdout.write(f"http://127.0.0.1:{port}/\n")
        stdout.write("An owner already exists. Sign in. The setup token is not used.\n")
        return 0
    token = ensure_first_run_token(_config(args, env))
    stdout.write(f"http://127.0.0.1:{port}/#setup={token}\n")
    stdout.write("The token is in the URL fragment so it is not sent to the server or Referer.\n")
    return 0


def _yes(stdin, stdout, prompt: str) -> bool:
    return _ask(stdin, stdout, prompt).strip().lower() in {"y", "yes"}


def _ask(stdin, stdout, prompt: str) -> str:
    stdout.write(prompt)
    stdout.flush()
    line = stdin.readline()
    if line == "":
        raise EOFError
    return line.rstrip("\n")


def _secret(stdin, stdout, prompt: str) -> str:
    """Read a secret. A terminal uses getpass so the value is not echoed."""
    if not _isatty(stdin):
        return _ask(stdin, stdout, prompt)
    previous = sys.stdin
    sys.stdin = stdin
    try:
        return getpass.getpass(prompt, stream=stdout)
    finally:
        sys.stdin = previous


def _isatty(stdin) -> bool:
    check = getattr(stdin, "isatty", None)
    if not callable(check):
        return False
    return bool(check())


def _config(args, env: Mapping[str, str]) -> Path:
    explicit = getattr(args, "config_dir", None)
    if explicit:
        return Path(explicit)
    return config_dir(env)


def _data(args, env: Mapping[str, str]) -> Path:
    explicit = getattr(args, "data_dir", None)
    if explicit:
        return Path(explicit)
    return data_dir(env)


def _has_owner(args, env: Mapping[str, str]) -> bool:
    path = _data(args, env) / "accounts.db"
    if not path.exists():
        return False
    store = AccountStore(path)
    try:
        return store.has_accounts()
    finally:
        store.close()
