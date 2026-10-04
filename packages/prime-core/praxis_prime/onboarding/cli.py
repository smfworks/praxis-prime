"""``praxis-prime setup`` — the terminal wizard. It calls the shared backend."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path

from praxis_prime.accounts.db import AccountError, AccountStore
from praxis_prime.onboarding.messages import cloud_warning
from praxis_prime.onboarding.service import OnboardingError, OnboardingService, Selection
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
        stdout.write(
            "praxis-prime setup: --skip-test cannot mark the provider ready.\n"
        )
        return 2
    if args.web:
        return _web(args, stdout, environ)
    interactive = not args.non_interactive
    if interactive and not _isatty(stdin):
        stdout.write(
            "praxis-prime setup: no terminal. Re-run with --non-interactive,\n"
            "or start praxis-primed and open the web UI.\n"
        )
        return 2
    service = OnboardingService(
        config_dir=_config(args, environ),
        data_dir=_data(args, environ),
        env=environ,
        fetcher=fetcher,
    )
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
        "The daemon listens on 127.0.0.1 only. "
        "A cloud provider sends prompts off this machine.\n"
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
    password = _ask(stdin, stdout, "Owner password: ")
    if not username or not password:
        stdout.write("Owner was not created.\n")
        return 2
    return _create_owner(args, env, username, password, stdout)


def _interactive_models(service, stdin, stdout, status: dict[str, object]) -> None:
    current = status["models"]["primary"]  # type: ignore[index]
    stdout.write(f"Primary model: {current or '(unset)'}\n")
    stdout.write("Lane: 1 On this computer, 2 On my network, 3 Cloud provider, 4 Skip for now.\n")
    choice = _ask(stdin, stdout, "Choice (nothing is preselected): ")
    lanes = {"1": "local", "2": "lan", "3": "cloud", "4": "skip"}
    lane = lanes.get(choice.strip())
    if lane is None:
        stdout.write("No lane chosen. The current provider was left in place.\n")
        return
    if lane == "skip":
        if current and not _yes(stdin, stdout, "Leave inference unconfigured? [y/N] "):
            stdout.write("Left the current provider in place.\n")
            return
        service.save(Selection(lane="skip", replace=bool(current)))
        return
    if lane == "cloud" and status.get("cloudWarning"):
        stdout.write(str(status["cloudWarning"]) + "\n")
    provider = _ask(stdin, stdout, "Provider id (for example ollama, openai, xai): ")
    model = _ask(stdin, stdout, "Primary model id: ")
    base = _ask(stdin, stdout, "Base URL (blank for the preset): ")
    key = _ask(stdin, stdout, "API key (blank to keep the stored key): ")
    utility = _ask(stdin, stdout, "Utility model (blank to skip): ")
    vision = _ask(stdin, stdout, "Vision model (blank to skip): ")
    judge = _ask(stdin, stdout, "Decision Engine judge (blank to skip): ")
    replace = bool(current)
    if replace and not _yes(stdin, stdout, "Replace the current provider? [y/N] "):
        stdout.write("Left the current provider in place.\n")
        return
    service.save(
        Selection(
            lane=lane,
            provider=provider,
            model=model,
            utility_model=utility,
            vision_model=vision,
            judge_model=judge,
            base_url=base,
            api_key=key,
            replace=replace,
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
            "praxis-prime setup: pass --owner-password-stdin. "
            "The password is not an argument.\n"
        )
        return 2
    password = stdin.readline().rstrip("\n")
    return _create_owner(args, env, args.owner, password, stdout)


def _create_owner(args, env, username: str, password: str, stdout) -> int:
    from praxis_prime.profiles.migrate import MigrationBusy, migrate_single_user, migrate_under_lock

    root = _data(args, env)
    config = _config(args, env)
    store = AccountStore(root / "accounts.db")
    try:
        if store.has_accounts():
            invalidate_first_run_token(config)
            stdout.write("praxis-prime setup: an owner already exists. It was left in place.\n")
            return 0
        result = migrate_under_lock(
            root,
            config,
            owner_account="",
            daemon_running=lambda: _daemon_running(env),
        )
        account = store.create_account(
            username_text=username,
            password=password,
            display_name=username,
            role="owner",
        )
        result = migrate_single_user(
            root,
            config,
            owner_account=account.id,
            daemon_running=lambda: False,
        )
        store.set_membership(account.id, result.profile_id, "owner")
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


def _lane_for(provider: str, base_url: str) -> str:
    if provider in {"openai", "anthropic", "xai"}:
        return "cloud"
    host = base_url.split("://", 1)[-1].split("/", 1)[0].split(":")[0].lower()
    if host and host not in {"127.0.0.1", "localhost", "::1"}:
        return "lan"
    return "local"


def _yes(stdin, stdout, prompt: str) -> bool:
    return _ask(stdin, stdout, prompt).strip().lower() in {"y", "yes"}


def _ask(stdin, stdout, prompt: str) -> str:
    stdout.write(prompt)
    stdout.flush()
    line = stdin.readline()
    if line == "":
        raise EOFError
    return line.rstrip("\n")


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
