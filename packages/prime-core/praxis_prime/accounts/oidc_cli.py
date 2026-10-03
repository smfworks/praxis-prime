"""``praxis-prime oidc`` commands.

The owner configures providers and can pre-link an identity. The client
secret is read from stdin and stored in the secrets file. It is not a
command argument and it is not printed.

This is the same local-operator trust as ``account passwd``: the person
who can write ``accounts.db``. Linking from the browser still requires a
signed-in session and a step-up.
"""

from __future__ import annotations

import argparse
import re
import sqlite3
import sys
from pathlib import Path

from praxis_prime.accounts.cli import _audit_target, _data
from praxis_prime.accounts.db import Account, AccountError, AccountStore
from praxis_prime.accounts.oidc import (
    ENTRA_ROLE_CLAIM,
    ENTRA_ROLE_MAP,
    OidcError,
    add_provider,
    get_provider,
    list_providers,
    normalize_issuer,
    prelink,
    remove_provider,
    secret_name,
)
from praxis_prime.audit.log import AuditLog
from praxis_prime.channels.secrets import delete_secret, secret_file, write_secret
from praxis_prime.state import DatabaseBusy, StateDB

GOOGLE_ISSUER = "https://accounts.google.com"
_TENANT = re.compile(r"^[A-Za-z0-9.][A-Za-z0-9.-]{0,80}$")
_ROLES = frozenset({"viewer", "auditor", "operator", "admin"})
_TEXT = {
    "provider_exists": "that provider already exists",
    "unknown_provider": "no such provider",
    "url_rejected": "the issuer URL is not allowed",
    "provider_unreachable": "the provider could not be reached",
    "provider_http": "the provider rejected discovery",
    "discovery_issuer": "the discovery document issuer does not match",
    "discovery_endpoint": "the discovery document is missing an endpoint",
    "redirect_refused": "the provider redirected discovery",
    "response_too_large": "the provider response was too large",
    "last_factor": "that would remove the last sign-in factor",
    "identity_taken": "that identity is already linked to another account",
    "issuer_taken": "this account already has an identity from that issuer",
    "bad_request": "the provider settings were rejected",
    "malformed": "the subject was rejected",
    "privileged_link": "an owner or admin account must link while signed in",
}


def add_oidc_parser(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    oidc = commands.add_parser("oidc", help="Configure an OpenID Connect provider.")
    sub = oidc.add_subparsers(dest="oidc_command")
    add = sub.add_parser("add", help="Add a provider. The client secret is read from stdin.")
    add.add_argument("provider_id")
    add.add_argument("--display-name", required=True)
    add.add_argument("--issuer", default="", help="Issuer URL. Presets fill this in.")
    add.add_argument("--client-id", required=True)
    add.add_argument(
        "--preset",
        choices=("google", "entra", "authentik", "keycloak"),
        help="google and entra have a fixed issuer. authentik and keycloak need --issuer.",
    )
    add.add_argument("--tenant", default="", help="Entra tenant id or domain.")
    add.add_argument(
        "--dev-loopback",
        action="store_true",
        help="Allow an http://127.0.0.1 or http://localhost issuer.",
    )
    add.add_argument(
        "--allow-email",
        action="append",
        default=[],
        help="Verified address that may link or create an account. Off when omitted.",
    )
    add.add_argument("--scope", default="openid email profile")
    add.add_argument("--role-claim", default="")
    add.add_argument(
        "--role-map",
        action="append",
        default=[],
        help="VALUE=ROLE. Entra's Praxis.* map is the default for that preset.",
    )
    add.add_argument(
        "--no-role-map",
        action="store_true",
        help="Do not map provider claims onto a Praxis role.",
    )
    add.add_argument(
        "--client-secret-stdin",
        action="store_true",
        help="Read one secret line from stdin. It is not a command argument.",
    )
    _add_dirs(add)
    listing = sub.add_parser("list", help="List providers. Secrets are not printed.")
    _add_dirs(listing)
    remove = sub.add_parser("remove", help="Remove a provider and its linked identities.")
    remove.add_argument("provider_id")
    _add_dirs(remove)
    link = sub.add_parser("link", help="Pre-link an iss+sub identity to an account.")
    link.add_argument("username")
    link.add_argument("--issuer", required=True)
    link.add_argument("--subject", required=True)
    _add_dirs(link)


def oidc_command(args: argparse.Namespace) -> int:
    command = getattr(args, "oidc_command", None)
    if command == "add":
        return _add(args)
    if command == "list":
        return _list(args)
    if command == "remove":
        return _remove(args)
    if command == "link":
        return _link(args)
    print("usage: praxis-prime oidc {add|list|remove|link}", file=sys.stderr)
    return 2


def resolve_provider_settings(
    *,
    preset: str,
    issuer: str,
    tenant: str,
    role_claim: str,
    role_map: list[str],
    no_role_map: bool,
) -> tuple[str, str, str, dict[str, str]]:
    """Issuer, preset, role claim, and role map. No network and no secret."""
    chosen = preset or ""
    given = issuer.strip()
    claim = role_claim.strip()
    mapping = _parse_maps(role_map)
    if no_role_map:
        if mapping:
            raise ValueError("pass either --role-map or --no-role-map")
        claim = ""
        mapping = {}
    elif chosen == "entra" and not mapping:
        claim = claim or ENTRA_ROLE_CLAIM
        mapping = dict(ENTRA_ROLE_MAP)
    if mapping and not claim:
        claim = "roles"
    if chosen == "google":
        fixed = GOOGLE_ISSUER
    elif chosen == "entra":
        if _TENANT.fullmatch(tenant.strip()) is None:
            raise ValueError("entra requires --tenant (letters, digits, dots, and hyphens)")
        fixed = f"https://login.microsoftonline.com/{tenant.strip()}/v2.0"
    elif chosen in {"authentik", "keycloak", ""}:
        fixed = ""
    else:
        raise ValueError("unknown preset")
    if fixed:
        if given and normalize_issuer(given) != fixed:
            raise ValueError("preset issuer does not match --issuer")
        given = fixed
    if not given:
        raise ValueError("an issuer is required")
    return given, chosen, claim, mapping


def _add(args: argparse.Namespace) -> int:
    if not args.client_secret_stdin:
        print("praxis-prime oidc: pass --client-secret-stdin", file=sys.stderr)
        return 2
    try:
        issuer, preset, claim, mapping = resolve_provider_settings(
            preset=args.preset or "",
            issuer=args.issuer,
            tenant=args.tenant,
            role_claim=args.role_claim,
            role_map=list(args.role_map),
            no_role_map=args.no_role_map,
        )
    except ValueError as exc:
        print(f"praxis-prime oidc: {exc}", file=sys.stderr)
        return 2
    secret = _read_secret()
    if secret is None:
        return 2
    store = _store(args)
    owner = store.owner()
    if owner is None or owner.status != "active":
        print("praxis-prime oidc: create the owner account first", file=sys.stderr)
        return 2
    path = secret_file(_config(args))
    key = secret_name(args.provider_id)
    try:
        existing = get_provider(store, args.provider_id)
    except OidcError as exc:
        print(f"praxis-prime oidc: {_explain(exc)}", file=sys.stderr)
        return 2
    if existing is not None:
        print(
            "praxis-prime oidc: that provider already exists. "
            f"Remove it with `praxis-prime oidc remove {args.provider_id}` "
            "and add it again to replace it. "
            "The stored client secret was left unchanged.",
            file=sys.stderr,
        )
        return 2
    try:
        write_secret(path, key, secret)
        add_provider(
            store,
            provider_id=args.provider_id,
            display_name=args.display_name,
            issuer=issuer,
            client_id=args.client_id,
            secret_key=key,
            scopes=args.scope,
            email_allowlist=tuple(args.allow_email),
            role_claim=claim,
            role_map=mapping,
            dev_loopback=bool(args.dev_loopback),
            preset=preset,
        )
    except (OidcError, ValueError, OSError) as exc:
        delete_secret(path, key)
        print(f"praxis-prime oidc: {_explain(exc)}", file=sys.stderr)
        return 2
    _audit(args, owner, "oidc provider added", {"provider": args.provider_id, "issuer": issuer})
    print(f"added {args.provider_id} ({key})")
    return 0


def _list(args: argparse.Namespace) -> int:
    providers = list_providers(_store(args))
    if not providers:
        print("no providers")
        return 0
    for item in providers:
        allow = len(item.email_allowlist)
        print(
            f"{item.id}  {item.display_name}  {item.issuer}  "
            f"{item.client_id}  secret {item.secret_key}  allow {allow}"
        )
    return 0


def _remove(args: argparse.Namespace) -> int:
    store = _store(args)
    owner = store.owner()
    if owner is None or owner.status != "active":
        print("praxis-prime oidc: create the owner account first", file=sys.stderr)
        return 2
    try:
        key = remove_provider(store, args.provider_id)
    except OidcError as exc:
        print(f"praxis-prime oidc: {_explain(exc)}", file=sys.stderr)
        return 2
    delete_secret(secret_file(_config(args)), key)
    _audit(args, owner, "oidc provider removed", {"provider": args.provider_id})
    print(f"removed {args.provider_id}")
    return 0


def _link(args: argparse.Namespace) -> int:
    store = _store(args)
    owner = store.owner()
    if owner is None or owner.status != "active":
        print("praxis-prime oidc: create the owner account first", file=sys.stderr)
        return 2
    try:
        account = prelink(
            store,
            username_text=args.username,
            issuer=args.issuer,
            subject=args.subject,
        )
    except AccountError as exc:
        print(f"praxis-prime oidc: {exc}", file=sys.stderr)
        return 2
    except OidcError as exc:
        print(f"praxis-prime oidc: {_explain(exc)}", file=sys.stderr)
        return 2
    _audit(
        args,
        owner,
        "oidc identity prelinked",
        {"provider": "", "username": account.username, "issuer": normalize_issuer(args.issuer)},
    )
    print(f"linked {account.username}")
    return 0


def _parse_maps(items: list[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise ValueError("--role-map must be VALUE=ROLE")
        raw_value, role = item.split("=", 1)
        if role not in _ROLES:
            raise ValueError("--role-map role must be viewer, auditor, operator, or admin")
        if not raw_value or any(ord(char) < 33 for char in raw_value):
            raise ValueError("--role-map value was rejected")
        mapping[raw_value] = role
    return mapping


def _read_secret() -> str | None:
    line = sys.stdin.readline()
    if line.endswith("\n"):
        line = line[:-1]
    if line.endswith("\r"):
        line = line[:-1]
    if not line:
        print("praxis-prime oidc: the client secret was empty", file=sys.stderr)
        return None
    return line


def _explain(exc: Exception) -> str:
    if isinstance(exc, OidcError):
        return _TEXT.get(exc.reason, "the change could not be completed")
    if isinstance(exc, ValueError):
        text = str(exc)
        if text in {"invalid secret name", "invalid secret value"}:
            return text
        return "the provider settings were rejected"
    return "the provider could not be saved"


def _audit(
    args: argparse.Namespace,
    owner: Account,
    summary: str,
    payload: dict[str, object],
) -> None:
    target = _audit_target(_data(args))
    if target is None:
        return
    path, profile = target
    stamped = {"actor_account": owner.id, "username": owner.username, **payload}
    try:
        db = StateDB(path)
    except (OSError, sqlite3.Error, DatabaseBusy, ValueError) as exc:
        print(f"praxis-prime oidc: audit event was not written ({exc})", file=sys.stderr)
        return
    try:
        AuditLog(db).append(
            session_id=None,
            kind="auth.oidc",
            summary=summary,
            payload=stamped,
            actor_account=owner.id,
            profile=profile,
        )
    except (OSError, sqlite3.Error) as exc:
        print(f"praxis-prime oidc: audit event was not written ({exc})", file=sys.stderr)
    finally:
        db.close()


def _store(args: argparse.Namespace) -> AccountStore:
    return AccountStore(_data(args) / "accounts.db")


def _config(args: argparse.Namespace) -> Path:
    explicit = getattr(args, "config_dir", None)
    if explicit:
        return Path(explicit)
    from praxis_prime.paths import config_dir

    return config_dir()


def _add_dirs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--data-dir", help="Data directory. Defaults to the XDG data path.")
    parser.add_argument("--config-dir", help="Config directory. Defaults to the XDG config path.")
