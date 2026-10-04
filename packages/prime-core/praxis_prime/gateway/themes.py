"""HTTP API for install, select, and lock.

Theme CSS and package assets are public on loopback. They are appearance
only. Install, remove, and lock require an owner or admin. A profile choice
follows the M1 roles: owner and admin for any profile, an operator who is a
profile owner or operator, and never a viewer or auditor. An admin lock
wins, and a non-admin cannot change a profile theme while it is locked.

Addendum A §1.6 and §6.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import parse_qs

from praxis_prime.accounts.db import AccountStore
from praxis_prime.accounts.roles import MANAGE_ROLES
from praxis_prime.audit.log import AuditLog
from praxis_prime.gateway.authz import Denial, Principal, authenticate_http, authorize_action
from praxis_prime.gateway.web import CSP
from praxis_prime.paths import data_dir
from praxis_prime.themes.cssgen import render_css
from praxis_prime.themes.errors import ThemeError, ThemeIssue
from praxis_prime.themes.legacy import hint_theme
from praxis_prime.themes.omarchy import LIVE_ID
from praxis_prime.themes.omarchy import installed as live_installed
from praxis_prime.themes.select import ThemeChoice, resolve_theme, set_lock, set_profile_theme
from praxis_prime.themes.store import (
    InstalledTheme,
    discard_stage,
    files_match_lock,
    find_hash,
    install_files,
    list_themes,
    remove_theme,
    stage_theme,
    sweep_stages,
    take_stage,
    winners,
)
from praxis_prime.themes.tokens import MODE_CHOICES
from praxis_prime.themes.validate import validate_zip

_CSS = re.compile(r"^/themes/([a-z0-9][a-z0-9.-]{0,63})/([0-9a-f]{64})\.css$")
# preview.png and preview.webp are the only gallery names. The validator
# checks their magic bytes and the 1 MiB cap. CSS does not reference them.
_ASSET = re.compile(
    r"^/themes/([a-z0-9][a-z0-9.-]{0,63})/([0-9a-f]{64})/"
    r"(assets/(?:fonts/[A-Za-z0-9._-]{1,80}|ornaments/[A-Za-z0-9._-]{1,80}|preview\.(?:png|webp)))$"
)
_ZIP = frozenset({"application/zip", "application/octet-stream"})
MAX_THEME_BODY = 5 * 1024 * 1024
_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".woff2": "font/woff2",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".webp": "image/webp",
}


def theme_asset_route(method: str, route: str) -> bool:
    if method != "GET":
        return False
    return _CSS.fullmatch(route) is not None or _ASSET.fullmatch(route) is not None


def theme_upload(method: str, route: str, headers: dict[str, str]) -> bool:
    if method != "POST" or route not in {"/v1/themes/install", "/v1/themes/preview"}:
        return False
    media = headers.get("content-type", "").split(";", 1)[0].strip().casefold()
    return media in _ZIP


def theme_zip_denial(headers: dict[str, str]) -> tuple[int, str, str] | None:
    raw = headers.get("content-length", "")
    if raw == "":
        return 400, "bad_request", "theme zip needs a content length"
    try:
        length = int(raw)
    except ValueError:
        return 400, "bad_request", "bad content length"
    if length < 0 or length > MAX_THEME_BODY:
        return 413, "payload_too_large", "theme zip is larger than 5 MiB"
    return None


def load_theme_asset(data_root: Path | None, route: str) -> tuple[bytes, str] | None:
    """Return body and content type when the hash matches an installed package."""
    css = _CSS.fullmatch(route)
    asset = _ASSET.fullmatch(route)
    if css is None and asset is None:
        return None
    match = css or asset
    assert match is not None
    theme_id, digest = match.group(1), match.group(2)
    if ".." in route:
        return None
    installed = _by_hash(data_root, theme_id, digest)
    if installed is None or not files_match_lock(installed, digest):
        return None
    if css is not None:
        body = render_css(installed.package, installed.package_hash).encode("utf-8")
        return body, _TYPES[".css"]
    relative = match.group(3)
    payload = installed.package.files.get(relative)
    if payload is None:
        return None
    return payload, _TYPES.get(Path(relative).suffix.lower(), "application/octet-stream")


def theme_asset_headers() -> list[tuple[str, str]]:
    return [
        ("Content-Security-Policy", CSP),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Cache-Control", "public, max-age=3600"),
    ]


def active_response(
    *,
    accounts: AccountStore | None,
    headers: dict[str, str],
    query: str,
    data_root: Path | None,
    token: str,
    bearer_enabled: bool,
    profile_exists,
    runtime_profile: str,
    multi_profile: bool,
) -> tuple[int, dict[str, object]]:
    """Public when the caller has no session. Otherwise the profile's theme."""
    root = _data(data_root)
    principal = authenticate_http(
        accounts,
        headers,
        "GET",
        bootstrap_token=token,
        bearer_enabled=bearer_enabled,
    )
    if isinstance(principal, Denial):
        return 200, _choice_body(resolve_theme(root, ""))
    profile = _named_profile(headers, query, "")
    denial = authorize_action(
        accounts,
        principal,
        action="read",
        profile=profile,
        profile_exists=profile_exists,
        runtime_profile=runtime_profile,
        multi_profile=multi_profile,
    )
    if not denial.ok:
        return denial.status, _plain(denial.code, denial.message)
    return 200, _choice_body(resolve_theme(root, profile))


def handle_themes(
    *,
    method: str,
    route: str,
    headers: dict[str, str],
    body: bytes,
    query: str,
    principal: Principal,
    profile: str,
    data_root: Path | None,
    audit: AuditLog | None,
    accounts: AccountStore | None,
) -> tuple[int, dict[str, object]] | None:
    if route not in {
        "/v1/themes",
        "/v1/themes/preview",
        "/v1/themes/install",
        "/v1/themes/remove",
        "/v1/themes/lock",
        "/v1/themes/select",
    }:
        return None
    root = _data(data_root)
    try:
        if method == "GET" and route == "/v1/themes":
            return 200, _catalog(root, profile)
        if method == "POST" and route == "/v1/themes/preview":
            return _preview(root, headers, body)
        if method == "POST" and route == "/v1/themes/install":
            return _install(root, headers, body, audit)
        if method == "POST" and route == "/v1/themes/remove":
            return _remove(root, body, audit)
        if method == "POST" and route == "/v1/themes/lock":
            return _lock(root, body, audit, profile)
        if method == "POST" and route == "/v1/themes/select":
            return _select(root, headers, body, query, principal, profile, accounts, audit)
    except ThemeError as exc:
        return _status(exc), exc.to_json()
    return None


def _catalog(root: Path, profile: str) -> dict[str, object]:
    choice = resolve_theme(root, profile)
    lock_id = choice.requested if choice.locked else ""
    chosen = winners(root)
    themes = []
    for item in list_themes(root):
        themes.append(_theme_row(item, selected=chosen.get(item.package.theme_id) is item))
    return {
        "ok": True,
        "lock": {"id": lock_id, "mode": choice.mode if choice.locked else ""},
        "active": _choice_body(choice),
        "themes": themes,
    }


def _preview(root: Path, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, object]]:
    sweep_stages(root)
    _require_zip(headers)
    package = validate_zip(body)
    digest = stage_theme(package, root)
    licenses = [package.license]
    if any(face.path for face in package.font_faces):
        licenses.append("OFL-1.1")
    return 200, {
        "ok": True,
        "id": package.theme_id,
        "version": package.version,
        "name": package.name,
        "packageHash": digest,
        "contrast": package.contrast,
        "licenses": licenses,
        "issues": [],
    }


def _install(
    root: Path,
    headers: dict[str, str],
    body: bytes,
    audit: AuditLog | None,
) -> tuple[int, dict[str, object]]:
    sweep_stages(root)
    media = headers.get("content-type", "").split(";", 1)[0].strip().casefold()
    digest = ""
    try:
        if media in _ZIP:
            package = validate_zip(body)
            installed = install_files(package.files, root)
        else:
            payload = _object(body)
            raw_digest = payload.get("packageHash", "")
            if not isinstance(raw_digest, str):
                raise ThemeError(
                    "packageHash is required",
                    (ThemeIssue("schema", "Send packageHash.", "packageHash"),),
                )
            digest = raw_digest
            staged = take_stage(digest, root)
            if staged is None:
                raise ThemeError(
                    "theme preview expired",
                    (
                        ThemeIssue(
                            "not_found",
                            "Preview that package again. Staged uploads last 15 minutes.",
                            "packageHash",
                        ),
                    ),
                )
            installed = install_files(staged, root)
    except Exception:
        if digest:
            discard_stage(digest, root)
        raise
    if digest:
        discard_stage(digest, root)
    _event(
        audit,
        "theme.install",
        f"installed theme {installed.package.theme_id}",
        {
            "id": installed.package.theme_id,
            "version": installed.package.version,
            "packageHash": installed.package_hash,
            "source": installed.source,
        },
    )
    return 200, {"ok": True, "theme": _theme_row(installed, selected=True)}


def _remove(root: Path, body: bytes, audit: AuditLog | None) -> tuple[int, dict[str, object]]:
    payload = _object(body)
    theme_id = _theme_id(payload.get("id"))
    removed = remove_theme(theme_id, root)
    for item in removed:
        _event(
            audit,
            "theme.remove",
            f"removed theme {item.theme_id}",
            {
                "id": item.theme_id,
                "version": item.version,
                "packageHash": item.package_hash,
            },
        )
    return 200, {"ok": True, "removed": theme_id}


def _lock(
    root: Path,
    body: bytes,
    audit: AuditLog | None,
    profile: str,
) -> tuple[int, dict[str, object]]:
    payload = _object(body)
    theme_id = payload.get("id", "")
    mode = payload.get("mode", "")
    if not isinstance(theme_id, str) or not isinstance(mode, str):
        raise ThemeError("bad lock", (ThemeIssue("schema", "id and mode must be strings.", "id"),))
    if theme_id:
        _theme_id(theme_id)
    set_lock(root, theme_id, mode)
    choice = resolve_theme(root, profile)
    _event(
        audit,
        "theme.activate",
        f"activated theme {choice.theme_id}",
        {
            "id": choice.theme_id,
            "mode": choice.mode,
            "packageHash": choice.installed.package_hash,
            "locked": True,
        },
    )
    return 200, _choice_body(choice)


def _select(
    root: Path,
    headers: dict[str, str],
    body: bytes,
    query: str,
    principal: Principal,
    profile: str,
    accounts: AccountStore | None,
    audit: AuditLog | None,
) -> tuple[int, dict[str, object]]:
    payload = _object(body)
    theme_id = _theme_id(payload.get("id"))
    mode = payload.get("mode", "system")
    if not isinstance(mode, str) or mode not in MODE_CHOICES:
        raise ThemeError("unknown mode",
            (ThemeIssue("schema", "Mode must be light, dark, or system.", "mode"),))
    chosen = _named_profile(headers, query, profile)
    body_profile = payload.get("profile", "")
    if isinstance(body_profile, str) and body_profile and chosen and body_profile != chosen:
        raise ThemeError("id does not match",
            (ThemeIssue("schema", "Profile does not match.", "profile"),))
    if isinstance(body_profile, str) and body_profile:
        chosen = body_profile
    if not chosen:
        raise ThemeError("a profile is required",
            (ThemeIssue("schema", "Name a profile.", "profile"),))
    _may_select(principal, accounts, chosen, root)
    choice = set_profile_theme(root, chosen, theme_id, mode)
    _event(
        audit,
        "theme.activate",
        f"activated theme {choice.theme_id}",
        {
            "id": choice.theme_id,
            "mode": choice.mode,
            "packageHash": choice.installed.package_hash,
            "profile": chosen,
            "locked": choice.locked,
        },
    )
    return 200, _choice_body(choice)


def _may_select(principal: Principal,
    accounts: AccountStore | None,
    profile: str,
    root: Path) -> None:
    from praxis_prime.themes.select import lock_state

    if principal.kind == "legacy" or accounts is None or not accounts.has_accounts():
        return
    locked, _mode = lock_state(root)
    if locked and principal.role not in MANAGE_ROLES:
        raise ThemeError(
            "theme is locked",
            (
                ThemeIssue(
                    "forbidden",
                    "An admin locked the theme. Ask an owner or admin to change it.",
                    profile,
                ),
            ),
        )
    if principal.role in MANAGE_ROLES:
        return
    if principal.role != "operator":
        raise ThemeError(
            "this role cannot set a theme",
            (ThemeIssue("forbidden", "Viewers and auditors cannot set a theme.", profile),),
        )
    membership = accounts.membership(principal.account_id, profile)
    if membership not in {"owner", "operator"}:
        raise ThemeError(
            "this role cannot set a theme",
            (ThemeIssue("forbidden", "A profile viewer cannot set the theme.", profile),),
        )


def _by_hash(data_root: Path | None, theme_id: str, digest: str) -> InstalledTheme | None:
    if theme_id == LIVE_ID:
        live = live_installed()
        if live is not None and live.package_hash == digest:
            return live
        return None
    found = find_hash(data_root, theme_id, digest)
    if found is not None:
        return found
    hinted = hint_theme(_data(data_root), theme_id)
    if hinted is not None and hinted.package_hash == digest:
        return hinted
    return None


def _choice_body(choice: ThemeChoice) -> dict[str, object]:
    package = choice.installed.package
    return {
        "ok": True,
        "id": choice.theme_id,
        "requested": choice.requested,
        "name": package.name,
        "version": package.version,
        "mode": choice.mode,
        "locked": choice.locked,
        "source": choice.installed.source,
        "contrast": package.contrast,
        "packageHash": choice.installed.package_hash,
        "css": choice.css_path,
    }


def _theme_row(item: InstalledTheme, *, selected: bool) -> dict[str, object]:
    package = item.package
    return {
        "id": package.theme_id,
        "name": package.name,
        "version": package.version,
        "description": package.description,
        "source": item.source,
        "contrast": package.contrast,
        "packageHash": item.package_hash,
        "builtin": item.source == "builtin",
        "selected": selected,
        "css": f"/themes/{package.theme_id}/{item.package_hash}.css",
    }


def _require_zip(headers: dict[str, str]) -> None:
    if not theme_upload("POST", "/v1/themes/preview", headers):
        raise ThemeError(
            "preview expects a theme zip",
            (ThemeIssue("file_type", "Send the .zip as application/zip.", "body"),),
        )


def _object(body: bytes) -> dict[str, object]:
    try:
        loaded = json.loads(body.decode("utf-8") or "{}")
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ThemeError("body must be JSON",
            (ThemeIssue("schema", "Send a JSON object.", "body"),)) from exc
    if not isinstance(loaded, dict):
        raise ThemeError("body must be an object",
            (ThemeIssue("schema", "Send a JSON object.", "body"),))
    return loaded


def _theme_id(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,63}", value) is None:
        raise ThemeError("bad theme id",
            (ThemeIssue("bad_id", "Theme id is missing or illegal.", "id"),))
    return value


def _named_profile(headers: dict[str, str], query: str, fallback: str) -> str:
    names = []
    header = headers.get("x-praxis-profile", "").strip()
    if header:
        names.append(header)
    parsed = parse_qs(query, keep_blank_values=False)
    for item in parsed.get("profile", []):
        if item:
            names.append(item)
    if fallback:
        names.append(fallback)
    if len(set(names)) > 1:
        raise ThemeError("id does not match",
            (ThemeIssue("schema", "Profile does not match.", "profile"),))
    return names[0] if names else ""


def _event(audit: AuditLog | None, kind: str, summary: str, payload: dict[str, object]) -> None:
    if audit is None:
        return
    audit.append(session_id=None, kind=kind, summary=summary, payload=payload)


def _data(data_root: Path | None) -> Path:
    if data_root is None:
        return data_dir()
    return Path(data_root)


def _status(exc: ThemeError) -> int:
    codes = {issue.code for issue in exc.issues}
    if "not_found" in codes:
        return 404
    if "forbidden" in codes:
        return 403
    if codes & {"zip_too_large", "file_too_large", "zip_too_many"}:
        return 413
    return 400


def _plain(code: str, message: str) -> dict[str, object]:
    return {"ok": False, "error": {"code": code, "message": message}}
