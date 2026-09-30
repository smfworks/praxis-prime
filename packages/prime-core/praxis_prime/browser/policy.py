"""Browser action policy.

Domain allow and deny lists come from config. Deny wins. Form submits,
logins, downloads, and purchase or payment-like pages always ask.
Page text is untrusted; this module only classifies the action.

ARCHITECTURE §13.2 and §16.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlparse

from praxis_prime.tools.builtin import validate_fetch_url
from praxis_prime.tools.registry import PreparedCall, Risk

ACTIONS = frozenset(
    {
        "navigate",
        "snapshot",
        "click",
        "type",
        "screenshot",
        "extract",
        "close",
        "submit",
        "login",
        "download",
        "purchase",
    }
)
_READ_ACTIONS = frozenset({"navigate", "snapshot", "screenshot", "extract", "close"})
_PAYMENT = re.compile(
    r"(?i)(checkout|payment|billing|\bcart\b|subscribe|purchase|/pay\b|buy-now|add-to-cart)"
)
_LOGIN = re.compile(r"(?i)(log[\s-]?in|sign[\s-]?in|\boauth\b|password|\bsso\b)")
_DOWNLOAD = re.compile(r"(?i)\bdownload\b")
_SUBMIT = re.compile(r"(?i)(\bsubmit\b|type=submit)")
_CARD = re.compile(r"(?:\d[ -]?){13,19}")


@dataclass(frozen=True, slots=True)
class BrowserPolicy:
    allow_domains: tuple[str, ...] = ()
    deny_domains: tuple[str, ...] = ()
    profile: str = "disposable"

    @property
    def persistent(self) -> bool:
        return self.profile == "persistent"


def classify_browser(
    arguments: Mapping[str, object],
    policy: BrowserPolicy,
    *,
    page_url: str = "",
) -> PreparedCall:
    """Classify one browser action. Denied domains raise ``ValueError``."""
    action = _action(arguments.get("action"))
    url = _text(arguments.get("url"))
    selector = _text(arguments.get("selector"))
    typed = _text(arguments.get("text"))
    if url:
        check_url(url, policy)
    if page_url and action != "navigate":
        check_url(page_url, policy)

    payment = action in {"purchase", "pay"} or _hit(_PAYMENT, url, page_url, selector)
    login = action == "login" or _hit(_LOGIN, url, page_url, selector)
    download = action == "download" or (
        action == "click" and _DOWNLOAD.search(selector) is not None
    )
    submit = action == "submit" or (action == "click" and _SUBMIT.search(selector) is not None)
    card = action == "type" and _CARD.search(typed) is not None

    if payment or card:
        risk = Risk.SPEND
        reason = "payment or purchase pages always need approval"
    elif login:
        risk = Risk.SEND
        reason = "login actions always need approval"
    elif download:
        risk = Risk.SEND
        reason = "downloads always need approval"
    elif submit:
        risk = Risk.SEND
        reason = "form submits always need approval"
    elif action in {"click", "type"}:
        risk = Risk.DRAFT
        reason = ""
    elif action in _READ_ACTIONS:
        risk = Risk.READ
        reason = ""
    else:
        risk = Risk.READ
        reason = ""

    force = bool(reason)
    return PreparedCall(
        risk=risk,
        sandboxed=True,
        force_approval=force,
        force_reason=reason,
        summary=_summary(
            action, url or page_url, selector, typed, redact=force or login or payment
        ),
    )


def check_url(url: str, policy: BrowserPolicy) -> str:
    """Return the URL when the host is allowed. Raise ``ValueError`` when it is not."""
    cleaned = validate_fetch_url(url)
    host = (urlparse(cleaned).hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("browser URL needs a host")
    if any(_host_matches(host, rule) for rule in policy.deny_domains):
        raise ValueError(f"browser host {host} is denied")
    if policy.allow_domains and not any(_host_matches(host, rule) for rule in policy.allow_domains):
        raise ValueError(f"browser host {host} is not in the allow list")
    return cleaned


def _host_matches(host: str, rule: str) -> bool:
    cleaned = rule.strip().lower().lstrip(".").rstrip(".")
    if cleaned.startswith("*."):
        cleaned = cleaned[2:]
    if not cleaned:
        return False
    return host == cleaned or host.endswith("." + cleaned)


def _action(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("browser requires an action")
    action = value.strip().lower()
    if action not in ACTIONS:
        raise ValueError(f"unknown browser action {action}")
    return action


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _hit(pattern: re.Pattern[str], *parts: str) -> bool:
    return any(pattern.search(part) for part in parts if part)


def _summary(action: str, url: str, selector: str, typed: str, *, redact: bool) -> str:
    bits = [action]
    if url:
        bits.append(url[:120])
    if selector:
        bits.append(selector[:60])
    if typed:
        bits.append("[redacted]" if redact else typed[:40])
    return " ".join(bits)[:180]
