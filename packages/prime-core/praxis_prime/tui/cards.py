"""Approval card for the terminal.

Fields are one line each. Risk, sandbox, and the host warning come before
the action, so a long action cannot push the dangerous part off the card.
Long fields are capped; the full text is a separate screen.
"""

from __future__ import annotations

from praxis_prime.approvals.card import HOST_FULL_WRITE
from praxis_prime.sanitize import sanitize

FIELD_LIMIT = 300
ACTION_LIMIT = 200
_CAPPED = ("id", "tool", "risk", "summary", "reason", "sessionId", "requester", "mount")


def scope_label(item: dict[str, object]) -> str:
    """What ``allow_session`` actually grants for this card.

    The daemon stores the grant on the approval's session. An empty session
    uses the process-wide bucket.
    """
    session = sanitize(item.get("sessionId") or "", newlines=False).strip()
    if session:
        return f"Always allow in session {session}"
    return "Always allow for this daemon process"


def clip(text: str, limit: int) -> str:
    """Keep ``limit`` characters and append ``...N more`` for the rest."""
    if len(text) <= limit:
        return text
    return f"{text[:limit]}...{len(text) - limit} more"


def card_truncated(item: dict[str, object]) -> bool:
    """True when the on-screen card hides the tail of a field."""
    return any(len(_plain(item, key)) > FIELD_LIMIT for key in _CAPPED)


def render_card(item: dict[str, object], *, full: bool = False) -> str:
    """One card. Newlines inside fields are ``⏎``. Controls are visible escapes."""
    approval_id = _field(item, "id", full=full)
    tool = _field(item, "tool", full=full)
    risk = _field(item, "risk", full=full)
    summary = _field(item, "summary", full=full)
    reason = _field(item, "reason", full=full)
    session = _field(item, "sessionId", full=full) or "(none)"
    requester = _field(item, "requester", full=full) or "(none)"
    sandbox = "bubblewrap" if item.get("sandboxed") else "host"
    mount = _field(item, "mount", full=full)
    lines = [
        f"Approval needed: {tool} {approval_id}".rstrip(),
        f"Risk: {risk}",
        f"Sandbox: {sandbox}",
    ]
    if not item.get("sandboxed"):
        lines.append(HOST_FULL_WRITE)
    if mount and mount not in lines:
        lines.append(mount)
    lines.extend(
        [
            f"Session: {session}",
            f"Requester: {requester}",
            scope_label(item) if full else clip(scope_label(item), FIELD_LIMIT),
            f"Action: {summary}",
            f"Why: {reason}",
            "Open the approval with a, s, or d. Tab to Confirm, then press Enter.",
        ]
    )
    if not full and card_truncated(item):
        lines.append("Press v for the full text.")
    lines.append(
        (
            f"Plain: /approve {approval_id}  /session-approve {approval_id}  /deny {approval_id}"
        ).rstrip()
    )
    return "\n".join(lines)


def _field(item: dict[str, object], key: str, *, full: bool) -> str:
    text = _plain(item, key)
    if full:
        return text
    return clip(text, FIELD_LIMIT)


def _plain(item: dict[str, object], key: str) -> str:
    return sanitize(item.get(key) or "", newlines=False)
