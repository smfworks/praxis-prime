"""Approval card for the terminal.

Fields are one line each. Risk, sandbox, and the host warning come before
the action, so a long action cannot push the dangerous part off the card.
"""

from __future__ import annotations

from praxis_prime.approvals.card import HOST_FULL_WRITE
from praxis_prime.tui.sanitize import sanitize

CONFIRM_ONCE = "ctrl+y"
CONFIRM_SESSION = "ctrl+u"
CONFIRM_DENY = "ctrl+x"


def scope_label(item: dict[str, object]) -> str:
    """What ``allow_session`` actually grants for this card.

    The daemon stores the grant on the approval's session. An empty session
    uses the process-wide bucket.
    """
    session = sanitize(item.get("sessionId") or "", newlines=False).strip()
    if session:
        return f"Always allow in session {session}"
    return "Always allow for this daemon process"


def render_card(item: dict[str, object]) -> str:
    """One card. Newlines inside fields are ``⏎``. Controls are visible escapes."""
    approval_id = _field(item, "id")
    tool = _field(item, "tool")
    risk = _field(item, "risk")
    summary = _field(item, "summary")
    reason = _field(item, "reason")
    session = _field(item, "sessionId") or "(none)"
    requester = _field(item, "requester") or "(none)"
    sandbox = "bubblewrap" if item.get("sandboxed") else "host"
    mount = _field(item, "mount")
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
            scope_label(item),
            f"Action: {summary}",
            f"Why: {reason}",
            "A text reply cannot approve this.",
            (
                "Full screen: a then ctrl+y approves once, "
                "s then ctrl+u allows the scope above, "
                "d then ctrl+x denies. The confirm dialog opens on Cancel."
            ),
            (
                f"Plain: /approve {approval_id}  "
                f"/session-approve {approval_id}  /deny {approval_id}"
            ).rstrip(),
        ]
    )
    return "\n".join(lines)


def _field(item: dict[str, object], key: str) -> str:
    return sanitize(item.get(key) or "", newlines=False)
