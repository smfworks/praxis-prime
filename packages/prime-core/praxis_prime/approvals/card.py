"""Text form of an approval card.

The same summary is shown on the CLI and on Telegram (ARCHITECTURE §21.2).
"""

from __future__ import annotations

# Unsandboxed approval. This replaces a mount line: the command is not read-only.
HOST_FULL_WRITE = "HOST: runs unsandboxed with full write access"
# The whole mount line when account data exists and bubblewrap is missing.
HOST_NEEDS_BWRAP = "install bubblewrap to run shell commands"
# Defence in depth on a fresh install, appended to HOST_FULL_WRITE.
HOST_DATA_DIR = "HOST: refusing this command because it can read the account data directory"


def mount_phrase(writable: bool) -> str:
    """Plain text for whether approval mounts the workspace read-write."""
    if writable:
        return "RW mount: workspace writable"
    return "read-only"


def format_approval_card(item: dict[str, object]) -> str:
    """One card: the action, its risk, and the fact that text cannot approve.

    Dynamic fields are flattened and controls are written as visible escapes,
    so a summary cannot hide the rest of the command or address the terminal.
    """
    sandbox = "bubblewrap" if item.get("sandboxed") else "host"
    summary = _visible(item.get("summary", ""))
    if len(summary) > 500:
        summary = summary[:499] + "…"
    lines = [
        "Approval needed",
        f"Id: {_visible(item.get('id', ''))}",
        f"Risk: {_visible(item.get('risk', ''))}",
        f"Tool: {_visible(item.get('tool', ''))}",
        f"Action: {summary}",
        f"Why: {_visible(item.get('reason', ''))}",
        f"Sandbox: {sandbox}",
    ]
    mount = item.get("mount")
    if isinstance(mount, str) and mount:
        lines.append(_visible(mount))
    lines.extend(
        [
            "A chat message cannot approve this.",
            "Use Approve, Deny, or Always this session.",
        ]
    )
    return "\n".join(lines)


def _visible(value: object) -> str:
    from praxis_prime.sanitize import sanitize

    return sanitize(value, newlines=False)
