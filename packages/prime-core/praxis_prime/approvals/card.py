"""Text form of an approval card.

The same summary is shown on the CLI and on Telegram (ARCHITECTURE §21.2).
"""

from __future__ import annotations


def format_approval_card(item: dict[str, object]) -> str:
    """One card: the action, its risk, and the fact that text cannot approve."""
    sandbox = "bubblewrap" if item.get("sandboxed") else "host"
    summary = str(item.get("summary", ""))
    if len(summary) > 500:
        summary = summary[:499] + "…"
    lines = [
        "Approval needed",
        f"Id: {item.get('id', '')}",
        f"Risk: {item.get('risk', '')}",
        f"Tool: {item.get('tool', '')}",
        f"Action: {summary}",
        f"Why: {item.get('reason', '')}",
        f"Sandbox: {sandbox}",
        "A text reply cannot approve this.",
        "Use Approve, Deny, or Always this session.",
    ]
    return "\n".join(lines)
