"""Compliance report from the audit log.

The report lists detections, blocks, approvals, and retention actions.
It does not repeat raw prompts. Starter policy, not legal advice.
"""

from __future__ import annotations

import html
import json
from typing import Any

from praxis_prime.audit.log import AuditLog

_KINDS = frozenset(
    {"compliance", "approval", "retention", "breach", "dial_change", "policy"}
)


def collect_events(audit: AuditLog, *, since: str = "") -> list[dict[str, Any]]:
    sql = """
        SELECT id, created_at, kind, summary, payload_json
        FROM audit_events
    """
    params: list[str] = []
    if since.strip():
        sql += " WHERE created_at >= ?"
        params.append(since.strip())
    sql += " ORDER BY id"
    events: list[dict[str, Any]] = []
    for row in audit.db.conn.execute(sql, params).fetchall():
        if row["kind"] not in _KINDS:
            continue
        payload = json.loads(row["payload_json"])
        if row["kind"] == "policy" and payload.get("decision") not in {"deny", "ask"}:
            continue
        events.append(
            {
                "id": int(row["id"]),
                "created_at": row["created_at"],
                "kind": row["kind"],
                "summary": row["summary"],
                "payload": payload,
            }
        )
    return events


def render_report(events: list[dict[str, Any]], *, fmt: str = "md") -> str:
    if fmt == "html":
        return _html(events)
    return _markdown(events)


def explain_event(audit: AuditLog, event_id: str, packs_by_dial: dict[str, Any]) -> str:
    row = audit.db.conn.execute(
        """
        SELECT id, created_at, kind, summary, payload_json
        FROM audit_events
        WHERE id = ?
        """,
        (int(event_id),),
    ).fetchone()
    if row is None:
        raise LookupError(f"no audit event {event_id}")
    payload = json.loads(row["payload_json"])
    lines = [
        f"Event {row['id']}  {row['created_at']}  {row['kind']}",
        row["summary"],
        "",
        json.dumps(payload, indent=2, sort_keys=True),
    ]
    dials = payload.get("dials")
    if isinstance(dials, list):
        lines.append("")
        lines.append("Pack notes:")
        for dial_id in dials:
            pack = packs_by_dial.get(str(dial_id))
            if pack is None:
                continue
            lines.append(f"- {pack.title}: {pack.disclaimer}")
            for ref in pack.legal_references:
                lines.append(f"  - {ref}")
    lines.append("")
    lines.append("Starter policy. Not legal advice.")
    return "\n".join(lines) + "\n"


def _markdown(events: list[dict[str, Any]]) -> str:
    counts = _counts(events)
    lines = [
        "# Compliance report",
        "",
        "Starter policy summary from the local audit log. Not legal advice.",
        "",
        "## Counts",
        "",
    ]
    for label, count in counts:
        lines.append(f"- {label}: {count}")
    lines.extend(["", "## Events", ""])
    if not events:
        lines.append("No matching audit events.")
    for event in events:
        lines.append(
            f"- `{event['id']}` {event['created_at']} **{event['kind']}** — {event['summary']}"
        )
        decision = event["payload"].get("decision")
        classes = event["payload"].get("data_classes")
        if decision:
            lines.append(f"  - decision: {decision}")
        if classes:
            lines.append(f"  - data classes: {', '.join(str(item) for item in classes)}")
    lines.append("")
    return "\n".join(lines)


def _html(events: list[dict[str, Any]]) -> str:
    counts = _counts(events)
    items = "".join(
        f"<li><strong>{html.escape(label)}</strong>: {count}</li>" for label, count in counts
    )
    rows = []
    for event in events:
        rows.append(
            "<tr>"
            f"<td>{event['id']}</td>"
            f"<td>{html.escape(str(event['created_at']))}</td>"
            f"<td>{html.escape(str(event['kind']))}</td>"
            f"<td>{html.escape(str(event['summary']))}</td>"
            "</tr>"
        )
    body = "".join(rows) or "<tr><td colspan='4'>No matching audit events.</td></tr>"
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>Compliance report</title></head><body>"
        "<h1>Compliance report</h1>"
        "<p>Starter policy summary from the local audit log. Not legal advice.</p>"
        f"<ul>{items}</ul>"
        "<table><thead><tr><th>Id</th><th>When</th><th>Kind</th><th>Summary</th></tr></thead>"
        f"<tbody>{body}</tbody></table></body></html>\n"
    )


def _counts(events: list[dict[str, Any]]) -> list[tuple[str, int]]:
    detections = 0
    blocks = 0
    approvals = 0
    retention = 0
    for event in events:
        kind = event["kind"]
        decision = str(event["payload"].get("decision", ""))
        if kind == "compliance":
            detections += 1
            if decision == "deny":
                blocks += 1
        elif kind == "policy" and decision == "deny":
            blocks += 1
        elif kind == "approval":
            approvals += 1
        elif kind == "retention":
            retention += 1
    return [
        ("detections", detections),
        ("blocks", blocks),
        ("approvals", approvals),
        ("retention actions", retention),
        ("events", len(events)),
    ]
