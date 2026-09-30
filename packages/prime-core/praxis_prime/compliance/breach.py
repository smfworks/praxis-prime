"""Security-breach record.

Nothing here sends a notice. The row is a local workflow record and a
draft the owner can edit. Day counts on packs are internal policy choices
unless a pack explicitly says the number is a legal deadline.

North Carolina's notice contents follow the starter checklist for
N.C.G.S. § 75-65. This is not legal advice.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from praxis_prime.audit.log import AuditLog
from praxis_prime.compliance.packs import PolicyPack
from praxis_prime.state import StateDB

_NC_FIELDS = (
    "description of the incident",
    "types of personal information involved",
    "acts taken to protect from further unauthorized access",
    "a telephone number for the business",
    "advice that the person remain vigilant",
    "toll-free numbers and addresses of the major consumer reporting agencies",
    "FTC contact information and the NC Attorney General Consumer Protection Division",
)


def record_breach(
    db: StateDB,
    *,
    pack: PolicyPack,
    summary: str,
    affected: int,
    audit: AuditLog | None = None,
) -> dict[str, Any]:
    if not pack.breach_enabled:
        raise ValueError(f"{pack.id} has no breach workflow in its pack")
    text = summary.strip()
    if not text:
        raise ValueError("breach summary is empty")
    if affected < 0:
        raise ValueError("affected count cannot be negative")
    now = datetime.now(UTC).isoformat()
    record_id = f"br_{uuid.uuid4().hex[:8]}"
    draft = _draft(pack, text, affected)
    payload = {
        "pack": pack.id,
        "dial": pack.dial,
        "affected": affected,
        "sla_days": pack.breach_sla_days,
        "sla_is_legal_deadline": pack.breach_sla_is_legal_deadline,
        "legal_references": list(pack.legal_references),
        "disclaimer": pack.disclaimer,
        "draft": draft,
    }
    db.conn.execute(
        """
        INSERT INTO breach_records (
            id, created_at, pack, summary, affected_count, status, notice_draft, payload_json
        )
        VALUES (?, ?, ?, ?, ?, 'recorded', ?, ?)
        """,
        (
            record_id,
            now,
            pack.id,
            text[:500],
            affected,
            draft,
            json.dumps(payload, sort_keys=True),
        ),
    )
    db.conn.commit()
    if audit is not None:
        audit.append(
            session_id=None,
            kind="breach",
            summary=f"breach record {record_id}",
            payload={
                "id": record_id,
                "pack": pack.id,
                "affected": affected,
                "status": "recorded",
            },
        )
    return {"id": record_id, "created_at": now, "pack": pack.id, "status": "recorded", **payload}


def list_breaches(db: StateDB) -> list[dict[str, Any]]:
    rows = db.conn.execute(
        """
        SELECT id, created_at, pack, summary, affected_count, status
        FROM breach_records
        ORDER BY created_at, id
        """
    ).fetchall()
    return [
        {
            "id": row["id"],
            "created_at": row["created_at"],
            "pack": row["pack"],
            "summary": row["summary"],
            "affected": int(row["affected_count"]),
            "status": row["status"],
        }
        for row in rows
    ]


def _sla_note(pack: PolicyPack) -> str:
    if pack.breach_sla_is_legal_deadline:
        return "stated as a legal deadline in the pack"
    return "a policy choice, not a legal deadline"


def _draft(pack: PolicyPack, summary: str, affected: int) -> str:
    lines = [
        f"Breach notice draft ({pack.title})",
        pack.disclaimer,
        "",
        "This draft is not sent automatically. Sending it is a SEND action and needs approval.",
        f"Internal SLA: {pack.breach_sla_days} days ({_sla_note(pack)}).",
        f"Persons recorded: {affected}.",
        "",
        f"What happened (owner summary): {summary}",
        "",
        "Fill in before any notice:",
    ]
    fields = _NC_FIELDS if pack.dial == "state_nc" else (
        "what happened",
        "what information was involved",
        "what the business is doing",
        "how the person can reach the business",
        "which regulator is notified, if the pack's statute requires it",
    )
    for field in fields:
        lines.append(f"- {field}:")
    if pack.dial == "state_nc" and affected > 1000:
        lines.append("")
        lines.append(
            "More than 1,000 persons are recorded. The starter NC checklist also "
            "includes notice to nationwide consumer reporting agencies. Confirm before sending."
        )
    if pack.dial == "state_nc":
        lines.append("")
        lines.append(
            "The starter checklist includes notice to the NC Attorney General when "
            "consumer notices go out. Nothing in this record sends that notice."
        )
    return "\n".join(lines)
