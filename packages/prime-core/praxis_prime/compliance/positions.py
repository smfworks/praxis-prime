"""Owner dial changes.

A fresh database records the current positions and does not audit them.
A later change, including ``PolicyEngine.set_dial(..., owner=True)``, is
appended to the hash chain. Nothing else may move a dial.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime

from praxis_prime.audit.log import AuditLog
from praxis_prime.state import StateDB


def sync_dial_positions(
    db: StateDB,
    audit: AuditLog,
    positions: Mapping[str, str],
) -> list[str]:
    """Persist owner positions. Return dial ids that changed since last time."""
    current = {key: positions[key] for key in sorted(positions)}
    row = db.conn.execute(
        "SELECT positions_json FROM dial_positions WHERE id = 1"
    ).fetchone()
    encoded = json.dumps(current, sort_keys=True)
    now = datetime.now(UTC).isoformat()
    if row is None:
        db.conn.execute(
            "INSERT INTO dial_positions (id, positions_json, updated_at) VALUES (1, ?, ?)",
            (encoded, now),
        )
        db.conn.commit()
        return []
    previous = json.loads(row["positions_json"])
    changed = [key for key in current if previous.get(key) != current[key]]
    if not changed:
        return []
    db.conn.execute(
        "UPDATE dial_positions SET positions_json = ?, updated_at = ? WHERE id = 1",
        (encoded, now),
    )
    db.conn.commit()
    audit.append(
        session_id=None,
        kind="dial_change",
        summary="owner compliance dial positions changed",
        payload={
            "actor": "owner",
            "changed": {
                key: {"from": previous.get(key, "off"), "to": current[key]} for key in changed
            },
        },
    )
    return changed
