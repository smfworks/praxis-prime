"""Session transcript store.

Working memory for one chat lives in ``prime.db`` under the XDG data
directory. Episodic search, semantic memory, and forgetting are not here.

ARCHITECTURE §10. This is tier-1 session state only.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from praxis_prime.router.types import ChatMessage, ToolCall, parse_arguments
from praxis_prime.state import StateDB


class SessionStore:
    def __init__(self, db: StateDB) -> None:
        self.db = db

    def create(
        self,
        *,
        model: str,
        preamble: str,
        owner_account: str = "",
        owner_profile: str = "",
    ) -> str:
        session_id = uuid.uuid4().hex
        now = _now()
        self.db.conn.execute(
            """
            INSERT INTO sessions (
                id, created_at, updated_at, model, title, preamble,
                owner_account, owner_profile
            )
            VALUES (?, ?, ?, ?, '', ?, ?, ?)
            """,
            (session_id, now, now, model, preamble, owner_account, owner_profile),
        )
        self.db.conn.commit()
        return session_id

    def owner(self, session_id: str) -> tuple[str, str] | None:
        """Account id and profile that opened this session, or None."""
        row = self.db.conn.execute(
            "SELECT owner_account, owner_profile FROM sessions WHERE id = ?",
            (session_id,),
        ).fetchone()
        if row is None:
            return None
        return str(row["owner_account"]), str(row["owner_profile"])

    def exists(self, session_id: str) -> bool:
        row = self.db.conn.execute(
            "SELECT 1 FROM sessions WHERE id = ?",
            (session_id,),
        ).fetchone()
        return row is not None

    def set_model(self, session_id: str, model: str) -> None:
        self.db.conn.execute(
            "UPDATE sessions SET model = ?, updated_at = ? WHERE id = ?",
            (model, _now(), session_id),
        )
        self.db.conn.commit()

    def note_title(self, session_id: str, text: str) -> None:
        title = " ".join(text.split())[:80]
        self.db.conn.execute(
            """
            UPDATE sessions
            SET title = ?, updated_at = ?
            WHERE id = ? AND title = ''
            """,
            (title, _now(), session_id),
        )
        self.db.conn.commit()

    def append(self, session_id: str, message: ChatMessage) -> None:
        tool_calls = ""
        if message.tool_calls:
            tool_calls = json.dumps(
                [
                    {"id": call.id, "name": call.name, "arguments": dict(call.arguments)}
                    for call in message.tool_calls
                ],
                separators=(",", ":"),
            )
        now = _now()
        self.db.conn.execute(
            """
            INSERT INTO messages (
                session_id, role, content, tool_call_id, tool_calls_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                message.role,
                message.content,
                message.tool_call_id,
                tool_calls or None,
                now,
            ),
        )
        self.db.conn.execute(
            "UPDATE sessions SET updated_at = ? WHERE id = ?",
            (now, session_id),
        )
        self.db.conn.commit()

    def replace_last(self, session_id: str, message: ChatMessage) -> None:
        row = self.db.conn.execute(
            "SELECT id FROM messages WHERE session_id = ? ORDER BY id DESC LIMIT 1",
            (session_id,),
        ).fetchone()
        if row is None:
            self.append(session_id, message)
            return
        self.db.conn.execute(
            "UPDATE messages SET role = ?, content = ?, tool_call_id = ? WHERE id = ?",
            (message.role, message.content, message.tool_call_id, row["id"]),
        )
        self.db.conn.commit()

    def load(self, session_id: str) -> list[ChatMessage]:
        rows = self.db.conn.execute(
            """
            SELECT role, content, tool_call_id, tool_calls_json
            FROM messages
            WHERE session_id = ?
            ORDER BY id
            """,
            (session_id,),
        ).fetchall()
        messages: list[ChatMessage] = []
        for row in rows:
            if row["role"] == "system":
                continue
            calls: list[ToolCall] = []
            if row["tool_calls_json"]:
                raw_calls = json.loads(row["tool_calls_json"])
                for item in raw_calls:
                    calls.append(
                        ToolCall(
                            id=str(item["id"]),
                            name=str(item["name"]),
                            arguments=parse_arguments(item.get("arguments") or {}),
                        )
                    )
            messages.append(
                ChatMessage(
                    role=row["role"],
                    content=row["content"],
                    tool_calls=tuple(calls),
                    tool_call_id=row["tool_call_id"],
                )
            )
        return messages


def _now() -> str:
    return datetime.now(UTC).isoformat()
