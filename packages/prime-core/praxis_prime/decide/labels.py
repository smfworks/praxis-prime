"""Outcome log for Decision Engine calibration.

Predicted labels are written when a decision is made. Feedback records
whether that prediction was right. Rows live in ``decide/labels.db``
(ARCHITECTURE §7.6). The file holds no API keys.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True, slots=True)
class LabelRow:
    decision_id: str
    question_id: str
    predicted: str
    confidence: float
    probabilities: dict[str, float]
    gold: str
    correct: int | None


class LabelStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS labels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                decision_id TEXT NOT NULL,
                question_id TEXT NOT NULL,
                predicted TEXT NOT NULL,
                confidence REAL NOT NULL,
                probabilities_json TEXT NOT NULL,
                gold TEXT NOT NULL DEFAULT '',
                correct INTEGER,
                created_at TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def record(
        self,
        *,
        decision_id: str,
        question_id: str,
        predicted: str,
        confidence: float,
        probabilities: dict[str, float],
    ) -> None:
        payload = json.dumps(probabilities, sort_keys=True, separators=(",", ":"))
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO labels (
                    decision_id, question_id, predicted, confidence,
                    probabilities_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    decision_id,
                    question_id,
                    predicted,
                    confidence,
                    payload,
                    datetime.now(UTC).isoformat(),
                ),
            )
            self._conn.commit()

    def feedback(
        self,
        decision_id: str,
        *,
        correct: bool | None = None,
        gold: str | None = None,
        question_id: str | None = None,
    ) -> int:
        """Update rows for ``decision_id``. Returns how many rows changed."""
        with self._lock:
            rows = self._rows(decision_id, question_id)
            changed = 0
            for row in rows:
                predicted = str(row["predicted"])
                new_gold = gold if gold is not None else str(row["gold"])
                if correct is None and gold is not None:
                    flag: int | None = 1 if gold == predicted else 0
                elif correct is None:
                    flag = None if row["correct"] is None else int(row["correct"])
                else:
                    flag = 1 if correct else 0
                    if correct and not new_gold:
                        new_gold = predicted
                self._conn.execute(
                    "UPDATE labels SET gold = ?, correct = ? WHERE id = ?",
                    (new_gold, flag, row["id"]),
                )
                changed += 1
            self._conn.commit()
            return changed

    def labeled(self) -> list[LabelRow]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT decision_id, question_id, predicted, confidence,
                       probabilities_json, gold, correct
                FROM labels
                WHERE correct IS NOT NULL
                ORDER BY id
                """
            ).fetchall()
        return [_label_row(row) for row in rows]

    def count(self) -> tuple[int, int]:
        """Return ``(labeled, total)``."""
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) AS n FROM labels").fetchone()
            labeled = self._conn.execute(
                "SELECT COUNT(*) AS n FROM labels WHERE correct IS NOT NULL"
            ).fetchone()
        return int(labeled["n"]), int(total["n"])

    def _rows(self, decision_id: str, question_id: str | None) -> list[sqlite3.Row]:
        if question_id:
            return self._conn.execute(
                "SELECT * FROM labels WHERE decision_id = ? AND question_id = ?",
                (decision_id, question_id),
            ).fetchall()
        return self._conn.execute(
            "SELECT * FROM labels WHERE decision_id = ?",
            (decision_id,),
        ).fetchall()


def _label_row(row: sqlite3.Row) -> LabelRow:
    try:
        probabilities = json.loads(row["probabilities_json"])
    except json.JSONDecodeError:
        probabilities = {}
    if not isinstance(probabilities, dict):
        probabilities = {}
    correct = None if row["correct"] is None else int(row["correct"])
    return LabelRow(
        decision_id=str(row["decision_id"]),
        question_id=str(row["question_id"]),
        predicted=str(row["predicted"]),
        confidence=float(row["confidence"]),
        probabilities={str(key): float(value) for key, value in probabilities.items()},
        gold=str(row["gold"]),
        correct=correct,
    )
