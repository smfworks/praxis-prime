"""JSON lines log for the daemon.

Logs go to the XDG state directory (ARCHITECTURE §25). Secret values
registered with :meth:`JsonLogger.add_secret` are scrubbed before a line
is written. The log never stores the gateway token or a bot token.
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path


class JsonLogger:
    """Append-only structured log. Safe to call from any thread."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._secrets: list[str] = []
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)

    def add_secret(self, value: str) -> None:
        """Remember a secret so it cannot land in the log."""
        if value and len(value) >= 6 and value not in self._secrets:
            self._secrets.append(value)

    def info(self, event: str, **fields: object) -> None:
        self._write("info", event, fields)

    def warning(self, event: str, **fields: object) -> None:
        self._write("warning", event, fields)

    def error(self, event: str, **fields: object) -> None:
        self._write("error", event, fields)

    def _write(self, level: str, event: str, fields: dict[str, object]) -> None:
        record: dict[str, object] = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "level": level,
            "event": event,
        }
        for key, value in fields.items():
            if isinstance(value, (str, int, float, bool)) or value is None:
                record[key] = value
            else:
                record[key] = str(value)
        line = self._scrub(json.dumps(record, ensure_ascii=True))
        if self.path is None:
            return
        try:
            with self._lock:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
        except OSError:
            return

    def _scrub(self, line: str) -> str:
        for secret in self._secrets:
            if secret in line:
                line = line.replace(secret, "[redacted]")
        return line
