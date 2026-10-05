"""Sessions this TUI visit has opened.

The gateway has no session list. Rows live in this process. A resumed id
is sent back on ``chat.send`` and is not read from ``prime.db``.
"""

from __future__ import annotations

DRAFT = ""


class SessionBook:
    """Ordered session ids, titles, and the transcript of this visit."""

    def __init__(self, resume: str = "") -> None:
        self.order: list[str] = []
        self.titles: dict[str, str] = {}
        self.transcripts: dict[str, list[str]] = {DRAFT: []}
        self.current = DRAFT
        self._pending_title = ""
        if resume:
            self._remember(resume, "resumed")
            self.current = resume
            self.transcripts[resume] = []

    def note_user(self, text: str) -> None:
        """Remember a title from the first line of a user message."""
        stripped = text.strip()
        if not stripped:
            return
        self._pending_title = stripped.splitlines()[0][:60]

    def append(self, session_id: str, line: str) -> None:
        self.transcripts.setdefault(session_id, []).append(line)

    def replace_last(self, session_id: str, prefix: str, line: str) -> None:
        rows = self.transcripts.setdefault(session_id, [])
        if rows and rows[-1].startswith(prefix):
            rows[-1] = line
            return
        rows.append(line)

    def last_with_prefix(self, session_id: str, prefix: str) -> str:
        rows = self.transcripts.get(session_id, [])
        if rows and rows[-1].startswith(prefix):
            return rows[-1][len(prefix) :]
        return ""

    def text(self, session_id: str | None = None) -> str:
        key = self.current if session_id is None else session_id
        return "\n".join(self.transcripts.get(key, []))

    def adopt(self, session_id: str) -> None:
        """Move the draft transcript onto the id the daemon returned.

        The current row changes only while the draft is still current, so a
        switch during the turn is left alone.
        """
        if not session_id or session_id == self.current:
            self._pending_title = ""
            return
        draft = self.transcripts.get(DRAFT, [])
        if draft:
            title = self._pending_title or self.titles.get(session_id) or "chat"
            if session_id not in self.transcripts:
                self.transcripts[session_id] = list(draft)
                self._remember(session_id, title)
            else:
                self.transcripts[session_id].extend(draft)
            self.transcripts[DRAFT] = []
            if self.current == DRAFT:
                self.current = session_id
        elif session_id not in self.transcripts:
            self.transcripts[session_id] = []
            self._remember(session_id, "resumed")
            if self.current == DRAFT:
                self.current = session_id
        self._pending_title = ""

    def new(self) -> None:
        self.current = DRAFT
        self.transcripts[DRAFT] = []
        self._pending_title = ""

    def switch(self, session_id: str) -> None:
        if not session_id:
            self.new()
            return
        if session_id not in self.transcripts:
            self.transcripts[session_id] = []
            self._remember(session_id, "resumed")
        self.current = session_id

    def rows(self) -> list[tuple[str, str]]:
        """``(id, title)``. A draft row is included only while it is current."""
        visible = [(session_id, self.titles[session_id]) for session_id in self.order]
        if self.current == DRAFT:
            visible.insert(0, (DRAFT, "new"))
        return visible

    def _remember(self, session_id: str, title: str) -> None:
        if session_id in self.titles:
            return
        self.order.append(session_id)
        self.titles[session_id] = title
