"""Sessions this TUI visit has opened.

The gateway has no session list. Rows live in this process. A resumed id
is sent back on ``chat.send`` and is not read from ``prime.db``.
"""

from __future__ import annotations

from praxis_prime.tui.sanitize import sanitize

DRAFT = ""


class SessionBook:
    """Ordered session ids, titles, and the transcript of this visit."""

    def __init__(self, resume: str = "") -> None:
        self.order: list[str] = []
        self.titles: dict[str, str] = {}
        self.transcripts: dict[str, list[str]] = {DRAFT: []}
        self.current = DRAFT
        self._pending_title = ""
        self._seq = 0
        self._wire: dict[str, str | None] = {}
        self._sealed: set[str] = set()
        self._split: set[str] = set()
        if resume:
            self._remember(resume, "resumed")
            self.current = resume
            self.transcripts[resume] = []

    def note_user(self, text: str) -> None:
        """Remember a title from the first line of a user message."""
        stripped = sanitize(text, newlines=False).strip()
        if not stripped:
            return
        self._pending_title = stripped[:60]

    def append(self, session_id: str, line: str) -> None:
        rows = self.transcripts.setdefault(session_id, [])
        if line.startswith("you:") and rows and rows[-1] != "":
            rows.append("")
        rows.append(line)

    def replace_last(self, session_id: str, prefix: str, line: str) -> None:
        rows = self.transcripts.setdefault(session_id, [])
        if rows and rows[-1].startswith(prefix):
            rows[-1] = line
            return
        rows.append(line)

    def add_assistant_chunk(self, session_id: str, chunk: str) -> None:
        """Grow the current prime line, or start one after a tool boundary."""
        if session_id in self._sealed:
            self._sealed.discard(session_id)
            self.transcripts.setdefault(session_id, []).append(f"prime: {chunk}")
            return
        current = self.last_with_prefix(session_id, "prime: ")
        self.replace_last(session_id, "prime: ", f"prime: {current}{chunk}")

    def last_with_prefix(self, session_id: str, prefix: str) -> str:
        rows = self.transcripts.get(session_id, [])
        if rows and rows[-1].startswith(prefix):
            return rows[-1][len(prefix) :]
        return ""

    def seal_assistant(self, session_id: str) -> None:
        """Keep the prime line written so far. Later text starts a new line."""
        self._sealed.add(session_id)
        self._split.add(session_id)

    def finish_assistant(self, session_id: str, final: str) -> None:
        """Keep pre-tool text, and show a different final answer as well."""
        if session_id in self._split or session_id in self._sealed:
            self._sealed.discard(session_id)
            self._split.discard(session_id)
            last = self.last_with_prefix(session_id, "prime: ")
            if final and final != last:
                self.transcripts.setdefault(session_id, []).append(f"prime: {final}")
            return
        if not final:
            return
        streamed = self.last_with_prefix(session_id, "prime: ")
        if streamed:
            if final != streamed:
                self.replace_last(session_id, "prime: ", f"prime: {final}")
            return
        self.transcripts.setdefault(session_id, []).append(f"prime: {final}")

    def text(self, session_id: str | None = None) -> str:
        key = self.current if session_id is None else session_id
        return "\n".join(self.transcripts.get(key, []))

    def pin_draft(self) -> str:
        """Move the draft onto a stable id before a turn starts.

        ``new`` clears only the empty draft, so the line already sent stays
        on this id when the user starts another session during the turn.
        """
        if self.current != DRAFT:
            return self.current
        self._seq += 1
        key = f"local-{self._seq}"
        self.transcripts[key] = list(self.transcripts.get(DRAFT, []))
        self.transcripts[DRAFT] = []
        self._remember(key, self._pending_title or "chat")
        self._wire[key] = None
        self.current = key
        return key

    def wire_id(self, key: str) -> str | None:
        """Session id to send, or None until the daemon assigns one."""
        if not key or key == DRAFT:
            return None
        if key.startswith("local-"):
            return self._wire.get(key)
        return key

    def rename(self, key: str, session_id: str) -> None:
        """Attach the daemon's id to a pinned local row."""
        session_id = session_id.strip()
        if not session_id or session_id == key:
            self._pending_title = ""
            return
        if not str(key).startswith("local-"):
            self._pending_title = ""
            return
        rows = self.transcripts.pop(key, [])
        title = self.titles.pop(key, None) or self._pending_title or "chat"
        if key in self.order:
            self.order.remove(key)
        self._wire.pop(key, None)
        if session_id in self.transcripts:
            self.transcripts[session_id].extend(rows)
        else:
            self.transcripts[session_id] = rows
            self._remember(session_id, title)
        if self.current == key:
            self.current = session_id
        self._pending_title = ""

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
        self.titles[session_id] = sanitize(title, newlines=False)[:60]
