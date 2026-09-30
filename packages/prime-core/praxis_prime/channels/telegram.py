"""Telegram channel adapter.

The bot token comes from the environment or a secrets file. Pairing is a
one-time code issued on the local machine. Only that chat id can talk to
the agent, and only that chat's inline-keyboard buttons can approve.

Inbound text is untrusted. ``/approve``, ``yes``, and lookalike messages
never call the approval queue. Unknown chats are rejected.

No network library is required. Tests pass a fake transport.
"""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol

from praxis_prime.approvals.card import format_approval_card
from praxis_prime.approvals.gate import ApprovalDecision
from praxis_prime.approvals.queue import ApprovalQueue, parse_decision
from praxis_prime.host import Host
from praxis_prime.observe import JsonLogger

_CALLBACK = re.compile(r"^a:(ap_[0-9a-f]{8}):([01s])$")
_APPROVAL_COMMANDS = ("/approve", "/deny", "/allow")
_EXACT_APPROVAL_TEXT = frozenset(
    {
        "approve",
        "deny",
        "allow",
        "allow once",
        "always",
        "always this session",
        "always-for-session",
    }
)


class TelegramError(RuntimeError):
    """The Telegram call failed. The message never includes the bot token."""


class TelegramTransport(Protocol):
    def call(self, method: str, payload: Mapping[str, object]) -> dict[str, object]:
        """Invoke one Bot API method."""


class HttpTelegramTransport:
    """Bot API over HTTPS. Errors are scrubbed so the token stays out of logs."""

    def __init__(self, token: str, opener: object | None = None) -> None:
        self._token = token
        self._opener = opener or urllib.request.urlopen

    def call(self, method: str, payload: Mapping[str, object]) -> dict[str, object]:
        url = f"https://api.telegram.org/bot{self._token}/{method}"
        body = json.dumps(dict(payload)).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with self._opener(request, timeout=15) as response:  # type: ignore[operator]
                raw = response.read()
        except Exception as exc:
            raise TelegramError("telegram request failed") from exc
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise TelegramError("telegram returned a response that was not JSON") from exc
        if not isinstance(parsed, dict) or not parsed.get("ok"):
            raise TelegramError("telegram rejected the request")
        return parsed


class PairingStore:
    """One-time pairing codes and the owner chat id. Files are mode 0600."""

    def __init__(self, code_path: Path, owner_path: Path, *, ttl: float = 600) -> None:
        self.code_path = code_path
        self.owner_path = owner_path
        self.ttl = ttl

    def issue(self, code: str | None = None, *, now: float | None = None) -> str:
        """Write a fresh code and return it. The caller prints it locally."""
        import secrets

        value = code or secrets.token_hex(4)
        record = {"code": value, "expires_at": (now if now is not None else time.time()) + self.ttl}
        _write_private(self.code_path, json.dumps(record))
        return value

    def pair(self, chat_id: int, presented: str, *, now: float | None = None) -> bool:
        """Consume a live code and record ``chat_id`` as the owner."""
        record = _read_json(self.code_path)
        if not record:
            return False
        expires = float(record.get("expires_at", 0))
        current = now if now is not None else time.time()
        expected = str(record.get("code", ""))
        if current > expires or not expected or not _code_matches(presented, expected):
            return False
        self.code_path.unlink(missing_ok=True)
        self.set_owner(chat_id)
        return True

    def set_owner(self, chat_id: int) -> None:
        _write_private(
            self.owner_path,
            json.dumps({"chat_id": chat_id, "paired_at": time.time()}),
        )

    def owner_chat_id(self) -> int | None:
        record = _read_json(self.owner_path)
        if not record:
            return None
        chat_id = record.get("chat_id")
        if isinstance(chat_id, int):
            return chat_id
        return None

    def is_owner(self, chat_id: object) -> bool:
        return isinstance(chat_id, int) and chat_id == self.owner_chat_id()


class TelegramAdapter:
    """Long-poll the bot and turn owner messages into untrusted turns."""

    def __init__(
        self,
        transport: TelegramTransport,
        pairing: PairingStore,
        host: Host,
        queue: ApprovalQueue,
        logger: JsonLogger | None = None,
        *,
        offset_path: Path | None = None,
    ) -> None:
        self.transport = transport
        self.pairing = pairing
        self.host = host
        self.queue = queue
        self.logger = logger
        self.offset_path = offset_path
        self._sessions: dict[int, str] = {}
        self._session_lock = threading.Lock()
        self._offset = self._load_offset()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.turns: list[threading.Thread] = []

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="praxis-telegram", daemon=True)
        self._thread.start()
        if self.logger is not None:
            self.logger.info("telegram_enabled")

    def stop(self) -> None:
        self._stop.set()

    def notify_pending(self, item: dict[str, object]) -> None:
        owner = self.pairing.owner_chat_id()
        if owner is None:
            return
        approval_id = str(item.get("id", ""))
        self._send(
            owner,
            format_approval_card(item),
            reply_markup=inline_keyboard(approval_id),
        )

    def notify_resolved(self, item: dict[str, object]) -> None:
        if item.get("actor") not in {"timeout", "shutdown"}:
            return
        owner = self.pairing.owner_chat_id()
        if owner is None:
            return
        state = str(item.get("state", ""))
        label = "Denied (timed out)" if state == "expired" else "Denied"
        self._send(owner, f"{label}: {item.get('tool')} ({item.get('risk')}) {item.get('id')}")

    def handle_update(self, update: Mapping[str, object]) -> None:
        """Process one update. Safe to call from tests with no network."""
        if "callback_query" in update:
            callback = update.get("callback_query")
            if isinstance(callback, dict):
                self._on_callback(callback)
            return
        message = update.get("message")
        if isinstance(message, dict):
            self._on_message(message)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                result = self.transport.call(
                    "getUpdates",
                    {"timeout": 5, "offset": self._offset},
                )
            except Exception as exc:
                if self.logger is not None:
                    self.logger.warning("telegram_poll_failed", error=type(exc).__name__)
                self._stop.wait(2)
                continue
            updates = result.get("result", [])
            if not isinstance(updates, list):
                continue
            for update in updates:
                if not isinstance(update, dict):
                    continue
                update_id = update.get("update_id")
                if isinstance(update_id, int):
                    self._offset = update_id + 1
                    self._store_offset()
                self.handle_update(update)

    def _on_message(self, message: Mapping[str, object]) -> None:
        chat = message.get("chat")
        chat_id = chat.get("id") if isinstance(chat, dict) else None
        if not isinstance(chat_id, int):
            return
        text = message.get("text")
        body = text if isinstance(text, str) else ""
        if body.startswith("/pair"):
            self._on_pair(chat_id, body)
            return
        if not self.pairing.is_owner(chat_id):
            self._send(chat_id, "This bot is paired to its owner. Your chat is not allowed.")
            if self.logger is not None:
                self.logger.info("telegram_reject_unknown")
            return
        if body.startswith("/start"):
            self._send(
                chat_id,
                "Praxis Prime is paired to this chat. "
                "Messages are untrusted input to the agent. "
                "Approvals use the buttons, never a text reply.",
            )
            return
        if is_approval_text(body):
            self._send(
                chat_id,
                "Chat text cannot approve an action. Use the Approve, Deny, "
                "or Always this session buttons.",
            )
            if self.logger is not None:
                self.logger.info("telegram_ignored_approval_text")
            return
        if self.logger is not None:
            self.logger.info("telegram_message_from_owner")
        # The poll loop must stay free to receive approval button presses.
        worker = threading.Thread(
            target=self._run_turn,
            args=(chat_id, body),
            name="praxis-telegram-turn",
            daemon=True,
        )
        self.turns.append(worker)
        worker.start()

    def _run_turn(self, chat_id: int, body: str) -> None:
        with self._session_lock:
            session_id = self._sessions.get(chat_id)
        try:
            result = self.host.chat(
                body,
                session_id=session_id,
                untrusted=True,
                source="telegram",
            )
        except Exception as exc:
            if self.logger is not None:
                self.logger.error("telegram_turn_failed", error=type(exc).__name__)
            self._send(chat_id, "The agent turn failed before it could reply.")
            return
        with self._session_lock:
            self._sessions[chat_id] = result.session_id
        reply = result.text.strip() or "(no reply)"
        self._send(chat_id, reply[:4000])

    def _on_pair(self, chat_id: int, text: str) -> None:
        parts = text.split(maxsplit=1)
        presented = parts[1].strip() if len(parts) > 1 else ""
        if self.pairing.pair(chat_id, presented):
            self._send(chat_id, "Paired. This chat is the owner.")
            if self.logger is not None:
                self.logger.info("telegram_paired")
            return
        self._send(chat_id, "Pairing code rejected.")
        if self.logger is not None:
            self.logger.info("telegram_pair_rejected")

    def _on_callback(self, callback: Mapping[str, object]) -> None:
        query_id = str(callback.get("id", ""))
        message = callback.get("message")
        chat_id = None
        if isinstance(message, dict):
            chat = message.get("chat")
            if isinstance(chat, dict):
                chat_id = chat.get("id")
        data = callback.get("data")
        parsed = parse_callback(data if isinstance(data, str) else "")
        if not self.pairing.is_owner(chat_id) or parsed is None:
            self._answer(query_id, "Not allowed")
            if self.logger is not None:
                self.logger.info("telegram_reject_callback")
            return
        approval_id, decision = parsed
        try:
            self.queue.decide(approval_id, decision, actor=f"telegram:{chat_id}")
        except LookupError:
            self._answer(query_id, "That approval is no longer pending")
            return
        label = {
            ApprovalDecision.ALLOW_ONCE: "Approved",
            ApprovalDecision.ALLOW_SESSION: "Approved for this session",
            ApprovalDecision.DENY: "Denied",
        }[decision]
        self._answer(query_id, label)
        if self.logger is not None:
            self.logger.info("telegram_approval", approval=approval_id, decision=decision.value)

    def _answer(self, query_id: str, text: str) -> None:
        if not query_id:
            return
        try:
            self.transport.call(
                "answerCallbackQuery",
                {"callback_query_id": query_id, "text": text},
            )
        except Exception as exc:
            if self.logger is not None:
                self.logger.warning("telegram_answer_failed", error=type(exc).__name__)

    def _send(
        self,
        chat_id: int,
        text: str,
        *,
        reply_markup: dict[str, object] | None = None,
    ) -> None:
        payload: dict[str, object] = {"chat_id": chat_id, "text": text[:4096]}
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup
        try:
            self.transport.call("sendMessage", payload)
        except Exception as exc:
            if self.logger is not None:
                self.logger.warning("telegram_send_failed", error=type(exc).__name__)

    def _load_offset(self) -> int:
        if self.offset_path is None or not self.offset_path.is_file():
            return 0
        try:
            return int(self.offset_path.read_text(encoding="utf-8").strip() or "0")
        except ValueError:
            return 0

    def _store_offset(self) -> None:
        if self.offset_path is None:
            return
        _write_private(self.offset_path, str(self._offset))


def is_approval_text(text: str) -> bool:
    """True when the message is trying to approve or deny in prose."""
    lowered = text.strip().lower()
    if any(lowered.startswith(command) for command in _APPROVAL_COMMANDS):
        return True
    return lowered in _EXACT_APPROVAL_TEXT


def parse_callback(data: str) -> tuple[str, ApprovalDecision] | None:
    """Parse a button payload. Anything else, including free text, is ignored."""
    match = _CALLBACK.fullmatch(data.strip())
    if match is None:
        return None
    code = match.group(2)
    decision = {"1": "allow_once", "0": "deny", "s": "allow_session"}[code]
    return match.group(1), parse_decision(decision)


def inline_keyboard(approval_id: str) -> dict[str, object]:
    return {
        "inline_keyboard": [
            [
                {"text": "Approve", "callback_data": f"a:{approval_id}:1"},
                {"text": "Deny", "callback_data": f"a:{approval_id}:0"},
                {"text": "Always this session", "callback_data": f"a:{approval_id}:s"},
            ]
        ]
    }


def _code_matches(presented: str, expected: str) -> bool:
    from praxis_prime.gateway.protocol import secrets_equal

    return secrets_equal(presented.strip(), expected.strip())


def _read_json(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if isinstance(loaded, dict):
        return loaded
    return {}


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    import os

    os.chmod(temporary, 0o600)
    temporary.replace(path)
    os.chmod(path, 0o600)
