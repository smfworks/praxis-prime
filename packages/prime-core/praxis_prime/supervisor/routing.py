"""Gateway-facing host and approval queue that dispatch to workers.

The daemon process does not open a profile database. Chat, approvals,
and session calls go to the worker for that profile.
"""

from __future__ import annotations

import time
from collections.abc import Collection

from praxis_prime import __version__
from praxis_prime.approvals.gate import ApprovalDecision
from praxis_prime.host import TurnResult
from praxis_prime.policy.engine import PolicyEngine
from praxis_prime.router.settings import Settings
from praxis_prime.supervisor.ipc import IpcError
from praxis_prime.supervisor.supervisor import Supervisor, WorkerUnavailable


class _StoreView:
    def __init__(self, host: RoutingHost) -> None:
        self._host = host

    def owner(self, session_id: str) -> tuple[str, str] | None:
        return self._host.session_owner(session_id)


class _RuntimeView:
    def __init__(self, host: RoutingHost) -> None:
        self.policy = host.policy
        self.profile_id = ""
        self.store = _StoreView(host)


class RoutingHost:
    """Methods the gateway and Telegram adapter call, forwarded per profile."""

    def __init__(self, supervisor: Supervisor, policy: PolicyEngine, settings: Settings) -> None:
        self.supervisor = supervisor
        self.policy = policy
        self.settings = settings
        self.started_at = time.time()
        self.runtime = _RuntimeView(self)
        self._closed = False

    def chat(
        self,
        text: str,
        *,
        session_id: str | None = None,
        untrusted: bool = False,
        source: str = "channel",
        channel: str = "",
        on_event: object | None = None,
        owner_account: str = "",
        owner_profile: str = "",
    ) -> TurnResult:
        del on_event
        if self._closed:
            raise RuntimeError("daemon is shut down")
        if not owner_profile:
            raise WorkerUnavailable("a profile is required")
        result = self.supervisor.call(
            owner_profile,
            "chat",
            {
                "text": text,
                "sessionId": session_id or "",
                "untrusted": untrusted,
                "source": source,
                "channel": channel,
                "account": owner_account,
            },
            timeout=3600,
        )
        error = result.get("error")
        return TurnResult(
            session_id=str(result.get("sessionId", "")),
            text=str(result.get("text", "")),
            error=error if isinstance(error, str) else None,
            cancelled=bool(result.get("cancelled")),
        )

    def set_model(self, spec: str, *, profile: str = "") -> str:
        if not profile:
            raise WorkerUnavailable("a profile is required")
        result = self.supervisor.call(profile, "model.set", {"spec": spec})
        return str(result.get("model", spec))

    def drop_session(self, session_id: str | None, *, account_id: str = "") -> None:
        if not session_id:
            return
        owner = self.session_owner(session_id)
        if owner is None:
            raise LookupError(f"no session {session_id}")
        found_account, found_profile = owner
        if account_id and found_account != account_id:
            raise PermissionError("session belongs to another account")
        self.supervisor.call(
            found_profile or self._only_profile(),
            "session.drop",
            {"sessionId": session_id, "account": account_id},
        )

    def session_owner(self, session_id: str) -> tuple[str, str] | None:
        """Account and profile for ``session_id``.

        Running workers are asked first. Idle profiles are started only
        when none of those workers has the session.
        """
        asked: set[str] = set()
        for profile in self.supervisor.running():
            asked.add(profile)
            found = self._owner_on(profile, session_id)
            if found is not None:
                return found
        for profile in self.supervisor.profiles():
            if profile in asked:
                continue
            found = self._owner_on(profile, session_id)
            if found is not None:
                return found
        return None

    def _owner_on(self, profile: str, session_id: str) -> tuple[str, str] | None:
        try:
            result = self.supervisor.call(
                profile,
                "session.owner",
                {"sessionId": session_id},
                timeout=5,
            )
        except (IpcError, WorkerUnavailable, OSError):
            return None
        owner = result.get("owner")
        if isinstance(owner, dict) and owner.get("account"):
            return str(owner.get("account", "")), str(owner.get("profile", "") or profile)
        return None

    def status(self) -> dict[str, object]:
        pending = 0
        for profile in self.supervisor.running():
            try:
                listed = self.supervisor.call(profile, "approvals.list", {}, timeout=2)
            except (IpcError, WorkerUnavailable, OSError):
                continue
            rows = listed.get("approvals")
            if isinstance(rows, list):
                pending += len(rows)
        return {
            "service": "praxis-primed",
            "version": __version__,
            "model": self.settings.model_spec,
            "mode": self.settings.mode,
            "pendingApprovals": pending,
            "uptimeSeconds": int(time.time() - self.started_at),
            "workers": self.supervisor.snapshot(),
        }

    def close(self) -> None:
        self._closed = True
        self.supervisor.close()

    def _only_profile(self) -> str:
        names = self.supervisor.profiles()
        if len(names) == 1:
            return names[0]
        raise WorkerUnavailable("a profile is required")


class RoutingQueue:
    """Approval queue whose rows live in the profile workers."""

    def __init__(self, supervisor: Supervisor) -> None:
        self.supervisor = supervisor
        self.profile_id = ""
        self.on_pending = None
        self.on_resolved = None

    def list_pending(self) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for profile in self.supervisor.running():
            try:
                listed = self.supervisor.call(profile, "approvals.list", {}, timeout=2)
            except (IpcError, WorkerUnavailable, OSError):
                continue
            items = listed.get("approvals")
            if isinstance(items, list):
                rows.extend(item for item in items if isinstance(item, dict))
        rows.sort(key=lambda item: str(item.get("id", "")))
        return rows

    def list_meta(
        self,
        *,
        profiles: Collection[str] | None = None,
    ) -> list[dict[str, object]]:
        rows = []
        for item in self.list_pending():
            profile = str(item.get("profileId", ""))
            if profiles is not None and profile not in profiles:
                continue
            rows.append(
                {
                    "id": item.get("id", ""),
                    "tool": item.get("tool", ""),
                    "risk": item.get("risk", ""),
                    "createdAt": item.get("createdAt", ""),
                    "decision": (
                        "pending" if item.get("state") == "pending" else item.get("state", "")
                    ),
                }
            )
        return rows

    def get(self, approval_id: str) -> dict[str, object] | None:
        names = []
        known = self.supervisor.approval_profile(approval_id)
        if known:
            names.append(known)
        else:
            names.extend(self.supervisor.running())
        for profile in names:
            try:
                result = self.supervisor.call(
                    profile,
                    "approvals.get",
                    {"approvalId": approval_id},
                    timeout=2,
                )
            except (IpcError, WorkerUnavailable, OSError):
                continue
            item = result.get("approval")
            if isinstance(item, dict):
                self.supervisor.note_approval(profile, approval_id)
                return item
        return None

    def decide(
        self,
        approval_id: str,
        decision: ApprovalDecision,
        *,
        actor: str,
    ) -> dict[str, object]:
        existing = self.get(approval_id)
        profile = ""
        if existing is not None:
            profile = str(existing.get("profileId", "")) or self.supervisor.approval_profile(
                approval_id
            )
        if not profile:
            raise LookupError(f"approval {approval_id} is not pending")
        result = self.supervisor.call(
            profile,
            "approvals.decide",
            {"approvalId": approval_id, "decision": decision.value, "actor": actor},
        )
        item = result.get("approval")
        if not isinstance(item, dict):
            raise LookupError(f"approval {approval_id} is not pending")
        return item

    def deny_all(self, *, actor: str) -> None:
        for profile in self.supervisor.running():
            try:
                self.supervisor.call(
                    profile,
                    "approvals.deny_all",
                    {"actor": actor},
                    timeout=2,
                )
            except (IpcError, WorkerUnavailable, OSError):
                continue

    def authorize(self, request: object) -> ApprovalDecision:
        """The supervisor does not approve inside its own process."""
        del request
        return ApprovalDecision.DENY
