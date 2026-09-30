"""Agent loop.

Plan (call the model) → check (policy, then approval) → act (tool). Tool
output is fenced as untrusted data. The system prompt is fixed for the
life of the loop. A turn can be cancelled or steered between steps.

ARCHITECTURE §5.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator, Callable, Iterator, Mapping
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from praxis_prime.approvals.card import HOST_FULL_WRITE, mount_phrase
from praxis_prime.approvals.gate import (
    ApprovalDecision,
    ApprovalGate,
    ApprovalRequest,
    approval_actor,
    approval_session_id,
)
from praxis_prime.audit.log import AuditLog
from praxis_prime.decide.screen import ActionScreener
from praxis_prime.loop.control import TurnControl
from praxis_prime.loop.events import LoopEvent, StatusEvent, TurnEnded
from praxis_prime.loop.hooks import HookDecision, HookResult, LoopHooks
from praxis_prime.loop.prompt import FENCE_END, SYSTEM_PROMPT, fence_untrusted
from praxis_prime.memory.store import SessionStore
from praxis_prime.policy.boundary import InodeScanCache, ReadAccess, ReadDenied
from praxis_prime.policy.engine import HookPoint, PolicyContext, PolicyEngine
from praxis_prime.router.router import ModelRouter
from praxis_prime.router.types import (
    AssistantFinal,
    ChatMessage,
    ChatRequest,
    FallbackNotice,
    ProviderUnreachable,
    RouterExhausted,
    TextDelta,
    ToolCall,
)
from praxis_prime.tools.registry import PreparedCall, Risk, ToolContext, ToolRegistry

_OUTPUT_LIMIT = 16_000
_SECRET_KEY = re.compile(r"(?i)(api[_-]?key|token|secret|password|authorization)")
# Tools that cannot create a file or hard link. Anything else drops the
# inode scan before the next check. A read-risk shell can still ``ln``.
_INODE_CACHE_REUSE_TOOLS = frozenset(
    {
        "read_file",
        "list_dir",
        "grep",
        "glob",
        "web_fetch",
    }
)


def _reuses_inode_cache(name: str, risk: Risk) -> bool:
    """True when this tool cannot change the set of secret inodes.

    The loop keeps one cache and passes it on each ``PolicyContext``. A
    finished scan is reused only while every tool since the scan is in
    ``_INODE_CACHE_REUSE_TOOLS``. Any other tool marks the cache dirty.
    Reusing a set from before one of our tools wrote would allow a read a
    fresh scan would deny. Another process, or a project hook, can still
    add a file between two reads; this cache is not a lock against that.
    """
    return name in _INODE_CACHE_REUSE_TOOLS and risk == Risk.READ


class AgentLoop:
    """One session's conversation driver."""

    def __init__(
        self,
        *,
        router: ModelRouter,
        registry: ToolRegistry,
        policy: PolicyEngine,
        gate: ApprovalGate,
        cwd: Path,
        max_iterations: int = 200,
        mode: str = "ask",
        system_prompt: str = SYSTEM_PROMPT,
        history: list[ChatMessage] | None = None,
        preamble: str = "",
        store: SessionStore | None = None,
        audit: AuditLog | None = None,
        session_id: str | None = None,
        hooks: LoopHooks | None = None,
        screener: ActionScreener | None = None,
        recall_for: Callable[[str], str] | None = None,
        on_turn_end: Callable[[str, str], None] | None = None,
        read_access: ReadAccess | None = None,
        session_write_approved: bool = False,
        write_scope: Path | None = None,
        main_checkout: Path | None = None,
    ) -> None:
        self.router = router
        self.registry = registry
        self.policy = policy
        self.gate = gate
        self.cwd = Path(cwd)
        self.max_iterations = max_iterations
        self.mode = mode
        self.system_prompt = system_prompt
        self.history: list[ChatMessage] = list(history or [])
        self.preamble = preamble
        self.store = store
        self.audit = audit
        self.session_id = session_id
        self.hooks = hooks
        self.screener = screener
        self.recall_for = recall_for
        self.on_turn_end = on_turn_end
        self.read_access = read_access or ReadAccess()
        self.inode_cache = InodeScanCache()
        self._inode_cache_dirty = False
        self.session_write_approved = session_write_approved
        self.write_scope = None if write_scope is None else Path(write_scope)
        self.main_checkout = None if main_checkout is None else Path(main_checkout)
        self._turn_user = ""

    def run_turn(
        self,
        user_text: str,
        control: TurnControl | None = None,
    ) -> Iterator[LoopEvent]:
        """Run one user turn, yielding text and timeline events as they happen."""
        self.inode_cache.clear()
        self._inode_cache_dirty = False
        yield from self._run_turn(user_text, control)

    def _run_turn(
        self,
        user_text: str,
        control: TurnControl | None = None,
    ) -> Iterator[LoopEvent]:
        control = control or TurnControl()
        self._turn_user = user_text
        self.policy.session_id = self.session_id
        self._ingress(user_text)
        self._add_user(user_text)
        if self.session_id and self.store is not None:
            self.store.note_title(self.session_id, user_text)

        for iteration in range(1, self.max_iterations + 1):
            if control.cancelled:
                yield from self._cancelled("")
                return
            for steer in control.drain_steer():
                self._add_user(steer)
                yield StatusEvent("plan", f"steered: {_short(steer)}")
            if control.cancelled:
                yield from self._cancelled("")
                return

            blocked = self._prepare_model()
            if blocked:
                yield StatusEvent("plan", blocked)
                self._add_assistant(AssistantFinal(content=blocked))
                yield TextDelta(blocked)
                yield from self._turn_ended(blocked, error="compliance")
                return
            model = self.router.primary.spec()
            yield StatusEvent("plan", f"iteration {iteration} · {model}")
            request = ChatRequest(
                model=self.router.primary.model,
                messages=self._messages(),
                tools=tuple(self.registry.schemas()),
            )
            outcome = _Completion()
            try:
                yield from self._complete(request, control, outcome)
                if outcome.error:
                    return
                if control.cancelled:
                    self._add_assistant(AssistantFinal(content=outcome.content))
                    yield from self._cancelled(outcome.content)
                    return
                final = outcome.final or AssistantFinal(content=outcome.content)
                final = self._scan_model_output(final)
                if final.content and not outcome.streamed:
                    yield TextDelta(final.content)
            finally:
                self._restore_chain()
            self._add_assistant(final)
            self._audit(
                "model_call",
                f"iteration {iteration}",
                {
                    "model": model,
                    "tool_calls": [call.name for call in final.tool_calls],
                },
            )
            if not final.tool_calls:
                yield from self._turn_ended(final.content)
                return
            for call in final.tool_calls:
                if control.cancelled:
                    yield from self._cancelled(final.content)
                    return
                yield from self._check_and_act(call, control)
                if control.cancelled:
                    yield from self._cancelled(final.content)
                    return

        message = f"Stopped after {self.max_iterations} iterations without a final answer."
        self._add_assistant(AssistantFinal(content=message))
        yield TextDelta(message)
        yield from self._turn_ended(message, error="max_iterations")

    async def stream_turn(
        self,
        user_text: str,
        control: TurnControl | None = None,
    ) -> AsyncIterator[LoopEvent]:
        """Async wrapper around :meth:`run_turn` for embedding in an event loop."""
        for event in self.run_turn(user_text, control):
            yield event
            await asyncio.sleep(0)

    def reset_history(self) -> None:
        """Drop the in-memory transcript and session grants. Does not delete rows."""
        self.history.clear()
        self.gate.clear()

    def _messages(self) -> tuple[ChatMessage, ...]:
        return (ChatMessage(role="system", content=self.system_prompt), *self.history)

    def _ingress(self, user_text: str) -> None:
        self.policy.evaluate(
            PolicyContext(
                hook=HookPoint.H1_INGRESS,
                summary=_short(user_text),
                text=user_text,
                mode=self.mode,
            )
        )

    def _prepare_model(self) -> str | None:
        """Pin or block the model call. Return an error string when enforce blocks it."""
        text = "\n".join(message.content for message in self.history)
        verdict = self.policy.evaluate(
            PolicyContext(
                hook=HookPoint.H2_PRE_MODEL,
                mode=self.mode,
                tool="model",
                text=text,
                summary=_short(text),
            )
        )
        if verdict.decision == "deny":
            return verdict.reason
        allowed, message = self.policy.constrain_chain(self.router.chain, verdict)
        if message:
            return message
        if allowed != list(self.router.chain):
            self._chain_saved = list(self.router.chain)
            self.router.chain = allowed
        return None

    def _restore_chain(self) -> None:
        saved = getattr(self, "_chain_saved", None)
        if saved is not None:
            self.router.chain = saved
            self._chain_saved = None

    def _scan_model_output(self, final: AssistantFinal) -> AssistantFinal:
        if not final.content:
            return final
        verdict = self.policy.evaluate(
            PolicyContext(
                hook=HookPoint.H4_POST_TOOL,
                tool="model",
                mode=self.mode,
                text=final.content,
                summary=_short(final.content),
            )
        )
        if verdict.redact and verdict.redacted_text:
            return AssistantFinal(content=verdict.redacted_text, tool_calls=final.tool_calls)
        return final

    def _complete(
        self,
        request: ChatRequest,
        control: TurnControl,
        outcome: _Completion,
    ) -> Iterator[LoopEvent]:
        parts: list[str] = []
        try:
            for event in self.router.iter_stream(request):
                if control.cancelled:
                    outcome.content = "".join(parts)
                    return
                if isinstance(event, FallbackNotice):
                    yield StatusEvent("plan", event.text)
                elif isinstance(event, TextDelta):
                    outcome.streamed = True
                    parts.append(event.text)
                    yield event
                elif isinstance(event, AssistantFinal):
                    outcome.final = event
        except (RouterExhausted, ProviderUnreachable) as exc:
            message = str(exc)
            outcome.error = message
            self._audit("model_error", "model provider failed", {"error": _short(message, 400)})
            yield StatusEvent("plan", message)
            yield from self._turn_ended(outcome.content, error=message)
            return
        if outcome.final is None:
            outcome.final = AssistantFinal(content="".join(parts))
        outcome.content = outcome.final.content

    def _check_and_act(self, call: ToolCall, control: TurnControl) -> Iterator[LoopEvent]:
        try:
            tool = self.registry.get(call.name)
        except Exception as exc:
            content = f"Could not load {call.name}: {exc}"
            self._add_tool(call.id, content)
            yield StatusEvent("check", content)
            return
        if tool is None:
            content = f"Unknown tool {call.name}. It was not run."
            self._add_tool(call.id, content)
            yield StatusEvent("check", f"{call.name} · unknown tool · deny")
            return
        # A write marks the scan dirty. Drop it before classify so prepare
        # and the policy check share a fresh cache. Read-only tools leave
        # the flag clear and reuse the scan.
        if self._inode_cache_dirty:
            self.inode_cache.clear()
            self._inode_cache_dirty = False
        try:
            prepared = tool.prepare(
                call.arguments,
                workspace=self.cwd,
                cache=self.inode_cache,
            )
        except Exception as exc:
            content = f"Could not prepare {call.name}: {exc}"
            self._add_tool(call.id, content)
            yield StatusEvent("check", content)
            return

        ctx = PolicyContext(
            hook=HookPoint.H3_PRE_TOOL,
            tool=tool.name,
            risk=prepared.risk,
            arguments=call.arguments,
            sandboxed=prepared.sandboxed,
            force_approval=prepared.force_approval,
            force_reason=prepared.force_reason,
            mode=self.mode,
            summary=prepared.summary,
            text=prepared.summary,
            workspace_root=str(self.cwd),
            extra_roots=self.read_access.extra_roots,
            allow_paths=self.read_access.allow_paths,
            fetch_allow=tuple(sorted(self.read_access.fetch_allow)),
            inode_cache=self.inode_cache,
        )
        verdict = self.policy.evaluate(ctx)
        if self.screener is not None:
            verdict = self.screener.apply(verdict, ctx)
        self._audit(
            "policy",
            verdict.reason,
            {
                "hook": verdict.hook,
                "decision": verdict.decision,
                "tool": tool.name,
                "risk": prepared.risk.value,
                "arguments": _redact(call.arguments),
            },
        )
        yield StatusEvent(
            "check",
            f"{tool.name} · {prepared.risk.value} · {verdict.decision} · {verdict.reason}",
        )

        host_approved = False
        shell_approved = False
        if verdict.decision == "deny":
            content = f"Tool {tool.name} was not run. {verdict.reason}"
            self._add_tool(call.id, content)
            yield StatusEvent("result", f"{tool.name} · denied")
            return
        if verdict.decision == "ask":
            request = ApprovalRequest(
                tool=tool.name,
                risk=prepared.risk,
                reason=verdict.reason,
                summary=prepared.summary,
                arguments=dict(call.arguments),
                grant_key=verdict.grant_key,
                sandboxed=prepared.sandboxed,
                mount=self._mount_phrase(tool.name, prepared),
            )
            decision, actor = self._authorize(request)
            self._audit(
                "approval",
                decision.value,
                {
                    "tool": tool.name,
                    "risk": prepared.risk.value,
                    "grant_key": verdict.grant_key,
                    "arguments": _redact(call.arguments),
                    "sandboxed": prepared.sandboxed,
                    "actor": actor,
                },
            )
            if decision not in {ApprovalDecision.ALLOW_ONCE, ApprovalDecision.ALLOW_SESSION}:
                content = f"Tool {tool.name} was not run. Approval denied. {verdict.reason}"
                self._add_tool(call.id, content)
                yield StatusEvent("result", f"{tool.name} · approval denied")
                return
            host_approved = not prepared.sandboxed
            shell_approved = True
            yield StatusEvent("check", f"{tool.name} · approved · {decision.value}")

        blocked = self._pre_tool_hook(tool.name, call.arguments, prepared)
        if blocked is not None:
            self._add_tool(call.id, blocked)
            yield StatusEvent("result", f"{tool.name} · hook blocked")
            return

        if control.cancelled:
            content = f"Tool {tool.name} was not run. The turn was cancelled."
            self._add_tool(call.id, content)
            return

        yield StatusEvent("act", f"{tool.name} · {prepared.summary}")
        from praxis_prime.policy.shellguard import compliance_mode

        tool_ctx = ToolContext(
            cwd=str(self.cwd),
            cancelled=lambda: control.cancelled,
            host_shell_approved=host_approved,
            session_id=self.session_id,
            read_access=self.read_access,
            inode_cache=self.inode_cache,
            shell_approved=shell_approved,
            session_write_approved=self.session_write_approved,
            write_scope="" if self.write_scope is None else str(self.write_scope),
            main_checkout="" if self.main_checkout is None else str(self.main_checkout),
            audit=self.audit,
            dial_mode=compliance_mode(self.policy.positions),
        )
        try:
            raw = tool.execute(dict(call.arguments), tool_ctx)
            ok = True
        except ReadDenied as exc:
            raw = f"ReadDenied: {exc}"
            ok = False
            if self.policy.enforce_active():
                self._audit(
                    "read_denied",
                    f"read denied ({exc.code})",
                    {
                        "tool": tool.name,
                        "decision": "deny",
                        "code": exc.code,
                        "name": exc.display_name,
                    },
                )
        except Exception as exc:
            raw = f"{type(exc).__name__}: {exc}"
            ok = False
        if not _reuses_inode_cache(tool.name, prepared.risk):
            self._inode_cache_dirty = True
        raw, ok = self._post_tool_hook(tool.name, call.arguments, raw, ok=ok)
        post = self.policy.evaluate(
            PolicyContext(
                hook=HookPoint.H4_POST_TOOL,
                tool=tool.name,
                risk=prepared.risk,
                mode=self.mode,
                summary=_short(raw),
                text=raw,
            )
        )
        if post.redact and post.redacted_text:
            raw = post.redacted_text
        body = raw if len(raw) <= _OUTPUT_LIMIT else raw[:_OUTPUT_LIMIT] + "\n…[truncated]"
        if tool.trusted_output:
            shown = body.replace(FENCE_END, "<<<END UNTRUSTED (quoted)>>>")
        else:
            shown = fence_untrusted(body, source=tool.name, tool=tool.name)
        self._add_tool(call.id, shown)
        self._audit(
            "tool_call",
            f"{tool.name} {'ok' if ok else 'error'}",
            {
                "tool": tool.name,
                "ok": ok,
                "risk": prepared.risk.value,
                "arguments": _redact(call.arguments),
            },
        )
        yield StatusEvent("result", f"{tool.name} · {'ok' if ok else 'error'}")

    def _add_user(self, text: str) -> None:
        content = text
        if self.recall_for is not None:
            extra = self.recall_for(text)
            if extra:
                content = f"{extra}\n\n{text}"
        if self.preamble and not self.history:
            content = f"{self.preamble}\n\n{content}"
        if self.history and self.history[-1].role == "user":
            previous = self.history[-1]
            merged = ChatMessage(role="user", content=previous.content + "\n\n" + content)
            self.history[-1] = merged
            if self.store is not None and self.session_id:
                self.store.replace_last(self.session_id, merged)
            return
        message = ChatMessage(role="user", content=content)
        self.history.append(message)
        self._persist(message)

    def _add_assistant(self, final: AssistantFinal) -> None:
        message = ChatMessage(role="assistant", content=final.content, tool_calls=final.tool_calls)
        self.history.append(message)
        self._persist(message)

    def _add_tool(self, call_id: str, content: str) -> None:
        message = ChatMessage(role="tool", content=content, tool_call_id=call_id)
        self.history.append(message)
        self._persist(message)

    def _persist(self, message: ChatMessage) -> None:
        if self.store is None or not self.session_id:
            return
        verdict = self.policy.evaluate(
            PolicyContext(
                hook=HookPoint.H6_MEMORY_WRITE,
                tool="session",
                mode=self.mode,
                text=message.content,
                summary=_short(message.content),
            )
        )
        self.store.append(self.session_id, _stored_message(message, verdict))

    def _audit(self, kind: str, summary: str, payload: dict[str, object]) -> None:
        if self.audit is None:
            return
        self.audit.append(
            session_id=self.session_id,
            kind=kind,
            summary=summary,
            payload=payload,
        )

    def _mount_phrase(self, tool_name: str, prepared: PreparedCall) -> str:
        """Say how this command runs if it is approved.

        A sandboxed command is a read-only mount or a read-write mount.
        Without bubblewrap it runs on the host, so the card says that and
        does not describe the run as read-only.
        """
        if tool_name not in {"shell", "run_command", "run_tests"}:
            return ""
        if not prepared.sandboxed:
            return HOST_FULL_WRITE
        from praxis_prime.tools.shell import bind_is_writable

        writable = bind_is_writable(
            write_capable=prepared.write_capable,
            approved=True,
            session_write_approved=self.session_write_approved,
            write_scope="" if self.write_scope is None else str(self.write_scope),
            cwd=str(self.cwd),
            main_checkout="" if self.main_checkout is None else str(self.main_checkout),
        )
        return mount_phrase(writable)

    def _authorize(self, request: ApprovalRequest) -> tuple[ApprovalDecision, str]:
        session_token = approval_session_id.set(self.session_id)
        actor_token = approval_actor.set("")
        try:
            decision = self.gate.authorize(request)
            actor = approval_actor.get()
        finally:
            approval_session_id.reset(session_token)
            approval_actor.reset(actor_token)
        return decision, actor

    def _pre_tool_hook(
        self,
        name: str,
        arguments: Mapping[str, object],
        prepared: PreparedCall,
    ) -> str | None:
        """Return a tool message when a hook blocks or its ask is denied."""
        if self.hooks is None:
            return None
        try:
            result = self.hooks.pre_tool(name, arguments)
        except Exception as exc:
            result = HookResult(HookDecision.DENY, f"pre-tool hook failed: {exc}")
        if result.decision == HookDecision.DENY:
            reason = result.reason or "pre-tool hook blocked this action"
            self._audit("hook", reason, {"tool": name, "event": "PreToolUse", "decision": "deny"})
            return f"Tool {name} was not run. Hook blocked it. {reason}"
        if result.decision == HookDecision.ASK:
            reason = result.reason or "project hook asked for approval"
            request = ApprovalRequest(
                tool=name,
                risk=prepared.risk,
                reason=reason,
                summary=prepared.summary or name,
                arguments=dict(arguments),
                grant_key=f"hook:{name}:{reason[:80]}",
                sandboxed=prepared.sandboxed,
                mount=self._mount_phrase(name, prepared),
            )
            decision, actor = self._authorize(request)
            self._audit(
                "approval",
                decision.value,
                {"tool": name, "actor": actor, "hook": "PreToolUse"},
            )
            if decision not in {ApprovalDecision.ALLOW_ONCE, ApprovalDecision.ALLOW_SESSION}:
                return f"Tool {name} was not run. Hook asked and approval was denied. {reason}"
        return None

    def _post_tool_hook(
        self,
        name: str,
        arguments: Mapping[str, object],
        raw: str,
        *,
        ok: bool,
    ) -> tuple[str, bool]:
        if self.hooks is None:
            return raw, ok
        try:
            result = self.hooks.post_tool(name, arguments, raw, ok=ok)
        except Exception as exc:
            result = HookResult(HookDecision.DENY, f"post-tool hook failed: {exc}")
        if result.decision == HookDecision.DENY:
            reason = result.reason or "post-tool hook blocked this result"
            self._audit("hook", reason, {"tool": name, "event": "PostToolUse", "decision": "deny"})
            return f"{raw}\nHook blocked this result. {reason}", False
        return raw, ok

    def _turn_ended(
        self,
        text: str,
        *,
        cancelled: bool = False,
        error: str | None = None,
    ) -> Iterator[LoopEvent]:
        if not cancelled and self.on_turn_end is not None:
            try:
                self.on_turn_end(self._turn_user, text)
            except Exception as exc:
                self._audit(
                    "memory_error",
                    "episodic write failed",
                    {"error": type(exc).__name__},
                )
        if not cancelled and self.hooks is not None:
            try:
                result = self.hooks.on_finish(text)
            except Exception as exc:
                result = HookResult(HookDecision.DENY, f"on-finish hook failed: {exc}")
            if result.decision == HookDecision.DENY:
                reason = result.reason or "on-finish hook blocked"
                self._audit("hook", reason, {"event": "Stop", "decision": "deny"})
                yield StatusEvent("check", f"on-finish · blocked · {reason}")
                text = f"{text}\n{reason}".strip()
                error = error or reason
        yield TurnEnded(text=text, cancelled=cancelled, error=error)

    def _cancelled(self, text: str) -> Iterator[LoopEvent]:
        self._audit("turn_cancelled", "turn cancelled", {})
        yield StatusEvent("plan", "turn cancelled")
        yield TurnEnded(text=text, cancelled=True)


class _Completion:
    """Mutable result of one model call. Display events are yielded separately."""

    def __init__(self) -> None:
        self.final: AssistantFinal | None = None
        self.content = ""
        self.streamed = False
        self.error: str | None = None


def _stored_message(message: ChatMessage, verdict: object) -> ChatMessage:
    """Keep the live transcript. Persist a redacted copy when enforce says so."""
    redact = bool(getattr(verdict, "redact", False))
    decision = str(getattr(verdict, "decision", "allow"))
    redacted = str(getattr(verdict, "redacted_text", "") or "")
    if decision == "allow" and not redact:
        return message
    content = redacted if redact and redacted else "[redacted]"
    return ChatMessage(
        role=message.role,
        content=content,
        tool_calls=message.tool_calls,
        tool_call_id=message.tool_call_id,
    )


def _short(text: str, limit: int = 160) -> str:
    flat = " ".join(text.split())
    if len(flat) <= limit:
        return flat
    return flat[: limit - 1] + "…"


def _redact(arguments: Mapping[str, object]) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    for key, value in arguments.items():
        name = str(key)
        if _SECRET_KEY.search(name):
            cleaned[name] = "[redacted]"
        else:
            cleaned[name] = _redact_text(str(value))
    return cleaned


def _redact_text(text: str) -> str:
    """Drop query strings and fragments so a fetched token is not audited."""
    stripped = text.strip()
    parsed = urlparse(stripped)
    if parsed.scheme in {"http", "https"} and (parsed.query or parsed.fragment):
        query = "[redacted]" if parsed.query else ""
        stripped = urlunparse(parsed._replace(query=query, fragment=""))
    return _short(stripped, 180)
