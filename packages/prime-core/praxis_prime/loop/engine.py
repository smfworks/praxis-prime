"""Agent loop.

Plan (call the model) → check (policy, then approval) → act (tool). Tool
output is fenced as untrusted data. The system prompt is fixed for the
life of the loop. A turn can be cancelled or steered between steps.

ARCHITECTURE §5.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator, Iterator, Mapping
from pathlib import Path

from praxis_prime.approvals.gate import (
    ApprovalDecision,
    ApprovalGate,
    ApprovalRequest,
    approval_actor,
    approval_session_id,
)
from praxis_prime.audit.log import AuditLog
from praxis_prime.loop.control import TurnControl
from praxis_prime.loop.events import LoopEvent, StatusEvent, TurnEnded
from praxis_prime.loop.prompt import SYSTEM_PROMPT, fence_untrusted
from praxis_prime.memory.store import SessionStore
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
from praxis_prime.tools.registry import ToolContext, ToolRegistry

_OUTPUT_LIMIT = 16_000
_SECRET_KEY = re.compile(r"(?i)(api[_-]?key|token|secret|password|authorization)")


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

    def run_turn(
        self,
        user_text: str,
        control: TurnControl | None = None,
    ) -> Iterator[LoopEvent]:
        """Run one user turn, yielding text and timeline events as they happen."""
        control = control or TurnControl()
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

            model = self.router.primary.spec()
            yield StatusEvent("plan", f"iteration {iteration} · {model}")
            self._pre_model()
            request = ChatRequest(
                model=self.router.primary.model,
                messages=self._messages(),
                tools=tuple(self.registry.schemas()),
            )
            outcome = _Completion()
            yield from self._complete(request, control, outcome)
            if outcome.error:
                return
            if control.cancelled:
                self._add_assistant(AssistantFinal(content=outcome.content))
                yield from self._cancelled(outcome.content)
                return
            final = outcome.final or AssistantFinal(content=outcome.content)
            if final.content and not outcome.streamed:
                yield TextDelta(final.content)
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
                yield TurnEnded(text=final.content)
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
        yield TurnEnded(text=message, error="max_iterations")

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
            PolicyContext(hook=HookPoint.H1_INGRESS, summary=_short(user_text), mode=self.mode)
        )

    def _pre_model(self) -> None:
        self.policy.evaluate(
            PolicyContext(hook=HookPoint.H2_PRE_MODEL, mode=self.mode, tool="model")
        )

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
            yield TurnEnded(text=outcome.content, error=message)
            return
        if outcome.final is None:
            outcome.final = AssistantFinal(content="".join(parts))
        outcome.content = outcome.final.content

    def _check_and_act(self, call: ToolCall, control: TurnControl) -> Iterator[LoopEvent]:
        tool = self.registry.get(call.name)
        if tool is None:
            content = f"Unknown tool {call.name}. It was not run."
            self._add_tool(call.id, content)
            yield StatusEvent("check", f"{call.name} · unknown tool · deny")
            return
        try:
            prepared = tool.prepare(call.arguments)
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
        )
        verdict = self.policy.evaluate(ctx)
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
            )
            session_token = approval_session_id.set(self.session_id)
            actor_token = approval_actor.set("")
            try:
                decision = self.gate.authorize(request)
                actor = approval_actor.get()
            finally:
                approval_session_id.reset(session_token)
                approval_actor.reset(actor_token)
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
            yield StatusEvent("check", f"{tool.name} · approved · {decision.value}")

        if control.cancelled:
            content = f"Tool {tool.name} was not run. The turn was cancelled."
            self._add_tool(call.id, content)
            return

        yield StatusEvent("act", f"{tool.name} · {prepared.summary}")
        tool_ctx = ToolContext(
            cwd=str(self.cwd),
            cancelled=lambda: control.cancelled,
            host_shell_approved=host_approved,
        )
        try:
            raw = tool.execute(dict(call.arguments), tool_ctx)
            ok = True
        except Exception as exc:
            raw = f"{type(exc).__name__}: {exc}"
            ok = False
        self.policy.evaluate(
            PolicyContext(
                hook=HookPoint.H4_POST_TOOL,
                tool=tool.name,
                risk=prepared.risk,
                mode=self.mode,
                summary=_short(raw),
            )
        )
        body = raw if len(raw) <= _OUTPUT_LIMIT else raw[:_OUTPUT_LIMIT] + "\n…[truncated]"
        fenced = fence_untrusted(body, source=tool.name, tool=tool.name)
        self._add_tool(call.id, fenced)
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
        if self.preamble and not self.history:
            content = f"{self.preamble}\n\n{text}"
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
        self.policy.evaluate(
            PolicyContext(hook=HookPoint.H6_MEMORY_WRITE, tool="session", mode=self.mode)
        )
        self.store.append(self.session_id, message)

    def _audit(self, kind: str, summary: str, payload: dict[str, object]) -> None:
        if self.audit is None:
            return
        self.audit.append(
            session_id=self.session_id,
            kind=kind,
            summary=summary,
            payload=payload,
        )

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
            cleaned[name] = _short(str(value), 180)
    return cleaned
