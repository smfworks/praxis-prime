"""Apply loaded packs at a policy hook.

Monitor records a warning and does not change the decision. Enforce may
only tighten it (allow to ask or deny), redact, or pin providers. A hook,
skill, MCP server, or Decision Engine result cannot loosen that outcome.

ARCHITECTURE §16.2 and §17.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from praxis_prime.compliance.detectors import Hit, detect, redact_spans
from praxis_prime.compliance.packs import PolicyPack, RuleSpec, packs_for_dials
from praxis_prime.compliance.providers import filter_chain
from praxis_prime.policy.engine import PolicyContext, PolicyEngine, Verdict
from praxis_prime.router.types import ModelRef

_EXTERNAL = frozenset({"browser", "mcp", "telegram", "web_fetch"})


@dataclass(frozen=True, slots=True)
class RouteResult:
    chain: tuple[ModelRef, ...]
    message: str


def apply_compliance(engine: PolicyEngine, ctx: PolicyContext, verdict: Verdict) -> Verdict:
    """Fold active packs into ``verdict``. Dials that are off are skipped."""
    packs = packs_for_dials(engine.packs, engine.positions)
    if not packs:
        return verdict
    text = context_text(ctx)
    hits = _hits(text, packs)
    if not hits and ctx.hook.value != "H7":
        return verdict
    warnings: list[str] = []
    classes: list[str] = []
    groups: list[tuple[str, ...]] = list(verdict.route_groups)
    spans: list[tuple[int, int, str]] = []
    decision = verdict.decision
    reason = verdict.reason
    rules_hit: list[str] = []
    dials_hit: list[str] = []
    for hit, pack in hits:
        position = engine.positions.get(pack.dial, "off")
        classes.append(hit.data_class)
        matched = _rules_for(pack, hit, ctx)
        if not matched:
            if position == "monitor":
                warnings.append(
                    f"{pack.dial} monitor: detected {hit.data_class} ({hit.detector_id})"
                )
            elif position == "enforce":
                warnings.append(
                    f"{pack.dial} enforce: detected {hit.data_class} ({hit.detector_id})"
                )
            dials_hit.append(pack.dial)
            continue
        for rule in matched:
            rules_hit.append(rule.id)
            dials_hit.append(pack.dial)
            note = _note(pack, rule, hit)
            if position == "monitor":
                warnings.append(f"{pack.dial} monitor: would {rule.action}: {note}")
                continue
            decision, reason = _enforce(
                decision,
                reason,
                rule,
                note,
                groups,
                spans,
                hit,
            )
    redacted = ""
    redact = False
    if spans and text:
        redacted = redact_spans(text, spans)
        redact = redacted != text
    updated = Verdict(
        decision,
        reason,
        verdict.hook,
        verdict.grant_key,
        tuple(dict.fromkeys((*verdict.warnings, *warnings))),
        tuple(dict.fromkeys((*verdict.data_classes, *classes))),
        redacted if redact else verdict.redacted_text,
        tuple(dict.fromkeys((*verdict.route_groups, *groups))),
        verdict.redact or redact,
    )
    _audit(
        engine,
        ctx,
        updated,
        rules_hit,
        dials_hit,
        monitor_only=_monitor_only(engine, dials_hit),
    )
    return updated


def constrain_chain(
    engine: PolicyEngine, chain: Sequence[ModelRef], verdict: Verdict
) -> RouteResult:
    """Drop providers the enforce pins do not allow. Monitor does not pin."""
    if not verdict.route_groups:
        return RouteResult(tuple(chain), "")
    kept = filter_chain(chain, verdict.route_groups, engine.provider_flags)
    if kept:
        return RouteResult(tuple(kept), "")
    classes = ", ".join(verdict.data_classes) or "protected data"
    needed = " and ".join(
        "(" + " or ".join(group) + ")" for group in verdict.route_groups
    )
    message = (
        f"Blocked by compliance enforce: {classes} detected. "
        f"No provider in the chain is flagged {needed}. "
        "Cloud egress stays denied until the owner config flags an allowed provider "
        "(local, baa, eu_region, or zero_retention). "
        "This is a starter policy, not legal advice."
    )
    return RouteResult((), message)


def redact_for_memory(text: str, dials: Mapping[str, str], packs: tuple[PolicyPack, ...]) -> str:
    """Redact enforce-mode memory text. Monitor does not use this path."""
    active = packs_for_dials(packs, {key: value for key, value in dials.items()})
    spans: list[tuple[int, int, str]] = []
    for hit, pack in _hits(text, active):
        if dials.get(pack.dial) != "enforce":
            continue
        for rule in pack.rules:
            if rule.action != "redact":
                continue
            if "H6" not in rule.hooks:
                continue
            if hit.data_class not in rule.data_classes:
                continue
            spans.append((hit.start, hit.end, rule.style))
    if not spans:
        return text
    return redact_spans(text, spans)


def feed_tier0(
    text: str, dials: Mapping[str, str], packs: tuple[PolicyPack, ...]
) -> list[tuple[str, str]]:
    """Positive data-class tags for Decision Engine tier 0.

    The engine may add a class. It does not clear one that rules already set.
    """
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for hit, _pack in _hits(text, packs_for_dials(packs, dict(dials))):
        if hit.data_class in seen:
            continue
        seen.add(hit.data_class)
        found.append(
            (
                hit.data_class,
                f"T0 {hit.kind} detector {hit.detector_id} (starter policy, not legal advice)",
            )
        )
    return found


def context_text(ctx: PolicyContext) -> str:
    parts: list[str] = []
    if ctx.text:
        parts.append(ctx.text)
    elif ctx.summary:
        parts.append(ctx.summary)
    if ctx.arguments:
        try:
            dumped = json.dumps(ctx.arguments, default=str, sort_keys=True)
        except (TypeError, ValueError):
            dumped = str(ctx.arguments)
        parts.append(dumped[:20_000])
    if ctx.force_reason and ctx.force_reason not in ctx.text:
        parts.append(ctx.force_reason)
    return "\n".join(parts)[:100_000]


def tool_matches(tool: str, patterns: Sequence[str]) -> bool:
    name = tool.lower()
    for pattern in patterns:
        token = pattern.lower()
        if token == "mcp" and (name.startswith("mcp__") or name.startswith("mcp_")):
            return True
        if token in _EXTERNAL and (name == token or name.startswith(token + "_")):
            return True
        if name == token or name.startswith(token + "_"):
            return True
    return False


def _hits(text: str, packs: Sequence[PolicyPack]) -> list[tuple[Hit, PolicyPack]]:
    paired: list[tuple[Hit, PolicyPack]] = []
    if not text:
        return paired
    for pack in packs:
        for hit in detect(text, pack.detectors):
            paired.append((hit, pack))
    return paired


def _rules_for(pack: PolicyPack, hit: Hit, ctx: PolicyContext) -> list[RuleSpec]:
    matched: list[RuleSpec] = []
    for rule in pack.rules:
        if hit.data_class not in rule.data_classes:
            continue
        if rule.hooks and ctx.hook.value not in rule.hooks:
            continue
        if rule.tools and not tool_matches(ctx.tool, rule.tools):
            continue
        matched.append(rule)
    return matched


def _enforce(
    decision: str,
    reason: str,
    rule: RuleSpec,
    note: str,
    groups: list[tuple[str, ...]],
    spans: list[tuple[int, int, str]],
    hit: Hit,
) -> tuple[str, str]:
    if rule.action in {"block", "egress_deny"}:
        return _raise(decision, reason, "deny", f"compliance enforce blocked this. {note}")
    if rule.action == "require_approval":
        return _raise(decision, reason, "ask", f"compliance enforce requires approval. {note}")
    if rule.action == "redact":
        spans.append((hit.start, hit.end, rule.style))
        return decision, reason
    if rule.action == "route_local":
        flags = rule.provider_flags or ("local",)
        groups.append(tuple(flags))
        return decision, reason
    return decision, reason


def _raise(decision: str, reason: str, proposed: str, proposed_reason: str) -> tuple[str, str]:
    rank = {"allow": 0, "ask": 1, "deny": 2}
    if rank[proposed] > rank.get(decision, 0):
        return proposed, proposed_reason
    return decision, reason


def _note(pack: PolicyPack, rule: RuleSpec, hit: Hit) -> str:
    return (
        f"{pack.title} ({pack.dial}) {rule.id} on {hit.data_class}. "
        "Starter policy, not legal advice."
    )


def _monitor_only(engine: PolicyEngine, dials_hit: list[str]) -> bool:
    if not dials_hit:
        return True
    return all(engine.positions.get(dial_id) == "monitor" for dial_id in dials_hit)


def _audit(
    engine: PolicyEngine,
    ctx: PolicyContext,
    verdict: Verdict,
    rules_hit: list[str],
    dials_hit: list[str],
    *,
    monitor_only: bool,
) -> None:
    audit = engine.audit
    if audit is None or not (verdict.warnings or verdict.data_classes or rules_hit):
        return
    decision = "warn" if monitor_only and verdict.decision == "allow" else verdict.decision
    summary = verdict.warnings[0] if verdict.warnings else verdict.reason
    audit.append(
        session_id=engine.session_id,
        kind="compliance",
        summary=summary[:300],
        payload={
            "hook": ctx.hook.value,
            "tool": ctx.tool,
            "decision": decision,
            "data_classes": list(verdict.data_classes),
            "rules": list(dict.fromkeys(rules_hit)),
            "dials": list(dict.fromkeys(dials_hit)),
            "route_groups": [list(group) for group in verdict.route_groups],
            "redact": verdict.redact,
        },
    )
