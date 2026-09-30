"""Tiered decision cascade.

Tier 0 rules, Tier 1 classifiers, Tier 2 one local judge, Tier 3 a jury,
then Tier 4 a larger model or a human on the approval queue. A tier returns
as soon as its calibrated confidence clears the threshold and policy lets
that tier decide alone.

This process never calls a hosted Jev or TypeSafe endpoint.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from collections.abc import Mapping
from pathlib import Path

from praxis_prime.approvals.gate import (
    ApprovalDecision,
    ApprovalRequest,
    Approver,
)
from praxis_prime.audit.log import AuditLog
from praxis_prime.decide.aggregate import aggregate, label_distribution
from praxis_prime.decide.calibration import Calibrator, CalibratorStore
from praxis_prime.decide.classifiers import Classifier, KeywordClassifier
from praxis_prime.decide.config import DecideConfig, load_decide_config, safety_purpose
from praxis_prime.decide.judges import Judge, RouterJudge
from praxis_prime.decide.labels import LabelStore
from praxis_prime.decide.rules import evaluate_rules
from praxis_prime.decide.schema import (
    DecideRequest,
    DecisionResponse,
    JudgeVote,
    Question,
    QuestionAnswer,
    RequestLimits,
    parse_request,
)
from praxis_prime.paths import data_dir
from praxis_prime.router.router import ModelRouter
from praxis_prime.tools.registry import Risk

_SAFER = ("deny", "no", "false", "block", "reject", "unsafe")


class DecisionEngine:
    """In-process ``decide()`` implementation."""

    def __init__(
        self,
        config: DecideConfig | None = None,
        *,
        router: ModelRouter | None = None,
        judge: Judge | None = None,
        audit: AuditLog | None = None,
        approver: Approver | None = None,
        dials: Mapping[str, str] | None = None,
        labels: LabelStore | None = None,
        calibrators: CalibratorStore | None = None,
        classifiers: list[Classifier] | None = None,
        data_root: Path | None = None,
    ) -> None:
        self.config = config or DecideConfig()
        self.router = router
        self.judge = judge if judge is not None else (RouterJudge(router) if router else None)
        self.audit = audit
        self.approver = approver
        self.dials = dict(dials or {})
        root = data_root if data_root is not None else data_dir()
        self.labels = (
            labels if labels is not None else LabelStore(root / "decide" / "labels.db")
        )
        store = root / "decide" / "calibrators"
        self.calibrators = calibrators if calibrators is not None else CalibratorStore(store)
        self.classifiers: list[Classifier] = list(classifiers or [KeywordClassifier()])

    def decide(self, payload: DecideRequest | dict[str, object]) -> DecisionResponse:
        request = parse_request(payload)
        started = time.perf_counter()
        limits = _limits(self.config, request.limits)
        answers: dict[str, QuestionAnswer] = {}
        calls = 0
        spent = 0.0
        for key, question in request.questions.items():
            answer, used, cost = self._answer(
                key,
                question,
                request.state_text,
                limits,
                calls_used=calls,
                spent=spent,
            )
            answers[key] = answer
            calls += used
            spent += cost
        elapsed_ms = (time.perf_counter() - started) * 1000
        response = DecisionResponse(
            model=request.model,
            decision_id=_new_id(),
            answers=answers,
            latency_ms=elapsed_ms,
            cost_usd=spent,
            escalate=any(answer.escalate for answer in answers.values()),
        )
        self._record(response)
        response.audit_hash, response.audit_seq = self._audit(request, response)
        return response

    def _answer(
        self,
        key: str,
        question: Question,
        state: str,
        limits: _BoundLimits,
        *,
        calls_used: int,
        spent: float,
    ) -> tuple[QuestionAnswer, int, float]:
        started = time.perf_counter()
        trace: list[str] = []
        best: _Partial | None = None
        calls = 0
        cost = 0.0
        for tier in range(0, 5):
            if tier > limits.max_tier:
                trace.append(f"T{tier}: above max tier {limits.max_tier}")
                break
            blocked = self._budget_blocked(started, limits, calls_used + calls, spent + cost)
            if tier >= 2 and blocked:
                trace.append(f"T{tier}: budget exhausted, escalating")
                break
            partial, used = self._run_tier(tier, question, state, limits)
            calls += used
            if partial is None:
                trace.append(f"T{tier}: abstain")
                continue
            cost += used * self.config.usd_per_call
            partial.tier = tier
            best = partial
            trace.extend(partial.notes)
            allowed = not (safety_purpose(limits.purpose) and tier == 1)
            if not allowed:
                partial.decisive = False
                trace.append(f"T{tier}: policy does not let this tier decide {limits.purpose}")
            elif partial.decisive and partial.confidence >= limits.min_confidence:
                trace.append(
                    f"T{tier}: confidence {partial.confidence:.2f} "
                    f"clears {limits.min_confidence:.2f}"
                )
                break
            else:
                trace.append(
                    f"T{tier}: confidence {partial.confidence:.2f} "
                    f"below {limits.min_confidence:.2f}"
                )
        if best is None:
            best = _abstain(question)
            trace.append("no tier decided")
        escalate = best.confidence < limits.min_confidence or not best.decisive
        if best.human:
            escalate = False
        answer = QuestionAnswer(
            question_id=key,
            type=question.type,
            label=best.label,
            confidence=best.confidence,
            tier=best.tier,
            probabilities=best.probabilities,
            raw_probabilities=best.raw_probabilities,
            votes=best.votes,
            disagreement=best.disagreement,
            rationale=best.rationale,
            trace=trace,
            latency_ms=(time.perf_counter() - started) * 1000,
            cost_usd=cost,
            input_tokens=best.input_tokens,
            output_tokens=best.output_tokens,
            escalate=escalate,
            calibrator=best.calibrator,
        )
        return answer, calls, cost

    def _run_tier(
        self,
        tier: int,
        question: Question,
        state: str,
        limits: _BoundLimits,
    ) -> tuple[_Partial | None, int]:
        if tier == 0:
            return self._tier0(question, state), 0
        if tier == 1:
            return self._tier1(question, state), 0
        if tier == 2:
            return self._tier2(question, state)
        if tier == 3:
            return self._tier3(question, state, limits)
        return self._tier4(question, state, limits)

    def _tier0(self, question: Question, state: str) -> _Partial | None:
        hit = evaluate_rules(
            question,
            state,
            dials=self.dials,
            deny=self.config.deny,
            allow=self.config.allow,
        )
        if hit is None:
            return None
        return _Partial(
            label=hit.label,
            confidence=hit.confidence,
            probabilities=hit.probabilities,
            raw_probabilities=dict(hit.probabilities),
            rationale=hit.rationale,
            decisive=True,
            calibrator="rules@v0",
            notes=[f"T0: {hit.rationale}"],
        )

    def _tier1(self, question: Question, state: str) -> _Partial | None:
        for classifier in self.classifiers:
            found = classifier.classify(state, question)
            if found is None:
                continue
            label, confidence = found
            raw = label_distribution(label, confidence, question.options)
            calibrated, version = self._calibrate(raw)
            top = _top(calibrated)
            return _Partial(
                label=top,
                confidence=calibrated.get(top, confidence),
                probabilities=calibrated,
                raw_probabilities=raw,
                rationale=f"{classifier.name} classifier",
                decisive=True,
                calibrator=version,
                notes=[f"T1: {classifier.name} chose {label}"],
            )
        return None

    def _tier2(self, question: Question, state: str) -> tuple[_Partial | None, int]:
        vote = self._ask(self.config.tier2_model, "judge", question, state)
        if vote is None:
            return None, 0
        partial = self._from_vote(vote, notes=[f"T2: {vote.label} ({vote.confidence:.2f})"])
        return partial, 1

    def _tier3(
        self,
        question: Question,
        state: str,
        limits: _BoundLimits,
    ) -> tuple[_Partial | None, int]:
        votes: list[JudgeVote] = []
        roles = self.config.jury_roles()
        for index, role in enumerate(roles):
            vote = self._ask(self.config.model_for_role(index), role, question, state)
            if vote is not None:
                votes.append(vote)
        if not votes:
            return None, 0
        label, probabilities, divergence, tied = aggregate(
            votes, question.options, self.config.aggregation
        )
        calibrated, version = self._calibrate(probabilities)
        chosen = label
        confidence = calibrated.get(chosen, 0.0)
        decisive = (not tied) and divergence <= limits.disagreement_js
        notes = [
            f"T3: {len(votes)} judges, disagreement {divergence:.3f}, label {chosen}"
        ]
        return (
            _Partial(
                label=chosen,
                confidence=confidence,
                probabilities=calibrated,
                raw_probabilities=probabilities,
                rationale="jury",
                decisive=decisive,
                votes=votes,
                disagreement=divergence,
                calibrator=version,
                notes=notes,
                input_tokens=sum(len(vote.rationale) for vote in votes),
                output_tokens=len(votes),
            ),
            len(votes),
        )

    def _tier4(
        self,
        question: Question,
        state: str,
        limits: _BoundLimits,
    ) -> tuple[_Partial | None, int]:
        vote = self._ask(self.config.tier4_model, "reviewer", question, state)
        calls = 0 if vote is None else 1
        partial = None if vote is None else self._from_vote(
            vote, notes=[f"T4: {vote.label} ({vote.confidence:.2f})"]
        )
        needs_human = self.config.escalate_to_human and self.approver is not None
        weak = partial is None or partial.confidence < limits.min_confidence or not partial.decisive
        if needs_human and weak:
            human = self._human(question, partial)
            if human is not None:
                if partial is not None:
                    human.notes = [*partial.notes, *human.notes]
                    human.input_tokens += partial.input_tokens
                    human.output_tokens += partial.output_tokens
                return human, calls
        return partial, calls

    def _human(self, question: Question, partial: _Partial | None) -> _Partial | None:
        if self.approver is None:
            return None
        recommended = partial.label if partial is not None else ""
        request = ApprovalRequest(
            tool="decide",
            risk=Risk.READ,
            reason="Decision Engine tier 4 needs a human",
            summary=question.instructions[:180],
            arguments={
                "question": question.instructions[:500],
                "recommendation": recommended,
                "options": list(question.options),
            },
            grant_key=f"decide:{hashlib.sha256(question.instructions.encode()).hexdigest()[:12]}",
            sandboxed=True,
        )
        try:
            decision = self.approver(request)
        except Exception:
            return None
        if decision in {ApprovalDecision.ALLOW_ONCE, ApprovalDecision.ALLOW_SESSION}:
            label = recommended or question.options[0]
            probabilities = label_distribution(label, 1.0, question.options)
            return _Partial(
                label=label,
                confidence=1.0,
                probabilities=probabilities,
                raw_probabilities=probabilities,
                rationale="human approved the recommendation",
                decisive=True,
                human=True,
                calibrator="human@v0",
                notes=["T4: human approved"],
            )
        label = _safer_label(question, recommended)
        probabilities = label_distribution(label, 1.0, question.options)
        return _Partial(
            label=label,
            confidence=1.0,
            probabilities=probabilities,
            raw_probabilities=probabilities,
            rationale="human denied the recommendation",
            decisive=True,
            human=True,
            calibrator="human@v0",
            notes=["T4: human denied"],
        )

    def _ask(self, model: str, role: str, question: Question, state: str) -> JudgeVote | None:
        if self.judge is None:
            return None
        try:
            return self.judge.ask(model=model, role=role, question=question, state=state)
        except Exception:
            return None

    def _from_vote(self, vote: JudgeVote, *, notes: list[str]) -> _Partial:
        raw = dict(vote.probabilities)
        calibrated, version = self._calibrate(raw)
        label = _top(calibrated)
        return _Partial(
            label=label,
            confidence=calibrated.get(label, vote.confidence),
            probabilities=calibrated,
            raw_probabilities=raw,
            rationale=vote.rationale or role_note(vote.role),
            decisive=True,
            votes=[vote],
            calibrator=version,
            notes=notes,
            input_tokens=max(1, len(vote.rationale) // 4),
            output_tokens=max(1, len(vote.label)),
        )

    def _calibrate(self, probabilities: dict[str, float]) -> tuple[dict[str, float], str]:
        calibrator = self.calibrators.load()
        adjusted = _renormalize(calibrator.apply(probabilities))
        return adjusted, calibrator.version

    def _budget_blocked(
        self,
        started: float,
        limits: _BoundLimits,
        calls: int,
        spent: float,
    ) -> bool:
        elapsed_ms = (time.perf_counter() - started) * 1000
        if limits.latency_budget_ms >= 0 and elapsed_ms > limits.latency_budget_ms:
            return True
        if calls >= limits.max_calls:
            return True
        if self.config.usd_per_call > 0 and spent + self.config.usd_per_call > limits.max_usd:
            return True
        return False

    def _record(self, response: DecisionResponse) -> None:
        for answer in response.answers.values():
            self.labels.record(
                decision_id=response.decision_id,
                question_id=answer.question_id,
                predicted=answer.label,
                confidence=answer.confidence,
                probabilities=answer.probabilities,
            )

    def _audit(
        self,
        request: DecideRequest,
        response: DecisionResponse,
    ) -> tuple[str | None, int | None]:
        if self.audit is None:
            return None, None
        digest = hashlib.sha256(request.state_text.encode()).hexdigest()
        payload = {
            "decision_id": response.decision_id,
            "model": response.model,
            "state_sha256": digest,
            "escalate": response.escalate,
            "cost_usd": round(response.cost_usd, 6),
            "latency_ms": round(response.latency_ms, 3),
            "answers": {
                key: {
                    "label": answer.label,
                    "confidence": round(answer.confidence, 4),
                    "tier": answer.tier,
                    "disagreement": answer.disagreement,
                    "votes": [
                        {"role": vote.role, "label": vote.label, "confidence": vote.confidence}
                        for vote in answer.votes
                    ],
                }
                for key, answer in response.answers.items()
            },
        }
        audit_hash = self.audit.append(
            session_id=None,
            kind="decision",
            summary=response.decision_id,
            payload=payload,
        )
        return audit_hash, self.audit.last_id()


class _Partial:
    def __init__(
        self,
        *,
        label: str,
        confidence: float,
        probabilities: dict[str, float],
        raw_probabilities: dict[str, float],
        rationale: str,
        decisive: bool,
        calibrator: str,
        notes: list[str],
        votes: list[JudgeVote] | None = None,
        disagreement: float | None = None,
        human: bool = False,
        input_tokens: int = 0,
        output_tokens: int = 0,
        tier: int = 0,
    ) -> None:
        self.label = label
        self.confidence = confidence
        self.probabilities = probabilities
        self.raw_probabilities = raw_probabilities
        self.rationale = rationale
        self.decisive = decisive
        self.calibrator = calibrator
        self.notes = notes
        self.votes = votes or []
        self.disagreement = disagreement
        self.human = human
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.tier = tier


class _BoundLimits:
    def __init__(
        self,
        *,
        max_tier: int,
        min_confidence: float,
        disagreement_js: float,
        latency_budget_ms: int,
        max_calls: int,
        max_usd: float,
        purpose: str,
    ) -> None:
        self.max_tier = max_tier
        self.min_confidence = min_confidence
        self.disagreement_js = disagreement_js
        self.latency_budget_ms = latency_budget_ms
        self.max_calls = max_calls
        self.max_usd = max_usd
        self.purpose = purpose


def build_engine(
    *,
    config_path: Path | None = None,
    data_root: Path | None = None,
    router: ModelRouter | None = None,
    audit: AuditLog | None = None,
    approver: Approver | None = None,
    dials: Mapping[str, str] | None = None,
    judge: Judge | None = None,
    config: DecideConfig | None = None,
) -> DecisionEngine:
    loaded = config if config is not None else load_decide_config(config_path)
    return DecisionEngine(
        loaded,
        router=router,
        judge=judge,
        audit=audit,
        approver=approver,
        dials=dials,
        data_root=data_root,
    )


def _limits(config: DecideConfig, request: RequestLimits) -> _BoundLimits:
    max_tier = config.max_tier if request.max_tier is None else request.max_tier
    min_confidence = (
        config.min_confidence if request.min_confidence is None else request.min_confidence
    )
    latency = (
        config.latency_budget_ms
        if request.latency_budget_ms is None
        else request.latency_budget_ms
    )
    return _BoundLimits(
        max_tier=min(4, max(0, max_tier)),
        min_confidence=min(1.0, max(0.0, min_confidence)),
        disagreement_js=config.disagreement_js,
        latency_budget_ms=max(0, latency),
        max_calls=config.max_calls,
        max_usd=config.max_usd,
        purpose=request.purpose,
    )


def _abstain(question: Question) -> _Partial:
    share = 1.0 / len(question.options) if question.options else 1.0
    probabilities = dict.fromkeys(question.options, share)
    label = question.options[0] if question.options else ""
    return _Partial(
        label=label,
        confidence=0.0,
        probabilities=probabilities,
        raw_probabilities=dict(probabilities),
        rationale="no tier was confident",
        decisive=False,
        calibrator="identity@v0",
        notes=[],
        tier=0,
    )


def _top(probabilities: dict[str, float]) -> str:
    if not probabilities:
        return ""
    return max(probabilities, key=probabilities.get)


def _renormalize(probabilities: dict[str, float]) -> dict[str, float]:
    total = sum(max(0.0, value) for value in probabilities.values())
    if total <= 0:
        return dict(probabilities)
    return {key: max(0.0, value) / total for key, value in probabilities.items()}


def _safer_label(question: Question, recommended: str) -> str:
    for option in question.options:
        if option.lower() in _SAFER and option != recommended:
            return option
    if question.type == "noul":
        return "false"
    for option in question.options:
        if option != recommended:
            return option
    return recommended or (question.options[0] if question.options else "")


def _new_id() -> str:
    return "dec_" + secrets.token_hex(4)


def role_note(role: str) -> str:
    return role or "judge"


def _truth(row: object) -> str:
    gold = str(getattr(row, "gold", "") or "")
    predicted = str(getattr(row, "predicted", "") or "")
    correct = getattr(row, "correct", None)
    probabilities = getattr(row, "probabilities", {})
    if gold:
        return gold
    if correct == 1:
        return predicted
    others = [key for key in probabilities if key != predicted]
    if len(others) == 1:
        return str(others[0])
    return ""


def fit_report(engine: DecisionEngine) -> str:
    """Reliability table. Fits and saves a calibrator when enough labels exist."""
    from praxis_prime.decide.calibration import (
        choose_method,
        fit_isotonic,
        fit_platt,
        fit_temperature,
        reliability,
    )

    rows = engine.labels.labeled()
    pairs = [(row.confidence, row.correct == 1) for row in rows]
    usable = [(row, _truth(row)) for row in rows]
    usable = [(row, truth) for row, truth in usable if truth]
    if len(usable) < 4:
        report = reliability(pairs)
        return report.format()
    binary = all(set(row.probabilities) <= {"true", "false"} for row, _truth_label in usable)
    method = choose_method(
        engine.config.calibration_method, binary=binary, count=len(usable)
    )
    version = f"{method}@v{len(usable)}"
    if method == "temperature":
        temperature = fit_temperature([(row.probabilities, truth) for row, truth in usable])
        calibrator = Calibrator(method="temperature", version=version, temperature=temperature)
    elif method == "platt":
        scores = [row.probabilities.get("true", row.confidence) for row, _truth_label in usable]
        labels = [1.0 if row.correct == 1 else 0.0 for row, _truth_label in usable]
        a, b = fit_platt(scores, labels)
        calibrator = Calibrator(method="platt", version=version, platt_a=a, platt_b=b)
    else:
        steps = fit_isotonic(
            [
                (row.probabilities.get("true", row.confidence), 1.0 if row.correct == 1 else 0.0)
                for row, _truth_label in usable
            ]
        )
        calibrator = Calibrator(method="isotonic", version=version, isotonic=steps)
    engine.calibrators.save(calibrator)
    report = reliability(pairs, method=method, version=version)
    return report.format()


# Re-export for callers that catch parse failures from decide().
__all__ = ["DecisionEngine", "build_engine", "fit_report"]
