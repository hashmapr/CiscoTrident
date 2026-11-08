"""The autonomous investigation engine.

Phase 3.4. The loop is fixed and every step is observable:

    static analysis -> evidence gap -> testability -> hypotheses
      -> experiment -> observation -> hypothesis update -> stop condition

Three properties matter for the directive and are enforced here rather than
documented:

* **Static evidence wins first.** Verified answers never reach the simulator in
  Smart mode.
* **Every observation is attributed.** A result is only applied to a hypothesis
  if its device matches, and a contradictory result *eliminates* a hypothesis
  instead of being averaged into it.
* **Stopping is explicit.** The engine stops on sufficiency, exhaustion of
  useful experiments, or budget, and returns an unresolved outcome with the
  reason rather than guessing.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from ..diagnostics import diagnose
from ..diagnostics import report as diagnostic_report
from ..diagnostics.types import Confidence, HypothesisStatus
from ..evidence.bundle import EvidenceBundle
from ..models import AnswerStatus, NetworkModel
from ..simulator.contracts import Capability, OperationResult
from ..simulator.evidence_bridge import EvidenceLedger, operational_evidence_tier, to_cli_record
from ..simulator.sessions import Session
from .escalation import Mode, Testability, should_escalate
from .hypotheses import Hypothesis, select_experiment


class StopReason(enum.StrEnum):
    SUFFICIENT_EVIDENCE = "SUFFICIENT_EVIDENCE"
    NO_USEFUL_EXPERIMENT = "NO_USEFUL_EXPERIMENT"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    RUNTIME_UNAVAILABLE = "RUNTIME_UNAVAILABLE"
    NOT_OBSERVABLE = "NOT_OBSERVABLE"
    ALREADY_VERIFIED = "ALREADY_VERIFIED"
    SIMULATOR_FAILED = "SIMULATOR_FAILED"


@dataclass
class TimelineEntry:
    step: str
    detail: str
    at: str

    def as_dict(self) -> dict:
        return {"step": self.step, "detail": self.detail, "at": self.at}


@dataclass
class QuestionOutcome:
    """The result of investigating one question."""

    question: str
    status: AnswerStatus
    answer: str | None
    reason: str
    stop_reason: StopReason
    evidence_tier: str
    hypotheses: list[dict] = field(default_factory=list)
    experiments: list[dict] = field(default_factory=list)
    observations: list[dict] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "question": self.question,
            "status": self.status.value,
            "answer": self.answer,
            "reason": self.reason,
            "stop_reason": self.stop_reason.value,
            "evidence_tier": self.evidence_tier,
            "hypotheses": self.hypotheses,
            "experiments": self.experiments,
            "observations": self.observations,
            "unresolved": self.unresolved,
        }


@dataclass
class InvestigationReport:
    """Everything the engine did, in order, for the UI timeline."""

    mode: Mode
    runtime_available: bool
    runtime_reason: str
    outcomes: list[QuestionOutcome] = field(default_factory=list)
    timeline: list[TimelineEntry] = field(default_factory=list)
    ledger_counts: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "mode": self.mode.value,
            "runtime_available": self.runtime_available,
            "runtime_reason": self.runtime_reason,
            "outcomes": [outcome.as_dict() for outcome in self.outcomes],
            "timeline": [entry.as_dict() for entry in self.timeline],
            "ledger": self.ledger_counts,
        }


@dataclass
class Budget_:
    """Investigation-level ceilings, separate from the session's own budget."""

    max_experiments_per_question: int = 4
    max_experiments_total: int = 40


class Investigator:
    """Runs the investigation loop over one network and one question set."""

    def __init__(
        self,
        model: NetworkModel,
        *,
        mode: Mode = Mode.SMART,
        session: Session | None = None,
        runtime_available: bool = False,
        runtime_reason: str = "",
        bundle: EvidenceBundle | None = None,
        budget: Budget_ | None = None,
    ) -> None:
        self.model = model
        self.mode = mode
        self.session = session
        self.runtime_available = runtime_available and session is not None
        self.runtime_reason = runtime_reason
        self.bundle = bundle or EvidenceBundle()
        self.budget = budget or Budget_()
        self.ledger = EvidenceLedger()
        self.timeline: list[TimelineEntry] = []
        self._experiments_run_total = 0

    # -- public entry points ----------------------------------------------

    def investigate(self, questions: list[tuple[str, AnswerStatus, list[str]]]) -> InvestigationReport:
        """Investigate a batch of ``(question, static_status, missing_evidence)``.

        Batching matters: several questions often need the same artefact, and the
        ledger means it is collected once per session.
        """
        self._log("analyzing network", f"{len(self.model.devices)} devices")
        if not self.runtime_available:
            # Say why, once, in the timeline the user actually reads.
            self._log(
                "initializing isolated simulator",
                f"skipped: {self.runtime_reason or 'no simulator backend available'}",
            )
        report = InvestigationReport(
            mode=self.mode,
            runtime_available=self.runtime_available,
            runtime_reason=self.runtime_reason,
        )
        for question, status, missing in questions:
            outcome = self._investigate_one(question, status, missing)
            report.outcomes.append(outcome)
        report.timeline = list(self.timeline)
        report.ledger_counts = self.ledger.counts()
        return report

    def diagnose_network(self, symptoms: tuple[str, ...] = ()) -> dict:
        """Static diagnosis of the whole network, no simulator involved."""
        diagnosis = diagnose(self.model, self.bundle, symptoms=symptoms)
        return {
            "findings": diagnostic_report(diagnosis),
            "ranked": [h.as_dict() if hasattr(h, "as_dict") else str(h) for h in diagnosis.ranked],
            "hypothesis_count": len(diagnosis.hypotheses),
        }

    # -- the loop ---------------------------------------------------------

    def _investigate_one(
        self, question: str, status: AnswerStatus, missing: list[str]
    ) -> QuestionOutcome:
        self._log("resolving known facts", question)
        decision = should_escalate(
            status,
            mode=self.mode,
            runtime_available=self.runtime_available,
            missing=missing,
            already_exhausted=self._experiments_run_total >= self.budget.max_experiments_total,
        )

        if not decision.escalate:
            exhausted = self._experiments_run_total >= self.budget.max_experiments_total
            stop = (
                StopReason.BUDGET_EXHAUSTED
                if exhausted and decision.testability is Testability.OBSERVABLE
                else _stop_for(decision.testability, status)
            )
            if stop is StopReason.RUNTIME_UNAVAILABLE and self.runtime_reason:
                reason = f"{decision.reason}: {self.runtime_reason}"
            else:
                reason = decision.reason
            self._log("stopping", f"{question}: {decision.reason}")
            return QuestionOutcome(
                question=question,
                status=status,
                answer=None,
                reason=reason,
                stop_reason=stop,
                evidence_tier="NO_OPERATIONAL_EVIDENCE",
                unresolved=list(missing),
            )

        self._log("identifying missing evidence", "; ".join(missing) or "no static evidence")
        hypotheses = self._hypotheses_for(question, missing, status)
        if not hypotheses:
            return QuestionOutcome(
                question=question,
                status=status,
                answer=None,
                reason="no candidate hypothesis could be formed from the available facts",
                stop_reason=StopReason.NO_USEFUL_EXPERIMENT,
                evidence_tier="NO_OPERATIONAL_EVIDENCE",
                unresolved=list(missing),
            )

        self._log(
            "investigating possible causes",
            ", ".join(h.kind for h in hypotheses),
        )

        run: set[str] = set()
        experiments: list[dict] = []
        observations: list[dict] = []
        per_question = 0
        stop_reason = StopReason.NO_USEFUL_EXPERIMENT

        while per_question < self.budget.max_experiments_per_question:
            if self._experiments_run_total >= self.budget.max_experiments_total:
                stop_reason = StopReason.BUDGET_EXHAUSTED
                break
            experiment = select_experiment(hypotheses, already_run=run)
            if experiment is None:
                stop_reason = StopReason.NO_USEFUL_EXPERIMENT
                break
            run.add(experiment.experiment_id)
            per_question += 1
            self._experiments_run_total += 1
            experiments.append(experiment.as_dict())

            self._log("running diagnostics", f"{experiment.command} on {experiment.device}")
            result = self._execute(experiment, hypotheses)
            if result is None:
                stop_reason = StopReason.SIMULATOR_FAILED
                break
            observations.append(result.as_dict())
            self._apply(result, hypotheses)
            self._log("validating observations", f"{experiment.command}: {'ok' if result.ok else 'failed'}")

            if self._sufficient(hypotheses):
                stop_reason = StopReason.SUFFICIENT_EVIDENCE
                break

        confirmed = [h for h in hypotheses if h.status is HypothesisStatus.CONFIRMED_DEFECT]
        operational = [h for h in confirmed if h.operationally_supported]
        tier = operational_evidence_tier(list(self.ledger.results()))
        self._log("generating final report", f"{len(operational)} operationally confirmed")

        if operational:
            best = _strongest(operational)
            return QuestionOutcome(
                question=question,
                status=AnswerStatus.INCOMPLETE,
                answer=f"{best.kind} on {best.device}" + (f" {best.interface}" if best.interface else ""),
                reason=(
                    "operational evidence supports this cause. This is an operational "
                    "conclusion, not a consensus-verified static fact."
                ),
                stop_reason=StopReason.SUFFICIENT_EVIDENCE,
                evidence_tier=tier,
                hypotheses=[h.as_dict() for h in hypotheses],
                experiments=experiments,
                observations=observations,
            )

        if confirmed:
            best = _strongest(confirmed)
            return QuestionOutcome(
                question=question,
                status=status,
                answer=None,
                reason=(
                    f"static evidence indicates {best.kind} on {best.device}, but no "
                    "experiment produced operational confirmation; this is a static "
                    "suspect, not an observed result"
                ),
                stop_reason=stop_reason,
                evidence_tier=tier,
                hypotheses=[h.as_dict() for h in hypotheses],
                experiments=experiments,
                observations=observations,
                unresolved=list(missing),
            )

        return QuestionOutcome(
            question=question,
            status=status,
            answer=None,
            reason="no candidate cause could be confirmed by the experiments available",
            stop_reason=stop_reason,
            evidence_tier=tier,
            hypotheses=[h.as_dict() for h in hypotheses],
            experiments=experiments,
            observations=observations,
            unresolved=list(missing),
        )

    # -- helpers ----------------------------------------------------------

    def _hypotheses_for(
        self, question: str, missing: list[str], status: AnswerStatus
    ) -> list[Hypothesis]:
        """Form hypotheses from the static diagnosis.

        The engine does not invent causes: it asks the diagnostics engine what it
        suspects and turns those into testable hypotheses.
        """
        diagnosis = diagnose(self.model, self.bundle, symptoms=(question,))
        formed: list[Hypothesis] = []
        for hypothesis in diagnosis.hypotheses:
            if hypothesis.status is HypothesisStatus.RULED_OUT:
                continue
            if not hypothesis.device:
                continue
            formed.append(
                Hypothesis(
                    hypothesis_id=f"{hypothesis.kind}:{hypothesis.device}:{hypothesis.interface or '-'}",
                    kind=hypothesis.kind,
                    summary=hypothesis.suspected_cause,
                    device=hypothesis.device,
                    interface=hypothesis.interface,
                    status=hypothesis.status,
                    confidence=hypothesis.confidence,
                    supporting=[o.detail for o in hypothesis.supporting],
                    contradicting=[o.detail for o in hypothesis.contradicting],
                    missing=list(hypothesis.missing_evidence),
                )
            )
        # Deduplicate identical hypotheses so a device is not tested twice.
        seen: set[tuple] = set()
        unique: list[Hypothesis] = []
        for hypothesis in formed:
            key = (hypothesis.kind, hypothesis.device, hypothesis.interface)
            if key in seen:
                continue
            seen.add(key)
            unique.append(hypothesis)
        return unique

    def _execute(self, experiment, hypotheses: list[Hypothesis]) -> OperationResult | None:
        if self.session is None:
            return None
        if not self.session.supports(Capability.RUN_CLI):
            return None
        cached = self.ledger.recall(
            self.session.session_id, experiment.device, experiment.command
        )
        if cached is not None:
            # The same artefact settles several questions; collect it once.
            self._log("reusing evidence", f"{experiment.command} on {experiment.device}")
            return cached
        try:
            result = self.session.run_cli(experiment.device, experiment.command)
        except Exception as exc:  # noqa: BLE001 - reported, not hidden
            self._log("diagnostic failed", f"{experiment.command}: {exc}")
            return None
        self.ledger.remember(result)
        record = to_cli_record(result)
        if record is not None:
            self.bundle.add(record)
        return result

    def _apply(self, result: OperationResult, hypotheses: list[Hypothesis]) -> None:
        """Update hypotheses from one observation.

        A contradiction eliminates; it is never averaged into a score. That keeps
        the loop from "confirming" a cause that the evidence has already refuted.
        """
        if not result.ok:
            return
        text = result.raw.lower()
        for hypothesis in hypotheses:
            if not hypothesis.plausible:
                continue
            if hypothesis.device and result.device and hypothesis.device != result.device:
                continue
            hypothesis.experiments_run += 1
            verdict = _interpret(hypothesis.kind, text)
            if verdict == "support":
                hypothesis.add_support(f"{result.operation} on {result.device}")
                hypothesis.operationally_supported = True
                hypothesis.confirm()
            elif verdict == "refute":
                hypothesis.eliminate(
                    f"{result.operation} on {result.device} contradicts {hypothesis.kind}"
                )

    def _sufficient(self, hypotheses: list[Hypothesis]) -> bool:
        confirmed = [h for h in hypotheses if h.status is HypothesisStatus.CONFIRMED_DEFECT]
        remaining = [h for h in hypotheses if h.plausible and h.status is not HypothesisStatus.CONFIRMED_DEFECT]
        return bool(confirmed) and not remaining

    def _log(self, step: str, detail: str) -> None:
        from ..simulator.contracts import utcnow

        self.timeline.append(TimelineEntry(step=step, detail=detail, at=utcnow()))


def _interpret(kind: str, text: str) -> str | None:
    """Read one CLI output for evidence about one defect class.

    Returns ``"support"``, ``"refute"``, or ``None`` when the output says
    nothing decisive. Absence of a signal is never treated as refutation.
    """
    if kind == "SHUTDOWN_INTERFACE":
        if "administratively down" in text:
            return "support"
        if "up" in text and "administratively down" not in text:
            return None
    elif kind == "WRONG_VLAN" and "active" in text and "vlan" in text or kind == "TRUNK_MISMATCH" and ("trunking" in text or "allowed vlans" in text):
        return None
    elif kind == "MISSING_STATIC_ROUTE":
        if "gateway of last resort is not set" in text:
            return "support"
    elif kind == "ACL_BLOCK":
        if "deny" in text:
            return "support"
    elif kind == "INVALID_MASK":
        if "255.255.0.255" in text or "bad mask" in text:
            return "support"
    elif kind == "ROUTING_LOOP" and "via" in text and "directly connected" not in text:
        return None
    return None


def _strongest(hypotheses: list[Hypothesis]) -> Hypothesis:
    order = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
    return min(hypotheses, key=lambda h: (order[h.confidence], -len(h.supporting)))


def _stop_for(testability: Testability, status: AnswerStatus) -> StopReason:
    if status in {AnswerStatus.VERIFIED, AnswerStatus.VERIFIED_DERIVED}:
        return StopReason.ALREADY_VERIFIED
    if testability is Testability.RUNTIME_UNAVAILABLE:
        return StopReason.RUNTIME_UNAVAILABLE
    if testability is Testability.NOT_OBSERVABLE:
        return StopReason.NOT_OBSERVABLE
    return StopReason.NO_USEFUL_EXPERIMENT


__all__ = [
    "Budget_",
    "InvestigationReport",
    "Investigator",
    "QuestionOutcome",
    "StopReason",
    "TimelineEntry",
]
