"""Value types for evidence-driven fault diagnosis.

A :class:`Diagnosis` states what was observed (:class:`Observation`), what was
concluded (:class:`Hypothesis`) and how strong each conclusion is. The honesty
rules live in the types rather than in the detectors:

* ``CONFIRMED_DEFECT`` requires at least one supporting observation and no
  contradicting observation;
* ``INSUFFICIENT_EVIDENCE`` names the missing evidence instead of guessing;
* ``to_report_dicts`` only reports hypotheses that actually claim a defect, which
  is the shape :func:`trident.faultlab.grade` consumes.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class HypothesisStatus(StrEnum):
    """How strongly the evidence supports a hypothesis."""

    CONFIRMED_DEFECT = "CONFIRMED_DEFECT"
    SUSPECTED = "SUSPECTED"
    RULED_OUT = "RULED_OUT"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class Confidence(StrEnum):
    """Evidence strength behind a hypothesis."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class Observation:
    """One piece of evidence attributed to a source.

    ``source`` names the artefact class: ``"MODEL"`` for a fact read out of a
    :class:`~trident.models.NetworkModel` snapshot, and the
    :class:`~trident.evidence.types.ObservationSource` value for pasted CLI
    evidence. ``device`` is ``None`` when the evidence cannot be attributed.
    """

    source: str
    device: str | None
    detail: str


@dataclass(frozen=True)
class Hypothesis:
    """One candidate explanation for a symptom, with its evidence."""

    kind: str
    status: HypothesisStatus
    confidence: Confidence
    device: str | None
    interface: str | None
    suspected_cause: str
    supporting: tuple[Observation, ...]
    contradicting: tuple[Observation, ...]
    missing_evidence: tuple[str, ...]
    next_command: str | None
    repair_hint: str | None


@dataclass(frozen=True)
class Diagnosis:
    """Every hypothesis the engine formed, plus the ranked, reportable view."""

    symptoms: tuple[str, ...]
    hypotheses: tuple[Hypothesis, ...]
    ranked: tuple[Hypothesis, ...]

    def to_report_dicts(self) -> list[dict]:
        """Reportable findings, with the evidence and the repair that justify them.

        This used to omit ``supporting``, ``contradicting``, ``next_command`` and
        ``repair_hint``. A report built from it could say *that* something was
        wrong but not *why*, which is useless to the person reading it and makes
        the finding unverifiable.
        """
        return [
            {
                "kind": h.kind,
                "device": h.device,
                "interface": h.interface,
                "confidence": h.confidence.value,
                "status": h.status.value,
                "suspected_cause": h.suspected_cause,
                "supporting": [
                    {"source": o.source, "device": o.device, "detail": o.detail}
                    for o in h.supporting
                ],
                "contradicting": [
                    {"source": o.source, "device": o.device, "detail": o.detail}
                    for o in h.contradicting
                ],
                "missing_evidence": list(h.missing_evidence),
                "next_command": h.next_command,
                "repair_hint": h.repair_hint,
            }
            for h in self.ranked
            if h.status in (HypothesisStatus.CONFIRMED_DEFECT, HypothesisStatus.SUSPECTED)
        ]
