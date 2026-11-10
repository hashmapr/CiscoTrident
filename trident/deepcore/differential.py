"""Differential verification: does the simulator agree with the prediction?

This closes the loop that matters. DeepCore says where traffic should go; Ghost
says where it did go. When they disagree, one of them is wrong, and the
disagreement itself is the most valuable thing the system can produce.

The rules that keep this honest:

* **A prediction is not an observation.** DeepCore output carries
  ``SIMULATED_PREDICTION``; a PDU result carries ``SIMULATOR_OBSERVATION``. The
  comparison records both, and neither is rewritten.
* **Packet Tracer is not assumed correct.** A disagreement is classified, and
  "the simulator may not model this" is a real category. The tool decides nothing;
  a human does.
* **An inconclusive experiment produces no verdict.** ``INCONCLUSIVE`` from a PDU
  is recorded as ``INSUFFICIENT_EVIDENCE``, never as agreement or disagreement.
* **Agreement is corroboration, not proof.** Both agreeing raises confidence; it
  does not make either one authoritative.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from ..deepcore import DeepCore, PathPrediction
from ..models import NetworkModel


class Agreement(enum.StrEnum):
    """What comparing a prediction with an observation concluded."""

    AGREES = "AGREES"
    DISAGREES = "DISAGREES"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    #: The prediction itself was not definite, so there is nothing to compare.
    UNTESTABLE = "UNTESTABLE"


class Cause(enum.StrEnum):
    """Why a disagreement happened. Never assigned automatically."""

    PARSER_ERROR = "PARSER_ERROR"
    DEVICE_IDENTITY_ERROR = "DEVICE_IDENTITY_ERROR"
    IOS_SEMANTICS_ERROR = "IOS_SEMANTICS_ERROR"
    FORWARDING_LOGIC_ERROR = "FORWARDING_LOGIC_ERROR"
    PROTOCOL_STATE_ASSUMPTION = "PROTOCOL_STATE_ASSUMPTION"
    SIMULATOR_UNSUPPORTED = "SIMULATOR_UNSUPPORTED"
    TIMING_OR_CONVERGENCE = "TIMING_OR_CONVERGENCE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    UNKNOWN = "UNKNOWN"


@dataclass
class Discrepancy:
    """A reproducible disagreement between prediction and observation."""

    source: str
    destination: str
    predicted: bool | None
    observed: str
    agreement: Agreement
    prediction_steps: list[dict] = field(default_factory=list)
    observed_detail: str = ""
    cause: Cause = Cause.UNKNOWN
    #: The command or experiment that produced the observation.
    operation: str = ""
    simulator_version: str = ""
    source_sha256: str = ""
    session_id: str = ""
    reproduction: str = ""
    caveats: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "destination": self.destination,
            "predicted": self.predicted,
            "observed": self.observed,
            "agreement": self.agreement.value,
            "prediction_steps": self.prediction_steps,
            "observed_detail": self.observed_detail,
            "cause": self.cause.value,
            "operation": self.operation,
            "simulator_version": self.simulator_version,
            "source_sha256": self.source_sha256,
            "session_id": self.session_id,
            "reproduction": self.reproduction,
            "caveats": list(self.caveats),
        }

    @property
    def is_trusted(self) -> bool:
        """Only a definite prediction against a definite observation counts."""
        return self.agreement in {Agreement.AGREES, Agreement.DISAGREES}


#: What a PDU outcome means for "did traffic arrive".
_DELIVERED_OUTCOMES = {"DELIVERED"}
_FAILED_OUTCOMES = {"DROPPED", "TIMED_OUT"}


def compare(
    prediction: PathPrediction,
    pdu_status: str,
    *,
    operation: str = "",
    simulator_version: str = "",
    source_sha256: str = "",
    session_id: str = "",
    observed_detail: str = "",
) -> Discrepancy:
    """Compare a prediction with one PDU outcome.

    ``pdu_status`` is a :class:`~trident.simulator.pdu.DeliveryStatus` value.
    Anything unrecognised, or ``INCONCLUSIVE``/``UNSUPPORTED``, yields
    ``INSUFFICIENT_EVIDENCE``: the experiment did not establish delivery either
    way, so it cannot confirm or refute the prediction.
    """
    observed = pdu_status.upper()

    if not prediction.definite or prediction.delivered is None:
        return Discrepancy(
            source=prediction.source,
            destination=prediction.destination,
            predicted=prediction.delivered,
            observed=observed,
            agreement=Agreement.UNTESTABLE,
            prediction_steps=[step.as_dict() for step in prediction.steps],
            observed_detail=observed_detail,
            operation=operation,
            simulator_version=simulator_version,
            source_sha256=source_sha256,
            session_id=session_id,
            caveats=[
                (
                    "the prediction was not definite, so the experiment cannot "
                    "confirm or refute it"
                ),
                *prediction.limitations,
            ],
        )

    if observed in _DELIVERED_OUTCOMES:
        observed_delivered: bool | None = True
    elif observed in _FAILED_OUTCOMES:
        observed_delivered = False
    else:
        observed_delivered = None

    if observed_delivered is None:
        return Discrepancy(
            source=prediction.source,
            destination=prediction.destination,
            predicted=prediction.delivered,
            observed=observed,
            agreement=Agreement.INSUFFICIENT_EVIDENCE,
            prediction_steps=[step.as_dict() for step in prediction.steps],
            observed_detail=observed_detail,
            operation=operation,
            simulator_version=simulator_version,
            source_sha256=source_sha256,
            session_id=session_id,
            caveats=[
                (
                    f"the simulator reported {observed}, which establishes neither "
                    "delivery nor failure"
                ),
            ],
        )

    agreement = (
        Agreement.AGREES
        if observed_delivered == prediction.delivered
        else Agreement.DISAGREES
    )

    cause = Cause.UNKNOWN
    caveats: list[str] = []
    if agreement is Agreement.DISAGREES:
        # Classify only what the evidence actually shows. The default stays
        # UNKNOWN: guessing a cause from a single disagreement is how a bad rule
        # gets written.
        if observed_delivered and not prediction.delivered:
            cause = Cause.FORWARDING_LOGIC_ERROR
            caveats.append(
                "predicted a drop but traffic arrived: the model is missing a path "
                "that exists (an unparsed route, a dynamic protocol, or a NAT rule)"
            )
        else:
            cause = Cause.FORWARDING_LOGIC_ERROR
            caveats.append(
                "predicted delivery but traffic did not arrive: the model may trust "
                "a fact the running device does not have, or the simulator may not "
                "model this feature"
            )

    return Discrepancy(
        source=prediction.source,
        destination=prediction.destination,
        predicted=prediction.delivered,
        observed=observed,
        agreement=agreement,
        prediction_steps=[step.as_dict() for step in prediction.steps],
        observed_detail=observed_detail,
        cause=cause,
        operation=operation,
        simulator_version=simulator_version,
        source_sha256=source_sha256,
        session_id=session_id,
        reproduction=(
            f"predict_path({prediction.source!r}, {prediction.destination!r}) "
            f"then send_pdu({prediction.source!r}, {prediction.destination!r})"
        ),
        caveats=caveats,
    )


def differential_report(discrepancies: list[Discrepancy]) -> dict:
    """Summarise a batch of comparisons."""
    counts: dict[str, int] = {agreement.value: 0 for agreement in Agreement}
    for discrepancy in discrepancies:
        counts[discrepancy.agreement.value] += 1
    return {
        "total": len(discrepancies),
        "counts": counts,
        "trusted": sum(1 for d in discrepancies if d.is_trusted),
        "disagreements": [
            d.as_dict() for d in discrepancies if d.agreement is Agreement.DISAGREES
        ],
    }


def predict_and_compare(
    model: NetworkModel, source: str, destination: str, pdu_status: str, **kwargs
) -> Discrepancy:
    """Convenience: run DeepCore, then compare with one observation."""
    prediction = DeepCore(model).predict_path(source, destination)
    return compare(prediction, pdu_status, **kwargs)


__all__ = [
    "Agreement",
    "Cause",
    "Discrepancy",
    "compare",
    "differential_report",
    "predict_and_compare",
]
