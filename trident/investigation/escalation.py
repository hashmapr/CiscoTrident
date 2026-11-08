"""Escalation policy: when is running the simulator actually justified?

The policy is deterministic and explainable. Every decision returns a reason, so
a user can see why the simulator was or was not launched, and the UI never has to
invent a justification.

The rules that stop the system wasting the user's battery:

* a resolved answer is never re-tested in Smart mode;
* a question whose missing fact cannot be observed is never escalated —
  "which requirement is documented in the lab PDF" is not answered by packets;
* a `CONFLICT` *is* escalated, because a contradiction between the file and the
  running state is exactly what an experiment settles;
* if the runtime is unavailable the answer stays unresolved, with the real
  reason attached.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from ..models import AnswerStatus


class Mode(enum.StrEnum):
    """The two user-selectable operating modes."""

    SMART = "SMART"
    DOUBLE_CHECK = "DOUBLE_CHECK"


class Testability(enum.StrEnum):
    """Whether an observation can settle the missing fact."""

    #: A read-only diagnostic or reachability test can settle it.
    OBSERVABLE = "OBSERVABLE"
    #: It depends on information the network does not contain — a written
    #: requirement, an external document, or a human decision.
    NOT_OBSERVABLE = "NOT_OBSERVABLE"
    #: It would need a configuration change to test, so it is a what-if.
    MUTATION_REQUIRED = "MUTATION_REQUIRED"
    #: The runtime cannot be used at all.
    RUNTIME_UNAVAILABLE = "RUNTIME_UNAVAILABLE"


@dataclass(frozen=True)
class EscalationDecision:
    escalate: bool
    reason: str
    testability: Testability

    def as_dict(self) -> dict:
        return {
            "escalate": self.escalate,
            "reason": self.reason,
            "testability": self.testability.value,
        }


#: Phrases that indicate the gap is about documentation or intent, not behaviour.
_NON_OBSERVABLE_MARKERS = (
    "requirement",
    "instruction",
    "as stated in",
    "according to the lab",
    "document",
    "pdf",
    "policy",
    "intended by",
    "design intent",
    "should the student",
    "grading",
    "rubric",
)

#: Phrases that indicate the gap is about live behaviour.
_OBSERVABLE_MARKERS = (
    "reach",
    "connectivity",
    "ping",
    "route",
    "routing",
    "neighbor",
    "trunk",
    "vlan",
    "interface state",
    "up or down",
    "acl",
    "blocked",
    "permit",
    "deny",
    "gateway",
    "dhcp",
    "dns",
    "latency",
)


def classify_testability(missing: list[str] | tuple[str, ...]) -> Testability:
    """Decide whether the missing evidence is something packets can establish.

    Deliberately conservative: unless the gap clearly names observable network
    behaviour, it is treated as not observable. Firing the simulator on a
    documentation question wastes minutes and teaches the user to distrust the
    mode selector.
    """
    text = " ".join(missing).lower()
    if not text.strip():
        return Testability.NOT_OBSERVABLE
    if any(marker in text for marker in _NON_OBSERVABLE_MARKERS):
        return Testability.NOT_OBSERVABLE
    if any(marker in text for marker in _OBSERVABLE_MARKERS):
        return Testability.OBSERVABLE
    return Testability.NOT_OBSERVABLE


def should_escalate(
    status: AnswerStatus,
    *,
    mode: Mode = Mode.SMART,
    runtime_available: bool,
    missing: list[str] | tuple[str, ...] = (),
    testability: Testability | None = None,
    already_exhausted: bool = False,
) -> EscalationDecision:
    """Decide whether to run an experiment for one question."""
    resolved = status in {AnswerStatus.VERIFIED, AnswerStatus.VERIFIED_DERIVED}

    if mode is Mode.SMART and resolved:
        return EscalationDecision(
            False,
            "already verified from static evidence; re-testing is not justified",
            Testability.OBSERVABLE,
        )

    if not runtime_available:
        return EscalationDecision(
            False,
            "simulator runtime is unavailable, so the gap cannot be closed operationally",
            Testability.RUNTIME_UNAVAILABLE,
        )

    effective = testability or classify_testability(missing)

    if effective is Testability.NOT_OBSERVABLE:
        return EscalationDecision(
            False,
            (
                "the missing evidence is documentation or intent, which no network "
                "experiment can establish"
            ),
            effective,
        )

    if effective is Testability.MUTATION_REQUIRED:
        return EscalationDecision(
            False,
            (
                "settling this needs a configuration change; that belongs to a "
                "what-if experiment, which requires an explicit request"
            ),
            effective,
        )

    if already_exhausted:
        return EscalationDecision(
            False,
            "the experiment budget for this question is spent",
            effective,
        )

    if status is AnswerStatus.CONFLICT:
        return EscalationDecision(
            True,
            "static evidence contradicts itself; a targeted observation can separate the two",
            effective,
        )

    if mode is Mode.DOUBLE_CHECK:
        return EscalationDecision(
            True,
            "double-check mode re-tests even verified answers",
            effective,
        )

    return EscalationDecision(
        True,
        f"unresolved ({status.value}) with observable missing evidence",
        effective,
    )


def expected_information_gain(
    status: AnswerStatus,
    *,
    testability: Testability,
    already_collected: bool,
) -> float:
    """A coarse, non-probabilistic ranking signal.

    This is a scheduling weight, not a calibrated probability, and it is never
    reported to a user as one. Its only job is to order candidate experiments.
    """
    if already_collected:
        return 0.0
    if testability is Testability.OBSERVABLE:
        return 1.0 if status in {AnswerStatus.CONFLICT, AnswerStatus.INCOMPLETE} else 0.5
    return 0.0


__all__ = [
    "EscalationDecision",
    "Mode",
    "Testability",
    "classify_testability",
    "expected_information_gain",
    "should_escalate",
]
