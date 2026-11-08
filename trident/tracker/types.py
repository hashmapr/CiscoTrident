"""Board types for the Practice-Lab Task Tracker.

A :class:`TaskBoard` is a *view* over one lab assessment: one :class:`TaskEntry`
per instruction line, each carrying the state the engines reached and the
evidence behind it. Nothing here evaluates anything -- the state is supplied by
``trident.workflow.assess_lab`` and mapped through :data:`_STATE_BY_STATUS`.

Progress arithmetic (see :meth:`TaskBoard.progress_pct`) is deliberately
computed against *evaluable* tasks only. A line the parser could not turn into a
test, or a requirement the snapshot cannot speak to, is not a failure and must
not move the percentage in either direction.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from ..compliance import ComplianceStatus


class TaskState(enum.StrEnum):
    """How one lab instruction stands after assessment.

    ``NOT_EVALUATED`` is tracker-only: it means the instruction could not be
    turned into a testable requirement (unparsed line, or no evaluator for its
    kind). It is never collapsed into ``UNSATISFIED``.
    """

    SATISFIED = "SATISFIED"
    UNSATISFIED = "UNSATISFIED"
    PARTIALLY_SATISFIED = "PARTIALLY_SATISFIED"
    INDETERMINATE = "INDETERMINATE"
    UNSUPPORTED = "UNSUPPORTED"
    NOT_EVALUATED = "NOT_EVALUATED"


#: Display / counting order used by :meth:`TaskBoard.summary`.
STATE_ORDER: tuple[TaskState, ...] = (
    TaskState.SATISFIED,
    TaskState.UNSATISFIED,
    TaskState.PARTIALLY_SATISFIED,
    TaskState.INDETERMINATE,
    TaskState.UNSUPPORTED,
    TaskState.NOT_EVALUATED,
)

#: States that carry a verdict about the network and therefore count towards
#: the progress denominator. ``UNSUPPORTED`` (the snapshot cannot speak to the
#: requirement) and ``NOT_EVALUATED`` (the line was never turned into a test)
#: are excluded so an unreadable instruction sheet can neither inflate nor
#: deflate progress.
EVALUABLE_STATES: frozenset[TaskState] = frozenset(
    {
        TaskState.SATISFIED,
        TaskState.UNSATISFIED,
        TaskState.PARTIALLY_SATISFIED,
        TaskState.INDETERMINATE,
    }
)

_STATE_BY_STATUS: dict[ComplianceStatus, TaskState] = {
    ComplianceStatus.SATISFIED: TaskState.SATISFIED,
    ComplianceStatus.UNSATISFIED: TaskState.UNSATISFIED,
    ComplianceStatus.PARTIALLY_SATISFIED: TaskState.PARTIALLY_SATISFIED,
    ComplianceStatus.INDETERMINATE: TaskState.INDETERMINATE,
    ComplianceStatus.UNSUPPORTED: TaskState.UNSUPPORTED,
}


def state_from_status(status: ComplianceStatus) -> TaskState:
    """The task state for a compliance verdict (the single mapping in the package)."""
    return _STATE_BY_STATUS[status]


@dataclass(frozen=True, slots=True)
class TaskEntry:
    """One lab instruction, its verdict, and the evidence for that verdict.

    ``evidence`` holds human-readable ``"<detail> [<source>]"`` strings copied
    from the compliance :class:`~trident.compliance.Evidence` records. For a
    ``NOT_EVALUATED`` entry there is no evidence to cite, so the tuple carries
    the single reason the line was skipped (prefixed ``"not evaluated: "``) --
    the instruction is preserved, never dropped.

    ``rechecked_from`` is the previous state when this entry came from
    :func:`trident.tracker.reassess`; it is ``None`` on a first build.
    """

    task_id: str
    requirement_id: str
    text: str
    kind: str
    device: str | None
    state: TaskState
    evidence: tuple[str, ...]
    remediation_available: bool
    rechecked_from: str | None


@dataclass
class TaskBoard:
    """The full tracker view of one lab instruction document."""

    lab_title: str
    snapshot_id: str
    entries: list[TaskEntry] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        """Count entries by state, in :data:`STATE_ORDER`.

        Every state is always present (with ``0`` when unused) so the counts
        sum to ``len(self.entries)`` and a consumer can index a key without a
        ``KeyError``.
        """
        counts = {state.value: 0 for state in STATE_ORDER}
        for entry in self.entries:
            counts[entry.state.value] += 1
        return counts

    def outstanding(self) -> list[TaskEntry]:
        """Every entry that is not confirmed ``SATISFIED``.

        ``UNSUPPORTED`` and ``NOT_EVALUATED`` are included on purpose: they are
        not done, they need a human to look at the device or the instruction.
        """
        return [entry for entry in self.entries if entry.state is not TaskState.SATISFIED]

    def evaluable(self) -> list[TaskEntry]:
        """Entries that carry a verdict about the network."""
        return [entry for entry in self.entries if entry.state in EVALUABLE_STATES]

    def progress_pct(self) -> float:
        """Percentage of *evaluable* tasks that are fully ``SATISFIED``.

        Denominator is ``len(self.evaluable())`` -- ``UNSUPPORTED`` and
        ``NOT_EVALUATED`` entries are excluded, so unparseable instructions
        cannot inflate progress (by being dropped from the numerator) or
        deflate it (by counting as failures). ``PARTIALLY_SATISFIED`` is
        evaluable but is **not** progress: only a full ``SATISFIED`` counts.

        Returns ``0.0`` when there is nothing evaluable -- there is no
        defensible percentage to report.
        """
        evaluable = self.evaluable()
        if not evaluable:
            return 0.0
        satisfied = sum(1 for entry in evaluable if entry.state is TaskState.SATISFIED)
        return 100.0 * satisfied / len(evaluable)

    def to_dict(self) -> dict:
        """A JSON-serialisable view of the whole board."""
        return {
            "lab_title": self.lab_title,
            "snapshot_id": self.snapshot_id,
            "entries": [
                {
                    "task_id": entry.task_id,
                    "requirement_id": entry.requirement_id,
                    "text": entry.text,
                    "kind": entry.kind,
                    "device": entry.device,
                    "state": entry.state.value,
                    "evidence": list(entry.evidence),
                    "remediation_available": entry.remediation_available,
                    "rechecked_from": entry.rechecked_from,
                }
                for entry in self.entries
            ],
            "summary": self.summary(),
            "progress_pct": self.progress_pct(),
        }
