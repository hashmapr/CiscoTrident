"""Practice-Lab Task Tracker.

Turns one :class:`~trident.workflow.LabAssessment` into a per-instruction board a
learner can work from. This module is a *presentation and bookkeeping* layer:

* evaluation is delegated wholesale to :func:`trident.workflow.assess_lab`;
* status is delegated to :mod:`trident.compliance` (via that same assessment);
* nothing here re-implements a compliance rule, reads a file, or calls a model.

The only decisions made here are bookkeeping ones:

* one entry per instruction line, including lines that could not be parsed;
* a ``task_id`` derived from the instruction *text + kind* so it survives a
  reassessment (and therefore a diff) even when the line moves;
* a progress denominator that excludes tasks the engines could not speak to.
"""

from __future__ import annotations

import hashlib
import re

from ..compliance import ComplianceResult
from ..models import NetworkModel
from ..requirements import Requirement
from ..workflow import assess_lab
from .types import TaskBoard, TaskEntry, TaskState, state_from_status

_WS_RE = re.compile(r"\s+")

#: ``NOT_EVALUATED`` evidence prefix. The reason is kept in ``evidence`` so an
#: unparsed instruction never disappears and never looks like a network verdict.
_NOT_EVALUATED_PREFIX = "not evaluated: "

_EVIDENCE_LIMIT = 12


def _id_text(text: str) -> str:
    """Whitespace-normalised instruction text, used only for id derivation."""
    return _WS_RE.sub(" ", (text or "").strip())


def _task_id(kind: str, text: str, occurrence: int) -> str:
    """Stable id from instruction text + kind (+ duplicate occurrence index).

    Deliberately *not* the requirement id or the line number: both shift when a
    line is inserted or reordered, which would make every reassessment diff
    look like a full rewrite.
    """
    payload = f"{kind}\x00{_id_text(text)}\x00{occurrence}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    return f"TASK-{digest}"


def _evidence(result: ComplianceResult) -> tuple[str, ...]:
    """Flatten compliance evidence into citable ``"detail [source]"`` strings."""
    seen: list[str] = []
    for item in result.evidence:
        line = f"{item.detail} [{item.source}]"
        if line not in seen:
            seen.append(line)
    return tuple(seen[:_EVIDENCE_LIMIT])


def _state_for(result: ComplianceResult | None) -> TaskState:
    """Map a compliance verdict to a task state, enforcing the evidence rule."""
    if result is None:
        return TaskState.NOT_EVALUATED
    state = state_from_status(result.status)
    if state is TaskState.SATISFIED and not result.evidence:
        # Structural guard, mirrored from the compliance engine's own invariant:
        # a SATISFIED task must be able to cite why. Without evidence it is
        # INDETERMINATE, never a claim of success.
        return TaskState.INDETERMINATE
    return state


def _entry_from(
    requirement: Requirement,
    result: ComplianceResult | None,
    skipped_reason: str,
    remediation_available: bool,
    occurrence: int,
    rechecked_from: str | None,
) -> TaskEntry:
    state = _state_for(result)
    evidence = _evidence(result) if result is not None else ()
    if state is TaskState.NOT_EVALUATED:
        reason = skipped_reason or "the instruction could not be turned into a testable requirement"
        evidence = (f"{_NOT_EVALUATED_PREFIX}{reason}",)

    if result is not None:
        device = result.device or requirement.device
    else:
        device = requirement.device

    return TaskEntry(
        task_id=_task_id(requirement.kind.value, requirement.source_text, occurrence),
        requirement_id=requirement.id,
        text=requirement.source_text,
        kind=requirement.kind.value,
        device=device,
        state=state,
        evidence=evidence,
        remediation_available=remediation_available,
        rechecked_from=rechecked_from,
    )


def _occurrences(requirements: list[Requirement]) -> list[int]:
    """Per-requirement duplicate index over (kind, normalised text)."""
    counters: dict[tuple[str, str], int] = {}
    out: list[int] = []
    for req in requirements:
        key = (req.kind.value, _id_text(req.source_text))
        index = counters.get(key, 0)
        counters[key] = index + 1
        out.append(index)
    return out


def build_board(
    model: NetworkModel,
    instructions: str,
    *,
    lab_title: str = "Practice lab",
    generate_remediation: bool = True,
) -> TaskBoard:
    """Assess ``instructions`` against ``model`` and return one entry per line.

    Every non-blank instruction line produces exactly one :class:`TaskEntry`.
    A line the parser could not resolve becomes ``NOT_EVALUATED`` carrying its
    reason -- it is never dropped.

    Read-only: ``assess_lab`` evaluates, ``generate_plan`` builds advisory
    text only; nothing executes.
    """
    assessment = assess_lab(
        model, instructions, generate_remediation=generate_remediation
    )

    requirements = [outcome.requirement for outcome in assessment.outcomes]
    occurrences = _occurrences(requirements)

    entries: list[TaskEntry] = []
    for index, outcome in enumerate(assessment.outcomes):
        requirement = outcome.requirement
        entries.append(
            _entry_from(
                requirement,
                outcome.compliance,
                outcome.skipped_reason,
                outcome.remediation is not None,
                occurrences[index],
                rechecked_from=None,
            )
        )

    return TaskBoard(
        lab_title=lab_title,
        snapshot_id=assessment.snapshot_id,
        entries=entries,
    )


def _previous_states(board: TaskBoard) -> dict[str, TaskState]:
    return {entry.task_id: entry.state for entry in board.entries}


def reassess(board: TaskBoard, model: NetworkModel, instructions: str) -> TaskBoard:
    """Re-run the assessment and diff it against ``board``.

    ``task_id`` is preserved for an instruction whose text and kind are
    unchanged (the id is derived from those two values, not from the line
    number), so a per-task diff between two boards is meaningful.

    ``rechecked_from`` is set to the *previous* state for every task that
    existed on the previous board -- including unchanged ones -- and left
    ``None`` for a task that is seen for the first time. A change is therefore
    simply ``entry.rechecked_from != entry.state.value``.

    The previous board's ``lab_title`` is kept so the board names the same lab.
    """
    previous = _previous_states(board)
    fresh = build_board(model, instructions, lab_title=board.lab_title)

    entries: list[TaskEntry] = []
    for entry in fresh.entries:
        before = previous.get(entry.task_id)
        entries.append(
            TaskEntry(
                task_id=entry.task_id,
                requirement_id=entry.requirement_id,
                text=entry.text,
                kind=entry.kind,
                device=entry.device,
                state=entry.state,
                evidence=entry.evidence,
                remediation_available=entry.remediation_available,
                rechecked_from=before.value if before is not None else None,
            )
        )

    return TaskBoard(
        lab_title=fresh.lab_title,
        snapshot_id=fresh.snapshot_id,
        entries=entries,
    )
