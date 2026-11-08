"""Practice-Lab Task Tracker for TRIDENT.

Turns a lab assessment into a per-instruction board: one entry per instruction
line, each with its state, the evidence behind that state, and whether a
remediation plan exists.

Public surface::

    from trident.tracker import (
        TaskBoard, TaskEntry, TaskState, build_board, reassess,
    )

Evaluation is never re-implemented here: :func:`build_board` calls
:func:`trident.workflow.assess_lab`, which in turn calls
:mod:`trident.compliance`. This package only decides bookkeeping -- stable task
ids, one entry per line, and a progress denominator built from *evaluable*
tasks so that unparseable instructions can neither inflate nor deflate progress.

Read-only: nothing here writes a file, opens a socket, or runs a command.
"""

from __future__ import annotations

from .engine import build_board, reassess
from .types import (
    EVALUABLE_STATES,
    STATE_ORDER,
    TaskBoard,
    TaskEntry,
    TaskState,
    state_from_status,
)

__all__ = [
    "EVALUABLE_STATES",
    "STATE_ORDER",
    "TaskBoard",
    "TaskEntry",
    "TaskState",
    "build_board",
    "reassess",
    "state_from_status",
]
