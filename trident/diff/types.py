"""Result types for the before/after network comparison engine.

Plain, frozen dataclasses (no Pydantic) so a diff can be produced from any pair
of ``NetworkModel`` instances and rendered without further validation.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class ChangeKind(enum.StrEnum):
    """What happened to one field between two snapshots."""

    ADDED = "ADDED"
    REMOVED = "REMOVED"
    MODIFIED = "MODIFIED"
    UNCHANGED = "UNCHANGED"


class Severity(enum.StrEnum):
    """Operational weight of a single field change.

    ``INFO`` is a cosmetic/metadata change, ``WARNING`` changes reachability or
    an interface's identity, ``CRITICAL`` means a device disappeared or an
    interface was administratively taken down.
    """

    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class FieldChange:
    """One field-level difference between the before and after snapshot.

    ``evidence_before`` / ``evidence_after`` are always populated: when a value
    is absent on one side the string says so explicitly (``"absent: ..."``)
    instead of being left empty, so a renderer can never imply that a value was
    observed when it was not.
    """

    device: str
    interface: str | None
    field: str
    before: str | None
    after: str | None
    kind: ChangeKind
    severity: Severity
    evidence_before: str
    evidence_after: str


@dataclass(frozen=True)
class DiffResult:
    """Outcome of comparing two ``NetworkModel`` snapshots."""

    before_snapshot: str
    after_snapshot: str
    changes: tuple[FieldChange, ...]
    added_devices: tuple[str, ...]
    removed_devices: tuple[str, ...]
    #: Device names that could not be matched safely (one name resolving to
    #: several devices). These devices are never diffed.
    ambiguous_devices: tuple[str, ...]
    #: Number of (device|interface, field) slots that were compared and found
    #: equal, plus the number of route keys present in both snapshots.
    unchanged_count: int
