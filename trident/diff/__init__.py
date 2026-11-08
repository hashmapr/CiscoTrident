"""Before/after network comparison engine for TRIDENT.

``compare(before, after)`` returns a ``DiffResult`` of field-level changes, each
with the evidence strings from both snapshots. Matching is conservative and
boundary-aware; ambiguous names are reported, never guessed.
"""

from .engine import DEVICE_FIELDS, INTERFACE_FIELDS, compare
from .types import ChangeKind, DiffResult, FieldChange, Severity

__all__ = [
    "DEVICE_FIELDS",
    "INTERFACE_FIELDS",
    "ChangeKind",
    "DiffResult",
    "FieldChange",
    "Severity",
    "compare",
]
