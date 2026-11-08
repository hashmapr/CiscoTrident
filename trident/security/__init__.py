"""Configuration security auditor for TRIDENT.

Reads the recorded running-configuration of each device in a ``NetworkModel``
and reports evidence-based findings against a named baseline.

The auditor is a pure function of the model: no device connection, no command
execution, no mutation. ``remediation_hint`` is advisory text only, and
:class:`~trident.security.types.Finding` carries no field that could be mistaken
for an executed action.
"""

from .auditor import BASELINES, CHECK_IDS, REDACTED, audit
from .types import (
    SEVERITY_ORDER,
    AuditReport,
    Finding,
    FindingStatus,
    Severity,
    is_absence_note,
)

__all__ = [
    "BASELINES",
    "CHECK_IDS",
    "REDACTED",
    "SEVERITY_ORDER",
    "AuditReport",
    "Finding",
    "FindingStatus",
    "Severity",
    "audit",
    "is_absence_note",
]
