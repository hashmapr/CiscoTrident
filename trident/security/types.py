"""Result types for the configuration security auditor.

These are plain frozen dataclasses on purpose: a security finding is an
*observation* about recorded running-config text plus advisory guidance. Nothing
here models a device connection, a command to execute, or a remediation plan
that has been applied.

The honesty rules of the auditor are encoded structurally, so a caller cannot
accidentally manufacture an unsupported claim:

* every finding must carry at least one evidence string
* a ``COMPLIANT`` finding must cite at least one real configuration line; a
  bare "not present" note is not positive evidence
* a ``CONFIRMED_VIOLATION`` must cite the offending configuration line(s)
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

#: Prefix used for evidence entries that record an absence rather than a line.
NOT_PRESENT_PREFIX = "not present:"


class FindingStatus(enum.StrEnum):
    """How one check stands against the recorded configuration.

    ``CONFIRMED_VIOLATION`` and ``HARDENING_SUGGESTION`` are deliberately
    distinct: the first names an explicitly observed bad directive, the second
    names a good practice that the configuration does not show. Absence alone is
    never a confirmed violation, except for checks whose whole definition is
    "missing X" (``ssh-missing``, ``no-enable-secret``).
    """

    CONFIRMED_VIOLATION = "CONFIRMED_VIOLATION"
    HARDENING_SUGGESTION = "HARDENING_SUGGESTION"
    COMPLIANT = "COMPLIANT"
    INDETERMINATE = "INDETERMINATE"
    UNSUPPORTED = "UNSUPPORTED"


class Severity(enum.StrEnum):
    """Operator-facing weight of one finding.

    The severity is a property of the check's baseline entry, not of how
    confident the auditor is. ``INDETERMINATE`` findings keep the check's
    severity so that unreviewed risk is not silently downgraded to ``LOW``.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


#: Report ordering for :meth:`AuditReport.by_severity`.
SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
)


def is_absence_note(evidence: str) -> bool:
    """True when an evidence entry records a missing directive, not a line."""
    return evidence.strip().lower().startswith(NOT_PRESENT_PREFIX)


@dataclass(frozen=True)
class Finding:
    """One configuration observation for one device (and optionally interface).

    ``remediation_hint`` is advisory text only. It is never executed, never
    queued, and never treated as a validated change.
    """

    check_id: str
    device: str | None
    interface: str | None
    status: FindingStatus
    severity: Severity
    summary: str
    evidence: tuple[str, ...]
    baseline: str
    remediation_hint: str

    def __post_init__(self) -> None:
        if not self.check_id:
            raise ValueError("a finding must name the check it comes from")
        if not self.baseline:
            raise ValueError("a finding must name the baseline it was evaluated against")
        if not self.summary:
            raise ValueError("a finding must carry a human-readable summary")
        if not self.evidence:
            raise ValueError(
                f"finding {self.check_id!r} has no evidence; every observation must cite "
                "a configuration line or an explicit 'not present' note"
            )
        if self.status is FindingStatus.COMPLIANT and not any(
            not is_absence_note(item) for item in self.evidence
        ):
            raise ValueError(
                f"finding {self.check_id!r} claims COMPLIANT without a real configuration "
                "line; absence of evidence is not positive evidence"
            )


@dataclass(frozen=True)
class AuditReport:
    """The complete, deterministic result of auditing one snapshot."""

    findings: tuple[Finding, ...]
    checked_devices: int
    baseline: str

    def __post_init__(self) -> None:
        if not self.baseline:
            raise ValueError("an audit report must name its baseline")
        if self.checked_devices < 0:
            raise ValueError("checked_devices cannot be negative")
        for finding in self.findings:
            if finding.baseline != self.baseline:
                raise ValueError(
                    f"finding {finding.check_id!r} cites baseline {finding.baseline!r} "
                    f"inside a {self.baseline!r} report"
                )

    def by_severity(self) -> dict[str, int]:
        """Count findings per severity, always including all four keys."""
        counts = {severity.value: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def violations(self) -> tuple[Finding, ...]:
        """Only the findings backed by an explicitly observed bad directive."""
        return tuple(
            finding
            for finding in self.findings
            if finding.status is FindingStatus.CONFIRMED_VIOLATION
        )
