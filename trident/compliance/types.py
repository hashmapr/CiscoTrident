"""Result types for the configuration compliance engine.

These are plain, frozen dataclasses: they do not depend on Pydantic, on the
requirement layer, or on any parser. A compliance verdict is just a status, the
expected/actual pair, and the evidence that supports it.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class ComplianceStatus(enum.StrEnum):
    """How a requirement stands against the trusted network model.

    The five values are deliberately distinct. In particular ``UNSUPPORTED``
    (the snapshot cannot speak to this requirement) is never collapsed into
    ``UNSATISFIED`` (the snapshot says the requirement is not met).
    """

    SATISFIED = "SATISFIED"
    UNSATISFIED = "UNSATISFIED"
    PARTIALLY_SATISFIED = "PARTIALLY_SATISFIED"
    INDETERMINATE = "INDETERMINATE"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True)
class Evidence:
    """One fact that supports (or refutes) a compliance verdict.

    ``source`` names where the fact came from, e.g.
    ``"running-config line: ip address 10.0.0.1 255.255.255.0"`` or
    ``"normalized model: InterfaceInfo.ipv4_address"``.
    """

    device: str | None
    interface: str | None
    detail: str
    source: str


@dataclass(frozen=True)
class ComplianceResult:
    """The verdict for one requirement.

    ``requirement_kind`` is an opaque string on purpose: this module must not
    import ``trident.requirements``, which may be built independently.
    """

    requirement_kind: str
    device: str | None
    interface: str | None
    expected: str
    actual: str | None
    status: ComplianceStatus
    evidence: tuple[Evidence, ...]
    reason: str
