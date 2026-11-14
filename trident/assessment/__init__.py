"""Autonomous assessment subpackage.

The forensics layer is the read-only reconstruction phase: it turns one uploaded
Packet Tracer file into a normalised :class:`~trident.assessment.forensics.NetworkEvidence`
snapshot with per-record engine provenance, explicit engine states, and every
engine disagreement surfaced instead of averaged away.

Only the forensics API is re-exported here. The rest of the workflow lives in
sibling modules that import this package, so importing them from ``__init__``
would create cycles.
"""

from __future__ import annotations

from .forensics import (
    AclRecord,
    DeviceRecord,
    Discrepancy,
    InterfaceRecord,
    LinkRecord,
    NetworkEvidence,
    RouteRecord,
    UnsupportedItem,
    VlanRecord,
    build_evidence,
    load_requirements,
    reconstruct,
    write_evidence,
)

__all__ = [
    "AclRecord",
    "DeviceRecord",
    "Discrepancy",
    "InterfaceRecord",
    "LinkRecord",
    "NetworkEvidence",
    "RouteRecord",
    "UnsupportedItem",
    "VlanRecord",
    "build_evidence",
    "load_requirements",
    "reconstruct",
    "write_evidence",
]
