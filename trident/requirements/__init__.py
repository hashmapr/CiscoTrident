"""Deterministic requirement extraction for TRIDENT.

Public surface::

    from trident.requirements import (
        Requirement, RequirementKind, RequirementStatus, parse_requirements,
    )

The engine is rule-based and pure: free-text lab instructions in, structured
testable requirements out, with no model calls and no I/O.
"""

from __future__ import annotations

from .engine import parse_requirements
from .model import Requirement, RequirementKind, RequirementStatus

__all__ = [
    "Requirement",
    "RequirementKind",
    "RequirementStatus",
    "parse_requirements",
]
