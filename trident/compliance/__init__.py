"""Configuration compliance engine for TRIDENT.

Evaluates a requirement (identified by an opaque ``kind`` string) against the
trusted ``NetworkModel`` and returns a status, the expected/actual pair, and the
evidence behind the verdict.

Deliberately independent of ``trident.requirements``: requirements are supplied
as data, so this package has no cross-module import dependency.
"""

from .engine import SUPPORTED_KINDS, evaluate
from .types import ComplianceResult, ComplianceStatus, Evidence

__all__ = [
    "SUPPORTED_KINDS",
    "ComplianceResult",
    "ComplianceStatus",
    "Evidence",
    "evaluate",
]
