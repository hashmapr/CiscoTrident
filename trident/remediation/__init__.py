"""IOS remediation generator for TRIDENT.

Turns a ``trident.compliance.ComplianceResult`` into an ordered, advisory set of
Cisco IOS configuration commands. Nothing here executes anything: every plan is
``advisory_only=True`` and the destructive verbs in ``FORBIDDEN_VERBS`` can never
appear in generated advice.
"""

from .generator import (
    FORBIDDEN_VERBS,
    REMEDIABLE_KINDS,
    assert_safe_commands,
    generate_plan,
)
from .types import Confidence, RemediationPlan, RemediationStep

__all__ = [
    "FORBIDDEN_VERBS",
    "REMEDIABLE_KINDS",
    "Confidence",
    "RemediationPlan",
    "RemediationStep",
    "assert_safe_commands",
    "generate_plan",
]
