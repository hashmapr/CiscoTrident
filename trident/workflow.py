"""End-to-end practice-lab workflow: requirements -> compliance -> remediation.

This is the production entry point that ties the Phase 2 engines together. It is
deliberately thin: each stage delegates to its module and every stage carries
evidence forward.

Read-only: nothing here writes to an input file or executes a command.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .compliance import ComplianceResult, ComplianceStatus, evaluate
from .models import NetworkModel
from .remediation import RemediationPlan, generate_plan
from .requirements import Requirement, RequirementStatus, parse_requirements

#: Requirement kinds the compliance engine can evaluate.
COMPLIANCE_KINDS = {
    "ipv4_address",
    "ipv4_subnet",
    "hostname",
    "security",
    "default_route",
    "vlan_assignment",
    "ssh",
    "trunk",
}


@dataclass(frozen=True)
class RequirementOutcome:
    """One requirement after evaluation and (optional) remediation."""

    requirement: Requirement
    compliance: ComplianceResult | None
    remediation: RemediationPlan | None
    skipped_reason: str = ""


@dataclass
class LabAssessment:
    """The full assessment of one lab instruction document against one network."""

    snapshot_id: str
    outcomes: list[RequirementOutcome] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.outcomes)

    def by_status(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for outcome in self.outcomes:
            if outcome.compliance is None:
                key = "NOT_EVALUATED"
            else:
                key = outcome.compliance.status.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def satisfied(self) -> int:
        return sum(
            1
            for o in self.outcomes
            if o.compliance is not None
            and o.compliance.status is ComplianceStatus.SATISFIED
        )

    @property
    def unsatisfied(self) -> int:
        return sum(
            1
            for o in self.outcomes
            if o.compliance is not None
            and o.compliance.status is ComplianceStatus.UNSATISFIED
        )

    def actionable(self) -> list[RequirementOutcome]:
        """Outcomes where a remediation plan exists (advisory only)."""
        return [o for o in self.outcomes if o.remediation is not None]


def assess_lab(
    model: NetworkModel, instructions: str, *, generate_remediation: bool = True
) -> LabAssessment:
    """Parse lab instructions and evaluate them against one network model.

    Requirements the engine could not parse are preserved with their reason --
    never silently dropped, never guessed at.
    """
    assessment = LabAssessment(snapshot_id=model.snapshot_id or "unknown")
    requirements = parse_requirements(instructions)

    for req in requirements:
        if req.status is not RequirementStatus.PARSED:
            assessment.outcomes.append(
                RequirementOutcome(
                    requirement=req,
                    compliance=None,
                    remediation=None,
                    skipped_reason=f"requirement not parsed: {req.status.value}",
                )
            )
            continue

        kind = req.kind.value
        if kind not in COMPLIANCE_KINDS:
            assessment.outcomes.append(
                RequirementOutcome(
                    requirement=req,
                    compliance=None,
                    remediation=None,
                    skipped_reason=f"no compliance evaluator for kind '{kind}'",
                )
            )
            continue

        compliance = evaluate(
            model,
            kind=kind,
            device=req.device,
            interface=req.interface,
            expected=req.expected,
        )

        remediation = None
        if generate_remediation:
            remediation = generate_plan(compliance)

        assessment.outcomes.append(
            RequirementOutcome(
                requirement=req,
                compliance=compliance,
                remediation=remediation,
            )
        )

    return assessment
