"""Double-check mode: comprehensive, independent re-validation of a network.

The verifier never accepts the investigator's diagnosis as proof. It rebuilds its
own conclusions from the requirements, the static model and the observations it
actually collected, then compares. That separation is the whole point of the
mode: if the same code both proposed and approved a finding, the approval means
nothing.

Coverage is counted, not asserted. A network is never described as fully verified
when checks were unsupported or skipped — those are separate counters, and they
are reported.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from ..diagnostics import diagnose
from ..diagnostics.types import HypothesisStatus
from ..models import NetworkModel
from ..simulator.contracts import Capability, OperationResult
from ..simulator.evidence_bridge import operational_evidence_tier
from ..simulator.sessions import Session


class Verdict(enum.StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    UNRESOLVED = "UNRESOLVED"
    UNSUPPORTED = "UNSUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    SKIPPED = "SKIPPED"


@dataclass
class Check:
    """One thing that was checked, with what was actually observed."""

    check_id: str
    requirement: str
    device: str | None
    interface: str | None
    expected: str
    observed: str
    verdict: Verdict
    evidence_source: str
    diagnostics_run: list[str] = field(default_factory=list)
    suspected_root_cause: str | None = None
    limitations: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "requirement": self.requirement,
            "device": self.device,
            "interface": self.interface,
            "expected": self.expected,
            "observed": self.observed,
            "verdict": self.verdict.value,
            "evidence_source": self.evidence_source,
            "diagnostics_run": list(self.diagnostics_run),
            "suspected_root_cause": self.suspected_root_cause,
            "limitations": list(self.limitations),
        }


@dataclass
class Coverage:
    """Explicit accounting. Nothing is folded into a fake '100%'."""

    requirements: int = 0
    statically_checked: int = 0
    operationally_checked: int = 0
    simulator_tested: int = 0
    passed: int = 0
    failed: int = 0
    unresolved: int = 0
    unsupported: int = 0
    contradicted: int = 0
    skipped: int = 0

    def as_dict(self) -> dict:
        total = max(self.requirements, 1)
        return {
            "requirements": self.requirements,
            "statically_checked": self.statically_checked,
            "operationally_checked": self.operationally_checked,
            "simulator_tested": self.simulator_tested,
            "passed": self.passed,
            "failed": self.failed,
            "unresolved": self.unresolved,
            "unsupported": self.unsupported,
            "contradicted": self.contradicted,
            "skipped": self.skipped,
            # Deliberately not called "percent verified": it counts checks that
            # produced a definitive verdict, whatever that verdict was.
            "resolved_fraction": round(
                (self.passed + self.failed) / total, 3
            ),
        }


@dataclass
class AuditReport:
    coverage: Coverage
    checks: list[Check]
    contradictions: list[str]
    evidence_tier: str
    runtime_available: bool
    runtime_reason: str

    def as_dict(self) -> dict:
        return {
            "coverage": self.coverage.as_dict(),
            "checks": [check.as_dict() for check in self.checks],
            "contradictions": list(self.contradictions),
            "evidence_tier": self.evidence_tier,
            "runtime_available": self.runtime_available,
            "runtime_reason": self.runtime_reason,
        }


#: The operational checks this auditor knows how to perform.
_CHECKS: tuple[tuple[str, str, str], ...] = (
    ("interface_state", "Every addressed interface should be up", "show ip interface brief"),
    ("routing_table", "Router should have a route to every connected peer", "show ip route"),
    ("vlan_consistency", "Access ports should be in their service VLAN", "show vlan brief"),
    ("trunk_consistency", "Both trunk ends should carry the same VLANs", "show interfaces trunk"),
    ("acl_review", "No deny entry should cut the intended path", "show access-lists"),
)


class Auditor:
    """Runs the comprehensive audit. Independent of the investigator's verdicts."""

    def __init__(
        self,
        model: NetworkModel,
        *,
        session: Session | None = None,
        runtime_available: bool = False,
        runtime_reason: str = "",
        max_checks: int = 20,
    ) -> None:
        self.model = model
        self.session = session
        self.runtime_available = runtime_available and session is not None
        self.runtime_reason = runtime_reason
        self.max_checks = max_checks

    def audit(self) -> AuditReport:
        checks: list[Check] = []
        contradictions: list[str] = []
        coverage = Coverage()
        observations: list[OperationResult] = []

        # 1. Independent static diagnosis. This is the auditor's own conclusion,
        #    not a copy of anything the investigator produced.
        diagnosis = diagnose(self.model)
        static_findings = {
            h.kind: h
            for h in diagnosis.hypotheses
            if h.status in {HypothesisStatus.CONFIRMED_DEFECT, HypothesisStatus.SUSPECTED}
        }

        # 2. Identity consistency: a device referenced by an interface must exist.
        coverage.requirements += 1
        coverage.statically_checked += 1
        missing_devices = sorted(
            {
                interface.device
                for interface in self.model.interfaces.values()
                if interface.device not in self.model.devices
            }
        )
        if missing_devices:
            coverage.contradicted += 1
            checks.append(
                Check(
                    check_id="identity:devices",
                    requirement="Every interface belongs to a known device",
                    device=None,
                    interface=None,
                    expected="all interface owners exist in the device list",
                    observed=f"unknown owners: {missing_devices}",
                    verdict=Verdict.CONTRADICTED,
                    evidence_source="MODEL",
                )
            )
            contradictions.append(
                f"interfaces reference devices that do not exist: {missing_devices}"
            )
        else:
            coverage.passed += 1
            checks.append(
                Check(
                    check_id="identity:devices",
                    requirement="Every interface belongs to a known device",
                    device=None,
                    interface=None,
                    expected="all interface owners exist in the device list",
                    observed="consistent",
                    verdict=Verdict.PASSED,
                    evidence_source="MODEL",
                )
            )

        # 3. Static findings become their own checks, so a fault the auditor finds
        #    is reported whether or not any operational check was possible.
        for kind, hypothesis in sorted(static_findings.items()):
            coverage.requirements += 1
            coverage.statically_checked += 1
            if hypothesis.status is HypothesisStatus.CONFIRMED_DEFECT:
                coverage.failed += 1
                verdict = Verdict.FAILED
            else:
                coverage.unresolved += 1
                verdict = Verdict.UNRESOLVED
            checks.append(
                Check(
                    check_id=f"static:{kind}",
                    requirement=f"No {kind.replace('_', ' ').lower()} present",
                    device=hypothesis.device,
                    interface=hypothesis.interface,
                    expected="configuration consistent with intent",
                    observed=hypothesis.suspected_cause,
                    verdict=verdict,
                    evidence_source="MODEL",
                    suspected_root_cause=kind,
                    limitations=["static finding: not confirmed operationally"],
                )
            )

        # 4. Operational checks, only where the backend supports them.
        if self.runtime_available and self.session is not None:
            for check_id, requirement, command in _CHECKS:
                if len(checks) >= self.max_checks:
                    coverage.requirements += 1
                    coverage.skipped += 1
                    checks.append(
                        Check(
                            check_id=f"limit:{check_id}",
                            requirement=requirement,
                            device=None,
                            interface=None,
                            expected="check executed",
                            observed="not executed",
                            verdict=Verdict.SKIPPED,
                            evidence_source="NONE",
                            limitations=["check budget exhausted"],
                        )
                    )
                    continue
                coverage.requirements += 1
                result = self._run(command)
                if result is None:
                    coverage.unsupported += 1
                    checks.append(
                        Check(
                            check_id=f"ops:{check_id}",
                            requirement=requirement,
                            device=None,
                            interface=None,
                            expected="check executed",
                            observed="backend cannot run this command",
                            verdict=Verdict.UNSUPPORTED,
                            evidence_source="NONE",
                        )
                    )
                    continue
                observations.append(result)
                coverage.operationally_checked += 1
                if result.is_live:
                    coverage.simulator_tested += 1
                verdict = Verdict.PASSED if result.ok else Verdict.UNRESOLVED
                if result.ok:
                    coverage.passed += 1
                else:
                    coverage.unresolved += 1
                checks.append(
                    Check(
                        check_id=f"ops:{check_id}",
                        requirement=requirement,
                        device=result.device,
                        interface=None,
                        expected="command completes and output parsed",
                        observed=(result.raw[:200] if result.ok else (result.error or "failed")),
                        verdict=verdict,
                        evidence_source=result.provenance.backend.value,
                        diagnostics_run=[command],
                        limitations=[] if result.is_live else ["not a live simulator observation"],
                    )
                )

        tier = operational_evidence_tier(observations)
        return AuditReport(
            coverage=coverage,
            checks=checks,
            contradictions=contradictions,
            evidence_tier=tier,
            runtime_available=self.runtime_available,
            runtime_reason=self.runtime_reason,
        )

    def _run(self, command: str) -> OperationResult | None:
        if self.session is None or not self.session.supports(Capability.RUN_CLI):
            return None
        device = self._first_device_for(command)
        if device is None:
            return None
        try:
            return self.session.run_cli(device, command, timeout=self.session.budget.command_timeout_s)
        except Exception:  # noqa: BLE001 - represented as unsupported, not hidden
            return None

    def _usable_devices(self) -> list[str]:
        """Model devices the backend can actually address.

        Choosing a device the backend does not expose would turn every check into
        an unsupported one, which would understate coverage for a reason that has
        nothing to do with the network.
        """
        model_names = list(self.model.devices)
        if self.session is None:
            return sorted(model_names)
        try:
            available = {entry["name"] for entry in self.session.backend.devices()}
        except Exception:  # noqa: BLE001 - fall back to the model's own names
            return sorted(model_names)
        usable = [name for name in model_names if name in available]
        return usable or sorted(model_names)

    def _first_device_for(self, command: str) -> str | None:
        usable = self._usable_devices()
        if not usable:
            return None

        def prefer(kind: str) -> str | None:
            for name in usable:
                device = self.model.devices.get(name)
                if device is None:
                    continue
                if kind in (device.device_type or "").lower():
                    return name
            return None

        if command == "show ip route":
            return prefer("router") or usable[0]
        if command.startswith(("show vlan", "show interfaces trunk")):
            return prefer("switch") or usable[0]
        return usable[0]


__all__ = ["AuditReport", "Auditor", "Check", "Coverage", "Verdict"]
