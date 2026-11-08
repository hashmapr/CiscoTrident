"""End-to-end tests for the practice-lab workflow (requirements -> compliance -> remediation)."""

from __future__ import annotations

from trident.compliance import ComplianceStatus
from trident.models import DeviceInfo, InterfaceInfo, NetworkModel
from trident.workflow import LabAssessment, assess_lab


def _model() -> NetworkModel:
    return NetworkModel(
        devices={
            "R1": DeviceInfo(
                id="R1",
                name="R1",
                hostname="R1",
                configuration=[
                    "hostname R1",
                    "interface GigabitEthernet0/0",
                    "ip address 192.168.10.1 255.255.255.0",
                    "no shutdown",
                ],
            ),
            "SW1": DeviceInfo(id="SW1", name="SW1", hostname="SW1", configuration=["hostname SW1"]),
        },
        interfaces={
            "R1:GigabitEthernet0/0": InterfaceInfo(
                device="R1",
                name="GigabitEthernet0/0",
                canonical_name="GigabitEthernet0/0",
                ipv4_address="192.168.10.1",
                subnet_mask="255.255.255.0",
                prefix_length=24,
            ),
        },
        snapshot_id="block0",
    )


def test_satisfied_requirement_has_no_remediation():
    a = assess_lab(_model(), "Configure 192.168.10.1/24 on R1 GigabitEthernet0/0")
    assert a.total == 1
    o = a.outcomes[0]
    assert o.compliance is not None
    assert o.compliance.status is ComplianceStatus.SATISFIED
    assert o.remediation is None


def test_unsatisfied_requirement_produces_an_advisory_plan():
    a = assess_lab(_model(), "Configure 10.9.9.1/24 on R1 GigabitEthernet0/0")
    o = a.outcomes[0]
    assert o.compliance is not None
    assert o.compliance.status is ComplianceStatus.UNSATISFIED
    assert o.remediation is not None
    assert o.remediation.advisory_only is True


def test_unparseable_instruction_is_preserved_with_a_reason():
    a = assess_lab(_model(), "Review the topology diagram carefully.")
    assert a.total == 1
    o = a.outcomes[0]
    assert o.compliance is None
    assert o.skipped_reason
    assert "not parsed" in o.skipped_reason or "no compliance evaluator" in o.skipped_reason


def test_unknown_device_is_unsupported_not_unsatisfied():
    a = assess_lab(_model(), "Configure 10.0.0.1/24 on R99 GigabitEthernet0/0")
    o = a.outcomes[0]
    assert o.compliance is not None
    assert o.compliance.status is ComplianceStatus.UNSUPPORTED
    assert o.remediation is None


def test_status_counts_are_consistent():
    text = (
        "Configure 192.168.10.1/24 on R1 GigabitEthernet0/0\n"\
        "Configure 10.9.9.1/24 on R1 GigabitEthernet0/0\n"\
        "This line is not a requirement at all."
    )
    a = assess_lab(_model(), text)
    assert a.total == 3
    counts = a.by_status()
    assert counts.get("SATISFIED", 0) == 1
    assert counts.get("UNSATISFIED", 0) == 1
    assert counts.get("NOT_EVALUATED", 0) == 1
    assert a.satisfied == 1
    assert a.unsatisfied == 1


def test_workflow_never_executes_anything():
    """Every plan the workflow returns must be advisory-only."""
    a = assess_lab(_model(), "Configure 10.9.9.1/24 on R1 GigabitEthernet0/0")
    for o in a.actionable():
        assert o.remediation is not None
        assert o.remediation.advisory_only is True


def test_empty_instructions_yield_empty_assessment():
    a = assess_lab(_model(), "   \n\n  ")
    assert isinstance(a, LabAssessment)
    assert a.total == 0
