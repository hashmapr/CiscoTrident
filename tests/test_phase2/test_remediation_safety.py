"""Tests pinning remediation safety: no mask guessing, no silent no-shutdown."""

from __future__ import annotations

from trident.compliance.types import ComplianceResult, ComplianceStatus, Evidence
from trident.remediation.generator import generate_plan


def _result(kind: str, expected: str, actual: str | None, *, device="R1", interface="GigabitEthernet0/0"):
    return ComplianceResult(
        requirement_kind=kind,
        device=device,
        interface=interface,
        expected=expected,
        actual=actual,
        status=ComplianceStatus.UNSATISFIED,
        evidence=(Evidence(device=device, interface=interface, detail="observed", source="running-config"),),
        reason="mismatch",
    )


def test_address_repair_never_guesses_a_classful_mask():
    """A bare address with no prefix must not produce a /24-style guess."""
    plan = generate_plan(_result("ipv4_address", "10.0.0.1", "10.0.0.2", interface="GigabitEthernet0/0"))
    if plan is None:
        return
    all_commands = " ".join(c for step in plan.steps for c in step.commands)
    assert "/24" not in all_commands
    assert plan.confidence.value == "LOW" or not plan.steps


def test_address_repair_does_not_add_no_shutdown():
    """Adding an address must not silently bring the interface up."""
    plan = generate_plan(
        _result("ipv4_address", "10.0.0.1/24", "10.0.0.2/24", interface="GigabitEthernet0/0")
    )
    assert plan is not None
    all_commands = [c for step in plan.steps for c in step.commands]
    assert "no shutdown" not in all_commands, all_commands
    assert any("ip address 10.0.0.1 255.255.255.0" in c for c in all_commands)


def test_subnet_repair_with_mask_still_works():
    plan = generate_plan(
        _result("ipv4_subnet", "255.255.255.0", "255.255.0.0", interface="Gi0/0")
    )
    if plan is None:
        return
    all_commands = [c for step in plan.steps for c in step.commands]
    assert "no shutdown" not in all_commands


def test_plan_is_always_advisory():
    plan = generate_plan(
        _result("ipv4_address", "10.0.0.1/24", "10.0.0.2/24", interface="Gi0/0")
    )
    assert plan is not None
    assert plan.advisory_only is True


def test_no_destructive_verbs_anywhere():
    forbidden = ("reload", "erase", "write erase", "delete", "format")
    for kind, expected, actual in (
        ("ipv4_address", "10.0.0.1/24", "10.0.0.2/24"),
        ("ipv4_subnet", "255.255.255.0", "255.255.0.0"),
        ("vlan_assignment", "20", None),
        ("default_route", "10.1.1.2", None),
    ):
        plan = generate_plan(_result(kind, expected, actual, interface="Gi0/0"))
        if plan is None:
            continue
        blob = " ".join(c for step in plan.steps for c in step.commands)
        for verb in forbidden:
            assert verb not in blob.lower(), f"{kind}: {verb}"
