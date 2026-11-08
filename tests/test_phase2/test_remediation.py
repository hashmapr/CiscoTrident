"""Tests for the IOS remediation generator.

The tests are organised by the safety contract rather than by code path:

* every supported kind produces a plan for an UNSATISFIED verdict
* SATISFIED / UNSUPPORTED / INDETERMINATE produce no plan
* every plan is advisory-only
* no plan ever contains a destructive verb
* an unknown prior state yields an empty rollback and LOW confidence
"""

from __future__ import annotations

import pytest

from trident.compliance import ComplianceResult, ComplianceStatus, Evidence
from trident.remediation import (
    FORBIDDEN_VERBS,
    REMEDIABLE_KINDS,
    Confidence,
    RemediationPlan,
    assert_safe_commands,
    generate_plan,
)


def make_result(
    kind: str,
    *,
    device: str | None = "R1",
    interface: str | None = None,
    expected: str = "",
    actual: str | None = None,
    status: ComplianceStatus = ComplianceStatus.UNSATISFIED,
    evidence: tuple[Evidence, ...] = (),
    reason: str = "requirement not met",
) -> ComplianceResult:
    return ComplianceResult(
        requirement_kind=kind,
        device=device,
        interface=interface,
        expected=expected,
        actual=actual,
        status=status,
        evidence=evidence,
        reason=reason,
    )


def all_commands(plan: RemediationPlan) -> list[str]:
    commands: list[str] = []
    for step in plan.steps:
        commands.extend(step.commands)
    commands.extend(plan.verification_commands)
    commands.extend(plan.rollback_commands)
    return commands


# ---------------------------------------------------------------------------
# One plan per supported kind
# ---------------------------------------------------------------------------


def test_ipv4_address_plan() -> None:
    plan = generate_plan(
        make_result(
            "ipv4_address",
            interface="GigabitEthernet0/0",
            expected="10.0.0.1 255.255.255.0",
            actual="10.0.0.9",
            evidence=(
                Evidence(
                    device="R1",
                    interface="GigabitEthernet0/0",
                    detail="GigabitEthernet0/0 is configured with IPv4 address 10.0.0.9/24",
                    source="running-config line 5: ip address 10.0.0.9 255.255.255.0",
                ),
            ),
        )
    )
    assert plan is not None
    assert plan.advisory_only is True
    assert plan.interface == "GigabitEthernet0/0"
    commands = all_commands(plan)
    assert "interface GigabitEthernet0/0" in commands
    assert "ip address 10.0.0.1 255.255.255.0" in commands
    # no shutdown is intentionally NOT added: addressing does not imply enabling.
    assert "no shutdown" not in commands
    assert plan.confidence is Confidence.HIGH
    assert plan.rollback_commands == (
        "interface GigabitEthernet0/0",
        "ip address 10.0.0.9 255.255.255.0",
    )


def test_ipv4_address_plan_without_mask_proposes_nothing() -> None:
    """A bare address has no safe mask. The plan must abstain, not guess /8.

    Replaces an earlier expectation that a classful default was acceptable; that
    silently configured a wrong prefix on a live lab.
    """
    plan = generate_plan(
        make_result(
            "ipv4_address",
            interface="GigabitEthernet0/0",
            expected="10.0.0.1",
            actual=None,
        )
    )
    assert plan is not None
    assert all_commands(plan) == [], "no command may be proposed without a mask"
    assert plan.confidence is Confidence.LOW
    assert any("mask cannot be derived safely" in note for note in plan.evidence)


def test_ipv4_subnet_plan() -> None:
    plan = generate_plan(
        make_result(
            "ipv4_subnet",
            interface="GigabitEthernet0/0",
            expected="255.255.255.0",
            actual="255.255.0.0",
            evidence=(
                Evidence(
                    device="R1",
                    interface="GigabitEthernet0/0",
                    detail="GigabitEthernet0/0 subnet mask is 255.255.0.0 (/16)",
                    source="running-config line 5: ip address 10.0.0.1 255.255.0.0",
                ),
            ),
        )
    )
    assert plan is not None
    commands = all_commands(plan)
    assert "ip address 10.0.0.1 255.255.255.0" in commands
    assert plan.confidence is Confidence.HIGH
    assert plan.rollback_commands == (
        "interface GigabitEthernet0/0",
        "ip address 10.0.0.1 255.255.0.0",
    )


def test_hostname_plan() -> None:
    plan = generate_plan(
        make_result("hostname", expected="R1", actual="Router")
    )
    assert plan is not None
    assert [cmd for step in plan.steps for cmd in step.commands] == ["hostname R1"]
    assert plan.rollback_commands == ("hostname Router",)
    assert plan.confidence is Confidence.HIGH


def test_default_route_plan() -> None:
    plan = generate_plan(
        make_result("default_route", expected="10.0.0.254", actual="10.0.0.253")
    )
    assert plan is not None
    assert plan.steps[0].commands == ("ip route 0.0.0.0 0.0.0.0 10.0.0.254",)
    assert plan.rollback_commands == (
        "no ip route 0.0.0.0 0.0.0.0 10.0.0.254",
        "ip route 0.0.0.0 0.0.0.0 10.0.0.253",
    )
    assert plan.confidence is Confidence.HIGH


def test_default_route_plan_when_absent() -> None:
    plan = generate_plan(make_result("default_route", expected="10.0.0.254", actual=None))
    assert plan is not None
    assert plan.current_state == "no default route present"
    assert plan.rollback_commands == ("no ip route 0.0.0.0 0.0.0.0 10.0.0.254",)
    assert plan.confidence is Confidence.HIGH


def test_vlan_assignment_plan() -> None:
    plan = generate_plan(
        make_result(
            "vlan_assignment",
            interface="FastEthernet0/1",
            expected="VLAN 20",
            actual="10",
        )
    )
    assert plan is not None
    commands = all_commands(plan)
    assert "interface FastEthernet0/1" in commands
    assert "switchport mode access" in commands
    assert "switchport access vlan 20" in commands


def test_ssh_plan() -> None:
    plan = generate_plan(make_result("ssh", expected="enabled", actual="disabled"))
    assert plan is not None
    commands = all_commands(plan)
    assert any(command.startswith("ip domain-name ") for command in commands)
    assert "crypto key generate rsa modulus 2048" in commands
    assert "ip ssh version 2" in commands
    assert "line vty 0 4" in commands
    assert "transport input ssh" in commands


# ---------------------------------------------------------------------------
# No plan when there is nothing safe to say
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", sorted(REMEDIABLE_KINDS))
def test_no_plan_for_satisfied(kind: str) -> None:
    result = make_result(
        kind,
        interface="GigabitEthernet0/0",
        expected="x",
        actual="x",
        status=ComplianceStatus.SATISFIED,
    )
    assert generate_plan(result) is None


@pytest.mark.parametrize("kind", sorted(REMEDIABLE_KINDS))
def test_no_plan_for_unsupported(kind: str) -> None:
    result = make_result(
        kind,
        device=None,
        status=ComplianceStatus.UNSUPPORTED,
        reason="device is not present in this snapshot",
    )
    assert generate_plan(result) is None


@pytest.mark.parametrize("kind", sorted(REMEDIABLE_KINDS))
def test_no_plan_for_indeterminate(kind: str) -> None:
    result = make_result(
        kind,
        interface="GigabitEthernet0/0",
        status=ComplianceStatus.INDETERMINATE,
        reason="ambiguous",
    )
    assert generate_plan(result) is None


def test_no_plan_for_unsupported_kind() -> None:
    result = make_result("trunk", interface="GigabitEthernet0/1", expected="trunk")
    assert generate_plan(result) is None


# ---------------------------------------------------------------------------
# advisory_only is always True
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", sorted(REMEDIABLE_KINDS))
def test_plan_is_always_advisory_only(kind: str) -> None:
    result = make_result(
        kind,
        interface="GigabitEthernet0/0",
        expected="enabled",
        actual=None,
    )
    plan = generate_plan(result)
    if plan is not None:
        assert plan.advisory_only is True


def test_advisory_only_cannot_be_disabled() -> None:
    with pytest.raises(ValueError):
        RemediationPlan(
            device="R1",
            interface=None,
            current_state="unknown",
            required_state="x",
            steps=(),
            verification_commands=(),
            rollback_commands=(),
            confidence=Confidence.LOW,
            evidence=(),
            advisory_only=False,
        )


# ---------------------------------------------------------------------------
# Destructive verbs are refused
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("verb", FORBIDDEN_VERBS)
def test_blocklist_rejects_destructive_verb(verb: str) -> None:
    with pytest.raises(ValueError):
        assert_safe_commands([f"{verb} all"])


@pytest.mark.parametrize("kind", sorted(REMEDIABLE_KINDS))
def test_generated_plans_never_contain_destructive_verbs(kind: str) -> None:
    plan = generate_plan(
        make_result(
            kind,
            interface="GigabitEthernet0/0",
            expected="enabled",
            actual=None,
        )
    )
    if plan is None:
        return
    for command in all_commands(plan):
        assert_safe_commands([command])


# ---------------------------------------------------------------------------
# Unknown prior state -> empty rollback + LOW confidence
# ---------------------------------------------------------------------------


def test_hostname_unknown_prior_state() -> None:
    plan = generate_plan(make_result("hostname", expected="R1", actual=None))
    assert plan is not None
    assert plan.rollback_commands == ()
    assert plan.confidence is Confidence.LOW


def test_ssh_unknown_prior_state() -> None:
    plan = generate_plan(make_result("ssh", expected="enabled", actual=None))
    assert plan is not None
    assert plan.rollback_commands == ()
    assert plan.confidence is Confidence.LOW


def test_ipv4_subnet_unknown_address_has_no_rollback() -> None:
    plan = generate_plan(
        make_result(
            "ipv4_subnet",
            interface="GigabitEthernet0/0",
            expected="255.255.255.0",
            actual=None,
        )
    )
    assert plan is not None
    assert plan.rollback_commands == ()
    assert plan.confidence is Confidence.LOW
    assert plan.steps[0].commands == ()


def test_vlan_assignment_unknown_prior_state() -> None:
    plan = generate_plan(
        make_result(
            "vlan_assignment",
            interface="FastEthernet0/1",
            expected="VLAN 20",
            actual=None,
        )
    )
    assert plan is not None
    assert plan.rollback_commands == ()
    assert plan.confidence is Confidence.LOW
