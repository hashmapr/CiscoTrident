"""Tests for the configuration compliance engine.

Coverage is organised by the honesty contract rather than by code path:

* every supported kind has a satisfied case
* a recorded-but-wrong value is UNSATISFIED
* a device absent from the snapshot is UNSUPPORTED, never UNSATISFIED
* a requirement the model cannot speak to is INDETERMINATE
* SATISFIED is never returned without evidence
* UNSUPPORTED is structurally distinct from UNSATISFIED
"""

from __future__ import annotations

import pytest

from trident.compliance import (
    SUPPORTED_KINDS,
    ComplianceResult,
    ComplianceStatus,
    Evidence,
    evaluate,
)
from trident.models import (
    DeviceInfo,
    InterfaceInfo,
    NetworkModel,
    RouteInfo,
    SettingsInfo,
    VlanInfo,
)

R1_CONFIG = [
    "version 15.1",
    "hostname R1",
    "!",
    "interface GigabitEthernet0/0",
    " ip address 10.0.0.1 255.255.255.0",
    " no shutdown",
    "!",
    "interface GigabitEthernet0/1",
    " description uplink",
    " switchport mode trunk",
    " switchport trunk allowed vlan 10,20",
    "!",
    "interface FastEthernet0/1",
    " switchport mode access",
    " switchport access vlan 10",
    "!",
    "ip route 0.0.0.0 0.0.0.0 10.0.0.254",
    "!",
    "line vty 0 4",
    " transport input ssh",
    "!",
    "ip ssh version 2",
]


def build_model() -> NetworkModel:
    return NetworkModel(
        devices={
            "R1": DeviceInfo(
                id="R1",
                name="R1",
                hostname="R1",
                device_type="router",
                configuration=list(R1_CONFIG),
                interfaces=["GigabitEthernet0/0", "GigabitEthernet0/1", "FastEthernet0/1"],
            ),
            "SW1": DeviceInfo(
                id="SW1",
                name="SW1",
                hostname="SW1",
                device_type="switch",
                configuration=[
                    "hostname SW1",
                    "!",
                    "interface GigabitEthernet0/1",
                    " switchport mode access",
                    " switchport access vlan 10",
                ],
                interfaces=["GigabitEthernet0/1"],
            ),
        },
        interfaces={
            "R1:GigabitEthernet0/0": InterfaceInfo(
                device="R1",
                name="GigabitEthernet0/0",
                canonical_name="GigabitEthernet0/0",
                ipv4_address="10.0.0.1",
                subnet_mask="255.255.255.0",
                prefix_length=24,
                admin_state="up",
            ),
            "R1:GigabitEthernet0/1": InterfaceInfo(
                device="R1",
                name="GigabitEthernet0/1",
                canonical_name="GigabitEthernet0/1",
                description="uplink",
                access_mode="trunk",
                vlan_assignments=["10", "20"],
            ),
            "R1:FastEthernet0/1": InterfaceInfo(
                device="R1",
                name="FastEthernet0/1",
                canonical_name="FastEthernet0/1",
                access_mode="access",
                vlan_assignments=["10"],
            ),
            "SW1:GigabitEthernet0/1": InterfaceInfo(
                device="SW1",
                name="GigabitEthernet0/1",
                canonical_name="GigabitEthernet0/1",
                access_mode="access",
                vlan_assignments=["10"],
            ),
        },
        routes=[
            RouteInfo(
                destination="0.0.0.0",
                next_hop="10.0.0.254",
                outgoing_interface=None,
                route_type="static",
                device="R1",
                raw_config="ip route 0.0.0.0 0.0.0.0 10.0.0.254",
            )
        ],
        vlans=[
            VlanInfo(vlan_id=10, name="DATA", member_ports=["FastEthernet0/1", "GigabitEthernet0/1"]),
            VlanInfo(vlan_id=20, name="VOICE", trunk_allowances=["GigabitEthernet0/1"]),
        ],
        settings=SettingsInfo(),
        snapshot_id="compliance-test",
    )


@pytest.fixture
def model() -> NetworkModel:
    return build_model()


def check(
    model: NetworkModel,
    kind: str,
    device: str | None,
    interface: str | None,
    expected: str,
) -> ComplianceResult:
    return evaluate(model, kind=kind, device=device, interface=interface, expected=expected)


# ---------------------------------------------------------------------------
# engine surface
# ---------------------------------------------------------------------------


def test_supported_kinds_cover_the_required_set() -> None:
    assert {
        "ipv4_address",
        "ipv4_subnet",
        "hostname",
        "default_route",
        "vlan_assignment",
        "ssh",
        "trunk",
    } <= SUPPORTED_KINDS


def test_requirement_kind_is_echoed_as_a_plain_string(model: NetworkModel) -> None:
    result = check(model, "hostname", "R1", None, "R1")
    assert result.requirement_kind == "hostname"
    assert isinstance(result.requirement_kind, str)


# ---------------------------------------------------------------------------
# satisfied cases, one per kind
# ---------------------------------------------------------------------------


def test_ipv4_address_satisfied_with_mask_form(model: NetworkModel) -> None:
    result = check(model, "ipv4_address", "R1", "GigabitEthernet0/0", "10.0.0.1 255.255.255.0")
    assert result.status is ComplianceStatus.SATISFIED
    assert result.actual == "10.0.0.1"
    assert result.evidence
    assert "running-config line" in result.evidence[0].source


def test_ipv4_address_satisfied_with_cidr_form(model: NetworkModel) -> None:
    result = check(model, "ipv4_address", "R1", "Gi0/0", "10.0.0.1/24")
    assert result.status is ComplianceStatus.SATISFIED
    assert result.evidence


def test_ipv4_subnet_satisfied_with_dotted_mask(model: NetworkModel) -> None:
    result = check(model, "ipv4_subnet", "R1", "GigabitEthernet0/0", "255.255.255.0")
    assert result.status is ComplianceStatus.SATISFIED
    assert result.evidence


def test_ipv4_subnet_satisfied_with_prefix(model: NetworkModel) -> None:
    result = check(model, "ipv4_subnet", "R1", "GigabitEthernet0/0", "/24")
    assert result.status is ComplianceStatus.SATISFIED
    assert result.evidence


def test_hostname_satisfied(model: NetworkModel) -> None:
    result = check(model, "hostname", "R1", None, "R1")
    assert result.status is ComplianceStatus.SATISFIED
    assert result.evidence


def test_default_route_satisfied(model: NetworkModel) -> None:
    result = check(model, "default_route", "R1", None, "10.0.0.254")
    assert result.status is ComplianceStatus.SATISFIED
    assert result.evidence


def test_vlan_assignment_satisfied(model: NetworkModel) -> None:
    result = check(model, "vlan_assignment", "R1", "GigabitEthernet0/1", "10,20")
    assert result.status is ComplianceStatus.SATISFIED
    assert result.evidence


def test_ssh_satisfied(model: NetworkModel) -> None:
    result = check(model, "ssh", "R1", None, "enabled")
    assert result.status is ComplianceStatus.SATISFIED
    assert result.evidence
    assert any("transport input ssh" in e.detail for e in result.evidence)


def test_trunk_satisfied(model: NetworkModel) -> None:
    result = check(model, "trunk", "R1", "GigabitEthernet0/1", "trunk")
    assert result.status is ComplianceStatus.SATISFIED
    assert result.evidence


def test_trunk_access_expectation_satisfied(model: NetworkModel) -> None:
    result = check(model, "trunk", "R1", "FastEthernet0/1", "access")
    assert result.status is ComplianceStatus.SATISFIED
    assert result.evidence


# ---------------------------------------------------------------------------
# unsatisfied: value present but different
# ---------------------------------------------------------------------------


def test_ipv4_address_wrong_value_is_unsatisfied(model: NetworkModel) -> None:
    result = check(model, "ipv4_address", "R1", "GigabitEthernet0/0", "10.0.0.2")
    assert result.status is ComplianceStatus.UNSATISFIED
    assert result.actual == "10.0.0.1"


def test_ipv4_address_right_host_wrong_prefix_is_partial(model: NetworkModel) -> None:
    result = check(model, "ipv4_address", "R1", "GigabitEthernet0/0", "10.0.0.1/16")
    assert result.status is ComplianceStatus.PARTIALLY_SATISFIED
    assert result.actual == "10.0.0.1"


def test_ipv4_subnet_wrong_mask_is_unsatisfied(model: NetworkModel) -> None:
    result = check(model, "ipv4_subnet", "R1", "GigabitEthernet0/0", "255.255.255.128")
    assert result.status is ComplianceStatus.UNSATISFIED
    assert result.actual == "255.255.255.0"


def test_hostname_wrong_value_is_unsatisfied(model: NetworkModel) -> None:
    result = check(model, "hostname", "R1", None, "CORE-R1")
    assert result.status is ComplianceStatus.UNSATISFIED
    assert result.actual == "R1"


def test_default_route_wrong_next_hop_is_unsatisfied(model: NetworkModel) -> None:
    result = check(model, "default_route", "R1", None, "192.0.2.1")
    assert result.status is ComplianceStatus.UNSATISFIED
    assert result.evidence


def test_vlan_assignment_wrong_vlan_is_unsatisfied(model: NetworkModel) -> None:
    result = check(model, "vlan_assignment", "R1", "FastEthernet0/1", "30")
    assert result.status is ComplianceStatus.UNSATISFIED
    assert result.actual == "10"


def test_vlan_assignment_partial_overlap_is_partial(model: NetworkModel) -> None:
    result = check(model, "vlan_assignment", "R1", "GigabitEthernet0/1", "10,30")
    assert result.status is ComplianceStatus.PARTIALLY_SATISFIED


def test_vlan_assignment_extra_vlans_is_partial(model: NetworkModel) -> None:
    result = check(model, "vlan_assignment", "R1", "GigabitEthernet0/1", "10")
    assert result.status is ComplianceStatus.PARTIALLY_SATISFIED


def test_trunk_wrong_mode_is_unsatisfied(model: NetworkModel) -> None:
    result = check(model, "trunk", "R1", "FastEthernet0/1", "trunk")
    assert result.status is ComplianceStatus.UNSATISFIED
    assert result.actual == "access"


def test_ssh_expected_disabled_but_enabled_is_unsatisfied(model: NetworkModel) -> None:
    result = check(model, "ssh", "R1", None, "disabled")
    assert result.status is ComplianceStatus.UNSATISFIED


# ---------------------------------------------------------------------------
# unsupported: the snapshot has no such entity
# ---------------------------------------------------------------------------


def test_unknown_device_is_unsupported(model: NetworkModel) -> None:
    result = check(model, "hostname", "R99", None, "R99")
    assert result.status is ComplianceStatus.UNSUPPORTED
    assert "not present in this snapshot" in result.reason


def test_unknown_interface_is_unsupported(model: NetworkModel) -> None:
    result = check(model, "ipv4_address", "R1", "GigabitEthernet9/9", "10.0.0.1")
    assert result.status is ComplianceStatus.UNSUPPORTED


def test_unknown_kind_is_unsupported(model: NetworkModel) -> None:
    result = check(model, "spanning_tree_priority", "R1", None, "4096")
    assert result.status is ComplianceStatus.UNSUPPORTED
    assert result.evidence == ()


# ---------------------------------------------------------------------------
# indeterminate: the model cannot decide
# ---------------------------------------------------------------------------


def test_missing_interface_argument_is_indeterminate(model: NetworkModel) -> None:
    result = check(model, "ipv4_address", "R1", None, "10.0.0.1")
    assert result.status is ComplianceStatus.INDETERMINATE
    assert "does not name an interface" in result.reason


def test_ambiguous_device_is_indeterminate() -> None:
    model = NetworkModel(
        devices={
            "R1_1": DeviceInfo(id="R1_1", name="R1_1", hostname="edge"),
            "R1_2": DeviceInfo(id="R1_2", name="R1_2", hostname="edge"),
        }
    )
    result = check(model, "hostname", "edge", None, "edge")
    assert result.status is ComplianceStatus.INDETERMINATE
    assert "ambiguous" in result.reason


def test_interface_without_address_is_indeterminate() -> None:
    model = NetworkModel(
        devices={"R1": DeviceInfo(id="R1", name="R1", interfaces=["GigabitEthernet0/0"])},
        interfaces={
            "R1:GigabitEthernet0/0": InterfaceInfo(
                device="R1",
                name="GigabitEthernet0/0",
                canonical_name="GigabitEthernet0/0",
            )
        },
    )
    result = check(model, "ipv4_address", "R1", "GigabitEthernet0/0", "10.0.0.1")
    assert result.status is ComplianceStatus.INDETERMINATE
    assert "no IPv4 address is recorded" in result.reason


def test_unrepresented_route_table_is_indeterminate() -> None:
    model = NetworkModel(
        devices={"R1": DeviceInfo(id="R1", name="R1", configuration=["hostname R1"])}
    )
    result = check(model, "default_route", "R1", None, "10.0.0.254")
    assert result.status is ComplianceStatus.INDETERMINATE
    assert "route table" in result.reason


def test_undeterminable_trunk_state_is_indeterminate() -> None:
    model = NetworkModel(
        devices={"R1": DeviceInfo(id="R1", name="R1", configuration=[])},
        interfaces={
            "R1:GigabitEthernet0/1": InterfaceInfo(
                device="R1",
                name="GigabitEthernet0/1",
                canonical_name="GigabitEthernet0/1",
            )
        },
    )
    result = check(model, "trunk", "R1", "GigabitEthernet0/1", "trunk")
    assert result.status is ComplianceStatus.INDETERMINATE
    assert "not determinable" in result.reason


def test_ssh_without_configuration_is_indeterminate() -> None:
    model = NetworkModel(devices={"R1": DeviceInfo(id="R1", name="R1")})
    result = check(model, "ssh", "R1", None, "enabled")
    assert result.status is ComplianceStatus.INDETERMINATE
    assert "running-configuration" in result.reason


# ---------------------------------------------------------------------------
# invariants
# ---------------------------------------------------------------------------


SATISFIED_CASES = [
    ("ipv4_address", "R1", "GigabitEthernet0/0", "10.0.0.1 255.255.255.0"),
    ("ipv4_subnet", "R1", "GigabitEthernet0/0", "/24"),
    ("hostname", "R1", None, "R1"),
    ("default_route", "R1", None, "10.0.0.254"),
    ("vlan_assignment", "R1", "GigabitEthernet0/1", "10,20"),
    ("ssh", "R1", None, "enabled"),
    ("trunk", "R1", "GigabitEthernet0/1", "trunk"),
]


@pytest.mark.parametrize(("kind", "device", "interface", "expected"), SATISFIED_CASES)
def test_satisfied_always_carries_evidence(
    model: NetworkModel,
    kind: str,
    device: str | None,
    interface: str | None,
    expected: str,
) -> None:
    result = check(model, kind, device, interface, expected)
    assert result.status is ComplianceStatus.SATISFIED
    assert result.evidence, f"{kind} returned SATISFIED without evidence"
    for item in result.evidence:
        assert isinstance(item, Evidence)
        assert item.detail.strip()
        assert item.source.strip()


def test_every_satisfied_result_has_evidence_across_the_whole_matrix(model: NetworkModel) -> None:
    """No code path may produce SATISFIED with an empty evidence tuple."""
    probes = [
        ("ipv4_address", "R1", "GigabitEthernet0/0", "10.0.0.1"),
        ("ipv4_address", "R1", "Gi0/0", "10.0.0.1/24"),
        ("ipv4_subnet", "R1", "Gi0/0", "255.255.255.0"),
        ("hostname", "R1", None, "R1"),
        ("default_route", "R1", None, "10.0.0.254"),
        ("vlan_assignment", "R1", "GigabitEthernet0/1", "10,20"),
        ("vlan_assignment", "R1", "FastEthernet0/1", "10"),
        ("ssh", "R1", None, "enabled"),
        ("trunk", "R1", "GigabitEthernet0/1", "trunk"),
        ("trunk", "R1", "FastEthernet0/1", "access"),
        ("trunk", "SW1", "GigabitEthernet0/1", "access"),
    ]
    for kind, device, interface, expected in probes:
        result = check(model, kind, device, interface, expected)
        if result.status is ComplianceStatus.SATISFIED:
            assert result.evidence, f"SATISFIED without evidence: {kind} {device} {interface}"


def test_unsupported_is_not_unsatisfied(model: NetworkModel) -> None:
    unknown_device = check(model, "hostname", "GHOST", None, "GHOST")
    wrong_value = check(model, "hostname", "R1", None, "WRONG")

    assert unknown_device.status is ComplianceStatus.UNSUPPORTED
    assert wrong_value.status is ComplianceStatus.UNSATISFIED
    assert unknown_device.status is not wrong_value.status
    assert ComplianceStatus.UNSUPPORTED != ComplianceStatus.UNSATISFIED


def test_unsupported_results_never_claim_actual_values(model: NetworkModel) -> None:
    for kind, device, interface, expected in [
        ("hostname", "GHOST", None, "GHOST"),
        ("ipv4_address", "R1", "GigabitEthernet9/9", "10.0.0.1"),
        ("trunk", "GHOST", None, "trunk"),
    ]:
        result = check(model, kind, device, interface, expected)
        assert result.status is ComplianceStatus.UNSUPPORTED
        assert result.actual is None
        assert result.evidence == ()


def test_results_are_frozen(model: NetworkModel) -> None:
    result = check(model, "hostname", "R1", None, "R1")
    with pytest.raises(AttributeError):
        result.status = ComplianceStatus.UNSATISFIED  # type: ignore[misc]
