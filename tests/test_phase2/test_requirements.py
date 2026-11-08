"""Phase 2 — RequirementEngine tests.

Every case asserts the *exact* structured outcome. The negative cases matter as
much as the positive ones: the engine must never invent a device name and must
never promote an unsupported or ambiguous line to ``PARSED``.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from trident.requirements import (
    Requirement,
    RequirementKind,
    RequirementStatus,
    parse_requirements,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def only(text: str) -> Requirement:
    reqs = parse_requirements(text)
    assert len(reqs) == 1, f"expected exactly one requirement, got {reqs}"
    return reqs[0]


# ---------------------------------------------------------------------------
# 1. IPv4 address
# ---------------------------------------------------------------------------

def test_ipv4_address_on_named_interface():
    req = only("Configure 192.168.10.1/24 on R1 GigabitEthernet0/0")
    assert req.kind is RequirementKind.IPV4_ADDRESS
    assert req.device == "R1"
    assert req.interface == "GigabitEthernet0/0"
    assert req.expected == "192.168.10.1/24"
    assert req.status is RequirementStatus.PARSED
    assert req.confidence == "explicit"
    assert req.source_line == 1
    assert req.source_text == "Configure 192.168.10.1/24 on R1 GigabitEthernet0/0"


def test_ipv4_address_abbreviated_interface_is_canonicalised():
    req = only("Configure 10.0.0.1/30 on R2 Gi0/1")
    assert req.kind is RequirementKind.IPV4_ADDRESS
    assert req.interface == "GigabitEthernet0/1"
    assert req.device == "R2"


def test_ipv4_dotted_mask_form():
    req = only("Configure 192.168.1.1 255.255.255.0 on R1 Fa0/0")
    assert req.kind is RequirementKind.IPV4_ADDRESS
    assert req.expected == "192.168.1.1/24"
    assert req.interface == "FastEthernet0/0"


def test_ipv4_network_address_is_subnet_kind():
    req = only("Configure 192.168.10.0/24 on R1 Gi0/0")
    assert req.kind is RequirementKind.IPV4_SUBNET


# ---------------------------------------------------------------------------
# 2. Hostname -> SECURITY
# ---------------------------------------------------------------------------

def test_hostname_maps_to_security():
    req = only("Set the hostname of SW1 to CoreSwitch")
    assert req.kind is RequirementKind.SECURITY
    assert req.device == "SW1"
    assert req.interface is None
    assert req.expected == "hostname CoreSwitch"
    assert req.status is RequirementStatus.PARSED


def test_hostname_without_device_is_ambiguous_not_guessed():
    req = only("Set the hostname to CoreSwitch")
    assert req.kind is RequirementKind.SECURITY
    assert req.device is None
    assert req.status is RequirementStatus.AMBIGUOUS
    assert any("device not named" in n for n in req.notes)


# ---------------------------------------------------------------------------
# 3. VLAN assignment
# ---------------------------------------------------------------------------

def test_vlan_assignment_to_port():
    req = only("Assign VLAN 20 to the Fa0/5 port on SW2")
    assert req.kind is RequirementKind.VLAN_ASSIGNMENT
    assert req.device == "SW2"
    assert req.interface == "FastEthernet0/5"
    assert req.expected == "vlan 20"
    assert req.status is RequirementStatus.PARSED


def test_vlan_assignment_group_scope_has_no_device():
    req = only("Place all PCs on VLAN 10")
    assert req.kind is RequirementKind.VLAN_ASSIGNMENT
    assert req.device is None
    assert req.interface is None
    assert req.expected == "vlan 10"
    assert req.status is RequirementStatus.PARSED
    assert req.confidence == "inferred"
    assert any("group scope" in n for n in req.notes)


def test_vlan_out_of_range_is_ambiguous():
    req = only("Assign VLAN 9999 to the Fa0/5 port on SW2")
    assert req.kind is RequirementKind.VLAN_ASSIGNMENT
    assert req.status is RequirementStatus.AMBIGUOUS
    assert any("outside the valid 1-4094 range" in n for n in req.notes)


# ---------------------------------------------------------------------------
# 4. Default route
# ---------------------------------------------------------------------------

def test_default_route():
    req = only("Configure a default route on R1 pointing to 10.1.1.2")
    assert req.kind is RequirementKind.DEFAULT_ROUTE
    assert req.device == "R1"
    assert req.expected == "0.0.0.0/0 via 10.1.1.2"
    assert req.status is RequirementStatus.PARSED


def test_default_route_without_next_hop_is_ambiguous():
    req = only("Configure a default route on R1")
    assert req.kind is RequirementKind.DEFAULT_ROUTE
    assert req.device == "R1"
    assert req.status is RequirementStatus.AMBIGUOUS
    assert any("next hop not stated" in n for n in req.notes)


def test_static_route():
    req = only("Configure a static route on R1 to 172.16.0.0/16 via 10.1.1.2")
    assert req.kind is RequirementKind.STATIC_ROUTE
    assert req.device == "R1"
    assert req.expected == "172.16.0.0/16 via 10.1.1.2"


def test_ip_route_config_syntax():
    req = only("On R1 configure ip route 0.0.0.0 0.0.0.0 10.1.1.2")
    assert req.kind is RequirementKind.DEFAULT_ROUTE
    assert req.device == "R1"
    assert req.expected == "0.0.0.0/0 via 10.1.1.2"


# ---------------------------------------------------------------------------
# 5. SSH
# ---------------------------------------------------------------------------

def test_enable_ssh():
    req = only("Enable SSH on R1")
    assert req.kind is RequirementKind.SSH
    assert req.device == "R1"
    assert req.expected == "ssh enabled"
    assert req.status is RequirementStatus.PARSED


def test_enable_ssh_without_device_is_ambiguous():
    req = only("Enable SSH")
    assert req.kind is RequirementKind.SSH
    assert req.device is None
    assert req.status is RequirementStatus.AMBIGUOUS


# ---------------------------------------------------------------------------
# 6. Trunk
# ---------------------------------------------------------------------------

def test_trunk_between_two_switches():
    req = only("Create a trunk between SW1 Gi0/1 and SW2 Gi0/1")
    assert req.kind is RequirementKind.TRUNK
    assert req.device == "SW1"
    assert req.interface == "GigabitEthernet0/1"
    assert req.expected == (
        "trunk SW1 GigabitEthernet0/1 <-> SW2 GigabitEthernet0/1"
    )
    assert any("SW2 GigabitEthernet0/1" in n for n in req.notes)
    assert req.status is RequirementStatus.PARSED


def test_trunk_without_endpoints_is_ambiguous():
    req = only("Configure a trunk between SW1 and SW2")
    assert req.kind is RequirementKind.TRUNK
    assert req.status is RequirementStatus.AMBIGUOUS
    assert any("both trunk endpoints" in n for n in req.notes)


# ---------------------------------------------------------------------------
# Other supported kinds
# ---------------------------------------------------------------------------

def test_ipv6_address():
    req = only("Configure 2001:db8::1/64 on R1 GigabitEthernet0/0")
    assert req.kind is RequirementKind.IPV6_ADDRESS
    assert req.device == "R1"
    assert req.interface == "GigabitEthernet0/0"
    assert req.expected == "2001:db8::1/64"


def test_interface_enable():
    req = only("Enable interface Gi0/2 on SW1")
    assert req.kind is RequirementKind.INTERFACE_ENABLE
    assert req.device == "SW1"
    assert req.interface == "GigabitEthernet0/2"
    assert req.expected == "no shutdown"


def test_ospf():
    req = only("Configure OSPF on R1")
    assert req.kind is RequirementKind.OSPF
    assert req.device == "R1"


def test_dhcp():
    req = only("Configure DHCP pool LAN on R1")
    assert req.kind is RequirementKind.DHCP
    assert req.device == "R1"


def test_dns():
    req = only("Configure DNS server 8.8.8.8 on R1")
    assert req.kind is RequirementKind.DNS
    assert req.device == "R1"
    assert req.expected == "dns server 8.8.8.8"


def test_nat():
    req = only("Configure NAT on R1")
    assert req.kind is RequirementKind.NAT
    assert req.device == "R1"


def test_acl():
    req = only("Configure ACL 101 on R1")
    assert req.kind is RequirementKind.ACL
    assert req.device == "R1"
    assert req.expected == "acl 101"


def test_wireless():
    req = only("Configure SSID CorpWifi on WLC1")
    assert req.kind is RequirementKind.WIRELESS
    assert req.device == "WLC1"


def test_connectivity():
    req = only("Verify that PC1 can ping 192.168.10.1")
    assert req.kind is RequirementKind.CONNECTIVITY
    assert req.device == "PC1"


# ---------------------------------------------------------------------------
# Status discipline
# ---------------------------------------------------------------------------

def test_unsupported_line_is_not_parsed():
    req = only("Review the lab topology diagram before starting")
    assert req.status is RequirementStatus.UNSUPPORTED
    assert req.kind is RequirementKind.UNKNOWN
    assert req.device is None
    assert req.expected == ""
    assert any("no supported requirement grammar" in n for n in req.notes)


def test_unsupported_address_without_device_stays_ambiguous():
    """A real CIDR with no device named is AMBIGUOUS — never an invented host."""
    req = only("Configure 192.168.10.1/24")
    assert req.status is RequirementStatus.AMBIGUOUS
    assert req.device is None
    assert any("device not named" in n for n in req.notes)


@pytest.mark.parametrize(
    "text",
    [
        "Save the configuration before you close the window",
        "Ask the instructor to check your progress",
        "Open Packet Tracer",
        "Remember to label the diagram",
    ],
)
def test_arbitrary_prose_never_yields_a_parsed_requirement(text: str):
    reqs = parse_requirements(text)
    assert len(reqs) == 1
    assert reqs[0].status is RequirementStatus.UNSUPPORTED


def test_empty_input_returns_empty_list():
    assert parse_requirements("") == []


def test_whitespace_only_input_returns_empty_list():
    assert parse_requirements("\n\n   \n\t\n") == []


def test_blank_lines_are_skipped_but_line_numbers_are_preserved():
    text = "\n\nEnable SSH on R1\n"
    reqs = parse_requirements(text)
    assert len(reqs) == 1
    assert reqs[0].source_line == 3


# ---------------------------------------------------------------------------
# No fabrication
# ---------------------------------------------------------------------------

def test_no_device_input_never_fabricates_a_device():
    """Every device-less instruction must keep ``device is None``."""
    lines = [
        "Configure 192.168.10.1/24",
        "Set the hostname to CoreSwitch",
        "Configure a default route pointing to 10.1.1.2",
        "Enable SSH",
        "Configure a trunk between the two switches",
        "Place all PCs on VLAN 10",
        "Verify that all PCs can ping 192.168.10.1",
    ]
    reqs = parse_requirements("\n".join(lines))
    assert len(reqs) == len(lines)
    for req in reqs:
        assert req.device is None, f"{req.source_text!r} fabricated device {req.device!r}"
        assert req.status in {RequirementStatus.AMBIGUOUS, RequirementStatus.PARSED}


def test_only_named_devices_are_reported():
    lines = """
    Configure 192.168.10.1/24 on R1 Gi0/0
    Assign VLAN 20 to the Fa0/5 port on SW2
    Create a trunk between SW1 Gi0/1 and SW2 Gi0/1
    """
    reqs = parse_requirements(lines)
    named = {r.device for r in reqs if r.device is not None}
    assert named <= {"R1", "SW1", "SW2"}


def test_interface_tokens_are_never_treated_as_devices():
    req = only("Configure 192.168.10.1/24 on Gi0/0")
    assert req.status is RequirementStatus.AMBIGUOUS
    assert req.device is None
    assert req.interface == "GigabitEthernet0/0"


# ---------------------------------------------------------------------------
# Structural contract
# ---------------------------------------------------------------------------

def test_ids_are_sequential_and_stable():
    text = "Enable SSH on R1\nEnable SSH on R2\nEnable SSH on R3"
    reqs = parse_requirements(text)
    assert [r.id for r in reqs] == ["REQ-0001", "REQ-0002", "REQ-0003"]


def test_output_is_deterministic():
    text = (
        "Configure 192.168.10.1/24 on R1 GigabitEthernet0/0\n"
        "Assign VLAN 20 to the Fa0/5 port on SW2\n"
        "Something completely unrelated\n"
    )
    assert parse_requirements(text) == parse_requirements(text)


def test_bulleted_and_numbered_lines_are_unwrapped():
    text = "1. Enable SSH on R1\n- Assign VLAN 20 to the Fa0/5 port on SW2\n"
    reqs = parse_requirements(text)
    assert [r.kind for r in reqs] == [RequirementKind.SSH, RequirementKind.VLAN_ASSIGNMENT]


def test_requirement_is_frozen():
    req = only("Enable SSH on R1")
    with pytest.raises(FrozenInstanceError):
        req.device = "R2"  # type: ignore[misc]
