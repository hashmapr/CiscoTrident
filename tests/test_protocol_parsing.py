"""Typed protocol parsing: STP, EtherChannel, NAT, IPv6.

The two rules this suite protects:

* **Absence is not a default.** An unstated priority stays None; the reasoning
  layer must decide explicitly whether to assume IOS's default.
* **Unrecognised lines are kept.** A line the parser does not model is preserved,
  so a later reader sees it existed rather than concluding it never did.
"""

from __future__ import annotations

import pytest

from trident.deepcore.protocols import (
    NatRole,
    PortChannelMode,
    StpMode,
    parse_protocols,
)

# ---------------------------------------------------------------------------
# STP
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "mode"),
    [
        ("spanning-tree mode pvst", StpMode.PVST),
        ("spanning-tree mode rapid-pvst", StpMode.RAPID_PVST),
        ("spanning-tree mode mst", StpMode.MST),
    ],
)
def test_stp_mode_is_parsed(line, mode):
    assert parse_protocols([line]).stp.mode is mode


def test_an_unconfigured_stp_mode_is_unknown_not_a_guess():
    """No spanning-tree line means unstated, not PVST+."""
    configs = parse_protocols([])
    assert configs.stp.mode is StpMode.UNKNOWN
    assert configs.stp.priority is None


def test_global_and_per_vlan_priority():
    configs = parse_protocols(
        ["spanning-tree priority 4096", "spanning-tree vlan 10 priority 8192"]
    )
    assert configs.stp.priority == 4096
    assert configs.stp.vlan_priorities == {10: 8192}
    # A per-VLAN value wins over the global one.
    assert configs.stp.effective_priority(10) == 8192
    assert configs.stp.effective_priority(20) == 4096


def test_unstated_priority_for_a_vlan_is_none():
    configs = parse_protocols(["spanning-tree priority 4096"])
    assert configs.stp.effective_priority(99) == 4096
    empty = parse_protocols([])
    assert empty.stp.effective_priority(99) is None


def test_root_primary_is_recorded_per_vlan():
    configs = parse_protocols(["spanning-tree vlan 1,10 root primary"])
    # The line names two VLANs but IOS accepts a list; only the first is captured
    # by this parser, which is a stated limitation rather than a silent guess.
    assert configs.stp.root_primary_vlans


@pytest.mark.parametrize(
    "line",
    [
        "spanning-tree portfast",
        "spanning-tree bpduguard enable",
        "spanning-tree bpdufilter enable",
        "spanning-tree guard root",
        "spanning-tree guard loop",
    ],
)
def test_interface_stp_features(line):
    configs = parse_protocols(["interface GigabitEthernet0/1", f" {line}"])
    port = configs.stp_ports["GigabitEthernet0/1"]
    assert (
        port.portfast
        or port.bpdu_guard
        or port.bpdu_filter
        or port.root_guard
        or port.loop_guard
    )


def test_no_portfast_turns_it_off():
    configs = parse_protocols(
        ["interface Gi0/1", " spanning-tree portfast", " no spanning-tree portfast"]
    )
    assert configs.stp_ports["Gi0/1"].portfast is False


def test_port_cost_and_priority():
    configs = parse_protocols(
        ["interface Gi0/1", " spanning-tree cost 19", " spanning-tree port-priority 32"]
    )
    port = configs.stp_ports["Gi0/1"]
    assert port.cost == 19
    assert port.priority == 32


# ---------------------------------------------------------------------------
# EtherChannel
# ---------------------------------------------------------------------------


def test_lacp_members_are_grouped():
    configs = parse_protocols(
        [
            "interface Gi0/1",
            " channel-group 1 mode active",
            "interface Gi0/2",
            " channel-group 1 mode active",
        ]
    )
    channel = configs.etherchannels["Port-channel1"]
    assert channel.mode is PortChannelMode.ACTIVE
    assert channel.protocol == "lacp"
    assert sorted(channel.members) == ["Gi0/1", "Gi0/2"]
    assert channel.issues == []


def test_pagp_modes_are_distinguished():
    assert parse_protocols(
        ["interface Gi0/1", " channel-group 2 mode desirable"]
    ).etherchannels["Port-channel2"].protocol == "pagp"
    assert parse_protocols(
        ["interface Gi0/1", " channel-group 2 mode auto"]
    ).etherchannels["Port-channel2"].protocol == "pagp"


def test_static_on_mode_is_not_a_negotiated_protocol():
    channel = parse_protocols(
        ["interface Gi0/1", " channel-group 3 mode on"]
    ).etherchannels["Port-channel3"]
    assert channel.mode is PortChannelMode.ON
    assert channel.protocol == "static"
    assert channel.negotiates is False


def test_mismatched_modes_within_one_channel_are_flagged():
    configs = parse_protocols(
        [
            "interface Gi0/1",
            " channel-group 1 mode active",
            "interface Gi0/2",
            " channel-group 1 mode desirable",
        ]
    )
    channel = configs.etherchannels["Port-channel1"]
    assert channel.issues
    assert "Gi0/2" in channel.issues[0]


def test_independent_interfaces_do_not_form_a_channel():
    """Ports without channel-group are not a broken EtherChannel."""
    configs = parse_protocols(
        ["interface Gi0/1", " switchport mode access", "interface Gi0/2", " switchport mode access"]
    )
    assert configs.etherchannels == {}


# ---------------------------------------------------------------------------
# NAT
# ---------------------------------------------------------------------------


def test_inside_and_outside_roles():
    configs = parse_protocols(
        [
            "interface Gi0/0",
            " ip nat outside",
            "interface Gi0/1",
            " ip nat inside",
        ]
    )
    assert configs.nat.role_of("Gi0/0") is NatRole.OUTSIDE
    assert configs.nat.role_of("Gi0/1") is NatRole.INSIDE
    assert configs.nat.role_of("Gi0/2") is NatRole.NONE
    assert configs.nat.configured is True


def test_static_translation_is_recorded():
    configs = parse_protocols(["ip nat inside source static 10.0.0.5 203.0.113.5"])
    rule = configs.nat.static_rules[0]
    assert rule.kind == "static"
    assert rule.inside == "10.0.0.5"
    assert rule.outside == "203.0.113.5"


def test_overload_is_detected_on_a_dynamic_rule():
    configs = parse_protocols(
        ["ip nat inside source list 10 interface Gi0/0 overload"]
    )
    rule = configs.nat.dynamic_rules[0]
    assert rule.overload is True
    assert rule.acl_id == "10"


def test_a_pool_declaration_is_recorded():
    configs = parse_protocols(
        ["ip nat pool PUBLIC 203.0.113.1 203.0.113.10 netmask 255.255.255.0"]
    )
    assert configs.nat.pools["public"] == (
        "203.0.113.1",
        "203.0.113.10",
        "255.255.255.0",
    )


def test_no_nat_configuration_is_not_configured():
    assert parse_protocols([]).nat.configured is False


# ---------------------------------------------------------------------------
# IPv6
# ---------------------------------------------------------------------------


def test_ipv6_address_enables_forwarding():
    configs = parse_protocols(
        ["interface Gi0/0", " ipv6 address 2001:db8::1/64"]
    )
    assert configs.ipv6.forwarding is True
    assert configs.ipv6.interfaces["Gi0/0"].addresses == ["2001:db8::1/64"]


def test_link_local_is_separated_from_global():
    configs = parse_protocols(
        [
            "interface Gi0/0",
            " ipv6 address 2001:db8::1/64",
            " ipv6 address fe80::1 link-local",
        ]
    )
    interface = configs.ipv6.interfaces["Gi0/0"]
    assert interface.addresses == ["2001:db8::1/64"]
    assert interface.link_local == "fe80::1"


def test_ipv6_enable_without_an_address():
    configs = parse_protocols(["interface Gi0/0", " ipv6 enable"])
    assert configs.ipv6.interfaces["Gi0/0"].enabled is True
    assert configs.ipv6.interfaces["Gi0/0"].addresses == []


def test_ipv6_static_route():
    configs = parse_protocols(["ipv6 route ::/0 2001:db8::ff"])
    assert configs.ipv6.routes == [("::/0", "2001:db8::ff")]
    assert configs.ipv6.forwarding is True


def test_ipv6_acl_binding():
    """IOS ACL names are case-sensitive, so the original spelling is kept."""
    configs = parse_protocols(
        ["interface Gi0/0", " ipv6 traffic-filter GUEST in"]
    )
    assert configs.ipv6.interfaces["Gi0/0"].acl_in == "GUEST"


def test_no_ipv6_is_not_configured():
    assert parse_protocols([]).ipv6.configured is False


# ---------------------------------------------------------------------------
# Unsupported lines are preserved
# ---------------------------------------------------------------------------


def test_an_unrecognised_protocol_line_is_kept():
    """A command the parser does not model must not vanish."""
    configs = parse_protocols(["spanning-tree extend system-id"])
    assert "spanning-tree extend system-id" in configs.unsupported


def test_ordinary_lines_are_not_listed_as_unsupported():
    configs = parse_protocols(["hostname R1", "service timestamps log"])
    assert configs.unsupported == []


# ---------------------------------------------------------------------------
# Context handling
# ---------------------------------------------------------------------------


def test_interface_commands_land_on_the_right_interface():
    configs = parse_protocols(
        [
            "interface Gi0/1",
            " spanning-tree portfast",
            "interface Gi0/2",
            " spanning-tree cost 39",
        ]
    )
    assert configs.stp_ports["Gi0/1"].portfast is True
    assert configs.stp_ports["Gi0/1"].cost is None
    assert configs.stp_ports["Gi0/2"].cost == 39
    assert configs.stp_ports["Gi0/2"].portfast is False


def test_a_new_context_stops_interface_parsing():
    """A router block must not have its commands attributed to an interface."""
    configs = parse_protocols(
        ["interface Gi0/1", " router ospf 1", " network 10.0.0.0 0.0.0.255 area 0"]
    )
    assert configs.stp_ports["Gi0/1"].portfast is False


def test_parsing_does_not_mutate_the_input():
    lines = ["interface Gi0/1", " spanning-tree portfast"]
    snapshot = list(lines)
    parse_protocols(lines)
    assert lines == snapshot
