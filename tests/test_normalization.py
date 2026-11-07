"""Normalisation, IOS config parsing and value canonicalisation tests."""

from __future__ import annotations

import pytest

from trident.normalization.configs import collect_switchport_vlans, parse_running_config
from trident.normalization.values import (
    broadcast_address,
    canonical_interface_name,
    is_valid_mask,
    macs_equal,
    mask_to_prefix,
    network_address,
    normalize_mac,
    same_subnet,
)

# --- value normalisation ---------------------------------------------------

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("0040.0B1E.B601", "00:40:0b:1e:b6:01"),
        ("00:40:0B:1E:B6:01", "00:40:0b:1e:b6:01"),
        ("00-40-0b-1e-b6-01", "00:40:0b:1e:b6:01"),
        ("00400B1EB601", "00:40:0b:1e:b6:01"),
        ("not-a-mac", None),
        ("0040.0B1E", None),
        ("", None),
    ],
)
def test_normalize_mac(raw, expected):
    assert normalize_mac(raw) == expected


def test_macs_equal_variants():
    assert macs_equal("0040.0B1E.B601", "00:40:0b:1e:b6:01")
    assert not macs_equal("0040.0B1E.B601", "0040.0B1E.B602")
    assert not macs_equal(None, None)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Gi0/1", "GigabitEthernet0/1"),
        ("gi0/1", "GigabitEthernet0/1"),
        ("GigabitEthernet0/1", "GigabitEthernet0/1"),
        ("GigabitEthernet 0/1", "GigabitEthernet0/1"),
        ("Fa0/24", "FastEthernet0/24"),
        ("vlan1", "Vlan1"),
        ("Vlan1", "Vlan1"),
        ("Se0/0/0", "Serial0/0/0"),
        ("Lo0", "Loopback0"),
        ("Po1", "Port-channel1"),
        ("TenGigabitEthernet1/1", "TenGigabitEthernet1/1"),
    ],
)
def test_canonical_interface_name(raw, expected):
    assert canonical_interface_name(raw) == expected


@pytest.mark.parametrize(
    "mask,expected_prefix,valid",
    [
        ("255.255.255.0", 24, True),
        ("255.255.0.0", 16, True),
        ("255.255.255.252", 30, True),
        ("255.0.255.0", None, False),
        ("255.255.255.1", None, False),
        ("not-a-mask", None, False),
    ],
)
def test_mask_validation(mask, expected_prefix, valid):
    assert is_valid_mask(mask) is valid
    assert mask_to_prefix(mask) == expected_prefix


def test_subnet_arithmetic():
    assert network_address("192.168.1.10", "255.255.255.0") == "192.168.1.0"
    assert broadcast_address("192.168.1.10", "255.255.255.0") == "192.168.1.255"
    assert network_address("10.1.2.3", 16) == "10.1.0.0"
    assert broadcast_address("10.1.2.3", 16) == "10.1.255.255"


def test_same_subnet():
    assert same_subnet("192.168.1.10", "192.168.1.20", "255.255.255.0") is True
    assert same_subnet("192.168.1.10", "192.168.2.20", "255.255.255.0") is False
    assert same_subnet("bad", "192.168.2.20", "255.255.255.0") is None


# --- IOS config parsing ----------------------------------------------------

SAMPLE_CONFIG = """!
version 15.1
hostname R1
!
ip default-gateway 192.168.1.254
ip name-server 8.8.8.8
!
interface GigabitEthernet0/0
 description Link to SW1
 ip address 192.168.1.1 255.255.255.0
 no shutdown
 speed 1000
 duplex full
!
interface GigabitEthernet0/1
 ip address 10.0.0.1 255.255.255.252
 shutdown
!
interface FastEthernet0/1
 switchport mode access
 switchport access vlan 20
 description Access port
!
interface GigabitEthernet0/2
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30-32
 switchport trunk native vlan 99
!
vlan 20
 name USERS
!
vlan 30
 name VOICE
!
ip route 0.0.0.0 0.0.0.0 192.168.1.254
ip route 10.99.0.0 255.255.0.0 GigabitEthernet0/0
!
access-list 10 permit 192.168.1.0 0.0.0.255
access-list 100 deny tcp any any eq 23
access-list 100 permit ip any any
!
ip access-list extended FILTER
 permit tcp 10.0.0.0 0.0.0.255 any eq 443
 deny ip any any
!
"""


@pytest.fixture(scope="module")
def parsed():
    return parse_running_config(SAMPLE_CONFIG)


def test_parse_hostname_and_version(parsed):
    assert parsed.hostname == "R1"
    assert parsed.ios_version == "15.1"


def test_parse_interface_ip_and_mask(parsed):
    gi0 = parsed.interface("Gi0/0")
    assert gi0 is not None
    assert gi0.ipv4_address == "192.168.1.1"
    assert gi0.subnet_mask == "255.255.255.0"
    assert gi0.prefix_length == 24
    assert gi0.description == "Link to SW1"
    assert gi0.admin_state == "up"
    assert gi0.speed == "1000"
    assert gi0.duplex == "full"


def test_parse_shutdown_interface(parsed):
    gi1 = parsed.interface("GigabitEthernet0/1")
    assert gi1 is not None
    assert gi1.admin_state == "administratively down"
    assert gi1.prefix_length == 30


def test_parse_access_port(parsed):
    fa = parsed.interface("FastEthernet0/1")
    assert fa is not None
    assert fa.switchport_mode == "access"
    assert fa.access_vlan == "20"


def test_parse_trunk_and_native_vlan(parsed):
    gi2 = parsed.interface("GigabitEthernet0/2")
    assert gi2 is not None
    assert gi2.switchport_mode == "trunk"
    assert gi2.trunk_allowed == ["10", "20", "30", "31", "32"]
    assert gi2.native_vlan == "99"


def test_parse_vlans(parsed):
    names = {v.vlan_id: v.name for v in parsed.vlans}
    assert names[20] == "USERS"
    assert names[30] == "VOICE"


def test_parse_static_routes(parsed):
    destinations = {r.destination for r in parsed.routes}
    assert "0.0.0.0" in destinations
    assert "10.99.0.0" in destinations
    default = [r for r in parsed.routes if r.destination == "0.0.0.0"][0]
    assert default.next_hop == "192.168.1.254"
    assert default.route_type == "static"


def test_parse_route_with_interface_next_hop(parsed):
    route = [r for r in parsed.routes if r.destination == "10.99.0.0"][0]
    assert route.outgoing_interface == "GigabitEthernet0/0"
    assert route.next_hop is None


def test_parse_numbered_acls(parsed):
    acl10 = [a for a in parsed.acls if a.acl_id == "10"]
    assert len(acl10) == 1
    assert acl10[0].action == "permit"
    assert acl10[0].acl_type == "standard"

    acl100 = [a for a in parsed.acls if a.acl_id == "100"]
    assert len(acl100) == 2
    assert acl100[0].action == "deny"
    assert acl100[0].protocol == "tcp"
    assert "23" in acl100[0].port_conditions


def test_parse_named_acl(parsed):
    named = [a for a in parsed.acls if a.acl_id == "FILTER"]
    assert len(named) == 2
    assert named[0].action == "permit"
    assert named[0].acl_type == "extended"
    assert named[1].action == "deny"


def test_parse_default_gateway_and_dns(parsed):
    assert parsed.default_gateway == "192.168.1.254"
    assert "8.8.8.8" in parsed.dns_servers


def test_switchport_vlan_membership(parsed):
    members = collect_switchport_vlans(parsed)
    assert "FastEthernet0/1" in members["20"]
    # trunk allows 30 but is not an *access* member; collect_switchport_vlans
    # includes trunk allowances by design, so Gi0/2 appears for 30
    assert "GigabitEthernet0/2" in members["30"]


def test_config_accepts_string_or_list():
    as_string = parse_running_config("interface Gi0/0\n ip address 1.2.3.4 255.255.255.0\n")
    as_list = parse_running_config(["interface Gi0/0", " ip address 1.2.3.4 255.255.255.0"])
    assert as_string.interface("Gi0/0").ipv4_address == as_list.interface("Gi0/0").ipv4_address


def test_empty_config_parses_to_empty_model():
    cfg = parse_running_config("")
    assert cfg.hostname is None
    assert cfg.interfaces == {}
    assert cfg.routes == []
