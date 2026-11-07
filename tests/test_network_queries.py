"""Network query engine tests: routing, ACLs, VLANs, topology, subnet maths."""

from __future__ import annotations

import pytest

from trident.models import (
    AclEntry,
    DeviceInfo,
    InterfaceInfo,
    LinkInfo,
    NetworkModel,
    RouteInfo,
    VlanInfo,
)
from trident.reasoning import network_queries as nq


@pytest.fixture
def model() -> NetworkModel:
    def iface(device, name, ip=None, mask=None, vlan=None, mode=None):
        return InterfaceInfo(
            device=device,
            name=name,
            canonical_name=name,
            ipv4_address=ip,
            subnet_mask=mask,
            prefix_length=24 if mask == "255.255.255.0" else None,
            vlan_assignments=[vlan] if vlan else [],
            access_mode=mode,
        )

    model = NetworkModel(
        devices={
            "R1": DeviceInfo(id="R1", name="R1", hostname="R1", ios_version="15.1",
                             interfaces=["GigabitEthernet0/0", "GigabitEthernet0/1"]),
            "R2": DeviceInfo(id="R2", name="R2", hostname="R2",
                             interfaces=["GigabitEthernet0/0"]),
            "SW1": DeviceInfo(id="SW1", name="SW1", hostname="SW1",
                              interfaces=["FastEthernet0/1", "FastEthernet0/2"]),
            "PC-A": DeviceInfo(id="PC-A", name="PC-A", hostname="PC-A", interfaces=["FastEthernet0"]),
        },
        interfaces={
            "R1:GigabitEthernet0/0": iface("R1", "GigabitEthernet0/0", "192.168.1.1", "255.255.255.0"),
            "R1:GigabitEthernet0/1": iface("R1", "GigabitEthernet0/1", "10.0.0.1", "255.255.255.252"),
            "R2:GigabitEthernet0/0": iface("R2", "GigabitEthernet0/0", "10.0.0.2", "255.255.255.252"),
            "SW1:FastEthernet0/1": iface("SW1", "FastEthernet0/1", vlan="10", mode="access"),
            "SW1:FastEthernet0/2": iface("SW1", "FastEthernet0/2", vlan="20", mode="access"),
        },
        links=[
            LinkInfo(device_a="R1", interface_a="GigabitEthernet0/0",
                     device_b="SW1", interface_b="FastEthernet0/1"),
            LinkInfo(device_a="R1", interface_a="GigabitEthernet0/1",
                     device_b="R2", interface_b="GigabitEthernet0/0"),
            LinkInfo(device_a="SW1", interface_a="FastEthernet0/2",
                     device_b="PC-A", interface_b="FastEthernet0"),
        ],
        routes=[
            RouteInfo(destination="0.0.0.0", next_hop="192.168.1.254",
                      route_type="static", protocol="static",
                      raw_config="ip route 0.0.0.0 0.0.0.0 192.168.1.254"),
        ],
        vlans=[
            VlanInfo(vlan_id=10, name="USERS", member_ports=["SW1:FastEthernet0/1"]),
            VlanInfo(vlan_id=20, name="VOICE", member_ports=["SW1:FastEthernet0/2"]),
        ],
        acls=[
            AclEntry(acl_id="100", acl_type="extended", action="deny", protocol="tcp",
                     source="any", destination="any", port_conditions=["eq", "23"],
                     raw="access-list 100 deny tcp any any eq 23"),
        ],
    )
    model.settings.default_gateways = {"PC-A": "192.168.1.1"}
    model.settings.dns_servers = {"PC-A": ["8.8.8.8"]}
    model.settings.software_versions = {"R1": "15.1"}
    return model


def test_find_device_by_name(model):
    assert nq.find_device(model, "R1").name == "R1"
    assert nq.find_device(model, "r1").name == "R1"
    assert nq.find_device(model, "nope") is None


def test_find_device_by_hostname(model):
    assert nq.find_device_by_hostname(model, "R2").name == "R2"


def test_get_interface_by_alias(model):
    assert nq.get_interface(model, "R1", "Gi0/0").ipv4_address == "192.168.1.1"
    assert nq.get_interface(model, "R1", "GigabitEthernet0/1").ipv4_address == "10.0.0.1"


def test_device_ip_requires_unambiguous(model):
    # R1 has two L3 addresses: must not pick one arbitrarily
    assert nq.device_ip(model, "R1") is None
    # explicit interface works
    result = nq.device_ip(model, "R1", "Gi0/0")
    assert result.value == "192.168.1.1"


def test_device_ip_single_address(model):
    result = nq.device_ip(model, "R2")
    assert result.value == "10.0.0.2"


def test_default_gateway(model):
    assert nq.get_default_gateway(model, "PC-A").value == "192.168.1.1"
    assert nq.get_default_gateway(model, "R1") is None


def test_dns_servers(model):
    assert nq.get_dns_servers(model, "PC-A") == ["8.8.8.8"]
    assert nq.get_dns_servers(model, "R1") == []


def test_vlan_assignment(model):
    result = nq.get_vlan_assignment(model, "SW1", "Fa0/1")
    assert result.value == "10"


def test_vlan_membership(model):
    assert nq.find_vlan(model, 10) == ["SW1:FastEthernet0/1"]
    assert nq.find_vlan(model, 20) == ["SW1:FastEthernet0/2"]
    assert nq.find_vlan(model, 999) == []


def test_connected_devices(model):
    assert nq.directly_connected(model, "R1") == ["R2", "SW1"]
    assert nq.directly_connected(model, "PC-A") == ["SW1"]


def test_topology_path(model):
    assert nq.topology_path(model, "R2", "PC-A") == ["R2", "R1", "SW1", "PC-A"]


def test_topology_path_unknown_device(model):
    assert nq.topology_path(model, "R1", "Ghost") is None


def test_interface_for_link(model):
    result = nq.interface_for_link(model, "R1", "R2")
    assert result.value == "GigabitEthernet0/1"


def test_route_lookup(model):
    matches = nq.static_route_lookup(model, "0.0.0.0")
    assert len(matches) == 1
    assert "192.168.1.254" in matches[0]


def test_acl_lookup(model):
    entries = nq.acl_entries(model, "100")
    assert len(entries) == 1
    assert "deny" in entries[0]


def test_switchport_mode(model):
    assert nq.switchport_mode(model, "SW1", "Fa0/1").value == "access"


def test_ios_version(model):
    assert nq.get_ios_version(model, "R1").value == "15.1"
    assert nq.get_ios_version(model, "PC-A") is None


def test_subnet_functions(model):
    assert nq.subnet_network_address("192.168.1.10", "255.255.255.0").value == "192.168.1.0"
    assert nq.subnet_broadcast_address("192.168.1.10", "255.255.255.0").value == "192.168.1.255"
    assert nq.ips_same_subnet("192.168.1.10", "192.168.1.20", "255.255.255.0").value == "yes"
    assert nq.ips_same_subnet("192.168.1.10", "10.0.0.1", "255.255.255.0").value == "no"


def test_subnet_prefix_input():
    assert nq.subnet_network_address("10.1.2.3", 16).value == "10.1.0.0"
    assert nq.subnet_network_address("10.1.2.3", "/16").value == "10.1.0.0"


def test_invalid_mask_returns_none(model):
    assert nq.subnet_network_address("192.168.1.10", "255.0.255.0") is None


def test_invalid_ip_returns_none(model):
    assert nq.subnet_network_address("999.1.1.1", "255.255.255.0") is None


def test_summary(model):
    summary = nq.network_device_summary(model)
    assert summary["devices"] == 4
    assert summary["links"] == 3
    assert summary["vlans"] == 2
