"""Holdout fault fixtures: realistic cases beyond the synthetic fault lab.

The fault lab's 12 scenarios are single-fault and constructed from one baseline.
That is good for grading an engine but it does not resemble a real lab file: real
files have dozens of default-state ports, dynamic routing, public edge addressing
and device names containing spaces and parentheses.

These fixtures are built the same way (a model plus a held-back manifest) but with
those realistic features present, so a detector that only works on a tidy
synthetic network fails here.

Every fixture declares `faults` as `(kind, device, interface)` triples. The tests
in `tests/adversarial/test_holdout_faults.py` grade the engine against them.
"""

from __future__ import annotations

from dataclasses import dataclass

from trident.models import (
    AclEntry,
    DeviceInfo,
    InterfaceInfo,
    LinkInfo,
    NetworkModel,
    RouteInfo,
    SettingsInfo,
    VlanInfo,
)


@dataclass(frozen=True)
class HoldoutCase:
    name: str
    model: NetworkModel
    faults: tuple[tuple[str, str, str | None], ...]
    notes: str = ""

    @property
    def expected_kinds(self) -> set[str]:
        return {kind for kind, _device, _interface in self.faults}


def _device(name: str, kind: str, config: list[str] | None = None) -> DeviceInfo:
    return DeviceInfo(id=name, name=name, hostname=name, device_type=kind, configuration=config or [])


def _iface(
    device: str,
    name: str,
    address: str | None = None,
    prefix: int | None = None,
    admin: str | None = "up",
    vlans: list[str] | None = None,
    mode: str | None = "access",
    description: str | None = None,
) -> InterfaceInfo:
    return InterfaceInfo(
        device=device,
        name=name,
        canonical_name=name,
        ipv4_address=address,
        prefix_length=prefix,
        subnet_mask=_mask(prefix) if prefix else None,
        admin_state=admin,
        operational_state=admin,
        vlan_assignments=vlans or [],
        access_mode=mode,
        description=description,
    )


def _mask(prefix: int) -> str:
    import ipaddress

    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)


def _base() -> NetworkModel:
    """A realistic three-tier lab with OSPF, public edge addressing, and noise.

    The noise is deliberate: Vlan1 and unused serial ports administratively down,
    a public-only ISP router, device names with spaces and parentheses. A detector
    that cannot tell these from a fault will fail the holdout.
    """
    devices = {
        "Core Router (HQ)": _device(
            "Core Router (HQ)",
            "router",
            ["hostname CoreRouter", "router ospf 1", " network 10.0.0.0 0.0.0.255 area 0"],
        ),
        "Edge ISP Router": _device("Edge ISP Router", "router", ["hostname EdgeISP"]),
        "Floor Switch 1": _device("Floor Switch 1", "switch"),
        "Floor Switch 2": _device("Floor Switch 2", "switch"),
        "PC-A": _device("PC-A", "host"),
        "PC-B": _device("PC-B", "host"),
        "Server Farm": _device("Server Farm", "server"),
    }
    interfaces = {
        "Core Router (HQ):Gi0/0": _iface("Core Router (HQ)", "GigabitEthernet0/0", "10.0.0.1", 24),
        "Core Router (HQ):Gi0/1": _iface("Core Router (HQ)", "GigabitEthernet0/1", "198.51.100.2", 30),
        "Core Router (HQ):Gi0/2": _iface("Core Router (HQ)", "GigabitEthernet0/2", "10.0.1.1", 24),
        "Core Router (HQ):Vlan1": _iface("Core Router (HQ)", "Vlan1", admin="administratively down", mode=None),
        "Edge ISP Router:Gi0/0": _iface("Edge ISP Router", "GigabitEthernet0/0", "198.51.100.1", 30),
        "Edge ISP Router:Gi0/1": _iface("Edge ISP Router", "GigabitEthernet0/1", "203.0.113.1", 24),
        "Edge ISP Router:Se0/0/0": _iface(
            "Edge ISP Router", "Serial0/0/0", admin="administratively down", mode=None
        ),
        "Floor Switch 1:Gi0/1": _iface("Floor Switch 1", "GigabitEthernet0/1", "10.0.0.2", 24, vlans=["10"], mode="trunk"),
        "Floor Switch 1:Fa0/1": _iface("Floor Switch 1", "FastEthernet0/1", vlans=["10"]),
        "Floor Switch 1:Fa0/2": _iface("Floor Switch 1", "FastEthernet0/2", vlans=["10"]),
        "Floor Switch 1:Vlan1": _iface("Floor Switch 1", "Vlan1", admin="administratively down", mode=None),
        "Floor Switch 2:Gi0/1": _iface("Floor Switch 2", "GigabitEthernet0/1", "10.0.1.2", 24, vlans=["10", "20"], mode="trunk"),
        "Floor Switch 2:Fa0/1": _iface("Floor Switch 2", "FastEthernet0/1", vlans=["20"]),
        "Floor Switch 2:Gi0/2": _iface("Floor Switch 2", "GigabitEthernet0/2", "10.0.1.3", 24, vlans=["20"], mode="trunk"),
        "PC-A:Fa0": _iface("PC-A", "FastEthernet0", "10.0.0.10", 24, mode=None),
        "PC-B:Fa0": _iface("PC-B", "FastEthernet0", "10.0.1.10", 24, mode=None),
        "Server Farm:Fa0": _iface("Server Farm", "FastEthernet0", "10.0.1.50", 24, mode=None),
    }
    links = [
        LinkInfo(device_a="Core Router (HQ)", interface_a="GigabitEthernet0/0", device_b="Floor Switch 1", interface_b="GigabitEthernet0/1"),
        LinkInfo(device_a="Core Router (HQ)", interface_a="GigabitEthernet0/1", device_b="Edge ISP Router", interface_b="GigabitEthernet0/0"),
        LinkInfo(device_a="Floor Switch 1", interface_a="FastEthernet0/1", device_b="PC-A", interface_b="FastEthernet0"),
        LinkInfo(device_a="Floor Switch 2", interface_a="FastEthernet0/1", device_b="PC-B", interface_b="FastEthernet0"),
        LinkInfo(device_a="Floor Switch 2", interface_a="GigabitEthernet0/1", device_b="Server Farm", interface_b="FastEthernet0"),
        LinkInfo(device_a="Core Router (HQ)", interface_a="GigabitEthernet0/2", device_b="Floor Switch 2", interface_b="GigabitEthernet0/2"),
    ]
    routes = [
        RouteInfo(device="Core Router (HQ)", destination="0.0.0.0", next_hop="198.51.100.1", route_type="static", protocol="static"),
        RouteInfo(device="Core Router (HQ)", destination="10.0.0.0/24", route_type="connected", protocol="connected"),
        RouteInfo(device="Edge ISP Router", destination="0.0.0.0", next_hop="203.0.113.254", route_type="static", protocol="static"),
    ]
    vlans = [
        VlanInfo(vlan_id=10, name="USERS"),
        VlanInfo(vlan_id=20, name="SERVERS"),
    ]
    settings = SettingsInfo(
        default_gateways={"PC-A": "10.0.0.1", "PC-B": "10.0.1.1", "Server Farm": "10.0.1.1"},
        dhcp_configured=[
            "Core Router (HQ): pool USERS network 10.0.0.0/24 gateway 10.0.0.1",
        ],
    )
    return NetworkModel(
        devices=devices,
        interfaces=interfaces,
        links=links,
        routes=routes,
        vlans=vlans,
        settings=settings,
    )


def _mutate(model: NetworkModel, key: str, **changes) -> None:
    interface = model.interfaces[key]
    for field_name, value in changes.items():
        setattr(interface, field_name, value)


def healthy() -> HoldoutCase:
    return HoldoutCase("healthy-with-noise", _base(), ())


def wrong_vlan_realistic() -> HoldoutCase:
    model = _base()
    _mutate(model, "Floor Switch 1:Fa0/1", vlan_assignments=["30"])
    return HoldoutCase(
        "wrong-vlan-realistic",
        model,
        (("WRONG_VLAN", "Floor Switch 1", "FastEthernet0/1"),),
        "Port moved to an undefined VLAN while its segment uses VLAN 10.",
    )


def invalid_mask_realistic() -> HoldoutCase:
    model = _base()
    _mutate(model, "Core Router (HQ):Gi0/0", subnet_mask="255.255.0.255", prefix_length=None)
    return HoldoutCase(
        "invalid-mask-realistic",
        model,
        (("INVALID_MASK", "Core Router (HQ)", "GigabitEthernet0/0"),),
    )


def duplicate_ip_realistic() -> HoldoutCase:
    """Two hosts on the *same* VLAN and subnet share an address."""
    model = _base()
    _mutate(model, "PC-B:Fa0", ipv4_address="10.0.0.10", prefix_length=24, subnet_mask=_mask(24))
    # Keep PC-B on VLAN 10 so this is purely an address clash, not a VLAN move.
    model.interfaces["Floor Switch 2:Fa0/1"].vlan_assignments = ["10"]
    return HoldoutCase(
        "duplicate-ip-realistic",
        model,
        (("DUPLICATE_IP", "PC-A", "FastEthernet0"),),
        "PC-B reuses PC-A's address within the same VLAN and subnet.",
    )


def shutdown_realistic() -> HoldoutCase:
    model = _base()
    _mutate(model, "Floor Switch 2:Fa0/1", admin_state="administratively down")
    return HoldoutCase(
        "shutdown-addressed-port",
        model,
        (("SHUTDOWN_INTERFACE", "Floor Switch 2", "FastEthernet0/1"),),
        "An addressed, VLAN-assigned access port is shut; noise ports also exist.",
    )


def overloaded_dhcp_realistic() -> HoldoutCase:
    model = _base()
    model.settings.dhcp_configured = [
        "Core Router (HQ): pool USERS network 10.0.0.0/24 gateway 10.0.0.254",
    ]
    return HoldoutCase(
        "dhcp-gateway-unowned-realistic",
        model,
        (("DHCP_MISCONFIGURATION", "Core Router (HQ)", None),),
        "Pool gateway is an address no interface holds.",
    )


def acl_realistic() -> HoldoutCase:
    model = _base()
    model.acls = [
        AclEntry(
            acl_id="110",
            acl_type="extended",
            sequence=10,
            action="deny",
            protocol="tcp",
            source="any",
            destination="10.0.1.50 0.0.0.0",
            port_conditions=["eq 443"],
            applied_interface="GigabitEthernet0/0",
            direction="in",
            raw="access-list 110 deny tcp any host 10.0.1.50 eq 443",
        )
    ]
    model.interfaces["Core Router (HQ):Gi0/0"].description = "ip access-group 110 in"
    return HoldoutCase(
        "acl-block-realistic",
        model,
        (("ACL_BLOCK", "Core Router (HQ)", "GigabitEthernet0/0"),),
    )


def trunk_pruned_realistic() -> HoldoutCase:
    """One end of a switch-to-switch trunk stops carrying VLAN 20."""
    model = _base()
    # Make the two floor switches peers of each other on a trunk.
    model.interfaces["Floor Switch 1:Gi0/2"] = _iface(
        "Floor Switch 1", "GigabitEthernet0/2", vlans=["10", "20"], mode="trunk"
    )
    model.links.append(
        LinkInfo(
            device_a="Floor Switch 1",
            interface_a="GigabitEthernet0/2",
            device_b="Floor Switch 2",
            interface_b="GigabitEthernet0/2",
        )
    )
    # Floor Switch 2 carries only VLAN 10 on that trunk; its peer carries 10 and 20.
    _mutate(model, "Floor Switch 2:Gi0/2", vlan_assignments=["10"])
    return HoldoutCase(
        "trunk-pruned-realistic",
        model,
        (("TRUNK_MISMATCH", "Floor Switch 2", "GigabitEthernet0/2"),),
        "VLAN 20 pruned from one trunk end while the peer still carries it.",
    )


def overlapping_realistic() -> HoldoutCase:
    model = _base()
    model.interfaces["Core Router (HQ):Loopback0"] = _iface(
        "Core Router (HQ)", "Loopback0", "10.0.0.129", 25, mode=None
    )
    return HoldoutCase(
        "overlapping-subnet-realistic",
        model,
        (("OVERLAPPING_SUBNET", "Core Router (HQ)", "Loopback0"),),
    )


def multi_fault_realistic() -> HoldoutCase:
    """Two independent faults plus realistic noise."""
    model = _base()
    # Fa0/1 is the cabled port, so move *it* to the undefined VLAN; Fa0/2 has no
    # peer and no host address, so a VLAN change there is not observable.
    _mutate(model, "Floor Switch 1:Fa0/1", vlan_assignments=["30"])
    _mutate(model, "Core Router (HQ):Gi0/0", subnet_mask="255.255.0.255", prefix_length=None)
    return HoldoutCase(
        "multi-fault-realistic",
        model,
        (
            ("WRONG_VLAN", "Floor Switch 1", "FastEthernet0/1"),
            ("INVALID_MASK", "Core Router (HQ)", "GigabitEthernet0/0"),
        ),
    )


def noise_only_never_faulted() -> HoldoutCase:
    """Every `down` interface here is legitimately down. Expect zero findings."""
    model = _base()
    model.devices["Parked Router"] = _device("Parked Router", "router")
    model.interfaces["Parked Router:Gi0/0"] = _iface(
        "Parked Router", "GigabitEthernet0/0", admin="administratively down", mode=None
    )
    model.interfaces["Parked Router:Se0/0/0"] = _iface(
        "Parked Router", "Serial0/0/0", admin="administratively down", mode=None
    )
    return HoldoutCase(
        "noise-only",
        model,
        (),
        "An unconfigured spare router. Any finding here is a false positive.",
    )


def all_cases() -> tuple[HoldoutCase, ...]:
    return (
        healthy(),
        wrong_vlan_realistic(),
        invalid_mask_realistic(),
        duplicate_ip_realistic(),
        shutdown_realistic(),
        overloaded_dhcp_realistic(),
        acl_realistic(),
        trunk_pruned_realistic(),
        overlapping_realistic(),
        multi_fault_realistic(),
        noise_only_never_faulted(),
    )


__all__ = ["HoldoutCase", "all_cases"]
