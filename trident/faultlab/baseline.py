"""The correct reference network used by every scenario.

The topology is deliberately small and synthetic::

    WAN cloud
        |
      [R1] --- Gi0/1 --- Fa0/24 [SW1] Gi0/1 === Gi0/1 [SW2] --- Fa0/1 [PC1]
                                         |                    --- Fa0/2 [PC2]
                                         |                    --- Fa0/3 [SRV1]
                                      Fa0/4 [R2] Gi0/1        --- Fa0/4 (to R2 Gi0/0)

Addressing:

* ``10.10.10.0/24``  - R1/R2 transit VLAN 10
* ``10.10.20.0/24``  - user VLAN 20 behind R2
* ``203.0.113.0/30`` - R1 WAN link

This is *not* a Packet Tracer file, a parser fixture, or a capture of a real
device. It is constructed in memory so that a single field can be changed and
the defect is known exactly.
"""

from __future__ import annotations

from ..models import (
    DeviceInfo,
    InterfaceInfo,
    LinkInfo,
    NetworkModel,
    RouteInfo,
    SettingsInfo,
)

BASELINE_SNAPSHOT = "faultlab-baseline"


def _device(
    device_id: str,
    device_type: str,
    model: str,
    interfaces: list[str],
    ios_version: str,
) -> DeviceInfo:
    return DeviceInfo(
        id=device_id,
        name=device_id,
        hostname=device_id,
        device_type=device_type,
        model=model,
        ios_version=ios_version,
        interfaces=list(interfaces),
    )


def _iface(device: str, name: str, **kwargs) -> InterfaceInfo:
    fields = {
        "operational_state": "up",
        "admin_state": "up",
        "access_mode": "access",
    }
    fields.update(kwargs)
    return InterfaceInfo(device=device, name=name, canonical_name=name, **fields)


def baseline_lab() -> NetworkModel:
    """Return a fresh, defect-free ``NetworkModel`` of the reference lab.

    A new object (and a new settings instance) is built on every call, so a
    caller may mutate the result without affecting another scenario.
    """
    model = NetworkModel(snapshot_id=BASELINE_SNAPSHOT)

    devices = [
        _device("R1", "router", "ISR4331", ["GigabitEthernet0/0", "GigabitEthernet0/1"], "15.7"),
        _device("R2", "router", "ISR4331", ["GigabitEthernet0/0", "GigabitEthernet0/1"], "15.7"),
        _device(
            "SW1",
            "switch",
            "C2960",
            ["GigabitEthernet0/1", "FastEthernet0/24"],
            "15.0(2)SE",
        ),
        _device(
            "SW2",
            "switch",
            "C2960",
            [
                "GigabitEthernet0/1",
                "GigabitEthernet0/2",
                "FastEthernet0/1",
                "FastEthernet0/2",
                "FastEthernet0/3",
                "FastEthernet0/4",
            ],
            "15.0(2)SE",
        ),
        _device("PC1", "host", "PC-PT", ["FastEthernet0"], "1.0"),
        _device("PC2", "host", "PC-PT", ["FastEthernet0"], "1.0"),
        _device("SRV1", "server", "Server-PT", ["FastEthernet0"], "1.0"),
    ]
    for device in devices:
        model.devices[device.id] = device

    interfaces = [
        _iface(
            "R1",
            "GigabitEthernet0/0",
            ipv4_address="203.0.113.2",
            subnet_mask="255.255.255.252",
            prefix_length=30,
        ),
        _iface(
            "R1",
            "GigabitEthernet0/1",
            ipv4_address="10.10.10.1",
            subnet_mask="255.255.255.0",
            prefix_length=24,
        ),
        _iface(
            "R2",
            "GigabitEthernet0/0",
            ipv4_address="10.10.10.2",
            subnet_mask="255.255.255.0",
            prefix_length=24,
        ),
        _iface(
            "R2",
            "GigabitEthernet0/1",
            ipv4_address="10.10.20.1",
            subnet_mask="255.255.255.0",
            prefix_length=24,
        ),
        _iface(
            "SW1",
            "GigabitEthernet0/1",
            access_mode="trunk",
            vlan_assignments=["10", "20", "30"],
            native_vlan="1",
        ),
        _iface("SW1", "FastEthernet0/24", vlan_assignments=["10"]),
        _iface(
            "SW2",
            "GigabitEthernet0/1",
            access_mode="trunk",
            vlan_assignments=["10", "20", "30"],
            native_vlan="1",
        ),
        _iface("SW2", "GigabitEthernet0/2", vlan_assignments=["20"]),
        _iface("SW2", "FastEthernet0/1", vlan_assignments=["20"]),
        _iface("SW2", "FastEthernet0/2", vlan_assignments=["20"]),
        _iface("SW2", "FastEthernet0/3", vlan_assignments=["20"]),
        _iface("SW2", "FastEthernet0/4", vlan_assignments=["10"]),
        _iface(
            "PC1",
            "FastEthernet0",
            ipv4_address="10.10.20.10",
            subnet_mask="255.255.255.0",
            prefix_length=24,
            access_mode=None,
        ),
        _iface(
            "PC2",
            "FastEthernet0",
            ipv4_address="10.10.20.11",
            subnet_mask="255.255.255.0",
            prefix_length=24,
            access_mode=None,
        ),
        _iface(
            "SRV1",
            "FastEthernet0",
            ipv4_address="10.10.20.50",
            subnet_mask="255.255.255.0",
            prefix_length=24,
            access_mode=None,
        ),
    ]
    for iface in interfaces:
        model.interfaces[f"{iface.device}:{iface.name}"] = iface

    model.links = [
        LinkInfo(
            device_a="R1",
            interface_a="GigabitEthernet0/1",
            device_b="SW1",
            interface_b="FastEthernet0/24",
            media_type="copper",
        ),
        LinkInfo(
            device_a="SW1",
            interface_a="GigabitEthernet0/1",
            device_b="SW2",
            interface_b="GigabitEthernet0/1",
            media_type="copper",
        ),
        LinkInfo(
            device_a="SW2",
            interface_a="GigabitEthernet0/2",
            device_b="R2",
            interface_b="GigabitEthernet0/1",
            media_type="copper",
        ),
        LinkInfo(
            device_a="SW2",
            interface_a="FastEthernet0/4",
            device_b="R2",
            interface_b="GigabitEthernet0/0",
            media_type="copper",
        ),
        LinkInfo(
            device_a="SW2",
            interface_a="FastEthernet0/1",
            device_b="PC1",
            interface_b="FastEthernet0",
            media_type="copper",
        ),
        LinkInfo(
            device_a="SW2",
            interface_a="FastEthernet0/2",
            device_b="PC2",
            interface_b="FastEthernet0",
            media_type="copper",
        ),
        LinkInfo(
            device_a="SW2",
            interface_a="FastEthernet0/3",
            device_b="SRV1",
            interface_b="FastEthernet0",
            media_type="copper",
        ),
    ]

    model.routes = [
        RouteInfo(
            device="R1",
            destination="0.0.0.0",
            next_hop="203.0.113.1",
            route_type="static",
            protocol="static",
            administrative_distance=1,
            raw_config="ip route 0.0.0.0 0.0.0.0 203.0.113.1",
        ),
        RouteInfo(
            device="R1",
            destination="10.10.20.0/24",
            next_hop="10.10.10.2",
            route_type="static",
            protocol="static",
            administrative_distance=1,
            raw_config="ip route 10.10.20.0 255.255.255.0 10.10.10.2",
        ),
        RouteInfo(
            device="R2",
            destination="0.0.0.0",
            next_hop="10.10.10.1",
            route_type="static",
            protocol="static",
            administrative_distance=1,
            raw_config="ip route 0.0.0.0 0.0.0.0 10.10.10.1",
        ),
    ]

    model.settings = SettingsInfo(
        default_gateways={
            "PC1": "10.10.20.1",
            "PC2": "10.10.20.1",
            "SRV1": "10.10.20.1",
        },
        dhcp_configured=[
            "R2: pool LAN-POOL network 10.10.20.0/24 gateway 10.10.20.1 dns 203.0.113.53"
        ],
    )

    return model
