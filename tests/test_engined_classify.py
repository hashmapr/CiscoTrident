"""Device classification, and the gateway question it does and does not answer.

The classifier was wrong in a way that produced silent INCONCLUSIVE verdicts
rather than loud failures: ``_is_router_like`` required two addressed
interfaces, so a one-router/one-LAN lab — the commonest topology there is — had
no router at all, and every requirement behind it became undecidable.

These tests pin the classification for all five device classes, and then pin the
*separate* fact that being a router is not the same as being the intended
gateway.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from trident.engined.verify import (
    _is_router_like,
    _router_for_address,
    classify_device,
)


@dataclass
class FakeInterface:
    device: str
    name: str
    ipv4_address: str | None = None
    prefix_length: int | None = None
    admin_state: str = "up"
    access_mode: str | None = None
    vlan_assignments: list[str] = field(default_factory=list)


@dataclass
class FakeRoute:
    device: str
    destination: str
    next_hop: str | None = None
    mask: str | None = None


@dataclass
class FakeDevice:
    name: str
    model: str = ""
    device_type: str | None = None
    configuration: list[str] = field(default_factory=list)


@dataclass
class FakeModel:
    devices: dict
    interfaces: dict = field(default_factory=dict)
    routes: list = field(default_factory=list)
    links: list = field(default_factory=list)
    vlans: list = field(default_factory=list)
    acls: list = field(default_factory=list)


def _model(devices: dict, interfaces: list[FakeInterface] | None = None,
           routes: list[FakeRoute] | None = None) -> FakeModel:
    return FakeModel(
        devices=devices,
        interfaces={f"{i.device}:{i.name}": i for i in (interfaces or [])},
        routes=routes or [],
    )


# ---------------------------------------------------------------------------
# Classification across device classes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("model_string", "expected"),
    [
        ("2911", "router"),
        ("2901", "router"),
        ("4331", "router"),
        ("ISR4331", "router"),
        ("PC-PT", "end_host"),
        ("Server-PT", "end_host"),
        ("Laptop-PT", "end_host"),
        ("2960-24TT", "switch"),
        ("2950-24", "switch"),
        ("3560-24PS", "l3_switch"),
        ("3650-24PS", "l3_switch"),
    ],
)
def test_model_string_classification(model_string: str, expected: str) -> None:
    m = _model({"D": FakeDevice("D", model=model_string)})
    assert classify_device(m, "D") == expected


def test_explicit_device_type_wins_over_model_string() -> None:
    """A parser that supplies device_type must be believed."""
    m = _model({"D": FakeDevice("D", model="2960-24TT", device_type="router")})
    assert classify_device(m, "D") == "router"


def test_a_route_table_proves_routing_capability() -> None:
    """An otherwise unidentifiable device with routes is a router."""
    m = _model({"D": FakeDevice("D", model="")}, routes=[FakeRoute("D", "10.0.0.0/8")])
    assert classify_device(m, "D") == "router"


# ---------------------------------------------------------------------------
# The specific regression: single-interface router
# ---------------------------------------------------------------------------


def test_single_interface_router_is_still_a_router() -> None:
    """One LAN and one router is a normal lab, not a topology error.

    Requiring two addressed interfaces rejected it, so no gateway was found and
    every requirement became INCONCLUSIVE with no fault reported.
    """
    m = _model(
        {
            "R1": FakeDevice("R1", model="2911"),
            "PC1": FakeDevice("PC1", model="PC-PT"),
        },
        interfaces=[
            FakeInterface("R1", "Gi0/0", "172.16.80.1", 24),
            FakeInterface("PC1", "Fa0", "172.16.80.10", 24),
        ],
    )
    assert len([i for i in m.interfaces.values() if i.device == "R1"]) == 1
    assert _is_router_like(m, "R1") is True
    assert _router_for_address(m, "172.16.80.10") == "R1"


def test_router_is_found_for_the_172_16_80_subnet() -> None:
    """The exact case that was returning None."""
    m = _model(
        {"R1": FakeDevice("R1", model="2911")},
        interfaces=[FakeInterface("R1", "Gi0/0", "172.16.80.1", 24)],
    )
    assert _router_for_address(m, "172.16.80.10") == "R1"


# ---------------------------------------------------------------------------
# Devices that must NOT be treated as routers
# ---------------------------------------------------------------------------


def test_plain_switch_with_management_ip_is_not_a_router() -> None:
    """A 2960 with an SVI has an address and forwards nothing between subnets."""
    m = _model(
        {"SW1": FakeDevice("SW1", model="2960-24TT")},
        interfaces=[FakeInterface("SW1", "Vlan99", "192.168.99.2", 24)],
    )
    assert classify_device(m, "SW1") == "switch"
    assert _is_router_like(m, "SW1") is False
    assert _router_for_address(m, "192.168.99.10") is None


def test_multilayer_switch_is_routing_capable() -> None:
    """A 3560 can route, so it may legitimately be a gateway."""
    m = _model(
        {"MLS": FakeDevice("MLS", model="3560-24PS")},
        interfaces=[
            FakeInterface("MLS", "Gi0/1", "10.0.1.1", 24),
            FakeInterface("MLS", "Gi0/2", "10.0.2.1", 24),
        ],
    )
    assert classify_device(m, "MLS") == "l3_switch"
    assert _is_router_like(m, "MLS") is True


def test_pc_is_not_a_router_even_with_two_addresses() -> None:
    m = _model(
        {"PC1": FakeDevice("PC1", model="PC-PT")},
        interfaces=[
            FakeInterface("PC1", "Fa0", "10.0.1.10", 24),
            FakeInterface("PC1", "Fa1", "10.0.2.10", 24),
        ],
    )
    assert classify_device(m, "PC1") == "end_host"
    assert _is_router_like(m, "PC1") is False


def test_server_is_not_a_router() -> None:
    m = _model(
        {"SRV": FakeDevice("SRV", model="Server-PT")},
        interfaces=[FakeInterface("SRV", "Fa0", "10.0.1.50", 24)],
    )
    assert classify_device(m, "SRV") == "end_host"
    assert _is_router_like(m, "SRV") is False


def test_a_router_is_not_automatically_the_intended_gateway() -> None:
    """Being a router says what a box *can* do, never what it *should* do.

    R1 is a router. R2 is also a router, and R2 serves a different subnet. The
    resolution for an address must pick the router whose interface actually
    covers it — not merely any router in the topology.
    """
    m = _model(
        {
            "R1": FakeDevice("R1", model="2911"),
            "R2": FakeDevice("R2", model="2911"),
        },
        interfaces=[
            FakeInterface("R1", "Gi0/0", "172.16.80.1", 24),
            FakeInterface("R2", "Gi0/0", "172.16.90.1", 24),
        ],
    )
    assert classify_device(m, "R1") == "router"
    assert _router_for_address(m, "172.16.80.10") == "R1"
    assert _router_for_address(m, "172.16.90.10") == "R2"
