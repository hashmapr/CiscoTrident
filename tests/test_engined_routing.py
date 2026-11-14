"""Engine D must reason about a *path*, not one router's table.

The measured misses this file pins down were all routing-shaped: a packet that
crossed three routers, a static route whose next hop was on no connected subnet,
a default route mistaken for a gap, and a reply path that was never checked. Each
test below states a small topology explicitly and asserts the exact status and
the device the fault is attributed to. No test depends on pkt_core, Packet
Tracer, or the generator.

The models are hand-built in the same shape as ``tests/test_engined_intent.py``'s
``FakeModel``. The dataclasses are copied deliberately: a test must not import
another test module, or a change to one fixture silently changes another file's
world.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from trident.engined import (
    Endpoint,
    NetworkIntent,
    Requirement,
    Status,
    verify_intent,
    verify_requirement,
)
from trident.engined.reachability import (
    ForwardingTable,
    PathResult,
    TraceOutcome,
    trace_path,
)
from trident.engined.verify import _router_for_address

# ---------------------------------------------------------------------------
# A minimal model, shaped like NetworkModel's public surface
# ---------------------------------------------------------------------------


@dataclass
class FakeInterface:
    device: str
    name: str
    ipv4_address: str | None = None
    prefix_length: int | None = None
    admin_state: str = "up"
    access_mode: str | None = None
    vlan_assignments: list[str] = field(default_factory=list)
    #: End-host NIC gateway, as normalised onto InterfaceInfo.
    ipv4_gateway: str | None = None


@dataclass
class FakeRoute:
    device: str
    destination: str
    next_hop: str | None = None
    mask: str | None = None


@dataclass
class FakeLink:
    device_a: str
    interface_a: str
    device_b: str
    interface_b: str


@dataclass
class FakeDevice:
    name: str
    configuration: list[str] = field(default_factory=list)
    model: str = ""
    device_type: str | None = None


@dataclass
class FakeModel:
    devices: dict
    interfaces: dict
    routes: list = field(default_factory=list)
    links: list = field(default_factory=list)
    vlans: list = field(default_factory=list)
    acls: list = field(default_factory=list)


def _iface(model, device, name, address, prefix, **kw):
    model.interfaces[f"{device}:{name}"] = FakeInterface(
        device, name, address, prefix, **kw
    )


def _route(model, device, destination, next_hop, mask):
    model.routes.append(FakeRoute(device, destination, next_hop, mask))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def three_router_chain(*, middle_has_route: bool = True) -> FakeModel:
    """PC-A -- R1 -- R2 -- R3 -- PC-C, with one LAN at each end.

    The middle router is the interesting one: it is neither the source's gateway
    nor the destination's, and a single-router check never asks it anything.
    """
    m = FakeModel(
        devices={
            "R1": FakeDevice("R1", model="2911"),
            "R2": FakeDevice("R2", model="2911"),
            "R3": FakeDevice("R3", model="2911"),
            "PC-A": FakeDevice("PC-A", model="PC-PT"),
            "PC-C": FakeDevice("PC-C", model="PC-PT"),
        },
        interfaces={},
    )
    _iface(m, "R1", "Gi0/0", "10.0.1.1", 24)
    _iface(m, "R1", "Gi0/1", "10.0.12.1", 30)
    _iface(m, "R2", "Gi0/0", "10.0.12.2", 30)
    _iface(m, "R2", "Gi0/1", "10.0.23.2", 30)
    _iface(m, "R3", "Gi0/0", "10.0.23.3", 30)
    _iface(m, "R3", "Gi0/1", "10.0.3.1", 24)
    _iface(m, "PC-A", "Fa0", "10.0.1.10", 24, ipv4_gateway="10.0.1.1")
    _iface(m, "PC-C", "Fa0", "10.0.3.10", 24, ipv4_gateway="10.0.3.1")
    _route(m, "R1", "10.0.3.0", "10.0.12.2", "255.255.255.0")
    _route(m, "R2", "10.0.1.0", "10.0.12.1", "255.255.255.0")
    _route(m, "R3", "10.0.1.0", "10.0.23.2", "255.255.255.0")
    if middle_has_route:
        _route(m, "R2", "10.0.3.0", "10.0.23.3", "255.255.255.0")
    return m


def two_router_model(*, r1_route: bool, r2_route: bool) -> FakeModel:
    """PC-A -- R1 ==transit== R2 -- PC-B, with both routes independently optional."""
    m = FakeModel(
        devices={
            "R1": FakeDevice("R1", model="2911"),
            "R2": FakeDevice("R2", model="2911"),
            "PC-A": FakeDevice("PC-A", model="PC-PT"),
            "PC-B": FakeDevice("PC-B", model="PC-PT"),
        },
        interfaces={},
    )
    _iface(m, "R1", "Gi0/0", "10.0.1.1", 24)
    _iface(m, "R1", "Gi0/1", "10.0.12.1", 30)
    _iface(m, "R2", "Gi0/0", "10.0.2.1", 24)
    _iface(m, "R2", "Gi0/1", "10.0.12.2", 30)
    _iface(m, "PC-A", "Fa0", "10.0.1.10", 24, ipv4_gateway="10.0.1.1")
    _iface(m, "PC-B", "Fa0", "10.0.2.10", 24, ipv4_gateway="10.0.2.1")
    if r1_route:
        _route(m, "R1", "10.0.2.0", "10.0.12.2", "255.255.255.0")
    if r2_route:
        _route(m, "R2", "10.0.1.0", "10.0.12.1", "255.255.255.0")
    return m


def edge_and_lan(*, r1_has_default: bool) -> FakeModel:
    """PC-A -- R1 --(default)--> R2 -- PC-Z, where R1 may have no way off-LAN."""
    m = FakeModel(
        devices={
            "R1": FakeDevice("R1", model="2911"),
            "R2": FakeDevice("R2", model="2911"),
            "PC-A": FakeDevice("PC-A", model="PC-PT"),
            "PC-Z": FakeDevice("PC-Z", model="PC-PT"),
        },
        interfaces={},
    )
    _iface(m, "R1", "Gi0/0", "10.0.1.1", 24)
    _iface(m, "R1", "Gi0/1", "203.0.113.1", 30)
    _iface(m, "R2", "Gi0/0", "203.0.113.2", 30)
    _iface(m, "R2", "Gi0/1", "10.9.9.1", 24)
    _iface(m, "PC-A", "Fa0", "10.0.1.10", 24, ipv4_gateway="10.0.1.1")
    _iface(m, "PC-Z", "Fa0", "10.9.9.10", 24, ipv4_gateway="10.9.9.1")
    _route(m, "R2", "10.0.1.0", "203.0.113.1", "255.255.255.0")
    if r1_has_default:
        _route(m, "R1", "0.0.0.0", "203.0.113.2", "0.0.0.0")
    return m


def isp_edge_with_only_a_default() -> FakeModel:
    """PC-A -- R1 -- ISP -- SRV.

    The ISP has no private routes at all: its entire table is one default. It
    still forwards to a private address on its own attached segment, and still
    returns traffic through that default. Neither is a missing route.
    """
    m = FakeModel(
        devices={
            "R1": FakeDevice("R1", model="2911"),
            "ISP": FakeDevice("ISP", model="2911"),
            "PC-A": FakeDevice("PC-A", model="PC-PT"),
            "SRV": FakeDevice("SRV", model="Server-PT"),
        },
        interfaces={},
    )
    _iface(m, "R1", "Gi0/0", "10.0.1.1", 24)
    _iface(m, "R1", "Gi0/1", "203.0.113.1", 30)
    _iface(m, "ISP", "Gi0/0", "203.0.113.2", 30)
    _iface(m, "ISP", "Gi0/1", "10.50.0.1", 24)
    _iface(m, "PC-A", "Fa0", "10.0.1.10", 24, ipv4_gateway="10.0.1.1")
    _iface(m, "SRV", "Fa0", "10.50.0.10", 24, ipv4_gateway="10.50.0.1")
    _route(m, "R1", "0.0.0.0", "203.0.113.2", "0.0.0.0")
    # The ISP's entire table: one default toward the customer edge.
    _route(m, "ISP", "0.0.0.0", "203.0.113.1", "0.0.0.0")
    return m


def _reach_verdict(model, src: str, dst: str):
    return verify_requirement(model, Requirement(Endpoint(src), Endpoint(dst)))


# ---------------------------------------------------------------------------
# 1. Transit routing across several routers
# ---------------------------------------------------------------------------


def test_three_router_chain_is_reachable_and_lists_every_hop() -> None:
    """A path that crosses R1, R2 and R3 must record all three decisions."""
    m = three_router_chain()
    trace = trace_path(m, "10.0.1.10", "10.0.3.10")

    assert trace.outcome is TraceOutcome.REACHABLE
    assert trace.devices == ["R1", "R2", "R3"]
    assert len(trace.hops) == 3
    # The evidence is the hop list, not a conclusion: every decision is present.
    assert all(hop.detail for hop in trace.hops)
    assert {hop.device for hop in trace.hops} == {"R1", "R2", "R3"}

    verdict = _reach_verdict(m, "PC-A", "PC-C")
    assert verdict.status is Status.DERIVED
    assert verdict.reachable is True
    assert verdict.failed is False
    joined = " ".join(verdict.evidence)
    assert "R1" in joined and "R2" in joined and "R3" in joined


def test_three_router_chain_localizes_missing_route_to_the_middle_router() -> None:
    """R2 is neither endpoint's gateway; the fault must still land on R2."""
    m = three_router_chain(middle_has_route=False)
    trace = trace_path(m, "10.0.1.10", "10.0.3.10")

    assert trace.outcome is TraceOutcome.NO_ROUTE
    assert trace.fault_device == "R2"
    assert trace.devices == ["R1", "R2"]
    assert "R2" in trace.detail

    report = verify_intent(
        m,
        NetworkIntent(
            requirements=[Requirement(Endpoint("PC-A"), Endpoint("PC-C"))]
        ),
    )
    assert len(report.failures) == 1
    faults = report.localize_faults()
    assert len(faults) == 1
    assert faults[0].device == "R2"
    assert faults[0].kind == "MISSING_FORWARD_ROUTE"


# ---------------------------------------------------------------------------
# 2. A next hop that is on no connected subnet
# ---------------------------------------------------------------------------


def test_route_via_uncabled_next_hop_is_localized_to_its_router() -> None:
    """10.0.12.9 is outside the /30 transit, so IOS never installs the route."""
    m = FakeModel(
        devices={
            "R1": FakeDevice("R1", model="2911"),
            "R2": FakeDevice("R2", model="2911"),
            "PC-A": FakeDevice("PC-A", model="PC-PT"),
            "PC-B": FakeDevice("PC-B", model="PC-PT"),
        },
        interfaces={},
    )
    _iface(m, "R1", "Gi0/0", "10.0.1.1", 24)
    _iface(m, "R1", "Gi0/1", "10.0.12.1", 30)
    _iface(m, "R2", "Gi0/0", "10.0.2.1", 24)
    _iface(m, "R2", "Gi0/1", "10.0.12.2", 30)
    _iface(m, "PC-A", "Fa0", "10.0.1.10", 24, ipv4_gateway="10.0.1.1")
    _iface(m, "PC-B", "Fa0", "10.0.2.10", 24, ipv4_gateway="10.0.2.1")
    _route(m, "R1", "10.0.2.0", "10.0.12.9", "255.255.255.0")
    _route(m, "R2", "10.0.1.0", "10.0.12.1", "255.255.255.0")

    trace = trace_path(m, "10.0.1.10", "10.0.2.10")
    assert trace.outcome is TraceOutcome.UNREACHABLE_NEXT_HOP
    assert trace.fault_device == "R1"
    assert "10.0.12.9" in trace.detail

    verdict = _reach_verdict(m, "PC-A", "PC-B")
    assert verdict.status is Status.DERIVED
    assert verdict.reachable is False
    assert verdict.deciding_device == "R1"
    assert verdict.failure_direction == "forward"


# ---------------------------------------------------------------------------
# 3. Default routes, in both directions of the distinction
# ---------------------------------------------------------------------------


def test_default_route_reaches_an_unknown_destination_without_a_missing_route() -> None:
    """R1 has no specific route to 10.9.9.0/24 — only a default. That works."""
    m = edge_and_lan(r1_has_default=True)

    table = ForwardingTable(m, "R1")
    decision = table.decide("10.9.9.10")
    assert decision.result is PathResult.DEFAULT
    assert decision.forwards is True

    trace = trace_path(m, "10.0.1.10", "10.9.9.10")
    assert trace.outcome is TraceOutcome.REACHABLE
    # The default was followed, not reported as a missing specific route.
    assert trace.devices == ["R1", "R2"]

    verdict = _reach_verdict(m, "PC-A", "PC-Z")
    assert verdict.status is Status.DERIVED
    assert verdict.reachable is True
    assert verdict.failed is False
    assert verdict.missing == []


def test_no_default_and_no_specific_route_is_a_missing_route() -> None:
    """The contrast case: remove the default and the same path genuinely dies."""
    m = edge_and_lan(r1_has_default=False)

    decision = ForwardingTable(m, "R1").decide("10.9.9.10")
    assert decision.result is PathResult.NO_ROUTE
    assert decision.forwards is False

    verdict = _reach_verdict(m, "PC-A", "PC-Z")
    assert verdict.status is Status.DERIVED
    assert verdict.reachable is False
    assert verdict.deciding_device == "R1"
    assert verdict.failure_direction == "forward"


def test_isp_edge_with_only_a_default_reaches_private_addresses() -> None:
    """An ISP router with no private routes is correct, not broken."""
    m = isp_edge_with_only_a_default()

    isp_routes = [r for r in m.routes if r.device == "ISP"]
    assert len(isp_routes) == 1
    assert isp_routes[0].destination == "0.0.0.0"
    assert isp_routes[0].mask == "0.0.0.0"

    # A private address it has no specific route for is reached by the default.
    assert ForwardingTable(m, "ISP").decide("10.99.0.10").result is PathResult.DEFAULT

    trace = trace_path(m, "10.0.1.10", "10.50.0.10")
    assert trace.outcome is TraceOutcome.REACHABLE
    assert trace.devices == ["R1", "ISP"]

    verdict = _reach_verdict(m, "PC-A", "SRV")
    assert verdict.reachable is True
    assert verdict.failed is False
    assert verdict.missing == []


# ---------------------------------------------------------------------------
# 4. Missing forward route vs missing return route
# ---------------------------------------------------------------------------


def test_forward_failure_reports_only_missing_forward_route() -> None:
    """A replies fine; A cannot leave. The fault is the forward direction."""
    m = two_router_model(r1_route=False, r2_route=True)

    verdict = _reach_verdict(m, "PC-A", "PC-B")
    assert verdict.status is Status.DERIVED
    assert verdict.reachable is False
    assert verdict.failure_direction == "forward"
    assert verdict.deciding_device == "R1"

    report = verify_intent(
        m, NetworkIntent(requirements=[Requirement(Endpoint("PC-A"), Endpoint("PC-B"))])
    )
    kinds = [fault.kind for fault in report.localize_faults()]
    assert kinds == ["MISSING_FORWARD_ROUTE"]


def test_return_failure_reports_only_missing_return_route() -> None:
    """Forward works; the reply route is absent. Name the return direction."""
    m = two_router_model(r1_route=True, r2_route=False)

    verdict = _reach_verdict(m, "PC-A", "PC-B")
    assert verdict.status is Status.DERIVED
    assert verdict.reachable is False
    assert verdict.failure_direction == "return"
    assert verdict.deciding_device == "R2"

    report = verify_intent(
        m, NetworkIntent(requirements=[Requirement(Endpoint("PC-A"), Endpoint("PC-B"))])
    )
    kinds = [fault.kind for fault in report.localize_faults()]
    assert kinds == ["MISSING_RETURN_ROUTE"]


# ---------------------------------------------------------------------------
# 5. Gateway identification is per-address, not per-topology
# ---------------------------------------------------------------------------


def test_two_routers_each_resolve_to_the_router_that_serves_the_address() -> None:
    """A router on another subnet must never answer for this one."""
    m = FakeModel(
        devices={
            "R1": FakeDevice("R1", model="2911"),
            "R2": FakeDevice("R2", model="2911"),
        },
        interfaces={},
    )
    _iface(m, "R1", "Gi0/0", "172.16.80.1", 24)
    _iface(m, "R2", "Gi0/0", "172.16.90.1", 24)

    assert _router_for_address(m, "172.16.80.10") == "R1"
    assert _router_for_address(m, "172.16.90.10") == "R2"

    # Longest prefix wins when a summary covers the same address: the /24 is the
    # router that actually serves the host, not the /8 that merely contains it.
    m.interfaces["R1:Gi0/1"] = FakeInterface("R1", "Gi0/1", "10.0.0.1", 8)
    m.interfaces["R2:Gi0/1"] = FakeInterface("R2", "Gi0/1", "10.0.1.1", 24)
    assert _router_for_address(m, "10.0.1.5") == "R2"


# ---------------------------------------------------------------------------
# 6. Longest-prefix-match precedence
# ---------------------------------------------------------------------------


def _precedence_model() -> FakeModel:
    m = FakeModel(
        devices={"R1": FakeDevice("R1", model="2911")},
        interfaces={},
    )
    _iface(m, "R1", "Gi0/0", "192.0.2.1", 24)
    _route(m, "R1", "0.0.0.0", "192.0.2.10", "0.0.0.0")
    _route(m, "R1", "10.1.1.0", "192.0.2.20", "255.255.255.0")
    _route(m, "R1", "10.1.1.4", "192.0.2.30", "255.255.255.252")
    return m


def test_longest_prefix_match_prefers_30_over_24_over_default() -> None:
    m = _precedence_model()
    table = ForwardingTable(m, "R1")

    assert table.decide("10.1.1.5").matched_route == "10.1.1.4/30"
    assert table.decide("10.1.1.5").next_hop == "192.0.2.30"

    m.routes = [r for r in m.routes if r.destination != "10.1.1.4"]
    table = ForwardingTable(m, "R1")
    assert table.decide("10.1.1.5").matched_route == "10.1.1.0/24"
    assert table.decide("10.1.1.5").next_hop == "192.0.2.20"

    m.routes = [r for r in m.routes if r.destination != "10.1.1.0"]
    table = ForwardingTable(m, "R1")
    decision = table.decide("10.1.1.5")
    assert decision.matched_route == "0.0.0.0/0"
    assert decision.result is PathResult.DEFAULT


def test_a_connected_subnet_beats_a_static_route_for_the_same_prefix() -> None:
    m = FakeModel(
        devices={"R1": FakeDevice("R1", model="2911")},
        interfaces={},
    )
    _iface(m, "R1", "Gi0/0", "10.1.1.1", 24)
    _iface(m, "R1", "Gi0/1", "192.0.2.1", 24)
    _route(m, "R1", "10.1.1.0", "192.0.2.20", "255.255.255.0")

    decision = ForwardingTable(m, "R1").decide("10.1.1.5")
    assert decision.result is PathResult.CONNECTED
    assert decision.matched_route == "10.1.1.0/24"
    assert decision.out_interface == "Gi0/0"


# ---------------------------------------------------------------------------
# Hop counter: a trace always terminates
# ---------------------------------------------------------------------------


def test_a_routing_loop_stops_at_the_hop_limit() -> None:
    """R1 and R2 both point the destination at each other."""
    m = FakeModel(
        devices={
            "R1": FakeDevice("R1", model="2911"),
            "R2": FakeDevice("R2", model="2911"),
        },
        interfaces={},
    )
    _iface(m, "R1", "Gi0/0", "10.0.12.1", 30)
    _iface(m, "R2", "Gi0/0", "10.0.12.2", 30)
    _route(m, "R1", "10.9.9.0", "10.0.12.2", "255.255.255.0")
    _route(m, "R2", "10.9.9.0", "10.0.12.1", "255.255.255.0")

    trace = trace_path(m, "10.0.12.1", "10.9.9.9", max_hops=8)
    assert trace.outcome is TraceOutcome.HOP_LIMIT
    assert trace.fault_device is not None
    assert len(trace.hops) <= 8


def test_a_long_path_stops_at_max_hops_even_without_a_loop() -> None:
    """The counter is a backstop, not merely a loop detector."""
    m = three_router_chain()
    trace = trace_path(m, "10.0.1.10", "10.0.3.10", max_hops=2)

    assert trace.outcome is TraceOutcome.HOP_LIMIT
    assert len(trace.hops) == 2
    assert trace.fault_device == "R2"


# ---------------------------------------------------------------------------
# 7. INCONCLUSIVE when the model lacks the fact
# ---------------------------------------------------------------------------


def test_unowned_next_hop_is_inconclusive_not_a_fabricated_failure() -> None:
    """A connected-but-unowned next hop might be outside the model — say so."""
    m = FakeModel(
        devices={
            "R1": FakeDevice("R1", model="2911"),
            "PC-A": FakeDevice("PC-A", model="PC-PT"),
            "PC-B": FakeDevice("PC-B", model="PC-PT"),
        },
        interfaces={},
    )
    _iface(m, "R1", "Gi0/0", "10.0.1.1", 24)
    _iface(m, "R1", "Gi0/1", "10.0.12.1", 30)
    _iface(m, "PC-A", "Fa0", "10.0.1.10", 24, ipv4_gateway="10.0.1.1")
    _iface(m, "PC-B", "Fa0", "10.0.2.10", 24, ipv4_gateway="10.0.2.1")
    _route(m, "R1", "10.0.2.0", "10.0.12.2", "255.255.255.0")

    verdict = _reach_verdict(m, "PC-A", "PC-B")
    assert verdict.status is Status.INCONCLUSIVE
    assert verdict.reachable is None
    assert verdict.failed is False
    assert any("10.0.12.2" in fact for fact in verdict.missing)


def test_no_gateway_is_inconclusive_and_names_the_missing_fact() -> None:
    m = FakeModel(
        devices={
            "PC-X": FakeDevice("PC-X", model="PC-PT"),
            "PC-Y": FakeDevice("PC-Y", model="PC-PT"),
        },
        interfaces={},
    )
    _iface(m, "PC-X", "Fa0", "192.168.50.10", 24)
    _iface(m, "PC-Y", "Fa0", "192.168.60.10", 24)

    verdict = _reach_verdict(m, "PC-X", "PC-Y")
    assert verdict.status is Status.INCONCLUSIVE
    assert verdict.reachable is None
    assert verdict.failed is False
    assert any("no router interface serves" in fact for fact in verdict.missing)


def test_an_unresolvable_endpoint_is_inconclusive() -> None:
    m = three_router_chain()
    verdict = verify_requirement(m, Requirement(Endpoint("PC-A"), Endpoint("GHOST")))
    assert verdict.status is Status.INCONCLUSIVE
    assert verdict.failed is False
    assert any("could not be resolved" in fact for fact in verdict.missing)


def test_unmodelled_dynamic_routing_is_inconclusive_not_a_failure() -> None:
    """A model with OSPF configured but no learned routes cannot be path-analysed."""
    m = three_router_chain()
    m.devices["R1"].configuration = ["router ospf 1", " network 10.0.1.0 0.0.0.255 area 0"]

    verdict = _reach_verdict(m, "PC-A", "PC-C")
    assert verdict.status is Status.INCONCLUSIVE
    assert verdict.reachable is None
    assert verdict.failed is False
    assert any("dynamic routing" in fact for fact in verdict.missing)
