"""A fresh blind validation set with private ground truth.

Ten original labs the diagnostic engine has never been tuned against: two
healthy false-positive controls and eight deliberately broken networks. The
point is measurement, not teaching. Each lab carries a *private* manifest that
names the exact defect (device, interface, kind, expected, actual) and the
observable requirements that must pass or fail. A blind run may see only the
topology and the intent requirements; the manifest stays with the grader.

Why a separate module rather than more entries in :mod:`trident.labgen.ccna3`
--------------------------------------------------------------------------------
``ccna3`` was written alongside the detectors it exercises, so it is a
regression suite, not a blind one: the engine's behaviour informed its fault
choices. These cases were authored from the CCNA-3 syllabus (gateways, static
routing, return paths, interface state, VLANs and ACL policy) with no reference
to which detector exists. They use different addressing, different device
counts and different topology shapes from ``gauntlet``, ``broken_campus`` and
``ccna3`` on purpose.

Conventions
-----------
* A faulted case scores **exactly 100 points**; its faults are rebalanced to
  that total. A clean control has **zero faults and zero points**. There is no
  third convention.
* End-host faults are declared with ``TargetKind.ENDHOST`` and, because
  ``pkt_core`` cannot rewrite a NIC after the spec is built, the faulty value
  is authored directly into ``DeviceSpec.pc_ip``. ``faulted_configs`` records
  the fault without editing config text, which is honest about where the defect
  lives.
* ``pkt_core`` 0.2.2 does not write ``<ENGINE><GATEWAY>``, so a PC gateway may
  not survive a Packet Tracer load. The one gateway case therefore carries a
  second, independent routing fault and says so in its manifest notes; it is
  not a lab whose only value is the gateway.
* Every next hop in every *intended* build is on a cabled, addressed link. An
  IOS route whose next hop is not reachable at configuration time is silently
  rejected, which would make the answer key a lie.

The rules learned from live Packet Tracer runs (VLANs live in the ``<VLANS>``
element, VLAN names must be unique, IOS defaults cannot be faults, end-host CLI
rejects commands) are encoded here rather than rediscovered: VLAN-bearing
switches declare ``DeviceSpec.vlans`` explicitly, and no fault targets an end
host's CLI.
"""

from __future__ import annotations

from .gauntlet import rebalance
from .spec import (
    DeviceRole,
    DeviceSpec,
    FaultCategory,
    FaultSpec,
    InterfaceSpec,
    LinkSpec,
    Severity,
    TargetKind,
    TopologySpec,
    VlanSpec,
)

_ROUTER_MODEL = "2911"
_SWITCH_MODEL = "2960-24TT"
_PC_MODEL = "PC-PT"
_SERVER_MODEL = "Server-PT"

_ENABLE_SECRET = "Validate!23"
_USER_SECRET = "ValidateAdmin!23"

#: Router management baseline. It is placed before routing lines on purpose:
#: ``parse_running_config`` keeps an ``interface`` block open until a ``!`` or a
#: ``line`` block, so routes written straight after an interface are swallowed
#: as interface sub-commands and never reach the model.
_MGMT: tuple[str, ...] = (
    "line con 0",
    " logging synchronous",
    "line vty 0 4",
    " login local",
    " transport input ssh",
)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _router(
    name: str,
    x: int,
    y: int,
    *,
    interfaces: tuple[tuple[str, tuple[str, ...]], ...],
    routing: tuple[str, ...] = (),
) -> DeviceSpec:
    return DeviceSpec(
        name=name,
        model=_ROUTER_MODEL,
        role=DeviceRole.ROUTER,
        x=x,
        y=y,
        globals=(
            f"hostname {name}",
            f"enable secret {_ENABLE_SECRET}",
            f"username admin privilege 15 secret {_USER_SECRET}",
            "no ip domain-lookup",
        ),
        interfaces=tuple(InterfaceSpec(name=iface, lines=lines) for iface, lines in interfaces),
        trailing=(*_MGMT, *routing),
    )


def _switch(
    name: str,
    x: int,
    y: int,
    *,
    interfaces: tuple[tuple[str, tuple[str, ...]], ...] = (),
    vlans: tuple[VlanSpec, ...] | None = None,
) -> DeviceSpec:
    """An access switch. VLANs are declared in the database, never in config.

    A switch with no ``line vty`` block is out of scope for weak-management
    checks, which is correct: an unmanaged access switch has no remote login to
    protect.
    """
    return DeviceSpec(
        name=name,
        model=_SWITCH_MODEL,
        role=DeviceRole.SWITCH,
        x=x,
        y=y,
        globals=(f"hostname {name}", f"enable secret {_ENABLE_SECRET}"),
        interfaces=tuple(InterfaceSpec(name=iface, lines=lines) for iface, lines in interfaces),
        vlans=vlans,
    )


def _pc(name: str, x: int, y: int, address: str, gateway: str) -> DeviceSpec:
    return DeviceSpec(
        name=name,
        model=_PC_MODEL,
        role=DeviceRole.PC,
        x=x,
        y=y,
        pc_ip=(address, "255.255.255.0", gateway),
    )


def _server(name: str, x: int, y: int, address: str, gateway: str) -> DeviceSpec:
    return DeviceSpec(
        name=name,
        model=_SERVER_MODEL,
        role=DeviceRole.SERVER,
        x=x,
        y=y,
        pc_ip=(address, "255.255.255.0", gateway),
    )


def _lan(address: str) -> tuple[str, ...]:
    return (f" ip address {address} 255.255.255.0", " no shutdown")


def _transit(address: str) -> tuple[str, ...]:
    return (f" ip address {address} 255.255.255.252", " no shutdown")


def _access(vlan: int, *, description: str | None = None) -> tuple[str, ...]:
    lines = [
        " switchport mode access",
        f" switchport access vlan {vlan}",
        " no shutdown",
    ]
    if description:
        lines.insert(0, f" description {description}")
    return tuple(lines)


def _requirement(identifier: str, check: str, expect: str) -> dict[str, str]:
    return {"id": identifier, "check": check, "expect": expect}


def _build_case(
    spec: TopologySpec,
    requirements: list[dict[str, str]],
    kinds: dict[str, str],
    notes: tuple[str, ...] = (),
) -> tuple[TopologySpec, dict]:
    faults = []
    for fault in spec.faults:
        faults.append(
            {
                "fault_id": fault.fault_id,
                "device": fault.device,
                "interface": fault.interface or "",
                "kind": kinds.get(fault.fault_id, fault.category.value),
                "category": fault.category.value,
                "severity": fault.severity.value,
                "expected": fault.expected,
                "actual": fault.actual,
                "symptom": fault.symptom,
            }
        )
    manifest = {
        "case": spec.name,
        "title": spec.title,
        "fault_count": len(spec.faults),
        "points_total": spec.point_total(),
        "faults": faults,
        "requirements": list(requirements),
        "notes": list(notes),
    }
    return spec, manifest


# ---------------------------------------------------------------------------
# 1. clean-baseline — healthy two-router network, zero faults
# ---------------------------------------------------------------------------

_CLEAN_BASELINE_BRIEF = """\
TWO SITES, ONE TRANSIT

Two site routers are joined by a point-to-point /30. Each owns one LAN and each
PC must reach the far LAN and return. This network is complete: every route and
address described below is already configured and working.

Addressing
  LAN-A     172.16.10.0/24   R1 Gi0/0 .1   PC1 .10   PC2 .11
  LAN-B     172.16.20.0/24   R2 Gi0/0 .1   PC3 .10
  TRANSIT   10.10.12.0/30    R1 Gi0/1 .1   R2 Gi0/1 .2

Required end state
  * R1 has a static route to 172.16.20.0/24 via 10.10.12.2.
  * R2 has a static route to 172.16.10.0/24 via 10.10.12.1.
  * PC1 and PC2 reach PC3, and PC3 reaches both of them.
  * Every interface on the path is up.
"""


def clean_baseline() -> tuple[TopologySpec, dict]:
    devices = [
        _router(
            "R1",
            220,
            150,
            interfaces=(
                ("GigabitEthernet0/0", _lan("172.16.10.1")),
                ("GigabitEthernet0/1", _transit("10.10.12.1")),
            ),
            routing=("ip route 172.16.20.0 255.255.255.0 10.10.12.2",),
        ),
        _router(
            "R2",
            580,
            150,
            interfaces=(
                ("GigabitEthernet0/0", _lan("172.16.20.1")),
                ("GigabitEthernet0/1", _transit("10.10.12.2")),
            ),
            routing=("ip route 172.16.10.0 255.255.255.0 10.10.12.1",),
        ),
        _switch("SW1", 220, 300),
        _pc("PC1", 140, 400, "172.16.10.10", "172.16.10.1"),
        _pc("PC2", 280, 400, "172.16.10.11", "172.16.10.1"),
        _pc("PC3", 580, 400, "172.16.20.10", "172.16.20.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW1", "GigabitEthernet0/1"),
        LinkSpec("SW1", "FastEthernet0/1", "PC1", "FastEthernet0"),
        LinkSpec("SW1", "FastEthernet0/2", "PC2", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "R2", "GigabitEthernet0/1"),
        LinkSpec("R2", "GigabitEthernet0/0", "PC3", "FastEthernet0"),
    ]
    spec = TopologySpec(
        name="clean-baseline",
        title="Clean Baseline — Two Sites, One Transit",
        devices=devices,
        links=links,
        faults=[],
        brief=_CLEAN_BASELINE_BRIEF,
        difficulty="beginner",
    )
    requirements = [
        _requirement("pc1-pc2", "PC1 can ping PC2", "pass"),
        _requirement("pc1-pc3", "PC1 can ping PC3", "pass"),
        _requirement("pc3-pc1", "PC3 can ping PC1", "pass"),
        _requirement("r1-route-b", "R1 has a route to 172.16.20.0/24", "pass"),
        _requirement("r2-route-a", "R2 has a route to 172.16.10.0/24", "pass"),
    ]
    return _build_case(spec, requirements, {}, notes=("false-positive control",))


# ---------------------------------------------------------------------------
# 2. clean-segmented — two subnets that must stay isolated, zero faults
# ---------------------------------------------------------------------------

_CLEAN_SEGMENTED_BRIEF = """\
TWO SEGMENTS THAT MUST NOT MEET

Two business units share a transit link but are deliberately not routed to one
another. Each unit reaches its own gateway and its own peers; neither unit may
reach the other unit's subnet. The isolation is a policy decision, not a
misconfiguration, so no inter-segment route is supposed to exist.

Addressing
  SEG-A     172.16.11.0/24   R1 Gi0/0 .1   PC-A1 .10   PC-A2 .11
  SEG-B     172.16.21.0/24   R2 Gi0/0 .1   PC-B1 .10
  TRANSIT   10.10.13.0/30    R1 Gi0/1 .1   R2 Gi0/1 .2

Required end state
  * PC-A1 and PC-A2 reach each other and their gateway.
  * PC-B1 reaches its gateway.
  * Neither router carries a route to the other segment.
  * PC-A1 cannot reach PC-B1 and PC-B1 cannot reach PC-A1.
"""


def clean_segmented() -> tuple[TopologySpec, dict]:
    devices = [
        _router(
            "R1",
            210,
            150,
            interfaces=(
                ("GigabitEthernet0/0", _lan("172.16.11.1")),
                ("GigabitEthernet0/1", _transit("10.10.13.1")),
            ),
        ),
        _router(
            "R2",
            590,
            150,
            interfaces=(
                ("GigabitEthernet0/0", _lan("172.16.21.1")),
                ("GigabitEthernet0/1", _transit("10.10.13.2")),
            ),
        ),
        _switch("SW-A", 210, 300),
        _switch("SW-B", 590, 300),
        _pc("PC-A1", 120, 400, "172.16.11.10", "172.16.11.1"),
        _pc("PC-A2", 300, 400, "172.16.11.11", "172.16.11.1"),
        _pc("PC-B1", 590, 400, "172.16.21.10", "172.16.21.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW-A", "GigabitEthernet0/1"),
        LinkSpec("SW-A", "FastEthernet0/1", "PC-A1", "FastEthernet0"),
        LinkSpec("SW-A", "FastEthernet0/2", "PC-A2", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "R2", "GigabitEthernet0/1"),
        LinkSpec("R2", "GigabitEthernet0/0", "SW-B", "GigabitEthernet0/1"),
        LinkSpec("SW-B", "FastEthernet0/1", "PC-B1", "FastEthernet0"),
    ]
    spec = TopologySpec(
        name="clean-segmented",
        title="Clean Segmented — Two Isolated Subnets",
        devices=devices,
        links=links,
        faults=[],
        brief=_CLEAN_SEGMENTED_BRIEF,
        difficulty="beginner",
    )
    requirements = [
        _requirement("a1-a2", "PC-A1 can ping PC-A2", "pass"),
        _requirement("a1-gateway", "PC-A1 can ping 172.16.11.1", "pass"),
        _requirement("b1-gateway", "PC-B1 can ping 172.16.21.1", "pass"),
        _requirement("a1-b1", "PC-A1 can ping PC-B1", "fail"),
        _requirement("r1-route-b", "R1 has a route to 172.16.21.0/24", "fail"),
        _requirement("r2-route-a", "R2 has a route to 172.16.11.0/24", "fail"),
    ]
    return _build_case(spec, requirements, {}, notes=("false-positive control",))


# ---------------------------------------------------------------------------
# 3. wrong-gateway — one host points at an address no router owns
# ---------------------------------------------------------------------------

_WRONG_GATEWAY_BRIEF = """\
ONE HOST WITH THE WRONG DOOR

A single LAN is served by R1 and reaches a second site through R2. One PC has
been given a default gateway that is inside the subnet but is not the router.

Addressing
  LAN-A     172.16.30.0/24   R1 Gi0/0 .1   PC1 .10   PC2 .11
  LAN-B     172.16.31.0/24   R2 Gi0/0 .1   PC3 .10
  TRANSIT   10.10.30.0/30    R1 Gi0/1 .1   R2 Gi0/1 .2

Required end state
  * PC1's default gateway is 172.16.30.1, the address held by R1.
  * PC1 and PC2 reach PC3 in both directions.
  * R1 routes to 172.16.31.0/24 and R2 routes to 172.16.30.0/24 over the
    transit link, with reachable next hops.
"""


def wrong_gateway() -> tuple[TopologySpec, dict]:
    faults = rebalance(
        [
            FaultSpec(
                fault_id="gateway-pc1-not-router",
                category=FaultCategory.GATEWAY,
                severity=Severity.MAJOR,
                device="PC1",
                interface="FastEthernet0",
                description=(
                    "PC1's default gateway is 172.16.30.254, an address inside the LAN "
                    "subnet that no interface owns, so PC1 cannot route off-link."
                ),
                expected="172.16.30.1",
                actual="172.16.30.254",
                symptom=(
                    "PC1 pings PC2 on the same subnet but cannot ping PC3 or the gateway "
                    "172.16.30.1; its own IP configuration names 172.16.30.254."
                ),
                points=50,
                hint_1="A host only needs a gateway to leave its own subnet.",
                hint_2="Compare PC1's gateway with the address on R1's LAN interface.",
                target=TargetKind.ENDHOST,
                endhost_field="gateway",
            ),
            FaultSpec(
                fault_id="route-r2-lan-a-unreachable-next-hop",
                category=FaultCategory.ROUTING,
                severity=Severity.CRITICAL,
                device="R2",
                interface=None,
                description=(
                    "R2's route to LAN-A points at 10.10.30.9, which is outside the "
                    "10.10.30.0/30 transit, so the return route is not installed."
                ),
                expected="ip route 172.16.30.0 255.255.255.0 10.10.30.1",
                actual="ip route 172.16.30.0 255.255.255.0 10.10.30.9",
                symptom=(
                    "PC3's echo requests reach LAN-A but the replies never return; "
                    "`show ip route 172.16.30.0` on R2 names 10.10.30.9, which has no "
                    "connected subnet."
                ),
                points=50,
                hint_1="A ping that works one way and not the other is a return-path problem.",
                hint_2="Only 10.10.30.1 and 10.10.30.2 exist on the transit link.",
                target=TargetKind.GLOBAL_LINE,
            ),
        ]
    )
    devices = [
        _router(
            "R1",
            220,
            150,
            interfaces=(
                ("GigabitEthernet0/0", _lan("172.16.30.1")),
                ("GigabitEthernet0/1", _transit("10.10.30.1")),
            ),
            routing=("ip route 172.16.31.0 255.255.255.0 10.10.30.2",),
        ),
        _router(
            "R2",
            580,
            150,
            interfaces=(
                ("GigabitEthernet0/0", _lan("172.16.31.1")),
                ("GigabitEthernet0/1", _transit("10.10.30.2")),
            ),
            routing=("ip route 172.16.30.0 255.255.255.0 10.10.30.1",),
        ),
        _switch("SW1", 220, 300),
        _pc("PC1", 140, 400, "172.16.30.10", "172.16.30.254"),
        _pc("PC2", 300, 400, "172.16.30.11", "172.16.30.1"),
        _pc("PC3", 580, 400, "172.16.31.10", "172.16.31.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW1", "GigabitEthernet0/1"),
        LinkSpec("SW1", "FastEthernet0/1", "PC1", "FastEthernet0"),
        LinkSpec("SW1", "FastEthernet0/2", "PC2", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "R2", "GigabitEthernet0/1"),
        LinkSpec("R2", "GigabitEthernet0/0", "PC3", "FastEthernet0"),
    ]
    spec = TopologySpec(
        name="wrong-gateway",
        title="Wrong Gateway — A Host on the Wrong Door",
        devices=devices,
        links=links,
        faults=faults,
        brief=_WRONG_GATEWAY_BRIEF,
        difficulty="beginner",
    )
    requirements = [
        _requirement("pc1-pc2", "PC1 can ping PC2", "pass"),
        _requirement("pc1-gateway", "PC1 can ping 172.16.30.1", "fail"),
        _requirement("pc1-pc3", "PC1 can ping PC3", "fail"),
        _requirement("pc2-pc3", "PC2 can ping PC3 and receive replies", "fail"),
        _requirement("r1-same-subnet", "PC1 and R1 Gi0/0 share 172.16.30.0/24", "pass"),
    ]
    notes = (
        (
            "pkt_core 0.2.2 does not write <ENGINE><GATEWAY>; the wrong gateway is "
            "authored in the PC NIC spec and may not survive a Packet Tracer load. "
            "The second routing fault is independent of that limitation."
        ),
        "ENDHOST faults are recorded by faulted_configs but not applied to config text.",
    )
    kinds = {
        "gateway-pc1-not-router": "WRONG_GATEWAY",
        "route-r2-lan-a-unreachable-next-hop": "UNREACHABLE_NEXT_HOP",
    }
    return _build_case(spec, requirements, kinds, notes=notes)


# ---------------------------------------------------------------------------
# 4. missing-static-route — a hub router has no route to one spoke LAN
# ---------------------------------------------------------------------------

_MISSING_ROUTE_BRIEF = """\
THE SPOKE NOBODY ROUTED TO

One central router joins two spoke sites. Both spokes can reach the centre and
each other through it. The centre must know every spoke LAN; one of those routes
is absent.

Addressing
  HUB       172.16.40.0/24   R1 Gi0/0 .1   PC-A .10
  SPOKE-B   172.16.41.0/24   R2 Gi0/0 .1   PC-B .10
  SPOKE-C   172.16.42.0/24   R3 Gi0/0 .1   PC-C .10
  R1--R2    10.10.40.0/30    R1 Gi0/1 .1   R2 Gi0/1 .2
  R1--R3    10.10.41.0/30    R1 Gi0/2 .1   R3 Gi0/1 .2

Required end state
  * R1 has a route to 172.16.41.0/24 via 10.10.40.2.
  * R1 has a route to 172.16.42.0/24 via 10.10.41.2.
  * R2 and R3 each route back to the hub LAN and to the other spoke.
  * PC-A reaches PC-B and PC-C.
"""


def missing_static_route() -> tuple[TopologySpec, dict]:
    faults = rebalance(
        [
            FaultSpec(
                fault_id="route-r1-missing-lan-c",
                category=FaultCategory.ROUTING,
                severity=Severity.CRITICAL,
                device="R1",
                interface=None,
                description=(
                    "R1 has no route to SPOKE-C 172.16.42.0/24, so the hub cannot "
                    "forward to that spoke even though the spoke can reach the hub."
                ),
                expected="ip route 172.16.42.0 255.255.255.0 10.10.41.2",
                actual="! ip route 172.16.42.0 255.255.255.0 10.10.41.2",
                symptom=(
                    "`show ip route 172.16.42.0` on R1 reports no matching route; "
                    "PC-A cannot ping PC-C while PC-B can."
                ),
                points=100,
                hint_1="A router only knows the networks directly cabled to it.",
                hint_2="R1 has two remote LANs; check both in `show ip route`.",
                target=TargetKind.GLOBAL_LINE,
            )
        ]
    )
    devices = [
        _router(
            "R1",
            400,
            150,
            interfaces=(
                ("GigabitEthernet0/0", _lan("172.16.40.1")),
                ("GigabitEthernet0/1", _transit("10.10.40.1")),
                ("GigabitEthernet0/2", _transit("10.10.41.1")),
            ),
            routing=(
                "ip route 172.16.41.0 255.255.255.0 10.10.40.2",
                "ip route 172.16.42.0 255.255.255.0 10.10.41.2",
            ),
        ),
        _router(
            "R2",
            180,
            300,
            interfaces=(
                ("GigabitEthernet0/0", _lan("172.16.41.1")),
                ("GigabitEthernet0/1", _transit("10.10.40.2")),
            ),
            routing=(
                "ip route 172.16.40.0 255.255.255.0 10.10.40.1",
                "ip route 172.16.42.0 255.255.255.0 10.10.40.1",
            ),
        ),
        _router(
            "R3",
            620,
            300,
            interfaces=(
                ("GigabitEthernet0/0", _lan("172.16.42.1")),
                ("GigabitEthernet0/1", _transit("10.10.41.2")),
            ),
            routing=(
                "ip route 172.16.40.0 255.255.255.0 10.10.41.1",
                "ip route 172.16.41.0 255.255.255.0 10.10.41.1",
            ),
        ),
        _switch("SW-A", 400, 300),
        _pc("PC-A", 400, 420, "172.16.40.10", "172.16.40.1"),
        _pc("PC-B", 180, 420, "172.16.41.10", "172.16.41.1"),
        _pc("PC-C", 620, 420, "172.16.42.10", "172.16.42.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW-A", "GigabitEthernet0/1"),
        LinkSpec("SW-A", "FastEthernet0/1", "PC-A", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "R2", "GigabitEthernet0/1"),
        LinkSpec("R1", "GigabitEthernet0/2", "R3", "GigabitEthernet0/1"),
        LinkSpec("R2", "GigabitEthernet0/0", "PC-B", "FastEthernet0"),
        LinkSpec("R3", "GigabitEthernet0/0", "PC-C", "FastEthernet0"),
    ]
    spec = TopologySpec(
        name="missing-static-route",
        title="Missing Static Route — The Spoke Nobody Routed To",
        devices=devices,
        links=links,
        faults=faults,
        brief=_MISSING_ROUTE_BRIEF,
        difficulty="intermediate",
    )
    requirements = [
        _requirement("a-b", "PC-A can ping PC-B", "pass"),
        _requirement("a-c", "PC-A can ping PC-C", "fail"),
        _requirement("b-c", "PC-B can ping PC-C", "pass"),
        _requirement("r1-route-c", "R1 has a route to 172.16.42.0/24", "fail"),
        _requirement("r3-route-a", "R3 has a route to 172.16.40.0/24", "pass"),
    ]
    return _build_case(
        spec, requirements, {"route-r1-missing-lan-c": "MISSING_STATIC_ROUTE"}
    )


# ---------------------------------------------------------------------------
# 5. wrong-next-hop — a route points outside every connected subnet
# ---------------------------------------------------------------------------

_WRONG_NEXT_HOP_BRIEF = """\
THE NEXT HOP THAT DOES NOT EXIST

Two routers share a transit link. R2 serves two LANs: an office and a server
farm. R1 must reach both, but one of its static routes names a next hop that is
not on any connected subnet.

Addressing
  LAN-A     172.16.50.0/24   R1 Gi0/0 .1   PC-A .10
  LAN-B     172.16.51.0/24   R2 Gi0/0 .1   PC-B .10
  SERVERS   172.16.52.0/24   R2 Gi0/2 .1   SRV-D .10
  TRANSIT   10.10.50.0/30    R1 Gi0/1 .1   R2 Gi0/1 .2

Required end state
  * R1 reaches SERVERS via 10.10.50.2.
  * R2 reaches LAN-A via 10.10.50.1.
  * PC-A reaches PC-B and SRV-D.
"""


def wrong_next_hop() -> tuple[TopologySpec, dict]:
    faults = rebalance(
        [
            FaultSpec(
                fault_id="route-r1-servers-bad-next-hop",
                category=FaultCategory.ROUTING,
                severity=Severity.CRITICAL,
                device="R1",
                interface=None,
                description=(
                    "R1's route to SERVERS points at 10.10.50.9, an address outside "
                    "the 10.10.50.0/30 transit and owned by no device."
                ),
                expected="ip route 172.16.52.0 255.255.255.0 10.10.50.2",
                actual="ip route 172.16.52.0 255.255.255.0 10.10.50.9",
                symptom=(
                    "`show ip route 172.16.52.0` on R1 names 10.10.50.9, and no "
                    "connected subnet contains that address; SRV-D is unreachable."
                ),
                points=100,
                hint_1="A static route's next hop must be an address on a directly connected subnet.",
                hint_2="The transit link is 10.10.50.0/30: only .1 and .2 are usable.",
                target=TargetKind.GLOBAL_LINE,
            )
        ]
    )
    devices = [
        _router(
            "R1",
            220,
            150,
            interfaces=(
                ("GigabitEthernet0/0", _lan("172.16.50.1")),
                ("GigabitEthernet0/1", _transit("10.10.50.1")),
            ),
            routing=(
                "ip route 172.16.51.0 255.255.255.0 10.10.50.2",
                "ip route 172.16.52.0 255.255.255.0 10.10.50.2",
            ),
        ),
        _router(
            "R2",
            580,
            150,
            interfaces=(
                ("GigabitEthernet0/0", _lan("172.16.51.1")),
                ("GigabitEthernet0/1", _transit("10.10.50.2")),
                ("GigabitEthernet0/2", _lan("172.16.52.1")),
            ),
            routing=("ip route 172.16.50.0 255.255.255.0 10.10.50.1",),
        ),
        _switch("SW-A", 220, 300),
        _pc("PC-A", 220, 420, "172.16.50.10", "172.16.50.1"),
        _pc("PC-B", 580, 300, "172.16.51.10", "172.16.51.1"),
        _server("SRV-D", 580, 420, "172.16.52.10", "172.16.52.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW-A", "GigabitEthernet0/1"),
        LinkSpec("SW-A", "FastEthernet0/1", "PC-A", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "R2", "GigabitEthernet0/1"),
        LinkSpec("R2", "GigabitEthernet0/0", "PC-B", "FastEthernet0"),
        LinkSpec("R2", "GigabitEthernet0/2", "SRV-D", "FastEthernet0"),
    ]
    spec = TopologySpec(
        name="wrong-next-hop",
        title="Wrong Next Hop — A Route to Nowhere",
        devices=devices,
        links=links,
        faults=faults,
        brief=_WRONG_NEXT_HOP_BRIEF,
        difficulty="beginner",
    )
    requirements = [
        _requirement("a-b", "PC-A can ping PC-B", "pass"),
        _requirement("a-srv", "PC-A can ping SRV-D", "fail"),
        _requirement("srv-a", "SRV-D can ping PC-A", "fail"),
        _requirement("r1-route-servers", "R1 has an installed route to 172.16.52.0/24", "fail"),
    ]
    return _build_case(
        spec, requirements, {"route-r1-servers-bad-next-hop": "UNREACHABLE_NEXT_HOP"}
    )


# ---------------------------------------------------------------------------
# 6. broken-return-path — forward works, the reply route is gone
# ---------------------------------------------------------------------------

_BROKEN_RETURN_BRIEF = """\
THE RETURN PATH NOBODY CHECKED

A stub router extends the network beyond a second site. Traffic from LAN-A to
LAN-B leaves R1 over the first transit and reaches R2; the replies must come
back the same way. The forward route exists and the return route does not.

Addressing
  LAN-A     172.16.60.0/24   R1 Gi0/0 .1   PC-A .10
  LAN-B     172.16.61.0/24   R2 Gi0/0 .1   PC-B .10
  LAN-C     172.16.62.0/24   R3 Gi0/0 .1   PC-C .10
  R1--R2    10.10.60.0/30    R1 Gi0/1 .1   R2 Gi0/1 .2
  R2--R3    10.10.61.0/30    R2 Gi0/2 .1   R3 Gi0/1 .2

Required end state
  * R1 reaches LAN-B and LAN-C through R2.
  * R2 reaches LAN-C through R3 and LAN-A through R1.
  * R3 reaches LAN-A and LAN-B through R2.
  * PC-A and PC-B exchange pings in both directions.
"""


def broken_return_path() -> tuple[TopologySpec, dict]:
    faults = rebalance(
        [
            FaultSpec(
                fault_id="route-r2-missing-return-lan-a",
                category=FaultCategory.ROUTING,
                severity=Severity.CRITICAL,
                device="R2",
                interface=None,
                description=(
                    "R2 has no route back to LAN-A 172.16.60.0/24, so replies from "
                    "LAN-B and LAN-C die at R2 while the forward path is intact."
                ),
                expected="ip route 172.16.60.0 255.255.255.0 10.10.60.1",
                actual="! ip route 172.16.60.0 255.255.255.0 10.10.60.1",
                symptom=(
                    "PC-A's echo requests reach PC-B, but PC-B's replies never arrive. "
                    "`show ip route 172.16.60.0` on R2 reports no matching route."
                ),
                points=100,
                hint_1="A flow needs a route in each direction; the reverse of a working route is a different route.",
                hint_2="R2 is the return hop for LAN-A. Does R2 know where LAN-A is?",
                target=TargetKind.GLOBAL_LINE,
            )
        ]
    )
    devices = [
        _router(
            "R1",
            180,
            150,
            interfaces=(
                ("GigabitEthernet0/0", _lan("172.16.60.1")),
                ("GigabitEthernet0/1", _transit("10.10.60.1")),
            ),
            routing=(
                "ip route 172.16.61.0 255.255.255.0 10.10.60.2",
                "ip route 172.16.62.0 255.255.255.0 10.10.60.2",
            ),
        ),
        _router(
            "R2",
            460,
            150,
            interfaces=(
                ("GigabitEthernet0/0", _lan("172.16.61.1")),
                ("GigabitEthernet0/1", _transit("10.10.60.2")),
                ("GigabitEthernet0/2", _transit("10.10.61.1")),
            ),
            routing=(
                "ip route 172.16.60.0 255.255.255.0 10.10.60.1",
                "ip route 172.16.62.0 255.255.255.0 10.10.61.2",
            ),
        ),
        _router(
            "R3",
            740,
            150,
            interfaces=(
                ("GigabitEthernet0/0", _lan("172.16.62.1")),
                ("GigabitEthernet0/1", _transit("10.10.61.2")),
            ),
            routing=(
                "ip route 172.16.60.0 255.255.255.0 10.10.61.1",
                "ip route 172.16.61.0 255.255.255.0 10.10.61.1",
            ),
        ),
        _pc("PC-A", 180, 300, "172.16.60.10", "172.16.60.1"),
        _pc("PC-B", 460, 300, "172.16.61.10", "172.16.61.1"),
        _pc("PC-C", 740, 300, "172.16.62.10", "172.16.62.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "PC-A", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "R2", "GigabitEthernet0/1"),
        LinkSpec("R2", "GigabitEthernet0/0", "PC-B", "FastEthernet0"),
        LinkSpec("R2", "GigabitEthernet0/2", "R3", "GigabitEthernet0/1"),
        LinkSpec("R3", "GigabitEthernet0/0", "PC-C", "FastEthernet0"),
    ]
    spec = TopologySpec(
        name="broken-return-path",
        title="Broken Return Path — Forward Without a Reply",
        devices=devices,
        links=links,
        faults=faults,
        brief=_BROKEN_RETURN_BRIEF,
        difficulty="intermediate",
    )
    requirements = [
        _requirement("a-b", "PC-A can ping PC-B and receive replies", "fail"),
        _requirement("a-c", "PC-A can ping PC-C and receive replies", "fail"),
        _requirement("b-c", "PC-B can ping PC-C and receive replies", "pass"),
        _requirement("r2-route-a", "R2 has a route to 172.16.60.0/24", "fail"),
    ]
    return _build_case(
        spec, requirements, {"route-r2-missing-return-lan-a": "MISSING_RETURN_ROUTE"}
    )


# ---------------------------------------------------------------------------
# 7. admin-shutdown — one switch uplink on the path is disabled
# ---------------------------------------------------------------------------

_ADMIN_SHUTDOWN_BRIEF = """\
THE UPLINK THAT WAS TURNED OFF

A distribution switch serves a PC directly and reaches a second PC through an
edge switch. Every port is configured for the office VLAN. One port on the path
has been administratively disabled.

Addressing
  OFFICE    172.16.70.0/24   R1 Gi0/0 .1
  VLAN      10               name ASH-DIST on SW1, ASH-EDGE on SW2
  PC1                       172.16.70.10   gateway .1
  PC2                       172.16.70.11   gateway .1

Required end state
  * R1 Gi0/0, SW1 Gi0/1, SW1 Fa0/1, SW1 Fa0/2, SW2 Gi0/1 and SW2 Fa0/1 are up.
  * PC1 reaches its gateway and PC2.
  * PC2 reaches its gateway and PC1.
"""


def admin_shutdown() -> tuple[TopologySpec, dict]:
    faults = rebalance(
        [
            FaultSpec(
                fault_id="iface-sw1-uplink-shutdown",
                category=FaultCategory.INTERFACE,
                severity=Severity.MAJOR,
                device="SW1",
                interface="FastEthernet0/2",
                description=(
                    "SW1's uplink to the edge switch is administratively shut down, "
                    "so PC2 is isolated even though every VLAN assignment is correct."
                ),
                expected=" no shutdown",
                actual=" shutdown",
                symptom=(
                    "`show ip interface brief` on SW1 lists Fa0/2 as administratively "
                    "down while Fa0/1 and Gi0/1 are up; PC2 cannot reach its gateway."
                ),
                points=100,
                hint_1="A VLAN can be correct on both switches and still fail if the link between them is down.",
                hint_2="Check the state of every port on the path, not just the access ports.",
                target=TargetKind.INTERFACE_LINE,
            )
        ]
    )
    devices = [
        _router(
            "R1",
            400,
            120,
            interfaces=(("GigabitEthernet0/0", _lan("172.16.70.1")),),
        ),
        _switch(
            "SW1",
            400,
            260,
            interfaces=(
                ("GigabitEthernet0/1", _access(10, description="uplink to R1")),
                ("FastEthernet0/1", _access(10, description="PC1")),
                ("FastEthernet0/2", _access(10, description="uplink to SW2")),
            ),
            vlans=(VlanSpec(10, "ASH-DIST"),),
        ),
        _switch(
            "SW2",
            180,
            400,
            interfaces=(
                ("GigabitEthernet0/1", _access(10, description="uplink to SW1")),
                ("FastEthernet0/1", _access(10, description="PC2")),
            ),
            vlans=(VlanSpec(10, "ASH-EDGE"),),
        ),
        _pc("PC1", 520, 400, "172.16.70.10", "172.16.70.1"),
        _pc("PC2", 180, 520, "172.16.70.11", "172.16.70.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW1", "GigabitEthernet0/1"),
        LinkSpec("SW1", "FastEthernet0/1", "PC1", "FastEthernet0"),
        LinkSpec("SW1", "FastEthernet0/2", "SW2", "GigabitEthernet0/1"),
        LinkSpec("SW2", "FastEthernet0/1", "PC2", "FastEthernet0"),
    ]
    spec = TopologySpec(
        name="admin-shutdown",
        title="Administrative Shutdown — The Disabled Uplink",
        devices=devices,
        links=links,
        faults=faults,
        brief=_ADMIN_SHUTDOWN_BRIEF,
        difficulty="beginner",
    )
    requirements = [
        _requirement("pc1-gateway", "PC1 can ping 172.16.70.1", "pass"),
        _requirement("pc1-pc2", "PC1 can ping PC2", "fail"),
        _requirement("pc2-gateway", "PC2 can ping 172.16.70.1", "fail"),
        _requirement("sw1-fa0-2-up", "SW1 FastEthernet0/2 is up/up", "fail"),
    ]
    return _build_case(
        spec, requirements, {"iface-sw1-uplink-shutdown": "SHUTDOWN_INTERFACE"}
    )


# ---------------------------------------------------------------------------
# 8. vlan-mismatch — a host sits in the wrong access VLAN
# ---------------------------------------------------------------------------

_VLAN_MISMATCH_BRIEF = """\
ONE PORT IN THE WRONG VLAN

A single LAN is carried by one switch in VLAN 10 named VLM-DATA. Two PCs share
the subnet 172.16.80.0/24 and use R1 as their gateway. One access port has been
placed in a different VLAN.

Addressing
  OFFICE    172.16.80.0/24   R1 Gi0/0 .1
  VLAN 10   VLM-DATA         router uplink, PC1, PC2
  VLAN 20   VLM-QUAR         no host is meant to be here
  PC1                       172.16.80.10   gateway .1
  PC2                       172.16.80.11   gateway .1

Required end state
  * SW1 Gi0/1, Fa0/1 and Fa0/2 are access ports in VLAN 10.
  * Both PCs reach the gateway and each other.
"""


def vlan_mismatch() -> tuple[TopologySpec, dict]:
    faults = rebalance(
        [
            FaultSpec(
                fault_id="vlan-sw1-fa0-2-wrong",
                category=FaultCategory.VLAN,
                severity=Severity.MAJOR,
                device="SW1",
                interface="FastEthernet0/2",
                description=(
                    "PC2's access port is in VLAN 20 while the router uplink and PC1 "
                    "are in VLAN 10, so PC2 is isolated from its own subnet."
                ),
                expected=" switchport access vlan 10",
                actual=" switchport access vlan 20",
                symptom=(
                    "`show vlan brief` on SW1 lists Fa0/2 under VLAN 20; PC2 cannot "
                    "ping its gateway while PC1 can."
                ),
                points=100,
                hint_1="Two hosts in the same subnet must be in the same VLAN at the access layer.",
                hint_2="Compare the VLAN of each access port with the port that faces the router.",
                target=TargetKind.INTERFACE_LINE,
            )
        ]
    )
    devices = [
        _router(
            "R1",
            400,
            120,
            interfaces=(("GigabitEthernet0/0", _lan("172.16.80.1")),),
        ),
        _switch(
            "SW1",
            400,
            280,
            interfaces=(
                ("GigabitEthernet0/1", _access(10, description="uplink to R1")),
                ("FastEthernet0/1", _access(10, description="PC1")),
                ("FastEthernet0/2", _access(10, description="PC2")),
            ),
            vlans=(VlanSpec(10, "VLM-DATA"), VlanSpec(20, "VLM-QUAR")),
        ),
        _pc("PC1", 300, 440, "172.16.80.10", "172.16.80.1"),
        _pc("PC2", 500, 440, "172.16.80.11", "172.16.80.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW1", "GigabitEthernet0/1"),
        LinkSpec("SW1", "FastEthernet0/1", "PC1", "FastEthernet0"),
        LinkSpec("SW1", "FastEthernet0/2", "PC2", "FastEthernet0"),
    ]
    spec = TopologySpec(
        name="vlan-mismatch",
        title="VLAN Mismatch — One Port, Wrong Segment",
        devices=devices,
        links=links,
        faults=faults,
        brief=_VLAN_MISMATCH_BRIEF,
        difficulty="beginner",
    )
    requirements = [
        _requirement("pc1-pc2", "PC1 can ping PC2", "fail"),
        _requirement("pc1-gateway", "PC1 can ping 172.16.80.1", "pass"),
        _requirement("pc2-gateway", "PC2 can ping 172.16.80.1", "fail"),
        _requirement("fa0-2-vlan", "SW1 FastEthernet0/2 is in VLAN 10", "fail"),
    ]
    return _build_case(spec, requirements, {"vlan-sw1-fa0-2-wrong": "WRONG_VLAN"})


# ---------------------------------------------------------------------------
# 9. acl-deny — policy is enforced by an ACL that denies everything
# ---------------------------------------------------------------------------

_ACL_DENY_BRIEF = """\
THE POLICY THAT SWALLOWED ITSELF

A client LAN must reach a server LAN through one router. Policy is one-way:
the client subnet may reach the server subnet, and that is the only flow the
ACL is meant to permit. The ACL is bound to the server-facing interface.

Addressing
  CLIENTS   172.16.90.0/24   R1 Gi0/0 .1   PC-CLIENT .10
  SERVERS   172.16.91.0/24   R1 Gi0/1 .1   SRV .10
  ACL 110   permits 172.16.90.0/24 -> 172.16.91.0/24

Required end state
  * ACL 110 is applied inbound on R1 Gi0/1.
  * ACL 110 contains a permit for the client-to-server flow.
  * PC-CLIENT reaches SRV, and SRV's replies return.
"""


def acl_deny() -> tuple[TopologySpec, dict]:
    permit = "access-list 110 permit ip 172.16.90.0 0.0.0.255 172.16.91.0 0.0.0.255"
    faults = rebalance(
        [
            FaultSpec(
                fault_id="acl-110-deny-all",
                category=FaultCategory.SECURITY,
                severity=Severity.CRITICAL,
                device="R1",
                interface=None,
                description=(
                    "ACL 110's permit has been replaced by `deny ip any any`, so the "
                    "bound ACL blocks the only required client-to-server flow."
                ),
                expected=permit,
                actual="access-list 110 deny ip any any",
                symptom=(
                    "`show access-lists` on R1 shows a single deny and no permit; "
                    "PC-CLIENT cannot reach SRV even though the router has both "
                    "networks directly connected."
                ),
                points=100,
                hint_1="Directly connected routes plus zero connectivity points at a filter.",
                hint_2="Check the ACL bound to Gi0/1 and read its entries in order.",
                target=TargetKind.GLOBAL_LINE,
            )
        ]
    )
    devices = [
        _router(
            "R1",
            400,
            200,
            interfaces=(
                ("GigabitEthernet0/0", _lan("172.16.90.1")),
                (
                    "GigabitEthernet0/1",
                    (
                        " description access-group 110 inbound",
                        *_lan("172.16.91.1"),
                        " ip access-group 110 in",
                    ),
                ),
            ),
            routing=(permit,),
        ),
        _switch("SW1", 400, 340),
        _pc("PC-CLIENT", 400, 460, "172.16.90.10", "172.16.90.1"),
        _server("SRV", 620, 200, "172.16.91.10", "172.16.91.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW1", "GigabitEthernet0/1"),
        LinkSpec("SW1", "FastEthernet0/1", "PC-CLIENT", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "SRV", "FastEthernet0"),
    ]
    spec = TopologySpec(
        name="acl-deny",
        title="ACL Deny — Policy That Blocks the Required Flow",
        devices=devices,
        links=links,
        faults=faults,
        brief=_ACL_DENY_BRIEF,
        difficulty="intermediate",
    )
    requirements = [
        _requirement("client-srv", "PC-CLIENT can ping SRV", "fail"),
        _requirement("srv-client", "SRV can ping PC-CLIENT", "fail"),
        _requirement("acl-bound", "ACL 110 is applied inbound on R1 Gi0/1", "pass"),
        _requirement("acl-permit", "ACL 110 permits 172.16.90.0/24 -> 172.16.91.0/24", "fail"),
    ]
    return _build_case(spec, requirements, {"acl-110-deny-all": "ACL_BLOCK"})


# ---------------------------------------------------------------------------
# 10. multi-fault — three simultaneous defects on three devices
# ---------------------------------------------------------------------------

_MULTI_FAULT_BRIEF = """\
THREE PROBLEMS, THREE DEVICES

A head office LAN is carried by an access switch and reaches two remote LANs
through a second router. Three independent defects are present at the same
time, each on a different device: one at the access layer, one in routing, and
one in policy.

Addressing
  HQ        172.16.100.0/24  R1 Gi0/0 .1   PC-A1 .10   PC-A2 .11
  REMOTE    172.16.110.0/24  R2 Gi0/0 .1   PC-B .10
  LAB       172.16.111.0/24  R2 Gi0/2 .1   PC-C .10
  TRANSIT   10.10.100.0/30   R1 Gi0/1 .1   R2 Gi0/1 .2
  VLAN      10 MF-DATA, 20 MF-QUAR on SW1

Required end state
  * SW1 Gi0/1, Fa0/1 and Fa0/2 are access ports in VLAN 10.
  * R1 routes to both 172.16.110.0/24 and 172.16.111.0/24 via 10.10.100.2.
  * R2 routes to 172.16.100.0/24 via 10.10.100.1.
  * ACL 120 permits 172.16.110.0/24 -> 172.16.100.0/24 and is applied inbound
    on R2 Gi0/0.
  * PC-A1 reaches PC-B and PC-C; PC-A2 reaches PC-B and PC-C.
"""


def multi_fault() -> tuple[TopologySpec, dict]:
    permit = "access-list 120 permit ip 172.16.110.0 0.0.0.255 172.16.100.0 0.0.0.255"
    faults = rebalance(
        [
            FaultSpec(
                fault_id="vlan-sw1-fa0-2-wrong",
                category=FaultCategory.VLAN,
                severity=Severity.MAJOR,
                device="SW1",
                interface="FastEthernet0/2",
                description=(
                    "PC-A2's access port is in VLAN 20 while the uplink and PC-A1 are "
                    "in VLAN 10, isolating PC-A2 from the HQ subnet."
                ),
                expected=" switchport access vlan 10",
                actual=" switchport access vlan 20",
                symptom=(
                    "`show vlan brief` on SW1 lists Fa0/2 under VLAN 20; PC-A2 cannot "
                    "reach its gateway or PC-A1."
                ),
                points=40,
                hint_1="Start with the access layer: are both hosts in the VLAN that faces the router?",
                hint_2="Compare Fa0/2's VLAN with Gi0/1 and Fa0/1.",
                target=TargetKind.INTERFACE_LINE,
            ),
            FaultSpec(
                fault_id="route-r1-missing-lab",
                category=FaultCategory.ROUTING,
                severity=Severity.CRITICAL,
                device="R1",
                interface=None,
                description=(
                    "R1 has no route to LAB 172.16.111.0/24, so HQ cannot reach the "
                    "lab LAN even though REMOTE still works."
                ),
                expected="ip route 172.16.111.0 255.255.255.0 10.10.100.2",
                actual="! ip route 172.16.111.0 255.255.255.0 10.10.100.2",
                symptom=(
                    "`show ip route 172.16.111.0` on R1 reports no matching route; "
                    "PC-A1 reaches PC-B but not PC-C."
                ),
                points=35,
                hint_1="A working remote LAN does not prove both remote LANs are routed.",
                hint_2="Check every `ip route` on R1 against the two remote prefixes.",
                target=TargetKind.GLOBAL_LINE,
            ),
            FaultSpec(
                fault_id="acl-120-deny-all",
                category=FaultCategory.SECURITY,
                severity=Severity.CRITICAL,
                device="R2",
                interface=None,
                description=(
                    "ACL 120's permit is replaced by `deny ip any any`, blocking the "
                    "required REMOTE-to-HQ flow at the policy layer."
                ),
                expected=permit,
                actual="access-list 120 deny ip any any",
                symptom=(
                    "`show access-lists` on R2 shows a single deny; PC-B cannot reach "
                    "PC-A1 even after the VLAN and route defects are considered."
                ),
                points=25,
                hint_1="After routing is correct, a filter can still swallow the flow.",
                hint_2="Check ACL 120's entries and its binding on R2 Gi0/0.",
                target=TargetKind.GLOBAL_LINE,
            ),
        ]
    )
    devices = [
        _router(
            "R1",
            220,
            160,
            interfaces=(
                ("GigabitEthernet0/0", _lan("172.16.100.1")),
                ("GigabitEthernet0/1", _transit("10.10.100.1")),
            ),
            routing=(
                "ip route 172.16.110.0 255.255.255.0 10.10.100.2",
                "ip route 172.16.111.0 255.255.255.0 10.10.100.2",
            ),
        ),
        _router(
            "R2",
            620,
            160,
            interfaces=(
                (
                    "GigabitEthernet0/0",
                    (
                        " description access-group 120 inbound",
                        *_lan("172.16.110.1"),
                        " ip access-group 120 in",
                    ),
                ),
                ("GigabitEthernet0/1", _transit("10.10.100.2")),
                ("GigabitEthernet0/2", _lan("172.16.111.1")),
            ),
            routing=(
                "ip route 172.16.100.0 255.255.255.0 10.10.100.1",
                permit,
            ),
        ),
        _switch(
            "SW1",
            220,
            320,
            interfaces=(
                ("GigabitEthernet0/1", _access(10, description="uplink to R1")),
                ("FastEthernet0/1", _access(10, description="PC-A1")),
                ("FastEthernet0/2", _access(10, description="PC-A2")),
            ),
            vlans=(VlanSpec(10, "MF-DATA"), VlanSpec(20, "MF-QUAR")),
        ),
        _pc("PC-A1", 140, 460, "172.16.100.10", "172.16.100.1"),
        _pc("PC-A2", 300, 460, "172.16.100.11", "172.16.100.1"),
        _pc("PC-B", 620, 320, "172.16.110.10", "172.16.110.1"),
        _pc("PC-C", 620, 440, "172.16.111.10", "172.16.111.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW1", "GigabitEthernet0/1"),
        LinkSpec("SW1", "FastEthernet0/1", "PC-A1", "FastEthernet0"),
        LinkSpec("SW1", "FastEthernet0/2", "PC-A2", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "R2", "GigabitEthernet0/1"),
        LinkSpec("R2", "GigabitEthernet0/0", "PC-B", "FastEthernet0"),
        LinkSpec("R2", "GigabitEthernet0/2", "PC-C", "FastEthernet0"),
    ]
    spec = TopologySpec(
        name="multi-fault",
        title="Multi-Fault — Three Defects on Three Devices",
        devices=devices,
        links=links,
        faults=faults,
        brief=_MULTI_FAULT_BRIEF,
        difficulty="advanced",
    )
    requirements = [
        _requirement("a1-b", "PC-A1 can ping PC-B", "fail"),
        _requirement("a1-c", "PC-A1 can ping PC-C", "fail"),
        _requirement("a2-b", "PC-A2 can ping PC-B", "fail"),
        _requirement("a1-a2", "PC-A1 can ping PC-A2", "fail"),
        _requirement("b-gateway", "PC-B can ping 172.16.110.1", "pass"),
        _requirement("c-gateway", "PC-C can ping 172.16.111.1", "pass"),
        _requirement("r1-route-lab", "R1 has a route to 172.16.111.0/24", "fail"),
        _requirement("acl-120-permit", "ACL 120 permits 172.16.110.0/24 -> 172.16.100.0/24", "fail"),
    ]
    kinds = {
        "vlan-sw1-fa0-2-wrong": "WRONG_VLAN",
        "route-r1-missing-lab": "MISSING_STATIC_ROUTE",
        "acl-120-deny-all": "ACL_BLOCK",
    }
    return _build_case(spec, requirements, kinds)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

CASES: dict[str, tuple[TopologySpec, dict]] = {
    "clean-baseline": clean_baseline(),
    "clean-segmented": clean_segmented(),
    "wrong-gateway": wrong_gateway(),
    "missing-static-route": missing_static_route(),
    "wrong-next-hop": wrong_next_hop(),
    "broken-return-path": broken_return_path(),
    "admin-shutdown": admin_shutdown(),
    "vlan-mismatch": vlan_mismatch(),
    "acl-deny": acl_deny(),
    "multi-fault": multi_fault(),
}

CASE_NAMES: tuple[str, ...] = tuple(CASES)
CLEAN_CASES: tuple[str, ...] = ("clean-baseline", "clean-segmented")
FAULTED_CASES: tuple[str, ...] = tuple(name for name in CASE_NAMES if name not in CLEAN_CASES)


def case(name: str) -> tuple[TopologySpec, dict]:
    """One case by name; ``KeyError`` lists the valid names."""
    try:
        return CASES[name]
    except KeyError:
        raise KeyError(f"unknown validation case {name!r}; choose from {', '.join(CASE_NAMES)}") from None


def blind_manifest() -> dict[str, dict]:
    """What a blind run may see: topology and intent, never the defect list.

    The manifest deliberately omits faults, points, expected values, actual
    values, symptoms and hints. Requirements state observable outcomes only.
    """
    out: dict[str, dict] = {}
    for name, (spec, manifest) in CASES.items():
        out[name] = {
            "case": spec.name,
            "title": spec.title,
            "difficulty": spec.difficulty,
            "brief": spec.brief,
            "devices": [
                {"name": device.name, "model": device.model, "role": device.role.value}
                for device in spec.devices
            ],
            "links": [
                {"a": link.a, "a_port": link.a_port, "b": link.b, "b_port": link.b_port}
                for link in spec.links
            ],
            "requirements": [dict(requirement) for requirement in manifest["requirements"]],
        }
    return out


def ground_truth() -> dict[str, dict]:
    """The private manifests. Test-only: never ship this to a blind run."""
    return {
        name: {
            "case": manifest["case"],
            "title": manifest["title"],
            "fault_count": manifest["fault_count"],
            "points_total": manifest["points_total"],
            "faults": [dict(fault) for fault in manifest["faults"]],
            "requirements": [dict(requirement) for requirement in manifest["requirements"]],
            "notes": list(manifest["notes"]),
        }
        for name, (_spec, manifest) in CASES.items()
    }


__all__ = [
    "CASES",
    "CASE_NAMES",
    "CLEAN_CASES",
    "FAULTED_CASES",
    "blind_manifest",
    "case",
    "ground_truth",
]
