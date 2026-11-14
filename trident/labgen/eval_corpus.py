"""A second, independent evaluation corpus and an equivalence-aware scorer.

This module is deliberately *new*. It does not reuse, import or derive from
:mod:`trident.labgen.validation_set`, the six-level gauntlet, Broken Campus or
the CCNA3 labs. The twelve cases below use different addressing, different
device counts and different topology shapes, and none of them was used to tune
a detector. They exist to measure, not to teach.

Why a second corpus
-------------------
``validation_set`` was authored after the detectors it exercises. Even with the
best intent, a set written beside an engine is a regression suite. This one is
authored independently, with its own addressing plan, so that an accuracy figure
taken here is not a restatement of a figure taken there. In particular it
contains the three controls that broke earlier heuristics: a single-router LAN,
a two-router network with **no default route anywhere**, and an ISP edge router
whose *only* route is a default and which correctly holds no private routes.

The twelve cases
----------------
1.  ``healthy-single-router``      control, 0 faults
2.  ``healthy-no-default``         control, 0 faults (the shape that broke the
                                   naive "every router needs a default" rule)
3.  ``isp-edge-legit``             control, 0 faults (public-only ISP edge)
4.  ``missing-forward``            1 fault
5.  ``missing-return``             1 fault
6.  ``wrong-next-hop``             1 fault
7.  ``admin-shutdown``             1 fault
8.  ``gateway-fault``              1 fault (load-durability unverified)
9.  ``acl-intentional-isolation``  control, 0 faults (permit-list isolation)
10. ``acl-accidental-deny``        1 fault
11. ``multi-fault``                3 faults (40 + 30 + 30 = 100)
12. ``transit-three-routers``      1 fault

Conventions
-----------
* A faulted case scores **exactly 100 points**. A control carries **zero
  faults** and scores zero. There is no third convention.
* A private manifest records every fault with device, interface, kind,
  expected and actual, plus the observable ``requirements`` and a ``control``
  flag. ``blind_view`` exposes topology and requirements only.
* End-host faults are declared with ``TargetKind.ENDHOST`` and the faulty value
  is authored directly into ``DeviceSpec.pc_ip``: ``pkt_core`` 0.2.2 cannot
  rewrite a NIC after the spec is built. The manifest says so.
* ``pkt_core`` 0.2.2 does not write ``<ENGINE><GATEWAY>``, so the gateway fault
  may not survive a Packet Tracer load. It is recorded as
  ``load-durability: unverified`` and is still built.

Equivalence-aware scoring
-------------------------
A finding is a *claim about where a defect lives*, and two claims can name the
same defect from different, equally correct angles. Scoring a single string
match per fault therefore under-counts correct work. The rules are fixed
**before** scoring and live here, not in a caller, so a score cannot be
improvised to fit a result.

The four attribution rules
--------------------------
a. **Duplicate IP, any holder.** A duplicate-address fault is equivalent when
   the finding names *any* holder of the duplicated address. Both interfaces
   are genuinely wrong; naming the second one is not an error. ``truth`` may
   carry ``holders`` (a list of device names); when it does, membership decides.
b. **Two-ended trunk, either end.** A trunk fault exists on a link, and both
   ends are true statements about it. The finding matches when it names either
   endpoint. ``truth`` may carry ``ends`` (``[{device, interface}, ...]``).
c. **Device-level route, router only.** A static-route fault is a property of
   the *router's routing table*, not of one interface. When the finding names
   the correct router, the interface field is ignored. The device must match.
d. **Interface fault, device and interface.** An interface fault is equivalent
   only when *both* the device and the interface match. Nothing weaker counts.

Anything else (gateway, ACL, VLAN, DHCP, DNS, …) is device-level: the device
must match, and if the truth names an interface it must match too.

Kind compatibility is a gate before the attribution rules. Kinds match exactly,
unless ``rules["kind_aliases"]`` maps a truth kind to acceptable synonyms.

``score`` never returns a bare percentage. It returns integer TP/FP/FN counts
and ``{numerator, denominator}`` fractions for recall and precision, plus
separate ``correct_device`` and ``correct_interface`` attribution counts.
"""

from __future__ import annotations

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
)

_ROUTER_MODEL = "2911"
_SWITCH_MODEL = "2960-24TT"
_PC_MODEL = "PC-PT"

_ENABLE_SECRET = "EvalCorpus!23"
_USER_SECRET = "EvalCorpusAdmin!23"

#: Router management baseline. It is written *before* routing lines on purpose:
#: the normaliser keeps an ``interface`` block open until a ``!`` or ``line``
#: block, so routes written straight after an interface are swallowed.
_MGMT: tuple[str, ...] = (
    "line con 0",
    " logging synchronous",
    "line vty 0 4",
    " login local",
    " transport input ssh",
)


# ---------------------------------------------------------------------------
# Device builders
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


def _switch(name: str, x: int, y: int) -> DeviceSpec:
    """An unmanaged access switch: no vty, so weak-management is out of scope."""
    return DeviceSpec(
        name=name,
        model=_SWITCH_MODEL,
        role=DeviceRole.SWITCH,
        x=x,
        y=y,
        globals=(f"hostname {name}", f"enable secret {_ENABLE_SECRET}"),
        vlans=(),
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


def _lan(address: str) -> tuple[str, ...]:
    return (f" ip address {address} 255.255.255.0", " no shutdown")


def _transit(address: str) -> tuple[str, ...]:
    return (f" ip address {address} 255.255.255.252", " no shutdown")


def _requirement(identifier: str, check: str, expect: str) -> dict[str, str]:
    return {"id": identifier, "check": check, "expect": expect}


# ---------------------------------------------------------------------------
# Manifest assembly
# ---------------------------------------------------------------------------


def _build_case(
    spec: TopologySpec,
    requirements: list[dict[str, str]],
    kinds: dict[str, str],
    *,
    control: bool,
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
        "control": control,
        "fault_count": len(spec.faults),
        "points_total": spec.point_total(),
        "faults": faults,
        "requirements": [dict(requirement) for requirement in requirements],
        "notes": list(notes),
    }
    return spec, manifest


# ---------------------------------------------------------------------------
# 1. healthy-single-router — one LAN, one router, zero faults
# ---------------------------------------------------------------------------

_SINGLE_ROUTER_BRIEF = """\
ONE ROOM, ONE ROUTER

A single router serves one small LAN. Both PCs sit behind an access switch and
use the router as their gateway. Nothing is wrong with this network: every
address, mask and gateway described here is already configured and working.

Addressing
  LAN        192.168.77.0/24   R1 Gi0/0 .1   PC1 .10   PC2 .11

Required end state
  * PC1 and PC2 reach each other.
  * Both PCs use 192.168.77.1 as their default gateway.
  * R1 Gi0/0 is up.
"""


def healthy_single_router() -> tuple[TopologySpec, dict]:
    devices = [
        _router(
            "R1",
            240,
            140,
            interfaces=(("GigabitEthernet0/0", _lan("192.168.77.1")),),
        ),
        _switch("SW1", 240, 290),
        _pc("PC1", 160, 400, "192.168.77.10", "192.168.77.1"),
        _pc("PC2", 320, 400, "192.168.77.11", "192.168.77.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW1", "GigabitEthernet0/1"),
        LinkSpec("SW1", "FastEthernet0/1", "PC1", "FastEthernet0"),
        LinkSpec("SW1", "FastEthernet0/2", "PC2", "FastEthernet0"),
    ]
    spec = TopologySpec(
        name="healthy-single-router",
        title="Healthy Single Router — One LAN",
        devices=devices,
        links=links,
        faults=[],
        brief=_SINGLE_ROUTER_BRIEF,
        difficulty="beginner",
    )
    requirements = [
        _requirement("pc1-pc2", "PC1 can ping PC2", "pass"),
        _requirement("pc1-gateway", "PC1 can ping its default gateway", "pass"),
        _requirement("pc2-gateway", "PC2 can ping its default gateway", "pass"),
    ]
    return _build_case(spec, requirements, {}, control=True, notes=("false-positive control",))


# ---------------------------------------------------------------------------
# 2. healthy-no-default — two routers, no default route anywhere
# ---------------------------------------------------------------------------

_NO_DEFAULT_BRIEF = """\
TWO SITES, EXPLICIT ROUTES, NO DEFAULT

Two site routers are joined by a point-to-point /30. Each owns one LAN and each
has an explicit static route to the other LAN. There is no default route on
either router — and that is correct: every destination is known, so a default
route would be an unnecessary catch-all. This network is complete.

Addressing
  LAN-A      10.72.11.0/24   R1 Gi0/0 .1   PC1 .10   PC2 .11
  LAN-B      10.72.22.0/24   R2 Gi0/0 .1   PC3 .10
  TRANSIT    10.72.1.0/30    R1 Gi0/1 .1   R2 Gi0/1 .2

Required end state
  * R1 has a static route to 10.72.22.0/24 via 10.72.1.2.
  * R2 has a static route to 10.72.11.0/24 via 10.72.1.1.
  * Neither router has a default route; neither needs one.
  * PC1, PC2 and PC3 all reach each other.
"""


def healthy_no_default() -> tuple[TopologySpec, dict]:
    devices = [
        _router(
            "R1",
            220,
            140,
            interfaces=(
                ("GigabitEthernet0/0", _lan("10.72.11.1")),
                ("GigabitEthernet0/1", _transit("10.72.1.1")),
            ),
            routing=("ip route 10.72.22.0 255.255.255.0 10.72.1.2",),
        ),
        _router(
            "R2",
            600,
            140,
            interfaces=(
                ("GigabitEthernet0/0", _lan("10.72.22.1")),
                ("GigabitEthernet0/1", _transit("10.72.1.2")),
            ),
            routing=("ip route 10.72.11.0 255.255.255.0 10.72.1.1",),
        ),
        _switch("SW1", 220, 290),
        _switch("SW2", 600, 290),
        _pc("PC1", 140, 400, "10.72.11.10", "10.72.11.1"),
        _pc("PC2", 300, 400, "10.72.11.11", "10.72.11.1"),
        _pc("PC3", 600, 400, "10.72.22.10", "10.72.22.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW1", "GigabitEthernet0/1"),
        LinkSpec("SW1", "FastEthernet0/1", "PC1", "FastEthernet0"),
        LinkSpec("SW1", "FastEthernet0/2", "PC2", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "R2", "GigabitEthernet0/1"),
        LinkSpec("R2", "GigabitEthernet0/0", "SW2", "GigabitEthernet0/1"),
        LinkSpec("SW2", "FastEthernet0/1", "PC3", "FastEthernet0"),
    ]
    spec = TopologySpec(
        name="healthy-no-default",
        title="Healthy Two-Site Network — No Default Route",
        devices=devices,
        links=links,
        faults=[],
        brief=_NO_DEFAULT_BRIEF,
        difficulty="beginner",
    )
    requirements = [
        _requirement("pc1-pc3", "PC1 can ping PC3", "pass"),
        _requirement("pc3-pc1", "PC3 can ping PC1", "pass"),
        _requirement("r1-route-b", "R1 has a route to 10.72.22.0/24", "pass"),
        _requirement("r2-route-a", "R2 has a route to 10.72.11.0/24", "pass"),
        _requirement("r1-no-default", "R1 has no default route, and needs none", "pass"),
        _requirement("r2-no-default", "R2 has no default route, and needs none", "pass"),
    ]
    return _build_case(spec, requirements, {}, control=True, notes=("false-positive control",))


# ---------------------------------------------------------------------------
# 3. isp-edge-legit — public-only ISP edge with only a default route
# ---------------------------------------------------------------------------

_ISP_BRIEF = """\
ENTERPRISE EDGE MEETS A PUBLIC ISP

An enterprise router advertises one private LAN toward a public ISP. The ISP
edge router is correct exactly as configured: it has a default route toward its
upstream provider and **no routes to private networks**, because it is not
supposed to know them. The enterprise router has a default route toward the ISP.
This network is working as designed.

Addressing
  LAN        10.73.10.0/24      R1 Gi0/0 .1   PC1 .10   PC2 .11
  WAN        203.0.113.0/30     R1 Gi0/1 .2   ISP-EDGE Gi0/0 .1
  UPLINK     198.51.100.0/30    ISP-EDGE Gi0/1 .1   ISP-CORE Gi0/0 .2

Required end state
  * R1 has a default route via 203.0.113.1.
  * ISP-EDGE has a default route via 198.51.100.2.
  * ISP-EDGE holds no route to any private network; that is correct.
  * PC1 and PC2 reach their gateway.
"""


def isp_edge_legit() -> tuple[TopologySpec, dict]:
    devices = [
        _router(
            "R1",
            200,
            130,
            interfaces=(
                ("GigabitEthernet0/0", _lan("10.73.10.1")),
                ("GigabitEthernet0/1", _transit("203.0.113.2")),
            ),
            routing=("ip route 0.0.0.0 0.0.0.0 203.0.113.1",),
        ),
        _router(
            "ISP-EDGE",
            500,
            130,
            interfaces=(
                ("GigabitEthernet0/0", _transit("203.0.113.1")),
                ("GigabitEthernet0/1", _transit("198.51.100.1")),
            ),
            routing=("ip route 0.0.0.0 0.0.0.0 198.51.100.2",),
        ),
        _router(
            "ISP-CORE",
            760,
            130,
            interfaces=(("GigabitEthernet0/0", _transit("198.51.100.2")),),
        ),
        _switch("SW1", 200, 280),
        _pc("PC1", 120, 390, "10.73.10.10", "10.73.10.1"),
        _pc("PC2", 280, 390, "10.73.10.11", "10.73.10.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW1", "GigabitEthernet0/1"),
        LinkSpec("SW1", "FastEthernet0/1", "PC1", "FastEthernet0"),
        LinkSpec("SW1", "FastEthernet0/2", "PC2", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "ISP-EDGE", "GigabitEthernet0/0"),
        LinkSpec("ISP-EDGE", "GigabitEthernet0/1", "ISP-CORE", "GigabitEthernet0/0"),
    ]
    spec = TopologySpec(
        name="isp-edge-legit",
        title="ISP Edge — Public-Only Default Route",
        devices=devices,
        links=links,
        faults=[],
        brief=_ISP_BRIEF,
        difficulty="intermediate",
    )
    requirements = [
        _requirement("pc1-gateway", "PC1 can ping its default gateway", "pass"),
        _requirement("r1-default", "R1 has a default route via 203.0.113.1", "pass"),
        _requirement("isp-default", "ISP-EDGE has a default route via 198.51.100.2", "pass"),
        _requirement(
            "isp-no-private",
            "ISP-EDGE holds no route to a private network",
            "pass",
        ),
    ]
    return _build_case(
        spec,
        requirements,
        {},
        control=True,
        notes=("false-positive control", "public-only ISP edge"),
    )


# ---------------------------------------------------------------------------
# 4. missing-forward — router lacks the forward route to a remote LAN
# ---------------------------------------------------------------------------

_MISSING_FORWARD_BRIEF = """\
TWO LANs, ONE TRANSIT

Two routers share a point-to-point /30 and each owns one LAN. Every PC should be
able to reach every other PC, and each router should carry a route to the far
LAN.

Addressing
  LAN-A      10.74.10.0/24   R1 Gi0/0 .1   PC1 .10   PC2 .11
  LAN-B      10.74.20.0/24   R2 Gi0/0 .1   PC3 .10
  TRANSIT    10.74.1.0/30    R1 Gi0/1 .1   R2 Gi0/1 .2

Required end state
  * R1 has a route to 10.74.20.0/24 via 10.74.1.2.
  * R2 has a route to 10.74.10.0/24 via 10.74.1.1.
  * PC1, PC2 and PC3 all reach each other.
"""


def missing_forward() -> tuple[TopologySpec, dict]:
    route = "ip route 10.74.20.0 255.255.255.0 10.74.1.2"
    devices = [
        _router(
            "R1",
            220,
            130,
            interfaces=(
                ("GigabitEthernet0/0", _lan("10.74.10.1")),
                ("GigabitEthernet0/1", _transit("10.74.1.1")),
            ),
            routing=(route,),
        ),
        _router(
            "R2",
            600,
            130,
            interfaces=(
                ("GigabitEthernet0/0", _lan("10.74.20.1")),
                ("GigabitEthernet0/1", _transit("10.74.1.2")),
            ),
            routing=("ip route 10.74.10.0 255.255.255.0 10.74.1.1",),
        ),
        _switch("SW1", 220, 280),
        _switch("SW2", 600, 280),
        _pc("PC1", 140, 390, "10.74.10.10", "10.74.10.1"),
        _pc("PC2", 300, 390, "10.74.10.11", "10.74.10.1"),
        _pc("PC3", 600, 390, "10.74.20.10", "10.74.20.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW1", "GigabitEthernet0/1"),
        LinkSpec("SW1", "FastEthernet0/1", "PC1", "FastEthernet0"),
        LinkSpec("SW1", "FastEthernet0/2", "PC2", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "R2", "GigabitEthernet0/1"),
        LinkSpec("R2", "GigabitEthernet0/0", "SW2", "GigabitEthernet0/1"),
        LinkSpec("SW2", "FastEthernet0/1", "PC3", "FastEthernet0"),
    ]
    fault = FaultSpec(
        fault_id="F1",
        category=FaultCategory.ROUTING,
        severity=Severity.CRITICAL,
        device="R1",
        interface=None,
        description="R1 is missing the forward static route to the remote LAN.",
        expected=route,
        actual="!",
        symptom="PC1 and PC2 cannot reach PC3; PC3's replies die at R1.",
        points=100,
        hint_1="Compare R1's routing table with R2's.",
        hint_2="R1 knows how to leave the LAN but not how to reach LAN-B.",
        target=TargetKind.GLOBAL_LINE,
    )
    spec = TopologySpec(
        name="missing-forward",
        title="Missing Forward Route",
        devices=devices,
        links=links,
        faults=[fault],
        brief=_MISSING_FORWARD_BRIEF,
        difficulty="beginner",
    )
    requirements = [
        _requirement("pc1-pc2", "PC1 can ping PC2", "pass"),
        _requirement("pc1-pc3", "PC1 can ping PC3", "fail"),
        _requirement("pc3-pc1", "PC3 can ping PC1", "fail"),
        _requirement("r1-route-b", "R1 has a route to 10.74.20.0/24", "fail"),
    ]
    return _build_case(spec, requirements, {"F1": "MISSING_FORWARD_ROUTE"}, control=False)


# ---------------------------------------------------------------------------
# 5. missing-return — forward route present, return route absent
# ---------------------------------------------------------------------------

_MISSING_RETURN_BRIEF = """\
TWO LANs, ONE TRANSIT, EXPLICIT ROUTES BOTH WAYS

Two routers share a point-to-point /30 and each owns one LAN. Every PC should be
able to reach every other PC, and each router should carry a route to the far
LAN.

Addressing
  LAN-A      10.81.10.0/24   R1 Gi0/0 .1   PC1 .10   PC2 .11
  LAN-B      10.81.20.0/24   R2 Gi0/0 .1   PC3 .10
  TRANSIT    10.81.1.0/30    R1 Gi0/1 .1   R2 Gi0/1 .2

Required end state
  * R1 has a route to 10.81.20.0/24 via 10.81.1.2.
  * R2 has a route to 10.81.10.0/24 via 10.81.1.1.
  * PC1, PC2 and PC3 all reach each other.
"""


def missing_return() -> tuple[TopologySpec, dict]:
    return_route = "ip route 10.81.10.0 255.255.255.0 10.81.1.1"
    devices = [
        _router(
            "R1",
            220,
            130,
            interfaces=(
                ("GigabitEthernet0/0", _lan("10.81.10.1")),
                ("GigabitEthernet0/1", _transit("10.81.1.1")),
            ),
            routing=("ip route 10.81.20.0 255.255.255.0 10.81.1.2",),
        ),
        _router(
            "R2",
            600,
            130,
            interfaces=(
                ("GigabitEthernet0/0", _lan("10.81.20.1")),
                ("GigabitEthernet0/1", _transit("10.81.1.2")),
            ),
            routing=(return_route,),
        ),
        _switch("SW1", 220, 280),
        _switch("SW2", 600, 280),
        _pc("PC1", 140, 390, "10.81.10.10", "10.81.10.1"),
        _pc("PC2", 300, 390, "10.81.10.11", "10.81.10.1"),
        _pc("PC3", 600, 390, "10.81.20.10", "10.81.20.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW1", "GigabitEthernet0/1"),
        LinkSpec("SW1", "FastEthernet0/1", "PC1", "FastEthernet0"),
        LinkSpec("SW1", "FastEthernet0/2", "PC2", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "R2", "GigabitEthernet0/1"),
        LinkSpec("R2", "GigabitEthernet0/0", "SW2", "GigabitEthernet0/1"),
        LinkSpec("SW2", "FastEthernet0/1", "PC3", "FastEthernet0"),
    ]
    fault = FaultSpec(
        fault_id="F1",
        category=FaultCategory.ROUTING,
        severity=Severity.CRITICAL,
        device="R2",
        interface=None,
        description="R2 is missing the return static route to LAN-A.",
        expected=return_route,
        actual="!",
        symptom="Requests reach PC3 but the replies never return to LAN-A.",
        points=100,
        hint_1="Trace the return path, not just the forward path.",
        hint_2="R2 can name LAN-B but not LAN-A.",
        target=TargetKind.GLOBAL_LINE,
    )
    spec = TopologySpec(
        name="missing-return",
        title="Missing Return Route",
        devices=devices,
        links=links,
        faults=[fault],
        brief=_MISSING_RETURN_BRIEF,
        difficulty="intermediate",
    )
    requirements = [
        _requirement("pc1-pc2", "PC1 can ping PC2", "pass"),
        _requirement("pc1-pc3", "PC1 can ping PC3", "fail"),
        _requirement("pc3-pc1", "PC3 can ping PC1", "fail"),
        _requirement("r2-route-a", "R2 has a route to 10.81.10.0/24", "fail"),
    ]
    return _build_case(spec, requirements, {"F1": "MISSING_RETURN_ROUTE"}, control=False)


# ---------------------------------------------------------------------------
# 6. wrong-next-hop — static route points off every connected subnet
# ---------------------------------------------------------------------------

_WRONG_NEXT_HOP_BRIEF = """\
TWO LANs, ONE TRANSIT

Two routers share a point-to-point /30 and each owns one LAN. The routers are
supposed to carry a route to the far LAN across that transit link.

Addressing
  LAN-A      10.82.10.0/24   R1 Gi0/0 .1   PC1 .10   PC2 .11
  LAN-B      10.82.20.0/24   R2 Gi0/0 .1   PC3 .10
  TRANSIT    10.82.1.0/30    R1 Gi0/1 .1   R2 Gi0/1 .2

Required end state
  * R1 has a route to 10.82.20.0/24 via 10.82.1.2.
  * R2 has a route to 10.82.10.0/24 via 10.82.1.1.
  * PC1, PC2 and PC3 all reach each other.
"""


def wrong_next_hop() -> tuple[TopologySpec, dict]:
    intended = "ip route 10.82.20.0 255.255.255.0 10.82.1.2"
    devices = [
        _router(
            "R1",
            220,
            130,
            interfaces=(
                ("GigabitEthernet0/0", _lan("10.82.10.1")),
                ("GigabitEthernet0/1", _transit("10.82.1.1")),
            ),
            routing=(intended,),
        ),
        _router(
            "R2",
            600,
            130,
            interfaces=(
                ("GigabitEthernet0/0", _lan("10.82.20.1")),
                ("GigabitEthernet0/1", _transit("10.82.1.2")),
            ),
            routing=("ip route 10.82.10.0 255.255.255.0 10.82.1.1",),
        ),
        _switch("SW1", 220, 280),
        _switch("SW2", 600, 280),
        _pc("PC1", 140, 390, "10.82.10.10", "10.82.10.1"),
        _pc("PC2", 300, 390, "10.82.10.11", "10.82.10.1"),
        _pc("PC3", 600, 390, "10.82.20.10", "10.82.20.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW1", "GigabitEthernet0/1"),
        LinkSpec("SW1", "FastEthernet0/1", "PC1", "FastEthernet0"),
        LinkSpec("SW1", "FastEthernet0/2", "PC2", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "R2", "GigabitEthernet0/1"),
        LinkSpec("R2", "GigabitEthernet0/0", "SW2", "GigabitEthernet0/1"),
        LinkSpec("SW2", "FastEthernet0/1", "PC3", "FastEthernet0"),
    ]
    fault = FaultSpec(
        fault_id="F1",
        category=FaultCategory.ROUTING,
        severity=Severity.CRITICAL,
        device="R1",
        interface=None,
        description="R1's route to LAN-B points at an address on no connected subnet.",
        expected=intended,
        actual="ip route 10.82.20.0 255.255.255.0 10.82.1.9",
        symptom="R1 installs a black-hole route; PC1 cannot reach PC3.",
        points=100,
        hint_1="Check that the next hop is reachable at configuration time.",
        hint_2="10.82.1.9 is outside the /30 transit subnet.",
        target=TargetKind.GLOBAL_LINE,
    )
    spec = TopologySpec(
        name="wrong-next-hop",
        title="Wrong Next Hop",
        devices=devices,
        links=links,
        faults=[fault],
        brief=_WRONG_NEXT_HOP_BRIEF,
        difficulty="intermediate",
    )
    requirements = [
        _requirement("pc1-pc2", "PC1 can ping PC2", "pass"),
        _requirement("pc1-pc3", "PC1 can ping PC3", "fail"),
        _requirement("r1-route-b", "R1's route to 10.82.20.0/24 is usable", "fail"),
    ]
    return _build_case(spec, requirements, {"F1": "WRONG_NEXT_HOP"}, control=False)


# ---------------------------------------------------------------------------
# 7. admin-shutdown — an interface on the path is administratively down
# ---------------------------------------------------------------------------

_ADMIN_SHUTDOWN_BRIEF = """\
TWO LANs, ONE TRANSIT

Two routers share a point-to-point /30 and each owns one LAN. Every PC should be
able to reach every other PC across the transit link.

Addressing
  LAN-A      10.83.10.0/24   R1 Gi0/0 .1   PC1 .10   PC2 .11
  LAN-B      10.83.20.0/24   R2 Gi0/0 .1   PC3 .10
  TRANSIT    10.83.1.0/30    R1 Gi0/1 .1   R2 Gi0/1 .2

Required end state
  * Every interface on the transit path is up.
  * R1 has a route to 10.83.20.0/24 via 10.83.1.2.
  * R2 has a route to 10.83.10.0/24 via 10.83.1.1.
  * PC1, PC2 and PC3 all reach each other.
"""


def admin_shutdown() -> tuple[TopologySpec, dict]:
    devices = [
        _router(
            "R1",
            220,
            130,
            interfaces=(
                ("GigabitEthernet0/0", _lan("10.83.10.1")),
                ("GigabitEthernet0/1", _transit("10.83.1.1")),
            ),
            routing=("ip route 10.83.20.0 255.255.255.0 10.83.1.2",),
        ),
        _router(
            "R2",
            600,
            130,
            interfaces=(
                ("GigabitEthernet0/0", _lan("10.83.20.1")),
                ("GigabitEthernet0/1", _transit("10.83.1.2")),
            ),
            routing=("ip route 10.83.10.0 255.255.255.0 10.83.1.1",),
        ),
        _switch("SW1", 220, 280),
        _switch("SW2", 600, 280),
        _pc("PC1", 140, 390, "10.83.10.10", "10.83.10.1"),
        _pc("PC2", 300, 390, "10.83.10.11", "10.83.10.1"),
        _pc("PC3", 600, 390, "10.83.20.10", "10.83.20.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW1", "GigabitEthernet0/1"),
        LinkSpec("SW1", "FastEthernet0/1", "PC1", "FastEthernet0"),
        LinkSpec("SW1", "FastEthernet0/2", "PC2", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "R2", "GigabitEthernet0/1"),
        LinkSpec("R2", "GigabitEthernet0/0", "SW2", "GigabitEthernet0/1"),
        LinkSpec("SW2", "FastEthernet0/1", "PC3", "FastEthernet0"),
    ]
    fault = FaultSpec(
        fault_id="F1",
        category=FaultCategory.INTERFACE,
        severity=Severity.CRITICAL,
        device="R1",
        interface="GigabitEthernet0/1",
        description="R1's transit interface has been administratively shut down.",
        expected="no shutdown",
        actual="shutdown",
        symptom="The transit link is down; neither LAN can reach the other.",
        points=100,
        hint_1="Check interface state, not just routes.",
        hint_2="R1 Gi0/1 is administratively down.",
        target=TargetKind.INTERFACE_LINE,
    )
    spec = TopologySpec(
        name="admin-shutdown",
        title="Administratively Shut Interface",
        devices=devices,
        links=links,
        faults=[fault],
        brief=_ADMIN_SHUTDOWN_BRIEF,
        difficulty="beginner",
    )
    requirements = [
        _requirement("pc1-pc2", "PC1 can ping PC2", "pass"),
        _requirement("r1-transit-up", "R1 GigabitEthernet0/1 is up", "fail"),
        _requirement("pc1-pc3", "PC1 can ping PC3", "fail"),
    ]
    return _build_case(spec, requirements, {"F1": "ADMIN_SHUTDOWN"}, control=False)


# ---------------------------------------------------------------------------
# 8. gateway-fault — a host default gateway is not the router
# ---------------------------------------------------------------------------

_GATEWAY_BRIEF = """\
TWO LANs AND A WRONG DEFAULT GATEWAY

Two routers share a point-to-point /30 and each owns one LAN. Every PC should
use the local router interface as its default gateway and reach every other PC.

Addressing
  LAN-A      10.84.10.0/24   R1 Gi0/0 .1   PC1 .10   PC2 .11
  LAN-B      10.84.20.0/24   R2 Gi0/0 .1   PC3 .10
  TRANSIT    10.84.1.0/30    R1 Gi0/1 .1   R2 Gi0/1 .2

Required end state
  * Every PC uses the local router interface as its default gateway.
  * R1 has a route to 10.84.20.0/24 via 10.84.1.2.
  * R2 has a route to 10.84.10.0/24 via 10.84.1.1.
  * PC1, PC2 and PC3 all reach each other.
"""


def gateway_fault() -> tuple[TopologySpec, dict]:
    devices = [
        _router(
            "R1",
            220,
            130,
            interfaces=(
                ("GigabitEthernet0/0", _lan("10.84.10.1")),
                ("GigabitEthernet0/1", _transit("10.84.1.1")),
            ),
            routing=("ip route 10.84.20.0 255.255.255.0 10.84.1.2",),
        ),
        _router(
            "R2",
            600,
            130,
            interfaces=(
                ("GigabitEthernet0/0", _lan("10.84.20.1")),
                ("GigabitEthernet0/1", _transit("10.84.1.2")),
            ),
            routing=("ip route 10.84.10.0 255.255.255.0 10.84.1.1",),
        ),
        _switch("SW1", 220, 280),
        _switch("SW2", 600, 280),
        _pc("PC1", 140, 390, "10.84.10.10", "10.84.10.1"),
        # The faulty gateway is authored into the NIC: pkt_core cannot rewrite
        # an end-host field after the spec is built, so the defect lives here.
        _pc("PC2", 300, 390, "10.84.10.11", "10.84.10.254"),
        _pc("PC3", 600, 390, "10.84.20.10", "10.84.20.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW1", "GigabitEthernet0/1"),
        LinkSpec("SW1", "FastEthernet0/1", "PC1", "FastEthernet0"),
        LinkSpec("SW1", "FastEthernet0/2", "PC2", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "R2", "GigabitEthernet0/1"),
        LinkSpec("R2", "GigabitEthernet0/0", "SW2", "GigabitEthernet0/1"),
        LinkSpec("SW2", "FastEthernet0/1", "PC3", "FastEthernet0"),
    ]
    fault = FaultSpec(
        fault_id="F1",
        category=FaultCategory.GATEWAY,
        severity=Severity.MAJOR,
        device="PC2",
        interface=None,
        description="PC2's default gateway is not the router interface.",
        expected="default gateway 10.84.10.1",
        actual="default gateway 10.84.10.254",
        symptom="PC2 can reach its own LAN but no remote subnet.",
        points=100,
        hint_1="Check the host NIC, not just the router.",
        hint_2="10.84.10.254 is inside the subnet but no interface owns it.",
        target=TargetKind.ENDHOST,
    )
    spec = TopologySpec(
        name="gateway-fault",
        title="Wrong Host Default Gateway",
        devices=devices,
        links=links,
        faults=[fault],
        brief=_GATEWAY_BRIEF,
        difficulty="beginner",
    )
    requirements = [
        _requirement("pc1-pc2", "PC1 can ping PC2", "pass"),
        _requirement("pc1-pc3", "PC1 can ping PC3", "pass"),
        _requirement("pc2-pc3", "PC2 can ping PC3", "fail"),
        _requirement("pc2-gateway", "PC2's gateway is 10.84.10.1", "fail"),
    ]
    return _build_case(
        spec,
        requirements,
        {"F1": "WRONG_GATEWAY"},
        control=False,
        notes=("load-durability: unverified — pkt_core 0.2.2 does not write <ENGINE><GATEWAY>",),
    )


# ---------------------------------------------------------------------------
# 9. acl-intentional-isolation — an ACL keeps two departments apart on purpose
# ---------------------------------------------------------------------------

_ACL_ISOLATION_BRIEF = """\
TWO DEPARTMENTS THAT MUST STAY APART

A single router serves two departments, each on its own VLAN-less LAN interface.
A policy on the router deliberately keeps the departments apart: hosts inside a
department may talk to each other, and traffic between the two departments is
denied by design. This separation is correct and must not be "fixed".

Addressing
  DEPT-A     10.85.10.0/24   R1 Gi0/0 .1   A1 .10   A2 .11
  DEPT-B     10.85.20.0/24   R1 Gi0/1 .1   B1 .10   B2 .11

Required end state
  * A1 reaches A2; B1 reaches B2.
  * A1 cannot reach B1; B1 cannot reach A1.
  * The isolation is intentional. It is not a fault.
"""

_ISOLATION_ACL_A = (
    "access-list 100 permit ip 10.85.10.0 0.0.0.255 10.85.10.0 0.0.0.255",
)
_ISOLATION_ACL_B = (
    "access-list 101 permit ip 10.85.20.0 0.0.0.255 10.85.20.0 0.0.0.255",
)


def acl_intentional_isolation() -> tuple[TopologySpec, dict]:
    devices = [
        _router(
            "R1",
            400,
            140,
            interfaces=(
                ("GigabitEthernet0/0", (*_lan("10.85.10.1"), " ip access-group 100 in")),
                ("GigabitEthernet0/1", (*_lan("10.85.20.1"), " ip access-group 101 in")),
            ),
            routing=(*_ISOLATION_ACL_A, *_ISOLATION_ACL_B),
        ),
        _switch("SW-A", 200, 290),
        _switch("SW-B", 600, 290),
        _pc("A1", 120, 400, "10.85.10.10", "10.85.10.1"),
        _pc("A2", 280, 400, "10.85.10.11", "10.85.10.1"),
        _pc("B1", 520, 400, "10.85.20.10", "10.85.20.1"),
        _pc("B2", 680, 400, "10.85.20.11", "10.85.20.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW-A", "GigabitEthernet0/1"),
        LinkSpec("SW-A", "FastEthernet0/1", "A1", "FastEthernet0"),
        LinkSpec("SW-A", "FastEthernet0/2", "A2", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "SW-B", "GigabitEthernet0/1"),
        LinkSpec("SW-B", "FastEthernet0/1", "B1", "FastEthernet0"),
        LinkSpec("SW-B", "FastEthernet0/2", "B2", "FastEthernet0"),
    ]
    spec = TopologySpec(
        name="acl-intentional-isolation",
        title="Intentional ACL Isolation",
        devices=devices,
        links=links,
        faults=[],
        brief=_ACL_ISOLATION_BRIEF,
        difficulty="intermediate",
    )
    requirements = [
        _requirement("a1-a2", "A1 can ping A2", "pass"),
        _requirement("b1-b2", "B1 can ping B2", "pass"),
        _requirement("a1-b1", "A1 can ping B1", "fail"),
        _requirement("b1-a1", "B1 can ping A1", "fail"),
        _requirement("isolation-intended", "The A/B isolation is the intended policy", "pass"),
    ]
    return _build_case(
        spec,
        requirements,
        {},
        control=True,
        notes=(
            "false-positive control",
            "isolation expressed as a permit-list ACL whose implicit deny blocks the other pair",
        ),
    )


# ---------------------------------------------------------------------------
# 10. acl-accidental-deny — an ACL accidentally blocks required traffic
# ---------------------------------------------------------------------------

_ACL_DENY_BRIEF = """\
TWO DEPARTMENTS THAT MUST TALK

A single router serves two departments, each on its own LAN interface. Traffic
between the departments is required and must be permitted. An access policy on
the router is meant to allow it.

Addressing
  DEPT-A     10.86.10.0/24   R1 Gi0/0 .1   A1 .10   A2 .11
  DEPT-B     10.86.20.0/24   R1 Gi0/1 .1   B1 .10   B2 .11

Required end state
  * A1 reaches A2; B1 reaches B2.
  * A1 reaches B1 and B1 reaches A1.
"""

_ACL_DENY_INTENDED = "access-list 110 permit ip 10.86.10.0 0.0.0.255 10.86.20.0 0.0.0.255"
_ACL_DENY_ACTUAL = "access-list 110 deny ip 10.86.10.0 0.0.0.255 10.86.20.0 0.0.0.255"


def acl_accidental_deny() -> tuple[TopologySpec, dict]:
    devices = [
        _router(
            "R1",
            400,
            140,
            interfaces=(
                ("GigabitEthernet0/0", (*_lan("10.86.10.1"), " ip access-group 110 in")),
                ("GigabitEthernet0/1", _lan("10.86.20.1")),
            ),
            routing=(_ACL_DENY_INTENDED, "access-list 110 permit ip any any"),
        ),
        _switch("SW-A", 200, 290),
        _switch("SW-B", 600, 290),
        _pc("A1", 120, 400, "10.86.10.10", "10.86.10.1"),
        _pc("A2", 280, 400, "10.86.10.11", "10.86.10.1"),
        _pc("B1", 520, 400, "10.86.20.10", "10.86.20.1"),
        _pc("B2", 680, 400, "10.86.20.11", "10.86.20.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW-A", "GigabitEthernet0/1"),
        LinkSpec("SW-A", "FastEthernet0/1", "A1", "FastEthernet0"),
        LinkSpec("SW-A", "FastEthernet0/2", "A2", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "SW-B", "GigabitEthernet0/1"),
        LinkSpec("SW-B", "FastEthernet0/1", "B1", "FastEthernet0"),
        LinkSpec("SW-B", "FastEthernet0/2", "B2", "FastEthernet0"),
    ]
    fault = FaultSpec(
        fault_id="F1",
        category=FaultCategory.ACCESS,
        severity=Severity.CRITICAL,
        device="R1",
        interface="GigabitEthernet0/0",
        description="The inter-department ACL entry is a deny instead of a permit.",
        expected=_ACL_DENY_INTENDED,
        actual=_ACL_DENY_ACTUAL,
        symptom="A1 cannot reach B1 even though the policy is supposed to allow it.",
        points=100,
        hint_1="Read the ACL entries in order; the first match wins.",
        hint_2="The A-to-B entry denies the exact traffic the brief requires.",
        target=TargetKind.GLOBAL_LINE,
    )
    spec = TopologySpec(
        name="acl-accidental-deny",
        title="Accidental ACL Deny",
        devices=devices,
        links=links,
        faults=[fault],
        brief=_ACL_DENY_BRIEF,
        difficulty="intermediate",
    )
    requirements = [
        _requirement("a1-a2", "A1 can ping A2", "pass"),
        _requirement("a1-b1", "A1 can ping B1", "fail"),
        _requirement("b1-a1", "B1 can ping A1", "fail"),
    ]
    return _build_case(spec, requirements, {"F1": "ACL_ACCIDENTAL_DENY"}, control=False)


# ---------------------------------------------------------------------------
# 11. multi-fault — three faults on three devices
# ---------------------------------------------------------------------------

_MULTI_FAULT_BRIEF = """\
TWO LANs, ONE TRANSIT, THREE SEPARATE PROBLEMS

Two routers share a point-to-point /30 and each owns one LAN. Every PC should be
able to reach every other PC through the router pair, and every PC should use
the local router interface as its gateway.

Addressing
  LAN-A      10.87.10.0/24   R1 Gi0/0 .1   PC1 .10   PC2 .11
  LAN-B      10.87.20.0/24   R2 Gi0/0 .1   PC3 .10
  TRANSIT    10.87.1.0/30    R1 Gi0/1 .1   R2 Gi0/1 .2

Required end state
  * R1 has a route to 10.87.20.0/24 via 10.87.1.2.
  * R2 has a route to 10.87.10.0/24 via 10.87.1.1.
  * Every interface on the transit path is up.
  * Every PC uses the local router interface as its default gateway.
  * PC1, PC2 and PC3 all reach each other.
"""


def multi_fault() -> tuple[TopologySpec, dict]:
    forward_route = "ip route 10.87.20.0 255.255.255.0 10.87.1.2"
    devices = [
        _router(
            "R1",
            220,
            130,
            interfaces=(
                ("GigabitEthernet0/0", _lan("10.87.10.1")),
                ("GigabitEthernet0/1", _transit("10.87.1.1")),
            ),
            routing=(forward_route,),
        ),
        _router(
            "R2",
            600,
            130,
            interfaces=(
                ("GigabitEthernet0/0", _lan("10.87.20.1")),
                ("GigabitEthernet0/1", _transit("10.87.1.2")),
            ),
            routing=("ip route 10.87.10.0 255.255.255.0 10.87.1.1",),
        ),
        _switch("SW1", 220, 280),
        _switch("SW2", 600, 280),
        _pc("PC1", 140, 390, "10.87.10.10", "10.87.10.1"),
        _pc("PC2", 300, 390, "10.87.10.11", "10.87.10.1"),
        _pc("PC3", 600, 390, "10.87.20.10", "10.87.20.254"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW1", "GigabitEthernet0/1"),
        LinkSpec("SW1", "FastEthernet0/1", "PC1", "FastEthernet0"),
        LinkSpec("SW1", "FastEthernet0/2", "PC2", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "R2", "GigabitEthernet0/1"),
        LinkSpec("R2", "GigabitEthernet0/0", "SW2", "GigabitEthernet0/1"),
        LinkSpec("SW2", "FastEthernet0/1", "PC3", "FastEthernet0"),
    ]
    faults = [
        FaultSpec(
            fault_id="F1",
            category=FaultCategory.ROUTING,
            severity=Severity.CRITICAL,
            device="R1",
            interface=None,
            description="R1 is missing the forward static route to LAN-B.",
            expected=forward_route,
            actual="!",
            symptom="PC1 cannot reach PC3.",
            points=40,
            hint_1="Start with R1's routing table.",
            hint_2="R1 has no route to 10.87.20.0/24.",
            target=TargetKind.GLOBAL_LINE,
        ),
        FaultSpec(
            fault_id="F2",
            category=FaultCategory.INTERFACE,
            severity=Severity.CRITICAL,
            device="R2",
            interface="GigabitEthernet0/1",
            description="R2's transit interface is administratively shut down.",
            expected="no shutdown",
            actual="shutdown",
            symptom="The transit link is down.",
            points=30,
            hint_1="Check link state on both routers.",
            hint_2="R2 Gi0/1 is administratively down.",
            target=TargetKind.INTERFACE_LINE,
        ),
        FaultSpec(
            fault_id="F3",
            category=FaultCategory.GATEWAY,
            severity=Severity.MAJOR,
            device="PC3",
            interface=None,
            description="PC3's default gateway is not the router interface.",
            expected="default gateway 10.87.20.1",
            actual="default gateway 10.87.20.254",
            symptom="PC3 cannot leave its subnet.",
            points=30,
            hint_1="A host problem can hide behind a router problem.",
            hint_2="10.87.20.254 is not owned by any interface.",
            target=TargetKind.ENDHOST,
        ),
    ]
    spec = TopologySpec(
        name="multi-fault",
        title="Three Independent Faults",
        devices=devices,
        links=links,
        faults=faults,
        brief=_MULTI_FAULT_BRIEF,
        difficulty="advanced",
    )
    requirements = [
        _requirement("pc1-pc2", "PC1 can ping PC2", "pass"),
        _requirement("pc1-pc3", "PC1 can ping PC3", "fail"),
        _requirement("r1-route-b", "R1 has a route to 10.87.20.0/24", "fail"),
        _requirement("r2-transit-up", "R2 GigabitEthernet0/1 is up", "fail"),
        _requirement("pc3-gateway", "PC3's gateway is 10.87.20.1", "fail"),
    ]
    return _build_case(
        spec,
        requirements,
        {"F1": "MISSING_FORWARD_ROUTE", "F2": "ADMIN_SHUTDOWN", "F3": "WRONG_GATEWAY"},
        control=False,
        notes=("points are 40 + 30 + 30 = 100",),
    )


# ---------------------------------------------------------------------------
# 12. transit-three-routers — middle router missing a route
# ---------------------------------------------------------------------------

_THREE_ROUTER_BRIEF = """\
THREE ROUTERS IN A CHAIN

Two edge LANs are joined through a middle transit router. R1 owns LAN-1, R3 owns
LAN-3, and R2 is the middle hop. Each router must know how to reach the far LAN.

Addressing
  LAN-1      10.89.10.0/24   R1 Gi0/0 .1   PC1 .10
  TRANSIT-12 10.89.12.0/30   R1 Gi0/1 .1   R2 Gi0/0 .2
  TRANSIT-23 10.89.23.0/30   R2 Gi0/1 .1   R3 Gi0/1 .2
  LAN-3      10.89.30.0/24   R3 Gi0/0 .1   PC3 .10

Required end state
  * R1 routes LAN-3 via 10.89.12.2.
  * R2 routes LAN-1 via 10.89.12.1 and LAN-3 via 10.89.23.2.
  * R3 routes LAN-1 via 10.89.23.2.
  * PC1 and PC3 reach each other.
"""


def transit_three_routers() -> tuple[TopologySpec, dict]:
    r2_lan3_route = "ip route 10.89.30.0 255.255.255.0 10.89.23.2"
    devices = [
        _router(
            "R1",
            160,
            130,
            interfaces=(
                ("GigabitEthernet0/0", _lan("10.89.10.1")),
                ("GigabitEthernet0/1", _transit("10.89.12.1")),
            ),
            routing=("ip route 10.89.30.0 255.255.255.0 10.89.12.2",),
        ),
        _router(
            "R2",
            420,
            130,
            interfaces=(
                ("GigabitEthernet0/0", _transit("10.89.12.2")),
                ("GigabitEthernet0/1", _transit("10.89.23.1")),
            ),
            routing=(
                "ip route 10.89.10.0 255.255.255.0 10.89.12.1",
                r2_lan3_route,
            ),
        ),
        _router(
            "R3",
            680,
            130,
            interfaces=(
                ("GigabitEthernet0/0", _lan("10.89.30.1")),
                ("GigabitEthernet0/1", _transit("10.89.23.2")),
            ),
            routing=("ip route 10.89.10.0 255.255.255.0 10.89.23.1",),
        ),
        _switch("SW1", 160, 280),
        _switch("SW3", 680, 280),
        _pc("PC1", 160, 390, "10.89.10.10", "10.89.10.1"),
        _pc("PC3", 680, 390, "10.89.30.10", "10.89.30.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW1", "GigabitEthernet0/1"),
        LinkSpec("SW1", "FastEthernet0/1", "PC1", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "R2", "GigabitEthernet0/0"),
        LinkSpec("R2", "GigabitEthernet0/1", "R3", "GigabitEthernet0/1"),
        LinkSpec("R3", "GigabitEthernet0/0", "SW3", "GigabitEthernet0/1"),
        LinkSpec("SW3", "FastEthernet0/1", "PC3", "FastEthernet0"),
    ]
    fault = FaultSpec(
        fault_id="F1",
        category=FaultCategory.ROUTING,
        severity=Severity.CRITICAL,
        device="R2",
        interface=None,
        description="The middle router is missing its route to LAN-3.",
        expected=r2_lan3_route,
        actual="!",
        symptom="PC1 cannot reach PC3; the middle hop drops LAN-3 traffic.",
        points=100,
        hint_1="The fault is in the middle of the path.",
        hint_2="R2 has no route to 10.89.30.0/24.",
        target=TargetKind.GLOBAL_LINE,
    )
    spec = TopologySpec(
        name="transit-three-routers",
        title="Three-Router Transit — Missing Middle Route",
        devices=devices,
        links=links,
        faults=[fault],
        brief=_THREE_ROUTER_BRIEF,
        difficulty="advanced",
    )
    requirements = [
        _requirement("pc1-pc3", "PC1 can ping PC3", "fail"),
        _requirement("pc3-pc1", "PC3 can ping PC1", "fail"),
        _requirement("r2-route-lan3", "R2 has a route to 10.89.30.0/24", "fail"),
    ]
    return _build_case(spec, requirements, {"F1": "MISSING_FORWARD_ROUTE"}, control=False)


# ---------------------------------------------------------------------------
# Registry and public surfaces
# ---------------------------------------------------------------------------

CASES: dict[str, tuple[TopologySpec, dict]] = {
    "healthy-single-router": healthy_single_router(),
    "healthy-no-default": healthy_no_default(),
    "isp-edge-legit": isp_edge_legit(),
    "missing-forward": missing_forward(),
    "missing-return": missing_return(),
    "wrong-next-hop": wrong_next_hop(),
    "admin-shutdown": admin_shutdown(),
    "gateway-fault": gateway_fault(),
    "acl-intentional-isolation": acl_intentional_isolation(),
    "acl-accidental-deny": acl_accidental_deny(),
    "multi-fault": multi_fault(),
    "transit-three-routers": transit_three_routers(),
}

CASE_NAMES: tuple[str, ...] = tuple(CASES)
CONTROL_CASES: tuple[str, ...] = tuple(
    name for name, (_spec, manifest) in CASES.items() if manifest["control"]
)
FAULTED_CASES: tuple[str, ...] = tuple(name for name in CASE_NAMES if name not in CONTROL_CASES)


def case(name: str) -> tuple[TopologySpec, dict]:
    """One case by name; ``KeyError`` lists the valid names."""
    try:
        return CASES[name]
    except KeyError:
        raise KeyError(
            f"unknown evaluation case {name!r}; choose from {', '.join(CASE_NAMES)}"
        ) from None


def blind_view(name: str) -> dict:
    """What a blind run may see: topology and requirements, never the defects.

    The view deliberately omits faults, points, expected/actual values,
    symptoms, hints and the ``control`` flag. Requirements state observable
    outcomes only.
    """
    spec, manifest = case(name)
    return {
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


def blind_manifest() -> dict[str, dict]:
    """Every case's blind view, keyed by case name."""
    return {name: blind_view(name) for name in CASE_NAMES}


def ground_truth(name: str) -> dict:
    """The private manifest for one case, including every fault and ``control``."""
    _spec, manifest = case(name)
    return {
        "case": manifest["case"],
        "title": manifest["title"],
        "control": manifest["control"],
        "fault_count": manifest["fault_count"],
        "points_total": manifest["points_total"],
        "faults": [dict(fault) for fault in manifest["faults"]],
        "requirements": [dict(requirement) for requirement in manifest["requirements"]],
        "notes": list(manifest["notes"]),
    }


def ground_truth_all() -> dict[str, dict]:
    """Every private manifest, keyed by case name."""
    return {name: ground_truth(name) for name in CASE_NAMES}


# ---------------------------------------------------------------------------
# Equivalence-aware scoring
# ---------------------------------------------------------------------------

#: Fixed before scoring. A caller may override individual keys, but the
#: defaults are the rules documented in the module docstring.
DEFAULT_RULES: dict = {
    # (a) a duplicate-IP finding may name any holder of the duplicated address
    "duplicate_ip_any_holder": True,
    # (b) a two-ended trunk fault may be named from either end
    "trunk_either_end": True,
    # (c) a route fault is a property of the router; ignore the interface field
    "device_route_ignore_interface": True,
    # (d) an interface fault requires both device and interface to match
    "interface_requires_both": True,
    # Optional kind aliases: truth kind -> acceptable finding kinds.
    "kind_aliases": {},
}

EQUIVALENCE_RULES = DEFAULT_RULES

_ROUTE_KINDS = frozenset(
    {
        "MISSING_FORWARD_ROUTE",
        "MISSING_RETURN_ROUTE",
        "MISSING_STATIC_ROUTE",
        "WRONG_NEXT_HOP",
        "UNREACHABLE_NEXT_HOP",
        "ROUTE",
    }
)
_INTERFACE_KINDS = frozenset({"ADMIN_SHUTDOWN", "SHUTDOWN_INTERFACE", "INTERFACE"})
_DUPLICATE_KINDS = frozenset({"DUPLICATE_IP", "DUPLICATE_ADDRESS"})
_TRUNK_KINDS = frozenset({"TRUNK_MISMATCH", "TRUNK_NATIVE_VLAN", "TRUNK"})

_IFACE_PREFIXES = {
    "gi": "gigabitethernet",
    "g": "gigabitethernet",
    "fa": "fastethernet",
    "f": "fastethernet",
    "se": "serial",
    "s": "serial",
    "lo": "loopback",
    "vl": "vlan",
}


def _norm(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip().upper().replace("-", "_").replace(" ", "_")


def _kind_class(kind: str) -> str:
    if kind in _DUPLICATE_KINDS:
        return "duplicate"
    if kind in _TRUNK_KINDS:
        return "trunk"
    if kind in _ROUTE_KINDS:
        return "route"
    if kind in _INTERFACE_KINDS:
        return "interface"
    return "other"


def _canon_iface(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    letters = "".join(ch for ch in text if ch.isalpha()).lower()
    rest = text[len(letters) :]
    return _IFACE_PREFIXES.get(letters, letters) + rest


def _same(value: object, other: object) -> bool:
    return _norm(value) == _norm(other)


def _same_iface(value: object, other: object) -> bool:
    return _canon_iface(value) == _canon_iface(other)


def _kinds_match(finding_kind: str, truth_kind: str, rules: dict) -> bool:
    if not truth_kind and not finding_kind:
        return True
    if truth_kind == finding_kind:
        return True
    aliases = rules.get("kind_aliases") or {}
    allowed = {_norm(item) for item in aliases.get(truth_kind, ())}
    return finding_kind in allowed


def equivalent_finding(finding: dict, truth: dict, rules: dict | None = None) -> bool:
    """Whether ``finding`` names the same defect as ``truth`` under ``rules``.

    The four attribution rules (duplicate-any-holder, trunk-either-end,
    route-router-only, interface-device-and-interface) are applied after a kind
    gate. See the module docstring for the definitions.
    """
    active = {**DEFAULT_RULES, **(rules or {})}
    finding_kind = _norm(finding.get("kind"))
    truth_kind = _norm(truth.get("kind"))
    if not _kinds_match(finding_kind, truth_kind, active):
        return False

    cls = _kind_class(truth_kind) if truth_kind else _kind_class(finding_kind)

    if cls == "duplicate":
        if not active.get("duplicate_ip_any_holder", True):
            return _same(finding.get("device"), truth.get("device"))
        holders = truth.get("holders") or []
        if holders:
            return _same(finding.get("device"), truth.get("device")) or any(
                _same(finding.get("device"), holder) for holder in holders
            )
        # A finding may also carry the duplicated address explicitly.
        finding_address = finding.get("address") or finding.get("ip")
        truth_address = truth.get("address") or truth.get("ip")
        if finding_address and truth_address and _same(finding_address, truth_address):
            return True
        return _same(finding.get("device"), truth.get("device"))

    if cls == "trunk":
        if active.get("trunk_either_end", True):
            ends = truth.get("ends") or []
            for end in ends:
                if not _same(finding.get("device"), end.get("device")):
                    continue
                end_iface = end.get("interface")
                if not end_iface or _same_iface(finding.get("interface"), end_iface):
                    return True
            if ends:
                return False
        return _same(finding.get("device"), truth.get("device")) and _same_iface(
            finding.get("interface"), truth.get("interface")
        )

    if cls == "route":
        if not _same(finding.get("device"), truth.get("device")):
            return False
        if active.get("device_route_ignore_interface", True):
            return True
        return _same_iface(finding.get("interface"), truth.get("interface"))

    if cls == "interface":
        return _same(finding.get("device"), truth.get("device")) and _same_iface(
            finding.get("interface"), truth.get("interface")
        )

    # Everything else is device-level; an interface named by the truth must match.
    if not _same(finding.get("device"), truth.get("device")):
        return False
    truth_iface = truth.get("interface")
    if truth_iface and active.get("interface_requires_both", True):
        return _same_iface(finding.get("interface"), truth_iface)
    return True


def _truth_faults(entry: object) -> list[dict]:
    if entry is None:
        return []
    if isinstance(entry, dict):
        return [dict(fault) for fault in entry.get("faults", [])]
    return [dict(fault) for fault in entry]  # type: ignore[union-attr]


def score(
    predictions: dict,
    truth: dict,
    *,
    rules: dict | None = None,
) -> dict:
    """Score ``predictions`` against ``truth`` with equivalence-aware matching.

    ``predictions`` maps a case name to a list of finding dicts. ``truth`` maps
    a case name to either a manifest (with a ``faults`` list) or a fault list.

    Returns integer TP/FP/FN totals, per-case counts, ``{numerator,
    denominator}`` fractions for recall and precision, and separate
    ``correct_device`` / ``correct_interface`` attribution counts. It never
    returns a bare percentage.
    """
    active = {**DEFAULT_RULES, **(rules or {})}

    per_case: dict[str, dict] = {}
    total_tp = total_fp = total_fn = 0
    correct_device = 0
    correct_interface = 0
    interface_denominator = 0

    for name in sorted(set(predictions) | set(truth)):
        findings = [dict(item) for item in (predictions.get(name) or [])]
        faults = _truth_faults(truth.get(name))

        used: set[int] = set()
        tp = 0
        for fault in faults:
            truth_iface = fault.get("interface")
            if truth_iface:
                interface_denominator += 1
            match: int | None = None
            for index, finding in enumerate(findings):
                if index in used:
                    continue
                if equivalent_finding(finding, fault, active):
                    match = index
                    break
            if match is None:
                continue
            used.add(match)
            tp += 1
            finding = findings[match]
            device_ok = _same(finding.get("device"), fault.get("device"))
            if device_ok:
                correct_device += 1
            if truth_iface and device_ok and _same_iface(
                finding.get("interface"), truth_iface
            ):
                correct_interface += 1

        fp = len(findings) - len(used)
        fn = len(faults) - tp
        per_case[name] = {"tp": tp, "fp": fp, "fn": fn}
        total_tp += tp
        total_fp += fp
        total_fn += fn

    return {
        "cases": per_case,
        "tp": total_tp,
        "fp": total_fp,
        "fn": total_fn,
        "recall": {
            "numerator": total_tp,
            "denominator": total_tp + total_fn,
        },
        "precision": {
            "numerator": total_tp,
            "denominator": total_tp + total_fp,
        },
        "correct_device": {
            "numerator": correct_device,
            "denominator": total_tp,
        },
        "correct_interface": {
            "numerator": correct_interface,
            "denominator": interface_denominator,
        },
    }


__all__ = [
    "CASES",
    "CASE_NAMES",
    "CONTROL_CASES",
    "DEFAULT_RULES",
    "EQUIVALENCE_RULES",
    "FAULTED_CASES",
    "blind_manifest",
    "blind_view",
    "case",
    "equivalent_finding",
    "ground_truth",
    "ground_truth_all",
    "score",
]
