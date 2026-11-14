"""CCNA-3 extension labs: static routing, route selection and ACL policy.

Four original, multi-router labs that extend the labgen gauntlet past switched
campuses into routed internetworks. Each is a complete :class:`TopologySpec`
whose *intended* build is a working network and whose *faulted* build contains
exactly the defects its answer key claims.

Why these four, and why this shape
----------------------------------
CCNA-3 is where a student stops configuring a device and starts configuring a
*network*: a route on one router is only half a conversation, and the missing
half is only visible from the far end. Each lab therefore targets one failure
mode that cannot be found by looking at a single device:

``ccna3-static-chains``     a chain of three routers, where a route on the
                            middle router is the only thing two ends share.
``ccna3-route-selection``   two parallel paths, a primary and a floating static,
                            so "the route is present" and "the route is chosen"
                            are different questions.
``ccna3-acl-policy``        an extended ACL whose order determines whether the
                            policy permits or black-holes every flow.
``ccna3-asymmetric``        traffic leaves on one path and would return on
                            another; the return route is the one nobody checks.

Design constraints, each learned from a live run
------------------------------------------------
* **No default routes in the intended build.** The engine's
  ``MISSING_STATIC_ROUTE`` detector reasons about a default route and compares a
  masked static destination as ``/32`` (``parse_running_config`` discards the
  mask, and ``_route_network`` appends ``/32``). A healthy chain built on
  defaults therefore reports itself as broken in every direction. Explicit
  routes to every remote subnet are used instead: they are what a CCNA-3 answer
  key expects anyway, and they keep the clean control at zero findings.
* **No ``ip default-gateway``/DHCP/VLAN blocks.** They add detector surface
  without adding routing content. Access switches are left at their defaults
  (VLAN 1, no trunk), which is a legitimate design for a routing lab and keeps
  the false-positive guard meaningful.
* **No ``ENDHOST`` faults.** ``faulted_configs`` cannot rewrite ``pc_ip``; an
  end-host fault would have to ship its broken value in the intended build too,
  which is exactly the answer-key leak the spec exists to prevent.
* **No explicit ``deny`` in an intended ACL.** Any deny entry bound to an
  interface is reported as ``ACL_BLOCK`` by the engine — it cannot tell a
  deliberate policy denial from a broken ACL. The ACL lab therefore expresses
  its policy with an explicit ``permit`` and IOS's implicit deny, and the
  *fault* is the explicit ``deny ip any any`` that swallows the permit.
* **Routing config text goes after the management block.** ``parse_running_config``
  keeps the last ``interface`` block open until a ``!`` or a ``line`` block, so
  ``ip route``/``access-list`` written immediately after an interface are
  swallowed as interface sub-commands and the model sees no routes at all. The
  router helper below always emits ``_MGMT`` before the routes.
* **Every routed next hop is on a cabled, addressed link.** IOS silently rejects
  a static route whose next hop is unreachable at configuration time, which
  would remove the fault the answer key claims. Only the deliberately wrong next
  hops are off-subnet, and they are the fault itself.
* **Transit links are GigabitEthernet, not Serial.** ``builder.generate`` calls
  ``Lab.link`` without a ``kind``, which emits an ``eCopper`` cable; a serial
  interface would then be cabled with copper and never come up. The routing
  content (a point-to-point /30 with a static route on each end) is identical,
  and no config line names a serial interface.

What is *not* in the faulted build
----------------------------------
No fault is placed on end-host CLI: Packet Tracer 9.0.1 rejects ``enterCommand``
on PC-PT/Server-PT, so an end-host fault could never be verified. All faults are
running-config edits on routers.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

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
)

_ROUTER_MODEL = "2911"
_SWITCH_MODEL = "2960-24TT"
_PC_MODEL = "PC-PT"

_ENABLE_SECRET = "Trident!23"
_USER_SECRET = "TridentAdmin!23"

#: Management baseline for every router.
#:
#: The ordering matters to ``parse_running_config``: an open ``interface`` block
#: only closes at ``!`` or a ``line`` block, so a route written before this block
#: is read as an interface sub-command and disappears from the model. The router
#: helper always places this tuple ahead of the routing lines.
#:
#: Every router carries ``enable secret`` and a local user because
#: ``detect_weak_management`` flags any device that configures vty lines without
#: them. Supplying them is the configuration a lab router should have, not a
#: workaround.
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
    """A 2911 with the management baseline, then addressing, then routes.

    ``routing`` holds ``ip route`` and ``access-list`` lines. It is appended
    *after* ``_MGMT`` on purpose — see the module docstring.
    """
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
    """An access switch at IOS defaults: VLAN 1, no trunk, no SVI.

    It needs an identity and an enable secret and nothing else. No SVI means no
    management gateway to get wrong, and no ``line vty`` means the weak-management
    detector correctly treats it as out of scope rather than broken.
    """
    return DeviceSpec(
        name=name,
        model=_SWITCH_MODEL,
        role=DeviceRole.SWITCH,
        x=x,
        y=y,
        globals=(f"hostname {name}", f"enable secret {_ENABLE_SECRET}"),
    )


def _pc(name: str, x: int, y: int, address: str, gateway: str, mask: str = "255.255.255.0") -> DeviceSpec:
    return DeviceSpec(
        name=name,
        model=_PC_MODEL,
        role=DeviceRole.PC,
        x=x,
        y=y,
        pc_ip=(address, mask, gateway),
    )


def _server(name: str, x: int, y: int, address: str, gateway: str) -> DeviceSpec:
    return DeviceSpec(
        name=name,
        model="Server-PT",
        role=DeviceRole.SERVER,
        x=x,
        y=y,
        pc_ip=(address, "255.255.255.0", gateway),
    )


def _lan(address: str, mask: str = "255.255.255.0") -> tuple[str, ...]:
    """A routed LAN interface: address plus the ``no shutdown`` it needs."""
    return (f" ip address {address} {mask}", " no shutdown")


def _transit(address: str) -> tuple[str, ...]:
    """A /30 router-to-router link."""
    return (f" ip address {address} 255.255.255.252", " no shutdown")


def _net(host_base: str) -> str:
    """The network address for a three-octet host base (``192.168.10`` → ``192.168.10.0``)."""
    return f"{host_base}.0"


# ---------------------------------------------------------------------------
# Lab 1 — ccna3-static-chains
# ---------------------------------------------------------------------------

_CHAIN_A = "192.168.10"  # LAN-A   192.168.10.0/24
_CHAIN_B = "192.168.20"  # LAN-B   192.168.20.0/24
_CHAIN_C = "192.168.30"  # LAN-C   192.168.30.0/24
_CHAIN_12 = "10.0.12"  # R1 -- R2  10.0.12.0/30
_CHAIN_23 = "10.0.23"  # R2 -- R3  10.0.23.0/30

_CHAIN_BRIEF = """\
STATIC ROUTING IN A CHAIN

Three sites were joined with two point-to-point /30 links. Each site router owns
one LAN and knows nothing about the other two until someone writes a route.
Head office needs every LAN reachable from every other LAN, in both directions.

Addressing
  LAN-A   192.168.10.0/24   R1 Gi0/0  .1    PC-A1 .10    PC-A2 .11
  LAN-B   192.168.20.0/24   R2 Gi0/0  .1    PC-B  .10
  LAN-C   192.168.30.0/24   R3 Gi0/0  .1    PC-C  .10
  R1--R2  10.0.12.0/30      R1 Gi0/1  .1    R2 Gi0/1 .2
  R2--R3  10.0.23.0/30      R2 Gi0/2  .1    R3 Gi0/1 .2

Required end state
  * Every router reaches every LAN that is not directly connected to it.
  * Static routes are used — no routing protocol.
  * Every next hop is an address on a connected subnet.
  * Every PC pings every other PC.

Rules of engagement
  * Use `show ip route` and `show running-config | include ip route`.
  * Do not change addresses, device names or the cabling.
  * Fix the route, not the symptom: do not add a route that bypasses the design.
"""

_CHAIN_FAULTS: list[FaultSpec] = [
    FaultSpec(
        fault_id="route-missing-lan-c",
        category=FaultCategory.ROUTING,
        severity=Severity.MAJOR,
        device="R1",
        interface=None,
        description=("R1 has no route to LAN-C, so PC-A1 and PC-A2 cannot reach 192.168.30.0/24 at all."),
        expected=f"ip route {_net(_CHAIN_C)} 255.255.255.0 {_CHAIN_12}.2",
        actual=f"! ip route {_net(_CHAIN_C)} 255.255.255.0 {_CHAIN_12}.2",
        symptom=(
            "`show ip route 192.168.30.0` on R1 reports no matching route; PC-A1 "
            "cannot ping PC-C while PC-B can."
        ),
        points=22,
        hint_1="A router only knows its own LAN and the links it is cabled to.",
        hint_2="R1 has two remote LANs to reach. Check which one is missing from `show ip route`.",
        target=TargetKind.GLOBAL_LINE,
    ),
    FaultSpec(
        fault_id="route-wrong-next-hop",
        category=FaultCategory.ROUTING,
        severity=Severity.CRITICAL,
        device="R3",
        interface=None,
        description=(
            "R3's route to LAN-B points at 10.0.23.9, an address that is not on "
            "the 10.0.23.0/30 link and belongs to no device."
        ),
        expected=f"ip route {_net(_CHAIN_B)} 255.255.255.0 {_CHAIN_23}.1",
        actual=f"ip route {_net(_CHAIN_B)} 255.255.255.0 10.0.23.9",
        symptom=(
            "`show ip route` on R3 shows the LAN-B route via 10.0.23.9, and "
            "`show ip route 10.0.23.9` has no route at all."
        ),
        points=25,
        hint_1="A next hop must be an address on a directly connected subnet.",
        hint_2="The R2-R3 link is 10.0.23.0/30: only .1 and .2 are usable.",
        target=TargetKind.GLOBAL_LINE,
    ),
    FaultSpec(
        fault_id="addr-lan-b-subnet-typo",
        category=FaultCategory.ADDRESSING,
        severity=Severity.CRITICAL,
        device="R2",
        interface="GigabitEthernet0/0",
        description=(
            "R2's LAN-B interface carries 192.168.200.1, so PC-B's default "
            "gateway 192.168.20.1 exists nowhere on the network."
        ),
        expected=f" ip address {_CHAIN_B}.1 255.255.255.0",
        actual=" ip address 192.168.200.1 255.255.255.0",
        symptom=(
            "PC-B pings its own gateway and gets no reply; `show ip interface "
            "brief` on R2 shows Gi0/0 in 192.168.200.0/24."
        ),
        points=25,
        hint_1="Compare the router's LAN address with the PCs' default gateway.",
        hint_2="192.168.200.0 is not 192.168.20.0. One extra zero.",
    ),
    FaultSpec(
        fault_id="iface-lan-c-shutdown",
        category=FaultCategory.INTERFACE,
        severity=Severity.MAJOR,
        device="R3",
        interface="GigabitEthernet0/0",
        description=(
            "R3's LAN-C interface is administratively shut down, so PC-C has no "
            "gateway even though every route to LAN-C is correct."
        ),
        expected=" no shutdown",
        actual=" shutdown",
        symptom=(
            "`show ip interface brief` on R3 lists Gi0/0 as administratively "
            "down while every other interface is up."
        ),
        points=16,
        hint_1="A route can be perfect and still deliver nothing if the exit interface is down.",
        hint_2="Look at the interface state on R3, not just its routes.",
    ),
    FaultSpec(
        fault_id="route-return-points-at-self",
        category=FaultCategory.ROUTING,
        severity=Severity.MAJOR,
        device="R2",
        interface=None,
        description=(
            "R2's return route to LAN-A points at 10.0.12.2 — R2's own address on "
            "the R1 link — instead of at R1's 10.0.12.1."
        ),
        expected=f"ip route {_net(_CHAIN_A)} 255.255.255.0 {_CHAIN_12}.1",
        actual=f"ip route {_net(_CHAIN_A)} 255.255.255.0 {_CHAIN_12}.2",
        symptom=(
            "PC-C can ping R1 but not PC-A1; `show ip route 192.168.10.0` on R2 "
            "names R2's own interface as the next hop."
        ),
        points=12,
        hint_1="A return path is a route in the other direction, not the same route reversed.",
        hint_2="The next hop for LAN-A from R2 is R1's address on the shared link.",
        target=TargetKind.GLOBAL_LINE,
    ),
]


def static_chains() -> TopologySpec:
    """Three routers in a chain, three LANs, static routes in both directions."""
    devices = [
        _router(
            "R1",
            180,
            160,
            interfaces=(
                ("GigabitEthernet0/0", _lan(f"{_CHAIN_A}.1")),
                ("GigabitEthernet0/1", _transit(f"{_CHAIN_12}.1")),
            ),
            routing=(
                f"ip route {_net(_CHAIN_B)} 255.255.255.0 {_CHAIN_12}.2",
                f"ip route {_net(_CHAIN_C)} 255.255.255.0 {_CHAIN_12}.2",
            ),
        ),
        _router(
            "R2",
            420,
            160,
            interfaces=(
                ("GigabitEthernet0/0", _lan(f"{_CHAIN_B}.1")),
                ("GigabitEthernet0/1", _transit(f"{_CHAIN_12}.2")),
                ("GigabitEthernet0/2", _transit(f"{_CHAIN_23}.1")),
            ),
            routing=(
                f"ip route {_net(_CHAIN_A)} 255.255.255.0 {_CHAIN_12}.1",
                f"ip route {_net(_CHAIN_C)} 255.255.255.0 {_CHAIN_23}.2",
            ),
        ),
        _router(
            "R3",
            660,
            160,
            interfaces=(
                ("GigabitEthernet0/0", _lan(f"{_CHAIN_C}.1")),
                ("GigabitEthernet0/1", _transit(f"{_CHAIN_23}.2")),
            ),
            routing=(
                f"ip route {_net(_CHAIN_A)} 255.255.255.0 {_CHAIN_23}.1",
                f"ip route {_net(_CHAIN_B)} 255.255.255.0 {_CHAIN_23}.1",
            ),
        ),
        _switch("SW-A", 120, 300),
        _pc("PC-A1", 60, 380, f"{_CHAIN_A}.10", f"{_CHAIN_A}.1"),
        _pc("PC-A2", 180, 380, f"{_CHAIN_A}.11", f"{_CHAIN_A}.1"),
        _pc("PC-B", 420, 300, f"{_CHAIN_B}.10", f"{_CHAIN_B}.1"),
        _pc("PC-C", 660, 300, f"{_CHAIN_C}.10", f"{_CHAIN_C}.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW-A", "GigabitEthernet0/1"),
        LinkSpec("SW-A", "FastEthernet0/1", "PC-A1", "FastEthernet0"),
        LinkSpec("SW-A", "FastEthernet0/2", "PC-A2", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "R2", "GigabitEthernet0/1"),
        LinkSpec("R2", "GigabitEthernet0/2", "R3", "GigabitEthernet0/1"),
        LinkSpec("R2", "GigabitEthernet0/0", "PC-B", "FastEthernet0"),
        LinkSpec("R3", "GigabitEthernet0/0", "PC-C", "FastEthernet0"),
    ]
    return TopologySpec(
        name="ccna3-static-chains",
        title="CCNA-3 — Static Routing in a Chain",
        devices=devices,
        links=links,
        faults=rebalance(_CHAIN_FAULTS),
        brief=_CHAIN_BRIEF,
        difficulty="intermediate",
    )


# ---------------------------------------------------------------------------
# Lab 2 — ccna3-route-selection
# ---------------------------------------------------------------------------

_SEL_A = "192.168.10"  # LAN-A    192.168.10.0/24
_SEL_SRV = "192.168.20"  # SERVERS  192.168.20.0/24
_SEL_PRIMARY = "10.0.12"  # PRIMARY  10.0.12.0/30
_SEL_BACKUP = "10.0.13"  # BACKUP   10.0.13.0/30

_SELECTION_BRIEF = """\
ROUTE SELECTION AND THE FLOATING STATIC

Two sites are joined twice: a primary link and a backup link. The routing table
must prefer the primary path, and the backup must exist only as a floating
static that takes over when the primary is withdrawn.

Addressing
  LAN-A     192.168.10.0/24   R1 Gi0/0  .1    PC-1  .10
  SERVERS   192.168.20.0/24   R2 Gi0/0  .1    SRV-1 .10
  PRIMARY   10.0.12.0/30      R1 Gi0/1  .1    R2 Gi0/1 .2
  BACKUP    10.0.13.0/30      R1 Gi0/2  .1    R2 Gi0/2 .2

Required end state
  * Traffic to the far LAN uses the PRIMARY path while it is up.
  * A floating static for the same prefix exists on each router via the BACKUP
    link, with a higher administrative distance than the primary route.
  * Shutting the primary interface leaves the network reachable over the backup,
    but the primary link is the intended path and must be up.
  * Both PCs reach both LANs in both directions.

Rules of engagement
  * Use `show ip route`, `show ip route 192.168.20.0` and `show interfaces`.
  * Do not change addresses, device names or the cabling.
  * Administrative distance decides between routes to the SAME prefix; it never
    decides between different prefixes.
"""

_SELECTION_FAULTS: list[FaultSpec] = [
    FaultSpec(
        fault_id="route-primary-wrong-next-hop",
        category=FaultCategory.ROUTING,
        severity=Severity.CRITICAL,
        device="R1",
        interface=None,
        description=(
            "R1's primary route to SERVERS points at 10.0.12.9, which is outside "
            "the 10.0.12.0/30 primary link, so IOS will not install it."
        ),
        expected=f"ip route {_net(_SEL_SRV)} 255.255.255.0 {_SEL_PRIMARY}.2",
        actual=f"ip route {_net(_SEL_SRV)} 255.255.255.0 10.0.12.9",
        symptom=(
            "`show ip route 192.168.20.0` on R1 shows only the administrative "
            "distance 5 floating route; the distance 1 primary is absent."
        ),
        points=25,
        hint_1="A route whose next hop is not on a connected subnet is not installed.",
        hint_2="10.0.12.9 is not in 10.0.12.0/30. The primary next hop is .2.",
        target=TargetKind.GLOBAL_LINE,
    ),
    FaultSpec(
        fault_id="route-floating-missing",
        category=FaultCategory.ROUTING,
        severity=Severity.MAJOR,
        device="R1",
        interface=None,
        description=(
            "R1's floating static to SERVERS over the backup link is gone, so the "
            "network has no redundant path even though traffic still flows."
        ),
        expected=f"ip route {_net(_SEL_SRV)} 255.255.255.0 {_SEL_BACKUP}.2 5",
        actual=f"! ip route {_net(_SEL_SRV)} 255.255.255.0 {_SEL_BACKUP}.2 5",
        symptom=(
            "`show running-config | include ip route` on R1 lists one route to "
            "192.168.20.0, not two. Shutting Gi0/1 then black-holes the LAN."
        ),
        points=20,
        hint_1="A floating static is invisible until the primary is withdrawn.",
        hint_2="R1 should hold two routes to the same prefix, with different distances.",
        target=TargetKind.GLOBAL_LINE,
    ),
    FaultSpec(
        fault_id="addr-servers-mask-transposed",
        category=FaultCategory.ADDRESSING,
        severity=Severity.CRITICAL,
        device="R2",
        interface="GigabitEthernet0/0",
        description=(
            "R2's SERVERS interface uses 255.255.0.255 — the third and fourth "
            "octets of 255.255.255.0 transposed — which is not a legal mask."
        ),
        expected=f" ip address {_SEL_SRV}.1 255.255.255.0",
        actual=f" ip address {_SEL_SRV}.1 255.255.0.255",
        symptom=(
            "`show ip interface brief` on R2 shows a mask that is not contiguous; "
            "the SERVERS subnet cannot be derived and SRV-1 has no usable gateway."
        ),
        points=25,
        hint_1="A subnet mask is a run of ones followed by a run of zeros. Nothing else.",
        hint_2="Compare Gi0/0's mask on R2 against every other LAN interface.",
    ),
    FaultSpec(
        fault_id="iface-primary-path-shutdown",
        category=FaultCategory.INTERFACE,
        severity=Severity.MAJOR,
        device="R1",
        interface="GigabitEthernet0/1",
        description=(
            "The primary link interface on R1 is administratively shut down, so "
            "the intended primary path is withdrawn and traffic rides the backup."
        ),
        expected=" no shutdown",
        actual=" shutdown",
        symptom=(
            "`show interfaces GigabitEthernet0/1` on R1 reports administratively "
            "down; `show ip route` no longer lists the primary next hop."
        ),
        points=15,
        hint_1="Check interface state before you trust a routing table.",
        hint_2="Gi0/1 on R1 carries the primary path to R2.",
    ),
    FaultSpec(
        fault_id="route-return-wrong-next-hop",
        category=FaultCategory.ROUTING,
        severity=Severity.CRITICAL,
        device="R2",
        interface=None,
        description=(
            "R2's return route to LAN-A points at 10.0.13.9, which is not on the "
            "backup link it names, so replies from SERVERS have no path back."
        ),
        expected=f"ip route {_net(_SEL_A)} 255.255.255.0 {_SEL_PRIMARY}.1",
        actual=f"ip route {_net(_SEL_A)} 255.255.255.0 10.0.13.9",
        symptom=(
            "PC-1 can ping R2 but not SRV-1; R2's route to 192.168.10.0 names a "
            "next hop with no connected subnet."
        ),
        points=15,
        hint_1="A ping that works one way and not the other is a return-path fault.",
        hint_2="R2's return path to LAN-A is over the link that actually holds 10.0.12.1.",
        target=TargetKind.GLOBAL_LINE,
    ),
]


def route_selection() -> TopologySpec:
    """Two routers, two parallel paths, a primary static and a floating static."""
    devices = [
        _router(
            "R1",
            220,
            180,
            interfaces=(
                ("GigabitEthernet0/0", _lan(f"{_SEL_A}.1")),
                ("GigabitEthernet0/1", _transit(f"{_SEL_PRIMARY}.1")),
                ("GigabitEthernet0/2", _transit(f"{_SEL_BACKUP}.1")),
            ),
            routing=(
                f"ip route {_net(_SEL_SRV)} 255.255.255.0 {_SEL_PRIMARY}.2",
                f"ip route {_net(_SEL_SRV)} 255.255.255.0 {_SEL_BACKUP}.2 5",
            ),
        ),
        _router(
            "R2",
            520,
            180,
            interfaces=(
                ("GigabitEthernet0/0", _lan(f"{_SEL_SRV}.1")),
                ("GigabitEthernet0/1", _transit(f"{_SEL_PRIMARY}.2")),
                ("GigabitEthernet0/2", _transit(f"{_SEL_BACKUP}.2")),
            ),
            routing=(
                f"ip route {_net(_SEL_A)} 255.255.255.0 {_SEL_PRIMARY}.1",
                f"ip route {_net(_SEL_A)} 255.255.255.0 {_SEL_BACKUP}.1 5",
            ),
        ),
        _pc("PC-1", 120, 300, f"{_SEL_A}.10", f"{_SEL_A}.1"),
        _server("SRV-1", 620, 300, f"{_SEL_SRV}.10", f"{_SEL_SRV}.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "PC-1", "FastEthernet0"),
        LinkSpec("R2", "GigabitEthernet0/0", "SRV-1", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "R2", "GigabitEthernet0/1"),
        LinkSpec("R1", "GigabitEthernet0/2", "R2", "GigabitEthernet0/2"),
    ]
    return TopologySpec(
        name="ccna3-route-selection",
        title="CCNA-3 — Route Selection and the Floating Static",
        devices=devices,
        links=links,
        faults=rebalance(_SELECTION_FAULTS),
        brief=_SELECTION_BRIEF,
        difficulty="advanced",
    )


# ---------------------------------------------------------------------------
# Lab 3 — ccna3-acl-policy
# ---------------------------------------------------------------------------

_ACL_STAFF = "192.168.10"  # STAFF  192.168.10.0/24
_ACL_LAB = "192.168.20"  # LAB    192.168.20.0/24
_ACL_LINK = "10.0.12"  # LINK   10.0.12.0/30

_ACL_PERMIT = f"access-list 100 permit ip {_net(_ACL_STAFF)} 0.0.0.255 {_net(_ACL_LAB)} 0.0.0.255"

_ACL_BRIEF = """\
AN EXTENDED ACL AS POLICY

Staff and the teaching lab share one routed internetwork. The policy is one-way:
the Staff subnet may reach the Lab subnet, and no other source subnet may. The
policy is enforced with a numbered extended ACL on the link that carries the
only path between the two LANs.

Addressing
  STAFF   192.168.10.0/24   R1 Gi0/0  .1    PC-S1 .10   PC-S2 .11
  LAB     192.168.20.0/24   R2 Gi0/0  .1    PC-L1 .10   PC-L2 .11
  LINK    10.0.12.0/30      R1 Gi0/1  .1    R2 Gi0/1 .2

Policy, exactly
  * Permit 192.168.10.0/24 -> 192.168.20.0/24.
  * Deny every other source subnet.
  * The deny is the implicit deny at the end of an extended ACL. Do not add an
    explicit `deny ip any any`; a permit-only list is the correct expression of
    this policy, and an explicit deny placed first black-holes all traffic.

Required end state
  * ACL 100 is applied OUTBOUND on R1 Gi0/1 toward R2.
  * PC-S1 and PC-S2 reach PC-L1 and PC-L2.
  * The Lab subnet cannot originate traffic to Staff.
  * Both routers route in both directions.

Rules of engagement
  * Use `show access-lists` and `show ip interface` to check the binding.
  * ACL order matters: the first matching entry decides, and an implicit deny
    follows the last entry.
  * Do not change addresses, device names or the cabling.
"""

_ACL_FAULTS: list[FaultSpec] = [
    FaultSpec(
        fault_id="acl-deny-all-by-accident",
        category=FaultCategory.SECURITY,
        severity=Severity.CRITICAL,
        device="R1",
        interface=None,
        description=(
            "ACL 100's permit has been replaced by `deny ip any any`, so the "
            "applied ACL denies every packet on the only path between the LANs."
        ),
        expected=_ACL_PERMIT,
        actual="access-list 100 deny ip any any",
        symptom=(
            "`show access-lists` on R1 shows a single deny and no permit; every "
            "ping from Staff to Lab fails while the routing table is correct."
        ),
        points=30,
        hint_1="A working route plus zero connectivity points at a filter, not a route.",
        hint_2="Check the ACL bound to Gi0/1 and the order of its entries.",
        target=TargetKind.GLOBAL_LINE,
    ),
    FaultSpec(
        fault_id="route-return-missing",
        category=FaultCategory.ROUTING,
        severity=Severity.MAJOR,
        device="R2",
        interface=None,
        description=(
            "R2 has no route back to the Staff subnet, so permitted traffic "
            "arrives at the Lab and the replies are dropped."
        ),
        expected=f"ip route {_net(_ACL_STAFF)} 255.255.255.0 {_ACL_LINK}.1",
        actual=f"! ip route {_net(_ACL_STAFF)} 255.255.255.0 {_ACL_LINK}.1",
        symptom=(
            "`show ip route 192.168.10.0` on R2 reports no matching route; PC-L1 cannot reply to PC-S1."
        ),
        points=20,
        hint_1="An ACL that permits a flow is not the same as a network that can return it.",
        hint_2="R2 needs a route to the Staff subnet over the transit link.",
        target=TargetKind.GLOBAL_LINE,
    ),
    FaultSpec(
        fault_id="route-wrong-next-hop",
        category=FaultCategory.ROUTING,
        severity=Severity.CRITICAL,
        device="R1",
        interface=None,
        description=(
            "R1's route to the Lab subnet points at 10.0.12.9, which is outside "
            "the transit /30, so the route is not installed."
        ),
        expected=f"ip route {_net(_ACL_LAB)} 255.255.255.0 {_ACL_LINK}.2",
        actual=f"ip route {_net(_ACL_LAB)} 255.255.255.0 10.0.12.9",
        symptom=(
            "`show ip route 192.168.20.0` on R1 has no entry; the ACL never sees "
            "a packet because there is no route to filter."
        ),
        points=20,
        hint_1="Work bottom-up: is there a route before asking whether the ACL allows it?",
        hint_2="The transit link only contains 10.0.12.1 and 10.0.12.2.",
        target=TargetKind.GLOBAL_LINE,
    ),
    FaultSpec(
        fault_id="addr-staff-subnet-wrong",
        category=FaultCategory.ADDRESSING,
        severity=Severity.CRITICAL,
        device="R1",
        interface="GigabitEthernet0/0",
        description=(
            "R1's Staff interface carries 192.168.100.1 instead of 192.168.10.1, "
            "so the Staff PCs' default gateway does not exist and the ACL's "
            "permitted source subnet is no longer the subnet on the wire."
        ),
        expected=f" ip address {_ACL_STAFF}.1 255.255.255.0",
        actual=" ip address 192.168.100.1 255.255.255.0",
        symptom=(
            "PC-S1 and PC-S2 cannot reach their gateway; `show ip interface brief` "
            "on R1 places Gi0/0 in 192.168.100.0/24."
        ),
        points=20,
        hint_1="Check the gateway address on the PCs against the router interface.",
        hint_2="192.168.100.0 is not 192.168.10.0.",
    ),
    FaultSpec(
        fault_id="iface-transit-shutdown",
        category=FaultCategory.INTERFACE,
        severity=Severity.MINOR,
        device="R2",
        interface="GigabitEthernet0/1",
        description=(
            "R2's transit interface is administratively shut down, so the only "
            "path between Staff and Lab is down regardless of ACL or routes."
        ),
        expected=" no shutdown",
        actual=" shutdown",
        symptom=(
            "`show ip interface brief` on R2 lists Gi0/1 as administratively down; "
            "R1's neighbour address 10.0.12.2 stops responding."
        ),
        points=10,
        hint_1="Before blaming a filter, confirm the link is up at both ends.",
        hint_2="Gi0/1 on R2 faces R1.",
    ),
]


def acl_policy() -> TopologySpec:
    """Two routers, two LANs, and an extended ACL that permits one subnet and denies all others."""
    devices = [
        _router(
            "R1",
            220,
            180,
            interfaces=(
                ("GigabitEthernet0/0", _lan(f"{_ACL_STAFF}.1")),
                ("GigabitEthernet0/1", (*_transit(f"{_ACL_LINK}.1"), " ip access-group 100 out")),
            ),
            routing=(
                _ACL_PERMIT,
                f"ip route {_net(_ACL_LAB)} 255.255.255.0 {_ACL_LINK}.2",
            ),
        ),
        _router(
            "R2",
            560,
            180,
            interfaces=(
                ("GigabitEthernet0/0", _lan(f"{_ACL_LAB}.1")),
                ("GigabitEthernet0/1", _transit(f"{_ACL_LINK}.2")),
            ),
            routing=(f"ip route {_net(_ACL_STAFF)} 255.255.255.0 {_ACL_LINK}.1",),
        ),
        _switch("SW-A", 140, 320),
        _switch("SW-B", 640, 320),
        _pc("PC-S1", 80, 420, f"{_ACL_STAFF}.10", f"{_ACL_STAFF}.1"),
        _pc("PC-S2", 200, 420, f"{_ACL_STAFF}.11", f"{_ACL_STAFF}.1"),
        _pc("PC-L1", 580, 420, f"{_ACL_LAB}.10", f"{_ACL_LAB}.1"),
        _pc("PC-L2", 700, 420, f"{_ACL_LAB}.11", f"{_ACL_LAB}.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "SW-A", "GigabitEthernet0/1"),
        LinkSpec("SW-A", "FastEthernet0/1", "PC-S1", "FastEthernet0"),
        LinkSpec("SW-A", "FastEthernet0/2", "PC-S2", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "R2", "GigabitEthernet0/1"),
        LinkSpec("R2", "GigabitEthernet0/0", "SW-B", "GigabitEthernet0/1"),
        LinkSpec("SW-B", "FastEthernet0/1", "PC-L1", "FastEthernet0"),
        LinkSpec("SW-B", "FastEthernet0/2", "PC-L2", "FastEthernet0"),
    ]
    return TopologySpec(
        name="ccna3-acl-policy",
        title="CCNA-3 — Extended ACL as Policy",
        devices=devices,
        links=links,
        faults=rebalance(_ACL_FAULTS),
        brief=_ACL_BRIEF,
        difficulty="advanced",
    )


# ---------------------------------------------------------------------------
# Lab 4 — ccna3-asymmetric
# ---------------------------------------------------------------------------

_ASYM_A = "192.168.10"  # LAN-A  192.168.10.0/24
_ASYM_B = "192.168.20"  # LAN-B  192.168.20.0/24
_ASYM_C = "192.168.30"  # LAN-C  192.168.30.0/24
_ASYM_12 = "10.0.12"  # R1 -- R2  10.0.12.0/30
_ASYM_23 = "10.0.23"  # R2 -- R3  10.0.23.0/30
_ASYM_13 = "10.0.13"  # R1 -- R3  10.0.13.0/30

_ASYM_BRIEF = """\
THE RETURN PATH NOBODY CHECKED

Three sites are fully meshed. The design sends LAN-A's traffic to LAN-C over the
direct link, while LAN-C's replies come back through R2. Outbound and return
paths are different on purpose — this is asymmetric routing, and it only works
while every router on the return path has the route it needs.

Addressing
  LAN-A   192.168.10.0/24   R1 Gi0/0  .1    PC-A .10
  LAN-B   192.168.20.0/24   R2 Gi0/0  .1    PC-B .10
  LAN-C   192.168.30.0/24   R3 Gi0/0  .1    PC-C .10
  R1--R2  10.0.12.0/30      R1 Gi0/1  .1    R2 Gi0/1 .2
  R2--R3  10.0.23.0/30      R2 Gi0/2  .1    R3 Gi0/1 .2
  R1--R3  10.0.13.0/30      R1 Gi0/2  .1    R3 Gi0/2 .2

Required end state
  * R1 reaches LAN-C over the direct R1-R3 link (administrative distance 1).
  * R1 also holds a floating static to LAN-C through R2 (distance 10) as backup.
  * R3 returns LAN-A traffic through R2, as the design requires.
  * R2 has the routes that make that return path work.
  * Every PC pings every other PC.

Rules of engagement
  * A ping that succeeds one way and fails the other is a return-path fault.
  * Trace the path in both directions; do not assume the reverse of a route.
  * Do not change addresses, device names or the cabling.
"""

_ASYM_FAULTS: list[FaultSpec] = [
    FaultSpec(
        fault_id="route-return-missing-r2",
        category=FaultCategory.ROUTING,
        severity=Severity.CRITICAL,
        device="R2",
        interface=None,
        description=(
            "R2 has no route to LAN-A. R3 sends LAN-A replies through R2, so the "
            "return half of an asymmetric flow is black-holed at R2."
        ),
        expected=f"ip route {_net(_ASYM_A)} 255.255.255.0 {_ASYM_12}.1",
        actual=f"! ip route {_net(_ASYM_A)} 255.255.255.0 {_ASYM_12}.1",
        symptom=(
            "PC-A pings PC-C and gets no reply, while PC-C's echo requests arrive "
            "at PC-A. `show ip route 192.168.10.0` on R2 is empty."
        ),
        points=25,
        hint_1="The forward path can be perfect while the return path is missing.",
        hint_2="R3's route to LAN-A names R2 as the next hop. Does R2 know LAN-A?",
        target=TargetKind.GLOBAL_LINE,
    ),
    FaultSpec(
        fault_id="route-wrong-next-hop-r3",
        category=FaultCategory.ROUTING,
        severity=Severity.CRITICAL,
        device="R3",
        interface=None,
        description=(
            "R3's return route to LAN-A points at 10.0.23.9, which is not on the "
            "R2-R3 link, so the return path is not installed at all."
        ),
        expected=f"ip route {_net(_ASYM_A)} 255.255.255.0 {_ASYM_23}.1",
        actual=f"ip route {_net(_ASYM_A)} 255.255.255.0 10.0.23.9",
        symptom=(
            "`show ip route 192.168.10.0` on R3 has no entry; 10.0.23.9 has no matching connected subnet."
        ),
        points=20,
        hint_1="Confirm the next hop is inside the /30 that carries it.",
        hint_2="The R2-R3 link is 10.0.23.0/30: usable addresses are .1 and .2.",
        target=TargetKind.GLOBAL_LINE,
    ),
    FaultSpec(
        fault_id="route-floating-missing-r1",
        category=FaultCategory.ROUTING,
        severity=Severity.MINOR,
        device="R1",
        interface=None,
        description=(
            "R1's floating static to LAN-C through R2 is missing, so losing the "
            "direct link leaves LAN-C unreachable even though a backup path exists."
        ),
        expected=f"ip route {_net(_ASYM_C)} 255.255.255.0 {_ASYM_12}.2 10",
        actual=f"! ip route {_net(_ASYM_C)} 255.255.255.0 {_ASYM_12}.2 10",
        symptom=(
            "`show ip route 192.168.30.0` on R1 lists a single path over Gi0/2 and "
            "no administrative distance 10 alternative."
        ),
        points=8,
        hint_1="Two paths exist between R1 and LAN-C; the table should know both.",
        hint_2="The backup runs through R2 and must be less preferred than the direct link.",
        target=TargetKind.GLOBAL_LINE,
    ),
    FaultSpec(
        fault_id="addr-lan-b-subnet-typo",
        category=FaultCategory.ADDRESSING,
        severity=Severity.CRITICAL,
        device="R2",
        interface="GigabitEthernet0/0",
        description=(
            "R2's LAN-B interface carries 192.168.2.1, so PC-B's default gateway "
            "192.168.20.1 does not exist and LAN-B is unreachable."
        ),
        expected=f" ip address {_ASYM_B}.1 255.255.255.0",
        actual=" ip address 192.168.2.1 255.255.255.0",
        symptom=(
            "PC-B cannot ping its gateway; `show ip interface brief` on R2 shows Gi0/0 in 192.168.2.0/24."
        ),
        points=20,
        hint_1="A LAN is reachable only if the gateway address the hosts use is real.",
        hint_2="One octet is missing from R2's LAN-B address.",
    ),
    FaultSpec(
        fault_id="iface-lan-a-shutdown",
        category=FaultCategory.INTERFACE,
        severity=Severity.MAJOR,
        device="R1",
        interface="GigabitEthernet0/0",
        description=(
            "R1's LAN-A interface is administratively shut down, so LAN-A has no "
            "gateway and every inbound path to it terminates at a dead interface."
        ),
        expected=" no shutdown",
        actual=" shutdown",
        symptom=("`show ip interface brief` on R1 lists Gi0/0 as administratively down."),
        points=15,
        hint_1="Check interface state before tracing routes.",
        hint_2="Gi0/0 on R1 serves LAN-A.",
    ),
    FaultSpec(
        fault_id="route-points-at-self-r2",
        category=FaultCategory.ROUTING,
        severity=Severity.MAJOR,
        device="R2",
        interface=None,
        description=(
            "R2's route to LAN-C points at 10.0.12.2 — R2's own address — instead "
            "of at R3's 10.0.23.2, so the packet is routed back to R2."
        ),
        expected=f"ip route {_net(_ASYM_C)} 255.255.255.0 {_ASYM_23}.2",
        actual=f"ip route {_net(_ASYM_C)} 255.255.255.0 {_ASYM_12}.2",
        symptom=(
            "`show ip route 192.168.30.0` on R2 shows a next hop on R2's own "
            "interface; PC-B cannot reach PC-C."
        ),
        points=12,
        hint_1="A next hop that belongs to the router itself is a loop, not a path.",
        hint_2="LAN-C is behind R3. The route belongs on the R2-R3 link.",
        target=TargetKind.GLOBAL_LINE,
    ),
]


def asymmetric() -> TopologySpec:
    """Three routers in a triangle where the return path is a different path."""
    devices = [
        _router(
            "R1",
            200,
            140,
            interfaces=(
                ("GigabitEthernet0/0", _lan(f"{_ASYM_A}.1")),
                ("GigabitEthernet0/1", _transit(f"{_ASYM_12}.1")),
                ("GigabitEthernet0/2", _transit(f"{_ASYM_13}.1")),
            ),
            routing=(
                f"ip route {_net(_ASYM_B)} 255.255.255.0 {_ASYM_12}.2",
                f"ip route {_net(_ASYM_C)} 255.255.255.0 {_ASYM_13}.2",
                f"ip route {_net(_ASYM_C)} 255.255.255.0 {_ASYM_12}.2 10",
            ),
        ),
        _router(
            "R2",
            460,
            300,
            interfaces=(
                ("GigabitEthernet0/0", _lan(f"{_ASYM_B}.1")),
                ("GigabitEthernet0/1", _transit(f"{_ASYM_12}.2")),
                ("GigabitEthernet0/2", _transit(f"{_ASYM_23}.1")),
            ),
            routing=(
                f"ip route {_net(_ASYM_A)} 255.255.255.0 {_ASYM_12}.1",
                f"ip route {_net(_ASYM_C)} 255.255.255.0 {_ASYM_23}.2",
            ),
        ),
        _router(
            "R3",
            720,
            140,
            interfaces=(
                ("GigabitEthernet0/0", _lan(f"{_ASYM_C}.1")),
                ("GigabitEthernet0/1", _transit(f"{_ASYM_23}.2")),
                ("GigabitEthernet0/2", _transit(f"{_ASYM_13}.2")),
            ),
            routing=(
                # The return path: LAN-A replies go through R2, not directly.
                f"ip route {_net(_ASYM_A)} 255.255.255.0 {_ASYM_23}.1",
                f"ip route {_net(_ASYM_B)} 255.255.255.0 {_ASYM_23}.1",
            ),
        ),
        _pc("PC-A", 200, 260, f"{_ASYM_A}.10", f"{_ASYM_A}.1"),
        _pc("PC-B", 460, 420, f"{_ASYM_B}.10", f"{_ASYM_B}.1"),
        _pc("PC-C", 720, 260, f"{_ASYM_C}.10", f"{_ASYM_C}.1"),
    ]
    links = [
        LinkSpec("R1", "GigabitEthernet0/0", "PC-A", "FastEthernet0"),
        LinkSpec("R2", "GigabitEthernet0/0", "PC-B", "FastEthernet0"),
        LinkSpec("R3", "GigabitEthernet0/0", "PC-C", "FastEthernet0"),
        LinkSpec("R1", "GigabitEthernet0/1", "R2", "GigabitEthernet0/1"),
        LinkSpec("R2", "GigabitEthernet0/2", "R3", "GigabitEthernet0/1"),
        LinkSpec("R1", "GigabitEthernet0/2", "R3", "GigabitEthernet0/2"),
    ]
    return TopologySpec(
        name="ccna3-asymmetric",
        title="CCNA-3 — Asymmetric Routing and the Missing Return Path",
        devices=devices,
        links=links,
        faults=rebalance(_ASYM_FAULTS),
        brief=_ASYM_BRIEF,
        difficulty="advanced",
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_BUILDERS = {
    "ccna3-static-chains": static_chains,
    "ccna3-route-selection": route_selection,
    "ccna3-acl-policy": acl_policy,
    "ccna3-asymmetric": asymmetric,
}

#: Lab names in teaching order.
LAB_NAMES: tuple[str, ...] = (
    "ccna3-static-chains",
    "ccna3-route-selection",
    "ccna3-acl-policy",
    "ccna3-asymmetric",
)


def lab(name: str) -> TopologySpec:
    """One lab by name. ``KeyError`` names the valid choices."""
    try:
        builder = _BUILDERS[name]
    except KeyError:
        raise KeyError(f"unknown CCNA-3 lab {name!r}; choose from {', '.join(LAB_NAMES)}") from None
    return builder()


def labs() -> dict[str, TopologySpec]:
    """Every lab, keyed by name, in teaching order."""
    return {name: lab(name) for name in LAB_NAMES}


def clean_control(name: str) -> TopologySpec:
    """The same network with no faults: the reference build the answer key implies.

    ``generate(spec, apply_faults=False)`` writes this configuration. Dropping
    ``faults`` as well means the spec can be diagnosed directly as a model of a
    healthy network — which is what the false-positive guard needs.
    """
    return dataclasses.replace(lab(name), faults=[])


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Probe:
    """A read-only way to observe one fault on a real device.

    ``command`` must be a ``show`` command: probes are for evidence, not repair.
    ``expect_present`` is True when the probe's output should show the fault
    (the defective value or state) and False when the output should show the
    intended value *missing* — the same convention the gauntlet uses.

    ``expected_kind`` names the diagnostic hypothesis the offline engine should
    form for this fault in isolation (values match
    ``trident.diagnostics``'s exported constants). It is ``None`` for faults the
    static engine cannot see — a specific static route that is simply absent is
    not a defect any single-field rule can prove, and claiming otherwise would
    be a lie in the answer key.
    """

    fault_id: str
    device: str
    command: str
    expect_present: bool
    expected_kind: str | None = None


_PROBES: dict[str, tuple[Probe, ...]] = {
    "ccna3-static-chains": (
        Probe("route-missing-lan-c", "R1", "show ip route 192.168.30.0", False),
        Probe("route-wrong-next-hop", "R3", "show ip route 192.168.20.0", True, "UNREACHABLE_NEXT_HOP"),
        Probe("addr-lan-b-subnet-typo", "R2", "show ip interface brief", True, "WRONG_GATEWAY"),
        Probe("iface-lan-c-shutdown", "R3", "show ip interface brief", True, "SHUTDOWN_INTERFACE"),
        Probe("route-return-points-at-self", "R2", "show ip route 192.168.10.0", True, "ROUTING_LOOP"),
    ),
    "ccna3-route-selection": (
        Probe(
            "route-primary-wrong-next-hop", "R1", "show ip route 192.168.20.0", True, "UNREACHABLE_NEXT_HOP"
        ),
        Probe("route-floating-missing", "R1", "show running-config | include ip route", False),
        Probe("addr-servers-mask-transposed", "R2", "show ip interface brief", True, "INVALID_MASK"),
        Probe("iface-primary-path-shutdown", "R1", "show ip interface brief", True, "SHUTDOWN_INTERFACE"),
        Probe(
            "route-return-wrong-next-hop", "R2", "show ip route 192.168.10.0", True, "UNREACHABLE_NEXT_HOP"
        ),
    ),
    "ccna3-acl-policy": (
        Probe("acl-deny-all-by-accident", "R1", "show access-lists", True, "ACL_BLOCK"),
        Probe("route-return-missing", "R2", "show ip route 192.168.10.0", False),
        Probe("route-wrong-next-hop", "R1", "show ip route 192.168.20.0", True, "UNREACHABLE_NEXT_HOP"),
        Probe("addr-staff-subnet-wrong", "R1", "show ip interface brief", True, "WRONG_GATEWAY"),
        Probe("iface-transit-shutdown", "R2", "show ip interface brief", True, "SHUTDOWN_INTERFACE"),
    ),
    "ccna3-asymmetric": (
        Probe("route-return-missing-r2", "R2", "show ip route 192.168.10.0", False),
        Probe("route-wrong-next-hop-r3", "R3", "show ip route 192.168.10.0", True, "UNREACHABLE_NEXT_HOP"),
        Probe("route-floating-missing-r1", "R1", "show ip route 192.168.30.0", False),
        Probe("addr-lan-b-subnet-typo", "R2", "show ip interface brief", True, "WRONG_GATEWAY"),
        Probe("iface-lan-a-shutdown", "R1", "show ip interface brief", True, "SHUTDOWN_INTERFACE"),
        Probe("route-points-at-self-r2", "R2", "show ip route 192.168.30.0", True, "ROUTING_LOOP"),
    ),
}


def probes_for(name: str) -> tuple[Probe, ...]:
    """The read-only verification probes for one lab, in fault order."""
    try:
        probes = _PROBES[name]
    except KeyError:
        raise KeyError(f"unknown CCNA-3 lab {name!r}; choose from {', '.join(LAB_NAMES)}") from None
    order = {fault.fault_id: i for i, fault in enumerate(lab(name).faults)}
    return tuple(sorted(probes, key=lambda probe: order.get(probe.fault_id, len(order))))


# ---------------------------------------------------------------------------
# Offline model building (no Packet Tracer)
# ---------------------------------------------------------------------------


def end_hosts_for(spec: TopologySpec) -> dict[str, dict[str, str]]:
    """NIC facts for every end device, in the shape parser adapters report.

    PCs and servers have no running-config, so their address, mask and gateway
    are only visible as end-host facts. Without them the diagnostics engine has
    no way to relate a host to its subnet and the gateway detectors cannot run.
    """
    hosts: dict[str, dict[str, str]] = {}
    for device in spec.devices:
        if not device.pc_ip:
            continue
        address, mask, gateway = device.pc_ip
        hosts[device.name] = {"ip": address, "subnet": mask, "gateway": gateway}
    return hosts


def end_host_gateway_support() -> tuple[bool, str]:
    """Whether the installed ``pkt_core`` writes an end-host gateway PT will read.

    Packet Tracer reads a PC's default gateway from ``<ENGINE><GATEWAY>``, not
    from ``<PORT><PORT_GATEWAY>``. ``pkt_core`` 0.2.2 — the version pinned in
    this venv — writes only the port element, so every PC it builds keeps the
    donor template's ``1.1.1.2`` and cannot route off-link in the simulator. The
    newer ``pkt_core`` copy on this machine writes both.

    This is not a property of a lab spec: the same builder builds every lab in
    ``trident.labgen``, so the defect is shared. The probe exists so the
    limitation is measured rather than assumed, and so a test can fail loudly
    when the dependency is fixed.

    Returns ``(supported, note)`` and never raises.
    """
    try:
        from pkt_core.builder import Lab
    except Exception as exc:  # noqa: BLE001 - any import failure means "cannot check"
        return False, f"pkt_core unavailable: {type(exc).__name__}: {exc}"

    probe_address = "192.168.250.10"
    probe_gateway = "192.168.250.1"
    try:
        lab = Lab()
        lab.prune_seed_devices()
        lab.add_device(
            "PC-PT",
            "PROBE-PC",
            0,
            0,
            pc_ip=(probe_address, "255.255.255.0", probe_gateway),
        )
        # ``Lab.base`` is the tree ``save()`` serialises, so reading it is the
        # same evidence as reading the written file without touching the disk.
        written: str | None = None
        for device in lab.base.iter("DEVICE"):
            if device.findtext("ENGINE/NAME") == "PROBE-PC":
                written = device.findtext("ENGINE/GATEWAY")
                break
    except Exception as exc:  # noqa: BLE001 - a probe must not raise
        return False, f"could not probe pkt_core: {type(exc).__name__}: {exc}"

    if written == probe_gateway:
        return True, "pkt_core serialises the end-host gateway into <ENGINE><GATEWAY>"
    return False, (
        f"pkt_core writes <PORT><PORT_GATEWAY> but leaves <ENGINE><GATEWAY> at "
        f"{written!r}; Packet Tracer reads the latter, so generated PCs would keep "
        f"that donor gateway instead of {probe_gateway}"
    )


def build_network_model(spec: TopologySpec, *, apply_faults: bool = False):
    """Build a :class:`~trident.models.NetworkModel` from a spec, offline.

    This is the bridge between a lab *specification* and the diagnostics engine:
    it parses the same config lines that would be written into the ``.pkt`` and
    feeds them through the production normaliser, so a diagnosis of a lab is a
    diagnosis of the artefact rather than of a hand-built model that only looks
    like it. Packet Tracer is not involved and the result says nothing about
    simulator compatibility.

    ``apply_faults=False`` (the default) models the intended, healthy network.
    """
    from trident.models import ParserReport, ParserState
    from trident.normalization.devices import Normalizer
    from trident.parsers.base import AdapterResult

    from .builder import build_configs

    configs = build_configs(spec, apply_faults=apply_faults)
    result = AdapterResult(
        engine_id="labgen-ccna3",
        report=ParserReport(
            engine="labgen-ccna3",
            state=ParserState.OK,
            message="offline model built from spec configuration text",
        ),
        devices=sorted(configs),
        configs={device: list(lines) for device, lines in configs.items()},
        links=[(link.a, link.a_port, link.b, link.b_port, "copper") for link in spec.links],
        end_hosts=end_hosts_for(spec),
        extraction_family="labgen-ccna3",
    )
    return Normalizer([result], snapshot_id=spec.name).build()


__all__ = [
    "LAB_NAMES",
    "Probe",
    "acl_policy",
    "asymmetric",
    "build_network_model",
    "clean_control",
    "end_host_gateway_support",
    "end_hosts_for",
    "lab",
    "labs",
    "probes_for",
    "route_selection",
    "static_chains",
]
