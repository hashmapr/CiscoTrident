"""Deterministic forwarding and filtering reasoning for Engine D.

Every function here returns *evidence* — which device, interface, route or ACE
decided the outcome — rather than a bare boolean. A verdict without its cause is
not actionable, and the whole point of Engine D is root-cause localization.

Nothing in this module consults an LLM, and nothing infers intent. It answers
"given this table, where does a packet for X go?" and nothing more.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import StrEnum


class PathResult(StrEnum):
    """Where a packet for a destination ends up."""

    CONNECTED = "connected"      # destination is on a directly attached subnet
    VIA_NEXT_HOP = "via_next_hop"
    DEFAULT = "default"
    NO_ROUTE = "no_route"        # router has no matching route
    LOCAL = "local"              # destination is this device's own address
    UNSUPPORTED = "unsupported"  # dynamic routing / NAT: not modelled


@dataclass(frozen=True)
class ForwardingDecision:
    """One routing decision, with the evidence that produced it."""

    result: PathResult
    device: str
    next_hop: str | None = None
    out_interface: str | None = None
    matched_route: str | None = None
    detail: str = ""

    @property
    def forwards(self) -> bool:
        return self.result in {
            PathResult.CONNECTED,
            PathResult.VIA_NEXT_HOP,
            PathResult.DEFAULT,
            PathResult.LOCAL,
        }


def _iface_network(interface) -> ipaddress.IPv4Network | None:
    address = getattr(interface, "ipv4_address", None)
    prefix = getattr(interface, "prefix_length", None)
    if not address or prefix is None:
        return None
    try:
        return ipaddress.IPv4Network(f"{address}/{prefix}", strict=False)
    except ValueError:
        return None


#: Packet Tracer model strings for devices that forward packets between subnets.
#:
#: This table exists because ``DeviceInfo.device_type`` is ``None`` in every
#: model this pipeline produces — verified against five labs — so it cannot be
#: used. The model string is the only discriminator the parsers actually carry.
#:
#: Multilayer switches appear here because a 3560/3650 routes with ``ip routing``;
#: a 2960 does not, and treating every switch as L3 would let a plain access
#: switch be proposed as a gateway.
_ROUTER_MODELS = (
    "2911", "2901", "2811", "1841", "1941", "1941W", "4331", "4321",
    "4221", "4431", "4451", "ISR", "CSR", "ASR", "router",
)
_L3_SWITCH_MODELS = ("3560", "3650", "3750", "3850", "9300", "multilayer")
_END_HOST_MODELS = ("PC-PT", "Server-PT", "Laptop-PT", "Tablet-PT", "Printer-PT", "Phone")


def classify_device(model, device: str) -> str:
    """Classify a device as router / l3_switch / switch / end_host / unknown.

    Order matters: end hosts are checked first because ``Server-PT`` contains no
    router token but a naive substring search for "er" would be absurd; and
    multilayer switches are checked before plain switches because "3650"
    contains "36" and "2960" does not.

    Nothing here decides *whether routing succeeds* — only what kind of box it
    is. A router is not automatically the intended gateway; that is a separate
    question answered by the forwarding table.
    """
    info = getattr(model, "devices", {}).get(device)
    declared = (getattr(info, "device_type", None) or "").strip().lower() if info else ""
    name = (getattr(info, "model", None) or "") if info else ""

    # An explicit device_type, when a parser supplies one, is authoritative.
    if declared:
        if "router" in declared:
            return "router"
        if "multilayer" in declared or "l3" in declared or "layer3" in declared:
            return "l3_switch"
        if "switch" in declared:
            return "switch"
        if any(token in declared for token in ("pc", "server", "laptop", "host")):
            return "end_host"

    upper = str(name).upper()
    if any(token.upper() in upper for token in _END_HOST_MODELS):
        return "end_host"
    if any(token.upper() in upper for token in _L3_SWITCH_MODELS):
        return "l3_switch"
    if any(token.upper() in upper for token in _ROUTER_MODELS):
        return "router"
    if "2960" in upper or "2950" in upper or "SWITCH" in upper or "SW" in upper:
        return "switch"

    # Last resort: a device that demonstrably routes. A route table is proof of
    # routing capability, unlike an interface count which only suggests it.
    if any(getattr(r, "device", None) == device for r in getattr(model, "routes", [])):
        return "router"
    return "unknown"


def is_router_like(model, device: str) -> bool:
    """Whether ``device`` can forward between subnets.

    Deliberately *not* based on interface count. A single-interface router is a
    normal lab device, and an ordinary switch with a management IP has an
    addressed interface without routing anything. Both were previously
    misclassified: the router was rejected, and every requirement behind it
    became INCONCLUSIVE.

    Routing capability is a property of the device kind, optionally corroborated
    by an actual route table — never of how many interfaces happen to have an
    address.
    """
    return classify_device(model, device) in {"router", "l3_switch"}


def router_for_address(model, address: str, exclude=()) -> str | None:
    """The *router* whose interface actually serves ``address``'s subnet.

    Only routers qualify. Returning the first interface whose subnet contains the
    address would let another host on the same LAN answer for the gateway — a
    healthy network then produces a missing-route finding, which is precisely
    the false positive Engine D exists to avoid.

    ``exclude`` names devices that must not be returned. During a trace the
    router we are standing on is a candidate for its own next-hop subnet; without
    the exclusion the walk would resolve the next hop back to itself and stop.

    When several routers cover the address, the most specific prefix wins, then a
    stable (device, interface) order. That mirrors longest-prefix forwarding and
    keeps the answer deterministic.
    """
    try:
        query = ipaddress.IPv4Address(address)
    except ValueError:
        return None

    excluded = set(exclude)
    candidates = []
    for interface in getattr(model, "interfaces", {}).values():
        if getattr(interface, "ipv4_address", None) in {None, address}:
            continue
        if interface.device in excluded:
            continue
        if not is_router_like(model, interface.device):
            continue
        net = _iface_network(interface)
        if net is None or query not in net:
            continue
        candidates.append((net.prefixlen, interface))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (-item[0], item[1].device, item[1].name))
    return candidates[0][1].device


class ForwardingTable:
    """A device's forwarding view, derived from the normalised model."""

    def __init__(self, model, device: str) -> None:
        self.model = model
        self.device = device
        self.interfaces = [
            i
            for i in getattr(model, "interfaces", {}).values()
            if i.device == device
        ]
        self.routes = [r for r in getattr(model, "routes", []) if r.device == device]

    def own_addresses(self) -> set[str]:
        return {
            i.ipv4_address for i in self.interfaces if getattr(i, "ipv4_address", None)
        }

    def is_admin_down(self, address: str) -> tuple[bool, str | None]:
        """Whether the interface holding ``address`` is administratively down.

        A shutdown interface is the single most common "everything looks right
        but nothing works" fault, so it is checked before routing.
        """
        for interface in self.interfaces:
            if getattr(interface, "ipv4_address", None) != address:
                continue
            state = (getattr(interface, "admin_state", "") or "").lower()
            if "down" in state:
                return True, interface.name
        return False, None

    def connected_network_for(self, address: str) -> ipaddress.IPv4Network | None:
        for interface in self.interfaces:
            net = _iface_network(interface)
            if net is None:
                continue
            try:
                if ipaddress.IPv4Address(address) in net:
                    return net
            except ValueError:
                continue
        return None

    def _next_hop_reachable(self, next_hop: str) -> bool:
        """Whether ``next_hop`` sits inside a subnet on one of our interfaces."""
        try:
            hop = ipaddress.IPv4Address(next_hop)
        except ValueError:
            return False
        for interface in self.interfaces:
            net = _iface_network(interface)
            if net is not None and hop in net:
                return True
        return False

    def _egress_shutdown(self, next_hop: str | None) -> str | None:
        """Name the egress interface for ``next_hop`` if it is administratively down."""
        if not next_hop:
            return None
        try:
            hop = ipaddress.IPv4Address(next_hop)
        except ValueError:
            return None
        for interface in self.interfaces:
            net = _iface_network(interface)
            if net is None or hop not in net:
                continue
            if "down" in (getattr(interface, "admin_state", "") or "").lower():
                return interface.name
        return None

    def decide(self, destination: str) -> ForwardingDecision:
        """Longest-prefix match against connected subnets, then static routes."""
        try:
            dst = ipaddress.IPv4Address(destination)
        except ValueError:
            return ForwardingDecision(
                PathResult.UNSUPPORTED, self.device, detail=f"{destination} is not an IPv4 address"
            )

        if str(dst) in self.own_addresses():
            return ForwardingDecision(
                PathResult.LOCAL, self.device, detail=f"{dst} is an address of {self.device}"
            )

        # Connected subnets win over any route, as they do in IOS.
        for interface in self.interfaces:
            net = _iface_network(interface)
            if net is None or dst not in net:
                continue
            down, name = self.is_admin_down(interface.ipv4_address)
            if down:
                return ForwardingDecision(
                    PathResult.NO_ROUTE,
                    self.device,
                    out_interface=name,
                    detail=f"{name} is administratively down, so {net} is not forwarding",
                )
            return ForwardingDecision(
                PathResult.CONNECTED,
                self.device,
                out_interface=interface.name,
                matched_route=str(net),
                detail=f"{dst} is directly connected on {interface.name}",
            )

        best: tuple[int, object] | None = None
        for route in self.routes:
            net = _route_network(route)
            if net is None or dst not in net:
                continue
            if best is None or net.prefixlen > best[0]:
                best = (net.prefixlen, (route, net))
        if best is not None:
            route, net = best[1]
            next_hop = getattr(route, "next_hop", None)
            # The interface that carries this next hop must be forwarding. A
            # route is installed but useless if its egress port is shut; that is
            # the commonest transit fault and must be localised to the port.
            blocked = self._egress_shutdown(next_hop)
            if blocked is not None:
                return ForwardingDecision(
                    PathResult.NO_ROUTE,
                    self.device,
                    out_interface=blocked,
                    matched_route=str(net),
                    detail=(
                        f"{self.device} has a route to {net} via {next_hop}, but "
                        f"{blocked} is administratively down"
                    ),
                )
            # A next hop that is on no connected subnet is uninstalled by IOS.
            # Reporting the route as usable here is the "configured but dead"
            # trap, and it hid the UNREACHABLE_NEXT_HOP fault entirely.
            if next_hop and not self._next_hop_reachable(next_hop):
                return ForwardingDecision(
                    PathResult.NO_ROUTE,
                    self.device,
                    next_hop=next_hop,
                    matched_route=str(net),
                    detail=(
                        f"{self.device} has a route to {net} via {next_hop}, but "
                        f"{next_hop} is not on any connected subnet"
                    ),
                )
            default = str(net) == "0.0.0.0/0"
            # Carry the route's own egress interface when the model has one, so a
            # trace can name the port rather than "an interface" and a
            # point-to-point route with no next hop can still be followed.
            out_interface = getattr(route, "outgoing_interface", None)
            return ForwardingDecision(
                PathResult.DEFAULT if default else PathResult.VIA_NEXT_HOP,
                self.device,
                next_hop=next_hop,
                out_interface=out_interface,
                matched_route=str(net),
                detail=f"{self.device} routes {dst} via {next_hop or out_interface or 'an interface'} ({net})",
            )

        return ForwardingDecision(
            PathResult.NO_ROUTE,
            self.device,
            detail=f"{self.device} has no route covering {dst}",
        )


def _route_network(route) -> ipaddress.IPv4Network | None:
    """A route's network, respecting a separately-stored mask.

    A bare address would otherwise become /32 and match nothing useful.
    """
    destination = getattr(route, "destination", None)
    if not destination:
        return None
    if "/" in str(destination):
        try:
            return ipaddress.IPv4Network(str(destination), strict=False)
        except ValueError:
            return None
    mask = getattr(route, "mask", None) or getattr(route, "subnet_mask", None)
    try:
        if mask:
            return ipaddress.IPv4Network(f"{destination}/{mask}", strict=False)
        # No mask: a bare address is a /32 and would match nothing. Infer the
        # classful length, which is what an IOS "ip route 10.0.2.0" line means
        # when the model did not carry a separate mask field.
        # A real IOS route always carries a mask; a bare address reaching here
        # means the model lost it. Infer the most common lab prefix (/24) and
        # say so, rather than guessing classful.
        #
        # Classful inference was actively harmful: "ip route 172.16.42.0 ..."
        # became 172.16.0.0/16, which covered the transit subnet 10.10.40.0/30's
        # neighbour and produced a fabricated forwarding loop on a network whose
        # only real fault was one missing route.
        return ipaddress.IPv4Network(f"{destination}/24", strict=False)
    except ValueError:
        return None


@dataclass(frozen=True)
class AclDecision:
    """The outcome of applying a device's ACL chain to one packet."""

    action: str  # "permit" | "deny"
    acl_id: str | None = None
    ace_index: int | None = None
    implicit: bool = False
    detail: str = ""


def _acl_entries(model, device: str) -> list:
    entries = getattr(model, "acls", None)
    if not entries:
        return []
    return [e for e in entries if getattr(e, "device", device) == device]


def evaluate_acls(model, device: str, src: str, dst: str, protocol: str = "icmp") -> AclDecision:
    """Apply ``device``'s ACL entries to a packet, honouring implicit deny.

    Rules are evaluated in order, first match wins — the same semantics as IOS.
    An ``any any`` permit ends the scan as a permit; if nothing matches and the
    device has any ACL configured, the result is the implicit deny, which is
    reported as such rather than as a mystery.
    """
    entries = _acl_entries(model, device)
    if not entries:
        return AclDecision("permit", detail=f"{device} has no ACL configured")

    for index, entry in enumerate(entries):
        if not _ace_matches(entry, src, dst, protocol):
            continue
        action = (getattr(entry, "action", "") or "").lower()
        return AclDecision(
            action or "deny",
            acl_id=getattr(entry, "acl_id", None),
            ace_index=index,
            detail=(
                f"ACE {index} in {getattr(entry, 'acl_id', '?')} on {device} "
                f"{action}ed {protocol} {src} -> {dst}"
            ),
        )
    return AclDecision(
        "deny",
        implicit=True,
        detail=f"{device} has an ACL but no entry permits {src} -> {dst}; implicit deny",
    )


def _ace_matches(entry, src: str, dst: str, protocol: str) -> bool:
    entry_protocol = (getattr(entry, "protocol", "ip") or "ip").lower()
    if entry_protocol not in {"ip", protocol}:
        return False
    return _address_matches(getattr(entry, "source", "any"), src) and _address_matches(
        getattr(entry, "destination", "any"), dst
    )


def _address_matches(spec: str, address: str) -> bool:
    """Whether an ACE address token matches ``address``.

    IOS writes ACL addresses with a **wildcard mask**, not a prefix:
    ``10.85.10.0 0.0.0.255`` means 10.85.10.0/24. The parser keeps the two
    tokens as one string, so both shapes must be understood. Failing to parse
    the wildcard form made a real permit ACE look like a non-match, and the
    chain fell through to implicit deny — reporting a fault on a correctly
    configured ACL.

    Supported forms:
      ``any`` / ``0.0.0.0/0`` / ``host A.B.C.D`` / ``A.B.C.D/W`` / ``A.B.C.D M.M.M.M``
    """
    token = (spec or "any").strip().lower()
    if token in {"any", "0.0.0.0/0"}:
        return True
    try:
        addr = ipaddress.IPv4Address(address)
    except ValueError:
        return False

    if token.startswith("host "):
        return token.split(None, 1)[1] == address

    parts = token.split()
    if len(parts) == 2:
        try:
            network = ipaddress.IPv4Address(parts[0])
            wildcard = int(ipaddress.IPv4Address(parts[1]))
        except ValueError:
            return False
        # A wildcard is the bitwise complement of the mask.
        mask = int(ipaddress.IPv4Address(0xFFFFFFFF ^ wildcard))
        return (int(addr) & mask) == (int(network) & mask)

    if "/" in token:
        try:
            return addr in ipaddress.IPv4Network(token, strict=False)
        except ValueError:
            return False
    return token == address


@dataclass(frozen=True)
class VlanPath:
    """Whether a host's VLAN can reach its gateway through the switching path."""

    host: str
    vlan: int | None
    reachable: bool
    blockers: list[str] = field(default_factory=list)
    detail: str = ""


def vlan_path(model, host_device: str) -> VlanPath:
    """Trace a host's access port through the switch to a VLAN gateway.

    Blockers, in the order they are checked:

    * the host's access port is in no VLAN, or that VLAN is not defined;
    * the port is administratively down;
    * an uplink trunk on the same switch does not permit the VLAN;
    * no router interface serves that VLAN.
    """
    host_addrs = [
        i.ipv4_address
        for i in getattr(model, "interfaces", {}).values()
        if i.device == host_device and getattr(i, "ipv4_address", None)
    ]
    switch_port = None
    for interface in getattr(model, "interfaces", {}).values():
        if not getattr(interface, "vlan_assignments", None):
            continue
        peer = _peer(model, interface.device, interface.name)
        if peer and peer[0] == host_device:
            switch_port = interface
            break
    if switch_port is None:
        # Not a fault. A host with no VLAN-configured switch port has no
        # switching path to check: it is either directly on a router interface
        # or a router itself. Returning blockers here made every such model look
        # broken, because the caller reads blockers as reasons for failure.
        return VlanPath(
            host_device, None, True, [],
            f"{host_device} has no VLAN-configured switch port; nothing to check",
        )

    vlans = [v for v in switch_port.vlan_assignments if str(v).isdigit()]
    if not vlans:
        return VlanPath(
            host_device, None, False,
            ["access port has no VLAN"],
            f"{switch_port.device}:{switch_port.name} is in no access VLAN",
        )
    vlan = int(vlans[0])
    blockers: list[str] = []

    if "down" in (switch_port.admin_state or "").lower():
        blockers.append(f"{switch_port.device}:{switch_port.name} is administratively down")

    declared = {v.vlan_id for v in getattr(model, "vlans", [])}
    if declared and vlan not in declared:
        blockers.append(f"VLAN {vlan} is not defined in the VLAN database")

    # Walk the switching path toward the L3 gateway. A switch-to-switch link can
    # be administratively down and strand every host behind it, which the local
    # port check alone cannot see.
    blockers.extend(_uplink_blockers(model, switch_port.device, vlan))

    # Any trunk on the same switch must permit the VLAN.
    for interface in getattr(model, "interfaces", {}).values():
        if interface.device != switch_port.device:
            continue
        if (interface.access_mode or "").lower() != "trunk":
            continue
        allowed = [str(v) for v in interface.vlan_assignments]
        if allowed and str(vlan) not in allowed:
            blockers.append(
                f"{interface.device}:{interface.name} trunk does not permit VLAN {vlan}"
            )

    host_addr = host_addrs[0] if host_addrs else None
    gateway = _gateway_for_vlan(model, vlan, host_addr)
    if gateway is None:
        blockers.append(f"no router interface serves VLAN {vlan}")

    detail = (
        f"{host_device} is in VLAN {vlan} on {switch_port.device}:{switch_port.name}; "
        + (f"blocked by {blockers[0]}" if blockers else "path to gateway is clear")
    )
    return VlanPath(host_device, vlan, not blockers, blockers, detail)


def _uplink_blockers(model, start_switch: str, vlan: int) -> list[str]:
    """Administrative-down switch-to-switch links reachable from ``start_switch``.

    Breadth-first over the switching topology. A downed inter-switch link is the
    classic "one host works, another does not" fault, so it must be found by
    walking rather than by inspecting only the host's own port.
    """
    seen = {start_switch}
    queue = [start_switch]
    blockers: list[str] = []
    while queue:
        current = queue.pop(0)
        for link in getattr(model, "links", []):
            for local_dev, local_port, peer_dev, peer_port in (
                (link.device_a, link.interface_a, link.device_b, link.interface_b),
                (link.device_b, link.interface_b, link.device_a, link.interface_a),
            ):
                if local_dev != current or peer_dev in seen:
                    continue
                seen.add(peer_dev)
                local = model.interfaces.get(f"{local_dev}:{local_port}")
                peer = model.interfaces.get(f"{peer_dev}:{peer_port}")
                # Only follow switch-to-switch links (both sides have VLAN
                # assignments); a link to a host is that host's own port.
                if not (getattr(local, "vlan_assignments", None) and getattr(peer, "vlan_assignments", None)):
                    continue
                down = "down" in (getattr(local, "admin_state", "") or "").lower()
                if down:
                    blockers.append(
                        f"{local_dev}:{local_port} is administratively down, "
                        f"isolating {peer_dev}"
                    )
                else:
                    queue.append(peer_dev)
    return blockers


def _gateway_for_vlan(model, vlan: int, host_address: str | None = None):
    """The L3 interface that serves ``vlan``.

    Two shapes must both count:

    * a router subinterface carrying ``encapsulation dot1Q <vlan>``;
    * a plain routed interface whose own address is in the same subnet as the
      host — the single-VLAN case, which has no subinterfaces at all.

    Only checking ``vlan_assignments`` missed the second shape entirely and
    reported "no router interface serves VLAN 10" on a working network.
    """
    for interface in getattr(model, "interfaces", {}).values():
        if not getattr(interface, "ipv4_address", None):
            continue
        serves = vlan in [
            int(v) for v in getattr(interface, "vlan_assignments", []) if str(v).isdigit()
        ]
        if serves:
            return interface
    if host_address is None:
        return None
    for interface in getattr(model, "interfaces", {}).values():
        net = _iface_network(interface)
        if net is None:
            continue
        try:
            if ipaddress.IPv4Address(host_address) in net:
                return interface
        except ValueError:
            continue
    return None


def _peer(model, device: str, interface: str) -> tuple[str, str] | None:
    for link in getattr(model, "links", []):
        if getattr(link, "device_a", None) == device and getattr(link, "interface_a", None) == interface:
            return getattr(link, "device_b", None), getattr(link, "interface_b", None)
        if getattr(link, "device_b", None) == device and getattr(link, "interface_b", None) == interface:
            return getattr(link, "device_a", None), getattr(link, "interface_a", None)
    return None


def decide_forwarding(model, device: str, destination: str) -> ForwardingDecision:
    """Convenience: build a table and decide in one call."""
    return ForwardingTable(model, device).decide(destination)


# ---------------------------------------------------------------------------
# End-to-end path tracing
# ---------------------------------------------------------------------------


class TraceOutcome(StrEnum):
    """How a path between two addresses ended."""

    REACHABLE = "reachable"
    NO_ROUTE = "no_route"                          # a router had no matching route
    UNREACHABLE_NEXT_HOP = "unreachable_next_hop"  # route's next hop is off-subnet
    HOP_LIMIT = "hop_limit"                        # loop or path longer than max_hops
    UNSUPPORTED = "unsupported"                    # address is not analysable
    INCONCLUSIVE = "inconclusive"                  # the model lacks a needed fact


@dataclass
class PathTrace:
    """Every forwarding decision a packet provokes, with the fault it hit.

    ``decide`` answers "does *this* router forward?". A real path may cross three
    or four routers, and the only honest answer to "where does this packet die?"
    is the ordered list of decisions plus the hop that stopped it.
    """

    src_ip: str
    dst_ip: str
    hops: list[ForwardingDecision] = field(default_factory=list)
    outcome: TraceOutcome = TraceOutcome.INCONCLUSIVE
    fault_device: str | None = None
    fault_interface: str | None = None
    detail: str = ""
    missing: list[str] = field(default_factory=list)

    @property
    def reachable(self) -> bool:
        return self.outcome is TraceOutcome.REACHABLE

    @property
    def devices(self) -> list[str]:
        """The routers the packet traversed, in order, without repeats."""
        seen: list[str] = []
        for hop in self.hops:
            if hop.device not in seen:
                seen.append(hop.device)
        return seen

    def evidence(self) -> list[str]:
        """Every hop as a sentence, then the terminal statement."""
        lines = [hop.detail for hop in self.hops if hop.detail]
        if self.detail and self.detail not in lines:
            lines.append(self.detail)
        return lines or [
            f"no forwarding decision was evaluated for {self.src_ip} -> {self.dst_ip}"
        ]


def _address_owner(model, address: str) -> str | None:
    """The device that owns ``address`` exactly, if the model has one.

    A next hop is resolved by ownership, not by "some router on that subnet".
    Otherwise a route pointing at an end host would be followed into an
    unrelated router that merely shares the LAN.
    """
    for interface in getattr(model, "interfaces", {}).values():
        if getattr(interface, "ipv4_address", None) == address:
            return interface.device
    return None


def trace_path(
    model,
    src_ip: str,
    dst_ip: str,
    max_hops: int = 16,
    start_router: str | None = None,
) -> PathTrace:
    """Follow a packet from ``src_ip`` to ``dst_ip`` across as many routers as it takes.

    The walk starts at the router that serves the source subnet and then follows
    each ``next_hop`` to the device that owns it. It stops for exactly four
    reasons, each a distinct, localisable outcome:

    * **NO_ROUTE** — a router has no matching route. That router is the fault
      location, which is what lets a transit gap be named rather than guessed.
    * **UNREACHABLE_NEXT_HOP** — the matched route points at an address on no
      connected subnet. IOS does not install such a route; reporting the router
      that holds it is the whole point.
    * **HOP_LIMIT** — a loop, or a path longer than ``max_hops``. It never spins
      forever.
    * **INCONCLUSIVE** — the model lacks a fact: no router serves the source, the
      next hop is unowned, or the path leaves the modelled topology. This is the
      anti-fabrication stop; it is never a failure.

    Default routes are followed like any other: a router with ``0.0.0.0/0``
    reaches everything it does not know more specifically, so the walk continues
    through it instead of declaring a missing route. That distinction is what
    keeps an ISP edge router with only a default from being reported as broken.
    """
    trace = PathTrace(src_ip=src_ip, dst_ip=dst_ip)

    try:
        src = ipaddress.IPv4Address(src_ip)
        dst = ipaddress.IPv4Address(dst_ip)
    except ValueError:
        trace.outcome = TraceOutcome.UNSUPPORTED
        trace.detail = f"{src_ip} -> {dst_ip} is not an IPv4 path"
        return trace

    current = start_router or router_for_address(model, str(src))
    if current is None:
        trace.outcome = TraceOutcome.INCONCLUSIVE
        trace.missing.append(f"no router interface serves {src}")
        trace.detail = f"no L3 gateway for {src} is modelled"
        return trace

    visited: list[str] = []
    while len(trace.hops) < max_hops:
        if current in visited:
            trace.outcome = TraceOutcome.HOP_LIMIT
            trace.fault_device = current
            trace.detail = f"forwarding loop: {current} was already visited"
            return trace
        visited.append(current)

        table = ForwardingTable(model, current)
        decision = table.decide(str(dst))
        trace.hops.append(decision)

        if decision.result is PathResult.LOCAL:
            trace.outcome = TraceOutcome.REACHABLE
            trace.detail = f"delivered to {dst}, an address of {current}"
            return trace
        if decision.result is PathResult.CONNECTED:
            trace.outcome = TraceOutcome.REACHABLE
            trace.detail = f"delivered on {decision.out_interface} at {current}"
            return trace
        if decision.result is PathResult.UNSUPPORTED:
            trace.outcome = TraceOutcome.UNSUPPORTED
            trace.detail = decision.detail or f"{dst} is not analysable"
            return trace
        if decision.result is PathResult.NO_ROUTE:
            # ``decide`` reports a route whose next hop is on no connected subnet
            # as unusable and carries that next hop, so the trace can name the
            # precise fault class instead of a generic NO_ROUTE. The same branch
            # with a *connected* next hop is an administratively-down egress port,
            # which stays NO_ROUTE and is localised to the port.
            if decision.next_hop and table.connected_network_for(decision.next_hop) is None:
                trace.outcome = TraceOutcome.UNREACHABLE_NEXT_HOP
                trace.fault_device = current
                trace.fault_interface = decision.out_interface
                trace.detail = (
                    f"{current} route {decision.matched_route} points at "
                    f"{decision.next_hop}, which is not on any connected subnet; "
                    "IOS does not install that route"
                )
                return trace
            trace.outcome = TraceOutcome.NO_ROUTE
            trace.fault_device = current
            trace.fault_interface = decision.out_interface
            trace.detail = decision.detail or f"{current} has no route covering {dst}"
            return trace

        next_hop = decision.next_hop
        if next_hop:
            # A static route whose next hop is on no connected subnet is not
            # installed by IOS. There is no port to ARP out of, so the packet is
            # discarded at this router — never at the one that would have been
            # next.
            if table.connected_network_for(next_hop) is None:
                trace.outcome = TraceOutcome.UNREACHABLE_NEXT_HOP
                trace.fault_device = current
                trace.fault_interface = decision.out_interface
                trace.detail = (
                    f"{current} route {decision.matched_route} points at {next_hop}, "
                    "which is not on any connected subnet; IOS does not install "
                    "that route"
                )
                return trace
            if str(dst) == str(ipaddress.IPv4Address(next_hop)):
                trace.outcome = TraceOutcome.REACHABLE
                trace.detail = f"next hop {next_hop} is the destination"
                return trace

            owner = _address_owner(model, next_hop)
            if owner is None:
                trace.outcome = TraceOutcome.INCONCLUSIVE
                trace.fault_device = current
                trace.missing.append(
                    f"next hop {next_hop} is on a connected subnet but no modelled "
                    "device owns it"
                )
                trace.detail = (
                    f"{current} forwards to {next_hop}, but no modelled device "
                    "answers for that address"
                )
                return trace
            if not is_router_like(model, owner):
                trace.outcome = TraceOutcome.INCONCLUSIVE
                trace.fault_device = current
                trace.missing.append(
                    f"next hop {next_hop} belongs to {owner}, which is not modelled "
                    "as a router"
                )
                trace.detail = (
                    f"{current} forwards to {next_hop} on {owner}, but {owner} "
                    "cannot forward the packet onward"
                )
                return trace
            current = owner
            continue

        # A route that names only an egress interface (normal on a point-to-point
        # link) still has a peer. Follow the cable when the peer is a router.
        peer = _peer(model, current, decision.out_interface) if decision.out_interface else None
        if peer and is_router_like(model, peer[0]):
            current = peer[0]
            continue
        trace.outcome = TraceOutcome.INCONCLUSIVE
        trace.fault_device = current
        trace.missing.append(
            f"route via {decision.out_interface or 'an interface'} has no next hop "
            "and no modelled peer router"
        )
        trace.detail = (
            f"{current} routes {dst} out {decision.out_interface or 'an interface'} "
            "with no next hop, and the far end is not modelled"
        )
        return trace

    trace.outcome = TraceOutcome.HOP_LIMIT
    # Attribute to the last router that was actually asked, not the one the walk
    # would have visited next but never evaluated. The backstop says "this path
    # is longer than the limit", and the last decision is the evidence for it.
    trace.fault_device = trace.hops[-1].device if trace.hops else current
    trace.detail = f"hop limit {max_hops} reached before {dst} was delivered"
    return trace
