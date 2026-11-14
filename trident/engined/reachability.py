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
            default = str(net) == "0.0.0.0/0"
            return ForwardingDecision(
                PathResult.DEFAULT if default else PathResult.VIA_NEXT_HOP,
                self.device,
                next_hop=next_hop,
                matched_route=str(net),
                detail=f"{self.device} routes {dst} via {next_hop or 'an interface'} ({net})",
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
        address = ipaddress.IPv4Address(str(destination))
        # Classful default, matching how a bare prefix is read on IOS.
        if address in ipaddress.IPv4Network("10.0.0.0/8"):
            return ipaddress.IPv4Network(f"{destination}/8", strict=False)
        if address in ipaddress.IPv4Network("172.16.0.0/12"):
            return ipaddress.IPv4Network(f"{destination}/16", strict=False)
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

    Handles ``any`` and CIDR. Host/range forms this does not model return False
    rather than guessing, so an unmodelled ACE produces an inconclusive result
    upstream instead of a wrong deny.
    """
    token = (spec or "any").strip().lower()
    if token in {"any", "0.0.0.0/0"}:
        return True
    try:
        if "/" in token:
            return ipaddress.IPv4Address(address) in ipaddress.IPv4Network(token, strict=False)
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
