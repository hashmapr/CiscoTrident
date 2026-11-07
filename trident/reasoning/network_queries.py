"""Deterministic network query engine.

Every function here answers a question purely from the verified network model.
No AI, no guessing: a function returns ``None`` (or raises ``QueryError``) when
the model does not contain the fact, so callers can report INCOMPLETE /
NOT_AVAILABLE honestly instead of inventing a value.
"""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from ..models import DeviceInfo, InterfaceInfo, NetworkModel
from ..normalization.values import (
    broadcast_address,
    canonical_interface_name,
    network_address,
    normalize_ipv4,
    prefix_to_mask,
    same_subnet,
)


class QueryError(ValueError):
    """Raised when a query is malformed (not when data is merely absent)."""


@dataclass
class QueryResult:
    """A deterministic answer plus the trace explaining how it was produced."""

    value: str
    field: str
    device: str | None = None
    interface: str | None = None
    trace: list[str] = None  # type: ignore[assignment]
    raw_evidence: str = ""

    def __post_init__(self) -> None:
        if self.trace is None:
            self.trace = []


# ---------------------------------------------------------------------------
# Device lookups
# ---------------------------------------------------------------------------

def find_device(model: NetworkModel, name: str) -> DeviceInfo | None:
    if not name or not name.strip():
        raise QueryError("device name is empty")
    return model.find_device(name.strip())


def find_device_by_hostname(model: NetworkModel, hostname: str) -> DeviceInfo | None:
    if not hostname or not hostname.strip():
        raise QueryError("hostname is empty")
    key = hostname.strip().lower()
    for dev in model.devices.values():
        if (dev.hostname or "").lower() == key:
            return dev
    return None


def get_interface(model: NetworkModel, device: str, interface: str) -> InterfaceInfo | None:
    dev = find_device(model, device)
    if dev is None:
        return None
    target = canonical_interface_name(interface)
    for canon in dev.interfaces:
        if canon != target:
            continue
        iface = model.interfaces.get(f"{dev.name}:{canon}")
        if iface is None:
            iface = model.interfaces.get(canon)
        if iface is not None:
            return iface
    return None


def device_ip(model: NetworkModel, device: str, interface: str | None = None) -> QueryResult | None:
    dev = find_device(model, device)
    if dev is None:
        return None
    candidates: list[InterfaceInfo] = []
    for canon in dev.interfaces:
        iface = model.interfaces.get(f"{dev.name}:{canon}") or model.interfaces.get(canon)
        if iface and iface.ipv4_address:
            if interface and iface.canonical_name != canonical_interface_name(interface):
                continue
            candidates.append(iface)
    if not candidates:
        return None
    # Prefer a single unambiguous answer; a device with several L3 addresses is
    # reported via get_all_ip_addresses instead of picking arbitrarily.
    if len(candidates) > 1 and interface is None:
        return None
    iface = candidates[0]
    return QueryResult(
        value=iface.ipv4_address,
        field="ipv4_address",
        device=dev.name,
        interface=iface.canonical_name,
        trace=[f"matched interface {iface.canonical_name} on {dev.name}"],
    )


def get_all_ip_addresses(model: NetworkModel, device: str) -> list[InterfaceInfo]:
    dev = find_device(model, device)
    if dev is None:
        return []
    out = []
    for canon in dev.interfaces:
        iface = model.interfaces.get(f"{dev.name}:{canon}") or model.interfaces.get(canon)
        if iface and iface.ipv4_address:
            out.append(iface)
    return sorted(out, key=lambda i: i.canonical_name)


def get_default_gateway(model: NetworkModel, device: str) -> QueryResult | None:
    dev = find_device(model, device)
    if dev is None:
        return None
    gw = model.settings.default_gateways.get(dev.name)
    if not gw:
        return None
    return QueryResult(
        value=gw,
        field="default_gateway",
        device=dev.name,
        trace=[f"default gateway recorded for {dev.name}"],
    )


def get_dns_servers(model: NetworkModel, device: str) -> list[str]:
    dev = find_device(model, device)
    if dev is None:
        return []
    return list(model.settings.dns_servers.get(dev.name, []))


def get_ios_version(model: NetworkModel, device: str) -> QueryResult | None:
    dev = find_device(model, device)
    if dev is None or not dev.ios_version:
        return None
    return QueryResult(value=dev.ios_version, field="ios_version", device=dev.name)


# ---------------------------------------------------------------------------
# VLANs
# ---------------------------------------------------------------------------

def get_vlan_assignment(model: NetworkModel, device: str, interface: str) -> QueryResult | None:
    iface = get_interface(model, device, interface)
    if iface is None:
        return None
    if iface.vlan_assignments:
        vlan = iface.vlan_assignments[0]
        return QueryResult(
            value=vlan,
            field="vlan",
            device=device,
            interface=iface.canonical_name,
            trace=[f"{iface.canonical_name} is a member of VLAN {vlan}"],
        )
    return None


def find_vlan(model: NetworkModel, vlan_id: int) -> list[str]:
    """Return the sorted device:interface members of a VLAN."""
    members: list[str] = []
    for iface in model.interfaces.values():
        if str(vlan_id) in iface.vlan_assignments:
            members.append(f"{iface.device}:{iface.canonical_name}")
    return sorted(members)


def list_vlans(model: NetworkModel) -> list[str]:
    return sorted({str(v.vlan_id) for v in model.vlans}, key=int)


# ---------------------------------------------------------------------------
# Subnet arithmetic (VERIFIED_DERIVED)
# ---------------------------------------------------------------------------

def subnet_network_address(ip: str, mask_or_prefix: str | int) -> QueryResult | None:
    ip_n = normalize_ipv4(ip)
    if ip_n is None:
        return None
    if isinstance(mask_or_prefix, str) and _is_prefix_string(mask_or_prefix):
        mask_or_prefix = int(mask_or_prefix.lstrip("/"))
    value = network_address(ip_n, mask_or_prefix)
    if value is None:
        return None
    return QueryResult(
        value=value,
        field="network_address",
        trace=[f"network_address({ip_n}, {mask_or_prefix}) = {value}"],
    )


def subnet_broadcast_address(ip: str, mask_or_prefix: str | int) -> QueryResult | None:
    ip_n = normalize_ipv4(ip)
    if ip_n is None:
        return None
    if isinstance(mask_or_prefix, str) and _is_prefix_string(mask_or_prefix):
        mask_or_prefix = int(mask_or_prefix.lstrip("/"))
    value = broadcast_address(ip_n, mask_or_prefix)
    if value is None:
        return None
    return QueryResult(
        value=value,
        field="broadcast_address",
        trace=[f"broadcast_address({ip_n}, {mask_or_prefix}) = {value}"],
    )


def ips_same_subnet(ip_a: str, ip_b: str, mask: str) -> QueryResult | None:
    a, b = normalize_ipv4(ip_a), normalize_ipv4(ip_b)
    if a is None or b is None:
        return None
    result = same_subnet(a, b, mask)
    if result is None:
        return None
    return QueryResult(
        value="yes" if result else "no",
        field="same_subnet",
        trace=[f"{a} and {b} under mask {mask} -> {'same' if result else 'different'} subnet"],
    )


def _is_prefix_string(value: str) -> bool:
    v = value.strip()
    return v.startswith("/") or (v.isdigit() and 0 <= int(v) <= 32)


def mask_for_prefix(prefix: int) -> str:
    return prefix_to_mask(prefix)


# ---------------------------------------------------------------------------
# Topology traversal
# ---------------------------------------------------------------------------

def build_topology_graph(model: NetworkModel) -> nx.Graph:
    graph = nx.Graph()
    for dev in model.devices:
        graph.add_node(dev, kind="device")
    for link in model.links:
        graph.add_edge(
            link.device_a,
            link.device_b,
            interface_a=link.interface_a,
            interface_b=link.interface_b,
            media=link.media_type,
        )
    return graph


def directly_connected(model: NetworkModel, device: str) -> list[str]:
    dev = find_device(model, device)
    if dev is None:
        return []
    peers: set[str] = set()
    for link in model.links:
        if link.device_a == dev.name:
            peers.add(link.device_b)
        elif link.device_b == dev.name:
            peers.add(link.device_a)
    return sorted(peers)


def topology_path(model: NetworkModel, source: str, target: str) -> list[str] | None:
    """Shortest physical path by device name, or None when disconnected."""
    src, dst = find_device(model, source), find_device(model, target)
    if src is None or dst is None:
        return None
    graph = build_topology_graph(model)
    if src.name not in graph or dst.name not in graph:
        return None
    try:
        return nx.shortest_path(graph, src.name, dst.name)
    except nx.NetworkXNoPath:
        return None


def interface_for_link(model: NetworkModel, device: str, peer: str) -> QueryResult | None:
    dev = find_device(model, device)
    if dev is None:
        return None
    for link in model.links:
        if link.device_a == dev.name and link.device_b == peer:
            return QueryResult(
                value=link.interface_a,
                field="link_interface",
                device=dev.name,
                interface=link.interface_a,
                trace=[f"{dev.name} connects to {peer} via {link.interface_a}"],
            )
        if link.device_b == dev.name and link.device_a == peer:
            return QueryResult(
                value=link.interface_b,
                field="link_interface",
                device=dev.name,
                interface=link.interface_b,
                trace=[f"{dev.name} connects to {peer} via {link.interface_b}"],
            )
    return None


# ---------------------------------------------------------------------------
# Routing / ACL queries
# ---------------------------------------------------------------------------

def routes_for_device(model: NetworkModel, device: str) -> list[str]:
    """Return configured route lines that reference one of ``device``'s interfaces.

    TRIDENT merges routes model-wide, so ownership is derived from the device's
    own interface evidence rather than guessed.
    """
    dev = find_device(model, device)
    if dev is None:
        return []
    interface_names = {canon.lower() for canon in dev.interfaces}
    owned: list[str] = []
    for route in model.routes:
        if not route.raw_config:
            continue
        lowered = route.raw_config.lower()
        if any(name in lowered for name in interface_names):
            owned.append(route.raw_config)
    return sorted(set(owned))


def static_route_lookup(model: NetworkModel, destination: str) -> list[str]:
    target = destination.strip()
    matches = [r for r in model.routes if r.destination == target]
    return [f"{r.route_type} {r.destination} via {r.next_hop or r.outgoing_interface or '-'}" for r in matches]


def acl_entries(model: NetworkModel, acl_id: str) -> list[str]:
    return [e.raw for e in model.acls if e.acl_id.lower() == acl_id.strip().lower()]


def switchport_mode(model: NetworkModel, device: str, interface: str) -> QueryResult | None:
    iface = get_interface(model, device, interface)
    if iface is None or not iface.access_mode:
        return None
    return QueryResult(
        value=iface.access_mode,
        field="switchport_mode",
        device=device,
        interface=iface.canonical_name,
    )


def network_device_summary(model: NetworkModel) -> dict:
    return {
        "devices": len(model.devices),
        "interfaces": len(model.interfaces),
        "links": len(model.links),
        "routes": len(model.routes),
        "vlans": len(model.vlans),
        "acls": len(model.acls),
    }
