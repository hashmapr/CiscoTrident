"""Deterministic fault injection into the baseline lab.

``inject(fault)`` always starts from a **fresh** ``baseline_lab()``, applies
exactly one defect and returns the resulting model. The returned object has no
attribute, note, warning or provenance entry that names the injected defect: the
only record of what was done is the ``Fault`` object the caller already holds.
"""

from __future__ import annotations

from ..models import AclEntry, InterfaceInfo, NetworkModel, RouteInfo
from .baseline import baseline_lab
from .types import Fault, FaultKind

#: Interface added by OVERLAPPING_SUBNET so the overlap is real topology, not a
#: dangling route.
_OVERLAP_INTERFACE = "Loopback0"


class InjectionError(ValueError):
    """Raised when a fault cannot be applied to the baseline topology."""


def _iface(model: NetworkModel, device: str, interface: str) -> InterfaceInfo:
    key = f"{device}:{interface}"
    info = model.interfaces.get(key)
    if info is None:
        raise InjectionError(f"{key} is not part of the baseline lab")
    return info


def _apply(model: NetworkModel, fault: Fault) -> None:
    """Apply one defect to ``model`` in place."""
    kind = fault.kind

    if kind is FaultKind.WRONG_VLAN:
        if not fault.interface:
            raise InjectionError("WRONG_VLAN requires an interface")
        _iface(model, fault.device, fault.interface).vlan_assignments = ["30"]

    elif kind is FaultKind.INVALID_MASK:
        if not fault.interface:
            raise InjectionError("INVALID_MASK requires an interface")
        info = _iface(model, fault.device, fault.interface)
        # Non-contiguous: not a legal subnet mask, so no prefix length exists.
        info.subnet_mask = "255.255.0.255"
        info.prefix_length = None

    elif kind is FaultKind.WRONG_GATEWAY:
        model.settings.default_gateways[fault.device] = "10.10.20.254"

    elif kind is FaultKind.MISSING_STATIC_ROUTE:
        before = len(model.routes)
        model.routes = [
            route
            for route in model.routes
            if not (route.device == fault.device and route.destination == "10.10.20.0/24")
        ]
        if len(model.routes) == before:
            raise InjectionError(f"no 10.10.20.0/24 route on {fault.device} to remove")

    elif kind is FaultKind.SHUTDOWN_INTERFACE:
        if not fault.interface:
            raise InjectionError("SHUTDOWN_INTERFACE requires an interface")
        info = _iface(model, fault.device, fault.interface)
        info.admin_state = "administratively down"
        info.operational_state = "down"

    elif kind is FaultKind.ACL_BLOCK:
        if not fault.interface:
            raise InjectionError("ACL_BLOCK requires an interface")
        model.acls.append(
            AclEntry(
                acl_id="101",
                acl_type="extended",
                sequence=10,
                action="deny",
                protocol="tcp",
                source="any",
                destination="10.10.20.50 0.0.0.0",
                port_conditions=["eq 443"],
                applied_interface=fault.interface,
                direction="in",
                raw="access-list 101 deny tcp any host 10.10.20.50 eq 443",
            )
        )
        # The ACL is bound to the interface, so record both sides explicitly.
        info = _iface(model, fault.device, fault.interface)
        info.description = "ip access-group 101 in"

    elif kind is FaultKind.TRUNK_MISMATCH:
        if not fault.interface:
            raise InjectionError("TRUNK_MISMATCH requires an interface")
        info = _iface(model, fault.device, fault.interface)
        info.access_mode = "trunk"
        # VLAN 20 is carried by the peer trunk but pruned here.
        info.vlan_assignments = ["10", "30"]

    elif kind is FaultKind.ROUTING_LOOP:
        model.routes.append(
            RouteInfo(
                device=fault.device,
                destination="10.10.10.0/24",
                next_hop="10.10.20.1",
                route_type="static",
                protocol="static",
                administrative_distance=1,
                raw_config="ip route 10.10.10.0 255.255.255.0 10.10.20.1",
            )
        )

    elif kind is FaultKind.DHCP_MISCONFIGURATION:
        pool = (
            "R2: pool LAN-POOL network 10.10.20.0/24 gateway 10.10.20.254 "
            "dns 203.0.113.53"
        )
        model.settings.dhcp_configured = [
            pool if entry.startswith("R2:") else entry
            for entry in model.settings.dhcp_configured
        ]

    elif kind is FaultKind.DUPLICATE_IP:
        if not fault.interface:
            raise InjectionError("DUPLICATE_IP requires an interface")
        info = _iface(model, fault.device, fault.interface)
        # PC1 already owns 10.10.20.10.
        info.ipv4_address = "10.10.20.10"
        info.subnet_mask = "255.255.255.0"
        info.prefix_length = 24

    elif kind is FaultKind.OVERLAPPING_SUBNET:
        key = f"{fault.device}:{_OVERLAP_INTERFACE}"
        model.interfaces[key] = InterfaceInfo(
            device=fault.device,
            name=_OVERLAP_INTERFACE,
            canonical_name=_OVERLAP_INTERFACE,
            ipv4_address="10.10.20.129",
            subnet_mask="255.255.255.128",
            prefix_length=25,
            access_mode=None,
            operational_state="up",
            admin_state="up",
        )
        device = model.devices.get(fault.device)
        if device is not None and _OVERLAP_INTERFACE not in device.interfaces:
            device.interfaces.append(_OVERLAP_INTERFACE)

    else:  # pragma: no cover - exhaustive over FaultKind
        raise InjectionError(f"unsupported fault kind {kind!r}")


def inject(fault: Fault) -> NetworkModel:
    """Return a fresh baseline lab with exactly this one fault applied."""
    model = baseline_lab()
    _apply(model, fault)
    return model


def inject_many(faults: tuple[Fault, ...] | list[Fault]) -> NetworkModel:
    """Return a fresh baseline lab with every fault in ``faults`` applied.

    Used to build multi-fault scenarios. Each fault must target a distinct
    device/interface pair, otherwise the later edit would mask the earlier one.
    """
    model = baseline_lab()
    targets: set[tuple[str, str | None]] = set()
    for fault in faults:
        target = (fault.device, fault.interface)
        if target in targets:
            raise InjectionError(f"two faults target the same entity {target!r}")
        targets.add(target)
        _apply(model, fault)
    return model
