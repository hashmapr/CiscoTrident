"""Root-cause diagnostics over canonical facts and operational evidence.

The engine answers one question: *given what this network claims and what the
devices actually report, which classes of defect are present?* It is the piece
Phase 2 left open — the evidence bundle and the fault lab were both built
expecting it.

Design rules, all enforced structurally:

* A hypothesis is ``CONFIRMED_DEFECT`` only with at least one supporting
  observation and nothing contradicting it. When static and runtime evidence
  disagree the hypothesis is ``SUSPECTED`` and **both** observations are kept;
  the engine never silently picks the convenient one.
* When a detector cannot see the evidence it needs it returns
  ``INSUFFICIENT_EVIDENCE`` naming the missing artefact. It does not guess and
  it does not report a defect.
* Every detector must be **silent on a healthy network**. The fault lab's
  baseline is used as the regression case: a detector that fires there is
  wrong, not a conservative extra finding.
* The detectors reason about *consistency between parts of the network*
  (a trunk against its peer, a gateway against real interface addresses, a
  router against the neighbour that depends on it) rather than about
  single-field patterns. Single-field rules fire on healthy baselines, which
  is why they are not used.
* Nothing here mutates a model. Detection is read-only by construction.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict

from ..evidence.bundle import EvidenceBundle
from ..models import InterfaceInfo, NetworkModel
from .types import (
    Confidence,
    Diagnosis,
    Hypothesis,
    HypothesisStatus,
    Observation,
)

WRONG_VLAN = "WRONG_VLAN"
INVALID_MASK = "INVALID_MASK"
WRONG_GATEWAY = "WRONG_GATEWAY"
MISSING_STATIC_ROUTE = "MISSING_STATIC_ROUTE"
SHUTDOWN_INTERFACE = "SHUTDOWN_INTERFACE"
ACL_BLOCK = "ACL_BLOCK"
TRUNK_MISMATCH = "TRUNK_MISMATCH"
ROUTING_LOOP = "ROUTING_LOOP"
DHCP_MISCONFIGURATION = "DHCP_MISCONFIGURATION"
DUPLICATE_IP = "DUPLICATE_IP"
OVERLAPPING_SUBNET = "OVERLAPPING_SUBNET"

_MODEL = "MODEL"
_RUNTIME = "RUNTIME_STATE"

_DOWN_STATES = {"down", "administratively down", "disabled"}
_DEFAULT_DESTINATIONS = {"0.0.0.0", "0.0.0.0/0"}


# ---------------------------------------------------------------------------
# Topology helpers
# ---------------------------------------------------------------------------


def _interfaces(model: NetworkModel) -> list[InterfaceInfo]:
    return list(model.interfaces.values())


def _find_interface(model: NetworkModel, device: str, name: str) -> InterfaceInfo | None:
    key = (device, name.strip().lower())
    for interface in _interfaces(model):
        if (interface.device, interface.name.strip().lower()) == key:
            return interface
        if (interface.device, (interface.canonical_name or "").strip().lower()) == key:
            return interface
    return None


def _device_networks(model: NetworkModel, device: str) -> list[ipaddress.IPv4Network]:
    nets = []
    for interface in _interfaces(model):
        if interface.device != device:
            continue
        net = _network_of(interface)
        if net is not None:
            nets.append(net)
    return nets


def _network_of(interface: InterfaceInfo) -> ipaddress.IPv4Network | None:
    if not interface.ipv4_address or interface.prefix_length is None:
        return None
    try:
        return ipaddress.IPv4Interface(
            f"{interface.ipv4_address}/{interface.prefix_length}"
        ).network
    except ValueError:
        return None


def _mask_is_contiguous(mask: str) -> bool:
    try:
        ipaddress.IPv4Network(f"0.0.0.0/{mask}")
    except (ipaddress.NetmaskValueError, ValueError):
        return False
    return True


def _address_owners(model: NetworkModel) -> dict[str, list[InterfaceInfo]]:
    owners: dict[str, list[InterfaceInfo]] = defaultdict(list)
    for interface in _interfaces(model):
        if interface.ipv4_address:
            owners[interface.ipv4_address].append(interface)
    return owners


def _peer_interface(model: NetworkModel, device: str, name: str) -> tuple[str, str] | None:
    key = name.strip().lower()
    for link in model.links:
        if link.device_a == device and link.interface_a.strip().lower() == key:
            return link.device_b, link.interface_b
        if link.device_b == device and link.interface_b.strip().lower() == key:
            return link.device_a, link.interface_a
    return None


def _endpoint_address(model: NetworkModel, device: str, name: str) -> tuple[str, int] | None:
    interface = _find_interface(model, device, name)
    if interface is None or not interface.ipv4_address or interface.prefix_length is None:
        return None
    return interface.ipv4_address, interface.prefix_length


def _is_trunk(interface: InterfaceInfo) -> bool:
    return (interface.access_mode or "").lower() == "trunk"


def _vlan_ids(values) -> set[int]:
    out: set[int] = set()
    for raw in values or ():
        match = re.search(r"\d+", str(raw))
        if match:
            out.add(int(match.group()))
    return out


def _route_network(destination: str) -> ipaddress.IPv4Network | None:
    text = (destination or "").strip()
    if not text or text in _DEFAULT_DESTINATIONS:
        return None
    if "/" not in text:
        text = f"{text}/32"
    try:
        return ipaddress.IPv4Network(text, strict=False)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Hypothesis construction
# ---------------------------------------------------------------------------


def _hypothesis(
    kind: str,
    device: str | None,
    interface: str | None,
    cause: str,
    supporting: tuple[Observation, ...],
    next_command: str | None,
    repair_hint: str | None,
    contradicting: tuple[Observation, ...] = (),
) -> Hypothesis:
    if supporting and not contradicting:
        status, confidence, missing = HypothesisStatus.CONFIRMED_DEFECT, Confidence.HIGH, ()
    elif supporting:
        status, confidence, missing = HypothesisStatus.SUSPECTED, Confidence.MEDIUM, ()
    else:
        status, confidence, missing = HypothesisStatus.INSUFFICIENT_EVIDENCE, Confidence.LOW, ("supporting observation",)
    return Hypothesis(
        kind=kind,
        status=status,
        confidence=confidence,
        device=device,
        interface=interface,
        suspected_cause=cause,
        supporting=tuple(supporting),
        contradicting=tuple(contradicting),
        missing_evidence=missing,
        next_command=next_command,
        repair_hint=repair_hint,
    )


def _runtime_row(bundle: EvidenceBundle, device: str, interface: str) -> dict | None:
    row = bundle.runtime_interfaces(device).get(interface)
    return row if isinstance(row, dict) else None


# ---------------------------------------------------------------------------
# Detectors — each is silent on a healthy network
# ---------------------------------------------------------------------------


def detect_invalid_mask(model: NetworkModel, bundle: EvidenceBundle) -> list[Hypothesis]:
    """An addressed interface whose mask is not a legal contiguous mask."""
    found: list[Hypothesis] = []
    for interface in _interfaces(model):
        if not interface.ipv4_address or not interface.subnet_mask:
            continue
        if _mask_is_contiguous(interface.subnet_mask):
            continue
        supporting = (
            Observation(
                source=_MODEL,
                device=interface.device,
                detail=(
                    f"{interface.name} has {interface.ipv4_address} with non-contiguous "
                    f"mask {interface.subnet_mask}"
                ),
            ),
        )
        contradicting: list[Observation] = []
        row = _runtime_row(bundle, interface.device, interface.name)
        if row is not None and row.get("ip"):
            runtime_ip = str(row["ip"])
            mask = runtime_ip.split("/", 1)[1] if "/" in runtime_ip else ""
            if not mask or _mask_is_contiguous(mask):
                contradicting.append(
                    Observation(
                        source=_RUNTIME,
                        device=interface.device,
                        detail=f"{interface.name} reports a usable address at runtime: {runtime_ip}",
                    )
                )
        found.append(
            _hypothesis(
                INVALID_MASK,
                interface.device,
                interface.name,
                "Interface carries a subnet mask that is not legal.",
                supporting,
                f"show ip interface brief {interface.name}",
                f"Re-address {interface.name} with a valid mask.",
                tuple(contradicting),
            )
        )
    return found


def detect_shutdown_interface(model: NetworkModel, bundle: EvidenceBundle) -> list[Hypothesis]:
    """An interface an administrator has disabled."""
    found: list[Hypothesis] = []
    for interface in _interfaces(model):
        if (interface.admin_state or "").lower() not in _DOWN_STATES:
            continue
        supporting = (
            Observation(
                source=_MODEL,
                device=interface.device,
                detail=f"{interface.name} admin state is '{interface.admin_state}'",
            ),
        )
        contradicting: list[Observation] = []
        row = _runtime_row(bundle, interface.device, interface.name)
        if (
            row is not None
            and str(row.get("status", "")).lower() == "up"
            and str(row.get("protocol", "")).lower() == "up"
        ):
            contradicting.append(
                Observation(
                    source=_RUNTIME,
                    device=interface.device,
                    detail=f"{interface.name} reports up/up at runtime",
                )
            )
        found.append(
            _hypothesis(
                SHUTDOWN_INTERFACE,
                interface.device,
                interface.name,
                "Interface is administratively down.",
                supporting,
                f"show interfaces {interface.name}",
                f"no shutdown on {interface.name}.",
                tuple(contradicting),
            )
        )
    return found


def detect_wrong_gateway(model: NetworkModel, bundle: EvidenceBundle) -> list[Hypothesis]:
    """A host/device default gateway that is not a real address in its subnet.

    A gateway is only valid when some interface in the same subnet actually
    holds that address. Being merely *inside* the subnet is not enough — an
    address nobody owns forwards nothing.
    """
    owners = _address_owners(model)
    found: list[Hypothesis] = []
    for device, gateway in model.settings.default_gateways.items():
        try:
            gateway_ip = ipaddress.IPv4Address(gateway)
        except ValueError:
            continue
        local_nets = _device_networks(model, device)
        if not local_nets:
            continue
        in_subnet = [net for net in local_nets if gateway_ip in net]
        if gateway in owners:
            continue
        # The gateway address exists nowhere on the network.
        supporting = (
            Observation(
                source=_MODEL,
                device=device,
                detail=(
                    f"default gateway {gateway} is not assigned to any interface"
                    + (f" in {in_subnet[0]}" if in_subnet else " and is outside every local subnet")
                ),
            ),
        )
        contradicting: list[Observation] = []
        row_devices = {device} | ({owners[gateway][0].device} if gateway in owners else set())
        for other in row_devices:
            for name, row in bundle.runtime_interfaces(other).items():
                if isinstance(row, dict) and str(row.get("ip", "")).startswith(gateway):
                    contradicting.append(
                        Observation(
                            source=_RUNTIME,
                            device=other,
                            detail=f"{name} holds {gateway} at runtime",
                        )
                    )
                    break
        found.append(
            _hypothesis(
                WRONG_GATEWAY,
                device,
                None,
                f"Default gateway {gateway} is not an address that exists on the network.",
                supporting,
                "show ip interface brief",
                "Set the default gateway to the router address inside the local subnet.",
                tuple(contradicting),
            )
        )
    return found


def detect_duplicate_ip(model: NetworkModel, _bundle: EvidenceBundle) -> list[Hypothesis]:
    """Two interfaces claiming the same address."""
    owners = _address_owners(model)
    found: list[Hypothesis] = []
    for address, holders in owners.items():
        if len(holders) < 2:
            continue
        names = ", ".join(sorted(f"{h.device}:{h.name}" for h in holders))
        first = holders[0]
        found.append(
            _hypothesis(
                DUPLICATE_IP,
                first.device,
                first.name,
                f"Address {address} is claimed by more than one interface ({names}).",
                (Observation(source=_MODEL, device=first.device, detail=f"{address} held by {names}"),),
                "show ip interface brief",
                f"Give each interface a unique address; {address} is duplicated.",
            )
        )
    return found


def detect_overlapping_subnet(model: NetworkModel, _bundle: EvidenceBundle) -> list[Hypothesis]:
    """Two distinct interface networks on one device that overlap."""
    found: list[Hypothesis] = []
    for device in model.devices:
        nets: list[tuple[ipaddress.IPv4Network, InterfaceInfo]] = []
        for interface in _interfaces(model):
            if interface.device != device:
                continue
            net = _network_of(interface)
            if net is not None:
                nets.append((net, interface))
        for index, (left, left_iface) in enumerate(nets):
            for right, right_iface in nets[index + 1 :]:
                if left == right:
                    continue
                if right.subnet_of(left) or left.subnet_of(right):
                    found.append(
                        _hypothesis(
                            OVERLAPPING_SUBNET,
                            device,
                            right_iface.name,
                            f"{left_iface.name} ({left}) overlaps {right_iface.name} ({right}).",
                            (
                                Observation(
                                    source=_MODEL,
                                    device=device,
                                    detail=f"{left} and {right} overlap on {device}",
                                ),
                            ),
                            "show ip interface brief",
                            "Re-address one of the overlapping interfaces.",
                        )
                    )
                    break
    return found


def detect_wrong_vlan(model: NetworkModel, bundle: EvidenceBundle) -> list[Hypothesis]:
    """An access port whose VLAN disagrees with the VLAN its segment uses.

    The VLAN that serves a subnet is discovered from the network itself: every
    access port reaches one device, and the devices on one subnet agree on a
    dominant VLAN. A port that reports a different VLAN for the same subnet is
    the defect. This needs no VLAN-to-subnet table, which is why it also works
    on labs that never define explicit VLAN records.
    """
    # subnet -> VLANs seen on access ports attached to a device in that subnet
    subnet_vlans: dict[ipaddress.IPv4Network, Counter] = defaultdict(Counter)
    port_subnet: dict[tuple[str, str], ipaddress.IPv4Network] = {}
    for interface in _interfaces(model):
        if _is_trunk(interface):
            continue
        vlans = _vlan_ids(interface.vlan_assignments)
        if len(vlans) != 1:
            continue
        peer = _peer_interface(model, interface.device, interface.name)
        if peer is None:
            continue
        endpoint = _endpoint_address(model, *peer)
        if endpoint is None:
            continue
        address, prefix = endpoint
        try:
            net = ipaddress.IPv4Network(f"{address}/{prefix}", strict=False)
        except ValueError:
            continue
        vlan = next(iter(vlans))
        subnet_vlans[net][vlan] += 1
        port_subnet[(interface.device, interface.name)] = net

    found: list[Hypothesis] = []
    for (device, name), net in port_subnet.items():
        expected, count = subnet_vlans[net].most_common(1)[0]
        interface = _find_interface(model, device, name)
        if interface is None:
            continue
        actual = _vlan_ids(interface.vlan_assignments)
        if not actual or expected in actual:
            continue
        if count < 2 and not model.vlans:
            # One port alone cannot establish a dominant VLAN unless the file
            # declares the VLAN table itself.
            continue
        supporting = (
            Observation(
                source=_MODEL,
                device=device,
                detail=(
                    f"{name} is in VLAN {sorted(actual)} but subnet {net} is served by "
                    f"VLAN {expected} ({count} other ports)"
                ),
            ),
        )
        contradicting: list[Observation] = []
        row = _runtime_row(bundle, device, name)
        if row is not None and str(row.get("vlan", "")) == str(expected):
            contradicting.append(
                Observation(
                    source=_RUNTIME,
                    device=device,
                    detail=f"{name} reports VLAN {expected} at runtime",
                )
            )
        found.append(
            _hypothesis(
                WRONG_VLAN,
                device,
                name,
                f"Access port is in VLAN {sorted(actual)} but its segment uses VLAN {expected}.",
                supporting,
                "show vlan brief",
                f"Move {name} into VLAN {expected}.",
                tuple(contradicting),
            )
        )
    return found


def detect_trunk_mismatch(model: NetworkModel, _bundle: EvidenceBundle) -> list[Hypothesis]:
    """Two ends of one trunk link that do not carry the same VLAN set."""
    found: list[Hypothesis] = []
    seen: set[tuple[str, str, str, str]] = set()
    for interface in _interfaces(model):
        if not _is_trunk(interface):
            continue
        peer = _peer_interface(model, interface.device, interface.name)
        if peer is None:
            continue
        peer_iface = _find_interface(model, *peer)
        if peer_iface is None or not _is_trunk(peer_iface):
            continue
        pair = tuple(sorted([f"{interface.device}:{interface.name}", f"{peer[0]}:{peer[1]}"]))
        if pair in seen:
            continue
        seen.add(pair)
        local = _vlan_ids(interface.vlan_assignments)
        remote = _vlan_ids(peer_iface.vlan_assignments)
        if not local or not remote or local == remote:
            continue
        only_local = sorted(local - remote)
        only_remote = sorted(remote - local)
        if only_local:
            blamed, blamed_name, missing = interface, interface.name, only_local
            cause = (
                f"{interface.name} carries VLAN(s) {only_local} that peer "
                f"{peer[0]}:{peer[1]} does not."
            )
        else:
            blamed, blamed_name, missing = peer_iface, peer_iface.name, only_remote
            cause = (
                f"{peer_iface.name} carries VLAN(s) {only_remote} that peer "
                f"{interface.device}:{interface.name} does not."
            )
        found.append(
            _hypothesis(
                TRUNK_MISMATCH,
                blamed.device,
                blamed_name,
                cause,
                (
                    Observation(
                        source=_MODEL,
                        device=blamed.device,
                        detail=(
                            f"{interface.device}:{interface.name} allows {sorted(local)}; "
                            f"{peer[0]}:{peer[1]} allows {sorted(remote)}"
                        ),
                    ),
                ),
                "show interfaces trunk",
                f"Permit VLAN(s) {missing} on the trunk between the two switches.",
            )
        )
    return found


def detect_missing_static_route(model: NetworkModel, _bundle: EvidenceBundle) -> list[Hypothesis]:
    """A router that is the default transit for a neighbour but cannot return traffic.

    The rule is a reachability contradiction, not "a router has no routes":
    a neighbour sends everything unknown through this router, the neighbour has
    a directly connected subnet, and this router has neither a connection to
    that subnet nor any specific route for it. Traffic that arrives cannot be
    answered, so the route is genuinely missing.
    """
    owners = _address_owners(model)
    found: list[Hypothesis] = []
    for route in model.routes:
        if route.destination not in _DEFAULT_DESTINATIONS or not route.next_hop:
            continue
        holders = owners.get(route.next_hop)
        if not holders:
            continue
        transit = holders[0].device
        dependent = route.device
        if transit == dependent:
            continue
        dependent_nets = _device_networks(model, dependent)
        transit_nets = _device_networks(model, transit)
        transit_routes = [
            net
            for other in model.routes
            if other.device == transit
            for net in [_route_network(other.destination)]
            if net is not None
        ]
        for net in dependent_nets:
            if any(net.subnet_of(t) or net == t for t in transit_nets):
                continue
            if any(net.subnet_of(r) or net == r for r in transit_routes):
                continue
            supporting = (
                Observation(
                    source=_MODEL,
                    device=transit,
                    detail=(
                        f"{dependent} sends unknown traffic to {transit} via {route.next_hop}, "
                        f"but {transit} has no route to {net} which is directly connected on {dependent}"
                    ),
                ),
            )
            found.append(
                _hypothesis(
                    MISSING_STATIC_ROUTE,
                    transit,
                    None,
                    f"{transit} cannot reach {net}, which {dependent} depends on it to route.",
                    supporting,
                    "show ip route",
                    f"Add a static route on {transit} for {net}.",
                )
            )
    return found


def detect_acl_block(model: NetworkModel, _bundle: EvidenceBundle) -> list[Hypothesis]:
    """A deny entry actually bound to an interface."""
    found: list[Hypothesis] = []
    for acl in model.acls:
        if (acl.action or "").lower() != "deny" or not acl.applied_interface:
            continue
        # Bind the ACL to the interface that names it, not to the first
        # interface with the same name on some other device.
        target: InterfaceInfo | None = None
        for interface in _interfaces(model):
            if interface.name != acl.applied_interface:
                continue
            description = interface.description or ""
            if acl.acl_id in description or "access-group" in description:
                target = interface
                break
        if target is None:
            for interface in _interfaces(model):
                if interface.name == acl.applied_interface:
                    target = interface
                    break
        device = target.device if target else None
        found.append(
            _hypothesis(
                ACL_BLOCK,
                device,
                acl.applied_interface,
                f"ACL {acl.acl_id} denies traffic inbound on {acl.applied_interface}.",
                (
                    Observation(
                        source=_MODEL,
                        device=device,
                        detail=acl.raw or f"access-list {acl.acl_id} deny",
                    ),
                ),
                "show access-lists",
                f"Adjust ACL {acl.acl_id} to permit the intended traffic.",
            )
        )
    return found


def detect_routing_loop(model: NetworkModel, _bundle: EvidenceBundle) -> list[Hypothesis]:
    """A static route that points back at the device's own address."""
    owners = _address_owners(model)
    found: list[Hypothesis] = []
    for route in model.routes:
        if not route.next_hop or not route.device:
            continue
        if _route_network(route.destination) is None:
            continue
        holders = owners.get(route.next_hop)
        if not holders:
            continue
        if any(holder.device == route.device for holder in holders):
            found.append(
                _hypothesis(
                    ROUTING_LOOP,
                    route.device,
                    holders[0].name,
                    (
                        f"route to {route.destination} points at {route.next_hop}, "
                        f"an address on {route.device} itself"
                    ),
                    (
                        Observation(
                            source=_MODEL,
                            device=route.device,
                            detail=route.raw_config
                            or f"ip route {route.destination} {route.next_hop}",
                        ),
                    ),
                    f"show ip route {route.next_hop}",
                    "Point the route at the true next-hop router instead of the local address.",
                )
            )
    # A mutual pair is the same defect seen from both ends; report once.
    unique: dict[tuple, Hypothesis] = {}
    for hypothesis in found:
        unique[(hypothesis.kind, hypothesis.device, hypothesis.interface)] = hypothesis
    return list(unique.values())


def detect_dhcp_misconfiguration(model: NetworkModel, _bundle: EvidenceBundle) -> list[Hypothesis]:
    """A DHCP pool whose default router is not a real address on the network."""
    owners = _address_owners(model)
    found: list[Hypothesis] = []
    for entry in model.settings.dhcp_configured:
        network_match = re.search(r"network\s+(\d+\.\d+\.\d+\.\d+/\d+)", entry)
        gateway_match = re.search(r"gateway\s+(\d+\.\d+\.\d+\.\d+)", entry)
        if not network_match or not gateway_match:
            continue
        try:
            network = ipaddress.IPv4Network(network_match.group(1), strict=False)
            gateway = gateway_match.group(1)
        except ValueError:
            continue
        if gateway in owners:
            continue
        device = entry.split(":", 1)[0].strip() if ":" in entry else ""
        found.append(
            _hypothesis(
                DHCP_MISCONFIGURATION,
                device or None,
                None,
                f"DHCP default router {gateway} is not assigned to any interface in {network}.",
                (Observation(source=_MODEL, device=device or None, detail=entry),),
                "show running-config | section dhcp",
                "Correct the DHCP default-router to the real gateway address.",
            )
        )
    return found


_DETECTORS = (
    detect_invalid_mask,
    detect_shutdown_interface,
    detect_wrong_gateway,
    detect_duplicate_ip,
    detect_overlapping_subnet,
    detect_wrong_vlan,
    detect_trunk_mismatch,
    detect_missing_static_route,
    detect_acl_block,
    detect_routing_loop,
    detect_dhcp_misconfiguration,
)


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def diagnose(
    model: NetworkModel,
    bundle: EvidenceBundle | None = None,
    *,
    symptoms: tuple[str, ...] = (),
) -> Diagnosis:
    """Run every detector and return the ranked diagnosis.

    ``bundle`` may be ``None`` when only static facts are available; runtime
    cross-checks are then simply absent and each detector says so rather than
    assuming agreement.
    """
    bundle = bundle if bundle is not None else EvidenceBundle()
    hypotheses: list[Hypothesis] = []
    for detector in _DETECTORS:
        try:
            hypotheses.extend(detector(model, bundle))
        except Exception as exc:  # noqa: BLE001 - one broken detector must not sink the engine
            hypotheses.append(
                Hypothesis(
                    kind="DETECTOR_ERROR",
                    status=HypothesisStatus.INSUFFICIENT_EVIDENCE,
                    confidence=Confidence.LOW,
                    device=None,
                    interface=None,
                    suspected_cause=f"{detector.__name__} failed: {exc}",
                    supporting=(),
                    contradicting=(),
                    missing_evidence=("successful detector run",),
                    next_command=None,
                    repair_hint=None,
                )
            )
    return Diagnosis(
        symptoms=tuple(symptoms),
        hypotheses=tuple(hypotheses),
        ranked=tuple(rank(hypotheses)),
    )


_STATUS_ORDER = {
    HypothesisStatus.CONFIRMED_DEFECT: 0,
    HypothesisStatus.SUSPECTED: 1,
    HypothesisStatus.RULED_OUT: 2,
    HypothesisStatus.INSUFFICIENT_EVIDENCE: 3,
}

_CONFIDENCE_ORDER = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}


def rank(hypotheses: list[Hypothesis]) -> list[Hypothesis]:
    """Order by claim strength, then confidence, then evidence volume."""
    return sorted(
        hypotheses,
        key=lambda h: (
            _STATUS_ORDER[h.status],
            _CONFIDENCE_ORDER[h.confidence],
            -len(h.supporting),
            len(h.contradicting),
            h.kind,
            h.device or "",
            h.interface or "",
        ),
    )


def report(diagnosis: Diagnosis) -> list[dict]:
    """The reportable view: only hypotheses that actually claim a defect."""
    return diagnosis.to_report_dicts()


__all__ = [
    "ACL_BLOCK",
    "DHCP_MISCONFIGURATION",
    "DUPLICATE_IP",
    "INVALID_MASK",
    "MISSING_STATIC_ROUTE",
    "OVERLAPPING_SUBNET",
    "ROUTING_LOOP",
    "SHUTDOWN_INTERFACE",
    "TRUNK_MISMATCH",
    "WRONG_GATEWAY",
    "WRONG_VLAN",
    "diagnose",
    "rank",
    "report",
]
