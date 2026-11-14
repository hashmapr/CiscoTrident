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
UNREACHABLE_NEXT_HOP = "UNREACHABLE_NEXT_HOP"
DHCP_POOL_NETWORK = "DHCP_POOL_NETWORK"
DHCP_POOL_DNS = "DHCP_POOL_DNS"
UNRESERVED_GATEWAY = "UNRESERVED_GATEWAY"
WEAK_MANAGEMENT = "WEAK_MANAGEMENT"

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


#: Route types that represent a path the device actually learned or was given.
#: A network routed by OSPF/EIGRP/RIP is not missing a static route; the earlier
#: version of this detector only counted static routes and therefore reported
#: every dynamically-routed lab as broken.
_LEARNED_ROUTE_TYPES = {"static", "default", "dynamic", "connected", "local"}
_LEARNED_PROTOCOLS = {"static", "connected", "local"}


def _is_learned_route(route) -> bool:
    route_type = (route.route_type or "").lower()
    protocol = (route.protocol or "").lower()
    if route_type in {"static", "default", "connected", "local"}:
        return True
    # Dynamic routes carry their protocol (``ospf 1``, ``eigrp 10``, ``rip``).
    if route_type == "dynamic":
        return True
    return any(protocol.startswith(name) for name in ("ospf", "eigrp", "rip", "bgp", "isis"))


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


def _is_svi(interface: InterfaceInfo) -> bool:
    """True for a switch virtual interface (``Vlan10``, ``Vlan1``, ``Vlan100``).

    An SVI is up only when a member port is up, so its administrative-down state
    is *derived* from port state rather than a configuration choice. Reporting it
    as a defect flags every switch in every lab, which is what happened on real
    .pka files.
    """
    return (interface.name or "").strip().lower().startswith("vlan")


def _proves_intended_service(model: NetworkModel, interface: InterfaceInfo) -> str | None:
    """Why this interface is expected to be forwarding, or ``None``.

    Administrative shutdown is only a defect when the interface is demonstrably
    part of the intended service. The evidence ladder, strongest first:

    * ``"vlan"``   - an access port assigned to a VLAN, or a trunk. Explicit
      configuration intent: someone configured this port to carry traffic.
    * ``"address"`` - a routed physical port holding an address.
    * ``"cable"``  - merely connected. Not enough on its own: leaving an unused
      cabled port shut is a valid configuration choice.

    An SVI is never proof, because its state follows its member ports.
    """
    if _is_svi(interface):
        return None
    if interface.vlan_assignments or _is_trunk(interface):
        return "vlan"
    if interface.ipv4_address or interface.ipv6_address:
        return "address"
    if _peer_interface(model, interface.device, interface.name) is not None:
        return "cable"
    return None


def detect_shutdown_interface(model: NetworkModel, bundle: EvidenceBundle) -> list[Hypothesis]:
    """An interface an administrator has disabled that should have been up."""
    found: list[Hypothesis] = []
    for interface in _interfaces(model):
        if (interface.admin_state or "").lower() not in _DOWN_STATES:
            continue
        proof = _proves_intended_service(model, interface)
        if proof is None:
            # An SVI, or a port with no address, no VLAN and no cable: there is
            # no evidence this interface was meant to forward.
            continue
        if proof == "cable":
            # Cabled but unaddressed and not in a VLAN: shutting it is a valid
            # configuration choice, so it is a suspicion, not a confirmed defect.
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


def _unknown_gateway(
    device: str,
    missing: str,
    observed: str,
) -> Hypothesis:
    """A gateway verdict of UNKNOWN, carrying the configuration it came from.

    ``INSUFFICIENT_EVIDENCE`` is this engine's ``UNKNOWN``: the configured value
    was observed, but there is not enough evidence to call it a defect. It is
    deliberately not ``CONFIRMED_DEFECT`` and never appears in the defect report.
    """
    return Hypothesis(
        kind=WRONG_GATEWAY,
        status=HypothesisStatus.INSUFFICIENT_EVIDENCE,
        confidence=Confidence.LOW,
        device=device,
        interface=None,
        suspected_cause=(
            f"{observed}; the gateway cannot be judged without {missing}."
        ),
        supporting=(),
        contradicting=(),
        missing_evidence=(missing,),
        next_command="show ip interface brief",
        repair_hint=None,
    )


def detect_wrong_gateway(model: NetworkModel, bundle: EvidenceBundle) -> list[Hypothesis]:
    """A host/device default gateway that is not a real address in its subnet.

    A gateway is only valid when some interface in the same subnet actually
    holds that address. Being merely *inside* the subnet is not enough — an
    address nobody owns forwards nothing.

    Every verdict cites the observed configuration it was formed from. When the
    evidence needed to judge the gateway is absent — no interface addresses on
    the device, or a configured value that is not an IPv4 address — the verdict
    is ``INSUFFICIENT_EVIDENCE`` (UNKNOWN), never a defect.
    """
    owners = _address_owners(model)
    found: list[Hypothesis] = []
    for device, gateway in model.settings.default_gateways.items():
        observed = (
            f"observed configuration: {device} default gateway is {gateway!r}"
        )
        try:
            gateway_ip = ipaddress.IPv4Address(gateway)
        except ValueError:
            found.append(
                _unknown_gateway(
                    device,
                    "a gateway value that parses as an IPv4 address",
                    observed,
                )
            )
            continue

        local_nets = _device_networks(model, device)
        if not local_nets:
            found.append(
                _unknown_gateway(
                    device,
                    f"interface addresses and masks on {device}",
                    observed,
                )
            )
            continue

        if gateway in owners:
            continue

        in_subnet = [net for net in local_nets if gateway_ip in net]
        # A gateway inside one of this device's own subnets that no interface
        # holds is a defect: the subnet is served here, so the address must be
        # real and is not. A gateway outside every local subnet is a different
        # situation - it may belong to a neighbour this file does not fully
        # describe - so that case is reported at reduced confidence below rather
        # than as a confirmed defect.
        outside_only = not in_subnet
        scope = (
            f"in {in_subnet[0]}"
            if in_subnet
            else "on the network (the gateway is outside every local subnet)"
        )
        supporting = (
            Observation(
                source=_MODEL,
                device=device,
                detail=f"{observed}; no interface {scope} holds {gateway}",
            ),
        )
        contradicting: list[Observation] = []
        # Runtime evidence anywhere on the network can contradict the static
        # claim that the address is unowned.
        for other in sorted({device, *bundle.devices()}):
            for name, row in bundle.runtime_interfaces(other).items():
                if not isinstance(row, dict):
                    continue
                runtime_ip = str(row.get("ip", "")).split("/", 1)[0].strip()
                if runtime_ip == gateway:
                    contradicting.append(
                        Observation(
                            source=_RUNTIME,
                            device=other,
                            detail=f"{name} holds {gateway} at runtime",
                        )
                    )
                    break
        hypothesis = _hypothesis(
            WRONG_GATEWAY,
            device,
            None,
            f"Default gateway {gateway} is not an address that exists on the network.",
            supporting,
            "show ip interface brief",
            "Set the default gateway to the router address inside the local subnet.",
            tuple(contradicting),
        )
        if outside_only and not contradicting:
            # Downgrade: the address may belong to a device this file does not
            # describe. Still worth reporting, but not as a confirmed defect.
            hypothesis = Hypothesis(
                kind=hypothesis.kind,
                status=HypothesisStatus.SUSPECTED,
                confidence=Confidence.LOW,
                device=hypothesis.device,
                interface=hypothesis.interface,
                suspected_cause=hypothesis.suspected_cause,
                supporting=hypothesis.supporting,
                contradicting=hypothesis.contradicting,
                missing_evidence=("the owning device of the gateway address",),
                next_command=hypothesis.next_command,
                repair_hint=hypothesis.repair_hint,
            )
        found.append(hypothesis)
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
    """An access port whose VLAN is wrong for the segment it serves.

    Two independent signals, because either alone misses real cases:

    * **Undefined VLAN** — the port is in a VLAN the network does not define, so
      no host on it can reach the rest of the segment.
    * **Minority VLAN** — several ports serve the same subnet and this one is in
      the minority. This needs at least two ports, so a lone port cannot be
      judged against itself, which was the bug that made the first version miss
      every single-port case.
    """
    declared = {vlan.vlan_id for vlan in model.vlans}

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
        interface = _find_interface(model, device, name)
        if interface is None:
            continue
        actual = _vlan_ids(interface.vlan_assignments)
        if not actual:
            continue
        vlan = next(iter(actual))

        reason: str | None = None
        expected: int | None = None
        counts = subnet_vlans[net]
        if declared and vlan not in declared:
            reason = (
                f"{name} is in VLAN {vlan}, which this network does not define "
                f"(defined: {sorted(declared)})"
            )
        elif counts.total() >= 2:
            expected, _count = counts.most_common(1)[0]
            if expected != vlan:
                reason = (
                    f"{name} is in VLAN {vlan} but {counts[expected]} other port(s) on "
                    f"subnet {net} use VLAN {expected}"
                )
        if reason is None:
            continue

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
        fix = f"VLAN {expected}" if expected is not None else "a defined VLAN"
        found.append(
            _hypothesis(
                WRONG_VLAN,
                device,
                name,
                reason,
                (Observation(source=_MODEL, device=device, detail=reason),),
                "show vlan brief",
                f"Move {name} into {fix}.",
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
        # Native VLAN mismatch: the two ends disagree on which VLAN receives
        # untagged frames. Reported on the end whose value differs from its
        # peer's, with the peer named, so the student can see both sides.
        if (
            interface.native_vlan is not None
            and peer_iface.native_vlan is not None
            and interface.native_vlan != peer_iface.native_vlan
        ):
            detail = (
                f"native VLAN mismatch: {interface.device}:{interface.name} uses "
                f"{interface.native_vlan}, {peer[0]}:{peer[1]} uses "
                f"{peer_iface.native_vlan}"
            )
            found.append(
                _hypothesis(
                    TRUNK_MISMATCH,
                    interface.device,
                    interface.name,
                    detail,
                    (
                        Observation(
                            source=_MODEL,
                            device=interface.device,
                            detail=detail,
                        ),
                    ),
                    "show interfaces trunk",
                    "Set both ends of this trunk to the same native VLAN.",
                )
            )

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


#: RFC1918 space only. ``IPv4Address.is_private`` is broader than RFC1918: it
#: also matches the TEST-NET documentation ranges (192.0.2.0/24, 198.51.100.0/24,
#: 203.0.113.0/24), which labs use to represent *public* addressing. Using the
#: stdlib property therefore classifies a public-facing edge router as internal
#: and produces a false missing-route finding.
_RFC1918 = tuple(
    ipaddress.IPv4Network(net)
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def _is_private_address(value: str | None) -> bool:
    if not value:
        return False
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return any(address in net for net in _RFC1918)


def _device_uses_private_addressing(model: NetworkModel, device: str) -> bool:
    """True when the device has at least one RFC1918 interface.

    An edge router addressed entirely in public space is not expected to hold
    routes to private internals - that is what NAT is for - so the missing-route
    rule does not apply to it.
    """
    return any(
        interface.device == device and _is_private_address(interface.ipv4_address)
        for interface in _interfaces(model)
    )


def _runs_dynamic_routing(model: NetworkModel, device: str) -> bool:
    """True when the device has any dynamic routing configured or learned."""
    if any(
        _is_learned_route(route)
        and (route.route_type or "").lower() == "dynamic"
        and route.device == device
        for route in model.routes
    ):
        return True
    info = model.devices.get(device)
    if info is None:
        return False
    markers = ("router ospf", "router eigrp", "router rip", "router bgp", "router isis")
    for line in info.configuration or ():
        lowered = line.strip().lower()
        if any(lowered.startswith(marker) for marker in markers):
            return True
    return False


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
    reported_pairs: set[tuple[str, str]] = set()
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
        if _runs_dynamic_routing(model, transit):
            # A dynamically routed network is not missing a static route.
            continue
        if not _device_uses_private_addressing(model, transit):
            # A public-only edge router routes nothing private by design.
            continue
        if (transit, dependent) in reported_pairs:
            continue
        dependent_nets = _device_networks(model, dependent)
        transit_nets = _device_networks(model, transit)
        transit_routes = [
            net
            for other in model.routes
            if other.device == transit and _is_learned_route(other)
            for net in [_route_network(other.destination)]
            if net is not None
        ]
        for net in dependent_nets:
            if any(net.subnet_of(t) or net == t for t in transit_nets):
                continue
            if any(net.subnet_of(r) or net == r for r in transit_routes):
                continue
            reported_pairs.add((transit, dependent))
            supporting = (
                Observation(
                    source=_MODEL,
                    device=transit,
                    detail=(
                        f"{dependent} sends unknown traffic to {transit} via {route.next_hop}, "
                        f"but {transit} has no route to {net}, which is directly connected on {dependent}"
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
            break
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


def detect_unreachable_next_hop(
    model: NetworkModel, _bundle: EvidenceBundle
) -> list[Hypothesis]:
    """A static route whose next hop is not on any connected subnet.

    This is a different defect from a *missing* route (which the detector below
    handles): the route exists and is syntactically fine, but its next hop
    cannot be reached, so IOS either rejects it or installs a black hole. The
    original lab contained exactly this — a default route via 10.0.0.6 on a
    /30 where only .1 and .2 exist — and nothing detected it.
    """
    found: list[Hypothesis] = []
    for route in model.routes:
        if not route.next_hop:
            continue
        try:
            next_hop = ipaddress.IPv4Address(route.next_hop)
        except ValueError:
            # A route via an interface name has no next hop to check.
            continue
        connected = _device_networks(model, route.device)
        if not connected:
            # No addressing at all: this device's routing cannot be judged, and
            # saying so is better than calling every route broken.
            continue
        if any(next_hop in net for net in connected):
            continue
        detail = (
            f"{route.device} has route {route.destination} via {route.next_hop}, "
            f"but {route.next_hop} is not inside any subnet on this device "
            f"({', '.join(str(n) for n in connected)})"
        )
        found.append(
            _hypothesis(
                UNREACHABLE_NEXT_HOP,
                route.device,
                None,
                detail,
                (Observation(source=_MODEL, device=route.device, detail=detail),),
                "show ip route",
                f"Point the route at a next hop inside a connected subnet, "
                f"or add addressing that makes {route.next_hop} reachable.",
            )
        )
    return found


def _pool_network(info: dict) -> ipaddress.IPv4Network | None:
    """A pool's subnet from its ``network`` + ``mask`` pair.

    ``network`` alone is an address; treating it as a network yields /32 and
    every containment test then fails. The mask is a separate field precisely
    because IOS writes them separately.
    """
    network = info.get("network")
    if not network:
        return None
    mask = info.get("mask")
    try:
        if mask:
            return ipaddress.IPv4Network(f"{network}/{mask}", strict=False)
        return ipaddress.IPv4Network(network, strict=False)
    except ValueError:
        return None


def detect_dhcp_pool_problems(
    model: NetworkModel, _bundle: EvidenceBundle
) -> list[Hypothesis]:
    """A DHCP pool that cannot serve the clients it is meant to serve.

    Two checks with real evidence behind them:

    * **pool subnet** — the pool's declared network must match a subnet that
      actually exists on the device, otherwise no client is ever served;
    * **missing DNS** — a pool that omits ``dns-server`` while another pool on
      the same device sets one is an inconsistency, not a style choice.
    """
    found: list[Hypothesis] = []
    for device, pools in (model.settings.dhcp_details or {}).items():
        connected = _device_networks(model, device)
        known = {str(n) for n in connected}
        for name, info in pools.items():
            network = info.get("network")
            if not network:
                continue
            pool_net = _pool_network(info)
            if pool_net is None:
                continue
            if known and not any(
                pool_net.subnet_of(n) or n.subnet_of(pool_net) for n in connected
            ):
                detail = (
                    f"DHCP pool {name} on {device} serves {pool_net}, which is not "
                    f"any subnet configured on this device "
                    f"({', '.join(sorted(known))})"
                )
                found.append(
                    _hypothesis(
                        DHCP_POOL_NETWORK,
                        device,
                        None,
                        detail,
                        (Observation(source=_MODEL, device=device, detail=detail),),
                        "show ip dhcp pool",
                        f"Correct the network statement in pool {name}.",
                    )
                )
        # A pool with no dns-server while a sibling pool has one is a fault.
        with_dns = {
            name for name, info in pools.items() if info.get("dns_servers")
        }
        if len(with_dns) >= 1 and len(pools) > 1:
            for name in pools:
                if name in with_dns:
                    continue
                detail = (
                    f"DHCP pool {name} on {device} sets no dns-server, while "
                    f"pool(s) {', '.join(sorted(with_dns))} do"
                )
                found.append(
                    _hypothesis(
                        DHCP_POOL_DNS,
                        device,
                        None,
                        detail,
                        (Observation(source=_MODEL, device=device, detail=detail),),
                        "show ip dhcp pool",
                        f"Add the campus dns-server to pool {name}.",
                    )
                )
    return found


def detect_unreserved_gateway(
    model: NetworkModel, _bundle: EvidenceBundle
) -> list[Hypothesis]:
    """A DHCP pool that does not exclude the router's own address.

    Handing the gateway address to a client duplicates it. Reported only when a
    pool's default-router is inside the pool subnet and no excluded-address
    covers it, which is the condition that actually causes a conflict.
    """
    found: list[Hypothesis] = []
    for device, pools in (model.settings.dhcp_details or {}).items():
        excluded = {
            str(ip)
            for ip in (model.settings.dhcp_excluded or {}).get(device, [])
        }
        for name, info in pools.items():
            gateway = info.get("default_router")
            network = info.get("network")
            if not gateway or not network:
                continue
            pool_net = _pool_network(info)
            if pool_net is None:
                continue
            try:
                gw = ipaddress.IPv4Address(gateway)
            except ValueError:
                continue
            if gw not in pool_net or gateway in excluded:
                continue
            detail = (
                f"DHCP pool {name} on {device} can lease {gateway} "
                f"(its own default-router) because no excluded-address covers it"
            )
            found.append(
                _hypothesis(
                    UNRESERVED_GATEWAY,
                    device,
                    None,
                    detail,
                    (Observation(source=_MODEL, device=device, detail=detail),),
                    "show ip dhcp pool",
                    f"Exclude {gateway} from pool {name}.",
                )
            )
    return found


def detect_weak_management(
    model: NetworkModel, _bundle: EvidenceBundle
) -> list[Hypothesis]:
    """Management access configured in a way that cannot work or is unprotected.

    Two checks, both evidence-based and both real faults in practice:

    * **SSH without an authentication source** — ``transport input ssh`` plus
      ``login local`` requires a local user; without one, remote login cannot
      succeed. This is a functional defect, not a hardening opinion.
    * **Missing enable secret** — privileged EXEC reachable with no encrypted
      password.

    Only devices that are *configured* for management are judged. A device with
    no vty configuration at all is out of scope rather than assumed broken.
    """
    found: list[Hypothesis] = []
    for device in sorted(model.devices):
        lines = [line.strip() for line in (model.devices[device].configuration or [])]
        if not lines:
            continue
        has_vty = any(line.startswith(("line vty", "line con")) for line in lines)
        if not has_vty:
            continue
        ssh = any(line.startswith("transport input") and "ssh" in line for line in lines)
        login_local = any(line.strip() == "login local" for line in lines)
        local_user = any(line.startswith("username ") for line in lines)
        enable_secret = any(
            line.startswith(("enable secret", "enable password")) for line in lines
        )

        if ssh and login_local and not local_user:
            detail = (
                f"{device} enables SSH with `login local` but defines no local "
                f"username, so no remote login can authenticate"
            )
            found.append(
                _hypothesis(
                    WEAK_MANAGEMENT,
                    device,
                    None,
                    detail,
                    (Observation(source=_MODEL, device=device, detail=detail),),
                    "show running-config | include username",
                    "Create a local username for SSH authentication.",
                )
            )
        elif ssh and not login_local:
            detail = (
                f"{device} enables SSH but its vty lines use no local login method"
            )
            found.append(
                _hypothesis(
                    WEAK_MANAGEMENT,
                    device,
                    None,
                    detail,
                    (Observation(source=_MODEL, device=device, detail=detail),),
                    "show running-config | section line vty",
                    "Add `login local` to the vty lines.",
                )
            )

        if not enable_secret:
            detail = f"{device} has no enable secret or enable password"
            found.append(
                _hypothesis(
                    WEAK_MANAGEMENT,
                    device,
                    None,
                    detail,
                    (Observation(source=_MODEL, device=device, detail=detail),),
                    "show running-config | include enable",
                    "Set an encrypted enable secret.",
                )
            )
    return found


def detect_trunk_vlan_gap(
    model: NetworkModel, _bundle: EvidenceBundle
) -> list[Hypothesis]:
    """A trunk that does not permit a VLAN its own switch has active ports in.

    Evidence is local to one switch: an access port is assigned VLAN N, and the
    trunk that has to carry that traffic explicitly excludes N. This does not
    need the far end, which is what made the old peer-comparison detector miss
    the case where both trunks were misconfigured identically.
    """
    found: list[Hypothesis] = []
    by_device: dict[str, list[InterfaceInfo]] = defaultdict(list)
    for interface in _interfaces(model):
        by_device[interface.device].append(interface)

    for device, interfaces in by_device.items():
        trunks = [i for i in interfaces if _is_trunk(i)]
        if not trunks:
            continue
        access_vlans: dict[int, list[str]] = defaultdict(list)
        for interface in interfaces:
            if _is_trunk(interface):
                continue
            for vlan in _vlan_ids(interface.vlan_assignments):
                access_vlans[vlan].append(interface.name)
        for trunk in trunks:
            allowed = _vlan_ids(trunk.vlan_assignments)
            if not allowed:
                # No explicit allowed list means "all VLANs" to IOS.
                continue
            for vlan, ports in sorted(access_vlans.items()):
                if vlan in allowed:
                    continue
                detail = (
                    f"{device}:{trunk.name} does not permit VLAN {vlan}, but "
                    f"{', '.join(sorted(ports)[:3])} on this switch are in it"
                )
                found.append(
                    _hypothesis(
                        TRUNK_MISMATCH,
                        device,
                        trunk.name,
                        detail,
                        (Observation(source=_MODEL, device=device, detail=detail),),
                        "show interfaces trunk",
                        f"Add VLAN {vlan} to the trunk's allowed list.",
                    )
                )
    return found


_DETECTORS = (
    detect_invalid_mask,
    detect_unreachable_next_hop,
    detect_dhcp_pool_problems,
    detect_unreserved_gateway,
    detect_weak_management,
    detect_trunk_vlan_gap,
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
