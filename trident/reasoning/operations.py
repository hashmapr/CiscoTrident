"""Typed query operations with declared answer types, cardinality and evidence.

Every question resolves to exactly one operation here. The operation declares what
kind of answer it may produce; the verification layer rejects any result whose
value does not match that declared type. That is what stops a subnet-mask
question from being answered with a host IP, or a link-count question from being
answered with a list of device names.

Design rules:

* Operations are pure functions of the ``NetworkModel`` (no AI, no I/O).
* Each returns an ``OpResult`` carrying value, declared type, cardinality,
  evidence and the deterministic derivation (if any).
* Anything the model cannot establish returns ``status=UNAVAILABLE`` with a
  reason. Never a nearby substitute.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum

from ..models import NetworkModel
from ..normalization.values import (
    canonical_interface_name,
    mask_to_prefix,
    normalize_ipv4,
    prefix_to_mask,
)


class AnswerType(str, Enum):
    """Declared type of an operation's result."""

    DEVICE = "device"
    INTERFACE = "interface"
    DEVICE_SET = "device_set"
    INTERFACE_SET = "interface_set"
    IPV4 = "ipv4"
    MASK = "mask"
    HOSTNAME = "hostname"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    TEXT = "text"


class Cardinality(str, Enum):
    ONE = "one"
    MANY = "many"


class OpStatus(str, Enum):
    OK = "OK"
    UNAVAILABLE = "UNAVAILABLE"
    AMBIGUOUS = "AMBIGUOUS"
    BAD_ARGUMENT = "BAD_ARGUMENT"


@dataclass(frozen=True)
class OpSpec:
    """Static contract for an operation."""

    name: str
    answer_type: AnswerType
    cardinality: Cardinality
    requires_device: bool = False
    requires_interface: bool = False
    description: str = ""


@dataclass
class OpResult:
    """One operation's outcome, with everything verification needs."""

    operation: str
    status: OpStatus
    answer_type: AnswerType
    cardinality: Cardinality
    value: str = ""
    values: list[str] = field(default_factory=list)
    #: Deterministic calculation used to derive the value, if any.
    derivation: str = ""
    #: Verbatim / structural evidence supporting the value.
    evidence: list[str] = field(default_factory=list)
    #: Device/interface entities the answer refers to.
    entity: str = ""
    interface: str = ""
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.status is OpStatus.OK

    @property
    def is_integer(self) -> bool:
        return bool(re.fullmatch(r"-?\d+", self.value.strip()))

    def as_answer(self) -> str:
        if self.cardinality is Cardinality.MANY:
            return ", ".join(self.values)
        return self.value


SPECS: dict[str, OpSpec] = {
    # --- topology ---
    "get_physical_neighbor": OpSpec(
        "get_physical_neighbor", AnswerType.DEVICE, Cardinality.ONE, True, True,
        "device at the far end of a cable plugged into this interface",
    ),
    "get_peer_interface": OpSpec(
        "get_peer_interface", AnswerType.INTERFACE, Cardinality.ONE, True, True,
        "remote interface at the far end of the cable",
    ),
    "list_physical_neighbors": OpSpec(
        "list_physical_neighbors", AnswerType.DEVICE_SET, Cardinality.MANY, True, False,
        "unique devices with a direct cable to this device",
    ),
    "count_physical_links": OpSpec(
        "count_physical_links", AnswerType.INTEGER, Cardinality.ONE, False, False,
        "number of physical cables, counted once each",
    ),
    "count_physical_neighbors": OpSpec(
        "count_physical_neighbors", AnswerType.INTEGER, Cardinality.ONE, True, False,
        "number of distinct devices with a direct cable to this device",
    ),
    "count_devices": OpSpec(
        "count_devices", AnswerType.INTEGER, Cardinality.ONE, False, False,
        "number of devices",
    ),
    "get_device_model": OpSpec(
        "get_device_model", AnswerType.TEXT, Cardinality.ONE, True, False,
        "hardware model string",
    ),
    # --- devices and interfaces ---
    "get_hostname": OpSpec(
        "get_hostname", AnswerType.HOSTNAME, Cardinality.ONE, True, False,
        "configured IOS hostname",
    ),
    "get_interface_ip": OpSpec(
        "get_interface_ip", AnswerType.IPV4, Cardinality.ONE, True, True,
        "interface IPv4 address",
    ),
    "get_interface_mask": OpSpec(
        "get_interface_mask", AnswerType.MASK, Cardinality.ONE, True, True,
        "interface subnet mask",
    ),
    "get_interface_network": OpSpec(
        "get_interface_network", AnswerType.IPV4, Cardinality.ONE, True, True,
        "network address of the interface's subnet",
    ),
    "get_interface_prefix_length": OpSpec(
        "get_interface_prefix_length", AnswerType.INTEGER, Cardinality.ONE, True, True,
        "CIDR prefix length of the interface's IPv4 address",
    ),
    "get_interface_status": OpSpec(
        "get_interface_status", AnswerType.TEXT, Cardinality.ONE, True, True,
        "administrative/operational status",
    ),
    # --- routing and switching ---
    "get_default_route_next_hop": OpSpec(
        "get_default_route_next_hop", AnswerType.IPV4, Cardinality.ONE, True, False,
        "next hop of a static default route (ip route 0.0.0.0 0.0.0.0 ...)",
    ),
    "get_switch_default_gateway": OpSpec(
        "get_switch_default_gateway", AnswerType.IPV4, Cardinality.ONE, True, False,
        "ip default-gateway configured on a switch",
    ),
    "get_interface_vlan": OpSpec(
        "get_interface_vlan", AnswerType.INTEGER, Cardinality.ONE, True, True,
        "access VLAN of an interface",
    ),
    "get_trunk_allowed_vlans": OpSpec(
        "get_trunk_allowed_vlans", AnswerType.INTEGER, Cardinality.MANY, True, True,
        "allowed VLANs on a trunk",
    ),
    "list_static_routes": OpSpec(
        "list_static_routes", AnswerType.TEXT, Cardinality.MANY, True, False,
        "static routes configured on a device",
    ),
    # --- derived calculations ---
    "are_in_same_subnet": OpSpec(
        "are_in_same_subnet", AnswerType.BOOLEAN, Cardinality.ONE, False, False,
        "whether two endpoints share a subnet",
    ),
    "calculate_network_address": OpSpec(
        "calculate_network_address", AnswerType.IPV4, Cardinality.ONE, False, False,
        "network address from an IP and mask/prefix",
    ),
    "calculate_broadcast_address": OpSpec(
        "calculate_broadcast_address", AnswerType.IPV4, Cardinality.ONE, False, False,
        "broadcast address from an IP and mask/prefix",
    ),
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_NON_NETWORK_RE = re.compile(
    r"power distribution|^power|ups$|wall mount|ceiling mount|patch panel", re.IGNORECASE
)


def is_non_network_device(name: str) -> bool:
    """Power distribution units, mounts and patch panels are not network nodes."""
    return bool(_NON_NETWORK_RE.search(name or ""))


def _norm(name: str) -> str:
    return " ".join((name or "").split()).strip().lower()


def find_device(model: NetworkModel, name: str) -> tuple[str | None, list[str]]:
    """Resolve a device argument. Returns (exact_key, candidates).

    Never guesses between several equally good matches.
    """
    if not name:
        return None, []
    if name in model.devices:
        return name, [name]
    target = _norm(name)
    hits = [k for k in model.devices if _norm(k) == target]
    if len(hits) == 1:
        return hits[0], hits
    if len(hits) > 1:
        return None, hits
    host_hits = [
        k for k, d in model.devices.items() if d.hostname and _norm(d.hostname) == target
    ]
    if len(host_hits) == 1:
        return host_hits[0], host_hits
    if len(host_hits) > 1:
        return None, host_hits
    return None, []


def interface_display_name(model: NetworkModel, if_key: str) -> str:
    """Display name for an interface key from either source.

    Keys come from ``model.interfaces`` or are synthesised as
    ``device:PORT`` for cable-only endpoints.
    """
    info = model.interfaces.get(if_key)
    if info is not None:
        return info.name
    _, _, port = if_key.partition(":")
    return port or if_key


def _iface_index(model: NetworkModel, device_key: str) -> dict[str, str]:
    """Map canonical interface name -> interface key for one device."""
    out: dict[str, str] = {}
    for key, iface in model.interfaces.items():
        if iface.device != device_key:
            continue
        canon = canonical_interface_name(iface.name or iface.canonical_name)
        if canon:
            out[canon.lower()] = key
    return out


def find_interface(model: NetworkModel, device_key: str, iface: str) -> tuple[str | None, list[str]]:
    """Resolve an interface argument on a device (Gi0/0 == GigabitEthernet0/0).

    Interfaces come from two sources and both must be honoured:

    * the parsed running config (``model.interfaces``), and
    * physical cable endpoints (``model.links``).

    A port such as ``GigabitEthernet1/1/2`` on a switch is often absent from the
    captured config yet is a real, connected interface. Ignoring the cable
    endpoints makes the tool claim the interface does not exist and abstain on a
    question it can answer.
    """
    index = _iface_index(model, device_key)
    canon = canonical_interface_name(iface).lower()
    if canon in index:
        return index[canon], [index[canon]]

    target = _norm(iface)
    loose = [
        key
        for key, info in model.interfaces.items()
        if info.device == device_key and _norm(info.name) == target
    ]
    if len(loose) == 1:
        return loose[0], loose

    # Cable endpoints: synthesise a stable key so downstream code can refer to it.
    link_ports: set[str] = set()
    for link in model.links:
        if link.device_a == device_key:
            link_ports.add(canonical_interface_name(link.interface_a))
        if link.device_b == device_key:
            link_ports.add(canonical_interface_name(link.interface_b))
    for port in sorted(link_ports):
        if port.lower() == canon or _norm(port) == target:
            return f"{device_key}:{port}", [f"{device_key}:{port}"]
    return None, []


def _link_pairs(model: NetworkModel):
    """Yield (a_dev, a_if, b_dev, b_if, media) for every physical link, once."""
    for link in model.links:
        yield (
            link.device_a,
            link.interface_a,
            link.device_b,
            link.interface_b,
            getattr(link, "media_type", "") or "",
        )


# ---------------------------------------------------------------------------
# operations
# ---------------------------------------------------------------------------


def get_physical_neighbor(model: NetworkModel, device: str, interface: str) -> OpResult:
    spec = SPECS["get_physical_neighbor"]
    dev_key, cands = find_device(model, device)
    if dev_key is None:
        return _bad(spec, "device", device, cands, "device not found or ambiguous")
    if_key, if_cands = find_interface(model, dev_key, interface)
    if if_key is None:
        return _bad(spec, "interface", interface, if_cands, "interface not found on device")
    iface_name = interface_display_name(model, if_key)
    canon = canonical_interface_name(iface_name).lower()

    neighbours: list[tuple[str, str]] = []
    for a_dev, a_if, b_dev, b_if, _ in _link_pairs(model):
        if a_dev == dev_key and canonical_interface_name(a_if).lower() == canon:
            neighbours.append((b_dev, b_if))
        elif b_dev == dev_key and canonical_interface_name(b_if).lower() == canon:
            neighbours.append((a_dev, a_if))
    if not neighbours:
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, interface=iface_name,
            reason=f"no physical cable terminates on {device} {iface_name}",
        )
    uniq = sorted({d for d, _ in neighbours})
    if len(uniq) > 1:
        return OpResult(
            spec.name, OpStatus.AMBIGUOUS, spec.answer_type, spec.cardinality,
            entity=dev_key, interface=iface_name, values=uniq,
            reason="more than one neighbour recorded for this interface",
        )
    peer = uniq[0]
    return OpResult(
        spec.name, OpStatus.OK, spec.answer_type, spec.cardinality,
        value=peer, entity=dev_key, interface=iface_name,
        evidence=[f"{device} {iface_name} <-> {peer} {neighbours[0][1]}"],
    )


def get_peer_interface(
    model: NetworkModel, device: str, interface: str, peer: str = ""
) -> OpResult:
    spec = SPECS["get_peer_interface"]
    dev_key, cands = find_device(model, device)
    if dev_key is None:
        return _bad(spec, "device", device, cands, "device not found or ambiguous")
    if_key, if_cands = find_interface(model, dev_key, interface)
    if if_key is None:
        return _bad(spec, "interface", interface, if_cands, "interface not found on device")
    iface_name = interface_display_name(model, if_key)
    canon = canonical_interface_name(iface_name).lower()

    peers: list[tuple[str, str]] = []
    for a_dev, a_if, b_dev, b_if, _ in _link_pairs(model):
        if a_dev == dev_key and canonical_interface_name(a_if).lower() == canon:
            peers.append((b_dev, b_if))
        elif b_dev == dev_key and canonical_interface_name(b_if).lower() == canon:
            peers.append((a_dev, a_if))
    if not peers:
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, interface=iface_name,
            reason=f"no physical cable terminates on {device} {iface_name}",
        )
    peer_dev, peer_if = peers[0]

    # The peer interface must belong to the device the question asks about.
    # Without this, a question naming device A can be answered with the far end
    # of a cable that does not touch A at all -- which looks plausible and is
    # wrong. Abstain instead.
    if peer:
        wanted, _cands = find_device(model, peer)
        if wanted is not None and peer_dev != wanted and wanted != dev_key:
            return OpResult(
                spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
                entity=dev_key, interface=iface_name,
                reason=(
                    f"{device} {iface_name} connects to {peer_dev}, but the question asks "
                    f"for an interface on {peer}; refusing to answer with an unrelated cable"
                ),
            )

        wanted, _cands = find_device(model, peer)
        if wanted is not None:
            if wanted == peer_dev:
                # Far end is the device the question asks about.
                pass
            elif wanted == dev_key:
                # The question asks for this device's own interface: report the
                # interface we started from, which is the local end of the cable.
                return OpResult(
                    spec.name, OpStatus.OK, spec.answer_type, spec.cardinality,
                    value=iface_name, entity=dev_key, interface=iface_name,
                    evidence=[f"{device} {iface_name} <-> {peer_dev} {peer_if}"],
                )
            else:
                return OpResult(
                    spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
                    entity=dev_key, interface=iface_name,
                    reason=(
                        f"{device} {iface_name} connects to {peer_dev}, not to the "
                        "device named in the question"
                    ),
                )
    return OpResult(
        spec.name, OpStatus.OK, spec.answer_type, spec.cardinality,
        value=peer_if, entity=dev_key, interface=iface_name,
        evidence=[f"{device} {iface_name} <-> {peer_dev} {peer_if}"],
    )


def list_physical_neighbors(model: NetworkModel, device: str) -> OpResult:
    spec = SPECS["list_physical_neighbors"]
    dev_key, cands = find_device(model, device)
    if dev_key is None:
        return _bad(spec, "device", device, cands, "device not found or ambiguous")

    neighbours: set[str] = set()
    for a_dev, a_if, b_dev, b_if, _ in _link_pairs(model):
        if a_dev == dev_key:
            neighbours.add(b_dev)
        elif b_dev == dev_key:
            neighbours.add(a_dev)
    if not neighbours:
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, reason=f"no physical cables attach to {device}",
        )
    return OpResult(
        spec.name, OpStatus.OK, spec.answer_type, spec.cardinality,
        values=sorted(neighbours), entity=dev_key,
        evidence=[f"{len(neighbours)} physical neighbour(s) of {device}"],
    )


def count_physical_links(model: NetworkModel) -> OpResult:
    spec = SPECS["count_physical_links"]
    seen: set[frozenset] = set()
    for a_dev, a_if, b_dev, b_if, _ in _link_pairs(model):
        seen.add(frozenset({(a_dev, canonical_interface_name(a_if)),
                            (b_dev, canonical_interface_name(b_if))}))
    if not seen:
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            reason="no physical links were extracted from this snapshot",
        )
    return OpResult(
        spec.name, OpStatus.OK, spec.answer_type, spec.cardinality,
        value=str(len(seen)),
        derivation="count of unique physical link endpoint pairs",
        evidence=[f"{len(model.links)} link records -> {len(seen)} unique cables"],
    )


def count_physical_neighbors(model: NetworkModel, device: str) -> OpResult:
    spec = SPECS["count_physical_neighbors"]
    dev_key, cands = find_device(model, device)
    if dev_key is None:
        return _bad(spec, "device", device, cands, "device not found or ambiguous")
    neighbours: set[str] = set()
    for a_dev, _a_if, b_dev, _b_if, _ in _link_pairs(model):
        if a_dev == dev_key:
            neighbours.add(b_dev)
        elif b_dev == dev_key:
            neighbours.add(a_dev)
    if not neighbours:
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, reason=f"no physical cables attach to {device}",
        )
    return OpResult(
        spec.name, OpStatus.OK, spec.answer_type, spec.cardinality,
        value=str(len(neighbours)), entity=dev_key,
        derivation="count of unique physical neighbour devices",
        evidence=[f"{dev_key}: {len(neighbours)} distinct neighbour(s)"],
    )


def count_devices(model: NetworkModel, include_non_network_devices: bool = False) -> OpResult:
    spec = SPECS["count_devices"]
    names = list(model.devices)
    if not include_non_network_devices:
        names = [n for n in names if not is_non_network_device(n)]
    if not names:
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            reason="no devices were extracted from this snapshot",
        )
    return OpResult(
        spec.name, OpStatus.OK, spec.answer_type, spec.cardinality,
        value=str(len(names)),
        derivation=(
            "count of devices in the selected snapshot"
            + ("" if include_non_network_devices else " excluding non-network objects")
        ),
        evidence=[f"{len(names)} device(s) in snapshot {model.snapshot_id or 'unknown'}"],
    )


def get_device_model(model: NetworkModel, device: str) -> OpResult:
    spec = SPECS["get_device_model"]
    dev_key, cands = find_device(model, device)
    if dev_key is None:
        return _bad(spec, "device", device, cands, "device not found or ambiguous")
    info = model.devices[dev_key]
    if not info.model:
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, reason=f"no model recorded for {device}",
        )
    return OpResult(
        spec.name, OpStatus.OK, spec.answer_type, spec.cardinality,
        value=info.model, entity=dev_key,
        evidence=[f"{device} model = {info.model}"],
    )


def get_hostname(model: NetworkModel, device: str) -> OpResult:
    spec = SPECS["get_hostname"]
    dev_key, cands = find_device(model, device)
    if dev_key is None:
        return _bad(spec, "device", device, cands, "device not found or ambiguous")

    # Prefer the consensus-verified hostname observation. DeviceInfo.hostname falls
    # back to the display name when no config was parsed, which is not a hostname.
    observed: list[str] = []
    for ob in model.observations:
        if ob.entity_type == "device" and ob.entity_id == dev_key and ob.field == "hostname":
            value = (ob.value or "").strip()
            if value and "[[" not in value and value not in observed:
                observed.append(value)

    info = model.devices[dev_key]
    configured = (info.hostname or "").strip()
    has_config_hostname = bool(configured) and configured != info.name and "[[" not in configured

    host = ""
    if len(observed) == 1:
        host = observed[0]
    elif len(observed) > 1:
        return OpResult(
            spec.name, OpStatus.AMBIGUOUS, spec.answer_type, spec.cardinality,
            entity=dev_key, values=sorted(observed),
            reason=f"conflicting hostname observations for {device}",
        )
    elif has_config_hostname:
        host = configured

    if not host:
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, reason=f"no resolved IOS hostname for {device}",
        )
    return OpResult(
        spec.name, OpStatus.OK, spec.answer_type, spec.cardinality,
        value=host, entity=dev_key,
        evidence=[f"hostname {host} from the running configuration of {device}"],
    )


def _iface_result(
    spec: OpSpec, value: str, dev_key: str, iface: str, evidence: str, derivation: str = ""
) -> OpResult:
    return OpResult(
        spec.name, OpStatus.OK, spec.answer_type, spec.cardinality,
        value=value, entity=dev_key, interface=iface,
        evidence=[evidence], derivation=derivation,
    )


def get_interface_ip(model: NetworkModel, device: str, interface: str) -> OpResult:
    spec = SPECS["get_interface_ip"]
    dev_key, cands = find_device(model, device)
    if dev_key is None:
        return _bad(spec, "device", device, cands, "device not found or ambiguous")
    if_key, if_cands = find_interface(model, dev_key, interface)
    if if_key is None:
        return _bad(spec, "interface", interface, if_cands, "interface not found on device")
    info = model.interfaces.get(if_key)
    if info is None:
        # Cable-only endpoint: exists as a cable end but has no parsed config.
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, interface=interface_display_name(model, if_key),
            reason=(
                f"{device} {interface_display_name(model, if_key)} is a cable endpoint "
                "with no parsed configuration"
            ),
        )
    if not info.ipv4_address:
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, interface=info.name,
            reason=f"{device} {info.name} has no IPv4 address",
        )
    return _iface_result(
        spec, info.ipv4_address, dev_key, info.name,
        f"ip address {info.ipv4_address} {info.subnet_mask or ''}".strip(),
    )


def get_interface_mask(model: NetworkModel, device: str, interface: str) -> OpResult:
    spec = SPECS["get_interface_mask"]
    dev_key, cands = find_device(model, device)
    if dev_key is None:
        return _bad(spec, "device", device, cands, "device not found or ambiguous")
    if_key, if_cands = find_interface(model, dev_key, interface)
    if if_key is None:
        return _bad(spec, "interface", interface, if_cands, "interface not found on device")
    info = model.interfaces.get(if_key)
    if info is None:
        # Cable-only endpoint: exists as a cable end but has no parsed config.
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, interface=interface_display_name(model, if_key),
            reason=(
                f"{device} {interface_display_name(model, if_key)} is a cable endpoint "
                "with no parsed configuration"
            ),
        )
    mask = info.subnet_mask or (prefix_to_mask(info.prefix_length) if info.prefix_length else "")
    if not mask:
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, interface=info.name,
            reason=f"no subnet mask recorded for {device} {info.name}",
        )
    return _iface_result(
        spec, mask, dev_key, info.name,
        f"{info.name}: ip address {info.ipv4_address or '?'} {mask}",
    )


def get_interface_network(model: NetworkModel, device: str, interface: str) -> OpResult:
    spec = SPECS["get_interface_network"]
    dev_key, cands = find_device(model, device)
    if dev_key is None:
        return _bad(spec, "device", device, cands, "device not found or ambiguous")
    if_key, if_cands = find_interface(model, dev_key, interface)
    if if_key is None:
        return _bad(spec, "interface", interface, if_cands, "interface not found on device")
    info = model.interfaces.get(if_key)
    if info is None:
        # Cable-only endpoint: exists as a cable end but has no parsed config.
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, interface=interface_display_name(model, if_key),
            reason=(
                f"{device} {interface_display_name(model, if_key)} is a cable endpoint "
                "with no parsed configuration"
            ),
        )
    ip = normalize_ipv4(info.ipv4_address)
    mask = info.subnet_mask or (prefix_to_mask(info.prefix_length) if info.prefix_length else "")
    if not ip or not mask or mask_to_prefix(mask) is None:
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, interface=info.name,
            reason=f"cannot compute a network address for {device} {info.name}",
        )
    net = ipaddress.IPv4Interface(f"{ip}/{mask_to_prefix(mask)}").network
    return _iface_result(
        spec, str(net.network_address), dev_key, info.name,
        f"{ip} {mask} -> {net.network_address}/{net.prefixlen}",
        derivation=f"AND({ip}, {mask}) = {net.network_address}",
    )


def get_interface_prefix_length(model: NetworkModel, device: str, interface: str) -> OpResult:
    spec = SPECS["get_interface_prefix_length"]
    dev_key, cands = find_device(model, device)
    if dev_key is None:
        return _bad(spec, "device", device, cands, "device not found or ambiguous")
    if_key, if_cands = find_interface(model, dev_key, interface)
    if if_key is None:
        return _bad(spec, "interface", interface, if_cands, "interface not found on device")
    info = model.interfaces.get(if_key)
    if info is None:
        # Cable-only endpoint: exists as a cable end but has no parsed config.
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, interface=interface_display_name(model, if_key),
            reason=(
                f"{device} {interface_display_name(model, if_key)} is a cable endpoint "
                "with no parsed configuration"
            ),
        )
    prefix = info.prefix_length
    if prefix is None and info.subnet_mask:
        prefix = mask_to_prefix(info.subnet_mask)
    if prefix is None:
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, interface=info.name,
            reason=f"no prefix length derivable for {device} {info.name}",
        )
    return _iface_result(
        spec, str(prefix), dev_key, info.name,
        f"{info.name}: {info.ipv4_address or '?'} {info.subnet_mask or ''} -> /{prefix}",
        derivation=f"/{prefix} from mask {info.subnet_mask or 'unknown'}",
    )


def get_interface_status(model: NetworkModel, device: str, interface: str) -> OpResult:
    spec = SPECS["get_interface_status"]
    dev_key, cands = find_device(model, device)
    if dev_key is None:
        return _bad(spec, "device", device, cands, "device not found or ambiguous")
    if_key, if_cands = find_interface(model, dev_key, interface)
    if if_key is None:
        return _bad(spec, "interface", interface, if_cands, "interface not found on device")
    info = model.interfaces.get(if_key)
    if info is None:
        # Cable-only endpoint: exists as a cable end but has no parsed config.
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, interface=interface_display_name(model, if_key),
            reason=(
                f"{device} {interface_display_name(model, if_key)} is a cable endpoint "
                "with no parsed configuration"
            ),
        )
    status = getattr(info, "operational_state", "") or ""
    if not status:
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, interface=info.name,
            reason=f"no status recorded for {device} {info.name}",
        )
    return _iface_result(spec, status, dev_key, info.name, f"{info.name}: status {status}")


def get_default_route_next_hop(model: NetworkModel, device: str) -> OpResult:
    spec = SPECS["get_default_route_next_hop"]
    dev_key, cands = find_device(model, device)
    if dev_key is None:
        return _bad(spec, "device", device, cands, "device not found or ambiguous")
    hops: list[str] = []
    for route in model.routes:
        if route.device != dev_key:
            continue
        network = getattr(route, "destination", "") or ""
        prefix = getattr(route, "prefix_length", None)
        if (network == "0.0.0.0" and prefix in (0, None)) or str(network) == "0.0.0.0":
            nxt = getattr(route, "next_hop", "") or ""
            if nxt and nxt not in hops:
                hops.append(nxt)
    if not hops:
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, reason=f"no static default route on {device}",
        )
    if len(hops) > 1:
        return OpResult(
            spec.name, OpStatus.AMBIGUOUS, spec.answer_type, spec.cardinality,
            entity=dev_key, values=hops, reason="multiple default routes recorded",
        )
    return OpResult(
        spec.name, OpStatus.OK, spec.answer_type, spec.cardinality,
        value=hops[0], entity=dev_key,
        evidence=[f"ip route 0.0.0.0 0.0.0.0 {hops[0]}"],
    )


def get_switch_default_gateway(model: NetworkModel, device: str) -> OpResult:
    spec = SPECS["get_switch_default_gateway"]
    dev_key, cands = find_device(model, device)
    if dev_key is None:
        return _bad(spec, "device", device, cands, "device not found or ambiguous")
    gw = (model.settings.default_gateways or {}).get(dev_key, "")
    if not gw:
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, reason=f"no ip default-gateway on {device}",
        )
    return OpResult(
        spec.name, OpStatus.OK, spec.answer_type, spec.cardinality,
        value=gw, entity=dev_key,
        evidence=[f"ip default-gateway {gw}"],
    )


def get_interface_vlan(model: NetworkModel, device: str, interface: str) -> OpResult:
    spec = SPECS["get_interface_vlan"]
    dev_key, cands = find_device(model, device)
    if dev_key is None:
        return _bad(spec, "device", device, cands, "device not found or ambiguous")
    if_key, if_cands = find_interface(model, dev_key, interface)
    if if_key is None:
        return _bad(spec, "interface", interface, if_cands, "interface not found on device")
    info = model.interfaces.get(if_key)
    if info is None:
        # Cable-only endpoint: exists as a cable end but has no parsed config.
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, interface=interface_display_name(model, if_key),
            reason=(
                f"{device} {interface_display_name(model, if_key)} is a cable endpoint "
                "with no parsed configuration"
            ),
        )
    vlan = getattr(info, "vlan_assignments", None) or []
    if not vlan:
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, interface=info.name,
            reason=f"no access VLAN recorded for {device} {info.name}",
        )
    return _iface_result(
        spec, str(vlan[0]), dev_key, info.name, f"{info.name}: switchport access vlan {vlan[0]}"
    )


def get_trunk_allowed_vlans(model: NetworkModel, device: str, interface: str) -> OpResult:
    spec = SPECS["get_trunk_allowed_vlans"]
    dev_key, cands = find_device(model, device)
    if dev_key is None:
        return _bad(spec, "device", device, cands, "device not found or ambiguous")
    if_key, if_cands = find_interface(model, dev_key, interface)
    if if_key is None:
        return _bad(spec, "interface", interface, if_cands, "interface not found on device")
    info = model.interfaces.get(if_key)
    if info is None:
        # Cable-only endpoint: exists as a cable end but has no parsed config.
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, interface=interface_display_name(model, if_key),
            reason=(
                f"{device} {interface_display_name(model, if_key)} is a cable endpoint "
                "with no parsed configuration"
            ),
        )
    allowed = getattr(info, "vlan_assignments", None) or []
    if not allowed:
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, interface=info.name,
            reason=f"no trunk allowed-VLAN list recorded for {device} {info.name}",
        )
    return OpResult(
        spec.name, OpStatus.OK, spec.answer_type, spec.cardinality,
        values=[str(v) for v in allowed], entity=dev_key, interface=info.name,
        evidence=[f"{info.name}: switchport trunk allowed vlan {', '.join(map(str, allowed))}"],
    )


def list_static_routes(model: NetworkModel, device: str) -> OpResult:
    spec = SPECS["list_static_routes"]
    dev_key, cands = find_device(model, device)
    if dev_key is None:
        return _bad(spec, "device", device, cands, "device not found or ambiguous")
    rows: list[str] = []
    for route in model.routes:
        if route.device != dev_key:
            continue
        dest = getattr(route, "destination", "") or ""
        prefix = getattr(route, "prefix_length", None)
        nxt = getattr(route, "next_hop", "") or ""
        rows.append(f"{dest}/{prefix if prefix is not None else '?'} via {nxt}")
    if not rows:
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            entity=dev_key, reason=f"no static routes recorded for {device}",
        )
    return OpResult(
        spec.name, OpStatus.OK, spec.answer_type, spec.cardinality,
        values=sorted(rows), entity=dev_key, evidence=rows,
    )


def are_in_same_subnet(
    model: NetworkModel,
    device_a: str,
    interface_a: str,
    device_b: str,
    interface_b: str,
) -> OpResult:
    spec = SPECS["are_in_same_subnet"]
    left = get_interface_network(model, device_a, interface_a)
    if not left.ok:
        return OpResult(
            spec.name, left.status, spec.answer_type, spec.cardinality,
            reason=f"cannot resolve {device_a} {interface_a}: {left.reason}",
        )
    right = get_interface_network(model, device_b, interface_b)
    if not right.ok:
        return OpResult(
            spec.name, right.status, spec.answer_type, spec.cardinality,
            reason=f"cannot resolve {device_b} {interface_b}: {right.reason}",
        )
    left_ip = get_interface_ip(model, device_a, interface_a)
    right_ip = get_interface_ip(model, device_b, interface_b)
    left_mask = get_interface_mask(model, device_a, interface_a)
    right_mask = get_interface_mask(model, device_b, interface_b)
    if not (left_ip.ok and right_ip.ok and left_mask.ok and right_mask.ok):
        return OpResult(
            spec.name, OpStatus.UNAVAILABLE, spec.answer_type, spec.cardinality,
            reason="one or both endpoints lack an address and mask",
        )
    net_a = ipaddress.IPv4Network(f"{left_ip.value}/{mask_to_prefix(left_mask.value)}", strict=False)
    net_b = ipaddress.IPv4Network(f"{right_ip.value}/{mask_to_prefix(right_mask.value)}", strict=False)
    same = net_a == net_b
    return OpResult(
        spec.name, OpStatus.OK, spec.answer_type, spec.cardinality,
        value="true" if same else "false",
        derivation=(
            f"{left_ip.value}/{left_mask.value} -> {net_a}; "
            f"{right_ip.value}/{right_mask.value} -> {net_b}"
        ),
        evidence=[f"network A {net_a}, network B {net_b}"],
    )


def calculate_network_address(model: NetworkModel, ip: str, mask: str) -> OpResult:
    spec = SPECS["calculate_network_address"]
    return _calc_address(spec, ip, mask, broadcast=False)


def calculate_broadcast_address(model: NetworkModel, ip: str, mask: str) -> OpResult:
    spec = SPECS["calculate_broadcast_address"]
    return _calc_address(spec, ip, mask, broadcast=True)


def _calc_address(spec: OpSpec, ip: str, mask: str, broadcast: bool) -> OpResult:
    ip_norm = normalize_ipv4(ip)
    prefix = mask_to_prefix(mask)
    if not ip_norm or prefix is None:
        return OpResult(
            spec.name, OpStatus.BAD_ARGUMENT, spec.answer_type, spec.cardinality,
            reason=f"invalid IP/mask arguments: {ip!r} {mask!r}",
        )
    net = ipaddress.IPv4Interface(f"{ip_norm}/{prefix}").network
    value = str(net.broadcast_address if broadcast else net.network_address)
    return OpResult(
        spec.name, OpStatus.OK, spec.answer_type, spec.cardinality,
        value=value,
        derivation=(
            f"{'broadcast' if broadcast else 'network'} of {ip_norm}/{prefix} = {value}"
        ),
        evidence=[f"{ip_norm} {mask} -> {net.with_prefixlen}"],
    )


def _bad(
    spec: OpSpec,
    kind: str,
    arg: str,
    candidates: list[str],
    reason: str,
) -> OpResult:
    status = OpStatus.AMBIGUOUS if len(candidates) > 1 else OpStatus.BAD_ARGUMENT
    detail = f"{reason}: {arg!r}"
    if len(candidates) > 1:
        detail += f" (candidates: {', '.join(sorted(candidates))})"
    return OpResult(
        spec.name, status, spec.answer_type, spec.cardinality,
        values=sorted(candidates) if len(candidates) > 1 else [],
        reason=detail,
    )


#: Dispatch table: operation name -> callable(model, **arguments).
OPERATIONS = {
    "get_physical_neighbor": get_physical_neighbor,
    "get_peer_interface": get_peer_interface,
    "list_physical_neighbors": list_physical_neighbors,
    "count_physical_links": count_physical_links,
    "count_physical_neighbors": count_physical_neighbors,
    "count_devices": count_devices,
    "get_device_model": get_device_model,
    "get_hostname": get_hostname,
    "get_interface_ip": get_interface_ip,
    "get_interface_mask": get_interface_mask,
    "get_interface_network": get_interface_network,
    "get_interface_prefix_length": get_interface_prefix_length,
    "get_interface_status": get_interface_status,
    "get_default_route_next_hop": get_default_route_next_hop,
    "get_switch_default_gateway": get_switch_default_gateway,
    "get_interface_vlan": get_interface_vlan,
    "get_trunk_allowed_vlans": get_trunk_allowed_vlans,
    "list_static_routes": list_static_routes,
    "are_in_same_subnet": are_in_same_subnet,
    "calculate_network_address": calculate_network_address,
    "calculate_broadcast_address": calculate_broadcast_address,
}


def validate_value(op: OpResult) -> tuple[bool, str]:
    """Type gate: does the produced value satisfy the operation's declared type?

    This is the check that prevents a mask question from accepting a host IP.
    """
    spec = SPECS.get(op.operation)
    if spec is None:
        return False, f"unknown operation {op.operation!r}"
    if not op.ok:
        return False, f"operation status is {op.status.value}"

    if op.cardinality is Cardinality.MANY:
        if not op.values:
            return False, "expected several values, got none"
        return True, "ok"

    value = (op.value or "").strip()
    if not value:
        return False, "empty value"
    if "[[" in value:
        return False, "unresolved display-name placeholder in the value"

    t = spec.answer_type
    if t is AnswerType.INTEGER:
        return (bool(re.fullmatch(r"-?\d+", value)), "not an integer")
    if t is AnswerType.IPV4:
        return (normalize_ipv4(value) is not None, "not an IPv4 address")
    if t is AnswerType.MASK:
        if normalize_ipv4(value) is None:
            return False, "not a dotted-quad mask"
        return (mask_to_prefix(value) is not None, "not a contiguous subnet mask")
    if t is AnswerType.BOOLEAN:
        return (value.lower() in {"true", "false", "yes", "no"}, "not a boolean")
    if t is AnswerType.DEVICE:
        # A device answer is one identity. Reject lists and sentences; a real
        # device name may legitimately contain spaces and parentheses.
        if "," in value or ";" in value:
            return False, "device answer is a list, not a single device"
        if len(value) > 120:
            return False, "device answer is too long to be one identity"
        if "[[" in value:
            return False, "unresolved display-name placeholder"
        return True, "ok"
    if t is AnswerType.INTERFACE:
        return (canonical_interface_name(value) != "", "not an interface name")
    return True, "ok"


def run_operation(model: NetworkModel, name: str, arguments: dict) -> OpResult:
    """Execute one named operation, returning a typed result."""
    spec = SPECS.get(name)
    if spec is None:
        return OpResult(
            name, OpStatus.BAD_ARGUMENT, AnswerType.TEXT, Cardinality.ONE,
            reason=f"unknown operation {name!r}",
        )
    fn = OPERATIONS[name]
    try:
        return fn(model, **arguments)
    except TypeError as exc:
        return OpResult(
            name, OpStatus.BAD_ARGUMENT, spec.answer_type, spec.cardinality,
            reason=f"invalid arguments {arguments!r}: {exc}",
        )
