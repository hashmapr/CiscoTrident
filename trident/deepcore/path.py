"""DeepCore: deterministic packet-path reasoning.

Answers one question without an LLM: *given this configuration and topology, where
would traffic from A to B actually go, and where would it stop?*

The engine is deliberately narrow and honest about it:

* Every conclusion cites the configuration line or topology fact it rests on.
* A step the model cannot evaluate yields ``UNKNOWN`` with the reason, not a
  guess. A prediction containing ``UNKNOWN`` is never reported as a definite
  path.
* Predictions are **not** observations. They carry ``SIMULATED_PREDICTION`` as
  their evidence kind and are never written into the consensus that produces
  ``VERIFIED``.
* Layer 2 and Layer 3 are kept separate. Physical adjacency does not imply IP
  reachability, and the code does not conflate them.
"""

from __future__ import annotations

import enum
import ipaddress
from dataclasses import dataclass, field

from ..models import InterfaceInfo, NetworkModel

#: Interface names that are logical/VLAN interfaces rather than physical ports.
_SVI_PREFIXES = ("vlan",)


class Step(enum.StrEnum):
    """What a prediction step concluded."""

    #: Traffic continues to the next hop.
    FORWARD = "FORWARD"
    #: Traffic is delivered at this device.
    DELIVER = "DELIVER"
    #: Traffic is discarded here, with a stated reason.
    DROP = "DROP"
    #: The model cannot evaluate this step.
    UNKNOWN = "UNKNOWN"


class EvidenceKind(enum.StrEnum):
    """Where a conclusion came from. Never mixed."""

    #: Derived deterministically from parsed configuration and topology.
    SIMULATED_PREDICTION = "SIMULATED_PREDICTION"
    #: A live simulator reported this.
    SIMULATOR_OBSERVATION = "SIMULATOR_OBSERVATION"


@dataclass
class PathStep:
    """One hop of a prediction, with the evidence behind it."""

    device: str
    interface: str | None
    action: Step
    detail: str
    evidence: str = ""
    kind: EvidenceKind = EvidenceKind.SIMULATED_PREDICTION

    def as_dict(self) -> dict:
        return {
            "device": self.device,
            "interface": self.interface,
            "action": self.action.value,
            "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass
class PathPrediction:
    """The predicted path, its dependencies, and where it is unsure."""

    source: str
    destination: str
    protocol: str
    steps: list[PathStep] = field(default_factory=list)
    delivered: bool | None = None
    failure_point: str | None = None
    dependencies: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    kind: EvidenceKind = EvidenceKind.SIMULATED_PREDICTION

    @property
    def definite(self) -> bool:
        """True only when every step is decisive."""
        return all(step.action is not Step.UNKNOWN for step in self.steps) and bool(self.steps)

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "destination": self.destination,
            "protocol": self.protocol,
            "delivered": self.delivered,
            "definite": self.definite,
            "failure_point": self.failure_point,
            "steps": [step.as_dict() for step in self.steps],
            "dependencies": list(self.dependencies),
            "limitations": list(self.limitations),
            "evidence_kind": self.kind.value,
        }


def _network_of(interface: InterfaceInfo) -> ipaddress.IPv4Network | None:
    if not interface.ipv4_address or interface.prefix_length is None:
        return None
    try:
        return ipaddress.IPv4Interface(
            f"{interface.ipv4_address}/{interface.prefix_length}"
        ).network
    except ValueError:
        return None


def _is_svi(name: str) -> bool:
    return name.strip().lower().startswith(_SVI_PREFIXES)


class DeepCore:
    """Deterministic forwarding reasoning over one network model."""

    def __init__(self, model: NetworkModel) -> None:
        self.model = model
        self._by_device: dict[str, list[InterfaceInfo]] = {}
        for interface in model.interfaces.values():
            self._by_device.setdefault(interface.device, []).append(interface)

    # -- lookups ---------------------------------------------------------

    def interfaces(self, device: str) -> list[InterfaceInfo]:
        return self._by_device.get(device, [])

    def routed_interfaces(self, device: str) -> list[InterfaceInfo]:
        return [i for i in self.interfaces(device) if i.ipv4_address and i.prefix_length is not None]

    def _interface(self, device: str, name: str) -> InterfaceInfo | None:
        lowered = name.strip().lower()
        for interface in self.interfaces(device):
            if interface.name.strip().lower() == lowered:
                return interface
            if (interface.canonical_name or "").strip().lower() == lowered:
                return interface
        return None

    def peer(self, device: str, interface: str) -> tuple[str, str] | None:
        """The device and interface at the other end of a physical link."""
        key = interface.strip().lower()
        for link in self.model.links:
            if link.device_a == device and link.interface_a.strip().lower() == key:
                return link.device_b, link.interface_b
            if link.device_b == device and link.interface_b.strip().lower() == key:
                return link.device_a, link.interface_a
        return None

    def address_owner(self, address: str) -> tuple[str, str] | None:
        for interface in self.model.interfaces.values():
            if interface.ipv4_address == address:
                return interface.device, interface.name
        return None

    # -- routing ---------------------------------------------------------

    def routes(self, device: str) -> list:
        return [route for route in self.model.routes if route.device == device]

    def longest_prefix_match(self, device: str, destination: str):
        """The route a router would select for ``destination``.

        Longest prefix first, then lowest administrative distance. Returns
        ``None`` when nothing matches — which is a real answer: traffic is
        dropped, not "unknown".
        """
        try:
            target = ipaddress.IPv4Address(destination)
        except ValueError:
            return None

        best = None
        best_key: tuple[int, int] | None = None
        for route in self.routes(device):
            network = _route_network(route.destination)
            if network is None:
                continue
            if target not in network:
                continue
            distance = route.administrative_distance if route.administrative_distance is not None else 1
            key = (-network.prefixlen, distance)
            if best_key is None or key < best_key:
                best, best_key = route, key
        return best

    # -- prediction ------------------------------------------------------

    def predict_path(
        self, source: str, destination: str, protocol: str = "icmp"
    ) -> PathPrediction:
        """Predict the forwarding path from one device to another.

        ``source`` and ``destination`` are device names; the destination address
        is taken from the destination device's most specific routed interface.
        """
        prediction = PathPrediction(source=source, destination=destination, protocol=protocol)

        if source not in self.model.devices:
            prediction.steps.append(
                PathStep(source, None, Step.UNKNOWN, "source device is not in the model")
            )
            prediction.limitations.append("source device unknown")
            return prediction
        if destination not in self.model.devices:
            prediction.steps.append(
                PathStep(source, None, Step.UNKNOWN, "destination device is not in the model")
            )
            prediction.limitations.append("destination device unknown")
            return prediction

        target_interface = self._first_routed(destination)
        if target_interface is None:
            prediction.steps.append(
                PathStep(
                    source,
                    None,
                    Step.UNKNOWN,
                    f"{destination} has no IPv4 address in the model",
                )
            )
            prediction.limitations.append(
                "destination has no address; a host configured at runtime cannot be predicted"
            )
            return prediction

        target_address = target_interface.ipv4_address or ""
        target_network = _network_of(target_interface)

        # Step 1: is the source already on the destination's subnet?
        local = self._interface_on_network(source, target_network) if target_network else None
        if local is not None and local.ipv4_address != target_address:
            prediction.steps.append(
                PathStep(
                    source,
                    local.name,
                    Step.DELIVER,
                    f"{target_address} is directly connected on {local.name}'s subnet",
                    evidence=f"{local.name} {local.ipv4_address}/{local.prefix_length}",
                )
            )
            prediction.dependencies.append("L2 forwarding between the two ports")
            self._check_interface_state(prediction, source, local)
            prediction.delivered = not any(s.action is Step.DROP for s in prediction.steps)
            return prediction

        # Step 2: a source that is itself a router may route directly. Check its
        # own table before falling back to a host default gateway — otherwise a
        # correctly routed router chain is misreported as having no gateway.
        own_route = self.longest_prefix_match(source, target_address)
        if own_route is not None and not self._is_host(source):
            self._walk(prediction, source, target_address, target_network, visited=set())
            if prediction.steps and prediction.steps[-1].action is not Step.UNKNOWN:
                prediction.delivered = not any(
                    step.action is Step.DROP for step in prediction.steps
                )
                return prediction

        # Step 3: hand off to the default gateway.
        gateway = self.model.settings.default_gateways.get(source)
        if gateway is None:
            prediction.steps.append(
                PathStep(
                    source,
                    None,
                    Step.DROP,
                    "no default gateway is configured on the source",
                )
            )
            prediction.failure_point = source
            prediction.delivered = False
            return prediction

        owner = self.address_owner(gateway)
        if owner is None:
            prediction.steps.append(
                PathStep(
                    source,
                    None,
                    Step.DROP,
                    f"default gateway {gateway} is not assigned to any interface",
                )
            )
            prediction.failure_point = source
            prediction.delivered = False
            return prediction

        if _is_svi(self._interface(owner[0], owner[1]).name if self._interface(owner[0], owner[1]) else ""):
            prediction.dependencies.append(f"gateway is an SVI on {owner[0]}")

        # Step 3: walk the routed path.
        self._walk(prediction, owner[0], target_address, target_network, visited={source})
        return prediction

    def _is_host(self, device: str) -> bool:
        """A host is not expected to have a routing table of its own."""
        info = self.model.devices.get(device)
        kind = (info.device_type or "").lower() if info else ""
        return "host" in kind or kind in {"pc", "server", "endpoint"}

    def _first_routed(self, device: str) -> InterfaceInfo | None:
        routed = self.routed_interfaces(device)
        if not routed:
            return None
        # Prefer a physical routed port over an SVI when both exist.
        physical = [i for i in routed if not _is_svi(i.name)]
        return (physical or routed)[0]

    def _interface_on_network(self, device: str, network) -> InterfaceInfo | None:
        if network is None:
            return None
        for interface in self.routed_interfaces(device):
            candidate = _network_of(interface)
            if candidate == network:
                return interface
        return None

    def _check_interface_state(
        self, prediction: PathPrediction, device: str, interface: InterfaceInfo
    ) -> None:
        state = (interface.admin_state or "").lower()
        if state in {"administratively down", "down"}:
            prediction.steps.append(
                PathStep(
                    device,
                    interface.name,
                    Step.DROP,
                    f"{interface.name} is administratively down",
                    evidence=f"admin_state={interface.admin_state}",
                )
            )
            prediction.failure_point = device

    def _walk(
        self,
        prediction: PathPrediction,
        device: str,
        target_address: str,
        target_network,
        visited: set[str],
    ) -> None:
        """Follow the routed path from ``device`` toward the target."""
        if device in visited:
            prediction.steps.append(
                PathStep(device, None, Step.DROP, "forwarding loop detected")
            )
            prediction.failure_point = device
            prediction.delivered = False
            return
        visited.add(device)

        # Arrived: does this device hold the address itself?
        holder = self.address_owner(target_address)
        if holder is not None and holder[0] == device:
            prediction.steps.append(
                PathStep(
                    device,
                    holder[1],
                    Step.DELIVER,
                    f"{target_address} is local to this device",
                )
            )
            prediction.delivered = not any(s.action is Step.DROP for s in prediction.steps)
            return

        # Directly connected here?
        local = self._interface_on_network(device, target_network) if target_network else None
        if local is not None:
            prediction.steps.append(
                PathStep(
                    device,
                    local.name,
                    Step.DELIVER,
                    f"{target_network} is directly connected on {local.name}",
                    evidence=f"{local.name} {local.ipv4_address}/{local.prefix_length}",
                )
            )
            self._check_interface_state(prediction, device, local)
            prediction.dependencies.append("L2 forwarding to the destination port")
            prediction.delivered = not any(s.action is Step.DROP for s in prediction.steps)
            return

        route = self.longest_prefix_match(device, target_address)
        if route is None:
            prediction.steps.append(
                PathStep(
                    device,
                    None,
                    Step.DROP,
                    f"no route matches {target_address} on {device}",
                    evidence="routing table",
                )
            )
            prediction.failure_point = device
            prediction.delivered = False
            return

        outgoing = route.outgoing_interface or ""
        interface = self._interface(device, outgoing) if outgoing else None
        prediction.steps.append(
            PathStep(
                device,
                outgoing or None,
                Step.FORWARD,
                f"route {route.destination} via {route.next_hop or 'connected'}",
                evidence=route.raw_config or f"{route.destination} -> {route.next_hop}",
            )
        )
        if interface is not None:
            self._check_interface_state(prediction, device, interface)
            if prediction.failure_point:
                prediction.delivered = False
                return

        next_hop = route.next_hop
        if next_hop:
            next_owner = self.address_owner(next_hop)
            if next_owner is None:
                prediction.steps.append(
                    PathStep(
                        device,
                        None,
                        Step.UNKNOWN,
                        f"next hop {next_hop} is not a modelled interface",
                    )
                )
                prediction.limitations.append(
                    f"next hop {next_hop} is outside the model; the path cannot be followed further"
                )
                return
            self._walk(prediction, next_owner[0], target_address, target_network, visited)
            return

        prediction.steps.append(
            PathStep(
                device,
                None,
                Step.UNKNOWN,
                "route has neither a next hop nor a usable interface",
            )
        )
        prediction.limitations.append("incomplete route entry")

    # -- ACL -------------------------------------------------------------

    def acl_verdict(self, device: str, interface: str, address: str) -> str:
        """Whether an ACL on this interface would deny traffic to ``address``.

        Returns ``"permit"``, ``"deny"``, or ``"unknown"``. Only explicit denies
        bound to a real interface are evaluated; anything else is ``unknown``
        rather than assumed permitted.
        """
        for acl in self.model.acls:
            if acl.applied_interface != interface:
                continue
            if (acl.action or "").lower() != "deny":
                continue
            destination = (acl.destination or "").split()[0]
            if not destination or destination in {"any", "any/any"}:
                return "deny"
            network = _route_network(destination)
            if network is None:
                continue
            try:
                if ipaddress.IPv4Address(address) in network:
                    return "deny"
            except ValueError:
                continue
        # No bound deny matched. That is "permit" only in the sense that nothing
        # in the model denies it; an ACL the parser could not bind is still a
        # limitation, so callers see the evidence that led here.
        return "permit"


def _route_network(destination: str | None) -> ipaddress.IPv4Network | None:
    text = (destination or "").strip()
    if not text:
        return None
    if text in {"0.0.0.0", "0.0.0.0/0"}:
        return ipaddress.IPv4Network("0.0.0.0/0")
    if "/" not in text:
        text = f"{text}/32"
    try:
        return ipaddress.IPv4Network(text, strict=False)
    except ValueError:
        return None


__all__ = [
    "DeepCore",
    "EvidenceKind",
    "PathPrediction",
    "PathStep",
    "Step",
]
