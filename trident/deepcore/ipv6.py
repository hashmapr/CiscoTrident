"""IPv6 addressing and routing reasoning.

IPv6 is not IPv4 with longer addresses. The differences that matter for
reachability reasoning:

* **Link-local next hops.** A next hop written as ``fe80::1`` is only meaningful
  together with the outgoing interface. Without one, the next hop is ambiguous and
  the prediction must say so rather than pick an interface.
* **Neighbor Discovery replaces ARP.** On-link determination drives ND, and an
  address is on-link when it falls inside a prefix configured on an interface of
  the sending device — not by comparing a mask the way IPv4 does.
* **``ipv6 unicast-routing`` gates forwarding.** A router with addresses but
  without this command does not forward, and that is a real, checkable fault.
* **Addresses are not unique by 32-bit equality alone.** Two interfaces holding
  the same IPv6 address is a real conflict, but the *scope* matters: the same
  link-local on different links is normal.

Predictions here are configuration-derived. Neighbor cache contents are runtime
state and are never invented.
"""

from __future__ import annotations

import enum
import ipaddress
from dataclasses import dataclass, field

from .protocols import Ipv6Config


class Outcome(enum.StrEnum):
    """What the configuration says about one IPv6 path."""

    DELIVERS = "DELIVERS"
    DROPS = "DROPS"
    #: The configuration cannot decide it.
    UNDECIDED = "UNDECIDED"
    #: IPv6 forwarding is off on the transit device.
    FORWARDING_DISABLED = "FORWARDING_DISABLED"


@dataclass
class Ipv6Step:
    device: str
    interface: str | None
    detail: str
    on_link: bool | None = None

    def as_dict(self) -> dict:
        return {
            "device": self.device,
            "interface": self.interface,
            "detail": self.detail,
            "on_link": self.on_link,
        }


@dataclass
class Ipv6Prediction:
    source: str
    destination: str
    outcome: Outcome
    steps: list[Ipv6Step] = field(default_factory=list)
    next_hop: str | None = None
    failure_point: str | None = None
    caveats: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "destination": self.destination,
            "outcome": self.outcome.value,
            "steps": [step.as_dict() for step in self.steps],
            "next_hop": self.next_hop,
            "failure_point": self.failure_point,
            "caveats": list(self.caveats),
        }


def is_link_local(address: str) -> bool:
    """Whether ``address`` is link-local (``fe80::/10``)."""
    try:
        return ipaddress.IPv6Address(address.split("/")[0]).is_link_local
    except ValueError:
        return False


def is_unspecified(address: str) -> bool:
    try:
        return ipaddress.IPv6Address(address.split("/")[0]).is_unspecified
    except ValueError:
        return False


def _interface_networks(config: Ipv6Config) -> dict[str, list[ipaddress.IPv6Network]]:
    networks: dict[str, list[ipaddress.IPv6Network]] = {}
    for name, interface in config.interfaces.items():
        for address in interface.addresses:
            try:
                networks.setdefault(name, []).append(
                    ipaddress.IPv6Interface(address).network
                )
            except ValueError:
                continue
    return networks


def on_link_interface(config: Ipv6Config, address: str) -> str | None:
    """The local interface whose prefix contains ``address``, if any."""
    try:
        target = ipaddress.IPv6Address(address)
    except ValueError:
        return None
    for name, networks in _interface_networks(config).items():
        for network in networks:
            if target in network:
                return name
    return None


def predict(
    config: Ipv6Config,
    source_address: str,
    destination_address: str,
    *,
    device: str = "",
) -> Ipv6Prediction:
    """Predict reachability for one IPv6 destination from one device.

    Deliberately narrow: it decides on-link versus routed, and whether forwarding
    is even enabled. It does not guess neighbor state, and an ambiguous link-local
    next hop is reported rather than resolved.
    """
    prediction = Ipv6Prediction(
        source=source_address,
        destination=destination_address,
        outcome=Outcome.UNDECIDED,
    )

    if not config.configured:
        prediction.outcome = Outcome.UNDECIDED
        prediction.caveats.append(f"{device or 'this device'} has no IPv6 configuration")
        return prediction

    on_link = on_link_interface(config, destination_address)
    if on_link is not None:
        prediction.outcome = Outcome.DELIVERS
        prediction.steps.append(
            Ipv6Step(
                device=device,
                interface=on_link,
                detail=(
                    f"{destination_address} falls inside a prefix on {on_link}, so it is "
                    "on-link and reachable by Neighbor Discovery"
                ),
                on_link=True,
            )
        )
        prediction.caveats.append(
            "requires a completed neighbor discovery exchange, which is runtime state"
        )
        return prediction

    # Off-link: forwarding is checked before routing. A device that does not
    # forward drops the packet whether or not a route exists, so reporting a
    # missing route there would blame the wrong configuration.
    if not config.forwarding:
        prediction.outcome = Outcome.FORWARDING_DISABLED
        prediction.failure_point = device
        prediction.caveats.append(
            "ipv6 unicast-routing is not configured, so this device does not forward "
            "off-link traffic at all"
        )
        return prediction

    route = _match_route(config, destination_address)
    if route is None:
        prediction.outcome = Outcome.DROPS
        prediction.failure_point = device
        prediction.steps.append(
            Ipv6Step(
                device=device,
                interface=None,
                detail=f"no IPv6 route matches {destination_address}",
                on_link=False,
            )
        )
        return prediction

    prefix, next_hop = route
    prediction.next_hop = next_hop
    prediction.steps.append(
        Ipv6Step(
            device=device,
            interface=None,
            detail=f"route {prefix} via {next_hop or 'a connected interface'}",
            on_link=False,
        )
    )

    if next_hop and is_link_local(next_hop):
        # A link-local next hop without an outgoing interface is ambiguous.
        prediction.outcome = Outcome.UNDECIDED
        prediction.caveats.append(
            f"next hop {next_hop} is link-local, so it only means something together "
            "with the outgoing interface, which the route does not record"
        )
        return prediction

    prediction.outcome = Outcome.DELIVERS
    prediction.caveats.append(
        "the destination device must have a route back for the reply to arrive"
    )
    return prediction


def _match_route(
    config: Ipv6Config, destination: str
) -> tuple[str, str | None] | None:
    """Longest-prefix match over the configured IPv6 static routes."""
    try:
        target = ipaddress.IPv6Address(destination)
    except ValueError:
        return None
    best: tuple[str, str | None] | None = None
    best_length = -1
    for prefix, next_hop in config.routes:
        try:
            network = ipaddress.IPv6Network(prefix, strict=False)
        except ValueError:
            continue
        if target not in network:
            continue
        if network.prefixlen > best_length:
            best, best_length = (prefix, next_hop), network.prefixlen
    return best


def duplicate_addresses(config: Ipv6Config) -> list[tuple[str, list[str]]]:
    """Global addresses held by more than one interface.

    Link-local addresses are excluded: the same link-local on two different
    interfaces is normal, not a conflict.
    """
    owners: dict[str, list[str]] = {}
    for name, interface in config.interfaces.items():
        for address in interface.addresses:
            if is_link_local(address):
                continue
            key = address.split("/")[0].lower()
            owners.setdefault(key, []).append(name)
    return [(address, names) for address, names in sorted(owners.items()) if len(names) > 1]


def problems(config: Ipv6Config) -> list[str]:
    """Configuration-level IPv6 problems needing no traffic to detect."""
    found: list[str] = []
    for name, interface in config.interfaces.items():
        if interface.addresses and not config.forwarding:
            found.append(
                f"{name} has an IPv6 address but ipv6 unicast-routing is not configured"
            )
    for address, names in duplicate_addresses(config):
        found.append(f"{address} is configured on {len(names)} interfaces: {', '.join(names)}")
    return found


__all__ = [
    "Ipv6Prediction",
    "Ipv6Step",
    "Outcome",
    "duplicate_addresses",
    "is_link_local",
    "on_link_interface",
    "predict",
    "problems",
]
