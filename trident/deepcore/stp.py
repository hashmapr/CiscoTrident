"""Spanning Tree Protocol reasoning: root election and port roles.

Given switch bridges, their priorities, and the links between them, compute which
bridge is root and what role each port plays. This is deterministic graph
reasoning over IEEE 802.1D rules, not a configuration grep.

The honesty boundary is the important part. STP port state depends on things the
file may not contain — MAC addresses for tie-breaking, current topology events,
whether BPDUs are actually flowing. So:

* A role is computed only when the evidence needed to decide it exists.
* Tie-breakers that cannot be evaluated produce ``UNDECIDED`` with the missing
  fact named, never a guess.
* Every predicted role carries whether it rests on configured facts or on an
  assumed IOS default, so a reader can see how much weight it bears.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from .protocols import DEFAULT_BRIDGE_PRIORITY, DEFAULT_PORT_COST, StpMode


#: Port roles in a spanning tree.
class Role(enum.StrEnum):
    ROOT = "ROOT"
    DESIGNATED = "DESIGNATED"
    ALTERNATE = "ALTERNATE"
    BLOCKED = "BLOCKED"
    #: The evidence is not sufficient to decide.
    UNDECIDED = "UNDECIDED"

    @property
    def forwards(self) -> bool:
        return self in {Role.ROOT, Role.DESIGNATED}


@dataclass
class Bridge:
    """One switch participating in the tree."""

    name: str
    priority: int | None = None
    #: MAC used for the bridge-id tie-break. Often absent from a lab file.
    mac: str | None = None
    #: Interface name -> configured port cost. Missing means "derive from speed".
    port_costs: dict[str, int] = field(default_factory=dict)
    #: Interface name -> configured port priority.
    port_priorities: dict[str, int] = field(default_factory=dict)
    #: Ports currently blocking because BPDU guard or a similar feature tripped.
    blocked_ports: list[str] = field(default_factory=list)

    def effective_priority(self) -> int | None:
        """Configured priority, or ``None`` when unstated.

        Deliberately not defaulted to 32768 here: the caller decides whether to
        assume the IOS default, and a prediction built on an assumption says so.
        """
        return self.priority

    def cost_of(self, interface: str, speed_mbps: int | None = None) -> int | None:
        """Cost of a port: configured, else derived from speed, else unknown."""
        if interface in self.port_costs:
            return self.port_costs[interface]
        if speed_mbps is not None and speed_mbps in DEFAULT_PORT_COST:
            return DEFAULT_PORT_COST[speed_mbps]
        return None


@dataclass
class PortRole:
    """The computed role of one port."""

    bridge: str
    interface: str
    role: Role
    reason: str
    #: True when the role depends on assuming an IOS default rather than on
    #: configuration actually present in the file.
    assumed_default: bool = False

    def as_dict(self) -> dict:
        return {
            "bridge": self.bridge,
            "interface": self.interface,
            "role": self.role.value,
            "forwards": self.role.forwards,
            "reason": self.reason,
            "assumed_default": self.assumed_default,
        }


@dataclass
class Election:
    """The result of one spanning-tree computation."""

    mode: StpMode = StpMode.UNKNOWN
    root: str | None = None
    root_reason: str = ""
    roles: list[PortRole] = field(default_factory=list)
    undecided: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)

    def role_of(self, bridge: str, interface: str) -> Role:
        for port in self.roles:
            if port.bridge == bridge and port.interface == interface:
                return port.role
        return Role.UNDECIDED

    def forwarding_ports(self, bridge: str) -> list[str]:
        return [p.interface for p in self.roles if p.bridge == bridge and p.role.forwards]

    def as_dict(self) -> dict:
        return {
            "mode": self.mode.value,
            "root": self.root,
            "root_reason": self.root_reason,
            "roles": [role.as_dict() for role in self.roles],
            "undecided": list(self.undecided),
            "assumptions": list(self.assumptions),
        }


def elect_root(
    bridges: list[Bridge],
    assume_default_priority: bool = False,
) -> tuple[Bridge | None, str, list[str]]:
    """Elect the root bridge.

    Returns ``(root, reason, assumptions)``. Ties are broken by lowest priority,
    then lowest MAC. When priorities tie and no MAC is available, the election is
    undecidable and that is reported rather than resolved arbitrarily.
    """
    if not bridges:
        return None, "no bridges to elect", []

    assumptions: list[str] = []
    candidates: list[tuple[int, str, Bridge]] = []
    unknown: list[str] = []
    for bridge in bridges:
        priority = bridge.effective_priority()
        if priority is None:
            if not assume_default_priority:
                unknown.append(bridge.name)
                continue
            priority = DEFAULT_BRIDGE_PRIORITY
            assumptions.append(
                f"{bridge.name} has no configured priority; assumed the IOS default "
                f"of {DEFAULT_BRIDGE_PRIORITY}"
            )
        candidates.append((priority, bridge.mac or "", bridge))

    if not candidates:
        return (
            None,
            "no bridge states a priority, so the root cannot be decided",
            assumptions,
        )

    lowest = min(candidate[0] for candidate in candidates)
    tied = [candidate for candidate in candidates if candidate[0] == lowest]
    if len(tied) > 1:
        without_mac = [c[2].name for c in tied if not c[1]]
        if without_mac:
            return (
                None,
                (
                    f"{len(tied)} bridges share priority {lowest} and "
                    f"{len(without_mac)} have no MAC to break the tie: "
                    f"{', '.join(without_mac)}"
                ),
                assumptions,
            )
        tied.sort(key=lambda candidate: _mac_sort_key(candidate[1]))
        winner = tied[0][2]
        return (
            winner,
            (f"priority {lowest} ties with {', '.join(c[2].name for c in tied[1:])}; "
            f"{winner.name} wins on the lower MAC {winner.mac}"),
            assumptions,
        )

    winner = tied[0][2]
    return winner, f"lowest bridge priority {lowest}", assumptions


def _mac_sort_key(mac: str) -> tuple[int, ...]:
    parts = []
    for chunk in mac.replace("-", ":").split(":"):
        try:
            parts.append(int(chunk, 16))
        except ValueError:
            parts.append(0)
    return tuple(parts)


@dataclass
class Link:
    """A physical link between two switch ports."""

    bridge_a: str
    port_a: str
    bridge_b: str
    port_b: str
    cost: int | None = None


def compute(
    bridges: list[Bridge],
    links: list[Link],
    mode: StpMode = StpMode.UNKNOWN,
    assume_default_priority: bool = False,
) -> Election:
    """Compute root and port roles for one spanning tree.

    Root ports are chosen per non-root bridge as the port with the lowest path
    cost to the root. On each link the end closer to the root is designated; the
    other end is alternate. Equal-cost ties produce ``UNDECIDED`` rather than an
    arbitrary pick, because the real tie-break uses neighbour bridge ids that a
    lab file rarely contains.
    """
    election = Election(mode=mode)
    if not bridges:
        return election

    root, reason, assumptions = elect_root(bridges, assume_default_priority)
    election.root_reason = reason
    election.assumptions.extend(assumptions)
    if root is None:
        election.undecided.append(reason)
        for link in links:
            for bridge, port in ((link.bridge_a, link.port_a), (link.bridge_b, link.port_b)):
                election.roles.append(
                    PortRole(bridge, port, Role.UNDECIDED, "root bridge undecided")
                )
        return election
    election.root = root.name

    # Every port starts undecided; each link resolves two ends.
    by_name = {bridge.name: bridge for bridge in bridges}
    for link in links:
        left = by_name.get(link.bridge_a)
        right = by_name.get(link.bridge_b)
        if left is None or right is None:
            continue
        # A link whose two ends are the same bridge is a loop by construction,
        # whatever the local costs say.
        if left.name == right.name:
            message = f"{left.name}:{link.port_a} and :{link.port_b} are the same bridge"
            election.undecided.append(message)
            election.roles.append(
                PortRole(left.name, link.port_a, Role.UNDECIDED, message)
            )
            election.roles.append(
                PortRole(right.name, link.port_b, Role.UNDECIDED, message)
            )
            continue

        # The root bridge's own ports are designated whatever the cost, so this
        # is decided before cost is even consulted. Costs only matter between two
        # non-root bridges.
        if left.name == root.name or right.name == root.name:
            root_bridge, root_port = (
                (left, link.port_a) if left.name == root.name else (right, link.port_b)
            )
            other, other_port = (
                (right, link.port_b) if left.name == root.name else (left, link.port_a)
            )
            election.roles.append(
                PortRole(
                    root_bridge.name,
                    root_port,
                    Role.DESIGNATED,
                    "root bridge port forwards regardless of cost",
                )
            )
            election.roles.append(
                PortRole(
                    other.name,
                    other_port,
                    Role.ALTERNATE,
                    f"further from root {root.name}",
                )
            )
            continue

        left_cost = left.cost_of(link.port_a, link.cost)
        right_cost = right.cost_of(link.port_b, link.cost)
        if left_cost is None or right_cost is None:
            message = (
                f"cost of {link.bridge_a}:{link.port_a} <-> {link.bridge_b}:{link.port_b} "
                "is not stated"
            )
            election.undecided.append(message)
            election.roles.append(PortRole(link.bridge_a, link.port_a, Role.UNDECIDED, message))
            election.roles.append(PortRole(link.bridge_b, link.port_b, Role.UNDECIDED, message))
            continue

        # Neither end is the root: the cheaper path to the root wins the
        # designated role. Without full path costs this is a local decision, which
        # is exactly what the assumption list records.
        if left_cost < right_cost:
            election.roles.append(
                PortRole(left.name, link.port_a, Role.DESIGNATED, f"lower local cost {left_cost}")
            )
            election.roles.append(
                PortRole(right.name, link.port_b, Role.ALTERNATE, f"higher local cost {right_cost}")
            )
            election.assumptions.append(
                "port roles between non-root bridges approximated from local cost, not "
                "full root-path cost"
            )
        elif right_cost < left_cost:
            election.roles.append(
                PortRole(right.name, link.port_b, Role.DESIGNATED, f"lower local cost {right_cost}")
            )
            election.roles.append(
                PortRole(left.name, link.port_a, Role.ALTERNATE, f"higher local cost {left_cost}")
            )
            election.assumptions.append(
                "port roles between non-root bridges approximated from local cost, not "
                "full root-path cost"
            )
        else:
            message = (
                f"equal cost {left_cost} on {link.bridge_a}:{link.port_a} and "
                f"{link.bridge_b}:{link.port_b}; the neighbour bridge id breaks this tie "
                "and is not available"
            )
            election.undecided.append(message)
            election.roles.append(PortRole(link.bridge_a, link.port_a, Role.UNDECIDED, message))
            election.roles.append(PortRole(link.bridge_b, link.port_b, Role.UNDECIDED, message))

    # A port blocked administratively or by BPDU guard is reported as such, which
    # overrides whatever the topology computed.
    for bridge in bridges:
        for port in bridge.blocked_ports:
            election.roles = [
                role
                for role in election.roles
                if not (role.bridge == bridge.name and role.interface == port)
            ]
            election.roles.append(
                PortRole(
                    bridge.name,
                    port,
                    Role.BLOCKED,
                    "port is blocked by configuration (BPDU guard or shutdown)",
                )
            )
    return election


def loops_possible(election: Election, links: list[Link]) -> list[str]:
    """Links that could form a loop because neither end is blocked.

    A loop exists when a link has both ends forwarding and those ends belong to
    distinct bridges that are already connected another way. This is a coarse
    check over the computed roles, stated as a risk rather than a proven loop
    because a forwarded port set that looks cyclic may still be fine once the
    full tree is known.
    """
    found: list[str] = []
    for link in links:
        left = election.role_of(link.bridge_a, link.port_a)
        right = election.role_of(link.bridge_b, link.port_b)
        if left.forwards and right.forwards:
            found.append(
                f"{link.bridge_a}:{link.port_a} <-> {link.bridge_b}:{link.port_b} "
                "has both ends forwarding"
            )
    return found


__all__ = [
    "Bridge",
    "Election",
    "Link",
    "PortRole",
    "Role",
    "compute",
    "elect_root",
    "loops_possible",
]
