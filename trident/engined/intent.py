"""The intent model: explicit statements about what the network must do.

Intent is an *input*, never inferred. That single decision is what separates
Engine D from the detector that reported five faults on a healthy network.

The temptation when writing a verifier is to derive requirements from the
topology — "there are two subnets, so they should probably talk". That is not
intent; it is a guess, and it is wrong for any segmented network by design
(guest Wi-Fi, a management VLAN, a PCI enclave). ``any_to_any`` exists because
some labs genuinely want full mesh, but it must be named in the caller's code so
that a reader can see the assumption being made.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field


class IntentError(ValueError):
    """An intent that cannot be evaluated against a model."""


@dataclass(frozen=True)
class Endpoint:
    """A device whose address we can resolve.

    ``address`` may be supplied to pin a specific interface; otherwise the model
    decides, which is what a student means by "PC-A".
    """

    device: str
    address: str | None = None

    def resolve(self, model) -> str:
        """The IPv4 address this endpoint refers to, per the model.

        Raises ``IntentError`` rather than returning None: an unresolvable
        endpoint makes every downstream verdict meaningless, and a silent None
        would turn a modelling error into an "unreachable" finding.
        """
        if self.address:
            return self.address
        interfaces = [
            i
            for i in getattr(model, "interfaces", {}).values()
            if i.device == self.device and getattr(i, "ipv4_address", None)
        ]
        if not interfaces:
            raise IntentError(
                f"endpoint {self.device!r} has no IPv4 address in the model"
            )
        # Prefer the first by interface name so the choice is deterministic.
        interfaces.sort(key=lambda i: i.name)
        return interfaces[0].ipv4_address

    def as_dict(self) -> dict:
        return {"device": self.device, "address": self.address}


@dataclass(frozen=True)
class Requirement:
    """One thing the network must be able to do."""

    src: Endpoint
    dst: Endpoint
    description: str = ""
    required: bool = True
    #: Restrict the check to ICMP (the usual CyberPatriot phrasing) or ``"ip"``.
    protocol: str = "icmp"
    #: A non-reachability assertion, e.g. ``"route"`` (a device must have a route
    #: to a prefix) or ``"interface_up"`` / ``"vlan_membership"``.
    assertion: str | None = None
    #: Assertion operand: a prefix, ``"device:interface"``, or ``"vlan:N"``.
    operand: str | None = None
    #: When true, the requirement is satisfied by *unreachability*.
    #:
    #: This is how a segmented network is described honestly: "PC-A1 must NOT
    #: reach PC-B1" is a real requirement, not the absence of one. Without this
    #: flag a verifier has only two options for such a pair — invent a
    #: reachability requirement (wrong) or ignore it (also wrong).
    must_not_reach: bool = False

    def as_dict(self) -> dict:
        return {
            "src": self.src.as_dict(),
            "dst": self.dst.as_dict(),
            "description": self.description,
            "required": self.required,
            "protocol": self.protocol,
            "must_not_reach": self.must_not_reach,
            "assertion": self.assertion,
            "operand": self.operand,
        }


@dataclass
class NetworkIntent:
    """What the network is supposed to do, stated explicitly.

    ``isolated_pairs`` are the inverse: endpoint pairs that MUST NOT reach each
    other. They are first-class because a verifier that only understands "must
    reach" will flag every correctly segmented network as broken.
    """

    requirements: list[Requirement] = field(default_factory=list)
    isolated_pairs: list[tuple[Endpoint, Endpoint]] = field(default_factory=list)
    name: str = ""

    @classmethod
    def any_to_any(cls, prefixes: list[str], protocol: str = "icmp") -> NetworkIntent:
        """Full-mesh intent across every endpoint in ``prefixes``.

        Explicitly named so a reader sees the assumption. It resolves endpoints
        lazily, at verification time, because the device list belongs to the
        model, not to the intent.
        """
        intent = cls(name="any-to-any")
        intent._any_to_any_prefixes = [str(p) for p in prefixes]  # type: ignore[attr-defined]
        intent._any_to_any_protocol = protocol  # type: ignore[attr-defined]
        return intent

    def expand(self, model) -> list[Requirement]:
        """Requirements for this intent, resolving ``any_to_any`` if used."""
        prefixes = getattr(self, "_any_to_any_prefixes", None)
        if not prefixes:
            return list(self.requirements)
        nets = [ipaddress.IPv4Network(p, strict=False) for p in prefixes]
        endpoints: list[Endpoint] = []
        for interface in getattr(model, "interfaces", {}).values():
            address = getattr(interface, "ipv4_address", None)
            prefix = getattr(interface, "prefix_length", None)
            if not address or prefix is None:
                continue
            try:
                iface_net = ipaddress.IPv4Network(f"{address}/{prefix}", strict=False)
            except ValueError:
                continue
            if any(iface_net.subnet_of(net) for net in nets):
                endpoints.append(Endpoint(interface.device))
        expanded: list[Requirement] = []
        for src in endpoints:
            for dst in endpoints:
                if src.device == dst.device:
                    continue
                expanded.append(
                    Requirement(
                        src=src,
                        dst=dst,
                        description=f"{src.device} -> {dst.device}",
                        protocol=getattr(self, "_any_to_any_protocol", "icmp"),
                    )
                )
        return expanded

    def validate(self, model) -> list[str]:
        """Structural problems, resolved against a concrete model."""
        problems: list[str] = []
        for requirement in self.expand(model):
            for endpoint in (requirement.src, requirement.dst):
                if endpoint.device not in getattr(model, "devices", {}):
                    problems.append(f"requirement names unknown device {endpoint.device!r}")
                    continue
                try:
                    endpoint.resolve(model)
                except IntentError as exc:
                    problems.append(str(exc))
        for left, right in self.isolated_pairs:
            for endpoint in (left, right):
                if endpoint.device not in getattr(model, "devices", {}):
                    problems.append(f"isolation names unknown device {endpoint.device!r}")
        return problems

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "requirements": [r.as_dict() for r in self.requirements],
            "isolated_pairs": [
                [left.as_dict(), right.as_dict()] for left, right in self.isolated_pairs
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> NetworkIntent:
        return cls(
            name=data.get("name", ""),
            requirements=[
                Requirement(
                    src=Endpoint(**r["src"]),
                    dst=Endpoint(**r["dst"]),
                    description=r.get("description", ""),
                    required=r.get("required", True),
                    protocol=r.get("protocol", "icmp"),
                    must_not_reach=r.get("must_not_reach", False),
                    assertion=r.get("assertion"),
                    operand=r.get("operand"),
                )
                for r in data.get("requirements", [])
            ],
            isolated_pairs=[
                (Endpoint(**pair[0]), Endpoint(**pair[1]))
                for pair in data.get("isolated_pairs", [])
            ],
        )
