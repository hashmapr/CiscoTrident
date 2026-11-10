"""Formal network invariants: declarative policy checks with counterexamples.

A statement like "every student VLAN must reach DNS" is not a question about one
fact; it is a claim about *all* traffic in that class. This module evaluates such
claims against the canonical model and the forwarding engine, and answers one of
four things:

* ``PROVEN`` — holds for every case the model can enumerate.
* ``VIOLATED`` — does not hold, with a concrete counterexample naming the device,
  interface and the configuration line responsible.
* ``INCONCLUSIVE`` — the model cannot decide; the reason is stated.
* ``UNSUPPORTED`` — the claim needs a feature the model does not represent.

The rule that keeps "proven" honest: **a proof is only as strong as the model
behind it.** When an invariant depends on behaviour the model does not represent,
it is ``UNSUPPORTED`` rather than proven. Nothing here consults a live simulator,
and nothing is upgraded to a stronger status because a check happens to pass.

No SMT solver is used. The problems that matter here — reachability over a
routable topology, address uniqueness, gateway validity — are decidable by
enumeration over a graph of tens of nodes, and a solver would add a dependency
without adding correctness. That is a deliberate choice, recorded so it is not
mistaken for an oversight.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from ..models import NetworkModel
from .path import DeepCore, Step


class Result(enum.StrEnum):
    """The outcome of evaluating one invariant."""

    PROVEN = "PROVEN"
    VIOLATED = "VIOLATED"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass
class Counterexample:
    """A concrete case that breaks the invariant."""

    device: str
    interface: str | None
    description: str
    evidence: str
    path: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "device": self.device,
            "interface": self.interface,
            "description": self.description,
            "evidence": self.evidence,
            "path": list(self.path),
        }


@dataclass
class Verdict:
    """The result of one invariant, with everything behind it."""

    name: str
    rule: str
    result: Result
    detail: str = ""
    counterexamples: list[Counterexample] = field(default_factory=list)
    checked: int = 0
    assumptions: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "rule": self.rule,
            "result": self.result.value,
            "detail": self.detail,
            "checked": self.checked,
            "counterexamples": [c.as_dict() for c in self.counterexamples],
            "assumptions": list(self.assumptions),
            "limitations": list(self.limitations),
        }


class Invariant:
    """Base class for one declarative claim."""

    name = "invariant"
    rule = ""

    def evaluate(self, model: NetworkModel, core: DeepCore) -> Verdict:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Concrete invariants
# ---------------------------------------------------------------------------


class UniqueAddresses(Invariant):
    """No two interfaces may hold the same IPv4 address."""

    name = "unique-addresses"
    rule = "No two interfaces claim the same IPv4 address."

    def evaluate(self, model: NetworkModel, core: DeepCore) -> Verdict:
        owners: dict[str, list[tuple[str, str]]] = {}
        for interface in model.interfaces.values():
            if interface.ipv4_address:
                owners.setdefault(interface.ipv4_address, []).append(
                    (interface.device, interface.name)
                )
        duplicates = {addr: who for addr, who in owners.items() if len(who) > 1}
        if not duplicates:
            return Verdict(
                name=self.name,
                rule=self.rule,
                result=Result.PROVEN,
                detail=f"{len(owners)} distinct addresses, all unique",
                checked=len(owners),
            )
        return Verdict(
            name=self.name,
            rule=self.rule,
            result=Result.VIOLATED,
            detail=f"{len(duplicates)} address(es) claimed more than once",
            checked=len(owners),
            counterexamples=[
                Counterexample(
                    device=who[0][0],
                    interface=who[0][1],
                    description=f"{address} is claimed by {len(who)} interfaces",
                    evidence="; ".join(f"{d}:{i}" for d, i in who),
                )
                for address, who in sorted(duplicates.items())
            ],
        )


class GatewaysOnAServedSubnet(Invariant):
    """Every configured default gateway must be an address the network holds."""

    name = "gateways-exist"
    rule = "Every configured default gateway belongs to an interface on the network."

    def evaluate(self, model: NetworkModel, core: DeepCore) -> Verdict:
        gateways = model.settings.default_gateways
        if not gateways:
            return Verdict(
                name=self.name,
                rule=self.rule,
                result=Result.PROVEN,
                detail="no default gateways are configured",
                checked=0,
            )

        violations: list[Counterexample] = []
        held = 0
        for device, gateway in sorted(gateways.items()):
            owner = core.address_owner(gateway)
            if owner is None:
                violations.append(
                    Counterexample(
                        device=device,
                        interface=None,
                        description=f"gateway {gateway} is not assigned to any interface",
                        evidence=f"{device} default gateway {gateway}",
                    )
                )
            else:
                held += 1
        if violations:
            return Verdict(
                name=self.name,
                rule=self.rule,
                result=Result.VIOLATED,
                detail=f"{len(violations)} of {len(gateways)} gateways are unowned",
                checked=len(gateways),
                counterexamples=violations,
            )
        return Verdict(
            name=self.name,
            rule=self.rule,
            result=Result.PROVEN,
            detail=f"all {held} gateways are held by a real interface",
            checked=len(gateways),
        )


class Reachability(Invariant):
    """A named source must be able to reach a named destination.

    This is the invariant that needs the forwarding engine, so it is also the one
    whose proof is bounded by what the engine models.
    """

    name = "reachability"
    rule = "{source} reaches {destination}"

    def __init__(self, source: str, destination: str, protocol: str = "icmp") -> None:
        self.source = source
        self.destination = destination
        self.protocol = protocol

    def evaluate(self, model: NetworkModel, core: DeepCore) -> Verdict:
        prediction = core.predict_path(self.source, self.destination, self.protocol)
        rule = self.rule.format(source=self.source, destination=self.destination)

        if not prediction.definite:
            return Verdict(
                name=f"reach-{self.source}-{self.destination}",
                rule=rule,
                result=Result.INCONCLUSIVE,
                detail="the forwarding engine could not decide this path",
                checked=1,
                limitations=list(prediction.limitations),
            )

        if prediction.delivered:
            return Verdict(
                name=f"reach-{self.source}-{self.destination}",
                rule=rule,
                result=Result.PROVEN,
                detail="forwarding predicts delivery",
                checked=1,
                assumptions=[
                    "Layer 2 forwarding between adjacent ports works",
                    "addresses are as parsed from the configuration",
                ],
            )

        drop = next(
            (step for step in prediction.steps if step.action is Step.DROP), None
        )
        return Verdict(
            name=f"reach-{self.source}-{self.destination}",
            rule=rule,
            result=Result.VIOLATED,
            detail=prediction.failure_point or "traffic does not reach the destination",
            checked=1,
            counterexamples=[
                Counterexample(
                    device=drop.device if drop else prediction.source,
                    interface=drop.interface if drop else None,
                    description=drop.detail if drop else "no forwarding path",
                    evidence=drop.evidence if drop else "",
                    path=[step.as_dict() for step in prediction.steps],
                )
            ],
        )


class Isolation(Invariant):
    """One device must NOT be able to reach another.

    The mirror of reachability, and the one that matters for segmentation: guest
    traffic must not reach management.
    """

    name = "isolation"
    rule = "{source} cannot reach {destination}"

    def __init__(self, source: str, destination: str, protocol: str = "icmp") -> None:
        self.source = source
        self.destination = destination
        self.protocol = protocol

    def evaluate(self, model: NetworkModel, core: DeepCore) -> Verdict:
        prediction = core.predict_path(self.source, self.destination, self.protocol)
        rule = self.rule.format(source=self.source, destination=self.destination)

        if not prediction.definite:
            return Verdict(
                name=f"isolate-{self.source}-{self.destination}",
                rule=rule,
                result=Result.INCONCLUSIVE,
                detail="the forwarding engine could not decide this path",
                checked=1,
                limitations=list(prediction.limitations),
            )

        if prediction.delivered:
            return Verdict(
                name=f"isolate-{self.source}-{self.destination}",
                rule=rule,
                result=Result.VIOLATED,
                detail=f"traffic from {self.source} reaches {self.destination}",
                checked=1,
                counterexamples=[
                    Counterexample(
                        device=self.source,
                        interface=None,
                        description=(
                            f"{self.source} can reach {self.destination}, which the "
                            "isolation rule forbids"
                        ),
                        evidence="forwarding predicts delivery",
                        path=[step.as_dict() for step in prediction.steps],
                    )
                ],
            )
        return Verdict(
            name=f"isolate-{self.source}-{self.destination}",
            rule=rule,
            result=Result.PROVEN,
            detail="forwarding predicts the path is blocked",
            checked=1,
            assumptions=[
                "the blocking configuration is as parsed",
                "no ACL or NAT rule outside the model permits the traffic",
            ],
            limitations=["an ACL the parser could not bind is not considered"],
        )


class AllAddressedInterfacesUp(Invariant):
    """Every interface that holds an address should be administratively up."""

    name = "addressed-interfaces-up"
    rule = "Every addressed physical interface is administratively up."

    def evaluate(self, model: NetworkModel, core: DeepCore) -> Verdict:
        offenders: list[Counterexample] = []
        checked = 0
        for interface in model.interfaces.values():
            if not interface.ipv4_address:
                continue
            if interface.name.lower().startswith(("vlan", "loopback")):
                continue
            checked += 1
            state = (interface.admin_state or "").lower()
            if state in {"administratively down", "down"}:
                offenders.append(
                    Counterexample(
                        device=interface.device,
                        interface=interface.name,
                        description=f"{interface.name} holds an address but is shut",
                        evidence=f"admin_state={interface.admin_state}",
                    )
                )
        if offenders:
            return Verdict(
                name=self.name,
                rule=self.rule,
                result=Result.VIOLATED,
                detail=f"{len(offenders)} of {checked} addressed interfaces are down",
                checked=checked,
                counterexamples=offenders,
            )
        return Verdict(
            name=self.name,
            rule=self.rule,
            result=Result.PROVEN,
            detail=f"all {checked} addressed interfaces are up",
            checked=checked,
        )


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate(
    model: NetworkModel,
    invariants: list[Invariant] | None = None,
    *,
    core: DeepCore | None = None,
) -> list[Verdict]:
    """Evaluate every invariant. Defaults to the ones that need no parameters."""
    engine = core or DeepCore(model)
    selected = invariants if invariants is not None else default_invariants()
    return [invariant.evaluate(model, engine) for invariant in selected]


def default_invariants() -> list[Invariant]:
    """The invariants that apply to any network without user parameters."""
    return [
        UniqueAddresses(),
        GatewaysOnAServedSubnet(),
        AllAddressedInterfacesUp(),
    ]


def reachability_invariants(model: NetworkModel) -> list[Invariant]:
    """Reachability claims derived from the topology, for a quick sweep.

    Only device pairs that share a subnet or a routed path are proposed; this is
    not an exhaustive matrix, because a proof over unrelated pairs adds noise
    without adding information.
    """
    core = DeepCore(model)
    routed = [
        device.name
        for device in model.devices.values()
        if core.routed_interfaces(device.name)
    ]
    return [
        Reachability(routed[index], routed[index + 1])
        for index in range(min(len(routed) - 1, 6))
    ]


def summary(verdicts: list[Verdict]) -> dict:
    counts = {result.value: 0 for result in Result}
    for verdict in verdicts:
        counts[verdict.result.value] += 1
    return {
        "total": len(verdicts),
        "counts": counts,
        "violated": [
            verdict.as_dict() for verdict in verdicts if verdict.result is Result.VIOLATED
        ],
    }


__all__ = [
    "AllAddressedInterfacesUp",
    "Counterexample",
    "GatewaysOnAServedSubnet",
    "Invariant",
    "Isolation",
    "Reachability",
    "Result",
    "UniqueAddresses",
    "Verdict",
    "default_invariants",
    "evaluate",
    "reachability_invariants",
    "summary",
]
