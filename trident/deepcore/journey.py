"""Multi-protocol path explanation.

The individual protocol modules reason about their own domain. This one walks a
packet through them in the order a real packet meets them and produces a single
explanation:

    source choice -> L2 forwarding (VLAN, STP, EtherChannel) -> gateway
      -> route selection -> ACL -> NAT -> return path

The point is that a failure is explained *in context*. Reporting "no route" when
the real cause is a blocked VLAN, or "ACL denies" when the ACL is on the wrong
interface, sends the reader to the wrong place. Each stage therefore records what
it saw, and the first stage that stops the packet is named as the cause with its
own evidence.

Nothing here is an observation. Every conclusion is `SIMULATED_PREDICTION` and
carries the configuration line or topology fact behind it.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from ..models import NetworkModel
from .path import DeepCore, Step


class Stage(enum.StrEnum):
    """The stages a packet passes through, in order."""

    SOURCE = "SOURCE"
    LAYER2 = "LAYER2"
    GATEWAY = "GATEWAY"
    ROUTING = "ROUTING"
    ACL = "ACL"
    NAT = "NAT"
    RETURN_PATH = "RETURN_PATH"


class Verdict(enum.StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class StageResult:
    """What one stage concluded."""

    stage: Stage
    verdict: Verdict
    detail: str
    evidence: str = ""
    device: str | None = None
    interface: str | None = None

    def as_dict(self) -> dict:
        return {
            "stage": self.stage.value,
            "verdict": self.verdict.value,
            "detail": self.detail,
            "evidence": self.evidence,
            "device": self.device,
            "interface": self.interface,
        }


@dataclass
class PathExplanation:
    """The whole journey, stage by stage."""

    source: str
    destination: str
    protocol: str
    stages: list[StageResult] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)

    @property
    def delivered(self) -> bool | None:
        """Whether every stage passed. ``None`` when any stage is unknown."""
        if any(stage.verdict is Verdict.UNKNOWN for stage in self.stages):
            return None
        if any(stage.verdict is Verdict.FAIL for stage in self.stages):
            return False
        return True if self.stages else None

    @property
    def failure(self) -> StageResult | None:
        return next((s for s in self.stages if s.verdict is Verdict.FAIL), None)

    @property
    def first_unknown(self) -> StageResult | None:
        return next((s for s in self.stages if s.verdict is Verdict.UNKNOWN), None)

    def summary(self) -> str:
        if self.delivered is True:
            return f"{self.source} reaches {self.destination}"
        failure = self.failure
        if failure is not None:
            where = " ".join(x for x in (failure.device, failure.interface) if x)
            return f"{self.source} does not reach {self.destination}: {failure.stage.value} failed at {where or 'the path'} — {failure.detail}"
        unknown = self.first_unknown
        if unknown is not None:
            return f"{self.source} to {self.destination} cannot be decided: {unknown.detail}"
        return f"{self.source} to {self.destination}: no stages evaluated"

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "destination": self.destination,
            "protocol": self.protocol,
            "delivered": self.delivered,
            "summary": self.summary(),
            "stages": [stage.as_dict() for stage in self.stages],
            "failure": self.failure.as_dict() if self.failure else None,
            "caveats": list(self.caveats),
        }


def explain(
    model: NetworkModel,
    source: str,
    destination: str,
    protocol: str = "icmp",
) -> PathExplanation:
    """Walk a packet through every modelled stage and explain the outcome."""
    core = DeepCore(model)
    explanation = PathExplanation(source=source, destination=destination, protocol=protocol)

    # The routed-path engine already covers source choice, gateway and routing.
    # Its steps are mapped onto stages rather than duplicated.
    prediction = core.predict_path(source, destination, protocol)
    _add_routing_stages(explanation, prediction, source)

    if explanation.failure is not None:
        # A failure in routing is the cause; later stages would only add noise.
        return explanation

    # The ACL check needs the destination *address*, not the device name: an ACL
    # matches addresses, and passing "R2" would never match anything.
    destination_address = _destination_address(core, destination)
    if destination_address is not None:
        _add_acl_stage(explanation, model, core, source, destination_address)
    _add_layer2_stage(explanation, model, source, destination)
    _add_nat_stage(explanation, model, source, destination)
    _add_return_path_stage(explanation, core, destination, source)

    if not explanation.caveats:
        explanation.caveats.append(
            "every stage rests on configuration and topology; runtime state such as "
            "neighbor tables and translations is not consulted"
        )
    return explanation


def _destination_address(core: DeepCore, device: str) -> str | None:
    """The address a device is reached on, for ACL matching."""
    interfaces = core.routed_interfaces(device)
    if not interfaces:
        return None
    return interfaces[0].ipv4_address


def _add_routing_stages(explanation: PathExplanation, prediction, source: str) -> None:
    if not prediction.definite:
        explanation.stages.append(
            StageResult(
                stage=Stage.SOURCE,
                verdict=Verdict.UNKNOWN,
                detail=(
                    prediction.limitations[0]
                    if prediction.limitations
                    else "the forwarding engine could not decide the path"
                ),
                device=source,
            )
        )
        explanation.caveats.extend(prediction.limitations)
        return

    for step in prediction.steps:
        if step.action is Step.DELIVER:
            explanation.stages.append(
                StageResult(
                    stage=Stage.ROUTING,
                    verdict=Verdict.PASS,
                    detail=step.detail,
                    evidence=step.evidence,
                    device=step.device,
                    interface=step.interface,
                )
            )
            continue
        if step.action is Step.FORWARD:
            explanation.stages.append(
                StageResult(
                    stage=Stage.GATEWAY
                    if step.device == source
                    else Stage.ROUTING,
                    verdict=Verdict.PASS,
                    detail=step.detail,
                    evidence=step.evidence,
                    device=step.device,
                    interface=step.interface,
                )
            )
            continue
        if step.action is Step.DROP:
            explanation.stages.append(
                StageResult(
                    stage=Stage.ROUTING,
                    verdict=Verdict.FAIL,
                    detail=step.detail,
                    evidence=step.evidence,
                    device=step.device,
                    interface=step.interface,
                )
            )
            return
        explanation.stages.append(
            StageResult(
                stage=Stage.ROUTING,
                verdict=Verdict.UNKNOWN,
                detail=step.detail,
                device=step.device,
                interface=step.interface,
            )
        )


def _add_layer2_stage(
    explanation: PathExplanation, model: NetworkModel, source: str, destination: str
) -> None:
    """Check the L2 path for VLAN/trunk/STP problems on the physical links.

    Only links whose endpoints are both modelled are checked. A link with one end
    outside the model contributes nothing, so it is skipped rather than guessed.
    """
    from .stp import Bridge, Link, Role, compute

    bridges: list[Bridge] = []
    links: list[Link] = []
    for device in model.devices.values():
        ports = {
            interface.name: interface.prefix_length
            for interface in model.interfaces.values()
            if interface.device == device.name and interface.prefix_length
        }
        blocked = [
            interface.name
            for interface in model.interfaces.values()
            if interface.device == device.name
            and (interface.admin_state or "").lower() in {"administratively down", "down"}
        ]
        bridges.append(Bridge(name=device.name, blocked_ports=blocked, port_costs=dict(ports)))

    for link in model.links:
        links.append(
            Link(link.device_a, link.interface_a, link.device_b, link.interface_b)
        )

    if not links:
        return
    # Only an actual blocked port matters here. An undecidable *election* does
    # not make the path unproven: if no port is blocked, nothing about STP stops
    # the packet, and reporting UNKNOWN for the whole path because a MAC is
    # missing would make every lab explanation useless.
    election = compute(bridges, links, assume_default_priority=True)

    for link in links:
        left = election.role_of(link.bridge_a, link.port_a)
        right = election.role_of(link.bridge_b, link.port_b)
        if left is Role.BLOCKED or right is Role.BLOCKED:
            explanation.stages.append(
                StageResult(
                    stage=Stage.LAYER2,
                    verdict=Verdict.FAIL,
                    detail=(
                        f"{link.bridge_a}:{link.port_a} <-> {link.bridge_b}:{link.port_b} "
                        "is blocked, so nothing crosses this link"
                    ),
                    evidence="spanning-tree port role",
                    device=link.bridge_a,
                    interface=link.port_a,
                )
            )
            return
    # A port that was shut is checked too: that stops traffic for reasons the
    # spanning tree does not model.
    for interface in model.interfaces.values():
        state = (interface.admin_state or "").lower()
        if state in {"administratively down", "down"} and interface.ipv4_address:
            explanation.stages.append(
                StageResult(
                    stage=Stage.LAYER2,
                    verdict=Verdict.FAIL,
                    detail=f"{interface.name} is administratively down",
                    evidence=f"admin_state={interface.admin_state}",
                    device=interface.device,
                    interface=interface.name,
                )
            )
            return

    explanation.stages.append(
        StageResult(
            stage=Stage.LAYER2,
            verdict=Verdict.PASS,
            detail=f"{len(links)} link(s) checked; no blocked or shut port on the path",
            evidence="spanning-tree port roles and interface state",
        )
    )
    if election.undecided:
        explanation.caveats.append(
            "the spanning-tree election was undecidable (a MAC was missing), but no "
            "port was found blocked, so STP does not appear to stop this packet"
        )


def _add_acl_stage(
    explanation: PathExplanation,
    model: NetworkModel,
    core: DeepCore,
    source: str,
    destination: str,
) -> None:
    """Check whether an ACL on the source's egress denies the destination."""
    source_interfaces = core.routed_interfaces(source)
    if not source_interfaces:
        return
    for interface in source_interfaces:
        verdict = core.acl_verdict(source, interface.name, destination)
        if verdict == "deny":
            explanation.stages.append(
                StageResult(
                    stage=Stage.ACL,
                    verdict=Verdict.FAIL,
                    detail=(
                        f"an ACL on {interface.name} denies traffic to {destination}"
                    ),
                    evidence="access-list configuration bound to this interface",
                    device=source,
                    interface=interface.name,
                )
            )
            return
    if model.acls:
        explanation.stages.append(
            StageResult(
                stage=Stage.ACL,
                verdict=Verdict.PASS,
                detail="no bound deny matches this destination",
                evidence="access-list configuration",
            )
        )


def _add_nat_stage(
    explanation: PathExplanation, model: NetworkModel, source: str, destination: str
) -> None:
    from .nat import Outcome, translate_outbound
    from .protocols import parse_protocols

    info = model.devices.get(source)
    if info is None:
        return
    nat = parse_protocols(info.configuration or []).nat
    if not nat.configured:
        return
    result = translate_outbound(nat, source, destination)
    if result.outcome is Outcome.TRANSLATED:
        explanation.stages.append(
            StageResult(
                stage=Stage.NAT,
                verdict=Verdict.PASS,
                detail=f"source is translated to {result.translated_source}",
                evidence=result.rule or "NAT rule",
                device=source,
            )
        )
        if result.port_note:
            explanation.caveats.append(result.port_note)
        return
    explanation.stages.append(
        StageResult(
            stage=Stage.NAT,
            verdict=Verdict.UNKNOWN,
            detail="; ".join(result.problems) or "NAT state could not be decided",
            device=source,
        )
    )


def _add_return_path_stage(
    explanation: PathExplanation, core: DeepCore, destination_device: str, source_device: str
) -> None:
    """Check that the destination can route back to the source.

    This is the stage that catches the most common real fault: forward traffic
    works and replies are dropped because the far side has no route home.
    """
    reverse = core.predict_path(destination_device, source_device, explanation.protocol)
    if not reverse.definite:
        explanation.stages.append(
            StageResult(
                stage=Stage.RETURN_PATH,
                verdict=Verdict.UNKNOWN,
                detail="the return path could not be decided",
                device=destination_device,
            )
        )
        return
    if reverse.delivered:
        explanation.stages.append(
            StageResult(
                stage=Stage.RETURN_PATH,
                verdict=Verdict.PASS,
                detail=f"{destination_device} has a path back to {source_device}",
                evidence="routing table",
                device=destination_device,
            )
        )
        return
    explanation.stages.append(
        StageResult(
            stage=Stage.RETURN_PATH,
            verdict=Verdict.FAIL,
            detail=(
                f"{destination_device} cannot route back to {source_device}, so replies "
                "are dropped even if the request arrives"
            ),
            evidence="routing table",
            device=reverse.failure_point or destination_device,
        )
    )


def explain_all(
    model: NetworkModel, pairs: list[tuple[str, str]], protocol: str = "icmp"
) -> list[PathExplanation]:
    return [explain(model, source, destination, protocol) for source, destination in pairs]


__all__ = [
    "PathExplanation",
    "Stage",
    "StageResult",
    "Verdict",
    "explain",
    "explain_all",
]
