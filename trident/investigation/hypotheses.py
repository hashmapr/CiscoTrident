"""Hypotheses and experiment selection.

A hypothesis is a candidate explanation with the evidence that supports or
contradicts it, the evidence still missing, and the cheapest experiment that
would discriminate it. Selection prefers the experiment that splits the
remaining hypotheses most evenly, which is the property that actually reduces
uncertainty; running many commands is not the same as gaining information.

Confidence here is a coarse label (``HIGH``/``MEDIUM``/``LOW``) sourced from the
diagnostics engine, never a fabricated percentage.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from ..diagnostics.types import Confidence, HypothesisStatus


class Mutation(enum.StrEnum):
    """What an experiment needs from the session."""

    READ_ONLY = "READ_ONLY"
    CONFIG_CHANGE = "CONFIG_CHANGE"


@dataclass(frozen=True)
class Experiment:
    """One candidate diagnostic, with what it would establish."""

    experiment_id: str
    objective: str
    command: str
    device: str
    interface: str | None = None
    tests_hypothesis: str = ""
    mutation: Mutation = Mutation.READ_ONLY
    expected_signal: str = ""
    success_criteria: str = ""
    cost: float = 1.0

    @property
    def is_safe(self) -> bool:
        return self.mutation is Mutation.READ_ONLY

    def as_dict(self) -> dict:
        return {
            "experiment_id": self.experiment_id,
            "objective": self.objective,
            "command": self.command,
            "device": self.device,
            "interface": self.interface,
            "tests_hypothesis": self.tests_hypothesis,
            "mutation": self.mutation.value,
            "expected_signal": self.expected_signal,
            "success_criteria": self.success_criteria,
            "cost": self.cost,
        }


@dataclass
class Hypothesis:
    """A candidate cause with mutable evidence, updated as experiments run."""

    hypothesis_id: str
    kind: str
    summary: str
    device: str | None
    interface: str | None
    status: HypothesisStatus = HypothesisStatus.SUSPECTED
    confidence: Confidence = Confidence.LOW
    supporting: list[str] = field(default_factory=list)
    contradicting: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    eliminated: bool = False
    experiments_run: int = 0
    #: Set only when an executed experiment produced the supporting evidence.
    operationally_supported: bool = False

    def add_support(self, evidence: str) -> None:
        self.supporting.append(evidence)

    def add_contradiction(self, evidence: str) -> None:
        self.contradicting.append(evidence)
        if self.contradicting:
            # Any contradiction stops a confirmed claim; the evidence is kept.
            self.status = HypothesisStatus.SUSPECTED
            self.confidence = Confidence.MEDIUM

    def eliminate(self, reason: str) -> None:
        self.contradicting.append(reason)
        self.status = HypothesisStatus.RULED_OUT
        self.confidence = Confidence.LOW
        self.eliminated = True

    def confirm(self) -> None:
        if not self.contradicting and self.supporting:
            self.status = HypothesisStatus.CONFIRMED_DEFECT
            self.confidence = Confidence.HIGH

    @property
    def plausible(self) -> bool:
        return not self.eliminated

    def as_dict(self) -> dict:
        return {
            "hypothesis_id": self.hypothesis_id,
            "kind": self.kind,
            "summary": self.summary,
            "device": self.device,
            "interface": self.interface,
            "status": self.status.value,
            "confidence": self.confidence.value,
            "supporting": list(self.supporting),
            "contradicting": list(self.contradicting),
            "missing": list(self.missing),
            "eliminated": self.eliminated,
            "experiments_run": self.experiments_run,
            "operationally_supported": self.operationally_supported,
        }


#: The commands that discriminate each defect class. Ordered from cheapest and
#: most specific to broadest, so the planner stops early when it can.
_DISCRIMINATORS: dict[str, tuple[Experiment, ...]] = {}


def _experiment(kind: str, index: int, **kwargs) -> Experiment:
    return Experiment(experiment_id=f"{kind.lower()}-{index}", tests_hypothesis=kind, **kwargs)


def register_discriminators() -> dict[str, tuple[Experiment, ...]]:
    """Build the discriminator table once."""
    if _DISCRIMINATORS:
        return _DISCRIMINATORS
    table = {
        "SHUTDOWN_INTERFACE": (
            _experiment(
                "SHUTDOWN_INTERFACE", 1,
                objective="Confirm interface administrative state",
                command="show ip interface brief",
                device="{device}",
                expected_signal="status column shows administratively down",
                success_criteria="status is 'administratively down'",
            ),
        ),
        "WRONG_VLAN": (
            _experiment(
                "WRONG_VLAN", 1,
                objective="Confirm the VLAN an access port is in",
                command="show vlan brief",
                device="{device}",
                interface="{interface}",
                expected_signal="the port appears under the wrong VLAN",
                success_criteria="port VLAN differs from the service VLAN",
            ),
        ),
        "TRUNK_MISMATCH": (
            _experiment(
                "TRUNK_MISMATCH", 1,
                objective="Compare allowed VLANs at both ends of the trunk",
                command="show interfaces trunk",
                device="{device}",
                interface="{interface}",
                expected_signal="allowed lists differ between peers",
                success_criteria="a VLAN is carried on one side only",
            ),
        ),
        "MISSING_STATIC_ROUTE": (
            _experiment(
                "MISSING_STATIC_ROUTE", 1,
                objective="Check the routing table for the missing destination",
                command="show ip route",
                device="{device}",
                expected_signal="no route matches the dependent subnet",
                success_criteria="no route and no default covering the subnet",
            ),
        ),
        "WRONG_GATEWAY": (
            _experiment(
                "WRONG_GATEWAY", 1,
                objective="Confirm no interface holds the configured gateway",
                command="show ip interface brief",
                device="{device}",
                expected_signal="no interface has the gateway address",
                success_criteria="gateway address absent from every interface",
            ),
        ),
        "ACL_BLOCK": (
            _experiment(
                "ACL_BLOCK", 1,
                objective="Read the active access lists",
                command="show access-lists",
                device="{device}",
                interface="{interface}",
                expected_signal="a deny entry covers the intended traffic",
                success_criteria="deny entry matches the tested path",
            ),
        ),
        "INVALID_MASK": (
            _experiment(
                "INVALID_MASK", 1,
                objective="Confirm the interface mask at runtime",
                command="show ip interface brief",
                device="{device}",
                interface="{interface}",
                expected_signal="mask is not a legal contiguous mask",
                success_criteria="address/mask unusable",
            ),
        ),
        "ROUTING_LOOP": (
            _experiment(
                "ROUTING_LOOP", 1,
                objective="Trace the path toward the looping destination",
                command="show ip route",
                device="{device}",
                expected_signal="next hop points back at itself",
                success_criteria="route resolves to a local address",
            ),
        ),
        "DHCP_MISCONFIGURATION": (
            _experiment(
                "DHCP_MISCONFIGURATION", 1,
                objective="Read the DHCP pool configuration",
                command="show running-config",
                device="{device}",
                expected_signal="default-router outside the pool network",
                success_criteria="gateway not in pool subnet",
            ),
        ),
        "DUPLICATE_IP": (
            _experiment(
                "DUPLICATE_IP", 1,
                objective="Compare interface addresses",
                command="show ip interface brief",
                device="{device}",
                expected_signal="two interfaces share an address",
                success_criteria="duplicate address found",
            ),
        ),
        "OVERLAPPING_SUBNET": (
            _experiment(
                "OVERLAPPING_SUBNET", 1,
                objective="Compare interface networks",
                command="show ip interface brief",
                device="{device}",
                expected_signal="two networks overlap",
                success_criteria="one subnet contained in another",
            ),
        ),
    }
    _DISCRIMINATORS.update(table)
    return _DISCRIMINATORS


def experiments_for(hypothesis: Hypothesis) -> list[Experiment]:
    """Candidate experiments for one hypothesis, cheapest first."""
    table = register_discriminators()
    candidates = table.get(hypothesis.kind, ())
    resolved: list[Experiment] = []
    for template in candidates:
        device = hypothesis.device or "unknown"
        interface = hypothesis.interface or ""
        resolved.append(
            Experiment(
                experiment_id=template.experiment_id,
                objective=template.objective,
                command=template.command,
                device=device,
                interface=template.interface.format(
                    device=device, interface=interface
                )
                if template.interface
                else None,
                tests_hypothesis=template.tests_hypothesis,
                mutation=template.mutation,
                expected_signal=template.expected_signal,
                success_criteria=template.success_criteria,
                cost=template.cost,
            )
        )
    return sorted(resolved, key=lambda e: e.cost)


def select_experiment(
    hypotheses: list[Hypothesis],
    *,
    already_run: set[str],
    allow_mutation: bool = False,
) -> Experiment | None:
    """Pick the experiment that best discriminates the remaining hypotheses.

    Preference order: read-only before mutating; an experiment that has not run
    before; then the lowest cost. Returns ``None`` when nothing useful remains,
    which is a legitimate outcome and the signal to stop.
    """
    candidates: list[Experiment] = []
    for hypothesis in hypotheses:
        if not hypothesis.plausible:
            continue
        for experiment in experiments_for(hypothesis):
            if experiment.experiment_id in already_run:
                continue
            if experiment.mutation is Mutation.CONFIG_CHANGE and not allow_mutation:
                continue
            candidates.append(experiment)
    if not candidates:
        return None
    # More hypotheses are discriminated by the command that covers several of
    # them, so score by how many candidates share the same command.
    coverage: dict[str, int] = {}
    for experiment in candidates:
        coverage[experiment.command] = coverage.get(experiment.command, 0) + 1
    return min(
        candidates,
        key=lambda e: (
            e.mutation is Mutation.CONFIG_CHANGE,
            -coverage[e.command],
            e.cost,
            e.experiment_id,
        ),
    )


__all__ = [
    "Experiment",
    "Hypothesis",
    "Mutation",
    "experiments_for",
    "register_discriminators",
    "select_experiment",
]
