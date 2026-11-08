"""Core value types for the fault-injection practice laboratory.

The laboratory has two halves that must never touch at the point of grading:

* a **scenario model** - an ordinary ``NetworkModel`` that *contains* defects, and
* a **fault manifest** - the answer key describing what was injected.

A diagnostic engine under test is given ``Scenario.model`` only. The manifest
lives in ``Scenario.faults`` and is never copied into the model.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from ..models import NetworkModel


class FaultKind(enum.StrEnum):
    """The taxonomy of injectable defects.

    Every value names a *class* of misconfiguration, not a specific instance.
    Grading compares kinds, so a scenario must not contain two faults of the
    same kind.
    """

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


@dataclass(frozen=True)
class Fault:
    """One injected defect.

    ``device`` is the primary device that carries the defect. ``interface`` is
    ``None`` for device-level defects such as a wrong default gateway or a bad
    DHCP pool. ``description`` and ``expected_symptom`` are for the grader and
    for humans reading the answer key; neither is ever placed on the model.
    """

    fault_id: str
    kind: FaultKind
    device: str
    interface: str | None
    description: str
    expected_symptom: str


@dataclass(frozen=True)
class Scenario:
    """A faulty network plus its answer key.

    ``model`` is the only thing a solver may receive. ``faults`` is the manifest
    and must be held back by the caller performing the evaluation.
    """

    name: str
    model: NetworkModel
    faults: tuple[Fault, ...]
    single_fault: bool

    def __post_init__(self) -> None:
        if self.single_fault and len(self.faults) != 1:
            raise ValueError(
                f"scenario {self.name!r} is marked single_fault but carries "
                f"{len(self.faults)} faults"
            )
        if not self.single_fault and len(self.faults) < 2:
            raise ValueError(
                f"scenario {self.name!r} is marked multi-fault but carries "
                f"{len(self.faults)} fault(s)"
            )
        kinds = [fault.kind for fault in self.faults]
        if len(kinds) != len(set(kinds)):
            raise ValueError(
                f"scenario {self.name!r} repeats a fault kind; kind-level grading "
                "cannot distinguish the duplicates"
            )


@dataclass(frozen=True)
class Grade:
    """Kind-level score for one diagnostic report against one scenario.

    ``score = found / (found + missed + spurious)``. A scenario with no
    expected faults scores 0.0, never 1.0.
    """

    scenario: str
    found_kinds: tuple[FaultKind, ...]
    missed_kinds: tuple[FaultKind, ...]
    spurious_kinds: tuple[FaultKind, ...]
    exact_match: bool
    score: float
