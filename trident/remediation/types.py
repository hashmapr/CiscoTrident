"""Immutable result types for the IOS remediation generator.

A remediation plan is *advice*: an ordered list of Cisco IOS configuration
commands that a human (or a change-control process) may choose to apply. Nothing
in this package connects to a device, opens a socket, or executes a command.

``advisory_only`` therefore has no meaningful ``False`` state: constructing a
plan with anything other than ``True`` raises. That makes "this engine never
executes" a property of the type, not a promise in a docstring.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class Confidence(enum.StrEnum):
    """How much of the plan rests on recorded fact rather than assumption.

    * ``HIGH``   - the previously observed value is known in full, and the
      required value is unambiguous, so both the change and the rollback are
      exact.
    * ``MEDIUM`` - the change is exact but derived (e.g. a classful mask for a
      requirement that names only an address).
    * ``LOW``    - at least one input is unknown; the plan carries no rollback
      (see the rollback invariant in ``generator.py``).
    """

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class RemediationStep:
    """One ordered, reviewable action.

    ``commands`` are entered in configuration mode, in the given order. A step
    may carry no commands when the plan can only explain why no command is safe;
    that is always accompanied by ``Confidence.LOW``.
    """

    order: int
    commands: tuple[str, ...]
    rationale: str


@dataclass(frozen=True)
class RemediationPlan:
    """A complete, advisory remediation proposal for one compliance verdict."""

    device: str
    interface: str | None
    current_state: str
    required_state: str
    steps: tuple[RemediationStep, ...]
    verification_commands: tuple[str, ...]
    rollback_commands: tuple[str, ...]
    confidence: Confidence
    evidence: tuple[str, ...]
    advisory_only: bool = True

    def __post_init__(self) -> None:
        if self.advisory_only is not True:
            raise ValueError(
                "RemediationPlan is advisory only: advisory_only must always be True"
            )
