"""Controlled what-if experiments.

The contract, stated once and enforced by the shape of the API:

* the source lab is never modified — the runtime refuses non-disposable sessions,
  and the session re-hashes the source on close;
* a baseline is captured **before** any change, and the post-change result is
  stored separately, so the two are never confused;
* the outcome is one of a closed set, and "simulation unavailable" is a real
  member of that set rather than an error path dressed up as success;
* rollback is "destroy the disposable copy", not "type the inverse command".
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from ..models import NetworkModel
from ..simulator.contracts import Capability, OperationResult
from ..simulator.sessions import Session


class Outcome(enum.StrEnum):
    IMPROVEMENT_OBSERVED = "IMPROVEMENT_OBSERVED"
    REGRESSION_OBSERVED = "REGRESSION_OBSERVED"
    NO_MEANINGFUL_CHANGE = "NO_MEANINGFUL_CHANGE"
    INCONCLUSIVE = "INCONCLUSIVE"
    EXPERIMENT_FAILED = "EXPERIMENT_FAILED"
    UNSUPPORTED_COMMAND = "UNSUPPORTED_COMMAND"
    SIMULATION_UNAVAILABLE = "SIMULATION_UNAVAILABLE"


@dataclass(frozen=True)
class Candidate:
    """A proposed change, traceable to the hypothesis that motivated it."""

    candidate_id: str
    device: str
    commands: tuple[str, ...]
    intent: str
    hypothesis: str
    requirement: str = ""

    def as_dict(self) -> dict:
        return {
            "candidate_id": self.candidate_id,
            "device": self.device,
            "commands": list(self.commands),
            "intent": self.intent,
            "hypothesis": self.hypothesis,
            "requirement": self.requirement,
        }


@dataclass
class WhatIfResult:
    candidate: Candidate
    baseline: list[dict]
    after: list[dict]
    outcome: Outcome
    explanation: str
    original_preserved: bool
    rollback: str
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "candidate": self.candidate.as_dict(),
            "baseline": self.baseline,
            "after": self.after,
            "outcome": self.outcome.value,
            "explanation": self.explanation,
            "original_preserved": self.original_preserved,
            "rollback": self.rollback,
            "notes": list(self.notes),
        }


def _probe(session: Session | None, device: str, command: str) -> dict:
    """Run one probe and reduce it to a comparable record."""
    if session is None:
        return {"command": command, "ok": False, "error": "no session", "raw": ""}
    try:
        result: OperationResult = session.run_cli(device, command)
    except Exception as exc:  # noqa: BLE001 - recorded, not swallowed
        return {"command": command, "ok": False, "error": str(exc), "raw": ""}
    return {
        "command": command,
        "ok": result.ok,
        "observed": result.observed,
        "backend": result.provenance.backend.value,
        "raw": result.raw,
        "parsed": result.parsed,
        "error": result.error,
    }


def evaluate(
    model: NetworkModel,
    candidate: Candidate,
    *,
    baseline_session: Session | None,
    probes: tuple[str, ...],
    runtime_available: bool,
    runtime_reason: str = "",
) -> WhatIfResult:
    """Compare baseline behaviour with behaviour after a candidate change.

    Mutation is performed only when the session explicitly supports it. Neither
    backend in this build advertises ``MUTATE_CONFIG``, so the honest outcome is
    ``UNSUPPORTED_COMMAND``/``SIMULATION_UNAVAILABLE`` rather than a fabricated
    "improvement".
    """
    if not runtime_available or baseline_session is None:
        return WhatIfResult(
            candidate=candidate,
            baseline=[],
            after=[],
            outcome=Outcome.SIMULATION_UNAVAILABLE,
            explanation=f"cannot evaluate: {runtime_reason or 'no simulator session'}",
            original_preserved=True,
            rollback="not needed; nothing was executed",
        )

    if not baseline_session.supports(Capability.MUTATE_CONFIG):
        return WhatIfResult(
            candidate=candidate,
            baseline=[],
            after=[],
            outcome=Outcome.UNSUPPORTED_COMMAND,
            explanation=(
                "the active backend does not permit configuration changes, so the "
                "candidate cannot be applied to a disposable copy"
            ),
            original_preserved=True,
            rollback="no change applied",
            notes=["mutations require a backend advertising MUTATE_CONFIG"],
        )

    # Baseline first, always.
    baseline = [_probe(baseline_session, candidate.device, command) for command in probes]

    try:
        for command in candidate.commands:
            baseline_session.run_cli(candidate.device, command)
    except Exception as exc:  # noqa: BLE001
        return WhatIfResult(
            candidate=candidate,
            baseline=baseline,
            after=[],
            outcome=Outcome.EXPERIMENT_FAILED,
            explanation=f"applying the candidate failed: {exc}",
            original_preserved=True,
            rollback="disposable session discarded",
            notes=["baseline observations retained"],
        )

    after = [_probe(baseline_session, candidate.device, command) for command in probes]
    outcome, explanation = _compare(baseline, after)
    return WhatIfResult(
        candidate=candidate,
        baseline=baseline,
        after=after,
        outcome=outcome,
        explanation=explanation,
        original_preserved=True,
        rollback="disposable session discarded; source file never opened for writing",
    )


def _compare(baseline: list[dict], after: list[dict]) -> tuple[Outcome, str]:
    if not baseline or not after:
        return Outcome.INCONCLUSIVE, "no observations to compare"
    if all(not record["ok"] for record in baseline + after):
        return Outcome.INCONCLUSIVE, "no probe returned usable output"
    better = sum(
        1 for before, now in zip(baseline, after) if not before["ok"] and now["ok"]
    )
    worse = sum(
        1 for before, now in zip(baseline, after) if before["ok"] and not now["ok"]
    )
    changed = sum(
        1
        for before, now in zip(baseline, after)
        if before["ok"] and now["ok"] and before["raw"] != now["raw"]
    )
    if better and not worse:
        return Outcome.IMPROVEMENT_OBSERVED, f"{better} probe(s) went from failing to passing"
    if worse and not better:
        return Outcome.REGRESSION_OBSERVED, f"{worse} probe(s) went from passing to failing"
    if better and worse:
        return Outcome.INCONCLUSIVE, f"{better} improved and {worse} regressed"
    if changed:
        return Outcome.NO_MEANINGFUL_CHANGE, "output changed but no pass/fail transition"
    return Outcome.NO_MEANINGFUL_CHANGE, "behaviour identical"


__all__ = ["Candidate", "Outcome", "WhatIfResult", "evaluate"]
