"""Deep Analyze: escalate genuinely testable gaps to a live simulator.

Quick Analyze answers everything the configuration can answer. Deep Analyze picks
up the remainder — the facts that only exist when traffic actually flows — and
runs the smallest experiment that settles each one.

The rules that keep this honest:

* **Lazy.** A hardware model, a stored hostname or an interface address is
  answered statically. Starting Packet Tracer for those would waste a minute and
  prove nothing. Escalation happens only for behaviour.
* **Bounded.** A fixed experiment budget, a per-experiment timeout and one
  session. Deep Analyze never becomes an open-ended search.
* **Observations stay observations.** A PDU result is tagged with its session and
  provenance and never enters the three-engine consensus.
* **Absent simulator is not success.** If no runtime is available, the report
  says exactly which checks did not run and why. Nothing is invented.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path

from ..models import NetworkModel


class RuntimeStatus(enum.StrEnum):
    """Why an operational check did or did not run."""

    #: A live simulator ran the experiment.
    OBSERVED = "OBSERVED"
    #: No simulator is configured or available.
    UNAVAILABLE = "UNAVAILABLE"
    #: The experiment ran but established nothing.
    INCONCLUSIVE = "INCONCLUSIVE"
    #: The backend cannot perform this operation.
    UNSUPPORTED = "UNSUPPORTED"
    #: The experiment itself failed.
    FAILED = "FAILED"
    #: Not attempted: the budget was spent.
    NOT_ATTEMPTED = "NOT_ATTEMPTED"


@dataclass
class OperationalCheck:
    """One runtime experiment and what it established."""

    name: str
    source: str
    destination: str
    status: RuntimeStatus
    detail: str = ""
    frames: int = 0
    simulator_version: str = ""
    session_id: str = ""
    decisions: list[str] = field(default_factory=list)

    @property
    def observed(self) -> bool:
        return self.status is RuntimeStatus.OBSERVED

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "source": self.source,
            "destination": self.destination,
            "status": self.status.value,
            "detail": self.detail,
            "frames": self.frames,
            "simulator_version": self.simulator_version,
            "session_id": self.session_id,
            "decisions": list(self.decisions),
            "observed": self.observed,
        }


@dataclass
class DeepResult:
    """The outcome of a Deep Analyze escalation."""

    available: bool
    reason: str
    checks: list[OperationalCheck] = field(default_factory=list)
    simulator_version: str = ""
    session_id: str = ""
    source_intact: bool = True

    def as_dict(self) -> dict:
        return {
            "available": self.available,
            "reason": self.reason,
            "checks": [check.as_dict() for check in self.checks],
            "simulator_version": self.simulator_version,
            "session_id": self.session_id,
            "source_intact": self.source_intact,
            "observed_count": sum(1 for c in self.checks if c.observed),
        }


#: Interface names that never carry user traffic and must not be tested.
_SKIP_INTERFACE_MARKERS = ("vlan", "loopback", "null", "tunnel", "power distribution")


def candidate_pairs(model: NetworkModel, limit: int = 4) -> list[tuple[str, str]]:
    """Pick source/destination device pairs worth a connectivity experiment.

    Only routed devices are chosen, and only pairs that are physically separate.
    Testing a device against itself proves nothing, and testing a host whose
    address Packet Tracer assigns at runtime is unreliable.
    """
    routed = [
        device.name
        for device in model.devices.values()
        if _has_routed_interface(model, device.name)
    ]
    pairs: list[tuple[str, str]] = []
    for index, source in enumerate(routed):
        for destination in routed[index + 1 :]:
            if source == destination:
                continue
            pairs.append((source, destination))
            if len(pairs) >= limit:
                return pairs
    return pairs


def _has_routed_interface(model: NetworkModel, device: str) -> bool:
    for interface in model.interfaces.values():
        if interface.device != device:
            continue
        if not interface.ipv4_address or interface.prefix_length is None:
            continue
        if any(marker in interface.name.lower() for marker in _SKIP_INTERFACE_MARKERS):
            continue
        return True
    return False


def run_deep(
    model: NetworkModel,
    lab_path: str | Path,
    *,
    max_experiments: int = 3,
    timeout_seconds: float = 30.0,
    runtime=None,
) -> DeepResult:
    """Run targeted experiments for a network, honestly reporting what happened.

    ``runtime`` may be injected for testing. When it is ``None``, a live simulator
    is used only if one is actually available; otherwise the result says so.
    """
    if runtime is None:
        from ..simulator import SimulatorRuntime

        runtime = SimulatorRuntime(prefer_live=True)

    available = runtime.is_available()
    reason = runtime.availability_reason()
    if not available:
        return DeepResult(
            available=False,
            reason=reason,
            checks=[
                OperationalCheck(
                    name="connectivity",
                    source=pair[0],
                    destination=pair[1],
                    status=RuntimeStatus.UNAVAILABLE,
                    detail=reason,
                )
                for pair in candidate_pairs(model)
            ],
        )

    pairs = candidate_pairs(model, limit=max_experiments)
    if not pairs:
        return DeepResult(
            available=True,
            reason="no two routed devices exist to test against each other",
            checks=[],
        )

    checks: list[OperationalCheck] = []
    session = None
    version = ""
    session_id = ""
    source_intact = True
    try:
        session = runtime.create_session(lab_path)
        version = session.backend.version
        session_id = session.session_id
        for index, (source, destination) in enumerate(pairs):
            if index >= max_experiments:
                checks.append(
                    OperationalCheck(
                        name="connectivity",
                        source=source,
                        destination=destination,
                        status=RuntimeStatus.NOT_ATTEMPTED,
                        detail=f"experiment budget of {max_experiments} spent",
                    )
                )
                continue
            try:
                result = session.send_pdu(
                    source, destination, timeout_seconds=timeout_seconds
                )
            except Exception as exc:  # noqa: BLE001 - reported, not hidden
                checks.append(
                    OperationalCheck(
                        name="connectivity",
                        source=source,
                        destination=destination,
                        status=RuntimeStatus.FAILED,
                        detail=f"{type(exc).__name__}: {exc}",
                        simulator_version=version,
                        session_id=session_id,
                    )
                )
                continue

            checks.append(
                OperationalCheck(
                    name="connectivity",
                    source=source,
                    destination=destination,
                    status=_status_for(result.status.value),
                    detail=f"{result.status.value}: {len(result.raw)} bytes of raw evidence",
                    frames=result.frames_seen,
                    simulator_version=result.provenance.simulator_version,
                    session_id=result.provenance.session_id,
                    decisions=list(result.decisions[:4]),
                )
            )
    finally:
        if session is not None:
            status = session.close()
            source_intact = "source=INTACT" in status

    return DeepResult(
        available=True,
        reason="operational experiments completed",
        checks=checks,
        simulator_version=version,
        session_id=session_id,
        source_intact=source_intact,
    )


def _status_for(pdu_status: str) -> RuntimeStatus:
    if pdu_status == "DELIVERED":
        return RuntimeStatus.OBSERVED
    if pdu_status in {"DROPPED", "TIMED_OUT"}:
        return RuntimeStatus.OBSERVED
    if pdu_status == "UNSUPPORTED":
        return RuntimeStatus.UNSUPPORTED
    if pdu_status == "EXECUTION_ERROR":
        return RuntimeStatus.FAILED
    return RuntimeStatus.INCONCLUSIVE


__all__ = [
    "DeepResult",
    "OperationalCheck",
    "RuntimeStatus",
    "candidate_pairs",
    "run_deep",
]
