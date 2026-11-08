"""Bridge simulator observations into the existing evidence and model layers.

Phase 3.3. The rule this module exists to enforce: a simulator observation is a
*new category* of evidence, never a fourth extraction family. It cannot make an
answer ``VERIFIED``, and it cannot overwrite a static fact.

Two outputs:

* :func:`to_cli_record` turns a raw ``OperationResult`` into the Phase 2
  :class:`~trident.evidence.types.CliRecord`, so the existing parsers and
  detectors consume simulator output with no new parsing code and no schema
  drift. A record read from a runtime command is classified ``RUNTIME_STATE`` by
  the Phase 2 layer itself, which is exactly what it is.
* :func:`merge_observations` folds simulator observations into a
  ``NetworkModel`` copy as ``Observation`` values carrying simulator
  provenance, and records any disagreement with the static facts instead of
  resolving it.

The provenance on a simulator observation always names the backend, so a
``SCRIPTED`` result can be filtered out before it reaches a report.
"""

from __future__ import annotations

from ..evidence.api import parse_cli_output
from ..evidence.bundle import EvidenceBundle
from ..models import NetworkModel, Observation, Provenance
from .contracts import BackendKind, OperationResult
from .contracts import ObservationKind as SimObservationKind

#: Maps commands onto the Phase 2 artefact kinds. The Phase 2 detector works out
#: the kind itself; this table is for callers that need to ask "which artefact
#: would settle this question" before running anything.
_COMMAND_KINDS: tuple[tuple[str, str], ...] = (
    ("show ip interface brief", "IP_INTERFACE_BRIEF"),
    ("show ip route", "IP_ROUTE"),
    ("show vlan brief", "VLAN_BRIEF"),
    ("show interfaces trunk", "INTERFACES_TRUNK"),
    ("show spanning-tree", "SPANNING_TREE"),
    ("show etherchannel summary", "ETHERCHANNEL_SUMMARY"),
    ("show access-lists", "ACCESS_LISTS"),
    ("show ip ospf neighbor", "OSPF_NEIGHBOR"),
    ("show running-config", "RUNNING_CONFIG"),
)


def classify_command(command: str) -> str:
    """Best-match Phase 2 artefact name for a CLI command, or ``"UNKNOWN"``."""
    text = " ".join(command.split()).lower()
    for prefix, kind in _COMMAND_KINDS:
        if text.startswith(prefix):
            return kind
    return "UNKNOWN"


def to_cli_record(result: OperationResult):
    """Convert a simulator CLI result into a Phase 2 ``CliRecord``.

    Returns ``None`` when there is nothing honest to hand over: a failed
    operation, or one that produced no text.
    """
    if not result.ok or result.kind is not SimObservationKind.CLI_OUTPUT:
        return None
    if not result.raw.strip():
        return None
    return parse_cli_output(
        result.raw,
        device=result.device,
        captured_at=result.provenance.executed_at,
    )


def to_bundle(results: list[OperationResult]) -> EvidenceBundle:
    """Build an ``EvidenceBundle`` from a batch of simulator CLI results."""
    bundle = EvidenceBundle()
    for result in results:
        record = to_cli_record(result)
        if record is not None:
            bundle.add(record)
    return bundle


def _detail(result: OperationResult) -> str:
    if result.kind is SimObservationKind.REACHABILITY_SUCCEEDED:
        return (
            f"{result.operation}: connectivity observed for this path under these "
            "conditions (does not prove other services or paths)"
        )
    if result.kind is SimObservationKind.REACHABILITY_FAILED:
        percent = 0
        if isinstance(result.parsed, dict):
            percent = int(result.parsed.get("success_percent", 0))
        return (
            f"{result.operation}: connectivity FAILED ({percent}% success). "
            "A failed test does not by itself name a cause."
        )
    return f"{result.operation}: raw CLI output captured"


def observation_of(result: OperationResult) -> Observation:
    """A model-level ``Observation`` describing what was actually established."""
    backend = result.provenance.backend.value
    liveness = "live" if result.is_live else "not-live"
    return Observation(
        field=result.operation,
        entity_type="device",
        entity_id=result.device or "unknown",
        value=_detail(result),
        raw_evidence=result.raw,
        provenance=Provenance(
            engine=f"simulator:{backend}",
            extraction_path=f"simulator-{liveness}",
            source_path=str(result.provenance.working_copy_sha256),
            snapshot=f"session:{result.provenance.session_id}",
            extraction_family="operational-cli",
            interpretation_family="simulator-observation",
            crypto_shared=False,
            validation=[
                f"backend={backend}",
                f"observed={result.observed}",
            ],
        ),
    )


def merge_observations(model: NetworkModel, results: list[OperationResult]) -> NetworkModel:
    """Return a copy of ``model`` with simulator observations appended.

    Static facts are never rewritten. Contradictions are surfaced as warnings so
    a reader sees both sides, which is the conflict policy the directive
    requires.
    """
    merged = model.model_copy(deep=True)
    for result in results:
        if not result.ok:
            continue
        merged.observations.append(observation_of(result))
        disagreement = _disagreement(model, result)
        if disagreement:
            merged.warnings.append(disagreement)
    return merged


def _disagreement(model: NetworkModel, result: OperationResult) -> str | None:
    """Describe a static/operational contradiction, or ``None``."""
    if result.kind is not SimObservationKind.CLI_OUTPUT or not result.device:
        return None
    if classify_command(result.operation) != "IP_INTERFACE_BRIEF":
        return None
    record = to_cli_record(result)
    if record is None or not isinstance(record.parsed, dict):
        return None
    for name, row in record.parsed.items():
        if not isinstance(row, dict):
            continue
        if str(row.get("status", "")).lower() != "up":
            continue
        for interface in model.interfaces.values():
            if interface.device != result.device or interface.name != name:
                continue
            configured = (interface.admin_state or "").lower()
            if configured in {"administratively down", "down"}:
                return (
                    f"CONFLICT: {result.device}:{name} is '{configured}' in the source "
                    f"file but reports 'up' at runtime ({result.provenance.backend.value} "
                    f"session {result.provenance.session_id}); both observations preserved"
                )
    return None


class EvidenceLedger:
    """Collects simulator results with their provenance.

    Used by the investigation layer so the same fact is not re-tested for every
    question, and so a cached value can be invalidated when the session changes.
    """

    def __init__(self) -> None:
        self._entries: list[OperationResult] = []
        self._index: dict[tuple[str, str, str], OperationResult] = {}

    def remember(self, result: OperationResult) -> None:
        self._entries.append(result)
        if result.ok:
            key = (result.provenance.session_id, result.device or "", result.operation)
            self._index[key] = result

    def recall(
        self, session_id: str, device: str, operation: str
    ) -> OperationResult | None:
        return self._index.get((session_id, device, operation))

    def results(self) -> tuple[OperationResult, ...]:
        return tuple(self._entries)

    def live_results(self) -> tuple[OperationResult, ...]:
        return tuple(r for r in self._entries if r.is_live)

    def counts(self) -> dict:
        total = len(self._entries)
        live = len(self.live_results())
        return {
            "total": total,
            "live": live,
            "not_live": total - live,
            "failed": len([r for r in self._entries if not r.ok]),
        }

    def by_backend(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for result in self._entries:
            key = result.provenance.backend.value
            counts[key] = counts.get(key, 0) + 1
        return counts


def operational_evidence_tier(results: list[OperationResult]) -> str:
    """A single label for how strong the operational evidence is.

    ``SIMULATOR_OBSERVED`` is returned only when every contributing result came
    from a live simulator. Otherwise the weaker label is returned, so a report
    can never imply live testing it did not perform.
    """
    if not results:
        return "NO_OPERATIONAL_EVIDENCE"
    if all(r.is_live for r in results):
        return "SIMULATOR_OBSERVED"
    if any(r.provenance.backend is BackendKind.SCRIPTED for r in results):
        return "SCRIPTED_NOT_OBSERVED"
    return "PARTIAL_OPERATIONAL_EVIDENCE"


__all__ = [
    "EvidenceLedger",
    "classify_command",
    "merge_observations",
    "observation_of",
    "operational_evidence_tier",
    "to_bundle",
    "to_cli_record",
]
