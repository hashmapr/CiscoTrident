"""Connect live simulator output to diagnostic hypotheses, honestly.

DeepCore predicts what a network *should* do from static configuration. This
module is the other half of the loop: it runs read-only diagnostics against a
real Packet Tracer session and turns what actually came back into evidence a
diagnostic engine can cite.

The rules that make that safe are encoded in types, not prose:

* :class:`EvidenceSource` distinguishes a raw **live simulator** observation
  from a **parser-derived** fact, from a **scripted** backend reply, and from
  **static analysis**. Nothing that was not observed on a live simulator can be
  labelled ``LIVE_SIMULATOR``.
* :class:`Conclusion` has exactly four values. ``VERIFIED`` and ``CONTRADICTED``
  require a live, completed command. A failure or timeout yields
  ``INCONCLUSIVE`` with the error attached — never a guess.
* Every evidence record keeps the raw simulator text and the backend's
  :class:`~trident.simulator.contracts.Provenance`, so a reviewer can check a
  parse against its source.
* :class:`LiveEvidenceSession` is a context manager. Commands are bounded per
  command and by an overall budget, and ``close`` always runs in ``finally``.
* The source ``.pkt`` is hashed on entry and again on exit. The working copy is
  what the simulator opens; the original must be byte-for-byte unchanged.

The command set is deliberately small and read-only: ``show ip interface
brief``, ``show running-config``, ``show vlan brief``, ``show interfaces
trunk``, ``show ip route`` and ``show interfaces status``. Any other command is
refused before it reaches the simulator.
"""

from __future__ import annotations

import enum
import ipaddress
import queue
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, Self, runtime_checkable

from ..diagnostics.types import Observation as DiagnosticObservation
from ..evidence.bundle import EvidenceBundle
from ..evidence.types import CliRecord, EvidenceKind, ParseStatus
from ..simulator.backends import is_read_only
from ..simulator.contracts import (
    BackendKind,
    OperationResult,
    Provenance,
    utcnow,
)
from ..simulator.evidence_bridge import to_cli_record
from ..simulator.isolation import sha256_file

# ---------------------------------------------------------------------------
# Source and conclusion vocabulary
# ---------------------------------------------------------------------------


class EvidenceSource(enum.StrEnum):
    """Where one piece of evidence came from. Never inferred from context.

    ``LIVE_SIMULATOR`` is the only value that means "a real Packet Tracer
    process answered this command". ``PARSER_DERIVED`` means the structured
    findings were parsed out of such an answer. ``STATIC_ANALYSIS`` is a fact
    read from the uploaded file or a model; it is never live.
    """

    #: Raw text produced by a live Packet Tracer backend (``observed=True``).
    LIVE_SIMULATOR = "LIVE_SIMULATOR"
    #: Structured rows parsed out of a live observation.
    PARSER_DERIVED = "PARSER_DERIVED"
    #: A backend answered, but it was the deterministic scripted peer.
    SCRIPTED_BACKEND = "SCRIPTED_BACKEND"
    #: Read from the source file or a model. Never executed.
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    #: The command did not complete: failure, timeout, refusal or no backend.
    UNAVAILABLE = "UNAVAILABLE"


class Conclusion(enum.StrEnum):
    """What a comparison between a prediction and a live observation concludes."""

    #: The live output states the predicted fact directly.
    VERIFIED = "VERIFIED"
    #: The fact follows from live output by a documented rule (set membership,
    #: boolean combination of observed fields), not from a literal line.
    DERIVED = "DERIVED"
    #: No usable live observation: the command failed, timed out, produced
    #: nothing parsable, or the evidence was not live.
    INCONCLUSIVE = "INCONCLUSIVE"
    #: The live output positively shows the predicted fact is false.
    CONTRADICTED = "CONTRADICTED"


class ExpectationKind(enum.StrEnum):
    """The kinds of prediction this module can check against a live command."""

    INTERFACE_UP = "interface_up"
    INTERFACE_STATUS = "interface_status"
    VLAN_EXISTS = "vlan_exists"
    VLAN_ALLOWED_ON_TRUNK = "vlan_allowed_on_trunk"
    ROUTE_EXISTS = "route_exists"
    CONFIG_CONTAINS = "config_contains"


#: The one command that can settle each expectation.
_COMMAND_FOR: dict[ExpectationKind, str] = {
    ExpectationKind.INTERFACE_UP: "show ip interface brief",
    ExpectationKind.INTERFACE_STATUS: "show interfaces status",
    ExpectationKind.VLAN_EXISTS: "show vlan brief",
    ExpectationKind.VLAN_ALLOWED_ON_TRUNK: "show interfaces trunk",
    ExpectationKind.ROUTE_EXISTS: "show ip route",
    ExpectationKind.CONFIG_CONTAINS: "show running-config",
}


# ---------------------------------------------------------------------------
# Live evidence record
# ---------------------------------------------------------------------------


def _source_for(result: OperationResult) -> EvidenceSource:
    """Classify an :class:`OperationResult` without ever overstating it."""
    if not result.ok:
        return EvidenceSource.UNAVAILABLE
    if result.observed and result.provenance.backend is BackendKind.SIMULATOR_LIVE:
        return EvidenceSource.LIVE_SIMULATOR
    if result.provenance.backend is BackendKind.SCRIPTED:
        return EvidenceSource.SCRIPTED_BACKEND
    # ok=True but observed=False from a live backend is an untrusted edge case.
    return EvidenceSource.UNAVAILABLE


@dataclass(frozen=True)
class LiveEvidence:
    """One command's outcome, with its raw text and its provenance."""

    command: str
    device: str
    raw: str
    ok: bool
    observed: bool
    source: EvidenceSource
    provenance: Provenance
    executed_at: str
    error: str | None = None
    #: The original result, kept so the existing evidence bridge can consume it.
    result: OperationResult | None = field(default=None, repr=False, compare=False)

    @classmethod
    def from_operation_result(cls, result: OperationResult) -> LiveEvidence:
        return cls(
            command=result.operation,
            device=result.device or "",
            raw=result.raw or "",
            ok=result.ok,
            observed=result.observed,
            source=_source_for(result),
            provenance=result.provenance,
            executed_at=result.provenance.executed_at,
            error=result.error,
            result=result,
        )

    @property
    def is_live(self) -> bool:
        """True only for a completed command answered by a live simulator."""
        return (
            self.source is EvidenceSource.LIVE_SIMULATOR
            and self.ok
            and self.observed
            and self.provenance.backend is BackendKind.SIMULATOR_LIVE
        )

    @property
    def liveness(self) -> str:
        return "LIVE" if self.is_live else "NOT_LIVE"

    def as_dict(self, *, full_raw: bool = False) -> dict:
        raw = self.raw if full_raw else self.raw[:400]
        return {
            "command": self.command,
            "device": self.device,
            "ok": self.ok,
            "observed": self.observed,
            "source": self.source.value,
            "liveness": self.liveness,
            "error": self.error,
            "executed_at": self.executed_at,
            "raw": raw,
            "raw_truncated": (not full_raw) and len(self.raw) > 400,
            "raw_lines": len(self.raw.splitlines()),
            "provenance": self.provenance.as_dict(),
        }


def static_observation(device: str | None, detail: str) -> DiagnosticObservation:
    """A :class:`DiagnosticObservation` explicitly labelled static analysis.

    Use this for facts read out of the uploaded file or a model. It can never be
    mistaken for a live result because its source is ``STATIC_ANALYSIS``.
    """
    return DiagnosticObservation(
        source=EvidenceSource.STATIC_ANALYSIS.value,
        device=device,
        detail=detail,
    )


# ---------------------------------------------------------------------------
# Collector output
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CollectorResult:
    """One collector's evidence plus its structured findings.

    ``record`` is the Phase 2 :class:`CliRecord` when the command has an
    :class:`EvidenceKind` in the ingestion layer. ``show interfaces status`` has
    no such kind, so it carries ``findings`` only and a note saying so.
    """

    evidence: LiveEvidence
    findings: dict | list | None
    record: CliRecord | None = None
    notes: tuple[str, ...] = ()

    @property
    def command(self) -> str:
        return self.evidence.command

    @property
    def device(self) -> str:
        return self.evidence.device

    @property
    def raw(self) -> str:
        return self.evidence.raw

    def add_to_bundle(self, bundle: EvidenceBundle) -> bool:
        """Add the parsed record to an ``EvidenceBundle``. False if there is none."""
        if self.record is None:
            return False
        bundle.add(self.record)
        return True

    def compare(self, expectation: Expectation) -> Comparison:
        return compare(expectation, self)

    def diagnostic_observations(self) -> tuple[DiagnosticObservation, ...]:
        """The evidence as diagnostic observations, labelled by source."""
        evidence = self.evidence
        device = evidence.device or None
        if evidence.ok:
            raw_detail = (
                f"{evidence.command} on {device or 'unknown device'} succeeded; "
                f"{len(evidence.raw.splitlines())} line(s) captured"
            )
        else:
            raw_detail = (
                f"{evidence.command} on {device or 'unknown device'} did not "
                f"complete: {evidence.error or 'unknown error'}"
            )
        observations = [
            DiagnosticObservation(
                source=evidence.source.value, device=device, detail=raw_detail
            )
        ]
        if evidence.ok and self.findings is not None:
            summary = _findings_summary(self.findings)
            note_text = f"; notes: {'; '.join(self.notes)}" if self.notes else ""
            observations.append(
                DiagnosticObservation(
                    source=EvidenceSource.PARSER_DERIVED.value,
                    device=device,
                    detail=f"{evidence.command}: parsed {summary}{note_text}",
                )
            )
        return tuple(observations)


def _findings_summary(findings: dict | list) -> str:
    if isinstance(findings, dict):
        keys = [str(key) for key in findings]
        head = ", ".join(keys[:8])
        more = "" if len(keys) <= 8 else f" (+{len(keys) - 8} more)"
        return f"{len(keys)} key(s): {head}{more}"
    return f"{len(findings)} row(s)"


# ---------------------------------------------------------------------------
# Expectations and comparisons
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Expectation:
    """A predicted fact to test against live output.

    ``predicted_by`` defaults to ``STATIC_ANALYSIS`` because an expectation is
    normally derived from the uploaded configuration. It is carried into the
    comparison so a reader can see that the *prediction* was not live.
    """

    kind: ExpectationKind
    device: str
    interface: str | None = None
    vlan_id: int | None = None
    status: str | None = None
    network: str | None = None
    prefix_length: int | None = None
    config_line: str | None = None
    description: str = ""
    predicted_by: str = EvidenceSource.STATIC_ANALYSIS.value

    def __post_init__(self) -> None:
        required: dict[ExpectationKind, tuple[str, ...]] = {
            ExpectationKind.INTERFACE_UP: ("interface",),
            ExpectationKind.INTERFACE_STATUS: ("interface", "status"),
            ExpectationKind.VLAN_EXISTS: ("vlan_id",),
            ExpectationKind.VLAN_ALLOWED_ON_TRUNK: ("interface", "vlan_id"),
            ExpectationKind.ROUTE_EXISTS: ("network",),
            ExpectationKind.CONFIG_CONTAINS: ("config_line",),
        }
        missing = [name for name in required[self.kind] if not getattr(self, name)]
        if missing:
            raise ValueError(f"{self.kind.value} requires {', '.join(missing)}")

    def as_dict(self) -> dict:
        return {
            "kind": self.kind.value,
            "device": self.device,
            "interface": self.interface,
            "vlan_id": self.vlan_id,
            "status": self.status,
            "network": self.network,
            "prefix_length": self.prefix_length,
            "config_line": self.config_line,
            "description": self.description,
            "predicted_by": self.predicted_by,
        }


@dataclass(frozen=True)
class Comparison:
    """A conclusion plus the live evidence that supports or refutes it."""

    expectation: Expectation
    conclusion: Conclusion
    detail: str
    evidence: tuple[LiveEvidence, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    observed: str | None = None

    @property
    def is_conclusive(self) -> bool:
        return self.conclusion in {
            Conclusion.VERIFIED,
            Conclusion.DERIVED,
            Conclusion.CONTRADICTED,
        }

    def evidence_observations(self) -> tuple[DiagnosticObservation, ...]:
        return tuple(
            DiagnosticObservation(
                source=item.source.value,
                device=item.device or None,
                detail=f"{item.command}: {self.detail}",
            )
            for item in self.evidence
        )

    def supporting_observations(self) -> tuple[DiagnosticObservation, ...]:
        if self.conclusion in {Conclusion.VERIFIED, Conclusion.DERIVED}:
            return self.evidence_observations()
        return ()

    def contradicting_observations(self) -> tuple[DiagnosticObservation, ...]:
        if self.conclusion is Conclusion.CONTRADICTED:
            return self.evidence_observations()
        return ()

    def as_dict(self) -> dict:
        return {
            "expectation": self.expectation.as_dict(),
            "prediction_source": self.expectation.predicted_by,
            "conclusion": self.conclusion.value,
            "detail": self.detail,
            "observed": self.observed,
            "missing_evidence": list(self.missing_evidence),
            "evidence": [item.as_dict() for item in self.evidence],
        }


def _normalise_command(command: str) -> str:
    return " ".join(command.split()).lower()


def _inconclusive(
    expectation: Expectation,
    observation: CollectorResult,
    detail: str,
    *,
    missing: Sequence[str] = (),
) -> Comparison:
    return Comparison(
        expectation=expectation,
        conclusion=Conclusion.INCONCLUSIVE,
        detail=detail,
        evidence=(observation.evidence,),
        missing_evidence=tuple(missing) or (detail,),
    )


def _concluded(
    expectation: Expectation,
    observation: CollectorResult,
    conclusion: Conclusion,
    detail: str,
    observed: str,
) -> Comparison:
    return Comparison(
        expectation=expectation,
        conclusion=conclusion,
        detail=detail,
        evidence=(observation.evidence,),
        observed=observed,
    )


def _row_for(rows: object, interface: str | None) -> dict | None:
    if interface is None or not isinstance(rows, dict):
        return None
    if interface in rows and isinstance(rows[interface], dict):
        return rows[interface]
    lowered = interface.lower()
    for key, value in rows.items():
        if str(key).lower() == lowered and isinstance(value, dict):
            return value
    return None


def _normalise_line(text: str) -> str:
    return " ".join(text.split())


def _mask_or_prefix_matches(value: object, prefix_length: int) -> bool:
    if value is None:
        return True
    text = str(value).strip()
    if not text:
        return True
    if text.isdigit():
        return int(text) == prefix_length
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{text}").prefixlen == prefix_length
    except ValueError:
        return False


def _route_matches(route: object, expectation: Expectation) -> bool:
    if not isinstance(route, dict):
        return False
    if str(route.get("network", "")) != expectation.network:
        return False
    if expectation.prefix_length is None:
        return True
    return _mask_or_prefix_matches(route.get("mask_or_prefix"), expectation.prefix_length)


def _route_table_present(raw: str) -> bool:
    lowered = raw.lower()
    return (
        "gateway of last resort" in lowered
        or ("codes:" in lowered and "c - connected" in lowered)
        or "routing entry" in lowered
    )


def _eval_interface_up(
    expectation: Expectation, observation: CollectorResult
) -> Comparison:
    rows = observation.findings
    if not isinstance(rows, dict) or not rows:
        return _inconclusive(
            expectation, observation, "show ip interface brief produced no interface rows"
        )
    row = _row_for(rows, expectation.interface)
    if row is None:
        return _inconclusive(
            expectation,
            observation,
            f"interface {expectation.interface!r} is not listed in show ip interface brief",
            missing=(f"a row for {expectation.interface} in show ip interface brief",),
        )
    status = str(row.get("status", "")).strip().lower()
    protocol = str(row.get("protocol", "")).strip().lower()
    observed = (
        f"{expectation.interface}: status={status or 'unknown'}, "
        f"protocol={protocol or 'unknown'}"
    )
    if status == "up" and protocol == "up":
        return _concluded(
            expectation, observation, Conclusion.VERIFIED, f"interface is up ({observed})", observed
        )
    if status in {"down", "administratively down"} or protocol == "down":
        return _concluded(
            expectation,
            observation,
            Conclusion.CONTRADICTED,
            f"interface is not up ({observed})",
            observed,
        )
    return _inconclusive(
        expectation,
        observation,
        f"interface state is neither clearly up nor down ({observed})",
        missing=("a definite interface state",),
    )


def _eval_interface_status(
    expectation: Expectation, observation: CollectorResult
) -> Comparison:
    rows = observation.findings
    if not isinstance(rows, dict) or not rows:
        return _inconclusive(
            expectation, observation, "show interfaces status produced no interface rows"
        )
    row = _row_for(rows, expectation.interface)
    if row is None:
        return _inconclusive(
            expectation,
            observation,
            f"interface {expectation.interface!r} is not listed in show interfaces status",
            missing=(f"a row for {expectation.interface} in show interfaces status",),
        )
    status = str(row.get("status", "")).strip().lower()
    wanted = str(expectation.status or "").strip().lower()
    observed = f"{expectation.interface}: status={status or 'unknown'}"
    if status == wanted:
        return _concluded(
            expectation,
            observation,
            Conclusion.VERIFIED,
            f"interface status is {status!r} as predicted ({observed})",
            observed,
        )
    return _concluded(
        expectation,
        observation,
        Conclusion.CONTRADICTED,
        f"interface status is {status!r}, predicted {wanted!r} ({observed})",
        observed,
    )


def _eval_vlan_exists(expectation: Expectation, observation: CollectorResult) -> Comparison:
    rows = observation.findings
    if not isinstance(rows, dict) or not rows:
        return _inconclusive(
            expectation,
            observation,
            "show vlan brief produced no VLAN rows; absence cannot be concluded",
        )
    key = str(expectation.vlan_id)
    if key in rows:
        info = rows[key]
        name = info.get("name") if isinstance(info, dict) else None
        observed = f"VLAN {key} present" + (f" (name={name})" if name else "")
        return _concluded(
            expectation,
            observation,
            Conclusion.VERIFIED,
            f"VLAN {key} is present in show vlan brief ({observed})",
            observed,
        )
    observed = (
        f"VLAN {key} absent from a parsed table of {len(rows)} VLAN(s): "
        f"{', '.join(sorted(rows, key=lambda value: int(value) if str(value).isdigit() else 0)[:12])}"
    )
    return _concluded(
        expectation,
        observation,
        Conclusion.CONTRADICTED,
        f"VLAN {key} is absent from a non-empty show vlan brief table ({observed})",
        observed,
    )


def _eval_vlan_allowed_on_trunk(
    expectation: Expectation, observation: CollectorResult
) -> Comparison:
    rows = observation.findings
    if not isinstance(rows, dict) or not rows:
        return _inconclusive(
            expectation, observation, "show interfaces trunk produced no trunk rows"
        )
    row = _row_for(rows, expectation.interface)
    if row is None:
        return _inconclusive(
            expectation,
            observation,
            f"interface {expectation.interface!r} is not listed as a trunk",
            missing=(f"a trunk row for {expectation.interface}",),
        )
    allowed = row.get("allowed_vlans")
    if not isinstance(allowed, list) or not allowed:
        return _inconclusive(
            expectation,
            observation,
            f"allowed VLAN list for {expectation.interface} is empty or unparsed; "
            "membership cannot be decided",
            missing=(f"a parsable allowed-VLAN list for {expectation.interface}",),
        )
    allowed_ids = sorted({str(value) for value in allowed}, key=lambda value: int(value) if value.isdigit() else 0)
    key = str(expectation.vlan_id)
    observed = f"{expectation.interface} allowed VLANs: {', '.join(allowed_ids[:20])}"
    if key in allowed_ids:
        return _concluded(
            expectation,
            observation,
            Conclusion.DERIVED,
            f"VLAN {key} is in the observed allowed-VLAN list ({observed})",
            observed,
        )
    return _concluded(
        expectation,
        observation,
        Conclusion.CONTRADICTED,
        f"VLAN {key} is absent from the observed allowed-VLAN list ({observed})",
        observed,
    )


def _eval_route_exists(expectation: Expectation, observation: CollectorResult) -> Comparison:
    routes = observation.findings
    if not isinstance(routes, list):
        return _inconclusive(
            expectation, observation, "show ip route produced no route list"
        )
    matched = [route for route in routes if _route_matches(route, expectation)]
    target = expectation.network or "the requested network"
    observed = f"{len(routes)} parsed route row(s)"
    if matched:
        first = matched[0]
        return _concluded(
            expectation,
            observation,
            Conclusion.VERIFIED,
            f"a route to {target} is present ({observed}): {first}",
            observed,
        )
    if routes:
        return _concluded(
            expectation,
            observation,
            Conclusion.CONTRADICTED,
            f"no route to {target} among {observed}",
            observed,
        )
    if _route_table_present(observation.raw):
        return _concluded(
            expectation,
            observation,
            Conclusion.CONTRADICTED,
            f"the routing table was printed but contains no route to {target}",
            "routing table present, no matching route",
        )
    return _inconclusive(
        expectation,
        observation,
        "show ip route produced no parsable routing table; absence cannot be concluded",
    )


def _eval_config_contains(
    expectation: Expectation, observation: CollectorResult
) -> Comparison:
    findings = observation.findings
    if not isinstance(findings, dict):
        return _inconclusive(
            expectation, observation, "show running-config produced no structured findings"
        )
    lines = findings.get("lines")
    if not isinstance(lines, list) or not lines:
        return _inconclusive(
            expectation, observation, "show running-config contained no configuration lines"
        )
    needle = _normalise_line(str(expectation.config_line))
    for line in lines:
        if _normalise_line(str(line)) == needle:
            return _concluded(
                expectation,
                observation,
                Conclusion.VERIFIED,
                f"configuration line present: {line!r}",
                f"{len(lines)} configuration line(s), match found",
            )
    return _concluded(
        expectation,
        observation,
        Conclusion.CONTRADICTED,
        f"configuration line {expectation.config_line!r} is absent from "
        f"{len(lines)} parsed line(s)",
        f"{len(lines)} configuration line(s), no match",
    )


_EVALUATORS: dict[ExpectationKind, Callable[[Expectation, CollectorResult], Comparison]] = {
    ExpectationKind.INTERFACE_UP: _eval_interface_up,
    ExpectationKind.INTERFACE_STATUS: _eval_interface_status,
    ExpectationKind.VLAN_EXISTS: _eval_vlan_exists,
    ExpectationKind.VLAN_ALLOWED_ON_TRUNK: _eval_vlan_allowed_on_trunk,
    ExpectationKind.ROUTE_EXISTS: _eval_route_exists,
    ExpectationKind.CONFIG_CONTAINS: _eval_config_contains,
}


def compare(expectation: Expectation, observation: CollectorResult) -> Comparison:
    """Compare one prediction with one live observation.

    The evidence must be a *live simulator* observation. A scripted reply, a
    failed command, a timeout, or output that was not parsed yields
    ``INCONCLUSIVE`` with the reason attached. It is never promoted to
    ``VERIFIED`` because it happens to match.
    """
    evidence = observation.evidence
    if not evidence.ok:
        return _inconclusive(
            expectation,
            observation,
            f"the live command did not complete: {evidence.error or 'unknown error'}",
            missing=(evidence.error or "a completed command",),
        )
    if evidence.source is not EvidenceSource.LIVE_SIMULATOR:
        return _inconclusive(
            expectation,
            observation,
            f"evidence source is {evidence.source.value}, not a live simulator observation",
            missing=(f"a LIVE_SIMULATOR observation from {_COMMAND_FOR[expectation.kind]!r}",),
        )
    if observation.findings is None:
        return _inconclusive(
            expectation,
            observation,
            "no structured findings were parsed from the live output",
        )
    expected_command = _COMMAND_FOR[expectation.kind]
    if _normalise_command(observation.command) != expected_command:
        return _inconclusive(
            expectation,
            observation,
            f"{expectation.kind.value} needs {expected_command!r}, but the observation is "
            f"{observation.command!r}",
            missing=(expected_command,),
        )
    return _EVALUATORS[expectation.kind](expectation, observation)


def compare_many(
    expectations: Sequence[Expectation], observations: Sequence[CollectorResult]
) -> tuple[Comparison, ...]:
    """Compare expectations against a batch, matching each to its command.

    An expectation whose command was not collected yields ``INCONCLUSIVE``; it
    is never silently dropped.
    """
    by_command: dict[str, CollectorResult] = {}
    for observation in observations:
        by_command.setdefault(_normalise_command(observation.command), observation)
    results: list[Comparison] = []
    for expectation in expectations:
        observation = by_command.get(_COMMAND_FOR[expectation.kind])
        if observation is None:
            results.append(
                Comparison(
                    expectation=expectation,
                    conclusion=Conclusion.INCONCLUSIVE,
                    detail=(
                        f"{_COMMAND_FOR[expectation.kind]!r} was not collected, so "
                        f"{expectation.kind.value} cannot be decided"
                    ),
                    missing_evidence=(f"output of {_COMMAND_FOR[expectation.kind]!r}",),
                )
            )
            continue
        results.append(compare(expectation, observation))
    return tuple(results)


# ---------------------------------------------------------------------------
# show interfaces status parser
# ---------------------------------------------------------------------------

#: IOS status words this parser accepts. Anything else is not coerced.
_INTERFACE_STATUS_WORDS = frozenset(
    {"connected", "notconnect", "disabled", "err-disabled", "inactive", "monitoring"}
)


def parse_interfaces_status(text: str) -> tuple[dict[str, dict], list[str]]:
    """Parse ``show interfaces status`` into ``{port: {status, vlan, ...}}``.

    Columns are read from the right (Type, Speed, Duplex, Vlan, Status), which
    keeps a names containing spaces from shifting the parse. A row whose status
    word is not a known IOS status is skipped with a note rather than guessed.
    """
    rows: dict[str, dict] = {}
    notes: list[str] = []
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        lowered = stripped.lower()
        if lowered.startswith("port") and "status" in lowered and "vlan" in lowered:
            continue
        if set(stripped) <= {"-", " ", "+"}:
            continue
        parts = stripped.split()
        if len(parts) < 6:
            notes.append(f"skipped malformed interface-status line: {stripped!r}")
            continue
        port = parts[0]
        status = parts[-5]
        if status.lower() not in _INTERFACE_STATUS_WORDS:
            notes.append(f"skipped interface-status line with unknown status: {stripped!r}")
            continue
        rows[port] = {
            "name": " ".join(parts[1:-5]),
            "status": status,
            "vlan": parts[-4],
            "duplex": parts[-3],
            "speed": parts[-2],
            "type": parts[-1],
        }
    return rows, notes


# ---------------------------------------------------------------------------
# Bounded execution and the context manager
# ---------------------------------------------------------------------------


@runtime_checkable
class CliBackend(Protocol):
    """The small backend surface this module needs."""

    kind: BackendKind
    version: str

    def run_cli(self, device: str, command: str, timeout: float) -> OperationResult: ...

    def close(self) -> str: ...


@dataclass(frozen=True)
class EvidenceBudget:
    """Hard ceilings for one evidence session. Ceilings, never targets."""

    command_timeout_s: float = 30.0
    overall_budget_s: float = 180.0
    max_commands: int = 40


def _call_bounded(fn: Callable[[], OperationResult], timeout: float) -> OperationResult:
    """Run ``fn`` in a daemon thread and stop waiting after ``timeout``.

    ``LiveBackend.run_cli`` currently ignores its ``timeout`` argument (the PTMP
    client hard-codes 60 s for ``enterCommand``), so the bound has to be enforced
    here as well. A timed-out command poisons the session: its state is unknown,
    and the only safe next step is to close it.
    """
    box: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

    def target() -> None:
        try:
            box.put((True, fn()))
        except BaseException as exc:  # noqa: BLE001 - re-raised in the caller
            box.put((False, exc))

    thread = threading.Thread(target=target, name="trident-live-evidence", daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise TimeoutError(f"command did not return within {timeout:.1f}s")
    try:
        ok, value = box.get_nowait()
    except queue.Empty:  # pragma: no cover - thread always puts exactly once
        raise TimeoutError("command ended without producing a result") from None
    if not ok:
        raise value  # type: ignore[misc]
    return value  # type: ignore[return-value]


class LiveEvidenceSession:
    """A bounded, self-cleaning window onto one live simulator backend.

    Use it as a context manager::

        with LiveEvidenceSession(backend, lab_path) as live:
            result = live.collect_vlan_brief("SW-DIST")

    Entering hashes the source file. Exiting closes the backend in ``finally``
    and hashes the source again. The source is never written to; the simulator
    only ever opens the runtime's disposable working copy.
    """

    def __init__(
        self,
        backend: CliBackend,
        source_path: str | Path,
        *,
        close: Callable[[], str] | None = None,
        budget: EvidenceBudget | None = None,
        session_id: str = "",
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._backend = backend
        self.source_path = Path(source_path)
        self._close = close
        self.budget = budget or EvidenceBudget()
        self.session_id = session_id or str(getattr(backend, "session_id", "") or "")
        self._clock = clock
        self._source_sha_before: str | None = None
        self._source_sha_after: str | None = None
        self._started = 0.0
        self._commands = 0
        self._poisoned = False
        self._entered = False
        self._closed_status = "NOT_CLOSED"
        self._notes: list[str] = []

    # -- lifecycle ---------------------------------------------------------

    def __enter__(self) -> Self:
        if self._entered:
            raise RuntimeError("LiveEvidenceSession is already entered")
        self._entered = True
        self._started = self._clock()
        self._source_sha_before = sha256_file(self.source_path)
        return self

    def __exit__(self, *_exc: object) -> bool:
        self.close()
        return False

    def close(self) -> str:
        """Close the backend, then prove the source did not change. Idempotent."""
        if self._closed_status != "NOT_CLOSED":
            return self._closed_status
        backend_status = "NOT_STARTED"
        try:
            if self._close is not None:
                backend_status = str(self._close())
            else:
                closer = getattr(self._backend, "close", None)
                backend_status = str(closer()) if closer is not None else "NOOP"
        except Exception as exc:  # noqa: BLE001 - cleanup must not mask the cause
            backend_status = f"CLOSE_FAILED: {exc}"
            self._notes.append(f"backend close failed: {exc}")
        try:
            self._source_sha_after = sha256_file(self.source_path)
        except OSError as exc:
            self._notes.append(f"could not re-hash the source: {exc}")
        intact = self.source_intact
        if intact is False:
            self._notes.append(
                "SOURCE CHANGED during the session; the working-copy promise was violated"
            )
        source_label = "INTACT" if intact else ("MODIFIED" if intact is False else "UNVERIFIED")
        self._closed_status = f"close={backend_status}/source={source_label}"
        return self._closed_status

    # -- introspection -----------------------------------------------------

    @property
    def source_sha256_before(self) -> str | None:
        return self._source_sha_before

    @property
    def source_sha256_after(self) -> str | None:
        return self._source_sha_after

    @property
    def source_intact(self) -> bool | None:
        """True when the source hash is unchanged, False when changed, None unknown."""
        if self._source_sha_before is None or self._source_sha_after is None:
            return None
        return self._source_sha_after == self._source_sha_before

    @property
    def cleanup_status(self) -> str:
        return self._closed_status

    @property
    def notes(self) -> tuple[str, ...]:
        return tuple(self._notes)

    @property
    def commands_run(self) -> int:
        return self._commands

    # -- execution ---------------------------------------------------------

    def run(
        self, device: str, command: str, *, timeout: float | None = None
    ) -> LiveEvidence:
        """Run one bounded, read-only command and return its evidence."""
        if not self._entered:
            raise RuntimeError(
                "LiveEvidenceSession must be used as a context manager so cleanup "
                "cannot be forgotten"
            )
        if self._poisoned:
            return self._unavailable(
                device,
                command,
                "session is unusable after a timed-out command; close and reopen it",
            )
        if self._commands >= self.budget.max_commands:
            return self._unavailable(
                device,
                command,
                f"command budget exhausted ({self.budget.max_commands} commands)",
            )
        remaining = self.budget.overall_budget_s - (self._clock() - self._started)
        if remaining <= 0:
            return self._unavailable(
                device,
                command,
                f"overall time budget exhausted ({self.budget.overall_budget_s:.0f}s)",
            )
        if not is_read_only(command):
            return self._unavailable(
                device,
                command,
                f"{command!r} is not a read-only diagnostic; refusing to send it",
            )
        effective = (
            self.budget.command_timeout_s if timeout is None else min(timeout, self.budget.command_timeout_s)
        )
        effective = min(effective, remaining)
        if effective <= 0:
            return self._unavailable(device, command, "no time left in the overall budget")
        self._commands += 1
        try:
            result = _call_bounded(
                lambda: self._backend.run_cli(device, command, effective), effective
            )
        except TimeoutError as exc:
            self._poisoned = True
            return self._unavailable(
                device, command, f"command timed out after {effective:.1f}s: {exc}"
            )
        except Exception as exc:  # noqa: BLE001 - any backend failure is INCONCLUSIVE
            return self._unavailable(
                device, command, f"{type(exc).__name__}: {exc}"
            )
        if not isinstance(result, OperationResult):
            return self._unavailable(
                device,
                command,
                f"backend returned {type(result).__name__}, not OperationResult",
            )
        return LiveEvidence.from_operation_result(result)

    def _unavailable(self, device: str, command: str, error: str) -> LiveEvidence:
        provenance = Provenance(
            backend=self._backend_kind,
            simulator_version=str(getattr(self._backend, "version", "unknown")),
            session_id=self.session_id,
            source_sha256=self._source_sha_before or "",
            # The working copy hash is not known for a command that never ran;
            # leaving it empty is honest, and the caveat says why.
            working_copy_sha256="",
            device=device or None,
            interface=None,
            operation=command,
            executed_at=utcnow(),
            parsed_by="live-evidence",
            caveats=("the command did not complete; no observation was produced",),
        )
        return LiveEvidence(
            command=command,
            device=device or "",
            raw="",
            ok=False,
            observed=False,
            source=EvidenceSource.UNAVAILABLE,
            provenance=provenance,
            executed_at=provenance.executed_at,
            error=error,
        )

    @property
    def _backend_kind(self) -> BackendKind:
        kind = getattr(self._backend, "kind", BackendKind.UNAVAILABLE)
        return kind if isinstance(kind, BackendKind) else BackendKind.UNAVAILABLE

    # -- collectors --------------------------------------------------------

    def collect_ip_interface_brief(
        self, device: str, *, timeout: float | None = None
    ) -> CollectorResult:
        return self._collect(
            device, "show ip interface brief", EvidenceKind.IP_INTERFACE_BRIEF, timeout=timeout
        )

    def collect_running_config(
        self, device: str, *, timeout: float | None = None
    ) -> CollectorResult:
        return self._collect(
            device,
            "show running-config",
            EvidenceKind.RUNNING_CONFIG,
            timeout=timeout,
            caveats=(
                (
                    "show running-config reports the device's intended configuration; "
                    "it does not prove operational state"
                ),
            ),
        )

    def collect_vlan_brief(
        self, device: str, *, timeout: float | None = None
    ) -> CollectorResult:
        return self._collect(
            device, "show vlan brief", EvidenceKind.VLAN_BRIEF, timeout=timeout
        )

    def collect_interfaces_trunk(
        self, device: str, *, timeout: float | None = None
    ) -> CollectorResult:
        return self._collect(
            device, "show interfaces trunk", EvidenceKind.INTERFACES_TRUNK, timeout=timeout
        )

    def collect_ip_route(
        self, device: str, *, timeout: float | None = None
    ) -> CollectorResult:
        return self._collect(device, "show ip route", EvidenceKind.IP_ROUTE, timeout=timeout)

    def collect_interfaces_status(
        self, device: str, *, timeout: float | None = None
    ) -> CollectorResult:
        evidence = self.run(device, "show interfaces status", timeout=timeout)
        if not evidence.ok:
            return CollectorResult(evidence=evidence, findings=None)
        findings, notes = parse_interfaces_status(evidence.raw)
        if not findings:
            notes = [*notes, "no interface status rows were parsed"]
        notes = [
            *notes,
            (
                "show interfaces status has no EvidenceKind in the ingestion layer; "
                "no CliRecord is produced"
            ),
        ]
        return CollectorResult(
            evidence=evidence,
            findings=findings or None,
            record=None,
            notes=tuple(notes),
        )

    def collect_standard_set(
        self, device: str, *, timeout: float | None = None
    ) -> tuple[CollectorResult, ...]:
        """Collect all six artefacts in one pass. Each result is independent."""
        return (
            self.collect_ip_interface_brief(device, timeout=timeout),
            self.collect_running_config(device, timeout=timeout),
            self.collect_vlan_brief(device, timeout=timeout),
            self.collect_interfaces_trunk(device, timeout=timeout),
            self.collect_ip_route(device, timeout=timeout),
            self.collect_interfaces_status(device, timeout=timeout),
        )

    def _collect(
        self,
        device: str,
        command: str,
        expected_kind: EvidenceKind | None,
        *,
        timeout: float | None = None,
        caveats: tuple[str, ...] = (),
    ) -> CollectorResult:
        evidence = self.run(device, command, timeout=timeout)
        if not evidence.ok:
            return CollectorResult(evidence=evidence, findings=None, notes=caveats)
        if not evidence.raw.strip():
            return CollectorResult(
                evidence=evidence,
                findings=None,
                notes=(*caveats, "the command succeeded but returned no text"),
            )
        record = to_cli_record(evidence.result) if evidence.result is not None else None
        if record is None:
            return CollectorResult(
                evidence=evidence,
                findings=None,
                notes=(*caveats, "output could not be converted into a CliRecord"),
            )
        notes: list[str] = [*caveats, *record.notes]
        if expected_kind is not None and record.kind is not expected_kind:
            notes.append(
                f"output was detected as {record.kind.value}, not the expected "
                f"{expected_kind.value}; findings withheld"
            )
            return CollectorResult(
                evidence=evidence, findings=None, record=record, notes=tuple(notes)
            )
        if record.kind is EvidenceKind.UNKNOWN or record.status is ParseStatus.UNRECOGNISED:
            notes.append("output was not recognised as a Cisco IOS show artefact")
            return CollectorResult(
                evidence=evidence, findings=None, record=record, notes=tuple(notes)
            )
        return CollectorResult(
            evidence=evidence,
            findings=record.parsed,
            record=record,
            notes=tuple(notes),
        )


@contextmanager
def open_live_evidence(
    lab_path: str | Path,
    *,
    runtime: object | None = None,
    budget: EvidenceBudget | None = None,
    prefer_live: bool = True,
    session_id: str | None = None,
) -> Iterator[LiveEvidenceSession]:
    """Open a live evidence session over ``lab_path`` through ``SimulatorRuntime``.

    Session creation is deferred to ``__enter__`` and the runtime session is
    closed in a ``finally`` even if hashing or entering fails, so a caller cannot
    leak a Packet Tracer process by forgetting cleanup.
    """
    from ..simulator import SimulatorRuntime  # imported lazily: no PT at import time

    if runtime is None:
        runtime = SimulatorRuntime(prefer_live=prefer_live)
    session = runtime.create_session(lab_path, session_id=session_id)  # type: ignore[attr-defined]
    try:
        with LiveEvidenceSession(
            session.backend,
            Path(lab_path),
            close=session.close,
            budget=budget,
            session_id=session.session_id,
        ) as live:
            yield live
    finally:
        # LiveEvidenceSession closes too; Session.close is idempotent and this
        # covers a failure inside __enter__ before the context was established.
        session.close()


__all__ = [
    "CliBackend",
    "CollectorResult",
    "Comparison",
    "Conclusion",
    "EvidenceBudget",
    "EvidenceSource",
    "Expectation",
    "ExpectationKind",
    "LiveEvidence",
    "LiveEvidenceSession",
    "compare",
    "compare_many",
    "open_live_evidence",
    "parse_interfaces_status",
    "static_observation",
]
