"""Bridge live Packet Tracer evidence into the diagnostic engine.

:mod:`trident.deepcore.live_evidence` knows how to *obtain* live evidence. This
module is the other end of the loop: it turns that evidence into an
:class:`~trident.evidence.bundle.EvidenceBundle` the existing detectors already
consume, and it upgrades or downgrades diagnostic hypotheses from real simulator
output.

The honesty rules are the same ones the rest of the engine uses, expressed as
code:

* Only evidence whose :attr:`LiveEvidence.is_live` is true is added to a runtime
  bundle or used to change a hypothesis. A scripted backend, a failed command,
  a timeout, or a static fact can never promote anything.
* ``CONFIRMED_DEFECT`` may be reached from ``INSUFFICIENT_EVIDENCE`` only when a
  *successful live command* supports the claim. Static evidence is never enough.
* A live ``CONTRADICTED`` comparison downgrades the hypothesis to
  :attr:`HypothesisStatus.RULED_OUT` - the existing vocabulary's refuted state -
  and the report names the live conclusion ``CONTRADICTED`` so the mapping is
  explicit rather than hidden.
* A hypothesis with no matching live check is left byte-for-byte unchanged.
* :meth:`LiveDiagnosisReport.as_dict` strips any instructor/answer-key key. A
  report is evidence for a student, never a leak of the grading manifest.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from typing import Any

from ..diagnostics import rank
from ..diagnostics.types import (
    Confidence,
    Diagnosis,
    Hypothesis,
    HypothesisStatus,
    Observation,
)
from ..evidence.bundle import EvidenceBundle
from .live_evidence import (
    CollectorResult,
    Comparison,
    Conclusion,
    ExpectationKind,
    LiveEvidenceSession,
)

#: The only source string a live observation may carry.
LIVE_SOURCE = "LIVE_SIMULATOR"

#: Conclusions that positively support a prediction.
_SUPPORTING_CONCLUSIONS = frozenset({Conclusion.VERIFIED, Conclusion.DERIVED})
_CONTRADICTING_CONCLUSION = Conclusion.CONTRADICTED

#: Which live expectation can settle which diagnostic hypothesis.
#:
#: The table is deliberately narrow. A ``VLAN_EXISTS`` answer says nothing about
#: a specific access port, so it is only auto-matched to a hypothesis whose cause
#: names that VLAN; the same target check is applied to routes and config lines.
_HYPOTHESIS_EXPECTATIONS: dict[str, frozenset[ExpectationKind]] = {
    "TRUNK_MISMATCH": frozenset({ExpectationKind.VLAN_ALLOWED_ON_TRUNK}),
    "WRONG_VLAN": frozenset(
        {
            ExpectationKind.VLAN_EXISTS,
            ExpectationKind.INTERFACE_STATUS,
            ExpectationKind.CONFIG_CONTAINS,
        }
    ),
    "MISSING_STATIC_ROUTE": frozenset({ExpectationKind.ROUTE_EXISTS}),
    "SHUTDOWN_INTERFACE": frozenset(
        {
            ExpectationKind.INTERFACE_UP,
            ExpectationKind.INTERFACE_STATUS,
            ExpectationKind.CONFIG_CONTAINS,
        }
    ),
    "INVALID_MASK": frozenset(
        {ExpectationKind.INTERFACE_UP, ExpectationKind.CONFIG_CONTAINS}
    ),
    "ACL_BLOCK": frozenset({ExpectationKind.CONFIG_CONTAINS}),
    "WRONG_GATEWAY": frozenset(
        {ExpectationKind.INTERFACE_UP, ExpectationKind.INTERFACE_STATUS}
    ),
}

_EXPECTATION_HYPOTHESES: dict[ExpectationKind, frozenset[str]] = {
    kind: frozenset(
        hypothesis_kind
        for hypothesis_kind, kinds in _HYPOTHESIS_EXPECTATIONS.items()
        if kind in kinds
    )
    for kind in ExpectationKind
}


# ---------------------------------------------------------------------------
# Runtime bundle
# ---------------------------------------------------------------------------


def collect_live_results(
    session: LiveEvidenceSession,
    devices: Iterable[str],
    *,
    timeout: float | None = None,
) -> tuple[CollectorResult, ...]:
    """Run the standard live collector set for every device in ``devices``.

    The collector set is the read-only one from ``live_evidence``: ``show ip
    interface brief``, ``show running-config``, ``show vlan brief``, ``show
    interfaces trunk``, ``show ip route`` and ``show interfaces status``. Each
    result is independent; a failure on one command does not hide the others.
    """
    results: list[CollectorResult] = []
    for device in devices:
        results.extend(session.collect_standard_set(device, timeout=timeout))
    return tuple(results)


def build_runtime_bundle(
    session: LiveEvidenceSession,
    devices: Iterable[str],
    *,
    timeout: float | None = None,
) -> EvidenceBundle:
    """Collect live output and assemble an :class:`EvidenceBundle`.

    Only live observations are added. A scripted backend, a refused command, a
    timeout, or an unparsed reply contributes no record, so the detectors cannot
    mistake it for runtime state. The bundle keeps one device's records apart
    from every other device, exactly as the ingestion layer requires.
    """
    bundle = EvidenceBundle()
    for result in collect_live_results(session, devices, timeout=timeout):
        if not result.evidence.is_live:
            continue
        if result.record is None:
            continue
        bundle.add(result.record)
    return bundle


# ---------------------------------------------------------------------------
# Checks and annotation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LiveCheck:
    """A live comparison, optionally pinned to one hypothesis kind.

    ``comparison`` alone is enough for the common case: the bridge infers which
    hypothesis kinds the expectation can settle. ``hypothesis_kind`` exists for
    callers that already know the link and want to remove any ambiguity.
    """

    comparison: Comparison
    hypothesis_kind: str | None = None
    device: str | None = None
    interface: str | None = None

    @property
    def device_name(self) -> str | None:
        return self.device or self.comparison.expectation.device or None

    @property
    def interface_name(self) -> str | None:
        if self.interface is not None:
            return self.interface
        return self.comparison.expectation.interface


def _normalise_checks(
    live_results: Sequence[Comparison | LiveCheck] | Comparison | LiveCheck,
) -> tuple[LiveCheck, ...]:
    if isinstance(live_results, LiveCheck):
        return (live_results,)
    if isinstance(live_results, Comparison):
        return (LiveCheck(comparison=live_results),)
    checks: list[LiveCheck] = []
    for item in live_results:
        if isinstance(item, LiveCheck):
            checks.append(item)
        elif isinstance(item, Comparison):
            checks.append(LiveCheck(comparison=item))
        else:  # defensive: a caller must not pass raw collector results here
            raise TypeError(
                "live_results must contain Comparison or LiveCheck values, "
                f"got {type(item).__name__}"
            )
    return tuple(checks)


def _is_live(comparison: Comparison) -> bool:
    """True only when every cited observation is a completed live command."""
    return bool(comparison.evidence) and all(
        item.is_live for item in comparison.evidence
    )


#: Common IOS interface abbreviations. Packet Tracer output switches between
#: ``Gi0/1`` and ``GigabitEthernet0/1`` freely, so a comparison must not hinge on
#: which spelling the parser happened to capture.
_INTERFACE_ALIASES = {
    "gi": "gigabitethernet",
    "gig": "gigabitethernet",
    "g": "gigabitethernet",
    "fa": "fastethernet",
    "f": "fastethernet",
    "eth": "ethernet",
    "se": "serial",
    "te": "tengigabitethernet",
    "po": "port-channel",
    "vl": "vlan",
}


def _normalise_interface(name: str) -> str:
    text = name.strip().lower().replace(" ", "")
    match = re.match(r"([a-z-]+)(.*)", text)
    if match is None:
        return text
    prefix, rest = match.groups()
    return f"{_INTERFACE_ALIASES.get(prefix, prefix)}{rest}"


def _interface_suffix(name: str) -> str:
    """The slot/port part of an interface name (``Gig0/1`` -> ``0/1``)."""
    normalized = _normalise_interface(name)
    match = re.match(r"[a-z-]+(.*)", normalized)
    return match.group(1) if match else normalized


def _same_interface(left: str, right: str) -> bool:
    if _normalise_interface(left) == _normalise_interface(right):
        return True
    # Same slot/port with a spelling this table has never seen (``Gig0/1``).
    return _interface_suffix(left) == _interface_suffix(right)


def _mentioned(hypothesis: Hypothesis, pattern: str) -> bool:
    return pattern.lower() in (hypothesis.suspected_cause or "").lower()


def _interface_mentioned(hypothesis: Hypothesis, interface: str) -> bool:
    cause = hypothesis.suspected_cause or ""
    if interface.lower() in cause.lower():
        return True
    target = _normalise_interface(interface)
    return any(
        _normalise_interface(token) == target
        for token in re.findall(r"[A-Za-z-]+\d[\w/.-]*", cause)
    )


def _vlan_mentioned(hypothesis: Hypothesis, vlan_id: int | None) -> bool:
    if vlan_id is None:
        return False
    return re.search(rf"(?<!\d){int(vlan_id)}(?!\d)", hypothesis.suspected_cause) is not None


def _target_mentioned(hypothesis: Hypothesis, expectation) -> bool:
    """Whether a device-wide check is specific to this hypothesis's claim.

    Used only when the hypothesis names no interface. Without it, a VLAN probe
    for VLAN 10 would be allowed to upgrade or downgrade every wrong-VLAN
    hypothesis on the same device.
    """
    kind = expectation.kind
    if kind is ExpectationKind.VLAN_EXISTS:
        return _vlan_mentioned(hypothesis, expectation.vlan_id)
    if kind is ExpectationKind.ROUTE_EXISTS:
        return bool(expectation.network) and _mentioned(hypothesis, expectation.network)
    if kind is ExpectationKind.CONFIG_CONTAINS:
        line = " ".join((expectation.config_line or "").split())
        return bool(line) and line.lower() in " ".join(
            (hypothesis.suspected_cause or "").split()
        ).lower()
    if expectation.interface:
        return _interface_mentioned(hypothesis, expectation.interface)
    return False


def _matches(hypothesis: Hypothesis, check: LiveCheck) -> bool:
    """Whether ``check`` can speak to ``hypothesis``. Narrow by construction."""
    expectation = check.comparison.expectation
    kinds = (
        frozenset({check.hypothesis_kind})
        if check.hypothesis_kind
        else _EXPECTATION_HYPOTHESES.get(expectation.kind, frozenset())
    )
    if hypothesis.kind not in kinds:
        return False

    check_device = check.device_name
    if check_device is None:
        if hypothesis.device is not None:
            return False
    elif (
        hypothesis.device is None
        or hypothesis.device.strip().lower() != check_device.strip().lower()
    ):
        return False

    check_interface = check.interface_name
    hypothesis_interface = hypothesis.interface
    if check_interface and hypothesis_interface:
        return _same_interface(check_interface, hypothesis_interface)
    if hypothesis_interface:
        # An interface-specific hypothesis is not settled by a device-wide probe
        # unless the probe itself names that interface.
        return False
    return _target_mentioned(hypothesis, expectation)


def _merge_observations(
    existing: tuple[Observation, ...], additions: Iterable[Observation]
) -> tuple[Observation, ...]:
    merged = list(existing)
    seen = {(item.source, item.device, item.detail) for item in merged}
    for observation in additions:
        key = (observation.source, observation.device, observation.detail)
        if key not in seen:
            seen.add(key)
            merged.append(observation)
    return tuple(merged)


def _promote(hypothesis: Hypothesis, support: tuple[Observation, ...]) -> Hypothesis:
    merged = _merge_observations(hypothesis.supporting, support)
    promotable = hypothesis.status is HypothesisStatus.INSUFFICIENT_EVIDENCE
    suspected = hypothesis.status is HypothesisStatus.SUSPECTED and not hypothesis.contradicting
    if promotable or suspected:
        return replace(
            hypothesis,
            status=HypothesisStatus.CONFIRMED_DEFECT,
            confidence=Confidence.HIGH,
            supporting=merged,
            missing_evidence=(),
        )
    if hypothesis.status is HypothesisStatus.CONFIRMED_DEFECT:
        return replace(hypothesis, supporting=merged, missing_evidence=())
    return replace(hypothesis, supporting=merged)


def _downgrade(hypothesis: Hypothesis, contradicting: tuple[Observation, ...]) -> Hypothesis:
    merged = _merge_observations(hypothesis.contradicting, contradicting)
    return replace(
        hypothesis,
        status=HypothesisStatus.RULED_OUT,
        confidence=Confidence.LOW,
        contradicting=merged,
        missing_evidence=(),
    )


def annotate_diagnosis(
    diagnosis: Diagnosis,
    live_results: Sequence[Comparison | LiveCheck] | Comparison | LiveCheck,
) -> Diagnosis:
    """Upgrade or downgrade hypotheses using live simulator evidence.

    * a hypothesis with live ``VERIFIED``/``DERIVED`` support is promoted when it
      was ``INSUFFICIENT_EVIDENCE`` (or ``SUSPECTED`` with no contradiction);
    * a hypothesis contradicted by a live command becomes ``RULED_OUT``, the
      existing vocabulary's refuted state;
    * a hypothesis with no matching live check keeps its status and evidence;
    * evidence that is not live is ignored entirely.

    The function never mutates its input: frozen dataclasses are rebuilt and the
    ranked view is recomputed with the engine's own ordering.
    """
    checks = _normalise_checks(live_results)
    annotated: list[Hypothesis] = []
    for hypothesis in diagnosis.hypotheses:
        support: list[Observation] = []
        contradicting: list[Observation] = []
        for check in checks:
            if not _matches(hypothesis, check):
                continue
            comparison = check.comparison
            if not _is_live(comparison):
                continue
            if comparison.conclusion in _SUPPORTING_CONCLUSIONS:
                support.extend(comparison.supporting_observations())
            elif comparison.conclusion is _CONTRADICTING_CONCLUSION:
                contradicting.extend(comparison.contradicting_observations())

        if contradicting:
            annotated.append(_downgrade(hypothesis, tuple(contradicting)))
        elif support:
            annotated.append(_promote(hypothesis, tuple(support)))
        else:
            annotated.append(hypothesis)

    return Diagnosis(
        symptoms=diagnosis.symptoms,
        hypotheses=tuple(annotated),
        ranked=tuple(rank(annotated)),
    )


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UnsupportedCheck:
    """A live check that could not decide anything, with the reason attached."""

    check: str
    device: str | None
    reason: str
    missing_evidence: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "check": self.check,
            "device": self.device,
            "reason": self.reason,
            "missing_evidence": list(self.missing_evidence),
        }


#: Keys that must never appear in a student-facing report.
_FORBIDDEN_KEY_PARTS = ("manifest", "instructor", "answer_key", "answer-key")


def _sanitise(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _sanitise(item)
            for key, item in value.items()
            if not any(part in str(key).lower() for part in _FORBIDDEN_KEY_PARTS)
        }
    if isinstance(value, (list, tuple)):
        return [_sanitise(item) for item in value]
    return value


def _model_finding(hypothesis: Hypothesis) -> dict:
    return {
        "kind": hypothesis.kind,
        "device": hypothesis.device,
        "interface": hypothesis.interface,
        "status": hypothesis.status.value,
        "confidence": hypothesis.confidence.value,
        "suspected_cause": hypothesis.suspected_cause,
        "supporting": [
            {"source": item.source, "device": item.device, "detail": item.detail}
            for item in hypothesis.supporting
        ],
    }


def _live_finding(check: LiveCheck) -> dict:
    comparison = check.comparison
    live = _is_live(comparison)
    return {
        "check": comparison.expectation.kind.value,
        "hypothesis_kind": check.hypothesis_kind,
        "device": check.device_name,
        "interface": check.interface_name,
        "conclusion": comparison.conclusion.value,
        "live": live,
        "source": LIVE_SOURCE if live else "NOT_LIVE",
        "detail": comparison.detail,
        "observed": comparison.observed,
        "missing_evidence": list(comparison.missing_evidence),
        "evidence": [
            {"source": item.source, "device": item.device, "detail": item.detail}
            for item in comparison.evidence_observations()
        ],
    }


def _model_only(hypothesis: Hypothesis) -> bool:
    return bool(hypothesis.supporting) and all(
        item.source == "MODEL" for item in hypothesis.supporting
    )


@dataclass(frozen=True)
class LiveDiagnosisReport:
    """What the model claimed, what the simulator showed, and what changed.

    ``model_findings`` are hypotheses that rest only on ``MODEL`` observations.
    ``live_findings`` describe every check, conclusive or not. ``promoted`` and
    ``downgraded`` are the transitions, with the live conclusion named.
    ``unsupported_checks`` records every check that could not decide anything and
    why, so an inconclusive run cannot masquerade as a clean one.
    """

    model_findings: tuple[dict, ...] = ()
    live_findings: tuple[dict, ...] = ()
    promoted: tuple[dict, ...] = ()
    downgraded: tuple[dict, ...] = ()
    unsupported_checks: tuple[UnsupportedCheck, ...] = ()

    def as_dict(self) -> dict:
        """Serialisable view. Instructor/answer-key keys are stripped."""
        return _sanitise(
            {
                "model_findings": [dict(item) for item in self.model_findings],
                "live_findings": [dict(item) for item in self.live_findings],
                "promoted": [dict(item) for item in self.promoted],
                "downgraded": [dict(item) for item in self.downgraded],
                "unsupported_checks": [
                    item.as_dict() for item in self.unsupported_checks
                ],
            }
        )

    @classmethod
    def from_run(
        cls,
        before: Diagnosis,
        after: Diagnosis,
        live_results: Sequence[Comparison | LiveCheck] | Comparison | LiveCheck,
    ) -> LiveDiagnosisReport:
        """Build a report from the diagnosis before and after annotation."""
        checks = _normalise_checks(live_results)

        promoted: list[dict] = []
        downgraded: list[dict] = []
        for original, updated in zip(before.hypotheses, after.hypotheses, strict=True):
            if original.status is updated.status:
                continue
            transition = {
                "kind": updated.kind,
                "device": updated.device,
                "interface": updated.interface,
                "from_status": original.status.value,
                "to_status": updated.status.value,
            }
            if updated.status is HypothesisStatus.CONFIRMED_DEFECT:
                transition["reason"] = (
                    "a successful live simulator command supported the hypothesis"
                )
                promoted.append(transition)
            elif updated.status is HypothesisStatus.RULED_OUT:
                transition["reason"] = (
                    "a live simulator command positively contradicted the hypothesis"
                )
                transition["live_conclusion"] = Conclusion.CONTRADICTED.value
                downgraded.append(transition)

        unsupported = tuple(
            UnsupportedCheck(
                check=check.comparison.expectation.kind.value,
                device=check.device_name,
                reason=check.comparison.detail,
                missing_evidence=check.comparison.missing_evidence,
            )
            for check in checks
            if not _is_live(check.comparison)
            or check.comparison.conclusion is Conclusion.INCONCLUSIVE
        )

        return cls(
            model_findings=tuple(
                _model_finding(hypothesis)
                for hypothesis in before.hypotheses
                if _model_only(hypothesis)
            ),
            live_findings=tuple(_live_finding(check) for check in checks),
            promoted=tuple(promoted),
            downgraded=tuple(downgraded),
            unsupported_checks=unsupported,
        )


def annotate_with_report(
    diagnosis: Diagnosis,
    live_results: Sequence[Comparison | LiveCheck] | Comparison | LiveCheck,
) -> tuple[Diagnosis, LiveDiagnosisReport]:
    """Convenience wrapper: annotate, then describe the transition."""
    annotated = annotate_diagnosis(diagnosis, live_results)
    report = LiveDiagnosisReport.from_run(diagnosis, annotated, live_results)
    return annotated, report


__all__ = [
    "LIVE_SOURCE",
    "LiveCheck",
    "LiveDiagnosisReport",
    "UnsupportedCheck",
    "annotate_diagnosis",
    "annotate_with_report",
    "build_runtime_bundle",
    "collect_live_results",
]
