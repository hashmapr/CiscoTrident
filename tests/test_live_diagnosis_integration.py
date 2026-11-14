"""Integration tests for the live-evidence bridge.

Two layers, on purpose:

* the default, mocked layer starts no simulator. A fake backend returns canned
  Packet Tracer output so every rule can be checked deterministically: the
  bundle is assembled, live support promotes, live contradiction downgrades,
  static data never promotes, and an unsupported check carries its reason;
* one opt-in live test opens the generated broken-campus lab and proves the same
  path against a real Packet Tracer process: a live ``CONTRADICTED`` and a live
  ``DERIVED``/``VERIFIED`` reach the diagnostic hypotheses, and the source
  ``.pkt`` is byte-for-byte unchanged afterwards.

The live test needs ``TRIDENT_ALLOW_LIVE_SIMULATOR=1`` **and**
``TRIDENT_RUN_LIVE_DIAGNOSIS=1``. A missing opt-in or artifact is a skip, never
a pass.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from trident.deepcore.evidence_bridge import (
    LiveCheck,
    LiveDiagnosisReport,
    annotate_diagnosis,
    annotate_with_report,
    build_runtime_bundle,
)
from trident.deepcore.live_evidence import (
    CollectorResult,
    Comparison,
    Conclusion,
    EvidenceBudget,
    EvidenceSource,
    Expectation,
    ExpectationKind,
    LiveEvidence,
    LiveEvidenceSession,
    compare,
)
from trident.diagnostics import TRUNK_MISMATCH, WRONG_VLAN, diagnose, rank
from trident.diagnostics.types import (
    Confidence,
    Diagnosis,
    Hypothesis,
    HypothesisStatus,
    Observation,
)
from trident.evidence.types import EvidenceKind
from trident.models import DeviceInfo, InterfaceInfo, LinkInfo, NetworkModel
from trident.simulator.contracts import (
    BackendKind,
    ObservationKind,
    OperationResult,
    Provenance,
    utcnow,
)

# ---------------------------------------------------------------------------
# Canned simulator output and a fake backend
# ---------------------------------------------------------------------------

IP_INT_BRIEF_UP = """\
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/1     10.0.0.2        YES manual up                    up
"""

VLAN_BRIEF_WITH_10 = """\
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Fa0/1, Fa0/2
10   ADMIN                            active    Fa0/3
20   STUDENT                          active
30   FACULTY                          active
99   MANAGEMENT                       active
"""

VLAN_BRIEF_WITHOUT_10 = """\
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Fa0/1, Fa0/2
20   STUDENT                          active
30   FACULTY                          active
99   MANAGEMENT                       active
"""

TRUNK_WITH_30 = """\
Port        Mode             Encapsulation  Status        Native vlan
Gi0/1       on               802.1q         trunking      99

Port        Vlans allowed on trunk
Gi0/1       10,20,30,99

Port        Vlans allowed and active in management domain
Gi0/1       10,20,30,99
"""

TRUNK_WITHOUT_30 = """\
Port        Mode             Encapsulation  Status        Native vlan
Gi0/1       on               802.1q         trunking      99

Port        Vlans allowed on trunk
Gi0/1       10,20,99

Port        Vlans allowed and active in management domain
Gi0/1       10,20,99
"""


class FakeBackend:
    """The small backend surface ``LiveEvidenceSession`` needs. No simulator."""

    def __init__(
        self,
        outputs: dict[str, str] | None = None,
        *,
        fail: str | None = None,
        timeout: bool = False,
        scripted: bool = False,
    ) -> None:
        self.outputs = outputs or {}
        self.fail = fail
        self.timeout = timeout
        self.kind = BackendKind.SCRIPTED if scripted else BackendKind.SIMULATOR_LIVE
        self.version = "fake-9.0.1"
        self.closed = 0
        self.calls: list[tuple[str, str, float]] = []
        self._scripted = scripted

    def run_cli(self, device: str, command: str, timeout: float) -> OperationResult:
        self.calls.append((device, command, timeout))
        if self.timeout:
            raise TimeoutError("simulated command timeout")
        if self.fail is not None:
            return self._result(device, command, ok=False, raw="", error=self.fail)
        raw = self.outputs.get(" ".join(command.split()).lower(), "")
        return self._result(device, command, ok=True, raw=raw, observed=not self._scripted)

    def _result(
        self,
        device: str,
        command: str,
        *,
        ok: bool,
        raw: str,
        error: str | None = None,
        observed: bool = False,
    ) -> OperationResult:
        provenance = Provenance(
            backend=self.kind,
            simulator_version=self.version,
            session_id="fake-session",
            source_sha256="0" * 64,
            working_copy_sha256="1" * 64,
            device=device,
            interface=None,
            operation=command,
            executed_at=utcnow(),
            parsed_by="raw",
        )
        return OperationResult(
            ok=ok,
            kind=ObservationKind.CLI_OUTPUT,
            operation=command,
            device=device,
            raw=raw,
            parsed=None,
            provenance=provenance,
            error=error,
            observed=observed,
        )

    def close(self) -> str:
        self.closed += 1
        return "FAKE_CLOSED"


def _lab(tmp_path: Path) -> Path:
    path = tmp_path / "lab.pkt"
    path.write_bytes(b"\x00\x01fake-pkt-bytes\x00")
    return path


# ---------------------------------------------------------------------------
# Model and hypothesis fixtures
# ---------------------------------------------------------------------------


def _trunk_model(*, dist_allowed: list[str], access_allowed: list[str]) -> NetworkModel:
    """Two switches, one trunk link, no addressing: only trunk-mismatch fires."""
    model = NetworkModel()
    for name in ("SW-DIST", "SW-ACCESS"):
        model.devices[name] = DeviceInfo(id=name, name=name, hostname=name)
    model.interfaces["SW-DIST:Gi0/1"] = InterfaceInfo(
        device="SW-DIST",
        name="Gi0/1",
        canonical_name="Gi0/1",
        access_mode="trunk",
        vlan_assignments=list(dist_allowed),
    )
    model.interfaces["SW-ACCESS:Gi0/1"] = InterfaceInfo(
        device="SW-ACCESS",
        name="Gi0/1",
        canonical_name="Gi0/1",
        access_mode="trunk",
        vlan_assignments=list(access_allowed),
    )
    model.links = [
        LinkInfo(
            device_a="SW-DIST",
            interface_a="Gi0/1",
            device_b="SW-ACCESS",
            interface_b="Gi0/1",
        )
    ]
    return model


def _trunk_expectation(
    device: str = "SW-DIST", vlan_id: int = 30
) -> Expectation:
    return Expectation(
        ExpectationKind.VLAN_ALLOWED_ON_TRUNK,
        device,
        interface="Gi0/1",
        vlan_id=vlan_id,
        description=f"VLAN {vlan_id} is allowed on {device} Gi0/1",
    )


def _vlan_expectation(vlan_id: int = 10) -> Expectation:
    return Expectation(
        ExpectationKind.VLAN_EXISTS,
        "SW-DIST",
        vlan_id=vlan_id,
        description=f"VLAN {vlan_id} exists on SW-DIST",
    )


def _hypothesis(
    *,
    status: HypothesisStatus = HypothesisStatus.INSUFFICIENT_EVIDENCE,
    device: str = "SW-DIST",
    interface: str | None = "Gi0/1",
    cause: str = "SW-DIST Gi0/1 allows VLAN 30",
    supporting: tuple[Observation, ...] = (),
    contradicting: tuple[Observation, ...] = (),
    missing: tuple[str, ...] = ("a successful live allowed-VLAN check",),
) -> Hypothesis:
    confidence = {
        HypothesisStatus.INSUFFICIENT_EVIDENCE: Confidence.LOW,
        HypothesisStatus.CONFIRMED_DEFECT: Confidence.HIGH,
        HypothesisStatus.SUSPECTED: Confidence.MEDIUM,
        HypothesisStatus.RULED_OUT: Confidence.LOW,
    }[status]
    return Hypothesis(
        kind=TRUNK_MISMATCH,
        status=status,
        confidence=confidence,
        device=device,
        interface=interface,
        suspected_cause=cause,
        supporting=supporting,
        contradicting=contradicting,
        missing_evidence=missing if status is HypothesisStatus.INSUFFICIENT_EVIDENCE else (),
        next_command="show interfaces trunk",
        repair_hint="Permit the missing VLAN on the trunk.",
    )


def _diagnosis(*hypotheses: Hypothesis) -> Diagnosis:
    items = list(hypotheses)
    return Diagnosis(
        symptoms=("faculty traffic cannot cross the dist-access uplink",),
        hypotheses=tuple(items),
        ranked=tuple(rank(items)),
    )


def _collect(session: LiveEvidenceSession, command: str, device: str = "SW-DIST"):
    if command == "vlan":
        return session.collect_vlan_brief(device)
    if command == "trunk":
        return session.collect_interfaces_trunk(device)
    raise AssertionError(f"unknown collector {command}")


# ---------------------------------------------------------------------------
# Mocked: bundle assembly
# ---------------------------------------------------------------------------


def test_build_runtime_bundle_assembles_live_records(tmp_path):
    backend = FakeBackend(
        {
            "show ip interface brief": IP_INT_BRIEF_UP,
            "show vlan brief": VLAN_BRIEF_WITH_10,
            "show interfaces trunk": TRUNK_WITH_30,
        }
    )
    with LiveEvidenceSession(backend, _lab(tmp_path)) as live:
        bundle = build_runtime_bundle(live, ["SW-DIST"])

    assert bundle.devices() == ("SW-DIST",)
    assert "GigabitEthernet0/1" in bundle.runtime_interfaces("SW-DIST")
    kinds = {record.kind for record in bundle.for_device("SW-DIST")}
    assert EvidenceKind.IP_INTERFACE_BRIEF in kinds
    assert EvidenceKind.VLAN_BRIEF in kinds
    assert EvidenceKind.INTERFACES_TRUNK in kinds
    # The standard set is six read-only commands; all were issued.
    assert live.commands_run == 6
    assert backend.closed == 1


def test_build_runtime_bundle_ignores_a_scripted_backend(tmp_path):
    backend = FakeBackend(
        {"show ip interface brief": IP_INT_BRIEF_UP}, scripted=True
    )
    with LiveEvidenceSession(backend, _lab(tmp_path)) as live:
        bundle = build_runtime_bundle(live, ["SW-DIST"])

    assert bundle.devices() == ()
    assert bundle.unattributed() == ()


# ---------------------------------------------------------------------------
# Mocked: promotion, downgrade, and the static-data prohibition
# ---------------------------------------------------------------------------


def test_live_support_promotes_insufficient_evidence(tmp_path):
    backend = FakeBackend({"show interfaces trunk": TRUNK_WITH_30})
    with LiveEvidenceSession(backend, _lab(tmp_path)) as live:
        result = _collect(live, "trunk")

    comparison = compare(_trunk_expectation(), result)
    assert comparison.conclusion is Conclusion.DERIVED
    assert comparison.evidence[0].is_live is True
    assert comparison.evidence[0].source is EvidenceSource.LIVE_SIMULATOR

    annotated, report = annotate_with_report(_diagnosis(_hypothesis()), comparison)

    updated = annotated.hypotheses[0]
    assert updated.status is HypothesisStatus.CONFIRMED_DEFECT
    assert updated.confidence is Confidence.HIGH
    assert updated.missing_evidence == ()
    assert any(item.source == "LIVE_SIMULATOR" for item in updated.supporting)

    assert len(report.promoted) == 1
    assert report.promoted[0]["from_status"] == "INSUFFICIENT_EVIDENCE"
    assert report.promoted[0]["to_status"] == "CONFIRMED_DEFECT"
    assert report.unsupported_checks == ()
    live_findings = report.as_dict()["live_findings"]
    assert live_findings[0]["conclusion"] == "DERIVED"
    assert live_findings[0]["source"] == "LIVE_SIMULATOR"


def test_live_contradiction_downgrades_a_confirmed_defect(tmp_path):
    # The model claims SW-DIST allows VLAN 30; the live trunk omits it.
    model = _trunk_model(
        dist_allowed=["10", "20", "30", "99"], access_allowed=["10", "20", "99"]
    )
    diagnosed = diagnose(model)
    finding = next(h for h in diagnosed.hypotheses if h.kind == TRUNK_MISMATCH)
    assert finding.status is HypothesisStatus.CONFIRMED_DEFECT

    backend = FakeBackend({"show interfaces trunk": TRUNK_WITHOUT_30})
    with LiveEvidenceSession(backend, _lab(tmp_path)) as live:
        result = _collect(live, "trunk")

    comparison = compare(_trunk_expectation(), result)
    assert comparison.conclusion is Conclusion.CONTRADICTED
    assert comparison.evidence[0].is_live is True

    annotated, report = annotate_with_report(diagnosed, comparison)
    updated = annotated.hypotheses[0]
    assert updated.status is HypothesisStatus.RULED_OUT
    assert updated.confidence is Confidence.LOW
    assert any(item.source == "LIVE_SIMULATOR" for item in updated.contradicting)
    assert all(item.source == "MODEL" for item in updated.supporting)

    assert len(report.downgraded) == 1
    assert report.downgraded[0]["from_status"] == "CONFIRMED_DEFECT"
    assert report.downgraded[0]["to_status"] == "RULED_OUT"
    assert report.downgraded[0]["live_conclusion"] == "CONTRADICTED"


def _static_live_evidence() -> LiveEvidence:
    provenance = Provenance(
        backend=BackendKind.SCRIPTED,
        simulator_version="fake-9.0.1",
        session_id="fake-session",
        source_sha256="0" * 64,
        working_copy_sha256="1" * 64,
        device="SW-DIST",
        interface=None,
        operation="show interfaces trunk",
        executed_at=utcnow(),
        parsed_by="raw",
    )
    return LiveEvidence(
        command="show interfaces trunk",
        device="SW-DIST",
        raw=TRUNK_WITH_30,
        ok=True,
        observed=False,
        source=EvidenceSource.SCRIPTED_BACKEND,
        provenance=provenance,
        executed_at=provenance.executed_at,
    )


def test_a_verified_comparison_is_not_promotion_without_live_evidence():
    """A hand-built ``VERIFIED`` comparison from a scripted backend is ignored."""
    evidence = _static_live_evidence()
    assert evidence.is_live is False
    result = CollectorResult(
        evidence=evidence,
        findings={"Gi0/1": {"allowed_vlans": [10, 20, 30, 99]}},
    )
    static_comparison = Comparison(
        expectation=_trunk_expectation(),
        conclusion=Conclusion.VERIFIED,
        detail="the scripted backend said the VLAN is allowed",
        evidence=(evidence,),
        observed="scripted output",
    )
    assert result.findings is not None

    annotated = annotate_diagnosis(_diagnosis(_hypothesis()), static_comparison)
    updated = annotated.hypotheses[0]
    assert updated.status is HypothesisStatus.INSUFFICIENT_EVIDENCE
    assert updated.supporting == ()
    assert updated.missing_evidence == ("a successful live allowed-VLAN check",)


def test_static_model_evidence_alone_cannot_promote():
    model_observation = Observation(
        source="MODEL",
        device="SW-DIST",
        detail="SW-DIST Gi0/1 is configured to allow VLAN 30",
    )
    hypothesis = _hypothesis(
        status=HypothesisStatus.INSUFFICIENT_EVIDENCE,
        supporting=(model_observation,),
    )
    annotated = annotate_diagnosis(_diagnosis(hypothesis), [])
    assert annotated.hypotheses[0].status is HypothesisStatus.INSUFFICIENT_EVIDENCE


# ---------------------------------------------------------------------------
# Mocked: unsupported checks and report hygiene
# ---------------------------------------------------------------------------


def test_unsupported_check_is_recorded_with_its_reason(tmp_path):
    backend = FakeBackend(fail="permission denied")
    with LiveEvidenceSession(backend, _lab(tmp_path)) as live:
        result = _collect(live, "trunk")

    comparison = compare(_trunk_expectation(), result)
    assert comparison.conclusion is Conclusion.INCONCLUSIVE

    annotated, report = annotate_with_report(_diagnosis(_hypothesis()), comparison)
    assert annotated.hypotheses[0].status is HypothesisStatus.INSUFFICIENT_EVIDENCE
    assert len(report.unsupported_checks) == 1
    unsupported = report.unsupported_checks[0]
    assert unsupported.check == "vlan_allowed_on_trunk"
    assert unsupported.device == "SW-DIST"
    assert "permission denied" in unsupported.reason
    assert unsupported.missing_evidence
    assert report.as_dict()["unsupported_checks"][0]["reason"] == unsupported.reason


def test_report_as_dict_never_contains_instructor_manifests():
    report = LiveDiagnosisReport(
        model_findings=(
            {
                "kind": "TRUNK_MISMATCH",
                "instructor_manifest": {"answer": "VLAN 30"},
                "nested": {"answer_key": "secret", "visible": "ok"},
            },
        ),
        live_findings=(),
        promoted=(),
        downgraded=(),
        unsupported_checks=(),
    )
    payload = report.as_dict()
    finding = payload["model_findings"][0]
    assert "instructor_manifest" not in finding
    assert finding["nested"] == {"visible": "ok"}
    assert "manifest" not in str(payload).lower()
    assert "answer_key" not in str(payload).lower()


def test_an_unmatched_hypothesis_is_left_untouched(tmp_path):
    backend = FakeBackend({"show interfaces trunk": TRUNK_WITH_30})
    with LiveEvidenceSession(backend, _lab(tmp_path)) as live:
        result = _collect(live, "trunk")
    comparison = compare(_trunk_expectation(), result)

    matched = _hypothesis()
    unmatched = _hypothesis(
        device="SW-ACCESS",
        interface="Gi0/9",
        cause="SW-ACCESS Gi0/9 allows VLAN 30",
    )
    annotated = annotate_diagnosis(_diagnosis(matched, unmatched), comparison)

    assert annotated.hypotheses[0].status is HypothesisStatus.CONFIRMED_DEFECT
    assert annotated.hypotheses[1] is unmatched


def test_interface_spelling_differences_do_not_defeat_matching(tmp_path):
    """Packet Tracer and the model may spell the same port differently."""
    output = TRUNK_WITHOUT_30.replace("Gi0/1", "Gig0/1")
    backend = FakeBackend({"show interfaces trunk": output})
    with LiveEvidenceSession(backend, _lab(tmp_path)) as live:
        result = _collect(live, "trunk")

    expectation = Expectation(
        ExpectationKind.VLAN_ALLOWED_ON_TRUNK,
        "SW-DIST",
        interface="Gig0/1",
        vlan_id=30,
        description="SW-DIST Gig0/1 allows VLAN 30",
    )
    comparison = compare(expectation, result)
    assert comparison.conclusion is Conclusion.CONTRADICTED

    annotated = annotate_diagnosis(_diagnosis(_hypothesis()), comparison)
    assert annotated.hypotheses[0].status is HypothesisStatus.RULED_OUT


def test_live_check_can_pin_the_hypothesis_kind(tmp_path):
    """An explicit ``LiveCheck`` removes any inference ambiguity."""
    backend = FakeBackend({"show vlan brief": VLAN_BRIEF_WITH_10})
    with LiveEvidenceSession(backend, _lab(tmp_path)) as live:
        result = _collect(live, "vlan", device="SW-DIST")

    # A VLAN probe names no interface, so it only matches a hypothesis whose
    # cause names the VLAN. The explicit kind does not bypass that check.
    vlan_hypothesis = Hypothesis(
        kind=WRONG_VLAN,
        status=HypothesisStatus.INSUFFICIENT_EVIDENCE,
        confidence=Confidence.LOW,
        device="SW-DIST",
        interface=None,
        suspected_cause="VLAN 10 is present on SW-DIST",
        supporting=(),
        contradicting=(),
        missing_evidence=("a successful live VLAN probe",),
        next_command="show vlan brief",
        repair_hint=None,
    )
    comparison = compare(_vlan_expectation(10), result)
    assert comparison.conclusion is Conclusion.VERIFIED
    annotated = annotate_diagnosis(
        _diagnosis(vlan_hypothesis), LiveCheck(comparison, hypothesis_kind=WRONG_VLAN)
    )
    assert annotated.hypotheses[0].status is HypothesisStatus.CONFIRMED_DEFECT
    assert any(
        item.source == "LIVE_SIMULATOR" for item in annotated.hypotheses[0].supporting
    )


# ---------------------------------------------------------------------------
# Live: the generated broken-campus lab
# ---------------------------------------------------------------------------

LAB = (
    Path(__file__).parents[1]
    / "test-labs"
    / "broken_campus"
    / "broken_campus_student.pkt"
)


def _enabled(name: str) -> bool:
    return os.environ.get(name, "").strip() not in {"", "0", "false", "no"}


def _require_live_lab() -> Path:
    if not LAB.is_file():
        pytest.skip(f"{LAB} is not present; generate the broken-campus lab first")
    from trident.simulator.backends import credentials_from_env, find_packet_tracer

    if find_packet_tracer() is None:
        pytest.skip("Packet Tracer is not installed in a searchable location")
    if credentials_from_env() is None:
        pytest.skip("no registered ExApp: configure TRIDENT_PT_APP_ID / TRIDENT_PT_SECRET")
    return LAB


def _trunk_interface(collector: CollectorResult) -> str:
    """Use the exact interface spelling the live parser produced, when known."""
    if isinstance(collector.findings, dict):
        for key in collector.findings:
            if str(key).lower().endswith("0/1"):
                return str(key)
    return "GigabitEthernet0/1"


@pytest.mark.live_simulator
@pytest.mark.skipif(
    not (
        _enabled("TRIDENT_ALLOW_LIVE_SIMULATOR")
        and _enabled("TRIDENT_RUN_LIVE_DIAGNOSIS")
    ),
    reason=(
        "live diagnosis integration needs TRIDENT_ALLOW_LIVE_SIMULATOR=1 and "
        "TRIDENT_RUN_LIVE_DIAGNOSIS=1"
    ),
)
def test_live_broken_campus_trunk_and_vlan_probes_annotate_diagnosis():
    lab_path = _require_live_lab()
    from trident.simulator import SimulatorRuntime, sha256_file

    # Static claim, deliberately the inverse of the lab's fault: SW-DIST allows
    # VLAN 30 and SW-ACCESS does not. The simulator will settle both.
    model = _trunk_model(
        dist_allowed=["10", "20", "30", "99"], access_allowed=["10", "20", "99"]
    )
    base = diagnose(model)
    access_claim = _hypothesis(
        device="SW-ACCESS",
        interface="Gi0/1",
        cause="SW-ACCESS Gi0/1 allows VLAN 30",
    )
    hypotheses = (*base.hypotheses, access_claim)
    diagnosis = Diagnosis(
        symptoms=("faculty traffic cannot cross the dist-access uplink",),
        hypotheses=hypotheses,
        ranked=tuple(rank(list(hypotheses))),
    )

    before = sha256_file(lab_path)
    runtime = SimulatorRuntime(prefer_live=True, allow_scripted=False)
    session = runtime.create_session(lab_path)
    try:
        with LiveEvidenceSession(
            session.backend,
            lab_path,
            close=session.close,
            budget=EvidenceBudget(
                command_timeout_s=90.0, overall_budget_s=300.0, max_commands=10
            ),
        ) as live:
            session.resolve_device("SW-DIST")
            session.resolve_device("SW-ACCESS")
            dist_vlan = live.collect_vlan_brief("SW-DIST", timeout=90.0)
            dist_trunk = live.collect_interfaces_trunk("SW-DIST", timeout=90.0)
            access_trunk = live.collect_interfaces_trunk("SW-ACCESS", timeout=90.0)
    finally:
        session.close()

    # Every probe must actually be a live simulator answer.
    for result in (dist_vlan, dist_trunk, access_trunk):
        assert result.evidence.is_live is True, result.evidence.as_dict()
        assert result.evidence.source is EvidenceSource.LIVE_SIMULATOR
        assert result.evidence.raw.strip(), result.evidence.as_dict()

    # Known fault: VLAN 10 is absent from the distribution switch.
    vlan_comparison = compare(_vlan_expectation(10), dist_vlan)
    assert vlan_comparison.conclusion is Conclusion.CONTRADICTED, vlan_comparison.as_dict()
    assert vlan_comparison.contradicting_observations()
    assert (
        vlan_comparison.contradicting_observations()[0].source
        == EvidenceSource.LIVE_SIMULATOR.value
    )

    # Known fault: SW-DIST omits VLAN 30 from its trunk allowed list, while
    # SW-ACCESS allows it.
    dist_interface = _trunk_interface(dist_trunk)
    access_interface = _trunk_interface(access_trunk)
    dist_comparison = compare(
        Expectation(
            ExpectationKind.VLAN_ALLOWED_ON_TRUNK,
            "SW-DIST",
            interface=dist_interface,
            vlan_id=30,
            description="SW-DIST trunk allows VLAN 30",
        ),
        dist_trunk,
    )
    access_comparison = compare(
        Expectation(
            ExpectationKind.VLAN_ALLOWED_ON_TRUNK,
            "SW-ACCESS",
            interface=access_interface,
            vlan_id=30,
            description="SW-ACCESS trunk allows VLAN 30",
        ),
        access_trunk,
    )
    assert dist_comparison.conclusion is Conclusion.CONTRADICTED, dist_comparison.as_dict()
    assert access_comparison.conclusion in {
        Conclusion.DERIVED,
        Conclusion.VERIFIED,
    }, access_comparison.as_dict()
    assert dist_comparison.evidence[0].is_live is True
    assert access_comparison.evidence[0].is_live is True

    # The live parser may spell the same port ``Gi0/1`` or
    # ``GigabitEthernet0/1``. The comparison used the live spelling; the
    # ``LiveCheck`` pins the link to the model's hypothesis so the assertion does
    # not depend on that cosmetic difference. Auto-inference is covered by the
    # mocked tests above.
    annotated, report = annotate_with_report(
        diagnosis,
        [
            LiveCheck(
                dist_comparison,
                hypothesis_kind=TRUNK_MISMATCH,
                device="SW-DIST",
                interface="Gi0/1",
            ),
            LiveCheck(
                access_comparison,
                hypothesis_kind=TRUNK_MISMATCH,
                device="SW-ACCESS",
                interface="Gi0/1",
            ),
        ],
    )
    by_device = {h.device: h for h in annotated.hypotheses if h.kind == TRUNK_MISMATCH}
    assert by_device.get("SW-DIST") is not None and (
        by_device["SW-DIST"].status is HypothesisStatus.RULED_OUT
    ), {
        "annotated": [
            (h.device, h.interface, h.status.value, len(h.contradicting))
            for h in annotated.hypotheses
        ],
        "dist_interface": dist_interface,
        "dist_comparison": dist_comparison.as_dict(),
        "access_comparison": access_comparison.as_dict(),
    }
    assert any(
        item.source == "LIVE_SIMULATOR"
        for item in by_device["SW-DIST"].contradicting
    )
    assert by_device.get("SW-ACCESS") is not None and (
        by_device["SW-ACCESS"].status is HypothesisStatus.CONFIRMED_DEFECT
    ), {
        "annotated": [
            (h.device, h.interface, h.status.value, len(h.supporting))
            for h in annotated.hypotheses
        ],
        "access_interface": access_interface,
        "access_comparison": access_comparison.as_dict(),
    }
    assert any(
        item.source == "LIVE_SIMULATOR"
        for item in by_device["SW-ACCESS"].supporting
    )

    payload = report.as_dict()
    assert payload["downgraded"], payload
    assert payload["downgraded"][0]["live_conclusion"] == "CONTRADICTED"
    assert payload["promoted"], payload
    assert all(
        item["source"] == "LIVE_SIMULATOR"
        for item in payload["live_findings"]
        if item["conclusion"] != Conclusion.INCONCLUSIVE.value
    )

    # Source preservation is proven by hashes, not asserted in prose.
    assert live.source_intact is True
    assert "source=INTACT" in live.cleanup_status
    assert sha256_file(lab_path) == before
