"""Double-check and what-if tests.

The properties under test are the ones that make these modes trustworthy:

* the auditor reaches its own conclusions and does not inherit the investigator's;
* coverage counters never let a partly-checked network look fully verified;
* a what-if never modifies the source, never applies a change without an
  explicitly capable backend, and never reports a prediction as an observation.
"""

from __future__ import annotations

import json

import pytest

from trident.faultlab import baseline_lab, scenarios
from trident.investigation import (
    Auditor,
    Candidate,
    Outcome,
    Verdict,
    evaluate,
)
from trident.simulator import SimulatorRuntime


def _session(tmp_path, scenario: dict):
    lab = tmp_path / "lab.pkt"
    lab.write_bytes(b"PKT\x00lab")
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(scenario))
    runtime = SimulatorRuntime(workspace_root=tmp_path / "ws", prefer_live=False)
    return lab, runtime.create_session(lab, scripted_scenario=path)


# ---------------------------------------------------------------------------
# Double-check: static only
# ---------------------------------------------------------------------------


def test_audit_without_runtime_still_reports_static_findings():
    model = next(s for s in scenarios() if s.name == "acl-block").model
    report = Auditor(model, runtime_available=False, runtime_reason="no App").audit()
    kinds = [check.suspected_root_cause for check in report.checks]
    assert "ACL_BLOCK" in kinds
    assert report.runtime_available is False
    assert report.evidence_tier == "NO_OPERATIONAL_EVIDENCE"


def test_audit_never_claims_full_verification_without_operational_checks():
    model = next(s for s in scenarios() if s.name == "wrong-vlan").model
    report = Auditor(model, runtime_available=False).audit()
    coverage = report.coverage
    assert coverage.operationally_checked == 0
    assert coverage.simulator_tested == 0
    # A network with a real fault can never resolve to "everything passed".
    assert coverage.failed >= 1


def test_audit_counts_identity_consistency():
    model = baseline_lab()
    report = Auditor(model, runtime_available=False).audit()
    identity = [c for c in report.checks if c.check_id == "identity:devices"]
    assert identity and identity[0].verdict is Verdict.PASSED


def test_audit_finds_broken_identity():
    model = baseline_lab()
    interface = next(iter(model.interfaces.values()))
    interface.device = "GHOST"
    report = Auditor(model, runtime_available=False).audit()
    assert report.contradictions
    assert any(c.verdict is Verdict.CONTRADICTED for c in report.checks)


def test_coverage_is_serialisable_and_has_no_fake_percentage():
    model = next(s for s in scenarios() if s.name == "wrong-vlan").model
    payload = Auditor(model, runtime_available=False).audit().as_dict()
    json.dumps(payload)
    assert "resolved_fraction" in payload["coverage"]
    assert "percent_verified" not in payload["coverage"]


def test_audit_is_independent_of_investigator_output():
    """The auditor takes a model, not a previous report, so it cannot echo one."""
    model = next(s for s in scenarios() if s.name == "trunk-mismatch").model
    report = Auditor(model, runtime_available=False).audit()
    assert any(check.suspected_root_cause == "TRUNK_MISMATCH" for check in report.checks)


def test_operational_checks_are_labelled_when_scripted(tmp_path):
    scenario = {
        "devices": [
            {
                "name": "SW2",
                "commands": {"show ip interface brief": "Interface Status\nFa0/1 up up\n"},
            }
        ]
    }
    lab, session = _session(tmp_path, scenario)
    try:
        model = baseline_lab()
        report = Auditor(model, session=session, runtime_available=True).audit()
        ops = [c for c in report.checks if c.check_id.startswith("ops:")]
        assert ops
        assert report.coverage.operationally_checked >= 1
        # Scripted results must never count as simulator-tested.
        assert report.coverage.simulator_tested == 0
        assert any("not a live simulator observation" in c.limitations for c in ops)
    finally:
        session.close()


def test_checks_with_no_data_are_unresolved_not_passed(tmp_path):
    """A command that runs but returns nothing is unresolved, never a pass."""
    scenario = {"devices": [{"name": "SW2", "commands": {}}]}
    lab, session = _session(tmp_path, scenario)
    try:
        report = Auditor(baseline_lab(), session=session, runtime_available=True).audit()
        ops = [c for c in report.checks if c.check_id.startswith("ops:")]
        assert ops
        assert all(c.verdict is not Verdict.PASSED for c in ops)
        assert report.coverage.unresolved >= 1
        assert report.coverage.passed == 0 or all(
            c.verdict is Verdict.PASSED for c in report.checks if c.check_id.startswith("identity")
        )
    finally:
        session.close()


def test_capability_gap_is_counted_as_unsupported(tmp_path):
    """A backend lacking a capability is a distinct, reported state."""

    scenario = {"devices": [{"name": "SW2", "commands": {}}]}
    lab, session = _session(tmp_path, scenario)
    try:
        class _NoCli:
            def __init__(self, session):
                self._session = session

            def devices(self):
                return self._session.backend.devices()

            def capabilities(self):
                return frozenset()

        original = session.backend
        session.backend = _NoCli(original)  # type: ignore[assignment]
        report = Auditor(baseline_lab(), session=session, runtime_available=True).audit()
        assert report.coverage.unsupported >= 1
        assert any(c.verdict is Verdict.UNSUPPORTED for c in report.checks)
        session.backend = original  # type: ignore[assignment]
    finally:
        session.close()


def test_check_limit_is_reported_as_skipped(tmp_path):
    scenario = {"devices": [{"name": "SW2", "commands": {}}]}
    lab, session = _session(tmp_path, scenario)
    try:
        report = Auditor(
            baseline_lab(), session=session, runtime_available=True, max_checks=1
        ).audit()
        assert report.coverage.skipped >= 1
        assert any(c.verdict is Verdict.SKIPPED for c in report.checks)
    finally:
        session.close()


# ---------------------------------------------------------------------------
# What-if
# ---------------------------------------------------------------------------


def test_whatif_without_runtime_is_simulation_unavailable(tmp_path):
    candidate = Candidate(
        candidate_id="c1",
        device="SW2",
        commands=("vlan 20",),
        intent="move port to VLAN 20",
        hypothesis="WRONG_VLAN",
    )
    result = evaluate(
        baseline_lab(),
        candidate,
        baseline_session=None,
        probes=("show vlan brief",),
        runtime_available=False,
        runtime_reason="not registered",
    )
    assert result.outcome is Outcome.SIMULATION_UNAVAILABLE
    assert result.original_preserved is True
    assert result.baseline == [] and result.after == []


def test_whatif_refuses_mutation_without_capability(tmp_path):
    scenario = {"devices": [{"name": "SW2", "commands": {"show vlan brief": "VLAN Name"}}]}
    lab, session = _session(tmp_path, scenario)
    try:
        before = session.source_sha256
        candidate = Candidate(
            candidate_id="c1",
            device="SW2",
            commands=("vlan 20",),
            intent="move port to VLAN 20",
            hypothesis="WRONG_VLAN",
        )
        result = evaluate(
            baseline_lab(),
            candidate,
            baseline_session=session,
            probes=("show vlan brief",),
            runtime_available=True,
        )
        assert result.outcome is Outcome.UNSUPPORTED_COMMAND
        assert result.original_preserved is True
        assert session.source_sha256 == before
        # No probe ran, because nothing could be applied.
        assert result.baseline == []
    finally:
        status = session.close()
    assert "source=INTACT" in status


def test_whatif_never_touches_the_source(tmp_path):
    scenario = {"devices": [{"name": "SW2", "commands": {"show vlan brief": "VLAN"}}]}
    lab, session = _session(tmp_path, scenario)
    original = lab.read_bytes()
    try:
        candidate = Candidate(
            candidate_id="c1",
            device="SW2",
            commands=("vlan 20",),
            intent="test",
            hypothesis="WRONG_VLAN",
        )
        evaluate(
            baseline_lab(),
            candidate,
            baseline_session=session,
            probes=("show vlan brief",),
            runtime_available=True,
        )
    finally:
        session.close()
    assert lab.read_bytes() == original


@pytest.mark.parametrize(
    ("baseline_ok", "after_ok", "expected"),
    [
        (False, True, Outcome.IMPROVEMENT_OBSERVED),
        (True, False, Outcome.REGRESSION_OBSERVED),
        (True, True, Outcome.NO_MEANINGFUL_CHANGE),
        (False, False, Outcome.INCONCLUSIVE),
    ],
)
def test_outcome_classification(baseline_ok, after_ok, expected):
    from trident.investigation.whatif import _compare

    baseline = [{"ok": baseline_ok, "raw": "a"}]
    after = [{"ok": after_ok, "raw": "b"}]
    outcome, _ = _compare(baseline, after)
    assert outcome is expected


def test_candidate_is_traceable():
    candidate = Candidate(
        candidate_id="c1",
        device="R1",
        commands=("ip route 10.0.0.0 255.0.0.0 1.1.1.1",),
        intent="restore the missing route",
        hypothesis="MISSING_STATIC_ROUTE",
        requirement="R1 must reach 10.0.0.0/8",
    )
    payload = candidate.as_dict()
    assert payload["hypothesis"] == "MISSING_STATIC_ROUTE"
    assert payload["requirement"]
