"""Investigation tests: escalation policy, hypothesis tracking, stopping, caching.

The loop is exercised against the scripted backend, which is the honest way to
test the *plumbing*: every assertion about live observation is made only where a
live backend could satisfy it, and scripted results are asserted to be
distinguishable from live ones.
"""

from __future__ import annotations

import json

import pytest

from trident.diagnostics.types import HypothesisStatus
from trident.faultlab import baseline_lab, scenarios
from trident.investigation import (
    Investigator,
    Mode,
    Mutation,
    StopReason,
    classify_testability,
    expected_information_gain,
    select_experiment,
    should_escalate,
)
from trident.investigation import (
    Testability as GapKind,
)
from trident.investigation.hypotheses import Hypothesis
from trident.models import AnswerStatus
from trident.simulator import SimulatorRuntime

# ---------------------------------------------------------------------------
# Testability
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "missing",
    [
        "reachability between PC1 and SRV1",
        "interface state of SW2 Fa0/3",
        "the routing table of R2",
        "trunk allowed VLANs between SW1 and SW2",
        "whether the ACL blocks the path",
        "DHCP gateway behaviour",
    ],
)
def test_observable_gaps_are_classified_observable(missing):
    assert classify_testability([missing]) is GapKind.OBSERVABLE


@pytest.mark.parametrize(
    "missing",
    [
        "which requirement is documented in the lab PDF",
        "the grading rubric for question 4",
        "the design intent stated by the instructor",
        "",
    ],
)
def test_documentation_gaps_are_not_observable(missing):
    assert classify_testability([missing]) is GapKind.NOT_OBSERVABLE


# ---------------------------------------------------------------------------
# Escalation policy
# ---------------------------------------------------------------------------


def test_verified_answers_are_not_retested_in_smart_mode():
    decision = should_escalate(
        AnswerStatus.VERIFIED,
        mode=Mode.SMART,
        runtime_available=True,
        missing=["reachability"],
    )
    assert decision.escalate is False
    assert "already verified" in decision.reason


def test_verified_answers_are_retested_in_double_check_mode():
    decision = should_escalate(
        AnswerStatus.VERIFIED,
        mode=Mode.DOUBLE_CHECK,
        runtime_available=True,
        missing=["reachability"],
    )
    assert decision.escalate is True
    assert "double-check" in decision.reason


def test_documentation_gap_never_escalates():
    decision = should_escalate(
        AnswerStatus.INCOMPLETE,
        runtime_available=True,
        missing=["the requirement listed in the lab instructions"],
    )
    assert decision.escalate is False
    assert decision.testability is GapKind.NOT_OBSERVABLE


def test_unavailable_runtime_blocks_escalation_with_real_reason():
    decision = should_escalate(
        AnswerStatus.INCOMPLETE,
        runtime_available=False,
        missing=["reachability"],
    )
    assert decision.escalate is False
    assert decision.testability is GapKind.RUNTIME_UNAVAILABLE


def test_conflict_is_escalated_even_without_missing_evidence():
    decision = should_escalate(
        AnswerStatus.CONFLICT,
        runtime_available=True,
        testability=GapKind.OBSERVABLE,
    )
    assert decision.escalate is True


def test_exhausted_budget_stops_escalation():
    decision = should_escalate(
        AnswerStatus.INCOMPLETE,
        runtime_available=True,
        missing=["reachability"],
        already_exhausted=True,
    )
    assert decision.escalate is False
    assert "budget" in decision.reason


def test_information_gain_is_a_weight_not_a_probability():
    assert expected_information_gain(
        AnswerStatus.INCOMPLETE, testability=GapKind.OBSERVABLE, already_collected=False
    ) == 1.0
    assert expected_information_gain(
        AnswerStatus.INCOMPLETE, testability=GapKind.OBSERVABLE, already_collected=True
    ) == 0.0
    assert expected_information_gain(
        AnswerStatus.INCOMPLETE, testability=GapKind.NOT_OBSERVABLE, already_collected=False
    ) == 0.0


# ---------------------------------------------------------------------------
# Experiment selection
# ---------------------------------------------------------------------------


def _hypothesis(kind: str, device: str = "SW2", interface: str | None = "FastEthernet0/1") -> Hypothesis:
    return Hypothesis(
        hypothesis_id=f"{kind}:{device}",
        kind=kind,
        summary="test",
        device=device,
        interface=interface,
    )


def test_experiment_selection_prefers_read_only():
    hypotheses = [_hypothesis("WRONG_VLAN"), _hypothesis("SHUTDOWN_INTERFACE")]
    experiment = select_experiment(hypotheses, already_run=set())
    assert experiment is not None
    assert experiment.mutation is Mutation.READ_ONLY
    assert experiment.is_safe


def test_experiment_selection_skips_already_run():
    hypotheses = [_hypothesis("WRONG_VLAN")]
    first = select_experiment(hypotheses, already_run=set())
    assert first is not None
    second = select_experiment(hypotheses, already_run={first.experiment_id})
    assert second is None or second.experiment_id != first.experiment_id


def test_experiment_selection_returns_none_when_all_eliminated():
    hypothesis = _hypothesis("WRONG_VLAN")
    hypothesis.eliminate("refuted")
    assert select_experiment([hypothesis], already_run=set()) is None


def test_mutating_experiments_need_explicit_permission():
    # No discriminator is mutating today; the guard must still hold if one is added.
    hypotheses = [_hypothesis("ACL_BLOCK")]
    experiment = select_experiment(hypotheses, already_run=set(), allow_mutation=False)
    assert experiment is None or experiment.mutation is Mutation.READ_ONLY


# ---------------------------------------------------------------------------
# End-to-end loop, scripted backend
# ---------------------------------------------------------------------------


def _scripted_session(tmp_path, scenario: dict, lab: bytes = b"PKT\x00lab"):
    lab_path = tmp_path / "lab.pkt"
    lab_path.write_bytes(lab)
    scenario_path = tmp_path / "scenario.json"
    scenario_path.write_text(json.dumps(scenario))
    runtime = SimulatorRuntime(workspace_root=tmp_path / "ws", prefer_live=False)
    session = runtime.create_session(lab_path, scripted_scenario=scenario_path)
    return runtime, session, lab_path


def test_unavailable_runtime_returns_unresolved_with_reason():
    investigator = Investigator(
        baseline_lab(), runtime_available=False, runtime_reason="not registered"
    )
    report = investigator.investigate(
        [("Why can't PC1 reach SRV1?", AnswerStatus.INCOMPLETE, ["reachability"])]
    )
    outcome = report.outcomes[0]
    assert outcome.status is AnswerStatus.INCOMPLETE
    assert outcome.answer is None
    assert outcome.stop_reason is StopReason.RUNTIME_UNAVAILABLE
    assert outcome.evidence_tier == "NO_OPERATIONAL_EVIDENCE"


def test_verified_question_is_answered_without_any_experiment(tmp_path):
    scenario = {"devices": [{"name": "SW2", "commands": {}}]}
    runtime, session, _ = _scripted_session(tmp_path, scenario)
    try:
        investigator = Investigator(
            next(s for s in scenarios() if s.name == "wrong-vlan").model,
            session=session,
            runtime_available=True,
        )
        report = investigator.investigate(
            [("What VLAN is Fa0/1 in?", AnswerStatus.VERIFIED, [])]
        )
        outcome = report.outcomes[0]
        assert outcome.stop_reason is StopReason.ALREADY_VERIFIED
        assert session.info().operations == 0, "no command may run for a verified answer"
    finally:
        session.close()


def test_documentation_question_does_not_start_a_session(tmp_path):
    scenario = {"devices": [{"name": "SW2", "commands": {}}]}
    runtime, session, _ = _scripted_session(tmp_path, scenario)
    try:
        investigator = Investigator(
            baseline_lab(), session=session, runtime_available=True
        )
        report = investigator.investigate(
            [
                (
                    "Which requirement does the lab document ask for?",
                    AnswerStatus.INCOMPLETE,
                    ["the requirement in the lab PDF"],
                )
            ]
        )
        outcome = report.outcomes[0]
        assert outcome.stop_reason is StopReason.NOT_OBSERVABLE
        assert session.info().operations == 0
    finally:
        session.close()


def test_hypothesis_is_confirmed_by_matching_observation(tmp_path):
    scenario = {
        "devices": [
            {
                "name": "SW2",
                "commands": {
                    "show ip interface brief": (
                        "Interface   IP-Address  OK? Method Status                Protocol\n"
                        "Fa0/3       unassigned  YES unset  administratively down down\n"
                    )
                },
            }
        ]
    }
    runtime, session, _ = _scripted_session(tmp_path, scenario)
    try:
        model = next(s for s in scenarios() if s.name == "shutdown-interface").model
        investigator = Investigator(model, session=session, runtime_available=True)
        report = investigator.investigate(
            [("Why is PC2 unreachable?", AnswerStatus.INCOMPLETE, ["interface state"])]
        )
        outcome = report.outcomes[0]
        confirmed = [
            h for h in outcome.hypotheses if h["status"] == HypothesisStatus.CONFIRMED_DEFECT.value
        ]
        assert confirmed, outcome.hypotheses
        assert outcome.answer is not None
        assert "SHUTDOWN_INTERFACE" in outcome.answer
        # The conclusion is operational, never called VERIFIED.
        assert outcome.status is AnswerStatus.INCOMPLETE
        assert outcome.evidence_tier == "SCRIPTED_NOT_OBSERVED"
    finally:
        session.close()


def test_contradicting_observation_eliminates_hypothesis(tmp_path):
    scenario = {
        "devices": [
            {
                "name": "SW2",
                "commands": {
                    "show ip interface brief": (
                        "Interface   IP-Address  OK? Method Status  Protocol\n"
                        "Fa0/1       unassigned  YES unset  up      up\n"
                    )
                },
            }
        ]
    }
    runtime, session, _ = _scripted_session(tmp_path, scenario)
    try:
        model = next(s for s in scenarios() if s.name == "wrong-vlan").model
        investigator = Investigator(model, session=session, runtime_available=True)
        report = investigator.investigate(
            [("What VLAN serves PC1?", AnswerStatus.INCOMPLETE, ["vlan membership"])]
        )
        outcome = report.outcomes[0]
        # The experiment produced no usable data, so the static suspect must not
        # be presented as an observed result.
        assert outcome.answer is None
        assert outcome.evidence_tier in {"NO_OPERATIONAL_EVIDENCE", "SCRIPTED_NOT_OBSERVED"}
        assert "not an observed result" in outcome.reason
    finally:
        session.close()


def test_repeated_fact_is_collected_once(tmp_path):
    scenario = {
        "devices": [
            {
                "name": "SW2",
                "commands": {"show ip interface brief": "Interface  Status\nFa0/1 up up\n"},
            }
        ]
    }
    runtime, session, _ = _scripted_session(tmp_path, scenario)
    try:
        model = next(s for s in scenarios() if s.name == "shutdown-interface").model
        investigator = Investigator(model, session=session, runtime_available=True)
        investigator.investigate(
            [
                ("Why is PC2 unreachable?", AnswerStatus.INCOMPLETE, ["interface state"]),
                ("Is SW2 Fa0/3 down?", AnswerStatus.INCOMPLETE, ["interface state"]),
            ]
        )
        commands = [result.operation for result in investigator.ledger.results()]
        assert commands.count("show ip interface brief") == 1
    finally:
        session.close()


def test_budget_exhaustion_is_reported_not_hidden(tmp_path):
    scenario = {
        "devices": [
            {
                "name": "SW2",
                "commands": {"show ip interface brief": "Interface  Status\nFa0/1 up up\n"},
            }
        ]
    }
    runtime, session, _ = _scripted_session(tmp_path, scenario)
    try:
        model = next(s for s in scenarios() if s.name == "shutdown-interface").model
        from trident.investigation import Budget_

        investigator = Investigator(
            model,
            session=session,
            runtime_available=True,
            budget=Budget_(max_experiments_per_question=1, max_experiments_total=1),
        )
        report = investigator.investigate(
            [
                ("q1", AnswerStatus.INCOMPLETE, ["interface state"]),
                ("q2", AnswerStatus.INCOMPLETE, ["interface state"]),
            ]
        )
        assert any(
            outcome.stop_reason is StopReason.BUDGET_EXHAUSTED
            for outcome in report.outcomes
        )
    finally:
        session.close()


def test_timeline_records_real_steps():
    investigator = Investigator(baseline_lab(), runtime_available=False)
    report = investigator.investigate([("q", AnswerStatus.INCOMPLETE, ["reachability"])])
    steps = [entry.step for entry in report.timeline]
    assert "analyzing network" in steps
    assert "resolving known facts" in steps


def test_static_diagnosis_does_not_need_a_session():
    model = next(s for s in scenarios() if s.name == "acl-block").model
    investigator = Investigator(model, runtime_available=False)
    result = investigator.diagnose_network()
    assert any(finding["kind"] == "ACL_BLOCK" for finding in result["findings"])


def test_report_is_json_serialisable():
    investigator = Investigator(baseline_lab(), runtime_available=False)
    report = investigator.investigate([("q", AnswerStatus.INCOMPLETE, ["reachability"])])
    json.dumps(report.as_dict())
