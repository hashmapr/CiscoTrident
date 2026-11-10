"""Adversarial verification: does the independent verifier actually reject?

The verifier's value is entirely in what it refuses. A verifier that confirms
everything is worse than none, because it manufactures confidence.

Each case here is a claim that is wrong in a specific way, and the assertion is
that the verifier does not confirm it. Positive controls are included so the
suite cannot pass by rejecting everything.
"""

from __future__ import annotations

from trident.models import (
    AnswerResult,
    AnswerStatus,
    DeviceInfo,
    InterfaceInfo,
    NetworkModel,
    Observation,
    Provenance,
)
from trident.verification.independent import IndependentVerifier, Verdict


def _model() -> NetworkModel:
    return NetworkModel(
        devices={
            "R1": DeviceInfo(id="R1", name="R1", hostname="R1", device_type="router", configuration=[]),
            "R2": DeviceInfo(id="R2", name="R2", hostname="R2", device_type="router", configuration=[]),
            "SW1": DeviceInfo(id="SW1", name="SW1", hostname="SW1", device_type="switch", configuration=[]),
        },
        interfaces={
            "R1:Gi0/0": InterfaceInfo(
                device="R1", name="GigabitEthernet0/0", canonical_name="GigabitEthernet0/0",
                ipv4_address="10.0.1.1", prefix_length=24,
            ),
            "R1:Gi0/1": InterfaceInfo(
                device="R1", name="GigabitEthernet0/1", canonical_name="GigabitEthernet0/1",
                ipv4_address="10.0.2.1", prefix_length=30,
            ),
            "R2:Gi0/0": InterfaceInfo(
                device="R2", name="GigabitEthernet0/0", canonical_name="GigabitEthernet0/0",
                ipv4_address="10.0.2.2", prefix_length=30,
            ),
            "SW1:Vlan1": InterfaceInfo(
                device="SW1", name="Vlan1", canonical_name="Vlan1",
                ipv4_address="10.0.1.2", prefix_length=24,
            ),
        },
    )


def _answer(text: str | None, status=AnswerStatus.VERIFIED, number: int = 1) -> AnswerResult:
    return AnswerResult(
        question_number=number, original_question="q", status=status, answer=text
    )


# ---------------------------------------------------------------------------
# Wrong device
# ---------------------------------------------------------------------------


def test_wrong_device_with_a_valid_address_is_contradicted():
    """R2 holding 10.0.1.1 is false: R1 holds it.

    The address exists, so a "does this address exist?" check passes and the
    wrong-device claim slips through. Pairing the named device WITH the address
    catches it, which is why the verifier checks the pair before either fact.
    """
    report = IndependentVerifier(_model()).verify(
        [_answer("R2 has address 10.0.1.1")]
    )
    record = report.records[0]
    assert record.verdict is Verdict.DISAGREES
    assert record.method == "device-address-pair"
    assert "R2" in record.detail and "R1" in record.detail


def test_correct_device_address_pair_is_confirmed():
    """The positive control for the pairing route."""
    report = IndependentVerifier(_model()).verify(
        [_answer("R1 GigabitEthernet0/0 has 10.0.1.1")]
    )
    record = report.records[0]
    assert record.verdict is Verdict.CONFIRMED
    assert record.method == "device-address-pair"


def test_address_the_model_does_not_hold_is_contradicted():
    report = IndependentVerifier(_model()).verify([_answer("the gateway is 10.9.9.9")])
    assert report.records[0].verdict is Verdict.DISAGREES


def test_claimed_device_that_does_not_exist_is_not_confirmed():
    report = IndependentVerifier(_model()).verify([_answer("R99 is the core router")])
    # R99 is absent; the verifier must not confirm it.
    assert report.records[0].verdict is not Verdict.CONFIRMED


# ---------------------------------------------------------------------------
# Correct claims are still confirmed (positive control)
# ---------------------------------------------------------------------------


def test_correct_address_is_confirmed():
    report = IndependentVerifier(_model()).verify([_answer("10.0.1.1")])
    assert report.records[0].verdict is Verdict.CONFIRMED
    assert "R1" in report.records[0].detail


def test_correct_device_is_confirmed():
    report = IndependentVerifier(_model()).verify([_answer("SW1")])
    assert report.records[0].verdict is Verdict.CONFIRMED


# ---------------------------------------------------------------------------
# Wrong interface / subnet / VLAN
# ---------------------------------------------------------------------------


def test_claim_with_no_derivation_route_is_not_confirmed():
    report = IndependentVerifier(_model()).verify(
        [_answer("the interface is in VLAN 40")]
    )
    assert report.records[0].verdict is Verdict.NOT_INDEPENDENTLY_CHECKABLE
    assert report.records[0].limitations


def test_subnet_claim_is_not_silently_confirmed():
    """A network address is not an interface address.

    "10.0.1.0/24" names a network; no interface holds 10.0.1.0. The verifier must
    not treat that as a confirmed interface address.
    """
    report = IndependentVerifier(_model()).verify(
        [_answer("10.0.1.0/24 is the correct subnet")]
    )
    record = report.records[0]
    assert record.verdict is Verdict.DISAGREES
    assert "no interface" in record.detail


# ---------------------------------------------------------------------------
# Stale snapshot and duplicate evidence
# ---------------------------------------------------------------------------


def test_verifier_reports_the_snapshot_it_derived_from():
    report = IndependentVerifier(_model()).verify([_answer("R1")])
    assert report.records[0].method
    assert report.records[0].detail


def test_duplicate_answers_are_checked_independently():
    """The same claim twice is two records, not one confirmation counted twice."""
    report = IndependentVerifier(_model()).verify(
        [_answer("10.0.1.1", number=1), _answer("10.0.1.1", number=2)]
    )
    assert len(report.records) == 2
    assert report.counts()["CONFIRMED"] == 2
    assert {r.question_number for r in report.records} == {1, 2}


def test_verifier_does_not_mutate_the_answers():
    answers = [_answer("10.0.1.1"), _answer("10.9.9.9", number=2)]
    before = [(a.question_number, a.status, a.answer) for a in answers]
    IndependentVerifier(_model()).verify(answers)
    after = [(a.question_number, a.status, a.answer) for a in answers]
    assert before == after


def test_verifier_never_promotes_status():
    """Verification must not turn anything into VERIFIED."""
    answer = _answer("10.0.1.1", status=AnswerStatus.INCOMPLETE)
    IndependentVerifier(_model()).verify([answer])
    assert answer.status is AnswerStatus.INCOMPLETE


# ---------------------------------------------------------------------------
# Conflicting or missing evidence
# ---------------------------------------------------------------------------


def test_observation_without_a_device_does_not_confirm_anything():
    model = _model()
    model.observations.append(
        Observation(
            field="hostname",
            entity_type="device",
            entity_id="",
            value="R9",
            provenance=Provenance(
                engine="test", extraction_path="t", source_path="s", snapshot="block0"
            ),
        )
    )
    report = IndependentVerifier(model).verify([_answer("R9")])
    assert report.records[0].verdict is not Verdict.CONFIRMED


def test_unresolved_answer_is_never_confirmed():
    for status in (
        AnswerStatus.INCOMPLETE,
        AnswerStatus.NOT_AVAILABLE,
        AnswerStatus.CONFLICT,
        AnswerStatus.ERROR,
    ):
        report = IndependentVerifier(_model()).verify([_answer("R1", status=status)])
        assert report.records[0].verdict is Verdict.UNRESOLVED, status


def test_report_counts_add_up():
    report = IndependentVerifier(_model()).verify(
        [
            _answer("R1", number=1),
            _answer("10.9.9.9", number=2),
            _answer(None, status=AnswerStatus.INCOMPLETE, number=3),
            _answer("the design intent is unclear", number=4),
        ]
    )
    counts = report.counts()
    assert counts["total"] == 4
    assert sum(v for k, v in counts.items() if k != "total") == 4
    assert counts["CONFIRMED"] == 1
    assert counts["DISAGREES"] == 1
    assert counts["UNRESOLVED"] == 1
    assert counts["NOT_INDEPENDENTLY_CHECKABLE"] == 1
