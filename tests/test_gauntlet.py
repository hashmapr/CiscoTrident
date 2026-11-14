"""The gauntlet must be buildable, scorable, and honest about its numbers.

Two classes of failure are guarded here:

* **structural** — a lab that cannot be built, or does not total 100 points, is
  not a lab. Every difficulty is asserted to validate and generate.
* **arithmetic** — a benchmark that reports a percentage without its numerator
  is not evidence. The metric helpers are pinned to exact fractions on
  hand-built cases, so a later refactor cannot quietly turn 3/4 into "75%".
"""

from __future__ import annotations

import pytest

from trident.labgen import available, generate
from trident.labgen.gauntlet import (
    DIFFICULTIES,
    LAB_FAULTS,
    Metrics,
    all_labs,
    lab_for,
    probes_for,
    rebalance,
    score_findings,
)
from trident.labgen.spec import FaultSpec, Severity

_available, _why = available()

EXPECTED_FAULT_COUNTS = {
    "easy": 4,
    "basic": 6,
    "intermediate": 8,
    "advanced": 11,
    "expert": 13,
    "insane": 15,
}


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("difficulty", DIFFICULTIES)
def test_every_lab_validates(difficulty: str) -> None:
    lab = lab_for(difficulty)
    assert lab.validate() == [], lab.validate()


@pytest.mark.parametrize("difficulty", DIFFICULTIES)
def test_every_lab_totals_exactly_100_points(difficulty: str) -> None:
    assert lab_for(difficulty).point_total() == 100


@pytest.mark.parametrize("difficulty", DIFFICULTIES)
def test_fault_counts_increase_with_difficulty(difficulty: str) -> None:
    lab = lab_for(difficulty)
    assert len(lab.faults) == EXPECTED_FAULT_COUNTS[difficulty]


def test_difficulty_is_monotonic() -> None:
    """A harder lab must never contain fewer faults than an easier one."""
    counts = [len(lab_for(d).faults) for d in DIFFICULTIES]
    assert counts == sorted(counts), counts


def test_every_lab_names_are_unique() -> None:
    names = [lab_for(d).name for d in DIFFICULTIES]
    assert len(names) == len(set(names))


def test_unknown_difficulty_is_refused() -> None:
    with pytest.raises(KeyError, match="unknown difficulty"):
        lab_for("impossible")


def test_labs_reference_only_verified_faults() -> None:
    """Every fault in every lab must exist in the verified base set.

    A gauntlet whose hard labs invent faults would be a difficulty ramp made of
    guesses. The base set is the 15 proven observable in Packet Tracer.
    """
    from trident.labgen.broken_campus import TOPOLOGY

    known = {f.fault_id for f in TOPOLOGY.faults}
    for difficulty, ids in LAB_FAULTS.items():
        unknown = set(ids) - known
        assert not unknown, f"{difficulty} references unverified faults: {unknown}"


@pytest.mark.parametrize("difficulty", DIFFICULTIES)
def test_no_fault_id_is_repeated_within_a_lab(difficulty: str) -> None:
    ids = [f.fault_id for f in lab_for(difficulty).faults]
    assert len(ids) == len(set(ids)), ids


@pytest.mark.parametrize("difficulty", DIFFICULTIES)
def test_every_fault_still_has_hints_and_a_symptom(difficulty: str) -> None:
    for fault in lab_for(difficulty).faults:
        assert fault.hint_1 and fault.hint_2, fault.fault_id
        assert fault.symptom, fault.fault_id
        assert fault.points > 0, fault.fault_id


@pytest.mark.parametrize("difficulty", DIFFICULTIES)
def test_probes_name_real_devices(difficulty: str) -> None:
    lab = lab_for(difficulty)
    names = {d.name for d in lab.devices}
    for probe in probes_for(difficulty):
        assert probe.device in names, probe
        assert probe.command.startswith(("show", "ipconfig")), probe


def test_probes_cover_every_fault_or_are_documented() -> None:
    """A fault without a probe must be an ENDHOST fault, and nothing else."""
    from trident.labgen.spec import TargetKind

    lab = lab_for("insane")
    probed = {p.fault_id for p in probes_for("insane")}
    for fault in lab.faults:
        if fault.fault_id in probed:
            continue
        assert fault.target is TargetKind.ENDHOST, (
            f"{fault.fault_id} has no probe and is not an end-host fault"
        )


# ---------------------------------------------------------------------------
# Point rebalancing
# ---------------------------------------------------------------------------


def _fault(points: int, fault_id: str = "x") -> FaultSpec:
    return FaultSpec(
        fault_id=fault_id,
        category=__import__(
            "trident.labgen.spec", fromlist=["FaultCategory"]
        ).FaultCategory.VLAN,
        severity=Severity.MAJOR,
        device="SW1",
        interface=None,
        description="d",
        expected="a",
        actual="b",
        symptom="s",
        points=points,
        hint_1="h",
        hint_2="h2",
    )


def test_rebalance_preserves_an_exact_100() -> None:
    faults = [_fault(40, "a"), _fault(60, "b")]
    assert [f.points for f in rebalance(faults)] == [40, 60]


def test_rebalance_scales_up() -> None:
    faults = [_fault(10, "a"), _fault(10, "b")]
    out = rebalance(faults)
    assert sum(f.points for f in out) == 100
    assert out[0].points == out[1].points == 50


def test_rebalance_scales_down() -> None:
    faults = [_fault(100, "a"), _fault(100, "b")]
    out = rebalance(faults)
    assert sum(f.points for f in out) == 100


def test_rebalance_never_assigns_zero_points() -> None:
    """A 0-point fault cannot be scored, so it must not exist."""
    faults = [_fault(1, "tiny"), _fault(1000, "huge")]
    out = rebalance(faults)
    assert all(f.points >= 1 for f in out), [f.points for f in out]
    assert sum(f.points for f in out) == 100


def test_rebalance_is_exact_for_awkward_ratios() -> None:
    """Three equal faults cannot split 100 evenly; the total must still be 100."""
    faults = [_fault(1, "a"), _fault(1, "b"), _fault(1, "c")]
    out = rebalance(faults)
    assert sum(f.points for f in out) == 100


def test_rebalance_of_empty_is_empty() -> None:
    assert rebalance([]) == []


# ---------------------------------------------------------------------------
# Metrics arithmetic — exact fractions, no bare percentages
# ---------------------------------------------------------------------------


def test_metrics_precision_and_recall_are_fractions() -> None:
    m = Metrics("lab", "easy", faults=10, true_positives=3,
                false_positives=1, false_negatives=7)
    assert m.precision == (3, 4)
    assert m.recall == (3, 10)
    assert m.precision_pct == 75.0
    assert m.recall_pct == 30.0


def test_metrics_include_the_fraction_in_the_row() -> None:
    m = Metrics("lab", "easy", faults=10, true_positives=3,
                false_positives=1, false_negatives=7)
    row = m.row()
    assert "3/4" in row and "3/10" in row


def test_metrics_with_no_findings_reports_zero_over_zero() -> None:
    """A run that found nothing must say 0/0, not divide by zero or say 0%."""
    m = Metrics("lab", "easy", faults=5, true_positives=0,
                false_positives=0, false_negatives=5)
    assert m.precision == (0, 0)
    assert m.precision_pct is None
    assert "n/a (0/0)" in m.row()


def test_metrics_perfect_run() -> None:
    m = Metrics("lab", "easy", faults=4, true_positives=4,
                false_positives=0, false_negatives=0)
    assert m.precision == (4, 4)
    assert m.recall == (4, 4)


def test_score_findings_counts_a_perfect_submission() -> None:
    lab = lab_for("easy")
    claimed = {f.fault_id for f in lab.faults}
    m = score_findings(lab, claimed)
    assert (m.true_positives, m.false_positives, m.false_negatives) == (4, 0, 0)


def test_score_findings_counts_an_empty_submission() -> None:
    lab = lab_for("easy")
    m = score_findings(lab, set())
    assert (m.true_positives, m.false_positives, m.false_negatives) == (0, 0, 4)


def test_score_findings_counts_a_false_positive() -> None:
    lab = lab_for("easy")
    m = score_findings(lab, {"not-a-real-fault"})
    assert (m.true_positives, m.false_positives) == (0, 1)


def test_score_findings_counts_a_partial_run() -> None:
    lab = lab_for("basic")
    ids = [f.fault_id for f in lab.faults]
    m = score_findings(lab, set(ids[:2]) | {"bogus"})
    assert m.true_positives == 2
    assert m.false_positives == 1
    assert m.false_negatives == len(ids) - 2
    assert m.recall == (2, len(ids))


# ---------------------------------------------------------------------------
# Real generation
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _available, reason=_why)
@pytest.mark.parametrize("difficulty", DIFFICULTIES)
def test_every_lab_generates_a_decodable_pkt(tmp_path, difficulty) -> None:
    lab = lab_for(difficulty)
    result = generate(lab, tmp_path / f"{difficulty}.pkt", apply_faults=True)
    assert result.encode_ok, result.notes
    assert result.device_count == len(lab.devices)
    assert result.link_count == len(lab.links)


@pytest.mark.skipif(not _available, reason=_why)
@pytest.mark.parametrize("difficulty", DIFFICULTIES)
def test_each_lab_differs_from_its_reference(tmp_path, difficulty) -> None:
    lab = lab_for(difficulty)
    student = generate(lab, tmp_path / "s.pkt", apply_faults=True)
    reference = generate(lab, tmp_path / "r.pkt", apply_faults=False)
    assert student.sha256 != reference.sha256


@pytest.mark.skipif(not _available, reason=_why)
def test_generated_labs_keep_the_topology(tmp_path) -> None:
    from pkt_core.codec.container import decode
    from pkt_core.models import Lab

    for difficulty in DIFFICULTIES:
        lab = lab_for(difficulty)
        result = generate(lab, tmp_path / f"{difficulty}.pkt", apply_faults=True)
        decoded = Lab.from_bytes(decode(str(result.path)).xml)
        assert {d.name for d in decoded.devices} == {d.name for d in lab.devices}


# ---------------------------------------------------------------------------
# Practice integration
# ---------------------------------------------------------------------------


def test_each_lab_is_playable_with_the_practice_engine(tmp_path, monkeypatch) -> None:
    """A gauntlet lab must score like any other lab, including full marks."""
    from trident.practice import PracticeSession, score_submission

    monkeypatch.setattr("trident.practice.HINT_STATE_FILE", tmp_path / "h.json")
    lab = lab_for("expert")
    session = PracticeSession(lab, difficulty="advanced")

    findings = []
    for fault in lab.faults:
        from trident.practice import Finding

        findings.append(
            Finding(
                device=fault.device,
                interface=fault.interface,
                category=fault.category.value,
            )
        )
    score = score_submission(session, findings)
    assert score.total_possible == 100
    assert score.final_score == 100, [
        (line.fault_id, line.points_awarded, line.reason)
        for line in score.lines
        if line.points_awarded < line.points_possible
    ]


def test_the_gauntlet_is_listed_by_name() -> None:
    assert set(all_labs()) == set(DIFFICULTIES)
