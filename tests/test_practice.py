"""Practice mode must score honestly and never leak the answer key.

The failure modes that matter here are not crashes:

* leaking the manifest into student output (the system stops teaching),
* awarding full marks for a vague guess (the score stops meaning anything),
* refusing full marks to a complete answer (the student is punished for
  being right), and
* letting a hint cost points it never charged.

Each is asserted directly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trident.labgen.broken_campus import TOPOLOGY
from trident.practice import (
    Finding,
    PracticeError,
    PracticeSession,
    parse_findings,
    render_instructor_markdown,
    render_markdown,
    score_submission,
    write_answer_key,
    write_reports,
)


@pytest.fixture
def session(tmp_path, monkeypatch) -> PracticeSession:
    """A session with no inherited hint progression."""
    monkeypatch.setattr(
        "trident.practice.HINT_STATE_FILE", tmp_path / "hints.json"
    )
    return PracticeSession(TOPOLOGY, difficulty="intermediate")


def _complete_findings() -> list[Finding]:
    """One finding per fault, stated as specifically as the fault allows."""
    out: list[Finding] = []
    for fault in TOPOLOGY.faults:
        if fault.interface:
            out.append(
                Finding(
                    device=fault.device,
                    interface=fault.interface,
                    category=fault.category.value,
                )
            )
        elif fault.target is not None and fault.device in {"PC-ADMIN-1", "PC-FACULTY-1"}:
            out.append(Finding(device=fault.device, category=fault.category.value))
        else:
            out.append(Finding(device=fault.device, category=fault.category.value))
    return out


# ---------------------------------------------------------------------------
# Answer-key separation
# ---------------------------------------------------------------------------


def test_objectives_do_not_name_the_defect(session: PracticeSession) -> None:
    """An objective states the goal, not the fault.

    Titles are category-level on purpose. If an objective said "VLAN 30 is
    renamed", the lab would be a reading exercise.
    """
    rendered = " ".join(f"{o.objective_id} {o.title}" for o in session.objectives()).lower()
    for leak in ("misconfigured", "wrong", "missing", "shutdown", "native vlan 1", "admin-pc"):
        assert leak not in rendered, f"objective text leaks {leak!r}"


def test_objectives_do_not_contain_expected_values(session: PracticeSession) -> None:
    rendered = " ".join(f"{o.objective_id} {o.title}" for o in session.objectives())
    for fault in TOPOLOGY.faults:
        # The expected IOS line must never appear in a student-facing objective.
        if fault.expected and len(fault.expected) > 6:
            assert fault.expected not in rendered, (
                f"objective leaks the expected value for {fault.fault_id}: "
                f"{fault.expected!r}"
            )


def test_objective_ids_are_unique(session: PracticeSession) -> None:
    """Duplicate ids made a hint request resolve to the wrong fault."""
    ids = [o.objective_id for o in session.objectives()]
    assert len(ids) == len(set(ids)), ids


def test_student_report_hides_expected_configuration(session: PracticeSession) -> None:
    score = score_submission(session, [Finding(device="R1")])
    report = render_markdown(score)
    for fault in TOPOLOGY.faults:
        if fault.expected and len(fault.expected) > 8:
            assert fault.expected not in report, (
                f"student report leaks {fault.expected!r}"
            )


def test_student_score_json_hides_expected_configuration(session: PracticeSession) -> None:
    """A missed fault's expected config must not appear in the student JSON.

    A *found* fault may show it: the student already named it, and confirming
    what the correct value was is teaching, not leaking. The distinction is the
    whole reason ``as_dict`` strips those fields only for missed lines.
    """
    score = score_submission(session, [Finding(device="R1")])
    found_ids = {line.fault_id for line in score.lines if line.correct}
    data = score.as_dict()
    for entry in data["lines"]:
        if entry["fault_id"] in found_ids:
            continue
        assert "expected" not in entry, f"{entry['fault_id']} leaks expected"
        assert "actual" not in entry, f"{entry['fault_id']} leaks actual"


def test_instructor_score_does_include_the_key(session: PracticeSession) -> None:
    """The same object can produce the key, but only when asked."""
    score = score_submission(session, [])
    data = score.as_dict(include_key=True)
    assert all("expected" in entry for entry in data["lines"])


def test_instructor_key_does_contain_the_answers(session: PracticeSession) -> None:
    """The key is the mirror image: it must contain what the report hides."""
    key = session.answer_key()
    assert key["point_total"] == 100
    assert len(key["faults"]) == len(TOPOLOGY.faults)
    for entry in key["faults"]:
        assert entry["expected"] and entry["actual"]
        assert entry["expected"] != entry["actual"], entry["fault_id"]


def test_instructor_markdown_has_expected_and_actual(tmp_path: Path, session) -> None:
    score = score_submission(session, [])
    text = render_instructor_markdown(session, score)
    assert "expected" in text and "actual" in text
    assert "192.168.30.1" in text


def test_write_reports_writes_two_files(tmp_path: Path, session) -> None:
    score = score_submission(session, [Finding(device="R1")])
    written = write_reports(session, score, tmp_path / "out")
    assert written["markdown"].is_file()
    assert written["json"].is_file()
    data = json.loads(written["json"].read_text())
    assert data["total_possible"] == 100


def test_write_answer_key_is_a_separate_explicit_act(tmp_path: Path, session) -> None:
    path = write_answer_key(session, tmp_path / "key.json")
    data = json.loads(path.read_text())
    assert data["faults"]
    # And the student report from the same session still hides it.
    score = score_submission(session, [])
    assert "192.168.30.1" not in render_markdown(score)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def test_a_complete_diagnosis_scores_full_marks(session: PracticeSession) -> None:
    """The regression that mattered: 15/15 scored 90 because precision was
    demanded for faults that live in a NIC or the VLAN database."""
    score = score_submission(session, _complete_findings())
    assert score.final_score == 100, [
        (line.fault_id, line.points_awarded, line.reason) for line in score.lines
    ]
    assert not score.missed


def test_full_marks_at_every_difficulty(tmp_path, monkeypatch) -> None:
    """Difficulty changes precision required, never the achievable maximum."""
    monkeypatch.setattr("trident.practice.HINT_STATE_FILE", tmp_path / "h.json")
    for difficulty in ("beginner", "intermediate", "advanced"):
        session = PracticeSession(TOPOLOGY, difficulty=difficulty)
        score = score_submission(session, _complete_findings())
        assert score.final_score == 100, (difficulty, score.final_score)


def test_an_empty_submission_scores_zero(session: PracticeSession) -> None:
    score = score_submission(session, [])
    assert score.final_score == 0
    assert len(score.missed) == len(TOPOLOGY.faults)


def test_a_wrong_device_earns_nothing_and_is_reported_spurious(
    session: PracticeSession,
) -> None:
    score = score_submission(session, [Finding(device="GHOST-1", category="VLAN")])
    assert score.final_score == 0
    assert score.spurious
    assert score.spurious[0].device == "GHOST-1"


def test_naming_the_right_device_alone_scores_at_beginner(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr("trident.practice.HINT_STATE_FILE", tmp_path / "h.json")
    session = PracticeSession(TOPOLOGY, difficulty="beginner")
    score = score_submission(session, [Finding(device="SW-ACCESS", interface="FastEthernet0/3")])
    assert score.final_score > 0


def test_advanced_requires_the_interface(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("trident.practice.HINT_STATE_FILE", tmp_path / "h.json")
    session = PracticeSession(TOPOLOGY, difficulty="advanced")
    score = score_submission(session, [Finding(device="SW-ACCESS", category="VLAN")])
    # Device-only on an interface fault earns nothing at advanced.
    assert score.final_score == 0


def test_a_finding_cannot_be_claimed_twice(session: PracticeSession) -> None:
    """Two faults on R1 must need two findings, not one."""
    one = score_submission(session, [Finding(device="R1")])
    two = score_submission(
        session,
        [
            Finding(device="R1", category="ROUTING"),
            Finding(device="R1", category="DHCP"),
        ],
    )
    assert two.raw_score > one.raw_score


def test_category_does_not_consume_the_wrong_fault(session: PracticeSession) -> None:
    """`R1 DHCP` must match a DHCP fault, not the routing fault on R1."""
    score = score_submission(
        session, [Finding(device="R1", category="DHCP")]
    )
    found = [line for line in score.lines if line.correct]
    assert found, "the DHCP claim matched nothing"
    assert all(line.category == "dhcp" for line in found), [
        (line.fault_id, line.category) for line in found
    ]


def test_points_never_exceed_the_total(session: PracticeSession) -> None:
    score = score_submission(session, _complete_findings())
    assert sum(line.points_awarded for line in score.lines) <= score.total_possible


# ---------------------------------------------------------------------------
# Hints
# ---------------------------------------------------------------------------


def test_hints_advance_then_refuse(session: PracticeSession) -> None:
    objective = session.objectives()[0].objective_id
    first = session.hint(objective)
    second = session.hint(objective)
    assert first.level == 1 and second.level == 2
    assert first.text != second.text
    with pytest.raises(PracticeError, match="no further hints"):
        session.hint(objective)


def test_hint_progress_persists_between_sessions(tmp_path, monkeypatch) -> None:
    """A CLI invocation is a new process; progress must survive it."""
    state = tmp_path / "hints.json"
    monkeypatch.setattr("trident.practice.HINT_STATE_FILE", state)
    objective = PracticeSession(TOPOLOGY).objectives()[0].objective_id
    PracticeSession(TOPOLOGY).hint(objective)
    # A brand-new session must see the hint already taken.
    fresh = PracticeSession(TOPOLOGY)
    assert fresh.hints_used.get(objective) == 1
    assert fresh.hint(objective).level == 2


def test_hint_penalty_is_charged_once(session: PracticeSession) -> None:
    objective = session.objectives()[0].objective_id
    session.hint(objective)
    assert session.hint_penalty() == 0, "level 1 should be free"
    session.hint(objective)
    penalty = session.hint_penalty()
    assert penalty > 0
    # Calling hint_penalty twice must not double-charge.
    assert session.hint_penalty() == penalty
    score = score_submission(session, [])
    assert score.final_score == 0


def test_hint_penalty_reduces_a_perfect_score(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("trident.practice.HINT_STATE_FILE", tmp_path / "h.json")
    session = PracticeSession(TOPOLOGY)
    objective = session.objectives()[0].objective_id
    session.hint(objective)
    session.hint(objective)
    score = score_submission(session, _complete_findings())
    assert score.final_score < 100
    assert score.final_score == 100 - score.hint_penalty


def test_unknown_objective_is_refused(session: PracticeSession) -> None:
    with pytest.raises(PracticeError, match="unknown objective"):
        session.hint("obj-does-not-exist")


# ---------------------------------------------------------------------------
# Submission parsing
# ---------------------------------------------------------------------------


def test_parse_findings_reads_device_interface_category() -> None:
    findings = parse_findings("R1\nSW-ACCESS Fa0/3 VLAN\n")
    assert findings[0].device == "R1"
    assert findings[1].interface == "Fa0/3"
    assert findings[1].category == "VLAN"


def test_a_category_word_is_not_an_interface() -> None:
    """`SW-DIST VLAN` used to parse "VLAN" as an interface name."""
    findings = parse_findings("SW-DIST VLAN\nR1 SECURITY\n")
    assert findings[0].interface is None and findings[0].category == "VLAN"
    assert findings[1].interface is None and findings[1].category == "SECURITY"


def test_a_real_interface_is_still_an_interface() -> None:
    findings = parse_findings("SW-ACCESS Vlan99\nR1 GigabitEthernet0/0.30\n")
    assert findings[0].interface == "Vlan99"
    assert findings[1].interface == "GigabitEthernet0/0.30"


def test_overlong_line_is_refused_with_the_line_number() -> None:
    with pytest.raises(PracticeError, match="line 1"):
        parse_findings("R1 Fa0/1 VLAN EXTRA TOKENS")


def test_comments_and_blanks_are_ignored() -> None:
    assert parse_findings("\n# a note\n\n") == []
