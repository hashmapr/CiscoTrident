"""Phase 2 — Practice-Lab Task Tracker tests.

The tracker adds no evaluation logic of its own, so these tests pin the two
things it *is* responsible for:

* bookkeeping fidelity -- one entry per instruction line, stable ``task_id``s
  across a reassessment, and a preserved reason for anything unparseable;
* honest arithmetic -- ``progress_pct`` divides by *evaluable* tasks only, so an
  unreadable instruction sheet can neither inflate nor deflate progress.

Every assertion is on exact values, not ranges, so a regression in either area
fails loudly.
"""

from __future__ import annotations

import json

from trident.models import DeviceInfo, InterfaceInfo, NetworkModel
from trident.tracker import (
    EVALUABLE_STATES,
    TaskBoard,
    TaskState,
    build_board,
    reassess,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ADDRESS_LINE = "Configure 192.168.10.1/24 on R1 GigabitEthernet0/0"
WRONG_ADDRESS_LINE = "Configure 10.9.9.1/24 on R1 GigabitEthernet0/0"
UNPARSEABLE_LINE = "Review the topology diagram carefully."
UNSUPPORTED_LINE = "Configure 192.168.10.1/24 on R99 GigabitEthernet0/0"


def _doc(*lines: str) -> str:
    """Assemble a lab instruction document, one instruction per line."""
    return "\n".join(lines)


def _model(address: str = "192.168.10.1") -> NetworkModel:
    """One router with a single addressed interface, snapshot ``block0``."""
    return NetworkModel(
        devices={
            "R1": DeviceInfo(
                id="R1",
                name="R1",
                hostname="R1",
                configuration=[
                    "hostname R1",
                    "interface GigabitEthernet0/0",
                    f"ip address {address} 255.255.255.0",
                    "no shutdown",
                ],
            ),
        },
        interfaces={
            "R1:GigabitEthernet0/0": InterfaceInfo(
                device="R1",
                name="GigabitEthernet0/0",
                canonical_name="GigabitEthernet0/0",
                ipv4_address=address,
                subnet_mask="255.255.255.0",
                prefix_length=24,
            ),
        },
        snapshot_id="block0",
    )


def _board(text: str, address: str = "192.168.10.1") -> TaskBoard:
    return build_board(_model(address), text, lab_title="Mixed lab")


def _entry(board: TaskBoard, text: str):
    for entry in board.entries:
        if entry.text == text:
            return entry
    raise AssertionError(f"no entry for {text!r} in {[e.text for e in board.entries]}")


# ---------------------------------------------------------------------------
# 1. One entry per instruction line
# ---------------------------------------------------------------------------

def test_mixed_document_yields_one_entry_per_non_blank_line():
    text = _doc(
        ADDRESS_LINE,
        WRONG_ADDRESS_LINE,
        UNPARSEABLE_LINE,
        "Configure 2001:db8::1/64 on R1 GigabitEthernet0/0",
        UNSUPPORTED_LINE,
    )
    board = _board(text)

    assert len(board.entries) == 5
    assert [e.text for e in board.entries] == text.splitlines()
    assert board.lab_title == "Mixed lab"
    assert board.snapshot_id == "block0"

    # Every state named in the spec is produced by real engine output, not
    # invented by the tracker.
    states = [e.state for e in board.entries]
    assert states[0] is TaskState.SATISFIED
    assert states[1] is TaskState.UNSATISFIED
    assert states[2] is TaskState.NOT_EVALUATED
    assert states[3] is TaskState.NOT_EVALUATED
    assert states[4] is TaskState.UNSUPPORTED

    # Requirement ids are the parser's, in source order.
    assert [e.requirement_id for e in board.entries] == [
        "REQ-0001",
        "REQ-0002",
        "REQ-0003",
        "REQ-0004",
        "REQ-0005",
    ]


def test_task_ids_are_unique():
    board = _board(_doc(ADDRESS_LINE, WRONG_ADDRESS_LINE, UNPARSEABLE_LINE))
    ids = [e.task_id for e in board.entries]
    assert len(set(ids)) == len(ids)


def test_duplicate_identical_instructions_get_distinct_task_ids():
    text = _doc(ADDRESS_LINE, ADDRESS_LINE)
    board = _board(text)
    assert len(board.entries) == 2
    assert board.entries[0].task_id != board.entries[1].task_id
    assert board.summary()["SATISFIED"] == 2


# ---------------------------------------------------------------------------
# 2. progress_pct arithmetic — unsupported excluded from the denominator
# ---------------------------------------------------------------------------

def test_progress_pct_excludes_unsupported_entries_arithmetic():
    """1 satisfied, 1 unsatisfied, 1 unsupported.

    Evaluable == 2 (the two the snapshot can speak to), satisfied == 1, so
    progress is exactly 50%. Counting the whole board would give 33.33%, and
    counting only the satisfied-but-not-unsatisfied set would give 100% -- both
    are explicitly ruled out below.
    """
    text = _doc(ADDRESS_LINE, WRONG_ADDRESS_LINE, UNSUPPORTED_LINE)
    board = _board(text)

    assert board.summary() == {
        "SATISFIED": 1,
        "UNSATISFIED": 1,
        "PARTIALLY_SATISFIED": 0,
        "INDETERMINATE": 0,
        "UNSUPPORTED": 1,
        "NOT_EVALUATED": 0,
    }

    evaluable = [e for e in board.entries if e.state in EVALUABLE_STATES]
    assert len(evaluable) == 2
    assert len(board.entries) == 3

    assert board.progress_pct() == 100.0 * 1 / 2
    assert board.progress_pct() == 50.0
    # Explicitly NOT satisfied / all, and NOT satisfied / (all - unsupported)
    # computed any other way.
    assert board.progress_pct() != 100.0 * 1 / 3
    assert board.progress_pct() != 100.0


def test_progress_pct_excludes_not_evaluated_entries():
    """An unparseable line must not deflate progress.

    1 satisfied + 1 unparseable -> denominator is 1, progress is 100%. If the
    unparseable line were counted the result would be 50%.
    """
    board = _board(_doc(ADDRESS_LINE, UNPARSEABLE_LINE))

    assert len(board.entries) == 2
    assert len(board.evaluable()) == 1
    assert board.progress_pct() == 100.0
    assert board.progress_pct() != 50.0


def test_progress_pct_is_zero_when_nothing_is_evaluable():
    board = _board(_doc(UNPARSEABLE_LINE, UNSUPPORTED_LINE))
    assert board.evaluable() == []
    assert board.progress_pct() == 0.0


def test_partially_satisfied_is_evaluable_but_is_not_progress():
    """A /16 on a /24 requirement is PARTIALLY_SATISFIED: evaluable, not done."""
    board = _board("Configure 192.168.10.1/16 on R1 GigabitEthernet0/0")
    entry = board.entries[0]
    assert entry.state is TaskState.PARTIALLY_SATISFIED
    assert len(board.evaluable()) == 1
    assert board.progress_pct() == 0.0


# ---------------------------------------------------------------------------
# 3. Reassessment
# ---------------------------------------------------------------------------

def test_reassess_flips_unsatisfied_to_satisfied_and_records_previous_state():
    text = WRONG_ADDRESS_LINE

    before = build_board(_model("192.168.10.1"), text, lab_title="Lab 1")
    assert before.entries[0].state is TaskState.UNSATISFIED
    assert before.entries[0].rechecked_from is None
    assert before.progress_pct() == 0.0

    after = reassess(before, _model("10.9.9.1"), text)

    entry = after.entries[0]
    assert entry.state is TaskState.SATISFIED
    assert entry.rechecked_from == "UNSATISFIED"
    assert entry.task_id == before.entries[0].task_id
    assert entry.evidence, "a flipped-to-SATISFIED task must cite evidence"
    assert after.progress_pct() == 100.0
    assert after.lab_title == "Lab 1"


def test_reassess_preserves_task_id_for_unchanged_instructions():
    text = _doc(ADDRESS_LINE, WRONG_ADDRESS_LINE, UNPARSEABLE_LINE)
    before = build_board(_model("192.168.10.1"), text)

    after = reassess(before, _model("10.9.9.1"), text)

    assert [e.task_id for e in after.entries] == [e.task_id for e in before.entries]
    assert [e.text for e in after.entries] == [e.text for e in before.entries]

    # Nothing about the instruction text changed, so every task keeps its id and
    # records exactly the state it held on the previous board. The model change
    # swaps which address line is satisfied.
    for previous, current in zip(before.entries, after.entries, strict=True):
        assert current.task_id == previous.task_id
        assert current.rechecked_from == previous.state.value

    # The unparseable line is unaffected by any model change.
    unparsed = _entry(after, UNPARSEABLE_LINE)
    assert unparsed.state is TaskState.NOT_EVALUATED
    assert unparsed.rechecked_from == "NOT_EVALUATED"

    # A task that changed state records the state it moved away from.
    flipped = _entry(after, WRONG_ADDRESS_LINE)
    assert flipped.state is TaskState.SATISFIED
    assert flipped.rechecked_from == "UNSATISFIED"


def test_reassess_marks_a_new_instruction_as_first_seen():
    before = build_board(_model(), ADDRESS_LINE)
    after = reassess(before, _model(), _doc(ADDRESS_LINE, WRONG_ADDRESS_LINE))

    new_entry = _entry(after, WRONG_ADDRESS_LINE)
    assert new_entry.rechecked_from is None
    assert _entry(after, ADDRESS_LINE).rechecked_from == "SATISFIED"


def test_reassess_returns_a_new_board_and_does_not_mutate_the_old_one():
    text = WRONG_ADDRESS_LINE
    before = build_board(_model("192.168.10.1"), text)
    snapshot = [(e.task_id, e.state, e.rechecked_from) for e in before.entries]

    after = reassess(before, _model("10.9.9.1"), text)

    assert after is not before
    assert [(e.task_id, e.state, e.rechecked_from) for e in before.entries] == snapshot


# ---------------------------------------------------------------------------
# 4. Unparseable instructions are preserved, never dropped
# ---------------------------------------------------------------------------

def test_unparseable_line_becomes_not_evaluated_with_a_reason():
    board = _board(UNPARSEABLE_LINE)

    assert len(board.entries) == 1
    entry = board.entries[0]
    assert entry.state is TaskState.NOT_EVALUATED
    assert entry.text == UNPARSEABLE_LINE
    assert entry.evidence, "the reason must be preserved on the entry"
    reason = entry.evidence[0]
    assert reason.startswith("not evaluated: ")
    assert "not parsed" in reason
    assert entry.remediation_available is False


def test_kind_without_an_evaluator_is_not_evaluated_with_a_reason():
    line = "Configure 2001:db8::1/64 on R1 GigabitEthernet0/0"
    board = _board(line)

    entry = board.entries[0]
    assert entry.state is TaskState.NOT_EVALUATED
    assert entry.kind == "ipv6_address"
    assert "no compliance evaluator" in entry.evidence[0]


def test_blank_lines_do_not_create_entries():
    board = _board(f"\n\n{ADDRESS_LINE}\n\n   \n")
    assert len(board.entries) == 1


# ---------------------------------------------------------------------------
# 5. SATISFIED always carries evidence
# ---------------------------------------------------------------------------

def test_every_satisfied_entry_has_evidence():
    text = _doc(ADDRESS_LINE, WRONG_ADDRESS_LINE, UNPARSEABLE_LINE, UNSUPPORTED_LINE)
    board = _board(text)

    satisfied = [e for e in board.entries if e.state is TaskState.SATISFIED]
    assert satisfied, "the fixture must produce at least one satisfied task"
    for entry in satisfied:
        assert entry.evidence, f"{entry.task_id} is SATISFIED with no evidence"
        assert all(isinstance(item, str) and item for item in entry.evidence)


def test_satisfied_evidence_names_its_source():
    entry = _board(ADDRESS_LINE).entries[0]
    assert entry.state is TaskState.SATISFIED
    joined = " ".join(entry.evidence)
    assert "running-config line" in joined or "normalized model" in joined


# ---------------------------------------------------------------------------
# 6. Summary counts and serialisation
# ---------------------------------------------------------------------------

def test_summary_counts_sum_to_the_number_of_entries():
    text = _doc(
        ADDRESS_LINE,
        ADDRESS_LINE,
        WRONG_ADDRESS_LINE,
        UNPARSEABLE_LINE,
        "Configure 2001:db8::1/64 on R1 GigabitEthernet0/0",
        UNSUPPORTED_LINE,
    )
    board = _board(text)
    summary = board.summary()

    assert len(board.entries) == 6
    assert sum(summary.values()) == len(board.entries)
    assert set(summary) == {state.value for state in TaskState}
    assert summary["SATISFIED"] == 2
    assert summary["UNSATISFIED"] == 1
    assert summary["NOT_EVALUATED"] == 2
    assert summary["UNSUPPORTED"] == 1


def test_summary_always_names_every_state_including_zero_counts():
    summary = _board(ADDRESS_LINE).summary()
    assert summary == {
        "SATISFIED": 1,
        "UNSATISFIED": 0,
        "PARTIALLY_SATISFIED": 0,
        "INDETERMINATE": 0,
        "UNSUPPORTED": 0,
        "NOT_EVALUATED": 0,
    }


def test_outstanding_is_everything_not_confirmed_satisfied():
    text = _doc(ADDRESS_LINE, WRONG_ADDRESS_LINE, UNPARSEABLE_LINE, UNSUPPORTED_LINE)
    board = _board(text)

    outstanding = board.outstanding()
    assert len(outstanding) == 3
    assert all(e.state is not TaskState.SATISFIED for e in outstanding)
    # Unsupported and unparsed work is still outstanding: a human must look.
    assert {e.state for e in outstanding} == {
        TaskState.UNSATISFIED,
        TaskState.NOT_EVALUATED,
        TaskState.UNSUPPORTED,
    }


def test_to_dict_round_trips_through_json():
    text = _doc(ADDRESS_LINE, WRONG_ADDRESS_LINE, UNPARSEABLE_LINE, UNSUPPORTED_LINE)
    board = _board(text)

    payload = board.to_dict()
    round_tripped = json.loads(json.dumps(payload))

    assert round_tripped == payload
    assert round_tripped["lab_title"] == "Mixed lab"
    assert round_tripped["snapshot_id"] == "block0"
    assert len(round_tripped["entries"]) == len(board.entries)
    assert round_tripped["summary"] == board.summary()
    assert round_tripped["progress_pct"] == board.progress_pct()

    first = round_tripped["entries"][0]
    assert first["state"] == "SATISFIED"
    assert first["task_id"].startswith("TASK-")
    assert isinstance(first["evidence"], list)
    assert first["rechecked_from"] is None
    assert set(first) == {
        "task_id",
        "requirement_id",
        "text",
        "kind",
        "device",
        "state",
        "evidence",
        "remediation_available",
        "rechecked_from",
    }


def test_to_dict_after_reassess_records_rechecked_from_as_a_string():
    before = build_board(_model("192.168.10.1"), WRONG_ADDRESS_LINE)
    after = reassess(before, _model("10.9.9.1"), WRONG_ADDRESS_LINE)

    payload = json.loads(json.dumps(after.to_dict()))
    assert payload["entries"][0]["rechecked_from"] == "UNSATISFIED"
    assert payload["entries"][0]["state"] == "SATISFIED"


# ---------------------------------------------------------------------------
# 7. Remediation is advertised, never executed
# ---------------------------------------------------------------------------

def test_remediation_availability_tracks_the_workflow():
    unsatisfied = _board(WRONG_ADDRESS_LINE).entries[0]
    satisfied = _board(ADDRESS_LINE).entries[0]
    unsupported = _board(UNSUPPORTED_LINE).entries[0]

    assert unsatisfied.remediation_available is True
    assert satisfied.remediation_available is False
    assert unsupported.remediation_available is False


def test_generate_remediation_false_disables_advertisement():
    board = build_board(
        _model("192.168.10.1"), WRONG_ADDRESS_LINE, generate_remediation=False
    )
    assert board.entries[0].state is TaskState.UNSATISFIED
    assert board.entries[0].remediation_available is False
