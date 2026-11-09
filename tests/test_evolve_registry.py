"""TRIDENT EVOLVE registry: trust rules and usability.

The whole value of the registry depends on one property: a record that was never
actually validated cannot be used as truth. These tests pin that boundary and
the append-only behaviour that makes the history auditable.
"""

from __future__ import annotations

import json

from trident.evolve import (
    EvidenceStrength,
    RecordState,
    Registry,
    RootCause,
    identity_of,
)


def _registry(tmp_path):
    return Registry(tmp_path / "registry.jsonl")


def _lesson(**overrides):
    base = {
        "lesson_id": "",
        "input_identity": "abc",
        "question": "Why is PC1 unreachable?",
        "predicted": "missing static route",
        "actual": "access port shut in the wrong VLAN",
        "incorrect_assumption": "a failed ping implies a routing fault",
        "root_cause": RootCause.REASONING_ERROR,
        "counterexample": "ping fails while the port is administratively down",
        "evidence": EvidenceStrength.SIMULATOR_OBSERVED,
        "state": RecordState.VALIDATED,
        "tags": ["reachability", "vlan"],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Trust rules
# ---------------------------------------------------------------------------


def test_a_validated_simulator_lesson_is_trusted(tmp_path):
    registry = _registry(tmp_path)
    lesson = registry.add(**_lesson())
    assert lesson.trusted is True
    assert registry.trusted() == [lesson]


def test_unverified_evidence_is_never_trusted(tmp_path):
    registry = _registry(tmp_path)
    registry.add(**_lesson(evidence=EvidenceStrength.UNVERIFIED))
    assert registry.trusted() == []


def test_static_reproduced_alone_is_not_enough(tmp_path):
    """A static guess repeated is still a guess about behaviour."""
    registry = _registry(tmp_path)
    registry.add(**_lesson(evidence=EvidenceStrength.STATIC_REPRODUCED))
    assert registry.trusted() == []


def test_consensus_is_enough(tmp_path):
    registry = _registry(tmp_path)
    registry.add(**_lesson(evidence=EvidenceStrength.CONSENSUS))
    assert len(registry.trusted()) == 1


def test_an_unvalidated_lesson_is_not_trusted(tmp_path):
    registry = _registry(tmp_path)
    registry.add(**_lesson(state=RecordState.INCOMPLETE))
    assert registry.trusted() == []


def test_a_validated_lesson_without_a_counterexample_is_downgraded(tmp_path):
    """Nothing to reproduce means nothing to learn from."""
    registry = _registry(tmp_path)
    lesson = registry.add(**_lesson(counterexample=""))
    assert lesson.state is RecordState.INCOMPLETE
    assert lesson.trusted is False


def test_a_rejected_lesson_is_not_trusted(tmp_path):
    registry = _registry(tmp_path)
    registry.add(**_lesson(state=RecordState.REJECTED))
    assert registry.trusted() == []


def test_trust_requires_both_state_and_strength(tmp_path):
    registry = _registry(tmp_path)
    registry.add(**_lesson(state=RecordState.VALIDATED, evidence=EvidenceStrength.UNVERIFIED))
    assert registry.trusted() == []


# ---------------------------------------------------------------------------
# Storage behaviour
# ---------------------------------------------------------------------------


def test_records_are_append_only(tmp_path):
    registry = _registry(tmp_path)
    registry.add(**_lesson(question="q1"))
    registry.add(**_lesson(question="q2"))
    lines = registry.path.read_text().strip().splitlines()
    assert len(lines) == 2
    assert [lesson.question for lesson in registry.all()] == ["q1", "q2"]


def test_ids_and_timestamps_are_assigned(tmp_path):
    registry = _registry(tmp_path)
    lesson = registry.add(**_lesson())
    assert lesson.lesson_id
    assert lesson.created_at
    assert "T" in lesson.created_at


def test_registry_file_is_private(tmp_path):
    import os
    import stat

    registry = _registry(tmp_path)
    registry.add(**_lesson())
    mode = stat.S_IMODE(os.stat(registry.path).st_mode)
    assert mode & 0o077 == 0


def test_a_corrupt_line_does_not_hide_the_rest(tmp_path):
    registry = _registry(tmp_path)
    registry.add(**_lesson(question="good"))
    with open(registry.path, "a", encoding="utf-8") as handle:
        handle.write("{not json}\n")
    registry.add(**_lesson(question="good2"))
    questions = [lesson.question for lesson in registry.all()]
    assert "good" in questions and "good2" in questions


def test_empty_registry_is_safe(tmp_path):
    registry = _registry(tmp_path)
    assert registry.all() == []
    assert registry.trusted() == []
    assert registry.summary()["total"] == 0


# ---------------------------------------------------------------------------
# Queries used by planning
# ---------------------------------------------------------------------------


def test_relevant_matches_tags_and_only_returns_trusted(tmp_path):
    registry = _registry(tmp_path)
    registry.add(**_lesson(question="trusted vlan", tags=["vlan"]))
    registry.add(**_lesson(question="untrusted vlan", tags=["vlan"],
                          evidence=EvidenceStrength.UNVERIFIED))
    registry.add(**_lesson(question="unrelated", tags=["acl"]))
    matches = registry.relevant(["vlan"])
    assert [lesson.question for lesson in matches] == ["trusted vlan"]


def test_relevant_respects_the_limit(tmp_path):
    registry = _registry(tmp_path)
    for index in range(5):
        registry.add(**_lesson(question=f"q{index}", tags=["routing"]))
    assert len(registry.relevant(["routing"], limit=2)) == 2


def test_relevant_with_no_tags_is_empty(tmp_path):
    registry = _registry(tmp_path)
    registry.add(**_lesson())
    assert registry.relevant([]) == []


def test_query_by_root_cause(tmp_path):
    registry = _registry(tmp_path)
    registry.add(**_lesson(root_cause=RootCause.PARSER_TIMEOUT))
    registry.add(**_lesson(root_cause=RootCause.DETECTOR_FALSE_POSITIVE))
    found = registry.by_root_cause(RootCause.PARSER_TIMEOUT)
    assert len(found) == 1


def test_query_by_input_identity(tmp_path):
    registry = _registry(tmp_path)
    registry.add(**_lesson(input_identity="aaa"))
    registry.add(**_lesson(input_identity="bbb"))
    assert len(registry.for_input("aaa")) == 1


def test_summary_counts_states_and_causes(tmp_path):
    registry = _registry(tmp_path)
    registry.add(**_lesson())
    registry.add(**_lesson(state=RecordState.INCOMPLETE))
    summary = registry.summary()
    assert summary["total"] == 2
    assert summary["trusted"] == 1
    assert summary["by_state"]["VALIDATED"] == 1


# ---------------------------------------------------------------------------
# Round-tripping and identity
# ---------------------------------------------------------------------------


def test_lesson_round_trips_through_json(tmp_path):
    registry = _registry(tmp_path)
    original = registry.add(**_lesson())
    reloaded = Registry(registry.path).all()[0]
    assert reloaded.as_dict()["lesson_id"] == original.lesson_id
    assert reloaded.evidence is original.evidence
    assert reloaded.state is original.state


def test_stored_json_is_human_readable(tmp_path):
    registry = _registry(tmp_path)
    registry.add(**_lesson())
    payload = json.loads(registry.path.read_text().strip())
    assert payload["root_cause"] == "REASONING_ERROR"
    assert payload["trusted"] is True


def test_identity_is_stable_and_content_addressed():
    assert identity_of(b"abc") == identity_of(b"abc")
    assert identity_of(b"abc") != identity_of(b"abd")
    assert len(identity_of(b"x")) == 64
