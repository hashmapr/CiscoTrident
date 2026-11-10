"""EVOLVE strategy advice: do validated lessons actually change behaviour?

The registry has stored lessons since the earlier sprint but nothing consumed
them, which made them a diary rather than a mechanism. This suite checks the
mechanism.

The safety property under test: only trusted lessons produce advice, and advice
never executes anything by itself.
"""

from __future__ import annotations

import pytest

from trident.evolve import (
    EvidenceStrength,
    Preference,
    RecordState,
    Registry,
    RootCause,
    advise,
    reorder_experiments,
)


@pytest.fixture()
def registry(tmp_path):
    return Registry(tmp_path / "lessons.jsonl")


def _lesson(**overrides):
    base = {
        "lesson_id": "",
        "input_identity": "net-abc",
        "question": "Why can't PC1 reach SRV1?",
        "predicted": "missing route",
        "actual": "port shut",
        "incorrect_assumption": "a failed ping implies a routing fault",
        "root_cause": RootCause.REASONING_ERROR,
        "counterexample": "ping failed while the port was administratively down",
        "evidence": EvidenceStrength.SIMULATOR_OBSERVED,
        "state": RecordState.VALIDATED,
        "tags": ["reachability"],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Only trusted lessons produce advice
# ---------------------------------------------------------------------------


def test_a_trusted_lesson_produces_advice(registry):
    registry.add(**_lesson())
    advice = advise(registry, ["reachability"])
    assert len(advice) == 1
    assert advice[0].preference is Preference.REQUIRE_EVIDENCE
    assert advice[0].lessons


def test_an_untrusted_lesson_produces_nothing(registry):
    registry.add(**_lesson(evidence=EvidenceStrength.UNVERIFIED))
    assert advise(registry, ["reachability"]) == []


def test_a_lesson_without_a_counterexample_produces_nothing(registry):
    registry.add(**_lesson(counterexample=""))
    assert advise(registry, ["reachability"]) == []


def test_an_unvalidated_lesson_produces_nothing(registry):
    registry.add(**_lesson(state=RecordState.INCOMPLETE))
    assert advise(registry, ["reachability"]) == []


def test_no_matching_tags_is_empty(registry):
    registry.add(**_lesson(tags=["vlans"]))
    assert advise(registry, ["ospf"]) == []


def test_empty_registry_gives_no_advice(registry):
    assert advise(registry, ["anything"]) == []


# ---------------------------------------------------------------------------
# Cause mapping
# ---------------------------------------------------------------------------


def test_a_false_positive_detector_is_deferred(registry):
    registry.add(**_lesson(root_cause=RootCause.DETECTOR_FALSE_POSITIVE, tags=["shutdown"]))
    advice = advise(registry, ["shutdown"])
    assert advice[0].preference is Preference.DEFER
    assert "false positive" in advice[0].reason


def test_a_false_negative_detector_requires_evidence(registry):
    registry.add(**_lesson(root_cause=RootCause.DETECTOR_FALSE_NEGATIVE, tags=["acl"]))
    advice = advise(registry, ["acl"])
    assert advice[0].preference is Preference.REQUIRE_EVIDENCE
    assert "silence as proof" in advice[0].reason


def test_repeated_lessons_merge_into_one_advice(registry):
    registry.add(**_lesson())
    registry.add(**_lesson())
    advice = advise(registry, ["reachability"])
    assert len(advice) == 1
    assert len(advice[0].lessons) == 2


# ---------------------------------------------------------------------------
# Reordering
# ---------------------------------------------------------------------------


def test_only_prefer_advice_reorders(registry):
    """DEFER is a note, not a permutation: it must not silently move things."""
    registry.add(**_lesson(root_cause=RootCause.DETECTOR_FALSE_POSITIVE, tags=["dns"]))
    advice = advise(registry, ["dns"])
    assert advice[0].preference is Preference.DEFER
    assert reorder_experiments(["show ip route", "show run"], advice) == [
        "show ip route",
        "show run",
    ]


def test_prefer_advice_moves_a_named_check_first():
    from trident.evolve.strategy import Advice

    advice = [Advice(preference=Preference.PREFER, target="show vlan", reason="x")]
    ordered = reorder_experiments(
        ["show ip route", "show vlan brief", "show interfaces"], advice
    )
    assert ordered[0] == "show vlan brief"


def test_reordering_with_no_advice_is_identity():
    assert reorder_experiments(["a", "b", "c"], []) == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# Advice does not act
# ---------------------------------------------------------------------------


def test_advice_is_inert(registry):
    """advise() must not execute, mutate the registry, or change any state."""
    registry.add(**_lesson())
    before = [l.as_dict() for l in registry.all()]
    advice = advise(registry, ["reachability"])
    after = [l.as_dict() for l in registry.all()]
    assert before == after
    assert all(isinstance(item.as_dict()["preference"], str) for item in advice)


def test_advice_serialises():
    import json

    from trident.evolve.strategy import Advice

    payload = Advice(
        preference=Preference.REQUIRE_EVIDENCE, target="reachability", reason="r", lessons=["l1"]
    ).as_dict()
    json.dumps(payload)
    assert payload["preference"] == "REQUIRE_EVIDENCE"
