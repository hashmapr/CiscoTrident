"""Adversarial MCQ / entity-resolution tests.

Each test pins a false-positive class that string matching historically allowed:
substring collisions, VLAN 10 vs 100, Gi0/1 vs Gi0/10, device names containing
other device names, duplicate options, a correct value inside a false sentence,
and negated options.
"""

from __future__ import annotations

from trident.models import (
    AnswerStatus,
    DeviceInfo,
    NetworkModel,
    ParsedQuestion,
    QuestionKind,
    QuestionOption,
)
from trident.reasoning import mcq
from trident.reasoning.entities import resolve_device_name
from trident.verification.validators import resolve_device


def q(options, kind=QuestionKind.SINGLE_SELECT, stem="Which one?"):
    return ParsedQuestion(
        question_number=1,
        original=stem,
        stem=stem,
        kind=kind,
        options=[QuestionOption(letter=l, text=t) for l, t in options],
    )


# ---------------------------------------------------------------------------
# Substring false positives
# ---------------------------------------------------------------------------

def test_vlan_10_does_not_match_vlan_100():
    question = q([("A", "VLAN 100"), ("B", "VLAN 10")])
    status, letters, _ = mcq.match_single(question, "10")
    assert status is AnswerStatus.VERIFIED
    assert letters == ["B"], "VLAN 10 must not match VLAN 100"


def test_vlan_100_does_not_match_vlan_10():
    question = q([("A", "VLAN 10"), ("B", "VLAN 100")])
    status, letters, _ = mcq.match_single(question, "100")
    assert status is AnswerStatus.VERIFIED
    assert letters == ["B"]


def test_gi0_1_does_not_match_gi0_10():
    question = q([("A", "Gi0/10"), ("B", "Gi0/1")])
    status, letters, _ = mcq.match_single(question, "GigabitEthernet0/1")
    assert letters == ["B"]

    status2, letters2, _ = mcq.match_single(question, "GigabitEthernet0/10")
    assert letters2 == ["A"]


def test_switch_does_not_match_switch_backup():
    question = q([("A", "Switch-Backup"), ("B", "Switch")])
    status, letters, _ = mcq.match_single(question, "Switch")
    assert letters == ["B"]


def test_ip_192_168_1_1_does_not_match_192_168_1_10():
    question = q([("A", "192.168.1.10")])
    status, letters, _ = mcq.match_single(question, "192.168.1.1")
    assert status is AnswerStatus.CONFLICT
    assert letters == []


def test_correct_value_inside_incorrect_sentence_does_not_match():
    """A verified value embedded in a false sentence must NOT verify the option."""
    question = q([("A", "R1 has no address 192.168.1.1 configured")])
    status, letters, _ = mcq.match_single(question, "192.168.1.1")
    assert status is AnswerStatus.CONFLICT
    assert letters == []


def test_negated_option_does_not_match_positive_value():
    question = q([("A", "R1 is NOT 192.168.1.1"), ("B", "192.168.1.1")])
    status, letters, _ = mcq.match_single(question, "192.168.1.1")
    assert letters == ["B"]


def test_device_name_containing_another_is_not_confused():
    """The resolver must not pick 'Router-1' for a question about 'Router-10'."""
    model = NetworkModel(
        devices={
            "Router": DeviceInfo(id="Router", name="Router", hostname="Router"),
            "Router-1": DeviceInfo(id="Router-1", name="Router-1", hostname="Router-1"),
            "Router-10": DeviceInfo(id="Router-10", name="Router-10", hostname="Router-10"),
        }
    )
    assert resolve_device(model, "What is the IP of Router-10?") == "Router-10"
    assert resolve_device(model, "What is the IP of Router-1?") == "Router-1"
    assert resolve_device(model, "What is the IP of Router?") == "Router"


def test_ambiguous_device_mention_returns_none():
    """Two devices that tie on match length must not be resolved arbitrarily."""
    resolution = resolve_device_name(["hs", "HS"], "which of HS is up")
    assert resolution.name is None
    assert resolution.ambiguous


def test_exact_device_name_wins_over_substring():
    resolution = resolve_device_name(["Router", "Router-10"], "Router-10")
    assert resolution.name == "Router-10"
    assert resolution.rule == "exact"


def test_hostname_resolution():
    resolution = resolve_device_name(
        ["Device Name With Spaces"], "NodeRouter1", {"NodeRouter1": "Device Name With Spaces"}
    )
    assert resolution.name == "Device Name With Spaces"
    assert resolution.rule == "hostname"


def test_duplicate_equivalent_options_are_conflict():
    question = q([("A", "192.168.1.1"), ("B", "192.168.1.1")])
    status, letters, _ = mcq.match_single(question, "192.168.1.1")
    assert status is AnswerStatus.CONFLICT
    assert letters == ["A", "B"]


def test_equivalent_mac_formats_match():
    question = q([("A", "00:40:0b:1e:b6:01")])
    status, letters, _ = mcq.match_single(question, "0040.0B1E.B601")
    assert status is AnswerStatus.VERIFIED


def test_invalid_subnet_notation_never_matches():
    question = q([("A", "255.0.255.0")])
    status, letters, _ = mcq.match_single(question, "255.255.0.0")
    assert status is AnswerStatus.CONFLICT


def test_cidr_prefix_equivalence():
    question = q([("A", "192.168.1.0/24"), ("B", "192.168.1.0/25")])
    status, letters, _ = mcq.match_single(question, "192.168.1.0/24")
    assert status is AnswerStatus.VERIFIED
    assert letters == ["A"]


def test_no_options_match_is_conflict_not_closest():
    question = q([("A", "10.0.0.1"), ("B", "10.0.0.2")])
    status, letters, explanation = mcq.match_single(question, "192.168.1.1")
    assert status is AnswerStatus.CONFLICT
    assert letters == []
    assert "None of the offered options" in explanation


# ---------------------------------------------------------------------------
# Multi-select adjudication
# ---------------------------------------------------------------------------

def test_every_option_gets_true_false_unknown():
    question = q(
        [("A", "192.168.1.1"), ("B", "10.0.0.1"), ("C", "172.16.0.1")],
        kind=QuestionKind.MULTI_SELECT,
        stem="Which two? (Choose two.)",
    )
    verdicts = mcq.adjudicate_options(question, ["192.168.1.1"], ["10.0.0.1"])
    assert verdicts == {"A": "TRUE", "B": "FALSE", "C": "UNKNOWN"}


def test_unknown_option_blocks_verified_multiselect():
    question = q(
        [("A", "192.168.1.1"), ("B", "10.0.0.1"), ("C", "172.16.0.1")],
        kind=QuestionKind.MULTI_SELECT,
        stem="Which two? (Choose two.)",
    )
    status, letters, explanation = mcq.match_multi_independent(
        question, ["192.168.1.1"], ["10.0.0.1"]
    )
    assert status is AnswerStatus.INCOMPLETE
    assert letters == ["A"]
    assert "UNKNOWN" in explanation and "C" in explanation


def test_fully_adjudicated_multiselect_verifies():
    question = q(
        [("A", "192.168.1.1"), ("B", "10.0.0.1")],
        kind=QuestionKind.MULTI_SELECT,
        stem="Which one?",
    )
    status, letters, _ = mcq.match_multi_independent(question, ["192.168.1.1"], ["10.0.0.1"])
    assert status is AnswerStatus.VERIFIED
    assert letters == ["A"]


def test_choose_two_with_one_established_is_incomplete():
    question = q(
        [("A", "192.168.1.1"), ("B", "10.0.0.1"), ("C", "172.16.0.1")],
        kind=QuestionKind.MULTI_SELECT,
        stem="Which two? (Choose two.)",
    )
    status, letters, explanation = mcq.match_multi_independent(
        question, ["192.168.1.1"], ["10.0.0.1", "172.16.0.1"]
    )
    assert status is AnswerStatus.INCOMPLETE
    assert "expects 2" in explanation


def test_multiselect_ambiguous_mapping_conflicts():
    question = q(
        [("A", "192.168.1.1"), ("B", "192.168.1.1")],
        kind=QuestionKind.MULTI_SELECT,
    )
    status, _, _ = mcq.match_multi_independent(question, ["192.168.1.1"])
    assert status is AnswerStatus.CONFLICT


def test_multiselect_selected_but_false_is_conflict():
    """A value both established TRUE and FALSE must conflict, not verify."""
    question = q([("A", "192.168.1.1")], kind=QuestionKind.MULTI_SELECT, stem="Pick one")
    status, letters, explanation = mcq.match_multi_independent(
        question, ["192.168.1.1"], ["192.168.1.1"]
    )
    assert status is AnswerStatus.CONFLICT
    assert "established false" in explanation
