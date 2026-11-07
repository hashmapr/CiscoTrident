"""Question parsing and multiple-choice matching tests."""

from __future__ import annotations

import pytest
from conftest import build_model, obs

from trident.config import Settings
from trident.models import AnswerStatus, QuestionKind
from trident.reasoning import mcq
from trident.reasoning.questions import QuestionParseError, parse_questions
from trident.verification.consensus import ConsensusEngine
from trident.verification.validators import AnswerBuilder

# --- question parsing ------------------------------------------------------

def test_parse_numbered_single_choice():
    qs = parse_questions("1. What is the IP?\nA. 1.1.1.1\nB. 2.2.2.2")
    assert len(qs) == 1
    assert qs[0].question_number == 1
    assert qs[0].kind is QuestionKind.SINGLE_SELECT
    assert [o.letter for o in qs[0].options] == ["A", "B"]


def test_parse_preserves_numbers_and_letters():
    text = "3) Third question\nA) alpha\nB) beta\n\n7) Seventh\nA) x\nB) y"
    qs = parse_questions(text)
    assert [q.question_number for q in qs] == [3, 7]
    assert qs[0].options[0].letter == "A"


def test_parse_multi_select_hint():
    qs = parse_questions("1. Which two are correct? (Choose two.)\nA. one\nB. two\nC. three")
    assert qs[0].kind is QuestionKind.MULTI_SELECT


def test_parse_true_false():
    qs = parse_questions("1. True or false: PC-A has a gateway.\nTrue\nFalse")
    assert qs[0].kind is QuestionKind.TRUE_FALSE
    assert [o.text for o in qs[0].options] == ["True", "False"]


def test_parse_reasoning_question():
    qs = parse_questions("4. Explain how OSPF selects a router ID.")
    assert qs[0].kind is QuestionKind.REASONING
    assert qs[0].options == []


def test_empty_questions_rejected():
    with pytest.raises(QuestionParseError):
        parse_questions("   ")


def test_max_questions_enforced():
    text = "\n".join(f"{i}. Q{i}?" for i in range(1, 12))
    with pytest.raises(QuestionParseError):
        parse_questions(text, max_questions=10)


# --- MCQ matching ----------------------------------------------------------

def _q(opts: list[tuple[str, str]], kind=QuestionKind.SINGLE_SELECT):
    from trident.models import ParsedQuestion, QuestionOption

    return ParsedQuestion(
        question_number=1,
        original="q",
        kind=kind,
        stem="q",
        options=[QuestionOption(letter=a, text=b) for a, b in opts],
    )


def test_mcq_matches_ip_option():
    q = _q([("A", "192.168.2.1"), ("B", "192.168.1.1")])
    status, letters, _ = mcq.match_single(q, "192.168.1.1")
    assert status is AnswerStatus.VERIFIED
    assert letters == ["B"]


def test_mcq_leading_zero_ip_is_not_silently_accepted():
    """Leading zeros are ambiguous (octal). Rejecting is safer than guessing."""
    q = _q([("A", "192.168.001.001")])
    status, letters, _ = mcq.match_single(q, "192.168.1.1")
    assert status is AnswerStatus.CONFLICT
    assert letters == []


def test_mcq_matches_mac_in_different_format():
    q = _q([("A", "00:40:0b:1e:b6:01")])
    status, letters, _ = mcq.match_single(q, "0040.0B1E.B601")
    assert status is AnswerStatus.VERIFIED
    assert letters == ["A"]


def test_mcq_matches_interface_alias():
    q = _q([("A", "Gi0/0"), ("B", "Fa0/1")])
    status, letters, _ = mcq.match_single(q, "GigabitEthernet0/0")
    assert status is AnswerStatus.VERIFIED
    assert letters == ["A"]


def test_mcq_matches_vlan_number():
    q = _q([("A", "10"), ("B", "20")])
    status, letters, _ = mcq.match_single(q, "20")
    assert status is AnswerStatus.VERIFIED
    assert letters == ["B"]


# 18. MCQ with no correct offered option -> CONFLICT, never a "closest" pick
def test_mcq_no_matching_option_is_conflict():
    q = _q([("A", "10.0.0.1"), ("B", "10.0.0.2")])
    status, letters, explanation = mcq.match_single(q, "192.168.1.1")
    assert status is AnswerStatus.CONFLICT
    assert letters == []
    assert "None of the offered options" in explanation


def test_mcq_ambiguous_matches_is_conflict():
    q = _q([("A", "192.168.1.1"), ("B", "192.168.1.1")])
    status, letters, _ = mcq.match_single(q, "192.168.1.1")
    assert status is AnswerStatus.CONFLICT
    assert len(letters) == 2


# 19. Multi-select
def test_multi_select_all_match():
    q = _q([("A", "192.168.1.1"), ("B", "10.0.0.1"), ("C", "172.16.0.1")], QuestionKind.MULTI_SELECT)
    status, letters, _ = mcq.match_multi(q, ["192.168.1.1", "172.16.0.1"])
    assert status is AnswerStatus.VERIFIED
    assert letters == ["A", "C"]


def test_multi_select_partial_is_incomplete():
    q = _q([("A", "192.168.1.1"), ("B", "10.0.0.1")], QuestionKind.MULTI_SELECT)
    status, letters, _ = mcq.match_multi(q, ["192.168.1.1", "203.0.113.9"])
    assert status is AnswerStatus.INCOMPLETE
    assert letters == ["A"]


def test_true_false_match():
    q = _q([("A", "True"), ("B", "False")], QuestionKind.TRUE_FALSE)
    status, letters, _ = mcq.match_true_false(q, True)
    assert status is AnswerStatus.VERIFIED
    assert letters == ["A"]


# --- builder integration ---------------------------------------------------

def _model_with_ip():
    return build_model(
        [
            obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_a"),
            obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_b"),
            obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_c"),
        ]
    )


def test_builder_verified_mcq_end_to_end():
    model = _model_with_ip()
    builder = AnswerBuilder(model, ConsensusEngine(model, Settings()))
    q = parse_questions("1. What is the IP of R1 GigabitEthernet0/0?\nA. 192.168.1.1\nB. 9.9.9.9")[0]
    result = builder.build(q, None)
    assert result.status is AnswerStatus.VERIFIED
    assert result.selected_options == ["A"]
    assert result.consensus.agree == 3
    assert result.evidence[0].sources == ["engine_a", "engine_b", "engine_c"]


def test_builder_conflict_when_option_missing():
    model = _model_with_ip()
    builder = AnswerBuilder(model, ConsensusEngine(model, Settings()))
    q = parse_questions("1. What is the IP of R1 GigabitEthernet0/0?\nA. 9.9.9.9\nB. 8.8.8.8")[0]
    result = builder.build(q, None)
    assert result.status is AnswerStatus.CONFLICT
    assert result.selected_options == []


def test_builder_unknown_device_is_not_available():
    model = _model_with_ip()
    builder = AnswerBuilder(model, ConsensusEngine(model, Settings()))
    q = parse_questions("1. What is the IP of R9 GigabitEthernet0/0?\nA. 1.1.1.1")[0]
    result = builder.build(q, None)
    assert result.status in (AnswerStatus.NOT_AVAILABLE, AnswerStatus.INCOMPLETE, AnswerStatus.CONFLICT)
    assert result.status is not AnswerStatus.VERIFIED


def test_builder_never_upgrades_incomplete_fact_to_verified():
    model = build_model(
        [
            obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_a"),
            obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_b"),
        ]
    )
    builder = AnswerBuilder(model, ConsensusEngine(model, Settings(consensus_policy="strict")))
    q = parse_questions("1. What is the IP of R1 GigabitEthernet0/0?\nA. 192.168.1.1")[0]
    result = builder.build(q, None)
    assert result.status is AnswerStatus.INCOMPLETE
    assert result.selected_options == ["A"]


def test_builder_derived_subnet_arithmetic():
    model = _model_with_ip()
    builder = AnswerBuilder(model, ConsensusEngine(model, Settings()))
    q = parse_questions("1. What is the network address of 192.168.1.10 255.255.255.0?")[0]
    result = builder.build(q, None)
    assert result.status is AnswerStatus.VERIFIED_DERIVED
    assert result.answer == "192.168.1.0"


def test_builder_same_subnet_derived():
    model = _model_with_ip()
    builder = AnswerBuilder(model, ConsensusEngine(model, Settings()))
    q = parse_questions(
        "1. Are 192.168.1.10 and 192.168.1.20 in the same subnet with mask 255.255.255.0?"
    )[0]
    result = builder.build(q, None)
    assert result.status is AnswerStatus.VERIFIED_DERIVED
    assert result.answer == "yes"


# 20. AI hallucination rejection — the AI cannot inject facts
def test_ai_plan_cannot_inject_a_fact():
    """A plan referencing a non-existent device must not produce a verified answer."""
    from trident.reasoning.ai_client import QueryPlan, QueryStep

    model = _model_with_ip()
    builder = AnswerBuilder(model, ConsensusEngine(model, Settings()))
    plan = QueryPlan(
        question_number=1,
        steps=[QueryStep(op="device_ip", device="Ghost_Router", interface="Gi0/0")],
    )
    q = parse_questions("1. What is the IP of Ghost_Router Gi0/0?\nA. 6.6.6.6")[0]
    result = builder.build(q, plan)
    assert result.status is not AnswerStatus.VERIFIED
    assert result.status is not AnswerStatus.VERIFIED_DERIVED
    assert result.selected_options == []


def test_ai_plan_with_unknown_op_is_ignored():
    from trident.reasoning.ai_client import QueryPlan, QueryStep

    model = _model_with_ip()
    builder = AnswerBuilder(model, ConsensusEngine(model, Settings()))
    plan = QueryPlan(
        question_number=1,
        steps=[QueryStep(op="execute_shell", device="R1")],
    )
    q = parse_questions("1. What is the IP of R1 GigabitEthernet0/0?\nA. 192.168.1.1")[0]
    result = builder.build(q, plan)
    # inference still works; the bogus step contributes nothing
    assert result.answer == "192.168.1.1"
