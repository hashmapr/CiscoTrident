"""Consensus engine tests — the core correctness guarantees."""

from __future__ import annotations

from conftest import build_model, obs

from trident.config import Settings
from trident.models import AnswerStatus
from trident.verification.consensus import ConsensusEngine


# 7. Three-parser agreement -> VERIFIED
def test_three_engine_agreement_is_verified(three_engine_model):
    ce = ConsensusEngine(three_engine_model, Settings(consensus_policy="strict"))
    fc = ce.verify_interface_field("R1", "GigabitEthernet0/0", "ipv4_address")
    assert fc.status is AnswerStatus.VERIFIED
    assert fc.value == "192.168.1.1"
    assert len(fc.agreeing_engines) == 3
    summary = fc.summary()
    assert (summary.agree, summary.available, summary.required) == (3, 3, 3)


# 8. Two-parser agreement with the third missing -> INCOMPLETE under strict policy
def test_two_engine_agreement_is_incomplete_under_strict(two_engine_model):
    ce = ConsensusEngine(two_engine_model, Settings(consensus_policy="strict"))
    fc = ce.verify_interface_field("R1", "GigabitEthernet0/0", "ipv4_address")
    assert fc.status is AnswerStatus.INCOMPLETE
    summary = fc.summary()
    assert summary.agree == 2
    assert summary.required == 3


# 9. Three-parser disagreement -> CONFLICT
def test_three_engine_disagreement_is_conflict(conflicting_model):
    ce = ConsensusEngine(conflicting_model, Settings(consensus_policy="strict"))
    fc = ce.verify_interface_field("R1", "GigabitEthernet0/0", "ipv4_address")
    assert fc.status is AnswerStatus.CONFLICT
    assert fc.value is None
    assert fc.conflicts
    assert "10.0.0.1" in fc.conflicts[0]
    assert "192.168.1.1" in fc.conflicts[0]


# 10. Equivalent MAC formatting compares equal
def test_mac_address_formatting_is_equivalent():
    model = build_model(
        [
            obs("interface", "R1:GigabitEthernet0/0", "mac_address", "0040.0B1E.B601", "engine_a"),
            obs("interface", "R1:GigabitEthernet0/0", "mac_address", "00:40:0b:1e:b6:01", "engine_b"),
            obs("interface", "R1:GigabitEthernet0/0", "mac_address", "00-40-0B-1E-B6-01", "engine_c"),
        ]
    )
    ce = ConsensusEngine(model, Settings())
    fc = ce.verify_interface_field("R1", "GigabitEthernet0/0", "mac_address")
    assert fc.status is AnswerStatus.VERIFIED
    assert fc.value == "00:40:0b:1e:b6:01"


# 11. Equivalent interface naming resolves to the same interface
def test_equivalent_interface_names_resolve():
    model = build_model(
        [
            obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_a"),
            obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_b"),
            obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_c"),
        ]
    )
    ce = ConsensusEngine(model, Settings())
    # all three aliases must find the same record
    for alias in ("Gi0/0", "gi0/0", "GigabitEthernet0/0", "GigabitEthernet 0/0"):
        fc = ce.verify_interface_field("R1", alias, "ipv4_address")
        assert fc.status is AnswerStatus.VERIFIED, alias
        assert fc.value == "192.168.1.1"


# 12. Conflicting IP values never yield a value
def test_conflicting_ip_has_no_value(conflicting_model):
    ce = ConsensusEngine(conflicting_model, Settings())
    fc = ce.verify_interface_field("R1", "GigabitEthernet0/0", "ipv4_address")
    assert fc.value is None
    assert fc.status is AnswerStatus.CONFLICT


def test_missing_field_is_not_available():
    model = build_model([])
    ce = ConsensusEngine(model, Settings())
    fc = ce.verify_interface_field("R1", "GigabitEthernet0/0", "ipv4_address")
    assert fc.status is AnswerStatus.NOT_AVAILABLE
    assert fc.value is None


def test_missing_output_never_counts_as_agreement():
    """Two engines agree, the third says nothing: still not VERIFIED."""
    model = build_model(
        [
            obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_a"),
            obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_b"),
        ]
    )
    ce = ConsensusEngine(model, Settings(consensus_policy="strict"))
    fc = ce.verify_interface_field("R1", "GigabitEthernet0/0", "ipv4_address")
    assert fc.status is not AnswerStatus.VERIFIED
    assert fc.summary().agree == 2


def test_crypto_shared_flag_is_surfaced():
    model = build_model(
        [
            obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_a"),
            obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_b"),
            obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_c"),
        ]
    )
    fc = ConsensusEngine(model, Settings()).verify_interface_field(
        "R1", "GigabitEthernet0/0", "ipv4_address"
    )
    assert fc.summary().crypto_shared is True


def test_same_engine_twice_is_not_two_votes():
    """A duplicated observation from one engine must not inflate agreement."""
    model = build_model(
        [
            obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_a"),
            obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_a"),
        ]
    )
    fc = ConsensusEngine(model, Settings()).verify_interface_field(
        "R1", "GigabitEthernet0/0", "ipv4_address"
    )
    assert len(fc.agreeing_engines) == 1
    assert fc.status is AnswerStatus.INCOMPLETE


def test_two_engine_policy_allows_verified_with_two():
    observations = [
        obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_a"),
        obs("interface", "R1:GigabitEthernet0/0", "ipv4_address", "192.168.1.1", "engine_b"),
    ]
    model = build_model(observations)
    ce = ConsensusEngine(model, Settings(consensus_policy="two_engine"))
    fc = ce.verify_interface_field("R1", "GigabitEthernet0/0", "ipv4_address")
    assert fc.status is AnswerStatus.VERIFIED
    assert fc.summary().policy == "two_engine"
