"""Regression tests for the audited OK Cup benchmark failures (Q1, Q2, Q52-Q61, Q63-Q65).

Every test here goes through the **production** path
(``pipeline.analyze`` -> question parsing -> intent routing -> typed operation ->
verification), not directly against helper functions, because the original defect
was that typed operations existed but questions never reached them.

The real file is used when available; otherwise the tests skip with a clear
reason rather than silently passing.
"""

from __future__ import annotations

import asyncio
import pathlib

import pytest
from conftest import all_engines_available, engine_available

from trident.ingestion import ingest
from trident.pipeline import analyze

REAL_FILE = pathlib.Path.home() / "Downloads" / "R1_OKCUP_24_25_CiscoPT(1).pka"

MH = "Main Hub Switch (Layer 3) (The Brainiac)"
N1 = "Node One Router (Our Loyal Minion)"
RT = "Internet (Router) 1"
SW = "Internet (Layer 2 Switch) 1"

pytestmark = pytest.mark.skipif(
    not REAL_FILE.exists(),
    reason=f"audited real file not present: {REAL_FILE}",
)

# These assertions were written against a three-engine environment: several of
# them require a status of VERIFIED, and under ``strict`` consensus that needs
# three distinct extraction families. Engine C (pt-convert) is an external
# All-Rights-Reserved checkout whose source is not present here, so only two
# families exist and the same correct answer is honestly INCOMPLETE.
#
# Be precise about what the marker below does: it skips the WHOLE test, and
# those tests also assert values. So the honest statement is not "only status
# assertions are gated" but "the gated tests are compensated by an ungated value
# test". `test_every_audited_answer_is_correct_at_any_engine_count` asserts all
# twelve audited values with no marker, so no wrong value can hide behind this.
#
# This is deliberately NOT a relaxation of consensus: nothing here promotes
# INCOMPLETE to VERIFIED.
#
# Verified with two engines: Q54 returns 'OpenSeas' with agree=2 available=2
# required=3. With TRIDENT_CONSENSUS_POLICY=two_engine the same answers become
# VERIFIED at required=2, which confirms the values were never the problem.
requires_three_engines = pytest.mark.skipif(
    not all_engines_available(),
    reason=(
        "needs three extraction families for a VERIFIED status under strict "
        f"consensus; engine_c available={engine_available('engine_c')}"
    ),
)


@pytest.fixture(scope="module")
def answers() -> dict[int, tuple[str, str]]:
    """Run the audited questions once through the production pipeline."""
    questions = {
        1: f"Which device is connected to {MH} GigabitEthernet1/0/2?",
        2: f"What is the peer interface on {N1} for GigabitEthernet0/0?",
        52: "How many physical links are in the network?",
        53: "How many devices are in the network?",
        54: f"What is the hostname of {RT}?",
        55: f"What is the hostname of {SW}?",
        56: f"What is the IP address of {RT} GigabitEthernet0/0?",
        57: f"What is the subnet mask of {RT} GigabitEthernet0/0?",
        58: f"What is the network address of {RT} GigabitEthernet0/0?",
        59: f"What is the IP address of {RT} GigabitEthernet0/1?",
        60: f"What is the subnet mask of {RT} GigabitEthernet0/1?",
        61: f"What is the network address of {RT} GigabitEthernet0/1?",
        63: f"What is the IP address of {SW} Vlan1?",
        64: f"What is the default gateway of {SW}?",
        65: f"Are {RT} GigabitEthernet0/0 and {SW} Vlan1 in the same subnet?",
    }
    text = "\n".join(f"{n}. {q}" for n, q in questions.items())
    outcome = asyncio.run(
        analyze(ingest(REAL_FILE.name, REAL_FILE.read_bytes()), text, use_ai=False)
    )
    return {
        r.question_number: ((r.answer or ""), r.status.value)
        for r in outcome.response.results
    }


@pytest.mark.parametrize(
    ("number", "expected"),
    [
        (1, "Node One Router (Our Loyal Minion)"),
        (54, "OpenSeas"),
        (55, "AtWorldsEnd"),
    ],
)
@requires_three_engines
def test_identity_questions(answers, number: int, expected: str) -> None:
    """Q1/Q54/Q55: a device identity, never an interface list or an IP."""
    actual, status = answers[number]
    assert actual.strip().lower() == expected.lower(), f"Q{number} got {actual!r}"
    assert status in {"VERIFIED", "VERIFIED_DERIVED"}
    assert "[[" not in actual, "unresolved display placeholder leaked into the answer"
    assert "," not in actual, "a single-device question returned a list"


def test_peer_interface(answers) -> None:
    """Q2: the opposite cable endpoint, not the device's interface inventory."""
    actual, status = answers[2]
    assert actual.strip().lower() == "gigabitethernet1/0/2"
    assert status in {"VERIFIED", "VERIFIED_DERIVED"}


@pytest.mark.parametrize(("number", "value"), [(52, 19), (53, 20)])
def test_counts_are_integers(answers, number: int, value: int) -> None:
    """Q52/Q53: deterministic counts, never a list of names."""
    actual, status = answers[number]
    assert actual.strip() == str(value), f"Q{number} got {actual!r}"
    assert actual.strip().isdigit()
    assert "," not in actual


@pytest.mark.parametrize(
    ("number", "expected"),
    [
        (56, "44.102.3.1"),
        (57, "255.255.255.0"),
        (58, "44.102.3.0"),
        (59, "34.130.13.1"),
        (60, "255.255.255.0"),
        (61, "34.130.13.0"),
    ],
)
@requires_three_engines
def test_address_family_is_distinguished(answers, number: int, expected: str) -> None:
    """Q56-Q61: host IP, mask and network address must never substitute for each other."""
    actual, status = answers[number]
    assert actual.strip() == expected, f"Q{number} got {actual!r}, want {expected}"
    assert status in {"VERIFIED", "VERIFIED_DERIVED"}


def test_subnet_mask_is_never_a_host_ip(answers) -> None:
    """The mask operation must not return 44.102.3.1 (a host address)."""
    actual, _ = answers[57]
    assert actual.strip() != "44.102.3.1"
    # a dotted-quad is not sufficient: it must be a contiguous mask
    octets = [int(p) for p in actual.split(".")]
    assert octets == [255, 255, 255, 0]


def test_network_address_differs_from_host_ip(answers) -> None:
    host_ip, _ = answers[56]
    network, _ = answers[58]
    assert host_ip != network
    assert network == "44.102.3.0"


@requires_three_engines
def test_gateway_and_vlan_answers(answers) -> None:
    vlan_ip, s1 = answers[63]
    gateway, s2 = answers[64]
    assert vlan_ip.strip() == "44.102.3.2"
    assert gateway.strip() == "44.102.3.1"
    # The Vlan1 address is corroborated by all three engines.
    assert s1 in {"VERIFIED", "VERIFIED_DERIVED"}
    # ``ip default-gateway`` is only present in the end-host/XML settings block,
    # which a single engine exposes. The value must be right, but it is honestly
    # single-source, so it must NOT be presented as corroborated.
    assert s2 in {"VERIFIED", "VERIFIED_DERIVED", "INCOMPLETE"}


def test_same_subnet(answers) -> None:
    actual, status = answers[65]
    assert actual.strip().lower() in {"true", "yes"}
    assert status in {"VERIFIED", "VERIFIED_DERIVED"}


def test_no_answer_contains_a_raw_placeholder(answers) -> None:
    """A regression for the placeholder-leak class: nothing may surface '[['."""
    leaks = {n: a for n, (a, _s) in answers.items() if "[[" in (a or "")}
    assert not leaks, f"placeholder leaked into answers: {leaks}"


def test_no_wrong_answer_is_verified(answers) -> None:
    """Every audited question must either be right or abstain -- never wrong+verified."""
    expected_values = {
        1: "Node One Router (Our Loyal Minion)",
        2: "GigabitEthernet1/0/2",
        52: "19",
        53: "20",
        54: "OpenSeas",
        55: "AtWorldsEnd",
        56: "44.102.3.1",
        57: "255.255.255.0",
        58: "44.102.3.0",
        59: "34.130.13.1",
        60: "255.255.255.0",
        61: "34.130.13.0",
        63: "44.102.3.2",
        64: "44.102.3.1",
    }
    wrong_verified = []
    for number, expected in expected_values.items():
        actual, status = answers[number]
        if status in {"VERIFIED", "VERIFIED_DERIVED"} and actual.strip() != expected:
            wrong_verified.append((number, actual, status))
    assert not wrong_verified, f"incorrect answers marked verified: {wrong_verified}"


def test_every_audited_answer_is_correct_at_any_engine_count(answers) -> None:
    """The values must be right whether or not Engine C is installed.

    The status-gated tests above measure the *environment* (a VERIFIED verdict
    needs three extraction families under strict consensus). This test measures
    the *product* and is deliberately ungated: if a question returns a wrong
    answer, it fails here with two engines, three engines, or none.

    This exists so that gating the status assertions cannot silently hide a
    wrong answer — the exact failure mode "skip it until the environment is
    right" would otherwise introduce.
    """
    expected_values = {
        1: "Node One Router (Our Loyal Minion)",
        2: "GigabitEthernet1/0/2",
        54: "OpenSeas",
        55: "AtWorldsEnd",
        56: "44.102.3.1",
        57: "255.255.255.0",
        58: "44.102.3.0",
        59: "34.130.13.1",
        60: "255.255.255.0",
        61: "34.130.13.0",
        63: "44.102.3.2",
        64: "44.102.3.1",
    }
    wrong = []
    for number, expected in expected_values.items():
        actual, _status = answers[number]
        if actual.strip() != expected:
            wrong.append((number, actual, expected))
    assert not wrong, f"answers are wrong regardless of engine count: {wrong}"
