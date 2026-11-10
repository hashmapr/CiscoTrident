"""EtherChannel compatibility reasoning.

The rule that keeps this useful: only ports configured into a group are assessed.
Two access ports that were never grouped are not a broken EtherChannel, and
reporting them would make every switch in every lab "wrong".
"""

from __future__ import annotations

import pytest

from trident.deepcore.etherchannel import (
    Compatibility,
    assess_all,
    assess_channel,
    assess_peer,
    modes_negotiate,
    peer_mode_problem,
)
from trident.deepcore.protocols import EtherChannel
from trident.deepcore.protocols import PortChannelMode as M


def _channel(members=None, mode=None, protocol=None, issues=None):
    mode = M.ACTIVE if mode is None else mode
    protocol = ("lacp" if mode is M.ACTIVE else "static") if protocol is None else protocol
    return EtherChannel(
        port_channel="Port-channel1",
        mode=mode,
        protocol=protocol,
        # `members or default` would turn an explicit empty list into two
        # members, which is exactly the case one test needs to exercise.
        members=["Gi0/1", "Gi0/2"] if members is None else members,
        issues=issues or [],
    )


# ---------------------------------------------------------------------------
# Negotiation matrix
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        (M.ACTIVE, M.ACTIVE, True),
        (M.ACTIVE, M.PASSIVE, True),
        (M.PASSIVE, M.ACTIVE, True),
        (M.PASSIVE, M.PASSIVE, False),
        (M.DESIRABLE, M.DESIRABLE, True),
        (M.DESIRABLE, M.AUTO, True),
        (M.AUTO, M.AUTO, False),
        (M.ON, M.ON, True),
        (M.ON, M.ACTIVE, False),
        (M.ACTIVE, M.DESIRABLE, False),
    ],
)
def test_negotiation_matrix(left, right, expected):
    assert modes_negotiate(left, right) is expected


def test_both_passive_is_explained_not_just_refused():
    problem = peer_mode_problem(M.PASSIVE, M.PASSIVE)
    assert problem is not None
    assert "neither initiates" in problem


def test_both_auto_is_explained():
    problem = peer_mode_problem(M.AUTO, M.AUTO)
    assert problem is not None
    assert "neither initiates" in problem


def test_complementary_modes_have_no_problem():
    assert peer_mode_problem(M.ACTIVE, M.PASSIVE) is None
    assert peer_mode_problem(M.DESIRABLE, M.AUTO) is None


# ---------------------------------------------------------------------------
# Single channel assessment
# ---------------------------------------------------------------------------


def test_a_consistent_channel_forms():
    assessment = assess_channel(_channel())
    assert assessment.compatibility is Compatibility.FORMS
    assert assessment.healthy is True


def test_conflicting_member_modes_cannot_form():
    channel = _channel(issues=["Gi0/2 uses mode desirable but Port-channel1 is active"])
    assessment = assess_channel(channel)
    assert assessment.compatibility is Compatibility.CANNOT_FORM
    assert assessment.problems[0].severity == "HIGH"


def test_a_channel_with_no_members_is_undecided():
    assessment = assess_channel(_channel(members=[]))
    assert assessment.compatibility is Compatibility.UNDECIDED


def test_a_single_member_channel_forms_but_buys_nothing():
    """One member is a design observation, not a failure."""
    assessment = assess_channel(_channel(members=["Gi0/1"]))
    assert assessment.compatibility is Compatibility.FORMS
    assert assessment.problems
    assert "no aggregation" in assessment.problems[0].description


def test_an_unknown_mode_is_undecided_not_assumed():
    assessment = assess_channel(_channel(mode=M.UNKNOWN, protocol="unknown"))
    assert assessment.compatibility is Compatibility.UNDECIDED


# ---------------------------------------------------------------------------
# Peer assessment
# ---------------------------------------------------------------------------


def test_two_active_ends_form():
    assessment = assess_peer(_channel(), _channel(), "SW1", "SW2")
    assert assessment.compatibility is Compatibility.FORMS
    assert assessment.healthy is True


def test_active_against_desirable_cannot_form():
    """LACP and PAgP do not negotiate with each other."""
    peer = _channel(mode=M.DESIRABLE, protocol="pagp")
    assessment = assess_peer(_channel(), peer, "SW1", "SW2")
    assert assessment.compatibility is Compatibility.CANNOT_FORM
    assert assessment.problems


def test_on_against_active_cannot_form():
    peer = _channel(mode=M.ACTIVE, protocol="lacp")
    local = _channel(mode=M.ON, protocol="static")
    assessment = assess_peer(local, peer, "SW1", "SW2")
    assert assessment.compatibility is Compatibility.CANNOT_FORM


def test_mismatched_member_counts_are_flagged():
    peer = _channel(members=["Gi0/9"])
    assessment = assess_peer(_channel(), peer, "SW1", "SW2")
    assert assessment.compatibility is Compatibility.FORMS
    assert any("member counts differ" in problem.description for problem in assessment.problems)


def test_differing_protocols_cannot_form():
    local = _channel(mode=M.ACTIVE, protocol="lacp")
    peer = _channel(mode=M.ACTIVE, protocol="pagp")
    assessment = assess_peer(local, peer, "SW1", "SW2")
    assert assessment.compatibility is Compatibility.CANNOT_FORM
    assert any("protocols differ" in problem.description for problem in assessment.problems)


# ---------------------------------------------------------------------------
# Independent interfaces
# ---------------------------------------------------------------------------


def test_no_channels_produces_no_assessments():
    """Ports that were never grouped are not assessed at all."""
    assert assess_all({}) == []


def test_assess_all_covers_every_configured_channel():
    second = _channel(members=["Gi0/5"], mode=M.ON, protocol="static")
    second.port_channel = "Port-channel2"
    channels = {"Port-channel1": _channel(), "Port-channel2": second}
    assessments = assess_all(channels)
    assert len(assessments) == 2
    assert {a.port_channel for a in assessments} == {"Port-channel1", "Port-channel2"}


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


def test_assessment_serialises():
    import json

    json.dumps(assess_channel(_channel()).as_dict())


def test_every_problem_has_evidence():
    channel = _channel(issues=["mode conflict"])
    assessment = assess_channel(channel)
    for problem in assessment.problems:
        assert problem.evidence


def test_assessment_does_not_mutate_the_channel():
    channel = _channel()
    before = list(channel.members)
    assess_channel(channel)
    assert channel.members == before
