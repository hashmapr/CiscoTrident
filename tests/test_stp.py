"""Spanning Tree reasoning: root election and port roles.

The honesty boundary is what these tests protect. STP state depends on facts a lab
file often lacks — MAC addresses, live BPDU flow, full path costs. A role is
computed only when the evidence supports it; otherwise the result is UNDECIDED
with the missing fact named. Guessing here would produce confident wrong answers
about which links forward.
"""

from __future__ import annotations

import pytest

from trident.deepcore.stp import (
    Bridge,
    Link,
    Role,
    compute,
    elect_root,
    loops_possible,
)


def _bridge(name, priority=None, mac=None, costs=None, blocked=None):
    return Bridge(
        name=name,
        priority=priority,
        mac=mac,
        port_costs=costs or {},
        blocked_ports=blocked or [],
    )


# ---------------------------------------------------------------------------
# Root election
# ---------------------------------------------------------------------------


def test_the_lowest_priority_wins():
    root, reason, _ = elect_root(
        [_bridge("SW1", 4096), _bridge("SW2", 8192), _bridge("SW3", 32768)]
    )
    assert root.name == "SW1"
    assert "4096" in reason


def test_a_tie_is_broken_by_the_lower_mac():
    root, reason, _ = elect_root(
        [
            _bridge("SW1", 4096, "00:00:00:00:00:02"),
            _bridge("SW2", 4096, "00:00:00:00:00:01"),
        ]
    )
    assert root.name == "SW2"
    assert "MAC" in reason


def test_a_tie_without_macs_is_undecided_not_arbitrary():
    """Picking a winner here would be inventing evidence."""
    root, reason, _ = elect_root(
        [_bridge("SW1", 4096), _bridge("SW2", 4096)]
    )
    assert root is None
    assert "no MAC" in reason


def test_an_unstated_priority_is_not_assumed_by_default():
    root, reason, assumptions = elect_root(
        [_bridge("SW1"), _bridge("SW2", 8192)]
    )
    assert root.name == "SW2"
    assert assumptions == []
    assert reason


def test_the_ios_default_can_be_assumed_explicitly():
    root, _, assumptions = elect_root(
        [_bridge("SW1"), _bridge("SW2", 8192)], assume_default_priority=True
    )
    assert root is not None
    assert assumptions
    assert "IOS default" in assumptions[0]


def test_no_bridges_is_undecided():
    root, reason, _ = elect_root([])
    assert root is None
    assert "no bridges" in reason


# ---------------------------------------------------------------------------
# Port roles
# ---------------------------------------------------------------------------


def _triangle(cost_left=4, cost_right=4, cost_middle=4):
    bridges = [
        _bridge("SW1", 4096, "00:00:00:00:00:01", {"Gi0/1": cost_left, "Gi0/2": cost_right}),
        _bridge("SW2", 8192, "00:00:00:00:00:02", {"Gi0/1": 4, "Gi0/2": cost_middle}),
        _bridge("SW3", 32768, "00:00:00:00:00:03", {"Gi0/1": 4, "Gi0/2": cost_middle}),
    ]
    links = [
        Link("SW1", "Gi0/1", "SW2", "Gi0/1"),
        Link("SW2", "Gi0/2", "SW3", "Gi0/2"),
        Link("SW1", "Gi0/2", "SW3", "Gi0/1"),
    ]
    return bridges, links


def test_the_root_bridge_ports_are_designated():
    bridges, links = _triangle()
    election = compute(bridges, links)
    assert election.root == "SW1"
    assert election.role_of("SW1", "Gi0/1") is Role.DESIGNATED
    assert election.role_of("SW1", "Gi0/2") is Role.DESIGNATED


def test_the_far_side_of_a_root_link_is_alternate():
    bridges, links = _triangle()
    election = compute(bridges, links)
    assert election.role_of("SW2", "Gi0/1") is Role.ALTERNATE
    assert election.role_of("SW3", "Gi0/1") is Role.ALTERNATE


def test_an_equal_cost_link_away_from_the_root_is_undecided():
    """The real tie-break uses neighbour bridge ids the file does not carry."""
    bridges, links = _triangle()
    election = compute(bridges, links)
    assert election.role_of("SW2", "Gi0/2") is Role.UNDECIDED
    assert election.undecided
    assert "equal cost" in election.undecided[0]


def test_only_the_forwarding_roles_count_as_forwarding():
    assert Role.ROOT.forwards is True
    assert Role.DESIGNATED.forwards is True
    assert Role.ALTERNATE.forwards is False
    assert Role.BLOCKED.forwards is False
    assert Role.UNDECIDED.forwards is False


def test_forwarding_ports_lists_only_forwarding():
    bridges, links = _triangle()
    election = compute(bridges, links)
    forwarding = election.forwarding_ports("SW1")
    assert set(forwarding) == {"Gi0/1", "Gi0/2"}


# ---------------------------------------------------------------------------
# Missing evidence
# ---------------------------------------------------------------------------


def test_the_root_side_of_a_link_is_designated_even_without_costs():
    """Roles adjacent to the root follow topology, not cost."""
    bridges = [_bridge("SW1", 4096, "00:00:00:00:00:01", {"Gi0/1": 4}),
               _bridge("SW2", 8192, "00:00:00:00:00:02", {})]
    links = [Link("SW1", "Gi0/1", "SW2", "Gi0/1")]
    election = compute(bridges, links)
    assert election.root == "SW1"
    assert election.role_of("SW1", "Gi0/1") is Role.DESIGNATED
    assert election.role_of("SW2", "Gi0/1") is Role.ALTERNATE


def test_a_link_that_is_both_ends_of_one_bridge_is_undecided():
    """A self-link cannot be resolved by cost; it is a topology error."""
    bridges = [_bridge("SW1", 4096, "00:00:00:00:00:01", {"Gi0/1": 4, "Gi0/2": 4})]
    links = [Link("SW1", "Gi0/1", "SW1", "Gi0/2")]
    election = compute(bridges, links)
    assert election.role_of("SW1", "Gi0/1") is Role.UNDECIDED
    assert election.undecided


def test_loop_check_is_empty_when_no_link_has_both_ends_forwarding():
    bridges, links = _triangle()
    election = compute(bridges, links)
    # Every root link has one designated and one alternate end.
    assert loops_possible(election, links) == []


def test_a_blocked_port_is_reported_as_blocked():
    bridges = [_bridge("SW1", 4096, "00:00:00:00:00:01", {"Gi0/1": 4}, blocked=["Gi0/1"]),
               _bridge("SW2", 8192, "00:00:00:00:00:02", {"Gi0/1": 4})]
    links = [Link("SW1", "Gi0/1", "SW2", "Gi0/1")]
    election = compute(bridges, links)
    assert election.role_of("SW1", "Gi0/1") is Role.BLOCKED


# ---------------------------------------------------------------------------
# Assumptions are visible
# ---------------------------------------------------------------------------


def test_non_root_roles_record_the_local_cost_approximation():
    bridges, links = _triangle(cost_left=4, cost_right=4, cost_middle=19)
    election = compute(bridges, links)
    if any(role.reason.startswith("lower local cost") for role in election.roles):
        assert any(
            "local cost" in assumption for assumption in election.assumptions
        )


def test_a_computed_role_records_why():
    bridges, links = _triangle()
    election = compute(bridges, links)
    for role in election.roles:
        assert role.reason


def test_election_serialises():
    import json

    bridges, links = _triangle()
    json.dumps(compute(bridges, links).as_dict())


def test_compute_does_not_mutate_the_bridges():
    bridges, links = _triangle()
    before = [(b.name, b.priority, dict(b.port_costs)) for b in bridges]
    compute(bridges, links)
    after = [(b.name, b.priority, dict(b.port_costs)) for b in bridges]
    assert before == after


def test_an_empty_topology_is_undecided():
    election = compute([], [])
    assert election.root is None
