"""Requirement decomposition: the six phrasings, and the refusals.

The tests are written around the failure mode that matters for an assessment
tool: a line it does not understand must not become a requirement it invented.
Every "unparseable" case below is therefore as important as the positive ones.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from trident.assessment.requirements import coverage, parse_requirements, to_intent
from trident.engined.verify import Status, verify_intent

# ---------------------------------------------------------------------------
# A small model, shaped like NetworkModel's public surface
# ---------------------------------------------------------------------------


@dataclass
class FakeInterface:
    device: str
    name: str
    ipv4_address: str | None = None
    prefix_length: int | None = None
    ipv4_gateway: str | None = None
    admin_state: str = "up"
    access_mode: str | None = None
    vlan_assignments: list[str] = field(default_factory=list)


@dataclass
class FakeLink:
    device_a: str
    interface_a: str
    device_b: str
    interface_b: str


@dataclass
class FakeDevice:
    name: str
    model: str = ""


@dataclass
class FakeModel:
    devices: dict
    interfaces: dict
    routes: list = field(default_factory=list)
    links: list = field(default_factory=list)
    vlans: list = field(default_factory=list)
    acls: list = field(default_factory=list)


def _iface(model, device, name, address=None, prefix=None, **kw):
    model.interfaces[f"{device}:{name}"] = FakeInterface(
        device, name, address, prefix, **kw
    )


def lab_model() -> FakeModel:
    """R1, one host per VLAN, and a switch that defines both VLANs.

    PC-A is on SW1's FastEthernet0/2 (VLAN 10); PC-B is on Fa0/3 (VLAN 20).
    Both names are deliberate: one exact interface name and one abbreviated
    one, so resolution is exercised in both directions.
    """
    model = FakeModel(
        devices={
            "R1": FakeDevice("R1", model="2911"),
            "SW1": FakeDevice("SW1", model="2960"),
            "PC-A": FakeDevice("PC-A", model="PC-PT"),
            "PC-B": FakeDevice("PC-B", model="PC-PT"),
        },
        interfaces={},
    )
    _iface(model, "R1", "Gi0/0", "10.1.1.1", 24)
    _iface(model, "R1", "Gi0/1", "10.5.4.1", 24)
    _iface(model, "PC-A", "Fa0", "10.1.1.10", 24, ipv4_gateway="10.1.1.1")
    _iface(model, "PC-B", "Fa0", "10.1.1.20", 24, ipv4_gateway="10.1.1.1")
    _iface(model, "SW1", "FastEthernet0/2", vlan_assignments=["10"])
    _iface(model, "SW1", "Fa0/3", vlan_assignments=["20"])
    model.links.extend(
        [
            FakeLink("SW1", "FastEthernet0/2", "PC-A", "Fa0"),
            FakeLink("SW1", "Fa0/3", "PC-B", "Fa0"),
        ]
    )
    return model


# ---------------------------------------------------------------------------
# Every supported phrasing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "kind", "assertion", "src", "dst", "operand", "protocol"),
    [
        ("PC-A can ping PC-B", "reachability", None, "PC-A", "PC-B", None, "icmp"),
        ("PC1 must reach SRV1", "reachability", None, "PC1", "SRV1", None, "icmp"),
        (
            "PC-A must be able to ping PC-B",
            "reachability",
            None,
            "PC-A",
            "PC-B",
            None,
            "icmp",
        ),
        (
            "VLAN 10 must remain isolated from VLAN 20",
            "isolation",
            None,
            None,
            None,
            "vlan:10|vlan:20",
            "icmp",
        ),
        (
            "R1 must have a route to 10.5.4.0/24",
            "route",
            "route",
            "R1",
            "R1",
            "10.5.4.0/24",
            "icmp",
        ),
        (
            "SW1 FastEthernet0/2 must be enabled",
            "interface_up",
            "interface_up",
            "SW1",
            "SW1",
            "SW1:FastEthernet0/2",
            "icmp",
        ),
        (
            "SW1 Fa0/2 must be up",
            "interface_up",
            "interface_up",
            "SW1",
            "SW1",
            "SW1:Fa0/2",
            "icmp",
        ),
        (
            "SW1 Fa0/2 must be in VLAN 10",
            "vlan_membership",
            "vlan_membership",
            "SW1",
            "SW1",
            "SW1:Fa0/2",
            "10",
        ),
        (
            "SW1 Fa0/2 must be assigned to VLAN 10",
            "vlan_membership",
            "vlan_membership",
            "SW1",
            "SW1",
            "SW1:Fa0/2",
            "10",
        ),
        (
            "PC-A gateway must be 10.1.1.1",
            "gateway",
            "gateway",
            "PC-A",
            "PC-A",
            "10.1.1.1",
            "icmp",
        ),
        (
            "PC-A's gateway is 10.1.1.1",
            "gateway",
            "gateway",
            "PC-A",
            "PC-A",
            "10.1.1.1",
            "icmp",
        ),
    ],
)
def test_supported_phrasings_parse_to_the_right_assertion(
    line, kind, assertion, src, dst, operand, protocol
) -> None:
    parsed = parse_requirements([line])
    assert len(parsed) == 1
    item = parsed[0]
    assert item.parsed is True
    assert item.kind == kind
    assert item.assertion == assertion
    assert item.src_device == src
    assert item.dst_device == dst
    assert item.operand == operand
    assert item.protocol == protocol


def test_vlan_isolation_is_must_not_reach() -> None:
    item = parse_requirements(["VLAN 10 must remain isolated from VLAN 20"])[0]
    assert item.must_not_reach is True
    assert (item.vlan_a, item.vlan_b) == (10, 20)


def test_device_isolation_is_must_not_reach() -> None:
    item = parse_requirements(["PC-A must not reach PC-B"])[0]
    assert item.parsed is True
    assert item.kind == "isolation"
    assert item.must_not_reach is True
    assert (item.src_device, item.dst_device) == ("PC-A", "PC-B")


def test_list_furniture_is_stripped_but_not_interpreted() -> None:
    parsed = parse_requirements(["- PC-A can ping PC-B", "2. PC-B must reach PC-A"])
    assert [item.parsed for item in parsed] == [True, True]
    assert [item.kind for item in parsed] == ["reachability", "reachability"]


# ---------------------------------------------------------------------------
# Refusals — never invent a requirement
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "Enable OSPF on all routers",
        "Configure SSH version 2",
        "Ensure the campus is secure",
        "R1 should be nice",
    ],
)
def test_unparseable_lines_stay_unparsed_never_guessed(line) -> None:
    """A line no parser understands is retained, never guessed into a check.

    Note: ``PC1 can ping its default gateway``, ``ISP-EDGE holds no route to a
    private network`` and ``R1 has a default route via 203.0.113.1`` were in
    this list and now parse. They were not removed to make the test pass —
    three parsers were added for them, and their behaviour is asserted below.
    """
    item = parse_requirements([line])[0]
    assert item.parsed is False
    assert item.assertion is None
    assert item.kind == "unparsed"


@pytest.mark.parametrize(
    ("line", "assertion"),
    [
        ("PC1 can ping its default gateway", "gateway_reachable"),
        ("R1 has a default route via 203.0.113.1", "default_route_via"),
        ("ISP-EDGE holds no route to a private network", "route"),
    ],
)
def test_newly_supported_phrasings_parse(line, assertion) -> None:
    """These were previously UNPARSED; each now maps to a testable assertion."""
    item = parse_requirements([line])[0]
    assert item.parsed is True
    assert item.assertion == assertion
    assert item.raw == line


def test_blank_lines_are_not_requirements() -> None:
    assert parse_requirements(["", "   ", "\n"]) == []


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def test_unknown_device_is_unresolvable_not_dropped() -> None:
    parsed = parse_requirements(["GHOST must reach PC-B"])
    assert len(parsed) == 1
    model = lab_model()
    intent = to_intent(parsed[0], model)
    assert intent.requirements == []
    assert parsed[0].unresolvable is not None
    assert "GHOST" in parsed[0].unresolvable
    # Retained in the caller's list: "not tested" is visible, not erased.
    assert parsed[0].raw == "GHOST must reach PC-B"


def test_unknown_device_in_isolation_is_unresolvable() -> None:
    parsed = parse_requirements(["PC-A must not reach GHOST"])[0]
    to_intent(parsed, lab_model())
    assert parsed.unresolvable is not None
    assert "GHOST" in parsed.unresolvable


def test_route_intent_carries_assertion_and_operand() -> None:
    parsed = parse_requirements(["R1 must have a route to 10.5.4.0/24"])[0]
    intent = to_intent(parsed, lab_model())
    assert parsed.unresolvable is None
    requirement = intent.requirements[0]
    assert requirement.assertion == "route"
    assert requirement.operand == "10.5.4.0/24"
    assert requirement.src.device == "R1"


def test_gateway_intent_is_evaluable() -> None:
    parsed = parse_requirements(["PC-A gateway must be 10.1.1.1"])[0]
    model = lab_model()
    intent = to_intent(parsed, model)
    report = verify_intent(model, intent)
    assert report.verdicts[0].status is Status.DERIVED
    assert report.verdicts[0].reachable is True
    assert report.failures == []


def test_vlan_membership_resolves_an_abbreviated_interface() -> None:
    parsed = parse_requirements(["SW1 Fa0/2 must be in VLAN 10"])[0]
    intent = to_intent(parsed, lab_model())
    requirement = intent.requirements[0]
    # The statement used "Fa0/2"; the model calls it FastEthernet0/2. The
    # operand is rewritten to the model's own name so the verifier can decide.
    assert requirement.operand == "SW1:FastEthernet0/2"
    assert requirement.protocol == "10"


def test_vlan_isolation_resolves_to_concrete_members() -> None:
    parsed = parse_requirements(["VLAN 10 must remain isolated from VLAN 20"])[0]
    model = lab_model()
    intent = to_intent(parsed, model)
    assert parsed.unresolvable is None
    assert len(intent.requirements) == 1
    requirement = intent.requirements[0]
    assert requirement.must_not_reach is True
    assert (requirement.src.device, requirement.dst.device) == ("PC-A", "PC-B")


def test_interface_up_assertion_is_evaluable() -> None:
    parsed = parse_requirements(["SW1 FastEthernet0/2 must be enabled"])[0]
    model = lab_model()
    intent = to_intent(parsed, model)
    report = verify_intent(model, intent)
    assert report.verdicts[0].reachable is True
    assert report.failures == []


# ---------------------------------------------------------------------------
# Coverage is exact
# ---------------------------------------------------------------------------


def test_coverage_counts_parsed_unparsed_and_unresolvable_exactly() -> None:
    lines = [
        "PC-A can ping PC-B",
        "VLAN 10 must remain isolated from VLAN 20",
        "R1 must have a route to 10.5.4.0/24",
        "SW1 FastEthernet0/2 must be enabled",
        "SW1 Fa0/2 must be in VLAN 10",
        "PC-A gateway must be 10.1.1.1",
        "Enable OSPF on all routers",
        "GHOST must reach PC-B",
    ]
    parsed = parse_requirements(lines)
    counts = coverage(parsed, lab_model())
    assert counts == {
        "total": 8,
        "parsed": 7,
        "unparsed": 1,
        "unresolvable": 1,
        "testable": 6,
    }


def test_coverage_of_an_empty_list_is_zero() -> None:
    assert coverage([], lab_model()) == {
        "total": 0,
        "parsed": 0,
        "unparsed": 0,
        "unresolvable": 0,
        "testable": 0,
    }
