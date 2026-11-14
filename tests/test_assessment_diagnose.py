"""Diagnosis: findings, the false-positive guard, and root-cause grouping.

Models are built by hand so each test states its world explicitly. Nothing here
starts Packet Tracer.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from trident.assessment.diagnose import diagnose
from trident.assessment.requirements import parse_requirements
from trident.engined.verify import Status

# ---------------------------------------------------------------------------
# Fixtures
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
class FakeRoute:
    device: str
    destination: str
    next_hop: str | None = None
    mask: str | None = None


@dataclass
class FakeDevice:
    name: str
    configuration: list[str] = field(default_factory=list)
    model: str = ""
    device_type: str | None = None


@dataclass
class FakeModel:
    devices: dict
    interfaces: dict
    routes: list = field(default_factory=list)
    links: list = field(default_factory=list)
    vlans: list = field(default_factory=list)
    acls: list = field(default_factory=list)


def _iface(model, device, name, address, prefix, **kw):
    model.interfaces[f"{device}:{name}"] = FakeInterface(
        device, name, address, prefix, **kw
    )


def two_router_model(*, r1_route: bool = True, transit_up: bool = True) -> FakeModel:
    """R1 -- 10.0.12.0/30 -- R2, with one LAN each."""
    model = FakeModel(
        devices={
            "R1": FakeDevice("R1", model="2911"),
            "R2": FakeDevice("R2", model="2911"),
            "PC-A": FakeDevice("PC-A", model="PC-PT"),
            "PC-B": FakeDevice("PC-B", model="PC-PT"),
        },
        interfaces={},
    )
    model.interfaces["R1:Gi0/1"] = FakeInterface(
        "R1",
        "Gi0/1",
        "10.0.12.1",
        30,
        admin_state="up" if transit_up else "administratively down",
    )
    _iface(model, "R1", "Gi0/0", "10.0.1.1", 24)
    _iface(model, "R2", "Gi0/0", "10.0.2.1", 24)
    _iface(model, "R2", "Gi0/1", "10.0.12.2", 30)
    _iface(model, "PC-A", "Fa0", "10.0.1.10", 24, ipv4_gateway="10.0.1.1")
    _iface(model, "PC-B", "Fa0", "10.0.2.10", 24, ipv4_gateway="10.0.2.1")
    model.routes.append(FakeRoute("R2", "10.0.1.0/24", "10.0.12.1"))
    if r1_route:
        model.routes.append(FakeRoute("R1", "10.0.2.0/24", "10.0.12.2"))
    return model


# ---------------------------------------------------------------------------
# Healthy network
# ---------------------------------------------------------------------------


def test_healthy_network_produces_zero_findings() -> None:
    model = two_router_model()
    parsed = parse_requirements(
        [
            "PC-A can ping PC-B",
            "R1 must have a route to 10.0.2.0/24",
            "PC-A gateway must be 10.0.1.1",
            "R1 Gi0/1 must be up",
        ]
    )
    diagnosis = diagnose(model, parsed)

    assert len(diagnosis.verdicts) == 4
    assert diagnosis.findings == []
    assert diagnosis.root_causes() == []
    assert diagnosis.unsupported == []
    assert diagnosis.inconclusive == []
    assert diagnosis.unparsed == []
    assert diagnosis.passed == 4
    # The whole structure must survive JSON, because this is what a report
    # serialises.
    json.dumps(diagnosis.as_dict())


# ---------------------------------------------------------------------------
# The fault that matters, and the false-positive guard
# ---------------------------------------------------------------------------


def test_missing_forward_route_with_a_requirement_is_one_finding() -> None:
    model = two_router_model(r1_route=False)
    diagnosis = diagnose(model, parse_requirements(["PC-A can ping PC-B"]))

    assert len(diagnosis.verdicts) == 1
    assert len(diagnosis.findings) == 1
    finding = diagnosis.findings[0]
    assert finding.device == "R1"
    assert "ROUTE" in finding.category
    assert finding.status is Status.DERIVED
    assert finding.confidence == "MEDIUM"
    assert finding.evidence
    # The correction names the missing prefix and a next hop the model owns.
    assert "10.0.2.0/24" in finding.proposed_correction
    assert "10.0.12.2" in finding.proposed_correction
    assert "expected" in finding.proposed_correction
    assert len(diagnosis.root_causes()) == 1


def test_missing_route_without_a_requirement_is_zero_findings() -> None:
    """The guard Engine D exists for: no intent, no fault."""
    model = two_router_model(r1_route=False)

    empty = diagnose(model, [])
    assert empty.findings == []
    assert empty.root_causes() == []

    only_unparsed = diagnose(model, parse_requirements(["Enable OSPF on all routers"]))
    assert only_unparsed.findings == []
    assert only_unparsed.root_causes() == []
    assert only_unparsed.unparsed == ["Enable OSPF on all routers"]


def test_unresolvable_requirement_is_unsupported_not_a_finding() -> None:
    model = two_router_model()
    diagnosis = diagnose(model, parse_requirements(["GHOST must reach PC-B"]))

    assert diagnosis.findings == []
    assert diagnosis.unresolvable == ["GHOST must reach PC-B"]
    assert len(diagnosis.unsupported) == 1
    assert "GHOST" in diagnosis.unsupported[0]


# ---------------------------------------------------------------------------
# INCONCLUSIVE is neither a pass nor a fault
# ---------------------------------------------------------------------------


def test_inconclusive_requirement_produces_no_finding() -> None:
    model = two_router_model()
    model.devices["PC-Z"] = FakeDevice("PC-Z", model="PC-PT")
    # A device with no address: the verifier cannot resolve it.
    _iface(model, "PC-Z", "Fa0", None, None)

    diagnosis = diagnose(model, parse_requirements(["PC-Z can ping PC-B"]))

    assert len(diagnosis.verdicts) == 1
    assert diagnosis.verdicts[0].status is Status.INCONCLUSIVE
    assert diagnosis.findings == []
    assert diagnosis.root_causes() == []
    assert len(diagnosis.inconclusive) == 1
    assert diagnosis.inconclusive[0]["requirement"] == "PC-Z can ping PC-B"
    # Crucially it is not counted as a pass either.
    assert diagnosis.passed == 0


# ---------------------------------------------------------------------------
# Root-cause grouping
# ---------------------------------------------------------------------------


def test_three_victims_behind_one_shut_port_are_one_root_cause() -> None:
    model = two_router_model(transit_up=False)
    for n in range(3):
        name = f"PC-A{n + 1}"
        model.devices[name] = FakeDevice(name, model="PC-PT")
        _iface(model, name, "Fa0", f"10.0.1.{20 + n}", 24, ipv4_gateway="10.0.1.1")

    parsed = parse_requirements([f"PC-A{n} can ping PC-B" for n in (1, 2, 3)])
    diagnosis = diagnose(model, parsed)

    assert len(diagnosis.findings) == 3
    causes = diagnosis.root_causes()
    assert len(causes) == 1
    cause = causes[0]
    assert cause.device == "R1"
    assert cause.interface == "Gi0/1"
    assert cause.category == "ADMIN_SHUTDOWN"
    assert cause.count == 3
    assert len(cause.requirements) == 3


# ---------------------------------------------------------------------------
# Evidence provenance and confidence discipline
# ---------------------------------------------------------------------------


def test_every_evidence_string_comes_from_its_verdict() -> None:
    model = two_router_model(transit_up=False)
    diagnosis = diagnose(
        model,
        parse_requirements(
            [
                "PC-A can ping PC-B",
                "R1 must have a route to 10.0.2.0/24",
            ]
        ),
    )

    assert diagnosis.findings
    for finding in diagnosis.findings:
        verdict = diagnosis.verdicts[finding.verdict_index]
        assert finding.evidence, "a finding without evidence is not allowed"
        assert set(finding.evidence) <= set(verdict.evidence)
        # No evidence string is invented in the diagnosis layer.
        assert finding.evidence == list(verdict.evidence)


def test_confidence_never_exceeds_the_status() -> None:
    model = two_router_model(r1_route=False)
    diagnosis = diagnose(model, parse_requirements(["PC-A can ping PC-B"]))
    finding = diagnosis.findings[0]

    assert finding.status is Status.DERIVED
    assert finding.confidence in {"MEDIUM", "LOW"}
    assert any("no live observation" in reason for reason in finding.uncertainty)
    assert finding.proposed_correction


def test_finding_status_is_the_verdict_status() -> None:
    model = two_router_model(r1_route=False)
    diagnosis = diagnose(model, parse_requirements(["PC-A can ping PC-B"]))
    finding = diagnosis.findings[0]
    assert finding.status is diagnosis.verdicts[finding.verdict_index].status
