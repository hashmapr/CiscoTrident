"""Adversarial verification must disagree when the diagnosis is wrong.

Each test states a small topology and a finding, then asserts what independent
re-derivation does with it. The fixtures are hand-built (no pkt_core, no Packet
Tracer) so every test's world is explicit.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from trident.assessment.verify_independent import challenge
from trident.engined import Endpoint, NetworkIntent, Requirement

# ---------------------------------------------------------------------------
# Minimal model, shaped like NetworkModel's public surface
# ---------------------------------------------------------------------------


@dataclass
class FakeInterface:
    device: str
    name: str
    ipv4_address: str | None = None
    prefix_length: int | None = None
    admin_state: str = "up"
    access_mode: str | None = None
    vlan_assignments: list[str] = field(default_factory=list)
    ipv4_gateway: str | None = None


@dataclass
class FakeRoute:
    device: str
    destination: str
    next_hop: str | None = None
    mask: str | None = None


@dataclass
class FakeLink:
    device_a: str
    interface_a: str
    device_b: str
    interface_b: str


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


def _iface(model: FakeModel, device: str, name: str, address: str, prefix: int, **kw) -> None:
    model.interfaces[f"{device}:{name}"] = FakeInterface(device, name, address, prefix, **kw)


def path_model(*, r1_route: bool = True) -> FakeModel:
    """PC-A -- R1 -- 10.0.12.0/30 -- R2 -- PC-B."""
    model = FakeModel(
        devices={
            "R1": FakeDevice("R1", model="2911"),
            "R2": FakeDevice("R2", model="2911"),
            "PC-A": FakeDevice("PC-A", model="PC-PT"),
            "PC-B": FakeDevice("PC-B", model="PC-PT"),
        },
        interfaces={},
    )
    _iface(model, "R1", "Gi0/0", "10.0.1.1", 24)
    _iface(model, "R1", "Gi0/1", "10.0.12.1", 30)
    _iface(model, "R2", "Gi0/0", "10.0.2.1", 24)
    _iface(model, "R2", "Gi0/1", "10.0.12.2", 30)
    _iface(model, "PC-A", "Fa0", "10.0.1.10", 24, ipv4_gateway="10.0.1.1")
    _iface(model, "PC-B", "Fa0", "10.0.2.10", 24, ipv4_gateway="10.0.2.1")
    model.routes.append(FakeRoute("R2", "10.0.1.0", "10.0.12.1", "255.255.255.0"))
    if r1_route:
        model.routes.append(FakeRoute("R1", "10.0.2.0", "10.0.12.2", "255.255.255.0"))
    return model


def intent() -> NetworkIntent:
    return NetworkIntent(
        name="pc-a-to-pc-b",
        requirements=[Requirement(Endpoint("PC-A"), Endpoint("PC-B"), "PC-A -> PC-B")],
    )


# ---------------------------------------------------------------------------
# Confirmation requires independent reproduction
# ---------------------------------------------------------------------------


def test_true_finding_is_confirmed_by_independent_rederivation() -> None:
    model = path_model()
    model.interfaces["R1:Gi0/1"].admin_state = "administratively down"
    findings = [
        {
            "device": "R1",
            "interface": "Gi0/1",
            "category": "ADMIN_SHUTDOWN",
            "detail": "R1 Gi0/1 is administratively down",
            "affected": ["PC-A -> PC-B"],
        }
    ]

    report = challenge(model, intent(), findings)

    assert len(report.confirmed) == 1
    assert report.confirmed[0]["device"] == "R1"
    assert report.confirmed[0]["interface"] == "Gi0/1"
    assert report.confirmed[0]["independent_evidence"]
    assert report.rejected == []


def test_finding_naming_an_absent_interface_is_rejected() -> None:
    model = path_model()
    findings = [
        {
            "device": "R1",
            "interface": "Gi9/9",
            "category": "ADMIN_SHUTDOWN",
            "detail": "R1 Gi9/9 is administratively down",
            "affected": ["PC-A -> PC-B"],
        }
    ]

    report = challenge(model, intent(), findings)

    assert len(report.rejected) == 1
    assert "no interface" in report.rejected[0]["reason"].lower()
    assert report.confirmed == []


def test_finding_citing_a_requirement_outside_intent_is_rejected() -> None:
    model = path_model()
    findings = [
        {
            "device": "R1",
            "interface": "Gi0/1",
            "category": "ADMIN_SHUTDOWN",
            "detail": "R1 Gi0/1 is administratively down",
            "requirement": "PC-X -> PC-Y",
        }
    ]

    report = challenge(model, intent(), findings)

    assert len(report.rejected) == 1
    assert "not in the intent" in report.rejected[0]["reason"]
    assert report.confirmed == []


def test_inconclusive_based_finding_is_rejected() -> None:
    model = path_model()
    findings = [
        {
            "device": "R1",
            "interface": "Gi0/1",
            "category": "MISSING_ROUTE",
            "detail": "dynamic routing is not modelled",
            "status": "INCONCLUSIVE",
            "evidence": ["dynamic routing is not modelled, so no route table can be derived"],
            "affected": ["PC-A -> PC-B"],
        }
    ]

    report = challenge(model, intent(), findings)

    assert len(report.rejected) == 1
    assert "inconclusive" in report.rejected[0]["reason"].lower()
    assert report.confirmed == []


# ---------------------------------------------------------------------------
# False negatives: what the diagnosis did not report
# ---------------------------------------------------------------------------


def test_shut_interface_the_diagnosis_missed_is_reported() -> None:
    model = path_model()
    model.interfaces["R1:Gi0/1"].admin_state = "down"
    findings = [
        {
            "device": "R2",
            "interface": None,
            "category": "MISSING_ROUTE",
            "detail": "R2 has no route covering 10.0.1.10",
            "affected": ["PC-A -> PC-B"],
        }
    ]

    report = challenge(model, intent(), findings)

    assert any(
        item["device"] == "R1" and item["interface"] == "Gi0/1" and item["kind"] == "ADMIN_SHUTDOWN"
        for item in report.missed
    ), report.missed


def test_report_distinguishes_confirmed_from_alternative_explanations() -> None:
    model = path_model(r1_route=False)
    model.devices["SW1"] = FakeDevice("SW1", model="2960")
    model.interfaces["SW1:Fa0/1"] = FakeInterface("SW1", "Fa0/1")
    findings = [
        {
            "device": "R1",
            "interface": None,
            "category": "MISSING_FORWARD_ROUTE",
            "detail": "R1 has no route covering 10.0.2.10",
            "affected": ["PC-A -> PC-B"],
        },
        {
            "device": "SW1",
            "interface": "Fa0/1",
            "category": "TRUNK_VLAN_GAP",
            "detail": "trunk does not permit VLAN 10",
            "affected": ["PC-A -> PC-B"],
        },
    ]

    report = challenge(model, intent(), findings)

    assert [item["device"] for item in report.confirmed] == ["R1"]
    assert [item["device"] for item in report.alternative_explanations] == ["SW1"]
    assert report.alternative_explanations[0]["possible_explanations"]
    assert not any(item["device"] == "SW1" for item in report.confirmed)
    assert "confirmed" in report.as_dict()["counts"]
