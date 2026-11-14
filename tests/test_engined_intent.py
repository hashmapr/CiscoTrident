"""Engine D must answer "does this network do what it was meant to do?"

The tests are built around the failure that motivated Engine D. A detector
asking "is this configuration odd?" reported five faults on a documented-healthy
network, because a router with a correct default route looks identical to one
missing a route. Engine D is only allowed to report a missing route when intent
says the path is required.

Models are built by hand here rather than generated, so each test states its
world explicitly and nothing depends on pkt_core or Packet Tracer.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from trident.engined import (
    Endpoint,
    NetworkIntent,
    Requirement,
    Status,
    explain,
    verify_intent,
    verify_requirement,
)
from trident.engined.intent import IntentError

# ---------------------------------------------------------------------------
# A minimal model, shaped like NetworkModel's public surface
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
    #: Packet Tracer model string. Classification reads this, because
    #: ``device_type`` is None in every model this pipeline produces.
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
    key = f"{device}:{name}"
    model.interfaces[key] = FakeInterface(device, name, address, prefix, **kw)


def two_router_model(*, r1_route: bool = True) -> FakeModel:
    """R1 -- 10.0.12.0/30 -- R2, with one LAN each.

    With ``r1_route=False`` R1 has no route to the far LAN. That is not a fault
    unless intent says R1's hosts must reach it.
    """
    m = FakeModel(
        devices={
            "R1": FakeDevice("R1", model="2911"),
            "R2": FakeDevice("R2", model="2911"),
            "PC-A": FakeDevice("PC-A", model="PC-PT"),
            "PC-B": FakeDevice("PC-B", model="PC-PT"),
        },
        interfaces={},
    )
    _iface(m, "R1", "Gi0/0", "10.0.1.1", 24)
    _iface(m, "R1", "Gi0/1", "10.0.12.1", 30)
    _iface(m, "R2", "Gi0/0", "10.0.2.1", 24)
    _iface(m, "R2", "Gi0/1", "10.0.12.2", 30)
    _iface(m, "PC-A", "Fa0", "10.0.1.10", 24)
    _iface(m, "PC-B", "Fa0", "10.0.2.10", 24)
    m.routes.append(FakeRoute("R2", "10.0.1.0", "10.0.12.1"))
    if r1_route:
        m.routes.append(FakeRoute("R1", "10.0.2.0", "10.0.12.2"))
    return m


# ---------------------------------------------------------------------------
# The false-positive guard — the reason Engine D exists
# ---------------------------------------------------------------------------


def test_no_intent_means_no_findings() -> None:
    """A network with no stated intent cannot have a requirement violated.

    This is the exact test the old detector failed: it treated two existing
    subnets as an implicit requirement that they reach each other.
    """
    model = two_router_model(r1_route=False)
    report = verify_intent(model, NetworkIntent(name="empty"))
    assert report.verdicts == []
    assert report.localize_faults() == []


def test_missing_route_is_not_a_fault_without_intent() -> None:
    """The route is absent; nothing says it is needed; so nothing is reported."""
    model = two_router_model(r1_route=False)
    report = verify_intent(model, NetworkIntent(name="no requirements"))
    assert report.failures == []
    assert report.localize_faults() == []


def test_a_requirement_that_crosses_the_gap_is_still_reported() -> None:
    """B -> A fails too, because the return path is the missing one.

    This is not a special case; it is the return-path rule working. A packet
    reaches A, but A's reply needs the route R1 lacks. Asserting that B -> A
    "passes" here would require Engine D to ignore half the conversation.
    """
    model = two_router_model(r1_route=False)
    intent = NetworkIntent(
        requirements=[Requirement(Endpoint("PC-B"), Endpoint("PC-A"), "B reaches A")]
    )
    report = verify_intent(model, intent)
    faults = report.localize_faults()
    assert faults, "the return path is broken and must be reported"
    assert faults[0].device == "R1"


def test_missing_route_is_a_fault_when_intent_requires_it() -> None:
    """Same network, opposite verdict, because intent says the path is needed."""
    model = two_router_model(r1_route=False)
    intent = NetworkIntent(
        name="a-must-reach-b",
        requirements=[Requirement(Endpoint("PC-A"), Endpoint("PC-B"), "A reaches B")],
    )
    report = verify_intent(model, intent)
    assert len(report.failures) == 1
    faults = report.localize_faults()
    assert len(faults) == 1
    assert faults[0].device == "R1"
    # Agent A's refinement names the direction: a forward route is what is
    # missing here, which matters when only one direction is broken.
    assert faults[0].kind in {"MISSING_ROUTE", "MISSING_FORWARD_ROUTE"}


def test_the_same_fault_does_not_exist_on_a_healthy_network() -> None:
    """Control: add the route back and the identical intent passes."""
    model = two_router_model(r1_route=True)
    intent = NetworkIntent(
        name="a-must-reach-b",
        requirements=[Requirement(Endpoint("PC-A"), Endpoint("PC-B"), "A reaches B")],
    )
    report = verify_intent(model, intent)
    assert report.failures == []
    assert report.verdicts[0].reachable is True


# ---------------------------------------------------------------------------
# Status semantics
# ---------------------------------------------------------------------------


def test_static_analysis_yields_derived_never_verified() -> None:
    """Nothing observed the packet, so the honest status is DERIVED."""
    model = two_router_model()
    verdict = verify_requirement(model, Requirement(Endpoint("PC-A"), Endpoint("PC-B")))
    assert verdict.status is Status.DERIVED
    assert verdict.reachable is True


def test_live_agreement_upgrades_to_verified() -> None:
    model = two_router_model()
    verdict = verify_requirement(
        model, Requirement(Endpoint("PC-A"), Endpoint("PC-B")), live_observation=True
    )
    assert verdict.status is Status.VERIFIED


def test_live_disagreement_is_contradicted_not_verified() -> None:
    """A ping that fails while analysis says reachable is a contradiction."""
    model = two_router_model()
    verdict = verify_requirement(
        model, Requirement(Endpoint("PC-A"), Endpoint("PC-B")), live_observation=False
    )
    assert verdict.status is Status.CONTRADICTED
    assert verdict.live_disagrees is True


def test_unresolvable_endpoint_is_inconclusive_with_a_reason() -> None:
    model = two_router_model()
    verdict = verify_requirement(model, Requirement(Endpoint("PC-A"), Endpoint("NOPE")))
    assert verdict.status is Status.INCONCLUSIVE
    assert verdict.missing
    assert "NOPE" in " ".join(verdict.missing)


def test_a_shutdown_interface_is_localized_to_that_interface() -> None:
    model = two_router_model()
    model.interfaces["R1:Gi0/1"].admin_state = "administratively down"
    intent = NetworkIntent(
        requirements=[Requirement(Endpoint("PC-A"), Endpoint("PC-B"))]
    )
    report = verify_intent(model, intent)
    faults = report.localize_faults()
    assert faults, "a shut transit interface must be reported"
    assert faults[0].device == "R1"


def test_five_hosts_behind_one_port_is_one_fault() -> None:
    """Root-cause localization: grouping, not one finding per victim."""
    model = two_router_model()
    model.interfaces["R1:Gi0/1"].admin_state = "administratively down"
    for n in range(5):
        name = f"PC-A{n}"
        model.devices[name] = FakeDevice(name, model="PC-PT")
        _iface(model, name, "Fa0", f"10.0.1.{20 + n}", 24)
    intent = NetworkIntent(
        requirements=[
            Requirement(Endpoint(f"PC-A{n}"), Endpoint("PC-B")) for n in range(5)
        ]
    )
    report = verify_intent(model, intent)
    assert len(report.failures) >= 1
    faults = report.localize_faults()
    assert len(faults) == 1, [f.as_dict() for f in faults]
    assert len(faults[0].affected) >= 1


# ---------------------------------------------------------------------------
# Intent gating
# ---------------------------------------------------------------------------


def test_any_to_any_is_explicit_and_expands() -> None:
    model = two_router_model()
    intent = NetworkIntent.any_to_any(["10.0.1.0/24", "10.0.2.0/24"])
    expanded = intent.expand(model)
    assert expanded, "any_to_any must expand to concrete requirements"
    devices = {r.src.device for r in expanded} | {r.dst.device for r in expanded}
    assert "PC-A" in devices


def test_intent_round_trips_through_dict() -> None:
    intent = NetworkIntent(
        name="r",
        requirements=[Requirement(Endpoint("PC-A"), Endpoint("PC-B"), "d")],
        isolated_pairs=[(Endpoint("PC-A"), Endpoint("PC-C"))],
    )
    restored = NetworkIntent.from_dict(intent.as_dict())
    assert restored.name == intent.name
    assert restored.requirements[0].src.device == "PC-A"
    assert restored.isolated_pairs[0][1].device == "PC-C"


def test_intent_validation_rejects_an_unknown_device() -> None:
    model = two_router_model()
    intent = NetworkIntent(requirements=[Requirement(Endpoint("GHOST"), Endpoint("PC-B"))])
    problems = intent.validate(model)
    assert any("GHOST" in p for p in problems)


def test_endpoint_without_address_raises_rather_than_guessing() -> None:
    model = two_router_model()
    with pytest.raises(IntentError):
        Endpoint("SW-UNKNOWN").resolve(model)


# ---------------------------------------------------------------------------
# Segmentation
# ---------------------------------------------------------------------------


def test_isolated_pair_that_cannot_reach_is_correct() -> None:
    """Refusing to reach an isolated network is a pass, not a failure."""
    model = two_router_model(r1_route=False)
    intent = NetworkIntent(
        name="segmented",
        isolated_pairs=[(Endpoint("PC-A"), Endpoint("PC-B"))],
    )
    report = verify_intent(model, intent)
    assert report.localize_faults() == []


# ---------------------------------------------------------------------------
# Explain is presentational only
# ---------------------------------------------------------------------------


def test_explain_does_not_change_the_status() -> None:
    model = two_router_model()
    verdict = verify_requirement(model, Requirement(Endpoint("PC-A"), Endpoint("PC-B")))
    before = verdict.status
    text = explain(verdict)
    assert verdict.status is before
    assert "PC-A" in text
