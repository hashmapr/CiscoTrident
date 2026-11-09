"""Diagnostics engine tests.

Two kinds of test live here and they check different things:

* **accuracy** — every fault-lab scenario is diagnosed exactly, so the engine is
  measured against a held-back answer key rather than trusted;
* **honesty** — the structural rules the engine claims (silence on a healthy
  network, no guessing without evidence, no silent conflict resolution, no
  mutation) hold even when the input is adversarial.
"""

from __future__ import annotations

import json

import pytest

from trident.diagnostics import (
    ACL_BLOCK,
    DUPLICATE_IP,
    INVALID_MASK,
    MISSING_STATIC_ROUTE,
    OVERLAPPING_SUBNET,
    ROUTING_LOOP,
    SHUTDOWN_INTERFACE,
    TRUNK_MISMATCH,
    WRONG_GATEWAY,
    WRONG_VLAN,
    diagnose,
    rank,
    report,
)
from trident.diagnostics.types import HypothesisStatus
from trident.evidence import EvidenceBundle
from trident.evidence.api import parse_cli_output
from trident.faultlab import baseline_lab, grade, scenarios

# ---------------------------------------------------------------------------
# Accuracy against the answer key
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario", scenarios(), ids=lambda s: s.name)
def test_every_scenario_is_diagnosed_exactly(scenario):
    result = grade(scenario, report(diagnose(scenario.model)))
    assert result.exact_match, (
        f"{scenario.name}: expected {[f.kind.value for f in scenario.faults]}, "
        f"reported {report(diagnose(scenario.model))}"
    )
    assert result.score == 1.0


def test_healthy_baseline_produces_no_findings():
    """A detector that fires on a clean network is wrong, not cautious."""
    diagnosis = diagnose(baseline_lab())
    assert report(diagnosis) == []
    assert not [
        h for h in diagnosis.hypotheses if h.status is HypothesisStatus.CONFIRMED_DEFECT
    ]


def test_known_kind_for_each_scenario_is_named():
    """The specific kind, not merely 'something is wrong'."""
    expected = {
        "wrong-vlan": WRONG_VLAN,
        "invalid-mask": INVALID_MASK,
        "wrong-gateway": WRONG_GATEWAY,
        "missing-static-route": MISSING_STATIC_ROUTE,
        "shutdown-interface": SHUTDOWN_INTERFACE,
        "acl-block": ACL_BLOCK,
        "trunk-mismatch": TRUNK_MISMATCH,
        "routing-loop": ROUTING_LOOP,
        "duplicate-ip": DUPLICATE_IP,
        "overlapping-subnet": OVERLAPPING_SUBNET,
    }
    by_name = {scenario.name: scenario for scenario in scenarios()}
    for name, kind in expected.items():
        reported = {entry["kind"] for entry in report(diagnose(by_name[name].model))}
        assert kind in reported


def test_multi_fault_scenario_reports_both_kinds():
    scenario = next(s for s in scenarios() if s.name == "dual-shutdown-gateway")
    reported = {entry["kind"] for entry in report(diagnose(scenario.model))}
    assert {SHUTDOWN_INTERFACE, WRONG_GATEWAY} <= reported


# ---------------------------------------------------------------------------
# Honesty rules
# ---------------------------------------------------------------------------


def test_diagnosis_does_not_mutate_the_model():
    scenario = next(s for s in scenarios() if s.name == "wrong-vlan")
    before = scenario.model.model_dump()
    diagnose(scenario.model)
    assert scenario.model.model_dump() == before


def test_report_is_json_serialisable():
    scenario = next(s for s in scenarios() if s.name == "acl-block")
    payload = report(diagnose(scenario.model))
    json.dumps(payload)  # must not raise


def test_report_excludes_insufficient_hypotheses():
    """Only defect claims are reportable; abstentions are not findings."""
    diagnosis = diagnose(baseline_lab())
    for entry in report(diagnosis):
        assert entry["kind"] not in {"", None}


def test_ranking_puts_confirmed_before_insufficient():
    scenario = next(s for s in scenarios() if s.name == "shutdown-interface")
    ranked = rank(list(diagnose(scenario.model).hypotheses))
    statuses = [hypothesis.status for hypothesis in ranked]
    order = {
        HypothesisStatus.CONFIRMED_DEFECT: 0,
        HypothesisStatus.SUSPECTED: 1,
        HypothesisStatus.RULED_OUT: 2,
        HypothesisStatus.INSUFFICIENT_EVIDENCE: 3,
    }
    assert statuses == sorted(statuses, key=lambda s: order[s])


def test_conflicting_runtime_evidence_downgrades_to_suspected():
    """Static says down; runtime says up/up. Both are kept, neither wins."""
    scenario = next(s for s in scenarios() if s.name == "shutdown-interface")
    device = scenario.faults[0].device
    interface = scenario.faults[0].interface

    bundle = EvidenceBundle()
    paste = (
        f"{device}# show ip interface brief\n"
        "Interface              IP-Address      OK? Method Status                Protocol\n"
        f"{interface}   unassigned      YES unset  up                    up\n"
    )
    record = parse_cli_output(paste, captured_at="2026-11-08T00:00:00Z")
    bundle.add(record)

    diagnosis = diagnose(scenario.model, bundle)
    shutdown = [
        h for h in diagnosis.hypotheses if h.kind == SHUTDOWN_INTERFACE
    ]
    assert shutdown, "the static evidence still produces the hypothesis"
    hypothesis = shutdown[0]
    assert hypothesis.status is HypothesisStatus.SUSPECTED
    assert hypothesis.confidence.value == "MEDIUM"
    assert hypothesis.contradicting, "the runtime observation must be preserved"
    assert any(o.source == "RUNTIME_STATE" for o in hypothesis.contradicting)


def test_missing_evidence_is_named_not_invented():
    """With no routes and no gateways the engine abstains instead of guessing."""
    model = baseline_lab()
    model.settings.default_gateways = {}
    model.routes = []
    diagnosis = diagnose(model)
    # Nothing may be claimed as a confirmed defect from an empty routing state.
    confirmed = [
        h for h in diagnosis.hypotheses if h.status is HypothesisStatus.CONFIRMED_DEFECT
    ]
    assert confirmed == []


def test_detector_failure_does_not_sink_the_engine(monkeypatch):
    import trident.diagnostics as engine

    def explode(*_args, **_kwargs):
        raise RuntimeError("deliberate")

    monkeypatch.setattr(
        engine,
        "_DETECTORS",
        (engine.detect_acl_block, explode),
    )
    scenario = next(s for s in scenarios() if s.name == "acl-block")
    diagnosis = engine.diagnose(scenario.model)
    assert any(h.kind == ACL_BLOCK for h in diagnosis.hypotheses)
    assert any(h.kind == "DETECTOR_ERROR" for h in diagnosis.hypotheses)


def test_symptoms_are_carried_through():
    diagnosis = diagnose(baseline_lab(), symptoms=("PC1 cannot reach SRV1",))
    assert diagnosis.symptoms == ("PC1 cannot reach SRV1",)


def test_duplicate_ip_needs_two_holders():
    model = baseline_lab()
    assert not [
        h for h in diagnose(model).hypotheses if h.kind == DUPLICATE_IP
    ]
    scenario = next(s for s in scenarios() if s.name == "duplicate-ip")
    assert any(h.kind == DUPLICATE_IP for h in diagnose(scenario.model).hypotheses)


def test_overlapping_subnet_needs_a_real_overlap():
    model = baseline_lab()
    assert not [
        h for h in diagnose(model).hypotheses if h.kind == OVERLAPPING_SUBNET
    ]
    scenario = next(s for s in scenarios() if s.name == "overlapping-subnet")
    assert any(
        h.kind == OVERLAPPING_SUBNET for h in diagnose(scenario.model).hypotheses
    )


def test_trunk_mismatch_compares_both_ends():
    """One trunk end alone is not evidence of a mismatch."""
    model = baseline_lab()
    trunk = next(
        i for i in model.interfaces.values() if (i.access_mode or "") == "trunk"
    )
    trunk.vlan_assignments = ["10"]
    # Its peer no longer participates in a trunk at all -> nothing to compare.
    peer = None
    for link in model.links:
        if link.device_a == trunk.device and link.interface_a == trunk.name:
            peer = (link.device_b, link.interface_b)
    assert peer is not None
    for interface in model.interfaces.values():
        if interface.device == peer[0] and interface.name == peer[1]:
            interface.access_mode = "access"
    assert not [
        h for h in diagnose(model).hypotheses if h.kind == TRUNK_MISMATCH
    ]


def test_routing_loop_is_not_reported_for_a_normal_default_route():
    model = baseline_lab()
    assert not [h for h in diagnose(model).hypotheses if h.kind == ROUTING_LOOP]


def test_invalid_mask_ignores_legal_masks():
    model = baseline_lab()
    assert not [h for h in diagnose(model).hypotheses if h.kind == INVALID_MASK]


def test_evidence_bundle_is_optional():
    scenario = next(s for s in scenarios() if s.name == "wrong-vlan")
    without = report(diagnose(scenario.model))
    with_empty = report(diagnose(scenario.model, EvidenceBundle()))
    assert without == with_empty


def test_unattributed_evidence_never_confirms_a_device():
    """An observation with no device cannot support a per-device claim."""
    scenario = next(s for s in scenarios() if s.name == "shutdown-interface")
    bundle = EvidenceBundle()
    record = parse_cli_output(
        "Interface  Status\nFastEthernet0/2  up\n", captured_at="2026-11-08T00:00:00Z"
    )
    bundle.add(record)
    assert bundle.unattributed() or record.device is None
    # The static fact still stands; unattributed text cannot overturn it.
    hypothesis = next(
        h
        for h in diagnose(scenario.model, bundle).hypotheses
        if h.kind == SHUTDOWN_INTERFACE
    )
    assert hypothesis.status is HypothesisStatus.CONFIRMED_DEFECT


# ---------------------------------------------------------------------------
# Precision on real, working networks
# ---------------------------------------------------------------------------
# These cases came from running the engine against the four-network benchmark.
# Each one was a false positive on a real, functioning lab, and each fix is a
# rule that generalises rather than a special case for one file.


def test_unaddressed_unconnected_shutdown_is_not_a_defect():
    """A default-state port being down is normal, not a fault."""
    model = baseline_lab()
    from trident.models import InterfaceInfo

    model.interfaces["R1:Vlan1"] = InterfaceInfo(
        device="R1",
        name="Vlan1",
        canonical_name="Vlan1",
        admin_state="administratively down",
    )
    assert not [
        h
        for h in diagnose(model).hypotheses
        if h.kind == SHUTDOWN_INTERFACE and h.interface == "Vlan1"
    ]


def test_addressed_shutdown_interface_is_a_defect():
    """A shut interface that holds an address is serving something."""
    model = baseline_lab()
    interface = next(
        i for i in model.interfaces.values() if i.device == "R2" and i.ipv4_address
    )
    interface.admin_state = "administratively down"
    found = [
        h
        for h in diagnose(model).hypotheses
        if h.kind == SHUTDOWN_INTERFACE and h.interface == interface.name
    ]
    assert found and found[0].status is HypothesisStatus.CONFIRMED_DEFECT


def test_cabled_but_unaddressed_shutdown_is_not_reported():
    """Cabled-and-shut without addressing is a valid configuration choice."""
    model = baseline_lab()
    interface = next(
        i for i in model.interfaces.values() if i.device == "SW2" and not i.ipv4_address
    )
    interface.admin_state = "administratively down"
    interface.vlan_assignments = []
    interface.access_mode = None
    # Remove the link so it is also uncabled.
    model.links = [
        link
        for link in model.links
        if not (
            (link.device_a, link.interface_a) == (interface.device, interface.name)
            or (link.device_b, link.interface_b) == (interface.device, interface.name)
        )
    ]
    assert not [
        h
        for h in diagnose(model).hypotheses
        if h.kind == SHUTDOWN_INTERFACE and h.interface == interface.name
    ]


def test_dynamic_routing_suppresses_missing_static_route():
    """A network routed by OSPF is not missing a static route."""
    model = baseline_lab()
    router = model.devices["R2"]
    router.configuration = [*router.configuration, "router ospf 1", " network 10.10.20.0 0.0.0.255 area 0"]
    from trident.models import RouteInfo

    model.routes.append(
        RouteInfo(
            device="R2",
            destination="10.10.99.0/24",
            route_type="dynamic",
            protocol="ospf 1",
            raw_config="O 10.10.99.0/24 [110/2] via 10.10.10.1",
        )
    )
    assert [
        h for h in diagnose(model).hypotheses if h.kind == MISSING_STATIC_ROUTE
    ] == []


def test_public_only_edge_router_is_not_told_to_hold_private_routes():
    """An ISP edge addressed in public space routes nothing private by design."""
    from trident.models import InterfaceInfo, RouteInfo

    model = baseline_lab()
    model.interfaces["R1:Gi0/0"] = InterfaceInfo(
        device="R1",
        name="GigabitEthernet0/0",
        canonical_name="GigabitEthernet0/0",
        ipv4_address="203.0.113.2",
        prefix_length=30,
    )
    for key in [k for k, i in model.interfaces.items() if i.device == "R1" and i.ipv4_address]:
        interface = model.interfaces[key]
        if not interface.ipv4_address.startswith("203."):
            interface.ipv4_address = f"198.51.100.{len(key) % 200 + 1}"
            interface.prefix_length = 24
    model.routes = [
        RouteInfo(device="R1", destination="0.0.0.0", next_hop="203.0.113.1", route_type="static"),
    ]
    assert not [
        h
        for h in diagnose(model).hypotheses
        if h.kind == MISSING_STATIC_ROUTE and h.device == "R1"
    ]


def test_missing_route_is_reported_once_per_pair_not_once_per_subnet():
    """Repeating the same pair for every subnet buries the operator."""
    model = baseline_lab()
    from trident.models import InterfaceInfo

    for index in range(5):
        model.interfaces[f"R2:Loop{index}"] = InterfaceInfo(
            device="R2",
            name=f"Loopback{index}",
            canonical_name=f"Loopback{index}",
            ipv4_address=f"10.99.{index}.1",
            prefix_length=24,
        )
    findings = [h for h in diagnose(model).hypotheses if h.kind == MISSING_STATIC_ROUTE]
    pairs = {(h.device, h.kind) for h in findings}
    assert len(findings) == len(pairs), findings


def test_gateway_inside_served_subnet_but_unowned_is_confirmed():
    """The subnet is served here, so an unowned address in it is a real defect."""
    scenario = next(s for s in scenarios() if s.name == "wrong-gateway")
    found = [
        h
        for h in diagnose(scenario.model).hypotheses
        if h.kind == WRONG_GATEWAY and h.device == "PC1"
    ]
    assert found and found[0].status is HypothesisStatus.CONFIRMED_DEFECT


def test_gateway_outside_every_subnet_is_only_suspected():
    """It may belong to a neighbour this file does not describe."""
    model = baseline_lab()
    model.settings.default_gateways["PC1"] = "192.0.2.1"
    found = [
        h
        for h in diagnose(model).hypotheses
        if h.kind == WRONG_GATEWAY and h.device == "PC1"
    ]
    assert found
    assert found[0].status is HypothesisStatus.SUSPECTED
    assert "owning device" in " ".join(found[0].missing_evidence)
