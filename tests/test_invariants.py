"""Formal network invariants.

The claim this suite protects: "PROVEN" means the model could enumerate every case
it represents and found no violation — not that a check happened to pass. When a
rule depends on behaviour the model does not represent, it must not be proven.
"""

from __future__ import annotations

from trident.deepcore.invariants import (
    AllAddressedInterfacesUp,
    Counterexample,
    GatewaysOnAServedSubnet,
    Isolation,
    Reachability,
    Result,
    UniqueAddresses,
    evaluate,
    summary,
)
from trident.models import (
    DeviceInfo,
    InterfaceInfo,
    NetworkModel,
    SettingsInfo,
)


def _device(name, model="2911"):
    return DeviceInfo(id=name, name=name, hostname=name, model=model, configuration=[])


def _iface(device, name, address=None, prefix=None, admin="up"):
    return InterfaceInfo(
        device=device, name=name, canonical_name=name,
        ipv4_address=address, prefix_length=prefix, admin_state=admin,
    )


def _pair() -> NetworkModel:
    return NetworkModel(
        devices={"R1": _device("R1"), "R2": _device("R2")},
        interfaces={
            "R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 30),
            "R2:Gi0/0": _iface("R2", "GigabitEthernet0/0", "10.0.0.2", 30),
        },
    )


# ---------------------------------------------------------------------------
# Unique addresses
# ---------------------------------------------------------------------------


def test_unique_addresses_is_proven_on_a_clean_network():
    verdict = UniqueAddresses().evaluate(_pair(), __import__(
        "trident.deepcore", fromlist=["DeepCore"]
    ).DeepCore(_pair()))
    assert verdict.result is Result.PROVEN
    assert verdict.checked == 2


def test_duplicate_address_is_violated_with_a_counterexample():
    model = NetworkModel(
        devices={"R1": _device("R1"), "R2": _device("R2")},
        interfaces={
            "R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 24),
            "R2:Gi0/0": _iface("R2", "GigabitEthernet0/0", "10.0.0.1", 24),
        },
    )
    verdict = evaluate(model, [UniqueAddresses()])[0]
    assert verdict.result is Result.VIOLATED
    assert verdict.counterexamples
    # The counterexample names both holders, so it is actionable.
    evidence = verdict.counterexamples[0].evidence
    assert "R1" in evidence and "R2" in evidence


# ---------------------------------------------------------------------------
# Gateways
# ---------------------------------------------------------------------------


def test_no_gateways_is_proven_not_inconclusive():
    verdict = evaluate(_pair(), [GatewaysOnAServedSubnet()])[0]
    assert verdict.result is Result.PROVEN
    assert verdict.checked == 0


def test_an_unowned_gateway_is_violated():
    model = _pair()
    model.settings = SettingsInfo(default_gateways={"PC1": "10.0.0.99"})
    verdict = evaluate(model, [GatewaysOnAServedSubnet()])[0]
    assert verdict.result is Result.VIOLATED
    assert "not assigned" in verdict.counterexamples[0].description


def test_an_owned_gateway_is_proven():
    model = _pair()
    model.settings = SettingsInfo(default_gateways={"PC1": "10.0.0.1"})
    verdict = evaluate(model, [GatewaysOnAServedSubnet()])[0]
    assert verdict.result is Result.PROVEN


# ---------------------------------------------------------------------------
# Addressed interfaces up
# ---------------------------------------------------------------------------


def test_a_shut_addressed_interface_is_violated():
    model = NetworkModel(
        devices={"R1": _device("R1")},
        interfaces={"R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 24,
                                       admin="administratively down")},
    )
    verdict = evaluate(model, [AllAddressedInterfacesUp()])[0]
    assert verdict.result is Result.VIOLATED
    assert verdict.counterexamples[0].interface == "GigabitEthernet0/0"


def test_an_svi_being_down_is_not_a_violation():
    """An SVI follows its member ports; its state is derived, not configured."""
    model = NetworkModel(
        devices={"SW1": _device("SW1", "2960-24TT")},
        interfaces={"SW1:Vlan1": _iface("SW1", "Vlan1", "10.0.0.1", 24,
                                        admin="administratively down")},
    )
    verdict = evaluate(model, [AllAddressedInterfacesUp()])[0]
    assert verdict.result is Result.PROVEN
    assert verdict.checked == 0


# ---------------------------------------------------------------------------
# Reachability
# ---------------------------------------------------------------------------


def test_reachability_is_proven_when_forwarding_predicts_delivery():
    model = _pair()
    verdict = evaluate(model, [Reachability("R1", "R2")])[0]
    assert verdict.result is Result.PROVEN
    # A proof rests on stated assumptions, never on nothing.
    assert verdict.assumptions


def test_reachability_is_violated_with_the_failing_step():
    model = NetworkModel(
        devices={"R1": _device("R1"), "R2": _device("R2")},
        interfaces={
            "R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 30,
                               admin="administratively down"),
            "R2:Gi0/0": _iface("R2", "GigabitEthernet0/0", "10.0.0.2", 30),
        },
    )
    verdict = evaluate(model, [Reachability("R1", "R2")])[0]
    assert verdict.result is Result.VIOLATED
    assert verdict.counterexamples
    assert verdict.counterexamples[0].path


def test_reachability_is_inconclusive_when_the_engine_cannot_decide():
    """A host with no parsed address cannot be reasoned about, so nothing is proven."""
    model = NetworkModel(
        devices={"R1": _device("R1"), "PC1": _device("PC1", "PC-PT")},
        interfaces={"R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 24)},
    )
    verdict = evaluate(model, [Reachability("R1", "PC1")])[0]
    assert verdict.result is Result.INCONCLUSIVE
    assert verdict.limitations


# ---------------------------------------------------------------------------
# Isolation
# ---------------------------------------------------------------------------


def test_isolation_is_violated_when_traffic_gets_through():
    model = _pair()
    verdict = evaluate(model, [Isolation("R1", "R2")])[0]
    assert verdict.result is Result.VIOLATED
    assert verdict.counterexamples


def test_isolation_is_proven_when_the_path_is_blocked():
    model = NetworkModel(
        devices={"R1": _device("R1"), "R2": _device("R2")},
        interfaces={
            "R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 30,
                               admin="administratively down"),
            "R2:Gi0/0": _iface("R2", "GigabitEthernet0/0", "10.0.0.2", 30),
        },
    )
    verdict = evaluate(model, [Isolation("R1", "R2")])[0]
    assert verdict.result is Result.PROVEN
    # A proof of isolation must state what it did NOT consider.
    assert verdict.limitations


# ---------------------------------------------------------------------------
# Summary and serialisation
# ---------------------------------------------------------------------------


def test_summary_counts_every_outcome():
    model = _pair()
    verdicts = evaluate(model)
    payload = summary(verdicts)
    assert payload["total"] == len(verdicts)
    assert sum(payload["counts"].values()) == len(verdicts)


def test_a_violation_appears_in_the_summary():
    model = NetworkModel(
        devices={"R1": _device("R1"), "R2": _device("R2")},
        interfaces={
            "R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 24),
            "R2:Gi0/0": _iface("R2", "GigabitEthernet0/0", "10.0.0.1", 24),
        },
    )
    payload = summary(evaluate(model))
    assert payload["counts"]["VIOLATED"] >= 1
    assert payload["violated"]


def test_every_verdict_serialises():
    import json

    json.dumps([verdict.as_dict() for verdict in evaluate(_pair())])


def test_counterexamples_serialise():
    example = Counterexample(device="R1", interface="Gi0/0", description="x", evidence="y")
    import json

    json.dumps(example.as_dict())


def test_default_invariants_need_no_parameters():
    verdicts = evaluate(_pair())
    assert {verdict.name for verdict in verdicts} == {
        "unique-addresses",
        "gateways-exist",
        "addressed-interfaces-up",
    }


def test_evaluation_does_not_mutate_the_model():
    model = _pair()
    before = model.model_dump()
    evaluate(model)
    assert model.model_dump() == before


def test_proven_never_claims_more_than_the_model_represents():
    """A reachability proof must carry assumptions and limits."""
    verdict = evaluate(_pair(), [Reachability("R1", "R2")])[0]
    assert verdict.assumptions
    # And an isolation proof must name what was not considered.
    blocked = evaluate(_pair(), [Isolation("R1", "R2")])[0]
    assert blocked.counterexamples or blocked.limitations
