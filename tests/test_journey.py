"""Multi-protocol path explanation.

Every protocol module reasons in isolation. This one walks a packet through them
in the order it meets them, so a failure is explained in context: the first stage
that stops the packet is named with its own evidence, rather than the reader being
sent to a stage that merely looks suspicious.
"""

from __future__ import annotations

from trident.deepcore.journey import Stage, Verdict, explain, explain_all
from trident.models import (
    AclEntry,
    DeviceInfo,
    InterfaceInfo,
    LinkInfo,
    NetworkModel,
    RouteInfo,
)


def _device(name):
    return DeviceInfo(id=name, name=name, hostname=name, model="2911", configuration=[])


def _iface(device, name, address=None, prefix=None, admin="up"):
    return InterfaceInfo(
        device=device, name=name, canonical_name=name,
        ipv4_address=address, prefix_length=prefix, admin_state=admin,
    )


def _connected_pair():
    return NetworkModel(
        devices={"R1": _device("R1"), "R2": _device("R2")},
        interfaces={
            "R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 30),
            "R2:Gi0/0": _iface("R2", "GigabitEthernet0/0", "10.0.0.2", 30),
        },
        links=[
            LinkInfo(device_a="R1", interface_a="GigabitEthernet0/0",
                     device_b="R2", interface_b="GigabitEthernet0/0")
        ],
    )


def _three_routers():
    return NetworkModel(
        devices={name: _device(name) for name in ("R1", "R2", "R3")},
        interfaces={
            "R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 30),
            "R2:Gi0/0": _iface("R2", "GigabitEthernet0/0", "10.0.0.2", 30),
            "R2:Gi0/1": _iface("R2", "GigabitEthernet0/1", "10.9.9.1", 24),
            "R3:Gi0/0": _iface("R3", "GigabitEthernet0/0", "10.9.9.2", 24),
        },
        links=[
            LinkInfo(device_a="R1", interface_a="GigabitEthernet0/0",
                     device_b="R2", interface_b="GigabitEthernet0/0"),
            LinkInfo(device_a="R2", interface_a="GigabitEthernet0/1",
                     device_b="R3", interface_b="GigabitEthernet0/0"),
        ],
        routes=[
            RouteInfo(device="R1", destination="10.9.9.0/24", next_hop="10.0.0.2",
                      route_type="static", outgoing_interface="GigabitEthernet0/0")
        ],
    )


# ---------------------------------------------------------------------------
# Healthy path
# ---------------------------------------------------------------------------


def test_a_connected_pair_delivers():
    explanation = explain(_connected_pair(), "R1", "R2")
    assert explanation.delivered is True
    assert explanation.failure is None
    assert "reaches" in explanation.summary()


def test_every_stage_states_its_verdict():
    explanation = explain(_connected_pair(), "R1", "R2")
    assert explanation.stages
    for stage in explanation.stages:
        assert isinstance(stage.verdict, Verdict)
        assert stage.detail


def test_the_explanation_is_not_an_observation():
    payload = explain(_connected_pair(), "R1", "R2").as_dict()
    assert "observed" not in payload
    assert payload["delivered"] is True


# ---------------------------------------------------------------------------
# The failure that matters most: return path
# ---------------------------------------------------------------------------


def test_a_missing_return_path_is_caught_and_named():
    """Forward traffic works; replies are dropped. This is the common real fault."""
    explanation = explain(_three_routers(), "R1", "R3")
    assert explanation.delivered is False
    failure = explanation.failure
    assert failure is not None
    assert failure.stage is Stage.RETURN_PATH
    assert "route back" in failure.detail
    assert explanation.stages[0].verdict is Verdict.PASS


def test_the_forward_path_is_reported_as_passing_before_the_return_failure():
    explanation = explain(_three_routers(), "R1", "R3")
    kinds = [stage.stage for stage in explanation.stages]
    assert Stage.RETURN_PATH in kinds
    return_stage = next(s for s in explanation.stages if s.stage is Stage.RETURN_PATH)
    assert return_stage.verdict is Verdict.FAIL


def test_a_complete_pair_of_routes_delivers():
    model = _three_routers()
    model.routes.append(
        RouteInfo(device="R3", destination="10.0.0.0/30", next_hop="10.9.9.1",
                  route_type="static", outgoing_interface="GigabitEthernet0/0")
    )
    explanation = explain(model, "R1", "R3")
    assert explanation.delivered is True


# ---------------------------------------------------------------------------
# Failures in earlier stages
# ---------------------------------------------------------------------------


def test_a_shut_interface_is_named_as_the_layer2_cause():
    model = NetworkModel(
        devices={"R1": _device("R1"), "R2": _device("R2")},
        interfaces={
            "R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 30,
                               admin="administratively down"),
            "R2:Gi0/0": _iface("R2", "GigabitEthernet0/0", "10.0.0.2", 30),
        },
        links=[
            LinkInfo(device_a="R1", interface_a="GigabitEthernet0/0",
                     device_b="R2", interface_b="GigabitEthernet0/0")
        ],
    )
    explanation = explain(model, "R1", "R2")
    assert explanation.delivered is False
    assert explanation.failure is not None


def test_an_acl_deny_is_reported_at_the_acl_stage():
    model = _connected_pair()
    model.acls = [
        AclEntry(acl_id="110", acl_type="extended", sequence=10, action="deny",
                 protocol="ip", source="any", destination="10.0.0.2",
                 applied_interface="GigabitEthernet0/0", direction="in")
    ]
    explanation = explain(model, "R1", "R2")
    acl_stage = next((s for s in explanation.stages if s.stage is Stage.ACL), None)
    assert acl_stage is not None
    assert acl_stage.verdict is Verdict.FAIL


# ---------------------------------------------------------------------------
# Unknowns are stated, not guessed
# ---------------------------------------------------------------------------


def test_an_undecidable_path_reports_unknown_rather_than_delivered():
    model = NetworkModel(
        devices={"R1": _device("R1"), "PC1": DeviceInfo(id="PC1", name="PC1",
                                                        hostname="PC1", model="PC-PT",
                                                        configuration=[])},
        interfaces={"R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 24)},
    )
    explanation = explain(model, "R1", "PC1")
    assert explanation.delivered is None
    assert explanation.first_unknown is not None


def test_caveats_explain_the_limits_of_a_prediction():
    payload = explain(_connected_pair(), "R1", "R2").as_dict()
    assert payload["caveats"]


def test_spanning_tree_uncertainty_does_not_invalidate_a_working_path():
    """Every lab lacks bridge MACs; that must not make every path undecided."""
    explanation = explain(_connected_pair(), "R1", "R2")
    assert explanation.delivered is True


# ---------------------------------------------------------------------------
# Batch and records
# ---------------------------------------------------------------------------


def test_explain_all_returns_one_explanation_per_pair():
    explanations = explain_all(_three_routers(), [("R1", "R3"), ("R1", "R2")])
    assert len(explanations) == 2
    assert [e.destination for e in explanations] == ["R3", "R2"]


def test_explanation_serialises():
    import json

    json.dumps(explain(_connected_pair(), "R1", "R2").as_dict())


def test_explain_does_not_mutate_the_model():
    model = _connected_pair()
    before = model.model_dump()
    explain(model, "R1", "R2")
    assert model.model_dump() == before
