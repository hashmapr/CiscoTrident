"""Regression tests for the peer-interface / neighbour attribution defects.

Each case was a false VERIFIED answer in the four-network benchmark. They are
general behaviours, not benchmark-specific strings.
"""

from __future__ import annotations

from trident.models import DeviceInfo, InterfaceInfo, LinkInfo, NetworkModel
from trident.reasoning import intent
from trident.reasoning import operations as ops


def _model() -> NetworkModel:
    """Two switches sharing a port name; only the cable tells them apart."""
    return NetworkModel(
        devices={
            "CSW1": DeviceInfo(id="CSW1", name="CSW1", hostname="CSW1"),
            "DSW-A1": DeviceInfo(id="DSW-A1", name="DSW-A1", hostname="DSW-A1"),
            "DSW-A2": DeviceInfo(id="DSW-A2", name="DSW-A2", hostname="DSW-A2"),
            "Phone2": DeviceInfo(id="Phone2", name="Phone2", hostname="Phone2"),
            "PC2": DeviceInfo(id="PC2", name="PC2", hostname="PC2"),
            "ASW-A3": DeviceInfo(id="ASW-A3", name="ASW-A3", hostname="ASW-A3"),
        },
        interfaces={
            # port names exist in config on both switches
            "CSW1:GigabitEthernet1/1/2": InterfaceInfo(
                device="CSW1", name="GigabitEthernet1/1/2", canonical_name="GigabitEthernet1/1/2"
            ),
            "DSW-A2:GigabitEthernet1/1/2": InterfaceInfo(
                device="DSW-A2", name="GigabitEthernet1/1/2", canonical_name="GigabitEthernet1/1/2"
            ),
        },
        links=[
            LinkInfo(
                device_a="CSW1",
                interface_a="GigabitEthernet1/1/2",
                device_b="DSW-A2",
                interface_b="GigabitEthernet1/1/1",
                media_type="eFiber",
            ),
            LinkInfo(
                device_a="Phone2",
                interface_a="PC",
                device_b="PC2",
                interface_b="FastEthernet0",
                media_type="eCopper",
            ),
            LinkInfo(
                device_a="ASW-A3",
                interface_a="FastEthernet0/1",
                device_b="Phone2",
                interface_b="Switch",
                media_type="eCopper",
            ),
        ],
        snapshot_id="block0",
    )


# --- peer interface must belong to the named subject -----------------------

def test_peer_interface_is_on_the_named_subject_device():
    """Q018 shape: 'which interface on DSW-A2 ... to CSW1 interface Gi1/1/2'."""
    q = (
        "Which interface on DSW-A2 is physically connected to CSW1 "
        "interface GigabitEthernet1/1/2?"
    )
    routed = intent.route(_model(), q)
    assert routed is not None
    result = ops.run_operation(_model(), routed.operation, routed.arguments)
    assert result.status is ops.OpStatus.OK
    assert result.value == "GigabitEthernet1/1/1", "must return the DSW-A2 side, not CSW1's"


def test_interface_that_exists_only_as_a_cable_endpoint_is_resolvable():
    """A port can be connected yet absent from the captured config."""
    found, _ = ops.find_interface(_model(), "DSW-A2", "Gi1/1/1")
    assert found is not None, "cable endpoints must count as interfaces"


def test_interface_token_belongs_to_the_device_named_before_it():
    """Positional attribution: 'to CSW1 interface X' means X is CSW1's."""
    q = "Which interface on DSW-A2 is physically connected to CSW1 interface GigabitEthernet1/1/2?"
    routed = intent.route(_model(), q)
    assert routed is not None
    assert routed.arguments["device"] == "CSW1"
    assert routed.arguments["interface"].lower().startswith("gigabitethernet1/1/2")


# --- neighbour of a specific interface, not the whole device --------------

def test_neighbor_question_with_interface_uses_that_interface():
    """Q010 shape: 'which device is connected to Phone2 on interface PC'."""
    q = "Which device is physically connected to Phone2 on interface PC?"
    routed = intent.route(_model(), q)
    assert routed is not None
    assert routed.operation == "get_physical_neighbor", (
        f"a specific interface was named; got {routed.operation}"
    )
    result = ops.run_operation(_model(), routed.operation, routed.arguments)
    assert result.status is ops.OpStatus.OK
    assert result.value == "PC2", f"expected only the PC-port neighbour, got {result.value!r}"


def test_neighbor_question_without_interface_lists_all_neighbours():
    q = "Which devices are physically connected to Phone2?"
    routed = intent.route(_model(), q)
    assert routed is not None
    assert routed.operation in {"list_physical_neighbors", "count_physical_neighbors"}


# --- abstention rather than an unrelated cable ----------------------------

def test_unknown_interface_does_not_answer_with_an_unrelated_cable():
    q = "Which interface on DSW-A2 is physically connected to CSW1 interface GigabitEthernet9/9/9?"
    routed = intent.route(_model(), q)
    if routed is None:
        return
    result = ops.run_operation(_model(), routed.operation, routed.arguments)
    assert result.status is not ops.OpStatus.OK
