"""Tests for the fault-injection practice laboratory.

The contract under test:

* every required single-fault scenario builds and carries exactly one fault;
* ``inject`` changes only the intended device/interface;
* the answer key is not recoverable from ``scenario.model``;
* grading is exact at 1.0, safe at 0.0, and punishes both misses and inventions;
* a two-fault scenario needs both faults to score 1.0.
"""

from __future__ import annotations

import copy
import json

import pytest

from trident.faultlab import (
    Fault,
    FaultKind,
    InjectionError,
    baseline_lab,
    grade,
    inject,
    scenarios,
)
from trident.models import NetworkModel

REQUIRED_KINDS = (
    FaultKind.WRONG_VLAN,
    FaultKind.INVALID_MASK,
    FaultKind.WRONG_GATEWAY,
    FaultKind.MISSING_STATIC_ROUTE,
    FaultKind.SHUTDOWN_INTERFACE,
    FaultKind.ACL_BLOCK,
    FaultKind.TRUNK_MISMATCH,
    FaultKind.DUPLICATE_IP,
)

#: Every string that would betray the answer key if it reached the model.
_KIND_NAMES = tuple(kind.value for kind in FaultKind)


def _report(*kinds: FaultKind) -> list[dict]:
    return [
        {"kind": kind.value, "device": "X", "interface": None, "confidence": "high"}
        for kind in kinds
    ]


def _scenario_named(name: str):
    for scenario in scenarios():
        if scenario.name == name:
            return scenario
    raise AssertionError(f"scenario {name!r} is missing from the catalogue")


# ---------------------------------------------------------------------------
# Catalogue
# ---------------------------------------------------------------------------


def test_catalogue_has_at_least_eight_single_fault_scenarios() -> None:
    singles = [s for s in scenarios() if s.single_fault]
    assert len(singles) >= 8


def test_every_required_kind_has_a_scenario() -> None:
    present = {fault.kind for scenario in scenarios() for fault in scenario.faults}
    missing = [kind.value for kind in REQUIRED_KINDS if kind not in present]
    assert missing == [], f"no scenario injects {missing}"


def test_each_scenario_builds_and_has_at_least_one_fault() -> None:
    built = scenarios()
    assert built, "catalogue is empty"
    for scenario in built:
        assert isinstance(scenario.model, NetworkModel)
        assert len(scenario.faults) >= 1
        assert scenario.model.devices, f"{scenario.name} has no devices"
        assert scenario.model.interfaces, f"{scenario.name} has no interfaces"
        assert scenario.model.links, f"{scenario.name} has no links"


def test_single_fault_flag_matches_manifest_length() -> None:
    for scenario in scenarios():
        if scenario.single_fault:
            assert len(scenario.faults) == 1, scenario.name
        else:
            assert len(scenario.faults) >= 2, scenario.name


def test_at_least_one_two_fault_scenario() -> None:
    multi = [s for s in scenarios() if not s.single_fault]
    assert len(multi) >= 1
    assert any(len(s.faults) == 2 for s in multi)


def test_scenario_models_are_independent_objects() -> None:
    first = scenarios()
    second = scenarios()
    first[0].model.devices.clear()
    assert second[0].model.devices, "catalogue returned a shared model"


def test_scenario_name_is_unique() -> None:
    names = [scenario.name for scenario in scenarios()]
    assert len(names) == len(set(names))


# ---------------------------------------------------------------------------
# Injection precision
# ---------------------------------------------------------------------------


def _snapshot(model: NetworkModel) -> dict:
    return model.model_dump(mode="json")


def _differences(before: dict, after: dict) -> list[str]:
    """Return dotted paths whose values differ, treating dict/list recursively."""
    out: list[str] = []

    def walk(left, right, path: str) -> None:
        if isinstance(left, dict) and isinstance(right, dict):
            for key in sorted(set(left) | set(right)):
                walk(left.get(key), right.get(key), f"{path}.{key}")
            return
        if isinstance(left, list) and isinstance(right, list):
            if len(left) != len(right):
                out.append(path)
                return
            for index, (a, b) in enumerate(zip(left, right)):
                walk(a, b, f"{path}[{index}]")
            return
        if left != right:
            out.append(path)

    walk(before, after, "model")
    return out


#: Non-interface regions a given kind is allowed to touch, in addition to the
#: device/interface records named by the fault itself.
_EXTRA_REGIONS: dict[FaultKind, tuple[str, ...]] = {
    FaultKind.WRONG_VLAN: (),
    FaultKind.INVALID_MASK: (),
    FaultKind.WRONG_GATEWAY: ("model.settings",),
    FaultKind.MISSING_STATIC_ROUTE: ("model.routes",),
    FaultKind.SHUTDOWN_INTERFACE: (),
    FaultKind.ACL_BLOCK: ("model.acls",),
    FaultKind.TRUNK_MISMATCH: (),
    FaultKind.DUPLICATE_IP: (),
    FaultKind.ROUTING_LOOP: ("model.routes",),
    FaultKind.DHCP_MISCONFIGURATION: ("model.settings",),
    FaultKind.OVERLAPPING_SUBNET: ("model.interfaces.", "model.devices."),
}


@pytest.mark.parametrize("kind", REQUIRED_KINDS)
def test_inject_changes_only_the_intended_entity(kind: FaultKind) -> None:
    scenario = next(s for s in scenarios() if s.faults[0].kind is kind)
    # Rebuild through the public inject so the diff is against a pristine lab.
    faulty = inject(scenario.faults[0])
    pristine = baseline_lab()

    changed = _differences(_snapshot(pristine), _snapshot(faulty))
    assert changed, f"{kind.value} injection changed nothing"

    fault = scenario.faults[0]
    allowed_prefixes = list(_EXTRA_REGIONS[kind]) + [f"model.devices.{fault.device}"]
    if fault.interface is not None:
        allowed_prefixes.append(f"model.interfaces.{fault.device}:{fault.interface}")

    strays = [
        path
        for path in changed
        if not any(path.startswith(prefix) for prefix in allowed_prefixes)
    ]
    assert strays == [], f"{kind.value} touched unrelated paths: {strays}"

    # The named device must still exist and the named interface must be present.
    assert fault.device in faulty.devices
    if fault.interface is not None:
        assert f"{fault.device}:{fault.interface}" in faulty.interfaces


def test_shutdown_interface_flips_admin_and_oper_state() -> None:
    fault = _scenario_named("shutdown-interface").faults[0]
    faulty = inject(fault)
    pristine = baseline_lab()
    key = f"{fault.device}:{fault.interface}"
    assert pristine.interfaces[key].admin_state == "up"
    assert faulty.interfaces[key].admin_state == "administratively down"
    assert faulty.interfaces[key].operational_state == "down"


def test_wrong_vlan_moves_the_port_and_leaves_peers_alone() -> None:
    fault = _scenario_named("wrong-vlan").faults[0]
    faulty = inject(fault)
    pristine = baseline_lab()
    key = f"{fault.device}:{fault.interface}"
    assert faulty.interfaces[key].vlan_assignments == ["30"]
    assert pristine.interfaces[key].vlan_assignments == ["20"]
    # A different access port is untouched.
    assert faulty.interfaces["SW2:FastEthernet0/2"].vlan_assignments == ["20"]


def test_missing_static_route_removes_only_that_route() -> None:
    fault = _scenario_named("missing-static-route").faults[0]
    faulty = inject(fault)
    pristine = baseline_lab()
    assert len(faulty.routes) == len(pristine.routes) - 1
    assert not any(
        route.device == "R1" and route.destination == "10.10.20.0/24"
        for route in faulty.routes
    )
    assert any(route.device == "R1" and route.destination == "0.0.0.0" for route in faulty.routes)


def test_duplicate_ip_collides_with_an_existing_host() -> None:
    faulty = inject(_scenario_named("duplicate-ip").faults[0])
    addresses = [
        iface.ipv4_address
        for iface in faulty.interfaces.values()
        if iface.ipv4_address is not None
    ]
    assert addresses.count("10.10.20.10") == 2


def test_inject_rejects_unknown_entity() -> None:
    fault = Fault(
        fault_id="bogus",
        kind=FaultKind.WRONG_VLAN,
        device="R9",
        interface="GigabitEthernet9/9",
        description="not in the lab",
        expected_symptom="nothing",
    )
    with pytest.raises(InjectionError):
        inject(fault)


def test_inject_does_not_mutate_the_caller_scenario() -> None:
    scenario = _scenario_named("wrong-vlan")
    before = copy.deepcopy(scenario.model.model_dump(mode="json"))
    inject(scenario.faults[0])
    assert scenario.model.model_dump(mode="json") == before


# ---------------------------------------------------------------------------
# Leak prevention
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario", scenarios(), ids=lambda s: s.name)
def test_model_does_not_leak_the_manifest(scenario) -> None:
    payload = scenario.model.model_dump_json()
    lowered = payload.lower()

    for name in _KIND_NAMES:
        assert name.lower() not in lowered, (
            f"{scenario.name}: model JSON leaks fault kind {name!r}"
        )

    for fault in scenario.faults:
        assert fault.fault_id.lower() not in lowered
        assert fault.description.lower() not in lowered
        assert fault.expected_symptom.lower() not in lowered

    # No attribute on the model may carry the answer key at all.
    declared = set(NetworkModel.model_fields)
    for attribute in vars(scenario.model):
        assert attribute in declared, f"unexpected attribute {attribute!r} on NetworkModel"

    dumped_keys = set(json.loads(scenario.model.model_dump_json()))
    assert dumped_keys <= declared
    assert not {"faults", "fault_manifest", "answer_key"} & dumped_keys


def test_model_json_parses_and_has_no_fault_payload() -> None:
    for scenario in scenarios():
        data = json.loads(scenario.model.model_dump_json())
        assert isinstance(data, dict)
        assert "faults" not in data
        # A defect may change a value, but the payload must never gain a field
        # whose name advertises the defect.
        assert not any("fault" in key.lower() for key in data)


# ---------------------------------------------------------------------------
# Grading
# ---------------------------------------------------------------------------


def test_perfect_report_scores_one_and_exact_match() -> None:
    for scenario in scenarios():
        kinds = tuple(fault.kind for fault in scenario.faults)
        result = grade(scenario, _report(*kinds))
        assert result.score == 1.0, scenario.name
        assert result.exact_match is True, scenario.name
        assert result.missed_kinds == ()
        assert result.spurious_kinds == ()
        assert result.scenario == scenario.name


def test_empty_report_scores_zero_and_does_not_crash() -> None:
    for scenario in scenarios():
        result = grade(scenario, [])
        assert result.score == 0.0, scenario.name
        assert result.exact_match is False
        assert result.found_kinds == ()
        assert len(result.missed_kinds) == len(scenario.faults)


def test_none_report_scores_zero() -> None:
    scenario = _scenario_named("wrong-vlan")
    result = grade(scenario, None)  # type: ignore[arg-type]
    assert result.score == 0.0
    assert result.exact_match is False


def test_one_spurious_extra_lowers_the_score() -> None:
    scenario = _scenario_named("wrong-vlan")
    correct = scenario.faults[0].kind
    spurious = FaultKind.ROUTING_LOOP
    assert spurious is not correct

    result = grade(scenario, _report(correct, spurious))
    assert 0.0 < result.score < 1.0
    assert result.score == pytest.approx(0.5)
    assert result.exact_match is False
    assert result.spurious_kinds == (spurious,)
    assert result.found_kinds == (correct,)


def test_one_missed_lowers_the_score() -> None:
    scenario = _scenario_named("wrong-vlan")
    result = grade(scenario, [])
    assert result.score == 0.0
    assert result.missed_kinds == (scenario.faults[0].kind,)
    assert result.exact_match is False


def test_precision_and_recall_carry_equal_weight_in_the_denominator() -> None:
    """Each missed fault and each spurious fault adds exactly one unit to the
    denominator, so the score is always found / (found + missed + spurious)."""
    scenario = _scenario_named("dual-shutdown-gateway")
    first, second = (fault.kind for fault in scenario.faults)

    # 2 found, 0 missed, 1 spurious -> 2 / 3
    invented = grade(scenario, _report(first, second, FaultKind.DUPLICATE_IP))
    assert invented.score == pytest.approx(2 / 3)
    assert invented.spurious_kinds == (FaultKind.DUPLICATE_IP,)

    # 1 found, 1 missed, 0 spurious -> 1 / 2
    missed_only = grade(scenario, _report(first))
    assert missed_only.score == pytest.approx(1 / 2)
    assert missed_only.missed_kinds == (second,)

    # Swap one spurious for one missed at the same denominator size.
    one_each = grade(scenario, _report(first, FaultKind.ACL_BLOCK))
    assert one_each.score == pytest.approx(1 / 3)
    assert one_each.missed_kinds == (second,)
    assert one_each.spurious_kinds == (FaultKind.ACL_BLOCK,)

    for result in (invented, missed_only, one_each):
        assert result.exact_match is False


def test_wrong_only_report_scores_zero() -> None:
    scenario = _scenario_named("wrong-vlan")
    result = grade(scenario, _report(FaultKind.DUPLICATE_IP, FaultKind.TRUNK_MISMATCH))
    assert result.score == 0.0
    assert result.found_kinds == ()
    assert len(result.spurious_kinds) == 2
    assert result.exact_match is False


def test_unknown_kind_counts_as_spurious() -> None:
    scenario = _scenario_named("wrong-vlan")
    correct = scenario.faults[0].kind
    result = grade(
        scenario,
        _report(correct) + [{"kind": "NOT_A_REAL_KIND", "confidence": "low"}],
    )
    assert result.score == pytest.approx(0.5)
    assert result.spurious_kinds == ()
    assert result.exact_match is False


def test_duplicate_report_entries_are_deduplicated() -> None:
    scenario = _scenario_named("wrong-vlan")
    correct = scenario.faults[0].kind
    result = grade(scenario, _report(correct, correct, correct))
    assert result.score == 1.0
    assert result.exact_match is True


def test_two_fault_scenario_needs_both_for_a_perfect_score() -> None:
    scenario = _scenario_named("dual-shutdown-gateway")
    assert len(scenario.faults) == 2
    first, second = (fault.kind for fault in scenario.faults)

    partial = grade(scenario, _report(first))
    assert partial.score < 1.0
    assert partial.exact_match is False
    assert partial.missed_kinds == (second,)

    perfect = grade(scenario, _report(first, second))
    assert perfect.score == 1.0
    assert perfect.exact_match is True


def test_two_fault_scenario_three_reports_is_not_exact() -> None:
    scenario = _scenario_named("dual-shutdown-gateway")
    first, second = (fault.kind for fault in scenario.faults)
    extra = next(kind for kind in FaultKind if kind not in {first, second})

    result = grade(scenario, _report(first, second, extra))
    assert result.score == pytest.approx(2 / 3)
    assert result.exact_match is False
    assert result.spurious_kinds == (extra,)


def test_grade_is_pure() -> None:
    scenario = _scenario_named("wrong-vlan")
    before = copy.deepcopy(scenario.model.model_dump(mode="json"))
    grade(scenario, _report(FaultKind.WRONG_VLAN))
    grade(scenario, [])
    assert scenario.model.model_dump(mode="json") == before
