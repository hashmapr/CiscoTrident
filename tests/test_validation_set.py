"""Offline checks for the blind validation set.

Nothing here starts Packet Tracer. The generation test skips when ``pkt_core``
is missing; every other test is pure Python over the specs and the offline
normaliser. The two healthy controls are the important ones: if a clean network
reports a defect, every blind measurement taken with this set is suspect.
"""

from __future__ import annotations

import json

import pytest

from trident.diagnostics import diagnose, report
from trident.labgen import available
from trident.labgen.ccna3 import build_network_model
from trident.labgen.faults import faulted_configs, intended_configs
from trident.labgen.spec import TargetKind
from trident.labgen.validation_set import (
    CASE_NAMES,
    CASES,
    CLEAN_CASES,
    FAULTED_CASES,
    blind_manifest,
    ground_truth,
)

_PKT_OK, _PKT_REASON = available()

_EXPECTED_CASE_NAMES = (
    "clean-baseline",
    "clean-segmented",
    "wrong-gateway",
    "missing-static-route",
    "wrong-next-hop",
    "broken-return-path",
    "admin-shutdown",
    "vlan-mismatch",
    "acl-deny",
    "multi-fault",
)

#: Keys that would expose the answer key. The blind manifest may name the case
#: ``multi-fault``; it may not carry any of these keys at any depth.
_FORBIDDEN_KEYS = {
    "actual",
    "expected",
    "fault",
    "fault_count",
    "fault_id",
    "faults",
    "hint_1",
    "hint_2",
    "kind",
    "points_total",
    "symptom",
}


def _walk_keys(value: object):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_keys(child)


# ---------------------------------------------------------------------------
# Shape and scoring convention
# ---------------------------------------------------------------------------


def test_the_registry_is_the_ten_prescribed_cases() -> None:
    assert CASE_NAMES == _EXPECTED_CASE_NAMES
    assert set(CASES) == set(_EXPECTED_CASE_NAMES)


@pytest.mark.parametrize("name", CASE_NAMES)
def test_every_case_is_a_valid_spec(name: str) -> None:
    spec, _manifest = CASES[name]
    assert spec.validate() == []


@pytest.mark.parametrize("name", CASE_NAMES)
def test_points_convention(name: str) -> None:
    """Faulted cases total 100; clean controls have zero faults and zero points.

    This is the one convention the whole set uses: there is no 99, no 101 and
    no clean case carrying a scored defect.
    """
    spec, manifest = CASES[name]
    if name in CLEAN_CASES:
        assert spec.faults == []
        assert spec.point_total() == 0
        assert manifest["fault_count"] == 0
    else:
        assert spec.faults, name
        assert spec.point_total() == 100
        assert manifest["fault_count"] == len(spec.faults)
        assert manifest["points_total"] == 100


@pytest.mark.parametrize("name", CASE_NAMES)
def test_every_device_is_cabled_and_no_port_is_used_twice(name: str) -> None:
    spec, _manifest = CASES[name]
    linked = {link.a for link in spec.links} | {link.b for link in spec.links}
    assert {device.name for device in spec.devices} - linked == set()
    ports = [(link.a, link.a_port) for link in spec.links] + [
        (link.b, link.b_port) for link in spec.links
    ]
    assert len(ports) == len(set(ports))


@pytest.mark.parametrize("name", CASE_NAMES)
def test_every_configured_interface_is_cabled(name: str) -> None:
    """A configured port with no cable would make a route silently unreachable."""
    spec, _manifest = CASES[name]
    cabled = {(link.a, link.a_port) for link in spec.links} | {
        (link.b, link.b_port) for link in spec.links
    }
    configured = {
        (device.name, interface.name)
        for device in spec.devices
        for interface in device.interfaces
    }
    assert configured <= cabled


# ---------------------------------------------------------------------------
# Fault application
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", CASE_NAMES)
def test_faulted_configs_applies_every_fault(name: str) -> None:
    """No FaultApplicationError, and every declared fault is accounted for."""
    spec, _manifest = CASES[name]
    _configs, applied = faulted_configs(spec)
    assert {change.fault_id for change in applied} == {fault.fault_id for fault in spec.faults}


@pytest.mark.parametrize("name", FAULTED_CASES)
def test_the_intended_build_differs_from_the_student_build(name: str) -> None:
    """Every config-level defect must actually change the config text."""
    spec, _manifest = CASES[name]
    student, _applied = faulted_configs(spec)
    reference = intended_configs(spec)
    if any(fault.target is not TargetKind.ENDHOST for fault in spec.faults):
        assert student != reference


# ---------------------------------------------------------------------------
# Generation (skipped without pkt_core)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _PKT_OK, reason=_PKT_REASON)
@pytest.mark.parametrize("name", CASE_NAMES)
def test_generate_round_trips_with_the_same_devices(name: str, tmp_path) -> None:
    """One file per case: a shared filename was a real generation bug."""
    from pkt_core.codec.container import decode
    from pkt_core.models import Lab

    from trident.labgen import generate

    spec, _manifest = CASES[name]
    destination = tmp_path / f"{name}.pkt"
    result = generate(spec, destination, apply_faults=True)

    assert result.encode_ok, result.notes
    assert destination.exists()
    decoded = Lab.from_bytes(decode(str(result.path)).xml)
    assert sorted(device.name for device in decoded.devices) == sorted(
        device.name for device in spec.devices
    )


# ---------------------------------------------------------------------------
# The false-positive controls
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", CLEAN_CASES)
def test_clean_controls_produce_zero_findings(name: str) -> None:
    spec, _manifest = CASES[name]
    model = build_network_model(spec, apply_faults=False)
    findings = report(diagnose(model))
    assert findings == [], f"{name}: a healthy network produced {findings}"


@pytest.mark.parametrize("name", CLEAN_CASES)
def test_clean_controls_confirm_no_defect(name: str) -> None:
    spec, _manifest = CASES[name]
    diagnosis = diagnose(build_network_model(spec, apply_faults=False))
    confirmed = [
        hypothesis
        for hypothesis in diagnosis.hypotheses
        if hypothesis.status.value == "CONFIRMED_DEFECT"
    ]
    assert confirmed == []


# ---------------------------------------------------------------------------
# Blind surface vs private ground truth
# ---------------------------------------------------------------------------


def test_blind_manifest_is_complete_but_carries_no_answer_key() -> None:
    blind = blind_manifest()
    assert set(blind) == set(CASE_NAMES)
    for name, view in blind.items():
        assert view["devices"], name
        assert view["links"], name
        assert view["requirements"], name
        spec, _manifest = CASES[name]
        assert len(view["devices"]) == len(spec.devices)
        assert len(view["links"]) == len(spec.links)

    forbidden = set(_walk_keys(blind)) & _FORBIDDEN_KEYS
    assert forbidden == set(), f"blind manifest exposes {sorted(forbidden)}"

    serialised = json.dumps(blind, sort_keys=True)
    intent_text = " ".join(
        [view["brief"] for view in blind.values()]
        + [
            requirement["check"]
            for view in blind.values()
            for requirement in view["requirements"]
        ]
    )
    for name, (spec, _manifest) in CASES.items():
        for fault in spec.faults:
            assert fault.fault_id not in serialised, (name, fault.fault_id)
            # The defect's actual value is never visible. Its intended value may
            # be visible only when the brief already documents it as intent.
            assert fault.actual not in serialised, (name, fault.fault_id)
            assert fault.expected not in serialised or fault.expected in intent_text, (
                name,
                fault.fault_id,
            )
            assert fault.symptom not in serialised, (name, fault.fault_id)


def test_ground_truth_is_complete_for_every_fault() -> None:
    truth = ground_truth()
    assert set(truth) == set(CASE_NAMES)

    for name, (spec, _manifest) in CASES.items():
        entry = truth[name]
        assert entry["fault_count"] == len(spec.faults), name
        assert len(entry["faults"]) == len(spec.faults), name
        if name in CLEAN_CASES:
            assert entry["fault_count"] == 0
            assert entry["faults"] == []
        by_id = {fault["fault_id"]: fault for fault in entry["faults"]}
        assert set(by_id) == {fault.fault_id for fault in spec.faults}
        for fault in spec.faults:
            record = by_id[fault.fault_id]
            assert record["device"] == fault.device
            assert record["device"], fault.fault_id
            assert record["kind"], fault.fault_id
            assert record["expected"], fault.fault_id
            assert record["actual"], fault.fault_id
            assert record["interface"] == (fault.interface or "")


def test_every_requirement_states_pass_or_fail() -> None:
    for name, (_spec, manifest) in CASES.items():
        requirements = manifest["requirements"]
        assert requirements, name
        for requirement in requirements:
            assert requirement["expect"] in {"pass", "fail"}, (name, requirement)
            assert requirement["check"], (name, requirement)
            assert requirement["id"], (name, requirement)
