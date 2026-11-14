"""Offline checks for the second evaluation corpus and its scorer.

Nothing here starts Packet Tracer. Generation is skipped when ``pkt_core`` is
missing; every other test is pure Python over the specs, the offline
normaliser and the equivalence scorer.

The controls matter most: if a clean network reports a defect, every accuracy
figure taken with this corpus is suspect. The scorer tests pin the four
attribution rules and the exact TP/FP/FN arithmetic so a score cannot drift.
"""

from __future__ import annotations

import pytest

from trident.diagnostics import diagnose, report
from trident.labgen import available
from trident.labgen.ccna3 import build_network_model
from trident.labgen.eval_corpus import (
    CASE_NAMES,
    CASES,
    CONTROL_CASES,
    DEFAULT_RULES,
    FAULTED_CASES,
    blind_view,
    equivalent_finding,
    ground_truth,
    score,
)
from trident.labgen.faults import FaultApplicationError, faulted_configs

_PKT_OK, _PKT_REASON = available()

_EXPECTED_CASE_NAMES = (
    "healthy-single-router",
    "healthy-no-default",
    "isp-edge-legit",
    "missing-forward",
    "missing-return",
    "wrong-next-hop",
    "admin-shutdown",
    "gateway-fault",
    "acl-intentional-isolation",
    "acl-accidental-deny",
    "multi-fault",
    "transit-three-routers",
)

_EXPECTED_CONTROLS = (
    "healthy-single-router",
    "healthy-no-default",
    "isp-edge-legit",
    "acl-intentional-isolation",
)

#: Keys that would expose the answer key. The blind view may describe topology
#: and requirements; it may not carry these keys at any depth.
_FORBIDDEN_KEYS = {"actual", "expected", "kind", "fault", "faults", "fault_id"}


def _walk_keys(value: object):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_keys(child)


# ---------------------------------------------------------------------------
# Shape and the 100-point convention
# ---------------------------------------------------------------------------


def test_the_registry_is_the_twelve_prescribed_cases() -> None:
    assert CASE_NAMES == _EXPECTED_CASE_NAMES
    assert set(CASES) == set(_EXPECTED_CASE_NAMES)


def test_the_controls_are_the_four_clean_cases() -> None:
    assert CONTROL_CASES == _EXPECTED_CONTROLS
    assert set(FAULTED_CASES) | set(CONTROL_CASES) == set(CASE_NAMES)
    assert set(FAULTED_CASES) & set(CONTROL_CASES) == set()


@pytest.mark.parametrize("name", CASE_NAMES)
def test_every_case_is_a_valid_spec(name: str) -> None:
    spec, _manifest = CASES[name]
    assert spec.validate() == []
    assert len(spec.devices) >= 3


@pytest.mark.parametrize("name", CASE_NAMES)
def test_controls_have_no_faults_and_faulted_cases_total_100(name: str) -> None:
    spec, manifest = CASES[name]
    truth = ground_truth(name)
    if name in CONTROL_CASES:
        assert spec.faults == []
        assert spec.point_total() == 0
        assert manifest["fault_count"] == 0
        assert truth["control"] is True
        assert truth["faults"] == []
    else:
        assert spec.faults, name
        assert spec.point_total() == 100
        assert manifest["fault_count"] == len(spec.faults)
        assert manifest["points_total"] == 100
        assert truth["control"] is False
        assert len(truth["faults"]) == len(spec.faults)


@pytest.mark.parametrize("name", FAULTED_CASES)
def test_each_fault_carries_its_private_evidence(name: str) -> None:
    truth = ground_truth(name)
    assert truth["faults"]
    for fault in truth["faults"]:
        assert fault["device"]
        assert fault["kind"]
        assert fault["expected"]
        assert fault["actual"]


# ---------------------------------------------------------------------------
# Fault application and generation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", CASE_NAMES)
def test_faulted_configs_applies_every_fault(name: str) -> None:
    """No FaultApplicationError, and every declared fault is accounted for."""
    spec, _manifest = CASES[name]
    try:
        _configs, applied = faulted_configs(spec)
    except FaultApplicationError as exc:  # pragma: no cover - failure path
        pytest.fail(f"{name}: {exc}")
    assert {change.fault_id for change in applied} == {fault.fault_id for fault in spec.faults}


@pytest.mark.skipif(not _PKT_OK, reason=_PKT_REASON)
@pytest.mark.parametrize("name", CASE_NAMES)
def test_generate_round_trips_with_a_unique_path(name: str, tmp_path) -> None:
    """One file per case: a shared filename caused a real generation bug."""
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


@pytest.mark.parametrize("name", CONTROL_CASES)
def test_clean_controls_confirm_no_defect(name: str) -> None:
    spec, _manifest = CASES[name]
    diagnosis = diagnose(build_network_model(spec, apply_faults=False))
    confirmed = [
        hypothesis
        for hypothesis in diagnosis.hypotheses
        if hypothesis.status.value == "CONFIRMED_DEFECT"
    ]
    assert confirmed == [], f"{name}: a healthy network produced {confirmed}"


@pytest.mark.parametrize("name", CONTROL_CASES)
def test_clean_controls_report_nothing(name: str) -> None:
    spec, _manifest = CASES[name]
    findings = report(diagnose(build_network_model(spec, apply_faults=False)))
    assert findings == [], f"{name}: a healthy network produced {findings}"


# ---------------------------------------------------------------------------
# Blind surface vs private ground truth
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", CASE_NAMES)
def test_blind_view_carries_topology_and_requirements_only(name: str) -> None:
    spec, _manifest = CASES[name]
    view = blind_view(name)

    assert view["devices"]
    assert view["links"]
    assert view["requirements"]
    assert len(view["devices"]) == len(spec.devices)
    assert len(view["links"]) == len(spec.links)

    leaked = sorted(set(_walk_keys(view)) & _FORBIDDEN_KEYS)
    assert leaked == [], f"{name}: blind view leaked {leaked}"


@pytest.mark.parametrize("name", CASE_NAMES)
def test_blind_view_does_not_name_a_private_fault(name: str) -> None:
    truth = ground_truth(name)
    blind = blind_view(name)
    # The case id and title are given to a blind run by definition; a token such
    # as "shutdown" can legitimately occur there. Everything else is payload.
    payload = {key: value for key, value in blind.items() if key not in {"case", "title"}}
    rendered = repr(payload)
    for fault in truth["faults"]:
        assert fault["actual"] not in rendered, name
        assert fault["expected"] not in rendered, name


# ---------------------------------------------------------------------------
# Equivalence rules (a) / (b) / (c) / (d)
# ---------------------------------------------------------------------------


def test_rule_a_duplicate_ip_any_holder() -> None:
    truth = {
        "kind": "DUPLICATE_IP",
        "device": "R1",
        "holders": ["R1", "R2"],
    }
    assert equivalent_finding({"kind": "DUPLICATE_IP", "device": "R1"}, truth, DEFAULT_RULES)
    assert equivalent_finding({"kind": "DUPLICATE_IP", "device": "R2"}, truth, DEFAULT_RULES)
    assert not equivalent_finding({"kind": "DUPLICATE_IP", "device": "R3"}, truth, DEFAULT_RULES)


def test_rule_b_two_ended_trunk_either_end() -> None:
    truth = {
        "kind": "TRUNK_MISMATCH",
        "device": "SW1",
        "interface": "GigabitEthernet0/1",
        "ends": [
            {"device": "SW1", "interface": "GigabitEthernet0/1"},
            {"device": "SW2", "interface": "GigabitEthernet0/2"},
        ],
    }
    local = {"kind": "TRUNK_MISMATCH", "device": "SW1", "interface": "GigabitEthernet0/1"}
    far = {"kind": "TRUNK_MISMATCH", "device": "SW2", "interface": "GigabitEthernet0/2"}
    wrong_port = {"kind": "TRUNK_MISMATCH", "device": "SW2", "interface": "GigabitEthernet0/3"}

    assert equivalent_finding(local, truth, DEFAULT_RULES)
    assert equivalent_finding(far, truth, DEFAULT_RULES)
    assert not equivalent_finding(wrong_port, truth, DEFAULT_RULES)


def test_rule_c_route_fault_router_only() -> None:
    truth = {
        "kind": "MISSING_FORWARD_ROUTE",
        "device": "R1",
        "interface": "GigabitEthernet0/1",
    }
    no_interface = {"kind": "MISSING_FORWARD_ROUTE", "device": "R1", "interface": None}
    wrong_iface = {"kind": "MISSING_FORWARD_ROUTE", "device": "R1", "interface": "GigabitEthernet9/9"}
    wrong_device = {"kind": "MISSING_FORWARD_ROUTE", "device": "R2", "interface": "GigabitEthernet0/1"}

    assert equivalent_finding(no_interface, truth, DEFAULT_RULES)
    assert equivalent_finding(wrong_iface, truth, DEFAULT_RULES)
    assert not equivalent_finding(wrong_device, truth, DEFAULT_RULES)


def test_rule_d_interface_fault_needs_device_and_interface() -> None:
    truth = {
        "kind": "ADMIN_SHUTDOWN",
        "device": "R1",
        "interface": "GigabitEthernet0/1",
    }
    same = {"kind": "ADMIN_SHUTDOWN", "device": "R1", "interface": "GigabitEthernet0/1"}
    wrong_port = {"kind": "ADMIN_SHUTDOWN", "device": "R1", "interface": "GigabitEthernet0/2"}
    wrong_device = {"kind": "ADMIN_SHUTDOWN", "device": "R2", "interface": "GigabitEthernet0/1"}

    assert equivalent_finding(same, truth, DEFAULT_RULES)
    assert not equivalent_finding(wrong_port, truth, DEFAULT_RULES)
    assert not equivalent_finding(wrong_device, truth, DEFAULT_RULES)


def test_a_different_kind_is_never_equivalent() -> None:
    truth = {"kind": "ADMIN_SHUTDOWN", "device": "R1", "interface": "GigabitEthernet0/1"}
    finding = {"kind": "WRONG_GATEWAY", "device": "R1", "interface": "GigabitEthernet0/1"}
    assert not equivalent_finding(finding, truth, DEFAULT_RULES)


# ---------------------------------------------------------------------------
# score(): exact arithmetic
# ---------------------------------------------------------------------------


def test_score_perfect() -> None:
    truth = {
        "c1": {
            "faults": [
                {"device": "R1", "interface": "", "kind": "MISSING_FORWARD_ROUTE"},
                {"device": "R1", "interface": "GigabitEthernet0/1", "kind": "ADMIN_SHUTDOWN"},
            ]
        }
    }
    predictions = {
        "c1": [
            {"device": "R1", "interface": None, "kind": "MISSING_FORWARD_ROUTE"},
            {"device": "R1", "interface": "GigabitEthernet0/1", "kind": "ADMIN_SHUTDOWN"},
        ]
    }

    result = score(predictions, truth)

    assert result["tp"] == 2
    assert result["fp"] == 0
    assert result["fn"] == 0
    assert result["recall"] == {"numerator": 2, "denominator": 2}
    assert result["precision"] == {"numerator": 2, "denominator": 2}
    assert result["correct_device"] == {"numerator": 2, "denominator": 2}
    assert result["correct_interface"] == {"numerator": 1, "denominator": 1}
    assert result["cases"]["c1"] == {"tp": 2, "fp": 0, "fn": 0}


def test_score_one_false_positive() -> None:
    truth = {
        "c1": {
            "faults": [
                {"device": "R1", "interface": "", "kind": "MISSING_FORWARD_ROUTE"},
            ]
        }
    }
    predictions = {
        "c1": [
            {"device": "R1", "interface": None, "kind": "MISSING_FORWARD_ROUTE"},
            {"device": "R9", "interface": None, "kind": "MISSING_FORWARD_ROUTE"},
        ]
    }

    result = score(predictions, truth)

    assert result["tp"] == 1
    assert result["fp"] == 1
    assert result["fn"] == 0
    assert result["recall"] == {"numerator": 1, "denominator": 1}
    assert result["precision"] == {"numerator": 1, "denominator": 2}
    assert result["correct_device"] == {"numerator": 1, "denominator": 1}
    assert result["cases"]["c1"] == {"tp": 1, "fp": 1, "fn": 0}


def test_score_one_false_negative() -> None:
    truth = {
        "c1": {
            "faults": [
                {"device": "R1", "interface": "", "kind": "MISSING_FORWARD_ROUTE"},
                {"device": "R1", "interface": "GigabitEthernet0/1", "kind": "ADMIN_SHUTDOWN"},
            ]
        }
    }
    predictions = {
        "c1": [
            {"device": "R1", "interface": None, "kind": "MISSING_FORWARD_ROUTE"},
        ]
    }

    result = score(predictions, truth)

    assert result["tp"] == 1
    assert result["fp"] == 0
    assert result["fn"] == 1
    assert result["recall"] == {"numerator": 1, "denominator": 2}
    assert result["precision"] == {"numerator": 1, "denominator": 1}
    assert result["correct_device"] == {"numerator": 1, "denominator": 1}
    assert result["correct_interface"] == {"numerator": 0, "denominator": 1}
    assert result["cases"]["c1"] == {"tp": 1, "fp": 0, "fn": 1}


def test_score_never_returns_a_bare_percentage() -> None:
    result = score({}, {})
    for key in _walk_keys(result):
        lowered = str(key).lower()
        assert "percent" not in lowered
        assert "pct" not in lowered
        assert "accuracy" not in lowered
