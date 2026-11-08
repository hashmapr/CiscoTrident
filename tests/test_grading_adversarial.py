"""Adversarial tests for benchmark grading.

The grader decides whether a TRIDENT answer is correct. A lenient grader
inflates the score; a strict one is the only thing that makes the published
numbers trustworthy. These tests pin the strict behaviour.
"""

from __future__ import annotations

import pytest

from trident.models import DeviceInfo, NetworkModel
from trident.tools.benchmark_pack import grade


def _model() -> NetworkModel:
    return NetworkModel(
        devices={
            "Core Switch 1": DeviceInfo(id="csw1", name="Core Switch 1", hostname="CSW1"),
            "Core Switch 2": DeviceInfo(id="csw2", name="Core Switch 2", hostname="CSW2"),
        }
    )


@pytest.mark.parametrize(
    ("answer", "actual", "expected"),
    [
        ("32", "32", True),
        ("32", " 32 ", True),
        ("32", "32/", False),
        ("32", "/32", False),
        ("32", "GigabitEthernet0/0, Loopback0", False),
        ("19", "19 links", False),
        ("19", "19, 20", False),
        ("19", "119", False),
    ],
)
def test_integer_requires_whole_value(answer, actual, expected):
    q = {"answer": answer, "answer_type": "integer"}
    assert grade(q, actual) is expected


def test_prefix_length_is_not_satisfied_by_an_interface_list():
    q = {"answer": "32", "answer_type": "derived_prefix_length"}
    assert grade(q, "GigabitEthernet0/0, GigabitEthernet0/1, Loopback0") is False


@pytest.mark.parametrize(
    ("answer", "actual", "expected"),
    [
        ("44.102.3.1", "44.102.3.1", True),
        ("44.102.3.1", "44.102.3.10", False),
        ("44.102.3.1", "44.102.3.1 255.255.255.0", False),
        ("255.255.255.0", "255.255.255.0", True),
        ("255.255.255.0", "255.255.255.0 and 255.0.0.0", False),
        ("44.102.3.0", "44.102.3.1", False),
    ],
)
def test_address_requires_exact_value(answer, actual, expected):
    q = {"answer": answer, "answer_type": "ipv4_address"}
    assert grade(q, actual) is expected


@pytest.mark.parametrize(
    ("qtype", "answer", "actual", "expected"),
    [
        ("hostname", "OpenSeas", "OpenSeas", True),
        ("hostname", "OpenSeas", "OpenSeas Router", False),
        ("hostname", "OpenSeas", "not OpenSeas", False),
        ("device_model", "2911", "2911", True),
        ("device_model", "2911", "2911 Router", False),
        ("device_model", "2911", "12911", False),
    ],
)
def test_hostname_and_model_are_strict(qtype, answer, actual, expected):
    q = {"answer": answer, "answer_type": qtype}
    assert grade(q, actual) is expected


def test_device_set_rejects_extra_devices():
    q = {"answer": "Core Switch 1", "answer_type": "unordered_device_set"}
    assert grade(q, "Core Switch 1, Core Switch 2", None) is False


def test_device_set_rejects_missing_devices():
    q = {"answer": "Core Switch 1, Core Switch 2", "answer_type": "unordered_device_set"}
    assert grade(q, "Core Switch 1", None) is False


def test_device_set_accepts_hostname_aliases():
    q = {"answer": ["CSW1", "CSW2"], "answer_type": "unordered_device_set"}
    assert grade(q, "Core Switch 2, Core Switch 1", _model()) is True


def test_device_set_order_does_not_matter():
    q = {"answer": ["Core Switch 1", "Core Switch 2"], "answer_type": "unordered_device_set"}
    m = _model()
    assert grade(q, "Core Switch 2, Core Switch 1", m) is True
    assert grade(q, "Core Switch 1, Core Switch 2", m) is True


def test_device_set_duplicate_does_not_satisfy_two_expected():
    q = {"answer": ["Core Switch 1", "Core Switch 2"], "answer_type": "unordered_device_set"}
    assert grade(q, "Core Switch 1, Core Switch 1", _model()) is False


@pytest.mark.parametrize(
    ("answer", "actual", "expected"),
    [
        ("GigabitEthernet0/1", "Gi0/1", True),
        ("GigabitEthernet0/1", "GigabitEthernet0/1", True),
        ("GigabitEthernet0/1", "GigabitEthernet0/10", False),
        ("FastEthernet0", "Fa0", True),
        ("FastEthernet0", "FastEthernet0/1", False),
        ("GigabitEthernet1/1/2", "GigabitEthernet1/1/1", False),
    ],
)
def test_interface_alias_equivalence_is_exact_on_numbers(answer, actual, expected):
    q = {"answer": answer, "answer_type": "interface_name"}
    assert grade(q, actual) is expected


def test_single_device_answer_rejects_a_list():
    q = {"answer": "PC2", "answer_type": "device_name"}
    assert grade(q, "ASW-A3, PC2", _model()) is False


def test_single_device_answer_accepts_hostname_alias():
    q = {"answer": "CSW1", "answer_type": "device_name"}
    assert grade(q, "Core Switch 1", _model()) is True


@pytest.mark.parametrize("actual", ["", "   ", None])
def test_empty_answer_is_never_correct(actual):
    q = {"answer": "32", "answer_type": "integer"}
    assert grade(q, actual) is False


def test_key_placeholder_is_resolved_before_comparison():
    m = _model()
    m.placeholder_map = {"pr3-rt_Display_name": "Core Switch 1"}
    q = {"answer": "[[pr3-rt_Display_name]]", "answer_type": "device_name"}
    assert grade(q, "Core Switch 1", m) is True


def test_unresolvable_placeholder_never_matches():
    m = _model()
    m.placeholder_map = {}
    q = {"answer": "[[unknown_ref]]", "answer_type": "device_name"}
    assert grade(q, "Core Switch 1", m) is False
