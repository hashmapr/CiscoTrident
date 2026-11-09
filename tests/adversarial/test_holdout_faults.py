"""Holdout faults on realistic networks.

The fault lab proves the engine can name each defect class on a tidied network.
This suite proves something stricter: that it still does so when the network
carries the noise a real lab file has — default-state ports, OSPF, public edge
addressing, device names with spaces and parentheses — and that it stays silent
on that noise.

The `noise-only` and `healthy-with-noise` cases are the important ones. They fail
the moment a detector starts treating normal configuration as a defect.
"""

from __future__ import annotations

import pytest
from holdout_fixtures import all_cases

from trident.diagnostics import diagnose, report
from trident.diagnostics.types import HypothesisStatus

CASES = all_cases()


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_reported_kinds_match_the_holdout_manifest(case):
    reported = {entry["kind"] for entry in report(diagnose(case.model))}
    assert reported == case.expected_kinds, (
        f"{case.name}: expected {sorted(case.expected_kinds)}, got {sorted(reported)}"
        + (f" ({case.notes})" if case.notes else "")
    )


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_no_spurious_findings(case):
    """Every reported kind must be in the manifest; no extra guesses."""
    reported = {entry["kind"] for entry in report(diagnose(case.model))}
    assert reported - case.expected_kinds == set()


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_diagnosis_is_deterministic(case):
    first = report(diagnose(case.model))
    second = report(diagnose(case.model))
    assert first == second


def test_healthy_noisy_network_is_silent():
    """The single most important assertion in this file."""
    case = next(c for c in CASES if c.name == "healthy-with-noise")
    assert report(diagnose(case.model)) == []


def test_noise_only_network_is_silent():
    case = next(c for c in CASES if c.name == "noise-only")
    assert report(diagnose(case.model)) == []
    assert not [
        h
        for h in diagnose(case.model).hypotheses
        if h.status is HypothesisStatus.CONFIRMED_DEFECT
    ]


def test_multi_fault_network_reports_every_fault():
    case = next(c for c in CASES if c.name == "multi-fault-realistic")
    reported = {entry["kind"] for entry in report(diagnose(case.model))}
    assert {"WRONG_VLAN", "INVALID_MASK"} <= reported


def test_noise_is_present_so_absence_is_meaningful():
    """Guard against the fixtures silently losing their realistic noise."""
    case = next(c for c in CASES if c.name == "healthy-with-noise")
    model = case.model
    assert any(
        (interface.admin_state or "") == "administratively down"
        for interface in model.interfaces.values()
    ), "the healthy fixture must contain administratively-down noise"
    assert any("(" in device.name for device in model.devices.values()), (
        "device names with parentheses are part of the realistic noise"
    )
    assert any(
        (route.route_type or "") in {"dynamic", "static"} for route in model.routes
    )
