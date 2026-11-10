"""Deep Analyze: escalating genuinely testable gaps to a live simulator.

The properties that matter: escalation is lazy (nothing is tested that static
evidence already answers), bounded (a fixed budget), honest (an unavailable
simulator produces a stated gap), and non-destructive (the source file is never
written to).
"""

from __future__ import annotations

import pathlib

import pytest

from trident.config import settings
from trident.deepcore.analyze import analyze_network, merge_operational_checks
from trident.deepcore.deep import (
    OperationalCheck,
    RuntimeStatus,
    candidate_pairs,
    run_deep,
)
from trident.ingestion import ingest
from trident.models import DeviceInfo, InterfaceInfo, NetworkModel
from trident.pipeline import analyze

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "sample_lab.pkt"


def _model():
    import asyncio

    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    return asyncio.run(
        analyze(
            ingest(FIXTURE.name, FIXTURE.read_bytes(), settings),
            "analyze",
            settings,
            use_ai=False,
        )
    ).model


def _device(name, model=None):
    return DeviceInfo(id=name, name=name, hostname=name, device_type=None, model=model, configuration=[])


def _iface(device, name, address=None, prefix=None):
    return InterfaceInfo(
        device=device, name=name, canonical_name=name,
        ipv4_address=address, prefix_length=prefix, admin_state="up",
    )


class _FakeRuntime:
    """A stand-in runtime, used only for the offline tests."""

    def __init__(self, available: bool = True, reason: str = "test stub") -> None:
        self._available = available
        self._reason = reason

    def is_available(self) -> bool:
        return self._available

    def availability_reason(self) -> str:
        return self._reason


# ---------------------------------------------------------------------------
# Lazy escalation
# ---------------------------------------------------------------------------


def test_only_routed_devices_are_test_candidates():
    """Static facts do not need experiments; connectivity between routers does."""
    model = NetworkModel(
        devices={"R1": _device("R1", "2911"), "R2": _device("R2", "2911"),
                 "PC1": _device("PC1", "PC-PT")},
        interfaces={
            "R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 30),
            "R2:Gi0/0": _iface("R2", "GigabitEthernet0/0", "10.0.0.2", 30),
            "PC1:Fa0": _iface("PC1", "FastEthernet0"),
        },
    )
    pairs = candidate_pairs(model)
    assert pairs == [("R1", "R2")]
    # A host with no parsed address is never a candidate: Packet Tracer assigns
    # its address at runtime, so a test against it would be unreliable.
    assert all("PC1" not in pair for pair in pairs)


def test_svi_and_loopback_interfaces_do_not_make_a_device_a_candidate():
    model = NetworkModel(
        devices={"SW1": _device("SW1", "2960-24TT"), "R1": _device("R1", "2911")},
        interfaces={
            "SW1:Vlan1": _iface("SW1", "Vlan1", "10.0.0.1", 24),
            "R1:Lo0": _iface("R1", "Loopback0", "10.9.9.9", 24),
        },
    )
    assert candidate_pairs(model) == []


def test_candidate_pairs_respect_the_limit():
    devices = {f"R{i}": _device(f"R{i}", "2911") for i in range(6)}
    interfaces = {
        f"R{i}:Gi0/0": _iface(f"R{i}", "GigabitEthernet0/0", f"10.0.{i}.1", 24)
        for i in range(6)
    }
    model = NetworkModel(devices=devices, interfaces=interfaces)
    assert len(candidate_pairs(model, limit=3)) == 3


# ---------------------------------------------------------------------------
# Unavailable simulator is reported, not faked
# ---------------------------------------------------------------------------


def test_an_unavailable_runtime_produces_a_stated_gap():
    model = _model()
    result = run_deep(model, FIXTURE, runtime=_FakeRuntime(available=False, reason="not registered"))
    assert result.available is False
    assert "not registered" in result.reason
    assert result.checks
    assert all(check.status is RuntimeStatus.UNAVAILABLE for check in result.checks)
    assert all(not check.observed for check in result.checks)


def test_an_unavailable_runtime_is_never_counted_as_observed():
    model = _model()
    result = run_deep(model, FIXTURE, runtime=_FakeRuntime(available=False))
    payload = result.as_dict()
    assert payload["observed_count"] == 0


def test_no_candidates_is_reported_plainly():
    model = NetworkModel(devices={"R1": _device("R1", "2911")}, interfaces={})
    result = run_deep(model, FIXTURE, runtime=_FakeRuntime())
    assert result.available is True
    assert result.checks == []
    assert "no two routed devices" in result.reason


# ---------------------------------------------------------------------------
# Merging into the report
# ---------------------------------------------------------------------------


def test_an_observed_check_becomes_a_fact_on_both_devices():
    model = _model()
    report = analyze_network(model)
    deep = type(
        "D",
        (),
        {
            "available": True,
            "reason": "ok",
            "simulator_version": "9.0.1",
            "source_intact": True,
            "checks": [
                OperationalCheck(
                    name="connectivity", source="R1", destination="R2",
                    status=RuntimeStatus.OBSERVED, detail="DELIVERED: 60 bytes",
                    frames=60, simulator_version="9.0.1", session_id="s1",
                )
            ],
        },
    )()
    merge_operational_checks(report, deep)
    r1 = next(s for s in report.sections if s.name == "R1")
    r2 = next(s for s in report.sections if s.name == "R2")
    assert any(q.status.value == "OBSERVED" for q in r1.questions)
    assert any(q.status.value == "OBSERVED" for q in r2.questions)
    assert report.overview["runtime_available"] is True


def test_an_unobserved_check_becomes_a_stated_gap_not_a_fact():
    model = _model()
    report = analyze_network(model)
    deep = type(
        "D",
        (),
        {
            "available": False,
            "reason": "no simulator",
            "simulator_version": "",
            "source_intact": True,
            "checks": [
                OperationalCheck(
                    name="connectivity", source="R1", destination="R2",
                    status=RuntimeStatus.UNAVAILABLE, detail="no simulator",
                )
            ],
        },
    )()
    merge_operational_checks(report, deep)
    observed = [
        q for s in report.sections for q in s.questions if q.status.value == "OBSERVED"
    ]
    assert observed == [], "an unavailable runtime must never produce an observation"
    assert any("runtime R1->R2" in item for item in report.unsupported_checks)


def test_merge_records_the_runtime_status_in_the_overview():
    model = _model()
    report = analyze_network(model)
    deep = type(
        "D", (), {"available": False, "reason": "not installed", "simulator_version": "",
                  "source_intact": True, "checks": []},
    )()
    merge_operational_checks(report, deep)
    assert report.overview["runtime_available"] is False
    assert report.overview["runtime_reason"] == "not installed"


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


def test_deep_endpoint_reports_runtime_status():
    from fastapi.testclient import TestClient

    from trident.server import app

    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    client = TestClient(app)
    response = client.post(
        "/api/network/analyze",
        files={"file": ("lab.pkt", FIXTURE.read_bytes(), "application/octet-stream")},
        data={"mode": "deep"},
    )
    assert response.status_code == 200
    overview = response.json()["overview"]
    assert "runtime_available" in overview
    assert "runtime_reason" in overview
    assert overview["source_intact"] is True


def test_quick_mode_does_not_start_a_simulator():
    from fastapi.testclient import TestClient

    from trident.server import app

    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    payload = TestClient(app).post(
        "/api/network/analyze",
        files={"file": ("lab.pkt", FIXTURE.read_bytes(), "application/octet-stream")},
        data={"mode": "quick"},
    ).json()
    assert "runtime_available" not in payload["overview"]


def test_deep_analyze_does_not_modify_the_upload(tmp_path):
    from fastapi.testclient import TestClient

    from trident.server import app

    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    original = FIXTURE.read_bytes()
    copy = tmp_path / "lab.pkt"
    copy.write_bytes(original)
    TestClient(app).post(
        "/api/network/analyze",
        files={"file": ("lab.pkt", copy.read_bytes(), "application/octet-stream")},
        data={"mode": "deep"},
    )
    assert copy.read_bytes() == original
