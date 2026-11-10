"""Analyze Mode: the device-by-device report.

The report is the product surface users actually see, so the tests here are about
honesty as much as coverage: every device gets a section, no value is invented,
absence of findings is never presented as compliance, and each fact carries its
evidence status.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from trident.config import settings
from trident.deepcore.analyze import (
    Severity,
    Status,
    analyze_network,
    iter_sections,
)
from trident.ingestion import ingest
from trident.models import (
    DeviceInfo,
    InterfaceInfo,
    LinkInfo,
    NetworkModel,
    RouteInfo,
)
from trident.pipeline import analyze

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "sample_lab.pkt"


def _real_model() -> NetworkModel:
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    outcome = _run(FIXTURE.read_bytes(), FIXTURE.name)
    return outcome.model


def _run(data: bytes, name: str = "lab.pkt"):
    import asyncio

    return asyncio.run(analyze(ingest(name, data, settings), "analyze", settings, use_ai=False))


def _device(name, model=None, kind=None, config=None):
    return DeviceInfo(
        id=name, name=name, hostname=name, device_type=kind, model=model,
        configuration=config or [],
    )


def _iface(device, name, address=None, prefix=None, admin="up", vlans=None, mode=None):
    return InterfaceInfo(
        device=device, name=name, canonical_name=name, ipv4_address=address,
        prefix_length=prefix, admin_state=admin, vlan_assignments=vlans or [],
        access_mode=mode,
    )


# ---------------------------------------------------------------------------
# Real network
# ---------------------------------------------------------------------------


def test_every_device_gets_a_section():
    model = _real_model()
    report = analyze_network(model)
    names = {section.name for section in report.sections}
    assert names == set(model.devices)


def test_overview_counts_match_the_model():
    model = _real_model()
    report = analyze_network(model)
    assert report.overview["device_count"] == len(model.devices)
    assert report.overview["link_count"] == len(model.links)
    assert report.overview["interface_count"] == len(model.interfaces)


def test_routers_are_classified_from_their_model_string():
    """The parser records a model, not a device type; classification must use it."""
    model = NetworkModel(
        devices={"R1": _device("R1", model="2911"), "SW1": _device("SW1", model="2960-24TT")},
        interfaces={},
    )
    report = analyze_network(model)
    kinds = {section.name: section.display_kind for section in report.sections}
    assert kinds["R1"] == "Router"
    assert kinds["SW1"] == "Switch"


def test_routers_are_listed_before_switches_before_endpoints():
    model = NetworkModel(
        devices={
            "PC1": _device("PC1", model="PC-PT"),
            "SW1": _device("SW1", model="2960-24TT"),
            "R1": _device("R1", model="2911"),
        },
        interfaces={},
    )
    order = [section.name for section in analyze_network(model).sections]
    assert order == ["R1", "SW1", "PC1"]


def test_headings_read_like_a_heading():
    section = analyze_network(_real_model()).sections[0]
    assert " — " in section.heading
    assert section.heading.split(" — ")[0] in {
        "Router", "Switch", "Multilayer Switch", "PC", "Server", "Firewall",
        "Access Point", "Wireless Router", "Hub", "Cloud", "Device",
    }


# ---------------------------------------------------------------------------
# Facts are not invented
# ---------------------------------------------------------------------------


def test_a_device_without_a_model_says_unsupported_rather_than_guessing():
    model = NetworkModel(devices={"X1": _device("X1")}, interfaces={})
    section = analyze_network(model).sections[0]
    model_question = next(
        q for q in section.questions if "hardware model" in q.question.lower()
    )
    assert model_question.answer is None
    assert model_question.status is Status.UNSUPPORTED
    assert model_question.limitation


def test_interface_addresses_are_reported_verbatim():
    model = NetworkModel(
        devices={"R1": _device("R1", model="2911")},
        interfaces={"R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 24)},
    )
    section = analyze_network(model).sections[0]
    text = section.to_text()
    assert "10.0.0.1/24" in text


def test_connected_networks_are_derived_not_verified():
    model = NetworkModel(
        devices={"R1": _device("R1", model="2911")},
        interfaces={"R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 24)},
    )
    section = analyze_network(model).sections[0]
    question = next(q for q in section.questions if "directly connected" in q.question)
    assert question.status is Status.DERIVED
    assert "10.0.0.0/24" in question.answer


def test_administratively_disabled_interfaces_are_listed():
    model = NetworkModel(
        devices={"R1": _device("R1", model="2911")},
        interfaces={
            "R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 24),
            "R1:Gi0/1": _iface("R1", "GigabitEthernet0/1", "10.0.1.1", 24, admin="administratively down"),
        },
    )
    section = analyze_network(model).sections[0]
    assert any("administratively disabled" in q.question.lower() for q in section.questions)
    assert "GigabitEthernet0/1" in section.to_text()


def test_default_route_is_reported():
    model = NetworkModel(
        devices={"R1": _device("R1", model="2911")},
        interfaces={"R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 24)},
        routes=[
            RouteInfo(device="R1", destination="0.0.0.0/0", next_hop="10.0.0.254",
                      route_type="static", outgoing_interface="GigabitEthernet0/0")
        ],
    )
    section = analyze_network(model).sections[0]
    assert "10.0.0.254" in section.to_text()


def test_neighbours_come_from_the_link_table():
    model = NetworkModel(
        devices={"R1": _device("R1", model="2911"), "SW1": _device("SW1", model="2960-24TT")},
        interfaces={
            "R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 24),
            "SW1:Gi0/1": _iface("SW1", "GigabitEthernet0/1"),
        },
        links=[
            LinkInfo(device_a="R1", interface_a="GigabitEthernet0/0",
                     device_b="SW1", interface_b="GigabitEthernet0/1")
        ],
    )
    report = analyze_network(model)
    r1 = next(s for s in report.sections if s.name == "R1")
    assert any("SW1" in neighbour for neighbour in r1.neighbors)


# ---------------------------------------------------------------------------
# Findings and attribution
# ---------------------------------------------------------------------------


def test_a_duplicate_address_is_reported_with_severity_and_evidence():
    model = NetworkModel(
        devices={"R1": _device("R1", model="2911"), "R2": _device("R2", model="2911")},
        interfaces={
            "R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 24),
            "R2:Gi0/0": _iface("R2", "GigabitEthernet0/0", "10.0.0.1", 24),
        },
    )
    report = analyze_network(model)
    findings = [f for s in report.sections for f in s.findings]
    duplicate = [f for f in findings if "same IP address" in f.description]
    assert duplicate
    assert duplicate[0].severity is Severity.HIGH
    assert duplicate[0].evidence
    assert duplicate[0].why_it_matters


def test_a_shut_addressed_interface_is_reported_on_its_own_device():
    model = NetworkModel(
        devices={"R1": _device("R1", model="2911")},
        interfaces={
            "R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 24, admin="administratively down")
        },
    )
    report = analyze_network(model)
    r1 = next(s for s in report.sections if s.name == "R1")
    assert r1.findings
    assert all(f.device == "R1" for f in r1.findings)


def test_no_findings_is_not_reported_as_compliance():
    model = NetworkModel(
        devices={"R1": _device("R1", model="2911")},
        interfaces={"R1:Gi2/0": _iface("R1", "GigabitEthernet2/0", "10.0.0.1", 24)},
    )
    report = analyze_network(model)
    text = report.to_text()
    assert "not proof that the" in text.lower() or "not proof" in text.lower()
    for section in report.sections:
        assert "No problem detected by the checks that were run" in section.to_text()


def test_network_wide_findings_are_separate_from_device_findings():
    model = NetworkModel(
        devices={"R1": _device("R1", model="2911"), "R2": _device("R2", model="2911")},
        interfaces={
            "R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 24),
            "R2:Gi0/0": _iface("R2", "GigabitEthernet0/0", "10.0.0.1", 24),
        },
    )
    report = analyze_network(model)
    # A device-attributed problem must not also appear in the network list.
    device_findings = {(f.device, f.description) for s in report.sections for f in s.findings}
    for finding in report.network_findings:
        assert (finding.device, finding.description) not in device_findings


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_an_empty_network_produces_an_honest_empty_report():
    report = analyze_network(NetworkModel(devices={}, interfaces={}))
    assert report.sections == []
    assert report.overview["device_count"] == 0
    assert "not proof" in report.to_text().lower()


def test_an_unnamed_device_is_still_reported():
    model = NetworkModel(devices={"": _device("")}, interfaces={})
    report = analyze_network(model)
    assert len(report.sections) == 1


def test_duplicate_hostnames_do_not_collide_sections():
    model = NetworkModel(
        devices={
            "R1": _device("R1", model="2911"),
            "R2": _device("R2", model="2911"),
        },
        interfaces={},
    )
    model.devices["R1"].hostname = "core"
    model.devices["R2"].hostname = "core"
    report = analyze_network(model)
    assert len(report.sections) == 2


def test_unknown_device_family_still_gets_a_section():
    model = NetworkModel(devices={"X1": _device("X1", model="mystery-box")}, interfaces={})
    section = analyze_network(model).sections[0]
    assert "Device" in section.heading


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------


def test_sections_can_be_iterated_one_at_a_time():
    model = _real_model()
    produced = list(iter_sections(model))
    assert len(produced) == len(model.devices)
    assert all(hasattr(section, "to_text") for section in produced)


def test_streaming_yields_the_same_sections_as_the_full_report():
    model = _real_model()
    full = analyze_network(model)
    streamed = list(iter_sections(model))
    assert [s.name for s in streamed] == [s.name for s in full.sections]


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------


def test_json_export_round_trips():
    report = analyze_network(_real_model())
    payload = report.as_dict()
    json.dumps(payload)
    assert payload["sections"]
    assert payload["overview"]["device_count"] == len(payload["sections"])


def test_markdown_export_has_a_heading_per_device():
    model = _real_model()
    report = analyze_network(model)
    markdown = report.to_markdown()
    for section in report.sections:
        assert f"## {section.heading}" in markdown


def test_text_export_lists_unsupported_checks():
    report = analyze_network(_real_model())
    text = report.to_text()
    assert "What was not checked" in text
    assert "not proof" in text.lower()


def test_exports_preserve_status_markers():
    model = NetworkModel(
        devices={"R1": _device("R1", model="2911")},
        interfaces={"R1:Gi0/0": _iface("R1", "GigabitEthernet0/0", "10.0.0.1", 24)},
    )
    report = analyze_network(model)
    assert "VERIFIED" in report.to_text()
    assert "DERIVED" in report.to_markdown()


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


def _client():
    from fastapi.testclient import TestClient

    from trident.server import app

    return TestClient(app)


def test_analyze_endpoint_returns_a_report_without_questions():
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    response = _client().post(
        "/api/network/analyze",
        files={"file": ("lab.pkt", FIXTURE.read_bytes(), "application/octet-stream")},
        data={"mode": "quick", "export": "json"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["overview"]["device_count"] > 0
    assert payload["sections"]


@pytest.mark.parametrize("fmt", ["markdown", "text"])
def test_analyze_endpoint_exports(fmt):
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    response = _client().post(
        "/api/network/analyze",
        files={"file": ("lab.pkt", FIXTURE.read_bytes(), "application/octet-stream")},
        data={"export": fmt},
    )
    assert response.status_code == 200
    assert "TRIDENT" in response.text


def test_deep_mode_escalates_and_reports_the_runtime_outcome():
    """Deep Analyze now genuinely escalates; the report must say what happened.

    Previously this asserted a warning that experiments were not run. They now
    are, so the assertion is that the outcome is stated either way — never
    implied by silence.
    """
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    payload = _client().post(
        "/api/network/analyze",
        files={"file": ("lab.pkt", FIXTURE.read_bytes(), "application/octet-stream")},
        data={"mode": "deep"},
    ).json()
    overview = payload["overview"]
    assert "runtime_available" in overview
    assert "runtime_reason" in overview
    assert overview["source_intact"] is True
    if overview["runtime_available"]:
        assert overview["runtime_version"]
    else:
        assert overview["runtime_reason"]


def test_analyze_does_not_modify_the_upload(tmp_path):
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    original = FIXTURE.read_bytes()
    copy = tmp_path / "lab.pkt"
    copy.write_bytes(original)
    _client().post(
        "/api/network/analyze",
        files={"file": ("lab.pkt", copy.read_bytes(), "application/octet-stream")},
        data={"export": "json"},
    )
    assert copy.read_bytes() == original


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------


def test_stream_sections_emits_overview_then_devices_then_coverage():
    from trident.deepcore.analyze import stream_sections

    model = _real_model()
    events = list(stream_sections(model))
    kinds = [kind for kind, _ in events]
    assert kinds[0] == "overview"
    assert kinds[-2:] == ["findings", "coverage"]
    assert kinds.count("section") == len(model.devices)


def test_stream_endpoint_emits_a_section_per_device():
    if not FIXTURE.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    response = _client().post(
        "/api/network/analyze/stream",
        files={"file": ("lab.pkt", FIXTURE.read_bytes(), "application/octet-stream")},
        data={"mode": "quick"},
    )
    assert response.status_code == 200
    assert "text/event-stream" in response.headers["content-type"]
    events = [
        json.loads(line[6:])
        for line in response.text.splitlines()
        if line.startswith("data: ")
    ]
    kinds = [event["kind"] for event in events]
    assert kinds[0] == "STAGE"
    assert kinds[1] == "OVERVIEW"
    assert kinds.count("SECTION") == 7
    assert kinds[-1] == "COMPLETE"


def test_streamed_sections_match_the_report_order():
    from trident.deepcore.analyze import stream_sections

    model = _real_model()
    streamed = [p["heading"] for k, p in stream_sections(model) if k == "section"]
    full = [s.heading for s in analyze_network(model).sections]
    assert streamed == full


def test_frontend_uses_the_streaming_analyze_endpoint():
    """The capability must be reachable from the real UI, not only from the API."""
    web = pathlib.Path(__file__).parents[1] / "trident" / "web" / "app.js"
    source = web.read_text()
    assert "/api/network/analyze/stream" in source
    assert "streamNetworkReport" in source
    assert "renderDeviceSection" in source
