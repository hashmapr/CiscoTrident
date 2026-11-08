"""Phase 3 API tests.

The endpoints must never overstate what they know: simulator status reports the
real reason, investigation payloads carry their evidence tier, and the payload
builders return the same structures the endpoints serve.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from trident.faultlab import baseline_lab, scenarios
from trident.investigation import Mode
from trident.models import AnswerStatus
from trident.phase3_api import audit_payload, diagnose_payload, investigate_payload
from trident.server import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------


def test_simulator_status_is_available_and_explained():
    response = client.get("/api/phase3/simulator/status")
    assert response.status_code == 200
    data = response.json()
    for key in ("available", "reason", "mode", "note"):
        assert key in data
    assert isinstance(data["available"], bool)
    assert data["reason"]


def test_status_does_not_claim_live_without_registration():
    """If it says unavailable, the reason must name a real cause."""
    data = client.get("/api/phase3/simulator/status").json()
    if not data["available"]:
        assert data["mode"] == "static-only"
        assert (
            "registered ExApp" in data["reason"]
            or "not installed" in data["reason"]
        )
        assert "Static analysis works normally" in data["note"]


def test_modes_are_listed_with_a_default():
    data = client.get("/api/phase3/modes").json()
    ids = [mode["id"] for mode in data["modes"]]
    assert ids == ["SMART", "DOUBLE_CHECK"]
    defaults = [mode for mode in data["modes"] if mode["default"]]
    assert len(defaults) == 1
    assert defaults[0]["id"] == "SMART"


def test_health_still_works_after_mounting_phase3():
    response = client.get("/api/health")
    assert response.status_code == 200


def test_phase3_routes_do_not_shadow_the_ui():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_ui_shows_simulator_status_section():
    html = client.get("/").text
    assert "sim-status" in html
    assert "Operational simulation" in html


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------


def test_diagnose_payload_is_static_only_and_honest():
    model = next(s for s in scenarios() if s.name == "wrong-vlan").model
    payload = diagnose_payload(model)
    assert any(finding["kind"] == "WRONG_VLAN" for finding in payload["findings"])
    # No evidence tier is claimed for a pure static pass.
    assert "evidence_tier" not in payload or payload.get("evidence_tier") is None


def test_investigate_payload_reports_runtime_unavailable():
    payload = investigate_payload(
        baseline_lab(),
        [("Why can't PC1 reach SRV1?", AnswerStatus.INCOMPLETE, ["reachability"])],
        mode=Mode.SMART,
        runtime_available=False,
        runtime_reason="Packet Tracer is not registered",
    )
    outcome = payload["outcomes"][0]
    assert outcome["stop_reason"] == "RUNTIME_UNAVAILABLE"
    assert outcome["answer"] is None
    assert "registered" in outcome["reason"]


def test_investigate_payload_never_marks_verified_as_escalated():
    payload = investigate_payload(
        baseline_lab(),
        [("What is R1's address?", AnswerStatus.VERIFIED, [])],
        runtime_available=True,
    )
    outcome = payload["outcomes"][0]
    assert outcome["stop_reason"] == "ALREADY_VERIFIED"
    assert outcome["experiments"] == []


def test_audit_payload_reports_coverage_not_a_percentage():
    model = next(s for s in scenarios() if s.name == "shutdown-interface").model
    payload = audit_payload(model)
    coverage = payload["coverage"]
    for key in (
        "requirements",
        "statically_checked",
        "operationally_checked",
        "simulator_tested",
        "passed",
        "failed",
        "unresolved",
        "unsupported",
        "contradicted",
        "skipped",
    ):
        assert key in coverage
    assert "percent_verified" not in coverage
    assert payload["evidence_tier"] == "NO_OPERATIONAL_EVIDENCE"
    assert payload["runtime_available"] is False


def test_audit_payload_lists_checks_with_evidence_source():
    model = next(s for s in scenarios() if s.name == "acl-block").model
    payload = audit_payload(model)
    assert payload["checks"]
    for check in payload["checks"]:
        assert check["evidence_source"] in {"MODEL", "SCRIPTED", "SIMULATOR_LIVE", "NONE"}
        assert check["verdict"] in {
            "PASSED",
            "FAILED",
            "UNRESOLVED",
            "UNSUPPORTED",
            "CONTRADICTED",
            "SKIPPED",
        }


def test_audit_payload_is_json_serialisable():
    import json

    model = next(s for s in scenarios() if s.name == "routing-loop").model
    json.dumps(audit_payload(model))


def test_investigate_payload_is_json_serialisable():
    import json

    payload = investigate_payload(
        baseline_lab(),
        [("q", AnswerStatus.INCOMPLETE, ["reachability"])],
        runtime_available=False,
    )
    json.dumps(payload)
