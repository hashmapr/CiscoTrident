"""API tests via FastAPI TestClient, plus performance/ordering guarantees."""

from __future__ import annotations

import pytest
from conftest import REAL_PKT, all_engines_available, requires_real_file
from fastapi.testclient import TestClient

from trident.server import app

client = TestClient(app)

QUESTIONS = """1. What is the IP address of R1 GigabitEthernet0/0?
A. 192.168.1.1
B. 192.168.2.1

2. What is the default gateway of PC-A?
A. 192.168.1.1
B. 10.0.0.1
"""


def test_index_serves_html():
    res = client.get("/")
    assert res.status_code == 200
    assert "TRIDENT" in res.text


def test_health_endpoint_shape():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["version"]
    assert isinstance(data["parsers"], list)
    assert len(data["parsers"]) == 3
    assert "ai_configured" in data
    assert data["consensus_policy"] in {"strict", "two_engine", "deterministic"}


def test_parsers_endpoint_lists_three():
    res = client.get("/api/parsers")
    assert res.status_code == 200
    data = res.json()
    engines = {p["engine"] for p in data["parsers"]}
    assert engines == {"engine_a", "engine_b", "engine_c"}
    for p in data["parsers"]:
        assert isinstance(p["available"], bool)
        assert isinstance(p["capabilities"], list)


def test_analyze_rejects_missing_file():
    res = client.post("/api/analyze", data={"questions": QUESTIONS})
    assert res.status_code == 422


def test_analyze_rejects_missing_questions():
    files = {"file": ("x.pkt", b"Z" * 400, "application/octet-stream")}
    res = client.post("/api/analyze", files=files, data={"questions": ""})
    assert res.status_code in (400, 422)


def test_analyze_rejects_bad_extension():
    files = {"file": ("virus.exe", b"Z" * 400, "application/octet-stream")}
    res = client.post("/api/analyze", files=files, data={"questions": QUESTIONS, "use_ai": "false"})
    assert res.status_code == 400
    assert "extension" in res.json()["detail"].lower()


def test_analyze_rejects_oversized_upload(monkeypatch):
    from dataclasses import replace

    from trident import server as server_module

    small = replace(server_module.settings, max_file_bytes=100)
    monkeypatch.setattr(server_module, "settings", small)
    files = {"file": ("big.pka", b"Z" * 500, "application/octet-stream")}
    res = client.post("/api/analyze", files=files, data={"questions": QUESTIONS, "use_ai": "false"})
    assert res.status_code == 400


@requires_real_file
def test_analyze_real_file_end_to_end():
    if not all_engines_available():
        pytest.skip("all three engines required for this end-to-end assertion")

    files = {"file": (REAL_PKT.name, REAL_PKT.read_bytes(), "application/octet-stream")}
    res = client.post(
        "/api/analyze", files=files, data={"questions": QUESTIONS, "use_ai": "false"}
    )
    assert res.status_code == 200
    data = res.json()

    # file identity preserved
    import hashlib

    assert data["file_sha256"] == hashlib.sha256(REAL_PKT.read_bytes()).hexdigest()
    assert data["file_bytes"] == REAL_PKT.stat().st_size

    # all engines ran for real
    states = {p["engine"]: p["state"] for p in data["parsers"]}
    assert states == {"engine_a": "OK", "engine_b": "OK", "engine_c": "OK"}

    # results ordered by question number
    numbers = [r["question_number"] for r in data["results"]]
    assert numbers == sorted(numbers)

    q1 = data["results"][0]
    assert q1["status"] == "VERIFIED"
    assert q1["answer"] == "192.168.1.1"
    assert q1["selected_options"] == ["A"]
    assert q1["consensus"]["agree"] == 3
    assert q1["consensus"]["required"] == 3
    sources = q1["evidence"][0]["sources"]
    assert set(sources) == {"engine_a", "engine_b", "engine_c"}


@requires_real_file
def test_analyze_is_repeatable_and_stable():
    if not all_engines_available():
        pytest.skip("all three engines required")
    files = {"file": (REAL_PKT.name, REAL_PKT.read_bytes(), "application/octet-stream")}
    first = client.post("/api/analyze", files=files, data={"questions": QUESTIONS, "use_ai": "false"}).json()
    files = {"file": (REAL_PKT.name, REAL_PKT.read_bytes(), "application/octet-stream")}
    second = client.post("/api/analyze", files=files, data={"questions": QUESTIONS, "use_ai": "false"}).json()

    assert first["file_sha256"] == second["file_sha256"]
    assert [r["status"] for r in first["results"]] == [r["status"] for r in second["results"]]
    assert [r["answer"] for r in first["results"]] == [r["answer"] for r in second["results"]]
    assert [r["selected_options"] for r in first["results"]] == [
        r["selected_options"] for r in second["results"]
    ]


@requires_real_file
def test_original_file_untouched_after_upload():
    import hashlib

    before = hashlib.sha256(REAL_PKT.read_bytes()).hexdigest()
    files = {"file": (REAL_PKT.name, REAL_PKT.read_bytes(), "application/octet-stream")}
    client.post("/api/analyze", files=files, data={"questions": QUESTIONS, "use_ai": "false"})
    after = hashlib.sha256(REAL_PKT.read_bytes()).hexdigest()
    assert before == after


@requires_real_file
def test_batch_of_65_questions_completes():
    """Performance/scale requirement: at least 65 questions in one batch."""
    if not all_engines_available():
        pytest.skip("all three engines required")

    lines = []
    for i in range(1, 66):
        lines.append(f"{i}. What is the IP address of R1 GigabitEthernet0/0?")
        lines.append("A. 192.168.1.1")
        lines.append("B. 10.0.0.1")
        lines.append("")
    batch = "\n".join(lines)

    files = {"file": (REAL_PKT.name, REAL_PKT.read_bytes(), "application/octet-stream")}
    res = client.post("/api/analyze", files=files, data={"questions": batch, "use_ai": "false"})
    assert res.status_code == 200
    data = res.json()
    assert len(data["results"]) == 65
    assert [r["question_number"] for r in data["results"]] == list(range(1, 66))
    # the file is parsed once, so every question agrees identically
    assert all(r["answer"] == "192.168.1.1" for r in data["results"])


@requires_real_file
def test_empty_activity_file_reports_no_devices():
    from conftest import REAL_PKA

    files = {"file": (REAL_PKA.name, REAL_PKA.read_bytes(), "application/octet-stream")}
    res = client.post("/api/analyze", files=files, data={"questions": QUESTIONS, "use_ai": "false"})
    assert res.status_code == 200
    data = res.json()
    assert data["network_summary"]["devices"] == 0
    # must NOT claim verified answers on an empty file
    assert all(r["status"] != "VERIFIED" for r in data["results"])


def test_response_never_contains_api_key(monkeypatch):
    from dataclasses import replace

    from trident import server as server_module

    secret = "sk-leak-canary-123456"
    monkeypatch.setattr(
        server_module, "settings", replace(server_module.settings, ai_api_key=secret, ai_model="m")
    )
    res = client.get("/api/health")
    assert secret not in res.text
    res2 = client.get("/api/parsers")
    assert secret not in res2.text
