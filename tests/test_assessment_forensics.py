"""Offline tests for the assessment forensics layer.

Nothing here starts Packet Tracer. Labs are generated with ``pkt_core`` into a
unique temporary path (a shared filename caused a real generation bug earlier),
then reconstructed through the normal pipeline.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from pathlib import Path

import pytest

from trident.assessment.forensics import (
    build_evidence,
    load_requirements,
    reconstruct,
    write_evidence,
)
from trident.config import settings
from trident.ingestion import ingest
from trident.labgen import available as labgen_available
from trident.labgen import generate
from trident.labgen.eval_corpus import case as eval_case
from trident.models import ParserReport, ParserState
from trident.normalization.devices import Normalizer
from trident.parsers.base import AdapterResult
from trident.pipeline import analyze, build_adapters

_PKT_OK, _PKT_REASON = labgen_available()
pytestmark = pytest.mark.skipif(not _PKT_OK, reason=_PKT_REASON)

_CASE = "healthy-single-router"


@pytest.fixture(scope="module")
def lab(tmp_path_factory) -> tuple:
    spec, _manifest = eval_case(_CASE)
    directory = tmp_path_factory.mktemp("forensics")
    destination = directory / f"{_CASE}-{uuid.uuid4().hex}.pkt"
    result = generate(spec, destination, apply_faults=True)
    assert result.encode_ok, result.notes
    return spec, destination


@pytest.fixture(scope="module")
def evidence(lab):
    _spec, destination = lab
    return reconstruct(destination)


def _engine_c_probe() -> tuple[bool, str]:
    for adapter in build_adapters(settings):
        if adapter.engine_id == "engine_c":
            return adapter.probe()
    raise AssertionError("engine_c adapter is missing")


def test_reconstruct_matches_generated_spec(lab, evidence) -> None:
    spec, destination = lab
    assert len(evidence.devices) == len(spec.devices)
    assert len(evidence.links) == len(spec.links)
    assert {device.name for device in evidence.devices} == {
        device.name for device in spec.devices
    }
    assert evidence.source_sha256 == hashlib.sha256(destination.read_bytes()).hexdigest()
    assert evidence.model.file_sha256 == evidence.source_sha256


def test_source_file_is_byte_identical_before_and_after(lab) -> None:
    _spec, destination = lab
    before_bytes = destination.read_bytes()
    before_hash = hashlib.sha256(before_bytes).hexdigest()

    reconstruct(destination)

    after_bytes = destination.read_bytes()
    assert after_bytes == before_bytes
    assert hashlib.sha256(after_bytes).hexdigest() == before_hash


def test_engine_c_is_reported_unavailable_with_a_reason(evidence) -> None:
    available, message = _engine_c_probe()
    if available:
        pytest.skip(f"engine_c is available here ({message}); nothing to assert")

    state = evidence.engines.get("engine_c")
    assert state is not None, "engine_c must appear even when it cannot run"
    assert state["state"] == "UNAVAILABLE"
    assert state["message"], "an unavailable engine must state why"
    assert state["device_count"] == 0
    assert state["observation_count"] == 0
    assert any(
        item.source == "engine_c" and item.status == "UNAVAILABLE"
        for item in evidence.unsupported
    ), "capabilities lost to engine_c must be listed, not dropped"


def test_discrepancies_empty_when_engines_agree(evidence) -> None:
    assert evidence.engines["engine_a"]["state"] == "OK"
    assert evidence.engines["engine_b"]["state"] == "OK"
    assert evidence.discrepancies == []


def test_discrepancies_populated_when_a_fake_adapter_disagrees(lab) -> None:
    _spec, destination = lab
    outcome = asyncio.run(
        analyze(
            ingest(destination.name, destination.read_bytes(), settings),
            "1. Report the network.",
            settings,
            use_ai=False,
        )
    )
    engine_a = next(
        result for result in outcome.adapter_results if result.engine_id == "engine_a"
    )

    fake = AdapterResult(
        engine_id="engine_x",
        report=ParserReport(
            engine="engine_x", state=ParserState.OK, message="synthetic disagreement"
        ),
        devices=["R1"],
        configs={
            "R1": [
                "hostname R1",
                "interface GigabitEthernet0/0",
                " ip address 10.99.99.99 255.255.255.0",
                " no shutdown",
            ]
        },
        extraction_family="synthetic",
    )

    model = Normalizer(
        [engine_a, fake], snapshot_id=outcome.model.snapshot_id or "root"
    ).build()
    rebuilt = build_evidence(model, [engine_a, fake], source_sha256="0" * 64)

    assert rebuilt.discrepancies, "a disagreeing engine must produce a discrepancy"
    conflict = next(
        entry
        for entry in rebuilt.discrepancies
        if entry.entity_id == "R1:GigabitEthernet0/0" and entry.field == "ipv4_address"
    )
    assert {conflict.engine_a, conflict.engine_b} == {"engine_a", "engine_x"}
    assert {conflict.value_a, conflict.value_b} == {"192.168.77.1", "10.99.99.99"}


def test_as_dict_is_json_serialisable_and_write_evidence_round_trips(
    evidence, tmp_path
) -> None:
    payload = evidence.as_dict()
    encoded = json.dumps(payload)
    decoded = json.loads(encoded)

    assert decoded["source_sha256"] == evidence.source_sha256
    assert len(decoded["devices"]) == len(evidence.devices)
    assert decoded["engines"]["engine_a"]["state"] == "OK"
    assert decoded["model"]["file_sha256"] == evidence.source_sha256

    written = write_evidence(evidence, tmp_path / "evidence")
    assert written.name == "network_evidence.json"
    assert written.exists()
    on_disk = json.loads(Path(written).read_text(encoding="utf-8"))
    assert len(on_disk["devices"]) == len(evidence.devices)


def test_unsupported_items_are_reported_not_dropped(evidence) -> None:
    assert evidence.unsupported
    by_capability = {item.capability: item for item in evidence.unsupported}
    assert by_capability["end_host_cli"].status == "UNSUPPORTED"
    assert by_capability["behavioural_ping"].status == "UNSUPPORTED"
    assert "CLI" in by_capability["end_host_cli"].reason
    assert all(item.reason for item in evidence.unsupported)


def test_load_requirements_parses_a_realistic_instruction_blob() -> None:
    blob = """CyberPatriot Autonomous Assessment — Network Readiness
INSTRUCTIONS
You have 45 minutes to complete this assessment.
Read each requirement carefully.

Requirements:
1. Configure OSPF area 0 on R1 and R2 so that all networks are advertised.
2. Assign VLAN 20 to FastEthernet0/2 on SW1.
3) Verify that PC-A can ping PC-B across the transit link.
- Restrict Telnet access on R1 using ACL 110.
* Enable port security on all access ports of SW2.
• Save the configuration on every device before you finish.

Click Submit when you are finished.
"""

    requirements = load_requirements(blob)

    assert len(requirements) == 6
    assert requirements[0] == (
        "Configure OSPF area 0 on R1 and R2 so that all networks are advertised."
    )
    assert requirements[-1] == (
        "Save the configuration on every device before you finish."
    )
    joined = "\n".join(requirements)
    assert "INSTRUCTIONS" not in joined
    assert "Click Submit" not in joined
