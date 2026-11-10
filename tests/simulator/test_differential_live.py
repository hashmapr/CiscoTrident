"""Real differential verification against live Packet Tracer.

Predict with DeepCore, observe with Ghost, compare. This is the loop the whole
system exists to close.

Skipped entirely when no simulator is registered, and the skip is never reported
as a pass.
"""

from __future__ import annotations

import pathlib

import pytest

from trident.deepcore import DeepCore
from trident.deepcore.differential import Agreement, compare
from trident.simulator import SimulatorRuntime, sha256_file
from trident.simulator.backends import credentials_from_env, find_packet_tracer

pytestmark = pytest.mark.live_simulator

LAB = pathlib.Path(__file__).parents[1] / "fixtures" / "sample_lab.pkt"

requires_simulator = pytest.mark.skipif(
    find_packet_tracer() is None or credentials_from_env() is None,
    reason="no registered Packet Tracer",
)


@pytest.fixture(autouse=True)
def _consent(monkeypatch):
    monkeypatch.setenv("TRIDENT_ALLOW_LIVE_SIMULATOR", "1")


@pytest.fixture(scope="module")
def model():
    """The canonical model of the practice lab, parsed once."""
    import asyncio

    from trident.config import settings
    from trident.ingestion import ingest
    from trident.pipeline import analyze

    if not LAB.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    outcome = asyncio.run(
        analyze(
            ingest(LAB.name, LAB.read_bytes(), settings),
            "q",
            settings,
            use_ai=False,
        )
    )
    return outcome.model


@requires_simulator
def test_prediction_and_observation_agree_on_a_connected_pair(tmp_path, model):
    """R1 and R2 share a link. Prediction and simulator must both say delivered."""
    prediction = DeepCore(model).predict_path("R1", "R2")
    assert prediction.definite, prediction.as_dict()

    before = sha256_file(LAB)
    runtime = SimulatorRuntime(workspace_root=tmp_path / "ws", prefer_live=True)
    session = runtime.create_session(LAB)
    try:
        pdu = session.send_pdu("R1", "R2", timeout_seconds=30)
        assert pdu.observed is True
        discrepancy = compare(
            prediction,
            pdu.status.value,
            operation=pdu.operation,
            simulator_version=pdu.provenance.simulator_version,
            source_sha256=pdu.provenance.source_sha256,
            session_id=pdu.session_id if hasattr(pdu, "session_id") else pdu.provenance.session_id,
            observed_detail="; ".join(pdu.decisions[:2]),
        )
    finally:
        status = session.close()
    assert "source=INTACT" in status
    assert sha256_file(LAB) == before

    assert discrepancy.agreement is Agreement.AGREES, discrepancy.as_dict()


@requires_simulator
def test_differential_record_carries_full_provenance(tmp_path, model):
    prediction = DeepCore(model).predict_path("R1", "R2")
    runtime = SimulatorRuntime(workspace_root=tmp_path / "ws", prefer_live=True)
    session = runtime.create_session(LAB)
    try:
        pdu = session.send_pdu("R1", "R2", timeout_seconds=30)
        record = compare(
            prediction,
            pdu.status.value,
            operation=pdu.operation,
            simulator_version=pdu.provenance.simulator_version,
            source_sha256=pdu.provenance.source_sha256,
            session_id=pdu.provenance.session_id,
        ).as_dict()
    finally:
        session.close()

    assert record["simulator_version"], "the simulator version must be recorded"
    assert record["session_id"], "the session must be recorded"
    assert record["source_sha256"], "the source hash must be recorded"
    assert record["prediction_steps"], "the predicted path must be preserved"
    assert record["reproduction"]
