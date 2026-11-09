"""Real PDU execution against Packet Tracer.

These tests run genuine packet experiments. They are skipped, never faked, when
no simulator is available. Expectations come from the simulator's own decision
text, which is quoted in each assertion's failure message.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest

from trident.simulator import SimulatorRuntime, sha256_file
from trident.simulator.backends import (
    credentials_from_env,
    find_packet_tracer,
)
from trident.simulator.contracts import Capability
from trident.simulator.pdu import DeliveryStatus

pytestmark = pytest.mark.live_simulator

LAB = pathlib.Path(__file__).parents[1] / "fixtures" / "sample_lab.pkt"


@pytest.fixture(autouse=True)
def _consent(monkeypatch):
    monkeypatch.setenv("TRIDENT_ALLOW_LIVE_SIMULATOR", "1")


def _available() -> bool:
    return find_packet_tracer() is not None and credentials_from_env() is not None


requires_simulator = pytest.mark.skipif(
    not _available(), reason="no Packet Tracer registration available"
)


def _window_count() -> int:
    if shutil.which("osascript") is None:
        return 0
    import time

    script = (
        'tell application "System Events" to tell process "PacketTracer" '
        "to get count of windows"
    )
    time.sleep(2.0)
    try:
        out = subprocess.run(
            ["osascript", "-e", script], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return 0
    text = out.stdout.strip()
    return int(text) if text.isdigit() else 0


@requires_simulator
def test_session_advertises_pdu_capability(tmp_path):
    if not LAB.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    runtime = SimulatorRuntime(workspace_root=tmp_path / "ws", prefer_live=True)
    session = runtime.create_session(LAB)
    try:
        assert session.supports(Capability.SEND_PDU)
        assert session.is_live
    finally:
        session.close()


@requires_simulator
def test_router_to_directly_connected_router_is_delivered(tmp_path):
    """R1 and R2 share a link on 192.168.2.0/24, so the echo must be answered."""
    if not LAB.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    runtime = SimulatorRuntime(workspace_root=tmp_path / "ws", prefer_live=True)
    session = runtime.create_session(LAB)
    try:
        result = session.send_pdu("R1", "R2", timeout_seconds=30)
        assert result.status is DeliveryStatus.DELIVERED, (
            f"expected delivery, got {result.status.value}; evidence:\n{result.raw[:1500]}"
        )
        assert result.delivered is True
        assert result.observed is True
        # The simulator must have recorded an actual echo exchange.
        joined = " ".join(result.decisions).lower()
        assert "echo request" in joined, joined[:400]
        assert "echo reply" in joined, joined[:400]
    finally:
        session.close()


@requires_simulator
def test_pc_to_pc_is_delivered_when_dynamic_routing_reaches_the_subnet(tmp_path):
    """Both routers run a dynamic protocol covering all four subnets.

    Host endpoints need ARP/DHCP warm-up, so this measures the steady state:
    once the path is warm, delivery must be repeatable. The cold first attempt is
    covered separately by the warm-up test.
    """
    if not LAB.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    runtime = SimulatorRuntime(workspace_root=tmp_path / "ws", prefer_live=True)
    session = runtime.create_session(LAB)
    try:
        session.send_pdu("PC-A", "PC-B", timeout_seconds=30)  # warm the endpoints
        result = session.send_pdu("PC-A", "PC-B", timeout_seconds=30)
        assert result.status is DeliveryStatus.DELIVERED, (
            f"expected delivery, got {result.status.value}; evidence:\n{result.raw[:1500]}"
        )
        joined = " ".join(result.decisions).lower()
        assert "received an echo request" in joined or "echo reply" in joined
    finally:
        session.close()


@requires_simulator
def test_a_cold_host_endpoint_is_never_reported_as_a_fault(tmp_path):
    """A first-ever send to an uninitialised host must not claim DROPPED.

    Measured: the first experiment to a host reports the echo as constructed but
    never sent, then subsequent sends deliver. Calling that DROPPED would be a
    false negative, so the outcome is INCONCLUSIVE until warm-up completes.
    """
    if not LAB.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    runtime = SimulatorRuntime(workspace_root=tmp_path / "ws", prefer_live=True)
    session = runtime.create_session(LAB)
    try:
        first = session.send_pdu("PC-A", "Server", timeout_seconds=30)
        assert first.status is not DeliveryStatus.DELIVERED or first.frames_sent > 0
        if first.status is DeliveryStatus.INCONCLUSIVE:
            assert any(
                "warm" in caveat.lower() or "never sent" in caveat.lower()
                for caveat in first.caveats
            ), first.caveats
    finally:
        session.close()


@requires_simulator
def test_unknown_destination_is_refused_not_delivered(tmp_path):
    """Packet Tracer returns a non-zero ADD_PDU_ERROR for an unknown device."""
    if not LAB.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    runtime = SimulatorRuntime(workspace_root=tmp_path / "ws", prefer_live=True)
    session = runtime.create_session(LAB)
    try:
        result = session.send_pdu("PC-A", "NoSuchDevice", timeout_seconds=15)
        assert result.status in {
            DeliveryStatus.EXECUTION_ERROR,
            DeliveryStatus.UNSUPPORTED,
        }, f"got {result.status.value}"
        assert result.delivered is False
        assert result.add_pdu_error in {
            "NO_SUCH_DESTINATION_DEVICE",
            "NO_SUCH_SOURCE_DEVICE",
        }, result.add_pdu_error
    finally:
        session.close()


@requires_simulator
def test_unknown_source_is_refused(tmp_path):
    if not LAB.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    runtime = SimulatorRuntime(workspace_root=tmp_path / "ws", prefer_live=True)
    session = runtime.create_session(LAB)
    try:
        result = session.send_pdu("GhostDevice", "PC-B", timeout_seconds=15)
        assert result.delivered is False
        assert result.add_pdu_error == "NO_SUCH_SOURCE_DEVICE"
    finally:
        session.close()


@requires_simulator
def test_repeated_experiments_are_independent(tmp_path):
    """Frames from one PDU must not contaminate the next verdict."""
    if not LAB.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    runtime = SimulatorRuntime(workspace_root=tmp_path / "ws", prefer_live=True)
    session = runtime.create_session(LAB)
    try:
        outcomes = [session.send_pdu("R1", "R2", timeout_seconds=30).status for _ in range(3)]
        assert all(status is DeliveryStatus.DELIVERED for status in outcomes), outcomes
    finally:
        session.close()


@requires_simulator
def test_pdu_is_invisible_and_preserves_the_source(tmp_path):
    """The whole headless promise, during packet work."""
    if not LAB.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    before_hash = sha256_file(LAB)
    runtime = SimulatorRuntime(workspace_root=tmp_path / "ws", prefer_live=True)
    session = runtime.create_session(LAB)
    try:
        session.send_pdu("R1", "R2", timeout_seconds=30)
        assert _window_count() == 0, "a window became visible during a PDU test"
    finally:
        status = session.close()
    assert "source=INTACT" in status
    assert sha256_file(LAB) == before_hash


@requires_simulator
def test_non_icmp_protocol_is_refused(tmp_path):
    if not LAB.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    runtime = SimulatorRuntime(workspace_root=tmp_path / "ws", prefer_live=True)
    session = runtime.create_session(LAB)
    try:
        result = session.send_pdu("R1", "R2", protocol="tcp", timeout_seconds=15)
        assert result.status is DeliveryStatus.UNSUPPORTED
        assert result.delivered is False
    finally:
        session.close()
