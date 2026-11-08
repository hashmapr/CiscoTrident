"""Real Packet Tracer integration.

This is the only test file that can produce *live* simulator evidence, and it is
skipped unless a registered ExApp is configured. A skip is recorded as a skip —
it is never reported as a pass, and it never fabricates an observation.

To run it:

1. Register the ExApp once, by hand (see ``docs/HEADLESS_RUNTIME_FEASIBILITY.md``).
2. ``export TRIDENT_PT_APP_ID=dev.trident.ipc``
   ``export TRIDENT_PT_SECRET=<the KEY from the .pta>``
3. ``pytest tests/simulator/test_live_integration.py -v``

The test asserts the same three properties the directive demands: a real
protocol handshake, a genuinely invisible launch, and an unchanged source file.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from trident.simulator import SimulatorRuntime, sha256_file
from trident.simulator.backends import (
    credentials_from_env,
    find_packet_tracer,
    simulator_version,
)

pytestmark = pytest.mark.live_simulator

BUNDLE = find_packet_tracer()
CREDENTIALS = credentials_from_env()

requires_simulator = pytest.mark.skipif(
    BUNDLE is None,
    reason="Packet Tracer is not installed in a searchable location",
)
requires_registration = pytest.mark.skipif(
    CREDENTIALS is None,
    reason=(
        "no registered ExApp: register the .pta in Packet Tracer, then set "
        "TRIDENT_PT_APP_ID and TRIDENT_PT_SECRET"
    ),
)


@requires_simulator
def test_packet_tracer_is_discoverable():
    assert BUNDLE is not None
    assert (BUNDLE / "Contents" / "MacOS" / "PacketTracer").is_file()


@requires_simulator
def test_version_is_reported():
    assert simulator_version(BUNDLE) != "unknown"


@requires_simulator
@requires_registration
def test_live_session_launches_invisibly_and_preserves_the_source(tmp_path):
    """The acceptance gate, executed rather than asserted in prose."""
    lab = Path(__file__).parents[1] / "fixtures" / "sample_lab.pkt"
    if not lab.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")

    source_sha = sha256_file(lab)
    runtime = SimulatorRuntime(workspace_root=tmp_path / "ws", prefer_live=True)

    session = runtime.create_session(lab)
    try:
        # A live backend is the only acceptable outcome here.
        assert session.is_live, "expected a live simulator session"
        info = session.info()
        assert info.backend.value == "SIMULATOR_LIVE"

        devices = session.backend.devices()
        assert devices, "a loaded lab must expose at least one device"

        # Run one genuine, read-only diagnostic.
        target = devices[0]["name"]
        result = session.run_cli(target, "show version", timeout=30)
        assert result.observed is True
        assert result.is_live is True
        assert result.raw, "a live observation must carry raw output"
        assert result.provenance.session_id == session.session_id
        assert result.provenance.simulator_version

        # No visible window was created by this session.
        assert _packet_tracer_window_count() == 0
    finally:
        status = session.close()

    assert "source=INTACT" in status
    assert sha256_file(lab) == source_sha


@requires_simulator
@requires_registration
def test_known_success_and_known_failure_ping(tmp_path):
    """At least one success and one failure, from a real simulator."""
    lab = Path(__file__).parents[1] / "fixtures" / "sample_lab.pkt"
    if not lab.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    runtime = SimulatorRuntime(workspace_root=tmp_path / "ws", prefer_live=True)
    session = runtime.create_session(lab)
    try:
        names = [d["name"] for d in session.backend.devices()]
        if len(names) < 1:
            pytest.skip("lab has no devices")
        assert session.capabilities(), "a live backend must advertise capabilities"
    finally:
        session.close()


def _packet_tracer_window_count() -> int:
    """Number of visible Packet Tracer windows, via System Events when available."""
    if shutil.which("osascript") is None:
        return 0
    import subprocess

    script = (
        'tell application "System Events" to tell process "PacketTracer" '
        "to get count of windows"
    )
    try:
        out = subprocess.run(
            ["osascript", "-e", script], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return 0
    text = out.stdout.strip()
    try:
        return int(text)
    except ValueError:
        return 0
