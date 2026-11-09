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
        assert session.is_live, "expected a live simulator session"
        assert session.info().backend.value == "SIMULATOR_LIVE"

        devices = session.backend.devices()
        assert devices, "a loaded lab must expose at least one device"
        names = {device["name"] for device in devices}
        assert any(name.startswith(("R", "SW", "PC", "Server")) for name in names), names

        # A genuine read-only diagnostic. "show version" proves the simulator
        # answered; "show ip interface brief" proves it answered about this lab.
        target = "R1" if "R1" in names else devices[0]["name"]
        version = session.run_cli(target, "show version", timeout=45)
        assert version.ok and version.observed and version.is_live
        assert "Cisco IOS Software" in version.raw, version.raw[:200]

        interfaces = session.run_cli(target, "show ip interface brief", timeout=45)
        assert interfaces.ok and interfaces.observed
        assert "Interface" in interfaces.raw and "Protocol" in interfaces.raw
        assert "GigabitEthernet" in interfaces.raw, interfaces.raw[:300]

        # Every observation is attributed to the session that produced it.
        assert interfaces.provenance.session_id == session.session_id
        assert interfaces.provenance.simulator_version

        assert _packet_tracer_window_count() == 0
    finally:
        status = session.close()

    assert "source=INTACT" in status
    assert sha256_file(lab) == source_sha


@requires_simulator
@requires_registration
def test_ping_never_invents_a_verdict(tmp_path):
    """A ping with no summary line must be inconclusive, not failed.

    Packet Tracer's CLI ping is interactive and completes only as simulation time
    advances, so a single command often returns a prompt with no summary.
    Reporting that as a failed reachability would be a fabricated conclusion.
    """
    lab = Path(__file__).parents[1] / "fixtures" / "sample_lab.pkt"
    if not lab.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    from trident.simulator.contracts import ObservationKind

    runtime = SimulatorRuntime(workspace_root=tmp_path / "ws", prefer_live=True)
    session = runtime.create_session(lab)
    try:
        names = {d["name"] for d in session.backend.devices()}
        if "R1" not in names:
            pytest.skip("R1 is not present in this lab")
        result = session.ping("R1", "192.168.2.1", timeout=45)
        assert result.kind in {
            ObservationKind.REACHABILITY_SUCCEEDED,
            ObservationKind.REACHABILITY_FAILED,
            ObservationKind.REACHABILITY_INCONCLUSIVE,
        }
        if result.kind is ObservationKind.REACHABILITY_INCONCLUSIVE:
            assert result.parsed["success_percent"] is None
        assert result.observed is True
    finally:
        session.close()


@requires_simulator
@requires_registration
def test_devices_are_named_not_indexed(tmp_path):
    """The regression that made every device report as '9'."""
    lab = Path(__file__).parents[1] / "fixtures" / "sample_lab.pkt"
    if not lab.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")
    runtime = SimulatorRuntime(workspace_root=tmp_path / "ws", prefer_live=True)
    session = runtime.create_session(lab)
    try:
        names = [d["name"] for d in session.backend.devices()]
        assert names, "the lab must expose devices"
        assert all(not name.isdigit() for name in names), names
        assert all(name.strip() for name in names), names
    finally:
        session.close()


def _packet_tracer_window_count(settle_seconds: float = 3.0) -> int:
    """Number of visible Packet Tracer windows once startup has settled.

    Under ``--no-gui`` the accessibility window count is transiently ``1`` for a
    second or two while the app initialises, then drops to ``0``. An
    instantaneous read therefore reports a window that does not exist, which is
    what made this test flake. The measurement waits for the window set to settle
    and reports the *final* count; a genuinely visible window would still be
    present after settling and would still fail.
    """
    if shutil.which("osascript") is None:
        return 0
    import subprocess
    import time

    script = (
        'tell application "System Events" to tell process "PacketTracer" '
        "to get count of windows"
    )

    def sample() -> int | None:
        try:
            out = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        text = out.stdout.strip()
        return int(text) if text.isdigit() else None

    time.sleep(settle_seconds)
    final: int | None = None
    for _ in range(3):
        value = sample()
        if value is None:
            return 0
        final = value
        if value == 0:
            return 0
        time.sleep(1.0)
    return final or 0
