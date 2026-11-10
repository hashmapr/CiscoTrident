"""Ghost must never terminate a Packet Tracer process it did not start.

The operator may have their own Packet Tracer open for studying. A cleanup path
that kills by name would close it, so ownership is checked by PID and process
group, and these tests fail if that ever regresses.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

from trident.simulator import SimulatorRuntime
from trident.simulator.backends import ProcessSupervisor, find_packet_tracer

# Several tests here create real sessions, which start Packet Tracer. That must
# never happen as a side effect of the default test run on someone's desktop, so
# the whole module is opt-in alongside the other live tests.
pytestmark = pytest.mark.live_simulator


def _foreign_process() -> subprocess.Popen:
    """A decoy process whose command line resembles Packet Tracer."""
    return subprocess.Popen(
        ["sleep", "120"],
        start_new_session=True,
    )


def test_runtime_reports_no_owned_pids_before_any_session():
    runtime = SimulatorRuntime(prefer_live=True)
    assert runtime.owned_pids() == []


def test_owned_pids_tracks_only_its_own_sessions(monkeypatch, tmp_path):
    """A live session lists exactly its own process."""
    from trident.simulator.backends import credentials_from_env

    if find_packet_tracer() is None or credentials_from_env() is None:
        pytest.skip("no installed registration on this machine")
    monkeypatch.setenv("TRIDENT_ALLOW_LIVE_SIMULATOR", "1")

    lab = Path(__file__).parents[1] / "fixtures" / "sample_lab.pkt"
    if not lab.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")

    runtime = SimulatorRuntime(workspace_root=tmp_path / "ws", prefer_live=True)
    session = runtime.create_session(lab)
    try:
        owned = runtime.owned_pids()
        assert len(owned) == 1
        supervisor = session.backend.supervisor
        assert supervisor is not None
        assert owned[0] == supervisor.process.pid
    finally:
        session.close()
    assert runtime.owned_pids() == []


def test_supervisor_starts_in_its_own_process_group(tmp_path):
    """Killing by process group is only safe if the group is ours alone."""
    bundle = find_packet_tracer()
    if bundle is None:
        pytest.skip("Packet Tracer is not installed")
    supervisor = ProcessSupervisor(bundle, 0)
    try:
        supervisor.start(tmp_path)
        assert supervisor.process is not None
        own_group = os.getpgid(supervisor.process.pid)
        parent_group = os.getpgid(os.getpid())
        assert own_group != parent_group, (
            "the simulator must not share the caller's process group, or a group "
            "kill would take down the calling process too"
        )
    finally:
        supervisor.stop()


def test_stop_does_not_touch_an_unrelated_process(tmp_path):
    """The decisive case: a foreign process survives our shutdown."""
    bundle = find_packet_tracer()
    if bundle is None:
        pytest.skip("Packet Tracer is not installed")

    foreign = _foreign_process()
    try:
        supervisor = ProcessSupervisor(bundle, 0)
        supervisor.start(tmp_path)
        own_pid = supervisor.process.pid
        supervisor.stop()

        assert supervisor.process.poll() is not None, "our process must be gone"
        assert foreign.poll() is None, "an unrelated process must survive"
        assert own_pid != foreign.pid
    finally:
        foreign.kill()
        foreign.wait(timeout=10)


def test_stop_is_idempotent(tmp_path):
    bundle = find_packet_tracer()
    if bundle is None:
        pytest.skip("Packet Tracer is not installed")
    supervisor = ProcessSupervisor(bundle, 0)
    supervisor.start(tmp_path)
    first = supervisor.stop()
    second = supervisor.stop()
    assert first in {"TERMINATED", "KILLED"}
    assert second == "ALREADY_EXITED"


def test_stop_before_start_is_safe():
    bundle = Path("/nonexistent.app")
    supervisor = ProcessSupervisor(bundle, 0)
    assert supervisor.stop() == "NOT_STARTED"


def test_repeated_sessions_leave_no_processes(monkeypatch, tmp_path):
    from trident.simulator.backends import credentials_from_env

    if find_packet_tracer() is None or credentials_from_env() is None:
        pytest.skip("no installed registration on this machine")
    monkeypatch.setenv("TRIDENT_ALLOW_LIVE_SIMULATOR", "1")
    lab = Path(__file__).parents[1] / "fixtures" / "sample_lab.pkt"
    if not lab.is_file():
        pytest.skip("sample_lab.pkt fixture is not present")

    runtime = SimulatorRuntime(workspace_root=tmp_path / "ws", prefer_live=True)
    for _ in range(2):
        session = runtime.create_session(lab)
        assert len(runtime.owned_pids()) == 1
        session.close()
        assert runtime.owned_pids() == []
        time.sleep(1)


def test_no_broad_pkill_anywhere_in_the_simulator_source():
    """Cleanup must target PIDs, never match by name.

    ``pkill -f PacketTracer`` would close the operator's own session, so the
    pattern is banned outright in the runtime package.
    """
    package = Path(__file__).parents[2] / "trident" / "simulator"
    offenders: list[str] = []
    for source in package.rglob("*.py"):
        for number, line in enumerate(source.read_text().splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if ("pkill" in stripped or "killall" in stripped) and "PacketTracer" in stripped:
                offenders.append(f"{source.name}:{number}: {stripped}")
    assert not offenders, "broad process-kill by name found: " + "; ".join(offenders)


# ---------------------------------------------------------------------------
# IPC port ownership
# ---------------------------------------------------------------------------


def test_a_free_port_is_chosen_not_a_foreign_listener():
    """The supervisor must never attach to a Packet Tracer it did not start.

    Accepting any listener on 39000-39009 is how a foreign instance gets used by
    mistake: the supervisor sees a live port, returns it, and its own process
    silently fails to bind. The session then talks to the wrong simulator.
    """
    import socket

    occupied: list[socket.socket] = []
    ports = [39000, 39001]
    try:
        for port in ports:
            sock = socket.socket()
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
            sock.listen(1)
            occupied.append(sock)
    except OSError:
        pytest.skip("ports 39000/39001 are already in use")

    try:
        supervisor = ProcessSupervisor(Path("/tmp/unused.app"), 0)
        chosen = supervisor._choose_port()
        assert chosen not in ports, f"chose an occupied port: {chosen}"
        assert chosen in ProcessSupervisor.IPC_PORT_RANGE
    finally:
        for sock in occupied:
            sock.close()


def test_no_free_port_is_reported_honestly():
    """When every port is taken, say so instead of guessing."""
    import socket

    from trident.simulator.contracts import BackendUnavailable

    occupied: list[socket.socket] = []
    try:
        for port in ProcessSupervisor.IPC_PORT_RANGE:
            sock = socket.socket()
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
            sock.listen(1)
            occupied.append(sock)
    except OSError:
        pytest.skip("could not occupy the whole IPC port range")
        return

    try:
        supervisor = ProcessSupervisor(Path("/tmp/unused.app"), 0)
        with pytest.raises(BackendUnavailable, match="no free Packet Tracer IPC port"):
            supervisor._choose_port()
    finally:
        for sock in occupied:
            sock.close()
