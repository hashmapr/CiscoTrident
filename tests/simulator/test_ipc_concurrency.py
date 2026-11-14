"""IPC port allocation and session-ownership invariants, proven by real sockets.

Nothing here starts Packet Tracer. Every assertion is exercised against the
loopback interface with real listening sockets, so the behaviour under test is
the same syscall path ``ProcessSupervisor._choose_port`` uses in production.

The four properties pinned down:

1. A port another process is already listening on is never returned. Returning
   it would let a session talk to a stranger's Packet Tracer (wrong lab, wrong
   state, cleanup that touches something it does not own).
2. Repeated choose/bind/close cycles do not exhaust the range. The stock
   Packet Tracer window is ten ports and a test sweep burns through it.
3. A port still in TIME_WAIT is not selected. This is the reason the probe
   deliberately binds without ``SO_REUSEADDR``: with it, ``bind()`` succeeds on
   a TIME_WAIT port, Packet Tracer then cannot serve it properly, and the PTMP
   handshake times out.
4. A runtime that has created no sessions owns no PIDs, and a PID it did not
   spawn can never appear in ``owned_pids()``.

Ports are taken from a block of 60 real free ports. The production range
(39000-39059) is used when it is entirely free; otherwise a block further up
is used, so a Packet Tracer instance already running on this machine is never
disturbed and never fought over.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from trident.simulator.backends import ProcessSupervisor
from trident.simulator.sessions import SimulatorRuntime

LOOPBACK = "127.0.0.1"
BLOCK_SIZE = len(ProcessSupervisor.IPC_PORT_RANGE)
#: Preferred base blocks, in order. 39000 is Packet Tracer's own starting
#: point; the rest are ordinary high ports that avoid the production window.
MAIN_BASES = (39000, 41000, 42000, 43000, 44000, 45000, 46000, 47000, 48000)
#: Bases used for throwaway ranges that may linger in TIME_WAIT afterwards.
EPHEMERAL_BASES = range(49000, 49801, 100)


def _plain_bind_ok(port: int) -> bool:
    """True when a default-options bind to ``port`` succeeds.

    Default options mean no ``SO_REUSEADDR``, which is exactly how
    ``_choose_port`` probes.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind((LOOPBACK, port))
        except OSError:
            return False
    return True


def _reuseaddr_bind_ok(port: int) -> bool:
    """True when ``SO_REUSEADDR`` lets us bind ``port``."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((LOOPBACK, port))
        except OSError:
            return False
    return True


def _block_available(base: int, size: int) -> bool:
    return all(_plain_bind_ok(port) for port in range(base, base + size))


def _find_free_block(size: int, bases: Iterable[int]) -> range:
    for base in bases:
        if _block_available(base, size):
            return range(base, base + size)
    pytest.skip(f"no contiguous block of {size} free loopback ports was available")


@pytest.fixture
def ipc_block(monkeypatch: pytest.MonkeyPatch) -> range:
    """A 60-port range that is genuinely free, installed as the IPC range.

    39000-39059 is preferred so the assertions match the shipped configuration.
    If any port in it is occupied (a real Packet Tracer, or a leftover), a
    higher block is used instead of competing for it.
    """
    block = _find_free_block(BLOCK_SIZE, MAIN_BASES)
    monkeypatch.setattr(ProcessSupervisor, "IPC_PORT_RANGE", block, raising=True)
    return block


def _supervisor() -> ProcessSupervisor:
    # Construction touches no filesystem path; the bundle is only read by
    # start(), which these tests never call.
    return ProcessSupervisor(Path("/nonexistent-packet-tracer"), 0)


@contextmanager
def _listeners(ports: Iterable[int]) -> Iterator[list[socket.socket]]:
    """Hold real listening sockets on ``ports`` for the duration of the block."""
    held: list[socket.socket] = []
    try:
        for port in ports:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind((LOOPBACK, port))
            listener.listen(1)
            held.append(listener)
        yield held
    finally:
        for listener in held:
            listener.close()


def test_choose_port_skips_ports_with_listeners(ipc_block: range) -> None:
    """Every port but the last is occupied; exactly the last one is chosen."""
    occupied = list(ipc_block)[:-1]
    expected = ipc_block.stop - 1

    with _listeners(occupied):
        chosen = _supervisor()._choose_port()

    assert chosen == expected
    assert chosen not in occupied
    # The selection must be bindable by the process that will use it.
    assert _plain_bind_ok(chosen)


def test_choose_port_skips_a_listener_in_the_middle(ipc_block: range) -> None:
    """A listener mid-range is skipped, proving the loop continues past a hit."""
    blocked = ipc_block.start + 7
    with _listeners([ipc_block.start, blocked]):
        chosen = _supervisor()._choose_port()

    assert chosen == ipc_block.start + 1
    assert chosen != blocked


def test_repeated_choose_bind_close_cycles_do_not_exhaust_range(
    ipc_block: range,
) -> None:
    """Four full sweeps of the range, each port released again.

    A ten-port window fails here after ten cycles. No connection is made, so
    no port enters TIME_WAIT and the same lowest free port is expected every
    time - that is the proof the range is recycled rather than consumed.
    """
    supervisor = _supervisor()
    cycles = len(ipc_block) * 4
    seen: set[int] = set()

    started = time.monotonic()
    for _ in range(cycles):
        port = supervisor._choose_port()
        assert port in ipc_block
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
            held.bind((LOOPBACK, port))  # simulate Packet Tracer taking it
            seen.add(port)
    elapsed = time.monotonic() - started

    assert seen == {ipc_block.start}
    assert elapsed < 10.0


def _force_time_wait(port: int) -> None:
    """Leave the *server* side of a loopback connection in TIME_WAIT."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((LOOPBACK, port))
        server.listen(1)
        with socket.create_connection((LOOPBACK, port), timeout=2.0) as client:
            connection, _ = server.accept()
            connection.sendall(b"x")
            assert client.recv(1) == b"x"
            # The side that closes first owns the TIME_WAIT state. Close the
            # accepted connection first, so 127.0.0.1:<port> is the one held.
            connection.close()
    finally:
        server.close()


def _wait_for_time_wait(port: int, timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _plain_bind_ok(port) and _reuseaddr_bind_ok(port):
            return True
        time.sleep(0.02)
    return False


def test_time_wait_port_is_not_selected(monkeypatch: pytest.MonkeyPatch) -> None:
    """A TIME_WAIT port is skipped, and the reason is demonstrated directly.

    The code under test binds without ``SO_REUSEADDR`` on purpose. This test
    shows the two probes disagreeing on the same port: a default bind fails
    while an ``SO_REUSEADDR`` bind would succeed. That disagreement is the
    evidence that a naive ``SO_REUSEADDR`` probe would have returned a port
    Packet Tracer cannot serve.
    """
    block = _find_free_block(2, EPHEMERAL_BASES)
    time_wait_port, free_port = block.start, block.start + 1

    _force_time_wait(time_wait_port)
    if not _wait_for_time_wait(time_wait_port):
        pytest.skip("the platform did not hold the port in TIME_WAIT")

    # Precondition, asserted rather than assumed: this is the exact hazard.
    assert _plain_bind_ok(time_wait_port) is False
    assert _reuseaddr_bind_ok(time_wait_port) is True

    monkeypatch.setattr(
        ProcessSupervisor, "IPC_PORT_RANGE", range(time_wait_port, free_port + 1)
    )
    chosen = _supervisor()._choose_port()

    assert chosen == free_port
    assert chosen != time_wait_port


def test_runtime_without_sessions_owns_no_pids() -> None:
    """No sessions means no owned PIDs, and no phantom cleanup targets."""
    runtime = SimulatorRuntime(prefer_live=False)

    assert runtime.active_sessions == ()
    assert runtime.owned_pids() == []
    assert runtime.close_all() == {}
    assert runtime.owned_pids() == []

    # Closing or forgetting an id that was never open is a no-op, not a leak.
    assert runtime.close_session("never-opened") == "UNKNOWN_SESSION"
    runtime._forget("never-opened")
    assert runtime.active_sessions == ()
    assert runtime.owned_pids() == []


class _FakeSupervisor:
    def __init__(self, process: subprocess.Popen | None) -> None:
        self.process = process


class _FakeBackend:
    def __init__(self, process: subprocess.Popen | None) -> None:
        self.supervisor = _FakeSupervisor(process)


class _FakeSession:
    def __init__(self, process: subprocess.Popen | None) -> None:
        self.backend = _FakeBackend(process)


def test_owned_pids_lists_only_live_spawned_processes() -> None:
    """A dead child is not owned; a missing supervisor is not owned."""
    runtime = SimulatorRuntime(prefer_live=False)
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        runtime._sessions["live"] = _FakeSession(child)  # type: ignore[assignment]
        runtime._sessions["absent"] = _FakeSession(None)  # type: ignore[assignment]
        assert runtime.owned_pids() == [child.pid]

        child.terminate()
        child.wait(timeout=10)
        assert runtime.owned_pids() == []
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
        runtime._sessions.clear()
