"""Bounded IPC behaviour, proven without Packet Tracer.

The differential gauntlet recorded three IPC defects this module pins down:

1. ``PtmpClient.call`` looped on ``while True`` forever while skipping frames.
   A socket timeout does not save it: Packet Tracer streams ``IPC_EVENT`` frames
   during simulation, each resets the timeout, and the loop spins at full CPU.
2. ``LiveBackend.connect`` leaked its Packet Tracer process whenever the client
   failed after the supervisor started (bad secret, occupied port, lab refused).
3. Port selection reported a stale range in its error message, and a port that
   was free was not actually held, so a racing process could take it.

Everything here drives a real TCP socket against a scripted fake server, so the
frame parsing and the deadline logic are exercised for real. Nothing starts
Packet Tracer, and no test depends on it being installed.
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Self

import pytest

from trident.simulator.ptmp import (
    DISCONNECT,
    IPC_CALL,
    IPC_EVENT,
    IPC_RESPONSE,
    PtmpClient,
    PtmpDisconnected,
    PtmpError,
    PtmpTimeout,
)


class FakeServer:
    """A one-connection PTMP peer that reads frames and sends canned replies."""

    def __init__(self, responder) -> None:
        self._responder = responder
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._stopped = threading.Event()

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stopped.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=5)

    def _read_frame(self, conn: socket.socket) -> list[str] | None:
        head = b""
        while b"\x00" not in head:
            chunk = conn.recv(1)
            if not chunk:
                return None
            head += chunk
        length = int(head[:-1])
        body = b""
        while len(body) < length:
            chunk = conn.recv(length - len(body))
            if not chunk:
                return None
            body += chunk
        parts = body.split(b"\x00")
        if parts and parts[-1] == b"":
            parts = parts[:-1]
        return [p.decode() for p in parts]

    def _serve(self) -> None:
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        conn.settimeout(0.2)
        try:
            while not self._stopped.is_set():
                try:
                    frame = self._read_frame(conn)
                except TimeoutError:
                    continue
                except (OSError, ValueError):
                    return
                if frame is None or not frame:
                    return
                if frame[0] == DISCONNECT:
                    return
                action = self._responder(frame, conn)
                if action == "close":
                    return
        finally:
            try:
                conn.close()
            except OSError:
                pass


def _send(conn: socket.socket, fields: list[str]) -> None:
    body = b"".join(f.encode() + b"\x00" for f in fields)
    conn.sendall(str(len(body)).encode() + b"\x00" + body)


def _authenticated(responder):
    """Wrap a responder so negotiation and auth succeed before it is consulted."""

    def handle(frame: list[str], conn: socket.socket):
        kind = frame[0]
        if kind == "0":  # negotiation
            _send(conn, ["1", "9.0.1", "{server-uid}", "1", "1", "1", "4"])
            return None
        if kind == "2":  # auth request
            _send(conn, ["3", "challenge"])
            return None
        if kind == "4":  # auth response
            _send(conn, ["5", "true"])
            return None
        return responder(frame, conn)

    return handle


def _client(port: int) -> PtmpClient:
    return PtmpClient("app", "secret", port=port)


def test_call_times_out_when_the_peer_streams_events_forever() -> None:
    """The regression that burned CPU: events with no reply, forever."""

    def responder(frame, conn):
        if frame[0] == IPC_CALL:
            # Emit events and never answer the call.
            for _ in range(200):
                _send(conn, [IPC_EVENT, "1", "noise"])

    with FakeServer(_authenticated(responder)) as server:
        client = _client(server.port)
        client.connect()
        try:
            started = time.monotonic()
            with pytest.raises(PtmpTimeout):
                client.call(["network", "getDeviceCount"], timeout=1.0)
            elapsed = time.monotonic() - started
            # Bounded by the deadline, not by the frame count.
            assert elapsed < 5.0, f"call took {elapsed:.1f}s despite a 1s timeout"
        finally:
            client.close()


def test_call_still_accepts_a_reply_after_unrelated_frames() -> None:
    """Skipping must not become refusing: a late reply is still the reply."""

    def responder(frame, conn):
        if frame[0] == IPC_CALL:
            call_id = frame[1]
            _send(conn, [IPC_EVENT, "1", "noise"])
            _send(conn, [IPC_RESPONSE, call_id, "4", "7"])

    with FakeServer(_authenticated(responder)) as server:
        client = _client(server.port)
        client.connect()
        try:
            assert client.call(["network", "getDeviceCount"], timeout=5.0) == ["7"]
        finally:
            client.close()


def test_call_reports_a_skipped_frame_cap_distinctly() -> None:
    """A flood of foreign frames is a different fault from a slow reply."""

    def responder(frame, conn):
        if frame[0] == IPC_CALL:
            for _ in range(PtmpClient.MAX_SKIPPED_FRAMES + 10):
                _send(conn, [IPC_EVENT, "1", "noise"])

    with FakeServer(_authenticated(responder)) as server:
        client = _client(server.port)
        client.connect()
        try:
            with pytest.raises(PtmpTimeout, match="without a reply"):
                client.call(["network", "getDeviceCount"], timeout=30.0)
        finally:
            client.close()


def test_disconnect_during_call_is_not_reported_as_a_timeout() -> None:
    """Error propagation must stay specific."""

    def responder(frame, conn):
        if frame[0] == IPC_CALL:
            return "close"
        return None

    with FakeServer(_authenticated(responder)) as server:
        client = _client(server.port)
        client.connect()
        try:
            with pytest.raises(PtmpDisconnected):
                client.call(["network", "getDeviceCount"], timeout=5.0)
        finally:
            client.close()


def test_connect_failure_leaves_no_socket_open() -> None:
    """A refused connection must not leave a half-built client behind."""
    # A port that nothing listens on: bind then close, so it is provably free.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]

    client = PtmpClient("app", "secret", port=dead_port, connect_timeout=1.0)
    with pytest.raises(PtmpError):
        client.connect()
    assert client._sock is None


# ---------------------------------------------------------------------------
# Process lifecycle: a failed connect must not abandon Packet Tracer
# ---------------------------------------------------------------------------


def test_connect_failure_tears_down_the_supervisor(monkeypatch) -> None:
    """A client failure after startup must stop the process it just started.

    The leak this pins: ``select_backend`` calls ``connect()`` and then
    ``close()`` on failure, but the old ``connect()`` raised out of
    ``client.connect()`` *after* the supervisor had spawned Packet Tracer. The
    backend's ``close()`` only touches ``self.supervisor``, which had been set —
    so the process was stopped in that path, but only because the caller
    happened to close. A caller that did not (a test, a script, an exception in
    ``_open_lab`` before ``self.client`` was assigned) left an invisible
    Packet Tracer running forever. ``connect`` now cleans up itself.
    """
    from trident.simulator import backends

    started: list[int] = []
    stopped: list[object] = []

    class FakeSupervisor:
        def __init__(self, *a, **kw) -> None:
            self.process = None

        def start(self, workspace, timeout_s=None) -> int:
            started.append(4242)

            class _P:
                pid = 4242

                def poll(self):
                    return None

            self.process = _P()
            return 39001

        def stop(self, timeout_s: float = 10.0) -> str:
            stopped.append(self.process)
            return "TERMINATED"

    class BoomClient:
        def __init__(self, *a, **kw) -> None:
            pass

        def connect(self):
            raise backends.PtmpError("app id 'x' was rejected")

    monkeypatch.setattr(backends, "ProcessSupervisor", FakeSupervisor)
    monkeypatch.setattr(backends, "PtmpClient", BoomClient)

    backend = backends.LiveBackend(
        bundle=__import__("pathlib").Path("/nonexistent"),
        working_copy=__import__("pathlib").Path("/tmp/x.pkt"),
        source_sha256="0" * 64,
        session_id="s1",
        credentials=("app", "secret"),
        workspace=__import__("pathlib").Path("/tmp"),
    )

    with pytest.raises(backends.PtmpError):
        backend.connect()

    assert started == [4242], "the fake supervisor never started"
    assert len(stopped) == 1, "connect() leaked the process it started"
    assert backend.supervisor is None
    assert backend.client is None


def test_connect_cancellation_also_tears_down(monkeypatch) -> None:
    """Cancellation is a BaseException; the teardown must still run."""
    from trident.simulator import backends

    stopped: list[str] = []

    class FakeSupervisor:
        def __init__(self, *a, **kw) -> None:
            self.process = None

        def start(self, workspace, timeout_s=None) -> int:
            class _P:
                pid = 4242

                def poll(self):
                    return None

            self.process = _P()
            return 39001

        def stop(self, timeout_s: float = 10.0) -> str:
            stopped.append("TERMINATED")
            return "TERMINATED"

    class CancelledClient:
        def __init__(self, *a, **kw) -> None:
            pass

        def connect(self):
            raise KeyboardInterrupt

    monkeypatch.setattr(backends, "ProcessSupervisor", FakeSupervisor)
    monkeypatch.setattr(backends, "PtmpClient", CancelledClient)

    backend = backends.LiveBackend(
        bundle=__import__("pathlib").Path("/nonexistent"),
        working_copy=__import__("pathlib").Path("/tmp/x.pkt"),
        source_sha256="0" * 64,
        session_id="s2",
        credentials=("app", "secret"),
        workspace=__import__("pathlib").Path("/tmp"),
    )

    with pytest.raises(KeyboardInterrupt):
        backend.connect()

    assert stopped == ["TERMINATED"]


def test_start_refuses_a_port_that_was_taken_before_spawn(monkeypatch, tmp_path) -> None:
    """A port occupied at spawn time must fail, not attach to the stranger.

    ``_choose_port`` releases its reservation before ``Popen``, so a racing
    process can bind in between. Attaching there would give the session a real
    but *foreign* Packet Tracer: wrong lab, wrong state, and a cleanup path that
    must not touch it. The supervisor now proves the port was refused before
    spawn and fails loudly instead.
    """
    import socket

    from trident.simulator import backends

    # A real listener, so the port is provably occupied.
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    holder.bind(("127.0.0.1", 0))
    holder.listen(1)
    taken = holder.getsockname()[1]
    try:
        # A fake executable that would "start": the guard must trip before spawn.
        exe = tmp_path / "Fake.app" / "Contents" / "MacOS"
        exe.mkdir(parents=True)
        (exe / "PacketTracer").write_text("#!/bin/sh\nsleep 30\n")
        (exe / "PacketTracer").chmod(0o755)

        supervisor = backends.ProcessSupervisor(tmp_path / "Fake.app", ipc_port=taken)
        with pytest.raises(backends.BackendUnavailable, match="already in use"):
            supervisor.start(tmp_path, timeout_s=1.0)
        assert supervisor.process is None or supervisor.process.poll() is not None
    finally:
        holder.close()
