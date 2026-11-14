"""Native PTMP wire client.

Packet Tracer speaks a small, fully specified binary protocol over a local TCP
socket. The specification is the Java framework Cisco ships inside the
installation; field order and type codes below were read from that framework,
and no Cisco code is copied here.

This is a direct adapter, deliberately not wrapped in an MCP server: Phase 3
must not take MCP as a runtime dependency.

Two properties matter for evidence integrity:

* The client never claims success it did not see. ``call`` raises
  :class:`PtmpError` on error responses, disconnects and timeouts.
* The secret is only used to compute a digest inside :meth:`PtmpClient.connect`
  and is never placed in an error message or a log line.
"""

from __future__ import annotations

import hashlib
import socket
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Self

NEGOTIATION_REQUEST = "0"
NEGOTIATION_RESPONSE = "1"
AUTH_REQUEST = "2"
AUTH_CHALLENGE = "3"
AUTH_RESPONSE = "4"
AUTH_STATUS = "5"
KEEP_ALIVE = "6"
DISCONNECT = "7"
IPC_CALL = "100"
IPC_ERROR = "101"
IPC_RESPONSE = "102"
IPC_EVENT = "103"
IPC_SUBSCRIBE = "104"

SIGNATURE = "PTMP"
PROTOCOL_VERSION = 1
TEXT_ENCODING = 1
NO_ENCRYPTION = 1
NO_COMPRESSION = 1
MD5_AUTHENTICATION = 4

# Argument type codes, from IPCMessageConstants in the shipped framework.
TYPE_VOID = 0
TYPE_BOOL = 2
TYPE_INT = 4
TYPE_STRING = 8
#: Qt-style string. Most UI-facing methods (fileOpen, getDevice) take a QString;
#: passing a plain String is rejected as invalid arguments.
TYPE_QSTRING = 9
TYPE_PAIR = 14

MAX_FRAME_BYTES = 64 * 1024 * 1024
DEFAULT_PORTS = tuple(range(39000, 39010))


class PtmpError(RuntimeError):
    """Any protocol, transport or authorization failure."""


class PtmpAuthRejected(PtmpError):
    """The server refused the app id or secret."""


class PtmpDisconnected(PtmpError):
    """The server closed the connection."""


class PtmpTimeout(PtmpError):
    """An operation exceeded its deadline."""


@dataclass(frozen=True)
class PtmpHandshake:
    server_version: str
    server_uid: str


def _frame(fields: list[str]) -> bytes:
    body = b"".join(field.encode() + b"\x00" for field in fields)
    return str(len(body)).encode() + b"\x00" + body


def _read_exact(sock: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise PtmpDisconnected("connection closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_frame(sock: socket.socket) -> list[str]:
    head = b""
    while b"\x00" not in head:
        if len(head) > 10:
            raise PtmpError("frame length field is implausible")
        chunk = sock.recv(1)
        if not chunk:
            raise PtmpDisconnected("connection closed before length")
        head += chunk
    try:
        length = int(head[:-1])
    except ValueError as exc:
        raise PtmpError("frame length is not an integer") from exc
    if length < 0 or length > MAX_FRAME_BYTES:
        raise PtmpError(f"frame length {length} outside bounds")
    body = _read_exact(sock, length) if length else b""
    parts = body.split(b"\x00")
    if parts and parts[-1] == b"":
        parts = parts[:-1]
    return [part.decode(errors="replace") for part in parts]


def _decode_result(fields: list[str]) -> list[str]:
    """Strip the result type code from an IPC response.

    A response body is ``<type_code> <value>``, and for object returns it is
    ``<type_code> <value> <cache_uuid>``. Returning the raw fields made callers
    read the type code as the value (every device was reported as ``"9"``), so
    the code is removed here. The cache UUID is appended by Packet Tracer for
    object handles and is not part of the value.
    """
    if not fields:
        return fields
    head = fields[0]
    if not head.isdigit():
        return fields
    code = int(head)
    if code == TYPE_VOID:
        return []
    if code == TYPE_PAIR:
        # A pair is encoded as the pair code, then two complete values. Unwrap
        # the first level only, so ``enterCommand`` yields
        # [command_status, output_text] rather than the leading type codes.
        return _decode_values(fields[1:], count=2)
    value = fields[1] if len(fields) > 1 else ""
    # Object handles carry a trailing cache uuid in braces.
    if len(fields) > 2 and fields[2].startswith("{") and fields[2].endswith("}"):
        return [value, fields[2]]
    return [value]


def _decode_values(fields: list[str], count: int) -> list[str]:
    """Decode ``count`` consecutive ``<type> <value>`` pairs from ``fields``."""
    out: list[str] = []
    index = 0
    while index < len(fields) and len(out) < count:
        head = fields[index]
        if not head.isdigit():
            out.append(head)
            index += 1
            continue
        value = fields[index + 1] if index + 1 < len(fields) else ""
        out.append(value)
        index += 2
    return out


def _timestamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%d%H%M%S")


class PtmpClient:
    """One PTMP connection. Not thread-safe; one session owns one client."""

    def __init__(
        self,
        app_id: str,
        secret: str,
        host: str = "127.0.0.1",
        port: int | None = None,
        *,
        connect_timeout: float = 10.0,
    ) -> None:
        self._app_id = app_id
        self._secret = secret
        self.host = host
        self.port = port
        self.connect_timeout = connect_timeout
        self._sock: socket.socket | None = None
        self._next_id = 1
        self.handshake: PtmpHandshake | None = None

    # -- lifecycle ---------------------------------------------------------

    def connect(self) -> PtmpHandshake:
        port = self.port if self.port is not None else self._discover_port()
        try:
            sock = socket.create_connection((self.host, port), timeout=self.connect_timeout)
        except OSError as exc:
            raise PtmpError(
                f"cannot reach Packet Tracer IPC on {self.host}:{port}: {exc}"
            ) from exc
        sock.settimeout(self.connect_timeout)
        self._sock = sock
        try:
            handshake = self._negotiate()
            self._authenticate()
        except Exception:
            self.close()
            raise
        self.handshake = handshake
        self.port = port
        return handshake

    def close(self) -> None:
        sock, self._sock = self._sock, None
        if sock is None:
            return
        try:
            sock.sendall(_frame([DISCONNECT, "trident session closed"]))
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def __enter__(self) -> Self:
        self.connect()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- operations --------------------------------------------------------

    def call(self, accessors: list, timeout: float = 30.0) -> list[str]:
        """Invoke an IPC accessor chain and return the raw response fields.

        Each step is either a bare accessor name (takes no arguments) or a
        ``(name, [(type_code, value), ...])`` tuple. The protocol writes the
        method name, then each argument as a type code followed by its value,
        then a terminating ``"0"``. Writing a void terminator after every name —
        which an earlier version did — makes every method look zero-argument,
        so calls like ``getDeviceAt(3)`` fail with "invalid arguments".

        The read loop is bounded twice. It was previously ``while True`` with no
        deadline, which was safe only by accident: a socket timeout bounds a
        *stalled* read, but Packet Tracer streams ``IPC_EVENT`` frames during
        simulation runs, and every one of them resets that timeout. A session
        left in simulation mode therefore spun reading events that were never
        ours, at full CPU, until the process was killed. Now the loop stops when
        the wall-clock deadline passes or when it has skipped more frames than a
        sane reply could require, and reports that as a timeout rather than
        pretending the call failed for another reason.
        """
        if self._sock is None:
            raise PtmpError("not connected")
        call_id = self._next_id
        self._next_id += 1
        fields = [IPC_CALL, str(call_id)]
        for step in accessors:
            if isinstance(step, tuple):
                name, arguments = step
            else:
                name, arguments = step, ()
            fields.append(name)
            for type_code, value in arguments:
                fields.append(str(type_code))
                fields.append(str(value))
            fields.append(str(TYPE_VOID))
        self._sock.sendall(_frame(fields))

        last = accessors[-1] if accessors else "<call>"
        label = last[0] if isinstance(last, tuple) else last
        deadline = time.monotonic() + timeout
        skipped = 0
        previous = self._sock.gettimeout()
        self._sock.settimeout(timeout)
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PtmpTimeout(
                        f"{label} timed out after {timeout}s "
                        f"({skipped} unrelated frame(s) skipped)"
                    )
                # Never let a single read block past the overall deadline.
                self._sock.settimeout(min(remaining, timeout))
                try:
                    reply = _read_frame(self._sock)
                except TimeoutError as exc:
                    raise PtmpTimeout(f"{label} timed out after {timeout}s") from exc
                kind = reply[0] if reply else ""
                if kind == IPC_RESPONSE and reply[1] == str(call_id):
                    return _decode_result(reply[2:])
                if kind == IPC_ERROR and reply[1] == str(call_id):
                    raise PtmpError(f"IPC error from {label}: {reply[2:]}")
                if kind == DISCONNECT:
                    raise PtmpDisconnected("server disconnected during call")
                # Responses to other calls and events are not ours; skip them,
                # but a flood of them means something is wrong, so cap the
                # skipping instead of trusting the deadline alone.
                skipped += 1
                if skipped > self.MAX_SKIPPED_FRAMES:
                    raise PtmpTimeout(
                        f"{label} received {skipped} unrelated frames without a reply; "
                        "the session is streaming events it cannot distinguish"
                    )
        finally:
            if self._sock is not None:
                try:
                    self._sock.settimeout(previous)
                except OSError:
                    pass

    #: Ceiling on unrelated frames skipped while waiting for one reply. A busy
    #: simulation run emits events continuously; this is high enough for normal
    #: traffic and low enough that a mistaken subscription cannot hang a session.
    MAX_SKIPPED_FRAMES = 5000

    def enter_command(self, device_name: str, command: str, mode: str = "enable") -> str:
        """Run one CLI command on a device and return its raw text.

        Maps to ``CiscoDevice.enterCommand(commandStr, modeStr)`` in the shipped
        framework. The response is a ``Pair<CommandStatus, String>``: status
        ``0`` (``STATUS_OK``) is the only value that means the command ran, and
        the text is returned verbatim so the caller can parse it.

        ``mode`` must be an accepted mode name. Packet Tracer accepts
        ``"enable"`` and ``"user"``; ``"exec"`` and ``"privileged"`` are rejected
        as ``ERROR_INVALID``, which was verified against 9.0.1 rather than
        assumed from the documentation.
        """
        fields = self.call(
            [
                "network",
                ("getDevice", [(9, device_name)]),
                ("enterCommand", [(TYPE_STRING, command), (TYPE_STRING, mode)]),
            ],
            timeout=60.0,
        )
        status = fields[0] if fields else ""
        text = fields[1] if len(fields) > 1 else ""
        if status not in {"0", "STATUS_OK"}:
            raise PtmpError(
                f"enterCommand on {device_name} returned status {status} for {command!r}"
            )
        return text

    # -- internals ---------------------------------------------------------

    def _discover_port(self) -> int:
        for port in DEFAULT_PORTS:
            try:
                probe = socket.create_connection((self.host, port), timeout=0.4)
            except OSError:
                continue
            probe.close()
            return port
        raise PtmpError(
            f"no Packet Tracer IPC listener on {self.host} ports "
            f"{DEFAULT_PORTS[0]}-{DEFAULT_PORTS[-1]}"
        )

    def _negotiate(self) -> PtmpHandshake:
        import uuid as uuid_module

        client_uid = "{" + str(uuid_module.uuid4()) + "}"
        self._send(
            [
                NEGOTIATION_REQUEST,
                SIGNATURE,
                str(PROTOCOL_VERSION),
                client_uid,
                str(TEXT_ENCODING),
                str(NO_ENCRYPTION),
                str(NO_COMPRESSION),
                str(MD5_AUTHENTICATION),
                _timestamp(),
                "0",
                "",
            ]
        )
        reply = self._recv()
        if not reply or reply[0] != NEGOTIATION_RESPONSE:
            raise PtmpError(f"unexpected negotiation reply: {reply[:2]}")
        server_uid = reply[3] if len(reply) > 3 else ""
        version = ""
        if len(reply) > 10 and reply[10].startswith(":PTVER"):
            version = reply[10][len(":PTVER") :]
        return PtmpHandshake(server_version=version, server_uid=server_uid)

    def _authenticate(self) -> None:
        self._send([AUTH_REQUEST, self._app_id])
        reply = self._recv()
        if not reply or reply[0] != AUTH_CHALLENGE:
            if reply and reply[0] == DISCONNECT:
                raise PtmpDisconnected("server disconnected before the challenge")
            raise PtmpError(f"expected auth challenge, got: {reply[:2]}")
        challenge = reply[1] if len(reply) > 1 else ""
        digest = hashlib.md5((challenge + self._secret).encode()).hexdigest().upper()
        self._send([AUTH_RESPONSE, self._app_id, digest, ""])
        reply = self._recv()
        if reply and reply[0] == DISCONNECT:
            raise PtmpAuthRejected(
                f"app id {self._app_id!r} is not registered in Packet Tracer, or the "
                "secret does not match the registered key"
            )
        if not reply or reply[0] != AUTH_STATUS:
            raise PtmpError(f"expected auth status, got: {reply[:2]}")
        if reply[1].lower() != "true":
            raise PtmpAuthRejected(f"app id {self._app_id!r} was rejected")

    def _send(self, fields: list[str]) -> None:
        if self._sock is None:
            raise PtmpError("not connected")
        self._sock.sendall(_frame(fields))

    def _recv(self) -> list[str]:
        if self._sock is None:
            raise PtmpError("not connected")
        return _read_frame(self._sock)
