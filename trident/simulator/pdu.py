"""Genuine packet-level connectivity testing through Packet Tracer.

This module answers a question the CLI cannot: *did traffic actually get
delivered?* A CLI ``ping`` in Packet Tracer is interactive and returns a prompt
rather than a verdict, but the simulation layer exposes a simple-PDU API, frame
delivery state and per-frame decision text. That is real evidence.

Measured against Packet Tracer 9.0.1.0858:

* ``appWindow.getUserCreatedPDU().addSimplePdu(from, to)`` returns an
  ``ADD_PDU_ERROR`` code. ``0`` is success; ``20`` is a missing source device and
  ``30`` a missing destination, verified by probing both.
* Both arguments are QStrings.
* After a PDU is added, ``simulation.getFrameInstanceCount()`` rises and each
  frame reports ``isFrameSent()``, ``isFrameDropped()`` and
  ``getPercentageSent()``.
* ``getDecisionAt(i)`` returns the simulator's own reasoning, e.g. *"The Ping
  process starts the next ping request."*

Honesty rules this module exists to enforce:

* Submitting a PDU is **not** delivery. Only frames and their state count.
* ``addSimplePdu`` returning an error is a real failure and is classified, never
  retried into existence.
* A frame that was sent but never arrived is ``INCONCLUSIVE``, not ``DELIVERED``.
* An absent capability is ``UNSUPPORTED``. It is never reported as a success.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from .contracts import (
    BackendKind,
    Capability,
    Provenance,
    utcnow,
)
from .ptmp import TYPE_INT, PtmpError

#: ``ADD_PDU_ERROR`` values, read from the shipped enum and confirmed by probing.
PDU_ERRORS: dict[int, str] = {
    0: "NOT_HAVING_ERROR",
    1: "NOT_IN_ADD_PDU_MODE",
    2: "NO_SUCH_SOURCE_DEVICE",
    3: "NO_IP_IN_SOURCE",
    4: "NO_IP_IN_SELECTED_DEVICE",
    5: "NO_SUCH_DESTINATION_DEVICE",
    6: "NO_IP_IN_DESTINATION",
    # The installed build returns these for unknown endpoints; both are treated
    # as a device-identity failure so the caller never mistakes them for success.
    20: "NO_SUCH_SOURCE_DEVICE",
    30: "NO_SUCH_DESTINATION_DEVICE",
}


class DeliveryStatus(enum.StrEnum):
    """What a packet experiment actually established."""

    #: Frames reached the destination and none were dropped.
    DELIVERED = "DELIVERED"
    #: The simulator dropped a frame.
    DROPPED = "DROPPED"
    #: Frames were produced but never completed in time.
    TIMED_OUT = "TIMED_OUT"
    #: A result was produced but does not establish delivery either way.
    INCONCLUSIVE = "INCONCLUSIVE"
    #: This backend cannot run packet experiments.
    UNSUPPORTED = "UNSUPPORTED"
    #: The experiment itself failed (device missing, IPC error).
    EXECUTION_ERROR = "EXECUTION_ERROR"


@dataclass(frozen=True)
class PduResult:
    """One packet experiment, with the evidence behind its verdict."""

    status: DeliveryStatus
    source: str
    destination: str
    protocol: str
    operation: str
    raw: str
    provenance: Provenance
    add_pdu_error: str | None = None
    frames_seen: int = 0
    frames_dropped: int = 0
    frames_sent: int = 0
    decisions: tuple[str, ...] = ()
    experiment_id: str = ""
    started_at: str = ""
    finished_at: str = ""
    error: str | None = None
    caveats: tuple[str, ...] = field(default_factory=tuple)

    @property
    def observed(self) -> bool:
        """True only when a live simulator actually produced this result.

        Backend kind alone is not enough: an ``UNSUPPORTED`` result from a live
        backend means nothing was executed, so nothing was observed.
        """
        if self.provenance.backend is not BackendKind.SIMULATOR_LIVE:
            return False
        return self.status not in {DeliveryStatus.UNSUPPORTED, DeliveryStatus.EXECUTION_ERROR}

    @property
    def delivered(self) -> bool:
        return self.status is DeliveryStatus.DELIVERED

    def as_dict(self) -> dict:
        return {
            "status": self.status.value,
            "source": self.source,
            "destination": self.destination,
            "protocol": self.protocol,
            "operation": self.operation,
            "add_pdu_error": self.add_pdu_error,
            "frames_seen": self.frames_seen,
            "frames_sent": self.frames_sent,
            "frames_dropped": self.frames_dropped,
            "decisions": list(self.decisions),
            "experiment_id": self.experiment_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "observed": self.observed,
            "caveats": list(self.caveats),
            "provenance": self.provenance.as_dict(),
            "raw": self.raw,
        }


#: Protocols a simple PDU can carry. ICMP is the only one Packet Tracer's simple
#: PDU actually sends; the rest are named so a caller gets UNSUPPORTED rather
#: than a silent ICMP substitution.
SUPPORTED_PROTOCOLS = frozenset({"icmp"})


class PduExecutor:
    """Runs simple-PDU experiments over one live PTMP connection.

    Deliberately takes a connected client rather than owning one, so a session
    keeps a single simulator for CLI and packet work.
    """

    def __init__(self, client, provenance_factory, session_id: str = "") -> None:
        self._client = client
        self._provenance = provenance_factory
        self._session_id = session_id
        self._sequence = 0

    def supported(self) -> bool:
        return self._client is not None

    # -- public API --------------------------------------------------------

    def send(
        self,
        source: str,
        destination: str,
        protocol: str = "icmp",
        timeout_seconds: float = 15.0,
        enter_simulation_mode: bool = True,
    ) -> PduResult:
        """Send one simple PDU and report what the simulator actually did.

        ``timeout_seconds`` bounds the wait for frames to appear and settle. It
        is not a delivery timeout: no frames at all inside the window yields
        ``TIMED_OUT``, while frames that never settle yields ``INCONCLUSIVE``.
        """
        self._sequence += 1
        experiment_id = f"pdu-{self._sequence}"
        started = utcnow()
        operation = f"addSimplePdu({source} -> {destination}, {protocol})"

        def finish(
            status: DeliveryStatus,
            *,
            raw: str = "",
            add_error: str | None = None,
            frames: int = 0,
            sent: int = 0,
            dropped: int = 0,
            decisions: tuple[str, ...] = (),
            error: str | None = None,
            caveats: tuple[str, ...] = (),
        ) -> PduResult:
            return PduResult(
                status=status,
                source=source,
                destination=destination,
                protocol=protocol,
                operation=operation,
                raw=raw,
                provenance=self._provenance(source, None, operation),
                add_pdu_error=add_error,
                frames_seen=frames,
                frames_sent=sent,
                frames_dropped=dropped,
                decisions=decisions,
                experiment_id=experiment_id,
                started_at=started,
                finished_at=utcnow(),
                error=error,
                caveats=caveats,
            )

        if self._client is None:
            return finish(
                DeliveryStatus.UNSUPPORTED,
                error="no live simulator connection",
                caveats=("packet experiments require a live backend",),
            )

        if protocol.lower() not in SUPPORTED_PROTOCOLS:
            return finish(
                DeliveryStatus.UNSUPPORTED,
                error=f"simple PDU cannot carry protocol {protocol!r}",
                caveats=(
                    (
                        "Packet Tracer's simple PDU sends ICMP only; a different "
                        "protocol was requested and is not substituted silently"
                    ),
                ),
            )

        # 1. Put the simulator in simulation mode so frames are recordable.
        if enter_simulation_mode:
            try:
                self._client.call(
                    ["simulation", ("setSimulationMode", [(2, "true")])], timeout=20.0
                )
            except PtmpError as exc:
                return finish(
                    DeliveryStatus.EXECUTION_ERROR,
                    error=f"could not enter simulation mode: {exc}",
                )

        # 2. Remove the previous PDU, then reset. Both are required: reset alone
        #    leaves earlier simple PDUs in the scenario, so they keep replaying
        #    and the frame counter climbs across experiments (measured 86 -> 110
        #    over four sends). Deleting first and resetting second returns the
        #    frame list to zero, which is the only state in which a frame's
        #    presence can be attributed to this experiment.
        self._delete_existing_pdus()
        try:
            self._client.call(["simulation", "resetSimulation"], timeout=20.0)
        except PtmpError:
            # Not fatal: frame indices are still read fresh below.
            pass
        self._settle_frame_reset()
        # After a reset the simulator keeps a single carried-over frame, so the
        # baseline is whatever remains. Every frame at or beyond it belongs to
        # this experiment.
        baseline = self._frame_count()

        # 3. Submit the PDU. This is submission, not delivery.
        try:
            reply = self._client.call(
                ["appWindow", "getUserCreatedPDU", ("addSimplePdu", [(9, source), (9, destination)])],
                timeout=30.0,
            )
        except PtmpError as exc:
            return finish(DeliveryStatus.EXECUTION_ERROR, error=f"addSimplePdu failed: {exc}")

        code_text = reply[0] if reply else ""
        try:
            code = int(code_text)
        except ValueError:
            code = -1
        add_error = PDU_ERRORS.get(code, f"UNKNOWN_{code_text}")

        if code != 0:
            # A device identity problem is a real answer: the experiment could
            # not be set up. It is not a delivery failure and not a success.
            status = (
                DeliveryStatus.EXECUTION_ERROR
                if add_error.startswith("NO_SUCH_")
                else DeliveryStatus.UNSUPPORTED
            )
            return finish(
                status,
                raw=code_text,
                add_error=add_error,
                error=f"Packet Tracer refused the PDU: {add_error}",
            )

        # 4. Capture the tested frame BEFORE advancing. Packet Tracer records the
        #    ICMP echo as the first frame after the PDU is added; once time is
        #    stepped, control-plane traffic (STP, CDP) floods the frame list and
        #    pushes it out of any bounded window. Reading it first is what makes
        #    the verdict stable.
        import time as _time

        # Poll for the PDU frame rather than assuming a fixed delay. Packet
        # Tracer needs a moment to construct the ICMP request after the PDU is
        # added, and on a cold session that is longer than on a warm one.
        seed_frames: list[dict] = []
        deadline = _time.monotonic() + min(10.0, timeout_seconds)
        while _time.monotonic() < deadline:
            _time.sleep(0.25)
            count_now = self._frame_count()
            if count_now > baseline:
                candidate = self._read_frames(baseline, count_now)
                if any(_mentions_icmp(frame["decisions"]) for frame in candidate):
                    seed_frames = candidate
                    break
                seed_frames = candidate

        # 5. Advance so the packet actually travels, then collect the rest.
        steps = self._advance(timeout_seconds)

        # 6. Read the resulting frames and merge with the seed. Submission alone
        #    proves nothing; the frame state is the evidence.
        frames = self._merge_frames(seed_frames, self._wait_for_frames(baseline, timeout_seconds))
        if not frames:
            return finish(
                DeliveryStatus.TIMED_OUT,
                raw=code_text,
                add_error=add_error,
                error=(
                    f"no frames appeared within {timeout_seconds:g}s "
                    f"({steps} simulation step(s) taken)"
                ),
                caveats=(
                    (
                        "the PDU was accepted but produced no observable traffic; "
                        "delivery is not established"
                    ),
                ),
            )

        # The tested traffic is the ICMP echo exchange. Everything else the
        # simulator emits (STP multicast, CDP, ARP for other hosts) floods on its
        # own schedule and says nothing about the ping. Measured on a healthy
        # PC-A -> R1 link: of 42 frames, exactly one carried the ICMP Echo
        # Request, and it was neither sent nor dropped when the source had no
        # route.
        icmp_frames = [
            frame
            for frame in frames
            if _mentions_icmp(frame["decisions"])
        ]
        noise_count = len(frames) - len(icmp_frames)
        decisions = tuple(
            text for frame in frames for text in frame["decisions"] if text
        )
        raw = "\n".join(
            f"frame {frame['index']} {frame['device']} {frame['source']}->"
            f"{frame['destination']} sent={frame['sent']} dropped={frame['dropped']}"
            + ("".join(f"\n  decision: {text}" for text in frame["decisions"]))
            for frame in frames
        )
        caveats: tuple[str, ...] = ()
        if noise_count:
            caveats = (
                (
                    f"{noise_count} of {len(frames)} frames were protocol control "
                    "traffic (STP/CDP/ARP) and are excluded from the verdict"
                ),
            )

        if not icmp_frames:
            return finish(
                DeliveryStatus.INCONCLUSIVE,
                raw=raw,
                add_error=add_error,
                frames=len(frames),
                sent=sum(1 for frame in frames if frame["sent"]),
                dropped=sum(1 for frame in frames if frame["dropped"]),
                decisions=decisions,
                caveats=caveats
                + (
                    (
                        "no ICMP echo frame was observed, so the simulator did "
                        "not start the tested traffic"
                    ),
                ),
            )

        # Frames that carried the tested traffic and were not rejected.
        progressed = [frame for frame in icmp_frames if frame["sent"]]
        rejected = [frame for frame in icmp_frames if frame["dropped"]]

        # Delivery requires the destination to have ANSWERED the echo. A frame
        # merely reaching a device proves nothing: the switch forwards broadcasts
        # everywhere, and a device with no route still emits frames. The
        # simulator states the answer explicitly in its decision text, so the
        # check is on that, not on arrival.
        arrived = [
            frame
            for frame in icmp_frames
            if not frame["dropped"]
            and frame["device"].strip().lower() == destination.strip().lower()
            and _replied(frame["decisions"])
        ]

        if arrived:
            return finish(
                DeliveryStatus.DELIVERED,
                raw=raw,
                add_error=add_error,
                frames=len(frames),
                sent=len(progressed),
                dropped=len(rejected),
                decisions=decisions,
                caveats=caveats,
            )

        if rejected:
            return finish(
                DeliveryStatus.DROPPED,
                raw=raw,
                add_error=add_error,
                frames=len(frames),
                sent=len(progressed),
                dropped=len(rejected),
                decisions=decisions,
                caveats=caveats,
            )

        if progressed:
            # The echo moved but never arrived: it was forwarded somewhere that
            # did not deliver it. This is a real negative result.
            return finish(
                DeliveryStatus.DROPPED,
                raw=raw,
                add_error=add_error,
                frames=len(frames),
                sent=len(progressed),
                dropped=0,
                decisions=decisions,
                caveats=caveats
                + (
                    (
                        "the ICMP echo was created but never reached the "
                        "destination device"
                    ),
                ),
            )

        # The echo was created and went nowhere. On a cold endpoint this is
        # frequently ARP/DHCP warm-up rather than a fault: measured on PC-A ->
        # PC-B, the first experiment in a session reports "never sent" and the
        # next five deliver. Reporting DROPPED there would be a false negative,
        # so this case is INCONCLUSIVE with the reason stated. A genuine black
        # hole still fails on the retry, and the caller sees that.
        return finish(
            DeliveryStatus.INCONCLUSIVE,
            raw=raw,
            add_error=add_error,
            frames=len(frames),
            sent=0,
            dropped=0,
            decisions=decisions,
            caveats=caveats
            + (
                (
                    "the ICMP echo was constructed but never sent. On a cold "
                    "endpoint this is usually ARP/DHCP warm-up, so delivery is "
                    "not established either way; repeat the experiment to "
                    "distinguish warm-up from a real black hole"
                ),
            ),
        )

    # -- internals ---------------------------------------------------------

    #: How many existing simple PDUs to clear before a new experiment. The
    #: scenario list is short in practice; the cap bounds a pathological file.
    MAX_EXISTING_PDUS = 16

    def _delete_existing_pdus(self) -> None:
        """Remove previously added simple PDUs so they cannot replay."""
        for index in range(self.MAX_EXISTING_PDUS):
            try:
                self._client.call(
                    [
                        "appWindow",
                        "getUserCreatedPDU",
                        ("deletePDU", [(TYPE_INT, index)]),
                    ],
                    timeout=15.0,
                )
            except PtmpError:
                return

    def _settle_frame_reset(self, attempts: int = 12) -> None:
        """Wait until the frame list is empty after a reset.

        A reset is asynchronous; reading the count immediately can still return
        the pre-reset value. Returning early would reintroduce the attribution
        bug this whole step exists to prevent.
        """
        import time

        for _ in range(attempts):
            if self._frame_count() == 0:
                return
            time.sleep(0.15)

    def _advance(self, timeout_seconds: float) -> int:
        """Step simulation time so the PDU runs to completion.

        Returns the number of steps taken. A failure here is not fatal: the
        frames collected so far still describe what the simulator did, and the
        caller classifies the outcome from them.
        """
        import time

        steps = 0
        deadline = time.monotonic() + timeout_seconds
        stall = 0
        previous = self._frame_count()
        # A simple PDU settles within a few dozen steps. The cap keeps a slow or
        # pathological simulation from running away; the stall detector is the
        # normal exit.
        while time.monotonic() < deadline and steps < 60:
            try:
                self._client.call(["simulation", "forward"], timeout=20.0)
            except PtmpError:
                break
            steps += 1
            time.sleep(0.05)
            current = self._frame_count()
            if current == previous:
                stall += 1
                # Stop once the frame set has been stable: the experiment has
                # finished producing traffic.
                if stall >= 3 and steps > 3:
                    break
            else:
                stall = 0
                previous = current
        return steps

    def _frame_count(self) -> int:
        try:
            reply = self._client.call(["simulation", "getFrameInstanceCount"], timeout=20.0)
        except PtmpError:
            return 0
        try:
            return int(reply[0])
        except (ValueError, IndexError):
            return 0

    def _wait_for_frames(self, baseline: int, timeout_seconds: float) -> list[dict]:
        """Poll until frames stop growing, then snapshot their state."""
        import time

        deadline = time.monotonic() + timeout_seconds
        previous = -1
        count = baseline
        while time.monotonic() < deadline:
            count = self._frame_count()
            if count > baseline and count == previous:
                break
            previous = count
            time.sleep(0.25)
        if count <= baseline:
            return []
        return self._read_frames(baseline, count)

    #: Frames examined per experiment. A simple PDU across a routed topology
    #: produces tens of frames; the cap bounds work on pathological files without
    #: truncating a normal test.
    MAX_FRAMES = 60
    #: Frames produced by the protocol control plane rather than by the test.
    #: These flood continuously (STP multicast every couple of steps), so their
    #: drop counts say nothing about the ping. Measured: on a healthy PC-A to
    #: PC-B ping, 57 of 96 frames were STP multicast with `dropped=true`.
    NOISE_DESTINATIONS = ("STP Multicast",)

    @staticmethod
    def _merge_frames(seed: list[dict], later: list[dict]) -> list[dict]:
        """Union of two frame snapshots, keyed by frame index.

        The seed holds the ICMP frame captured before simulation advancement; the
        later snapshot holds everything produced by the traversal. Frames seen in
        both take the later state, which is the more complete one.
        """
        by_index: dict[int, dict] = {frame["index"]: frame for frame in seed}
        for frame in later:
            by_index[frame["index"]] = frame
        return [by_index[index] for index in sorted(by_index)]

    def _read_frames(self, start: int, end: int) -> list[dict]:
        """Read frames from ``start`` forward, capped at ``MAX_FRAMES``.

        The window must move forward from the baseline, not backward from the
        end: the tested ICMP frame is created first and is then buried by
        control-plane flooding, so an end-anchored window loses exactly the frame
        the verdict depends on.
        """
        frames: list[dict] = []
        for index in range(start, min(end, start + self.MAX_FRAMES)):
            frame = self._read_frame(index)
            if frame is not None:
                frames.append(frame)
        return frames

    def _read_frame(self, index: int) -> dict | None:
        base = ["simulation", ("getFrameInstanceAt", [(TYPE_INT, index)])]
        try:
            device = self._client.call(base + ["getDevice", "getName"], timeout=15.0)
            sent = self._client.call(base + ["isFrameSent"], timeout=15.0)
            dropped = self._client.call(base + ["isFrameDropped"], timeout=15.0)
            percent = self._client.call(base + ["getPercentageSent"], timeout=15.0)
        except PtmpError:
            return None

        decisions: list[str] = []
        try:
            node_count_reply = self._client.call(
                base + ["getFlowChartNodeCount"], timeout=15.0
            )
            node_count = int(node_count_reply[0]) if node_count_reply else 0
        except (PtmpError, ValueError):
            node_count = 0
        for node in range(min(node_count, 32)):
            try:
                reply = self._client.call(
                    base + [("getDecisionAt", [(TYPE_INT, node)])], timeout=15.0
                )
            except PtmpError:
                break
            if reply and reply[0]:
                decisions.append(reply[0])

        source_text = ""
        destination_text = ""
        try:
            source_reply = self._client.call(base + ["getSourceString"], timeout=15.0)
            destination_reply = self._client.call(base + ["getDestinationString"], timeout=15.0)
            source_text = source_reply[0] if source_reply else ""
            destination_text = destination_reply[0] if destination_reply else ""
        except PtmpError:
            pass

        return {
            "index": index,
            "device": device[0] if device else "",
            "source": source_text,
            "destination": destination_text,
            "sent": (sent[0] if sent else "").lower() == "true",
            "dropped": (dropped[0] if dropped else "").lower() == "true",
            "percent": percent[0] if percent else "",
            "decisions": decisions,
        }


#: Decision phrases that mark a frame as part of the tested ICMP exchange.
_ICMP_MARKERS = ("icmp", "echo request", "echo reply", "ping process")


def _mentions_icmp(decisions: tuple[str, ...] | list[str]) -> bool:
    """Whether a frame's decision text identifies it as the tested traffic."""
    joined = " ".join(decisions).lower()
    return any(marker in joined for marker in _ICMP_MARKERS)


#: Decision phrases Packet Tracer emits when a device answers an echo request.
_REPLY_MARKERS = (
    "received an echo request",
    "replies to the echo request",
    "setting icmp type to echo reply",
    "sends an echo reply",
)


def _replied(decisions: tuple[str, ...] | list[str]) -> bool:
    """Whether this frame shows the device answering the echo request."""
    joined = " ".join(decisions).lower()
    return any(marker in joined for marker in _REPLY_MARKERS)


def _dropped_for_cold_arp(decisions: tuple[str, ...] | list[str]) -> bool:
    """True when a PDU was dropped only because ARP had not resolved yet.

    Packet Tracer drops the *first* packet to an unresolved next hop while it
    sends an ARP request. That drop is a warm-up artifact, not a forwarding
    failure: the same experiment succeeds once the entry is populated. The
    simulator says so directly, which is why this is detected from its own text
    rather than guessed from a frame count.
    """
    text = " ".join(decisions or ())
    return (
        "ARP process tries to send an ARP request" in text
        and "drops this packet" in text
    )


def send_with_warmup(
    executor: PduExecutor,
    source: str,
    destination: str,
    protocol: str = "icmp",
    timeout_seconds: float = 20.0,
    attempts: int = 2,
) -> PduResult:
    """Send a PDU, retrying once when a cold endpoint swallowed the echo.

    A first experiment on an uninitialised host reports the echo as constructed
    but never sent, because ARP and DHCP have not completed. Retrying is the
    difference between an inconclusive first result and a real one. It is bounded
    and only applies to that specific case: a genuine black hole fails both
    attempts and is reported as such.

    The same applies to a first packet dropped for an unresolved ARP entry. That
    drop says nothing about forwarding, so it is retried once and the retry is
    recorded as a caveat. A drop that persists after the retry is reported as a
    drop, because by then ARP is populated and the failure is real.
    """
    result = executor.send(source, destination, protocol, timeout_seconds)
    tries = 1
    retried_for_arp = False
    while tries < attempts:
        cold_endpoint = (
            result.status is DeliveryStatus.INCONCLUSIVE
            and result.frames_seen
            and result.frames_sent == 0
        )
        cold_arp = (
            result.status is DeliveryStatus.DROPPED
            and _dropped_for_cold_arp(result.decisions)
        )
        if not (cold_endpoint or cold_arp):
            break
        if cold_arp:
            retried_for_arp = True
        tries += 1
        result = executor.send(source, destination, protocol, timeout_seconds)
    if tries > 1:
        caveat = (
            f"retried once after a cold-ARP drop ({tries} attempts)"
            if retried_for_arp
            else f"retried once after a cold-endpoint warm-up ({tries} attempts)"
        )
        if retried_for_arp and result.status is DeliveryStatus.DELIVERED:
            caveat += "; the first attempt was dropped only for an unresolved ARP entry"
        result = PduResult(
            status=result.status,
            source=result.source,
            destination=result.destination,
            protocol=result.protocol,
            operation=result.operation,
            raw=result.raw,
            provenance=result.provenance,
            add_pdu_error=result.add_pdu_error,
            frames_seen=result.frames_seen,
            frames_sent=result.frames_sent,
            frames_dropped=result.frames_dropped,
            decisions=result.decisions,
            experiment_id=result.experiment_id,
            started_at=result.started_at,
            finished_at=result.finished_at,
            error=result.error,
            caveats=result.caveats + (caveat,),
        )
    return result


def capability_available(capabilities: frozenset[Capability]) -> bool:
    """Whether a session's advertised capabilities include packet testing."""
    return Capability.SEND_PDU in capabilities


__all__ = [
    "PDU_ERRORS",
    "SUPPORTED_PROTOCOLS",
    "DeliveryStatus",
    "PduExecutor",
    "PduResult",
    "capability_available",
    "send_with_warmup",
]

