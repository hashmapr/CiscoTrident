"""Typed contracts for the TRIDENT simulator runtime.

Everything a caller may rely on is declared here. The point of the indirection
is that a backend swap must not change a single type the investigation engine
sees: a scripted backend and a real Packet Tracer session produce the same
:class:`OperationResult`, and every result carries enough provenance that a
reader can tell which one it came from.

Honesty rules encoded structurally:

* :class:`BackendKind` distinguishes ``SIMULATOR_LIVE`` from ``SCRIPTED``. A
  scripted result can never be mistaken for a real observation, and the product
  surface refuses to describe scripted results as simulator evidence.
* :class:`OperationResult` has no default ``success`` and no default ``raw``.
  A caller must supply the raw simulator text, so "parsed but raw discarded"
  is not expressible.
* :class:`ObservationKind` names the *behaviour actually tested*. A successful
  ping means "connectivity observed for this path"; it never becomes a general
  claim about the network.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import UTC, datetime


def utcnow() -> str:
    return datetime.now(UTC).isoformat()


class BackendKind(enum.StrEnum):
    """Which kind of backend produced an observation."""

    #: A real Cisco Packet Tracer process answered over PTMP.
    SIMULATOR_LIVE = "SIMULATOR_LIVE"
    #: A deterministic in-process peer. Used when Packet Tracer cannot be
    #: driven, so the runtime can be tested without claiming real execution.
    SCRIPTED = "SCRIPTED"
    #: No backend could be used. Every operation fails with this.
    UNAVAILABLE = "UNAVAILABLE"


class SessionState(enum.StrEnum):
    """Lifecycle state of one simulator session."""

    NEW = "NEW"
    INITIALIZING = "INITIALIZING"
    LOADING = "LOADING"
    READY = "READY"
    EXECUTING = "EXECUTING"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"


class Capability(enum.StrEnum):
    """A diagnostic capability a backend may or may not serve.

    Capabilities are discovered, never assumed: a backend that cannot run a
    command must say so rather than return a fabricated result.
    """

    RUN_CLI = "RUN_CLI"
    PING = "PING"
    TRACEROUTE = "TRACEROUTE"
    INTERFACE_STATUS = "INTERFACE_STATUS"
    ROUTING_TABLE = "ROUTING_TABLE"
    VLAN_TABLE = "VLAN_TABLE"
    MAC_TABLE = "MAC_TABLE"
    ACL_VIEW = "ACL_VIEW"
    #: Simple-PDU packet experiments: real traffic, real delivery evidence.
    SEND_PDU = "SEND_PDU"
    MUTATE_CONFIG = "MUTATE_CONFIG"


class ObservationKind(enum.StrEnum):
    """What a single observation actually establishes."""

    #: Raw CLI text from a device, parsed into structure.
    CLI_OUTPUT = "CLI_OUTPUT"
    #: Connectivity was tested and succeeded, for this path and these conditions.
    REACHABILITY_SUCCEEDED = "REACHABILITY_SUCCEEDED"
    #: Connectivity was tested and failed. On its own this does not name a cause.
    REACHABILITY_FAILED = "REACHABILITY_FAILED"
    #: A path was traced; the hops are what was seen, not a diagnosis.
    PATH_TRACED = "PATH_TRACED"
    #: A reachability test ran but produced no verdict. Distinct from failure:
    #: the simulator did not say the path was down, it said nothing at all.
    REACHABILITY_INCONCLUSIVE = "REACHABILITY_INCONCLUSIVE"


@dataclass(frozen=True)
class Provenance:
    """Where a piece of evidence came from. Attached to every result."""

    backend: BackendKind
    simulator_version: str
    session_id: str
    #: Hash of the file the session was created from. Never of a mutated copy.
    source_sha256: str
    #: Hash of the working copy actually loaded by the simulator.
    working_copy_sha256: str
    device: str | None
    interface: str | None
    operation: str
    executed_at: str
    parsed_by: str = ""
    caveats: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "backend": self.backend.value,
            "simulator_version": self.simulator_version,
            "session_id": self.session_id,
            "source_sha256": self.source_sha256,
            "working_copy_sha256": self.working_copy_sha256,
            "device": self.device,
            "interface": self.interface,
            "operation": self.operation,
            "executed_at": self.executed_at,
            "parsed_by": self.parsed_by,
            "caveats": list(self.caveats),
        }


@dataclass(frozen=True)
class OperationResult:
    """The outcome of one diagnostic operation.

    ``raw`` is the simulator's own text and is never discarded after parsing:
    a reviewer must be able to check the parse against the source.
    """

    ok: bool
    kind: ObservationKind
    operation: str
    device: str | None
    raw: str
    parsed: dict | list | None
    provenance: Provenance
    error: str | None = None
    #: True only when a backend genuinely executed this. False for anything
    #: the runtime produced without a live simulator.
    observed: bool = False

    @property
    def is_live(self) -> bool:
        return self.provenance.backend is BackendKind.SIMULATOR_LIVE and self.observed

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "kind": self.kind.value,
            "operation": self.operation,
            "device": self.device,
            "raw": self.raw,
            "parsed": self.parsed,
            "provenance": self.provenance.as_dict(),
            "error": self.error,
            "observed": self.observed,
            "live": self.is_live,
        }


@dataclass(frozen=True)
class DeviceHandle:
    """A resolved device identity plus the evidence used to resolve it."""

    name: str
    device_type: str
    matched_on: str
    #: Other candidates when the name was not unique. Empty when unambiguous.
    alternatives: tuple[str, ...] = ()


@dataclass(frozen=True)
class Budget:
    """Hard limits for one session. All are ceilings, not targets."""

    startup_timeout_s: float = 45.0
    load_timeout_s: float = 60.0
    command_timeout_s: float = 30.0
    session_lifetime_s: float = 900.0
    max_operations: int = 200


@dataclass(frozen=True)
class SessionInfo:
    session_id: str
    state: SessionState
    backend: BackendKind
    simulator_version: str
    source_sha256: str
    working_copy_sha256: str
    working_copy_path: str
    source_path: str
    started_at: str
    operations: int = 0
    budget: Budget = field(default_factory=Budget)
    cleanup_status: str = "PENDING"
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "state": self.state.value,
            "backend": self.backend.value,
            "simulator_version": self.simulator_version,
            "source_sha256": self.source_sha256,
            "working_copy_sha256": self.working_copy_sha256,
            "working_copy_path": self.working_copy_path,
            "source_path": self.source_path,
            "started_at": self.started_at,
            "operations": self.operations,
            "cleanup_status": self.cleanup_status,
            "notes": list(self.notes),
        }


class RuntimeError_(RuntimeError):
    """Base error for the simulator runtime."""


class BackendUnavailable(RuntimeError_):
    """No backend can serve this request."""


class DeviceNotFound(RuntimeError_):
    """The requested device does not exist in the loaded network."""


class DeviceAmbiguous(RuntimeError_):
    """The name matched more than one device."""


class CapabilityUnsupported(RuntimeError_):
    """The backend cannot perform the requested operation."""


class BudgetExceeded(RuntimeError_):
    """A hard limit was reached."""


class SessionClosed(RuntimeError_):
    """The session is no longer usable."""
