"""Simulator runtime: create isolated sessions over disposable lab copies.

Phase 3.2. The public surface is intentionally three objects:

* :class:`SimulatorRuntime` — owns the workspace and the session limit.
* :class:`Session` — one lab copy, one backend, hard budgets.
* :class:`OperationResult` — what an operation actually established, with
  provenance attached.

Read :mod:`trident.simulator.contracts` for the honesty rules. The short
version: a backend that cannot execute says so, a scripted result is never
labelled live, and the source file's hash is checked when a session closes.
"""

from .contracts import (
    BackendKind,
    BackendUnavailable,
    Budget,
    BudgetExceeded,
    Capability,
    CapabilityUnsupported,
    DeviceAmbiguous,
    DeviceHandle,
    DeviceNotFound,
    ObservationKind,
    OperationResult,
    Provenance,
    SessionClosed,
    SessionInfo,
    SessionState,
    utcnow,
)
from .isolation import IsolationError, Workspace, sha256_file
from .sessions import Session, SimulatorRuntime

__all__ = [
    "BackendKind",
    "BackendUnavailable",
    "Budget",
    "BudgetExceeded",
    "Capability",
    "CapabilityUnsupported",
    "DeviceAmbiguous",
    "DeviceHandle",
    "DeviceNotFound",
    "IsolationError",
    "ObservationKind",
    "OperationResult",
    "Provenance",
    "Session",
    "SessionClosed",
    "SessionInfo",
    "SessionState",
    "SimulatorRuntime",
    "Workspace",
    "sha256_file",
    "utcnow",
]
