"""Simulator sessions: one disposable working copy, one backend, hard budgets.

A session owns the entire lifetime of one experiment. It is the only object
allowed to touch a working copy, and it guarantees:

* the source file's hash is checked on close, so "the original was untouched"
  is evidence rather than a promise;
* every operation counts against a budget, and the budget is enforced before
  the operation runs rather than after;
* an unsupported capability raises instead of returning something plausible;
* closing is idempotent and reports the real cleanup outcome.

Nothing here decides *what* to investigate. That belongs to the investigation
layer; this layer only answers "run this, honestly, and tell me what happened".
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Self

from .backends import Backend, live_allowed, select_backend
from .contracts import (
    BackendKind,
    Budget,
    BudgetExceeded,
    Capability,
    CapabilityUnsupported,
    DeviceHandle,
    OperationResult,
    SessionClosed,
    SessionInfo,
    SessionState,
    utcnow,
)
from .isolation import IsolationError, Workspace, sha256_file


class Session:
    """One isolated simulator session over one lab file."""

    def __init__(
        self,
        session_id: str,
        source_path: Path,
        source_sha256: str,
        working_copy: Path,
        working_copy_sha256: str,
        directory: Path,
        backend: Backend,
        workspace: Workspace,
        budget: Budget,
        notes: tuple[str, ...] = (),
        on_close: Callable[[str], None] | None = None,
    ) -> None:
        self.session_id = session_id
        self.source_path = source_path
        self.source_sha256 = source_sha256
        self.working_copy = working_copy
        self.working_copy_sha256 = working_copy_sha256
        self.directory = directory
        self.backend = backend
        self.workspace = workspace
        self.budget = budget
        self.notes = notes
        self.state = SessionState.READY
        self.started_at = utcnow()
        self._started_monotonic = time.monotonic()
        self._operations = 0
        self._cleanup_status = "PENDING"
        self._closed = False
        self._on_close = on_close

    # -- introspection -----------------------------------------------------

    def capabilities(self) -> frozenset[Capability]:
        return self.backend.capabilities()

    def supports(self, capability: Capability) -> bool:
        return capability in self.capabilities()

    def info(self) -> SessionInfo:
        return SessionInfo(
            session_id=self.session_id,
            state=self.state,
            backend=self.backend.kind,
            simulator_version=self.backend.version,
            source_sha256=self.source_sha256,
            working_copy_sha256=self.working_copy_sha256,
            working_copy_path=str(self.working_copy),
            source_path=str(self.source_path),
            started_at=self.started_at,
            operations=self._operations,
            budget=self.budget,
            cleanup_status=self._cleanup_status,
            notes=self.notes,
        )

    @property
    def is_live(self) -> bool:
        return self.backend.kind is BackendKind.SIMULATOR_LIVE

    # -- operations --------------------------------------------------------

    def resolve_device(self, name: str) -> DeviceHandle:
        self._check_usable()
        record = self.backend.resolve(name)
        alternatives = tuple(
            d["name"]
            for d in self.backend.devices()
            if d["name"] != record.get("name")
            and name.strip().lower() in d["name"].lower()
        )
        return DeviceHandle(
            name=str(record["name"]),
            device_type=str(record.get("device_type", "")),
            matched_on=str(record.get("matched_on", "")),
            alternatives=alternatives,
        )

    def run_cli(
        self, device: str, command: str, timeout: float | None = None
    ) -> OperationResult:
        self._check_usable()
        self._check_capability(Capability.RUN_CLI)
        self._consume_operation()
        return self.backend.run_cli(
            device, command, timeout if timeout is not None else self.budget.command_timeout_s
        )

    def ping(
        self, source: str, destination: str, timeout: float | None = None
    ) -> OperationResult:
        self._check_usable()
        self._check_capability(Capability.PING)
        # Resolving first means an unknown device fails before any packet is sent.
        self.backend.resolve(source)
        self._consume_operation()
        return self.backend.ping(
            source, destination, timeout if timeout is not None else self.budget.command_timeout_s
        )

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> str:
        """Close the session, verify the source, clean up. Idempotent."""
        if self._closed:
            return self._cleanup_status
        self._closed = True
        self.state = SessionState.CLOSING

        backend_status = self.backend.close()
        try:
            current = sha256_file(self.source_path)
        except OSError as exc:
            self.notes = (*self.notes, f"could not re-hash source: {exc}")
            current = self.source_sha256
        source_intact = current == self.source_sha256
        if not source_intact:
            self.notes = (
                *self.notes,
                "SOURCE CHANGED during the session; the working-copy promise was violated",
            )

        directory_status = self.workspace.cleanup(self.directory)
        self._cleanup_status = (
            f"{directory_status}/backend={backend_status}/"
            f"source={'INTACT' if source_intact else 'MODIFIED'}"
        )
        self.state = SessionState.CLOSED
        if self._on_close is not None:
            self._on_close(self.session_id)
        return self._cleanup_status

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- guards ------------------------------------------------------------

    def _check_usable(self) -> None:
        if self._closed:
            raise SessionClosed(f"session {self.session_id} is closed")
        elapsed = time.monotonic() - self._started_monotonic
        if elapsed > self.budget.session_lifetime_s:
            self.state = SessionState.TIMEOUT
            raise BudgetExceeded(
                f"session {self.session_id} exceeded its {self.budget.session_lifetime_s}s lifetime"
            )

    def _check_capability(self, capability: Capability) -> None:
        if not self.supports(capability):
            raise CapabilityUnsupported(
                f"{self.backend.kind.value} backend cannot perform {capability.value}"
            )

    def _consume_operation(self) -> None:
        if self._operations >= self.budget.max_operations:
            raise BudgetExceeded(
                f"session {self.session_id} reached its {self.budget.max_operations} operation limit"
            )
        self._operations += 1


class SimulatorRuntime:
    """Creates sessions. One runtime may hold at most ``max_sessions``."""

    def __init__(
        self,
        workspace_root: str | Path | None = None,
        budget: Budget | None = None,
        max_sessions: int = 1,
        prefer_live: bool | None = None,
        allow_scripted: bool = True,
    ) -> None:
        self.workspace = Workspace(workspace_root)
        self.budget = budget or Budget()
        self.max_sessions = max_sessions
        # Launching Packet Tracer is opt-in. The default is "live only when the
        # operator has explicitly allowed it", because starting a GUI app on
        # someone's desktop mid-task is disruptive and is not something a library
        # should do implicitly.
        self.prefer_live = live_allowed() if prefer_live is None else prefer_live
        self.allow_scripted = allow_scripted
        self._sessions: dict[str, Session] = {}

    def is_available(self) -> bool:
        """Whether LIVE simulation is usable. Never starts the simulator.

        The scripted backend deliberately does not count here: it produces no
        simulator evidence, so treating it as "available" would let the
        escalation policy claim an operational capability the process does not
        have.
        """
        from .backends import credentials_from_env, find_packet_tracer, live_allowed

        if not self.prefer_live or not live_allowed():
            return False
        return find_packet_tracer() is not None and credentials_from_env() is not None

    def scripted_available(self) -> bool:
        """Whether a deterministic scripted backend can serve sessions."""
        return self.allow_scripted

    def availability_reason(self) -> str:
        from .backends import credentials_from_env, find_packet_tracer

        if not live_allowed():
            return (
                "live simulator is disabled. Set TRIDENT_ALLOW_LIVE_SIMULATOR=1 "
                "to allow Packet Tracer to be started."
            )
        bundle = find_packet_tracer()
        if bundle is None:
            return "Packet Tracer is not installed in a searchable location"
        if credentials_from_env() is None:
            return (
                "Packet Tracer is installed but no registered ExApp is configured; "
                "set TRIDENT_PT_APP_ID and TRIDENT_PT_SECRET after registering the app"
            )
        return f"Packet Tracer available at {bundle}"

    def create_session(
        self,
        lab_path: str | Path,
        *,
        disposable: bool = True,
        scripted_scenario: str | Path | None = None,
        session_id: str | None = None,
    ) -> Session:
        if len(self._sessions) >= self.max_sessions:
            raise BudgetExceeded(
                f"this runtime already holds {self.max_sessions} active session(s); "
                "close one before creating another"
            )
        if not disposable:
            raise IsolationError(
                "sessions are always disposable; pass disposable=True. "
                "Mutating a source lab is never supported."
            )
        source = Path(lab_path).expanduser()
        if not source.is_file():
            raise IsolationError(f"lab not found: {source}")

        session_id = session_id or uuid.uuid4().hex
        directory = self.workspace.new_session_dir(source.stem)
        working_copy, copy_sha = self.workspace.stage_copy(source, directory)
        source_sha = sha256_file(source)

        notes: list[str] = []
        try:
            backend = select_backend(
                working_copy=working_copy,
                source_sha256=source_sha,
                session_id=session_id,
                workspace=directory,
                prefer_live=self.prefer_live,
                scripted_scenario=Path(scripted_scenario) if scripted_scenario else None,
                allow_scripted=self.allow_scripted,
            )
        except Exception:
            self.workspace.cleanup(directory)
            raise

        if backend.kind is BackendKind.SCRIPTED:
            notes.append(
                "SCRIPTED backend: observations are not simulator evidence and must not "
                "be reported as live results"
            )
        session = Session(
            session_id=session_id,
            source_path=source,
            source_sha256=source_sha,
            working_copy=working_copy,
            working_copy_sha256=copy_sha,
            directory=directory,
            backend=backend,
            workspace=self.workspace,
            budget=self.budget,
            notes=tuple(notes),
            on_close=self._forget,
        )
        self._sessions[session_id] = session
        return session

    def _forget(self, session_id: str) -> None:
        """Called by a session when it closes, so the slot is released."""
        self._sessions.pop(session_id, None)

    def close_session(self, session_id: str) -> str:
        session = self._sessions.pop(session_id, None)
        if session is None:
            return "UNKNOWN_SESSION"
        return session.close()

    def close_all(self) -> dict[str, str]:
        return {sid: self.close_session(sid) for sid in list(self._sessions)}

    @property
    def active_sessions(self) -> tuple[str, ...]:
        return tuple(self._sessions)
