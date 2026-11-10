"""Backends: the two ways a session can obtain observations.

``LiveBackend`` drives a real Packet Tracer process over PTMP. It is the only
backend that can ever produce ``observed=True`` results.

``ScriptedBackend`` is a deterministic in-process peer. It exists so the whole
runtime — sessions, isolation, budgets, parsing, evidence wiring — can be tested
without Packet Tracer, and so that static analysis keeps working when the
simulator is unavailable. It is explicitly *not* a simulator: its results carry
``BackendKind.SCRIPTED`` and ``observed=False``, and the product surface refuses
to present them as simulator evidence.

Both implement :class:`Backend` so callers cannot tell them apart except through
the provenance they are handed.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import time
from pathlib import Path

from .contracts import (
    BackendKind,
    BackendUnavailable,
    Capability,
    CapabilityUnsupported,
    DeviceAmbiguous,
    DeviceNotFound,
    ObservationKind,
    OperationResult,
    Provenance,
    utcnow,
)
from .isolation import sha256_file
from .ptmp import (
    TYPE_BOOL,
    PtmpAuthRejected,
    PtmpClient,
    PtmpDisconnected,
    PtmpError,
)

#: Packet Tracer bundle locations checked, newest first. The environment
#: variable wins so an install on another volume is supported.
_ENV_HOME = "TRIDENT_PT_HOME"
_SEARCH_ROOTS = (
    Path("/Applications"),
    Path.home() / "Applications",
    Path("/opt"),
    Path("/Volumes"),
)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


#: Launching Packet Tracer is opt-in. Set to "1" to allow the runtime to start it.
ALLOW_LIVE_ENV = "TRIDENT_ALLOW_LIVE_SIMULATOR"
#: Prefer the background-agent copy (no Dock icon, no window) when one exists.
GHOST_ENV = "TRIDENT_USE_GHOST_APP"


def live_allowed() -> bool:
    """Whether this process may start Packet Tracer.

    Starting a GUI application on the operator's desktop is intrusive, so it is
    never implicit. ``TRIDENT_ALLOW_LIVE_SIMULATOR=1`` is the explicit consent.
    """
    return os.environ.get(ALLOW_LIVE_ENV, "").strip() not in {"", "0", "false", "no"}


def ghost_preferred() -> bool:
    """Whether the background-agent copy should be preferred over the stock app."""
    return os.environ.get(GHOST_ENV, "").strip() not in {"", "0", "false", "no"}


def find_ghost_app() -> Path | None:
    """Return a usable background-agent copy, if one has been built."""
    from .ghost import DEFAULT_GHOST_DIR, GHOST_NAME

    candidate = DEFAULT_GHOST_DIR / GHOST_NAME
    if (candidate / "Contents" / "MacOS" / "PacketTracer").is_file():
        try:
            import plistlib

            with open(candidate / "Contents" / "Info.plist", "rb") as handle:
                if plistlib.load(handle).get("LSUIElement") is True:
                    return candidate
        except (OSError, Exception):  # noqa: BLE001 - a bad plist means "not usable"
            return None
    return None


def _bundles_on_disk() -> list[Path]:
    """All Packet Tracer bundles discoverable in the usual places."""
    found: list[Path] = []
    for root in _SEARCH_ROOTS:
        if not root.is_dir():
            continue
        try:
            entries = list(root.iterdir())
        except OSError:
            continue
        for entry in entries:
            if not entry.is_dir():
                continue
            bundle = _bundle_at(entry)
            if bundle is not None:
                found.append(bundle)
                continue
            try:
                children = list(entry.iterdir())
            except OSError:
                continue
            for child in children:
                bundle = _bundle_at(child)
                if bundle is not None:
                    found.append(bundle)
    return found


def find_packet_tracer() -> Path | None:
    """Locate a Packet Tracer bundle, or return ``None``.

    A background-agent copy is returned first when ``TRIDENT_USE_GHOST_APP`` is
    set, because it is the only variant that cannot show a Dock icon or steal
    focus.
    """
    if ghost_preferred():
        ghost = find_ghost_app()
        if ghost is not None:
            return ghost
    override = os.environ.get(_ENV_HOME)
    if override:
        candidate = Path(override).expanduser()
        if (candidate / "Contents" / "MacOS" / "PacketTracer").is_file():
            return candidate
        if candidate.name.endswith(".app") and (candidate / "Contents" / "MacOS" / "PacketTracer").is_file():
            return candidate
        raise BackendUnavailable(
            f"{_ENV_HOME} is set to {candidate} but it is not a Packet Tracer bundle"
        )

    found: list[Path] = []
    for root in _SEARCH_ROOTS:
        if not root.is_dir():
            continue
        try:
            entries = list(root.iterdir())
        except OSError:
            continue
        for entry in entries:
            if not entry.is_dir():
                continue
            bundle = _bundle_at(entry)
            if bundle is not None:
                found.append(bundle)
                continue
            # One level deeper covers both "/Volumes/<disk>/<container>" and a
            # container folder that holds the bundle beside other files.
            try:
                children = list(entry.iterdir())
            except OSError:
                continue
            for child in children:
                bundle = _bundle_at(child)
                if bundle is not None:
                    found.append(bundle)
    if not found:
        return None
    return max(found)


def credentials_disagreement() -> str | None:
    """Explain an environment/file credential mismatch, or return ``None``.

    A stale exported secret is the single most likely cause of an auth
    rejection once a registration is installed, and the raw error gives no hint
    of it. This turns that into an actionable message.
    """
    env_id = os.environ.get("TRIDENT_PT_APP_ID", "").strip()
    env_secret = os.environ.get("TRIDENT_PT_SECRET", "").strip()
    if not (env_id and env_secret):
        return None
    if not CREDENTIALS_FILE.is_file():
        return None
    try:
        values: dict[str, str] = {}
        for line in CREDENTIALS_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        return None
    file_id = values.get("TRIDENT_PT_APP_ID", "")
    file_secret = values.get("TRIDENT_PT_SECRET", "")
    if not (file_id and file_secret):
        return None
    if env_id != file_id or env_secret != file_secret:
        return (
            "TRIDENT_PT_APP_ID/TRIDENT_PT_SECRET in this shell differ from the "
            f"registration installed at {CREDENTIALS_FILE}. The installed "
            "registration is used regardless, so this is only a warning: the "
            "exported values are stale. Run "
            "`unset TRIDENT_PT_APP_ID TRIDENT_PT_SECRET` to silence it, or set "
            "TRIDENT_PT_FORCE_ENV=1 to deliberately prefer the shell."
        )
    return None


def _auth_hint(exc: Exception) -> str:
    hint = credentials_disagreement()
    if hint:
        return f"{exc}. {hint}"
    return (
        f"{exc}. Check that the .pta in Contents/extensions matches "
        f"{CREDENTIALS_FILE}, or run `python -m trident.simulator.registration "
        f"--verify`."
    )


def _bundle_at(path: Path) -> Path | None:
    """Return a usable Packet Tracer bundle at or directly inside ``path``."""
    if not path.is_dir():
        return None
    executable = path / "Contents" / "MacOS" / "PacketTracer"
    if executable.is_file() and path.suffix == ".app":
        return path
    name = path.name.lower()
    if "packet tracer" not in name:
        return None
    if executable.is_file():
        return path
    # A container directory: look for the bundle inside it.
    try:
        for inner in path.iterdir():
            if inner.name.endswith(".app") and (
                inner / "Contents" / "MacOS" / "PacketTracer"
            ).is_file():
                return inner
    except OSError:
        return None
    return None


def simulator_version(bundle: Path) -> str:
    """Best-effort version string for a bundle.

    Bundle metadata is unreliable across Packet Tracer builds (this 9.0.1 install
    reports no ``CFBundleShortVersionString`` at all), so the version is taken
    from the installer directory name when present and only then from the plist.
    """
    import plistlib

    match = re.search(r"(\d+\.\d+\.\d+)", bundle.name)
    if match:
        return match.group(1)

    # The ghost copy is named PTGhost.app, so its own name carries no version.
    # Ask the source bundle it was cloned from rather than reporting "unknown",
    # which would put an unusable value into every observation's provenance.
    if bundle.name.startswith("PTGhost"):
        try:
            from .ghost import DEFAULT_GHOST_DIR, GHOST_NAME

            marker = DEFAULT_GHOST_DIR / GHOST_NAME / ".trident-source"
            if marker.is_file():
                source = Path(marker.read_text().strip())
                version = simulator_version(source)
                if version != "unknown":
                    return version
        except (OSError, ValueError):
            pass
        # Fall back to any installed Packet Tracer of the same minor line.
        for candidate in _bundles_on_disk():
            if candidate.name != bundle.name:
                version = simulator_version(candidate)
                if version != "unknown":
                    return version

    plist = bundle / "Contents" / "Info.plist"
    try:
        with open(plist, "rb") as handle:
            data = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException):
        return "unknown"
    for key in ("CFBundleShortVersionString", "CFBundleVersion"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unknown"


#: Where a registered credential pair is stored if the operator chooses to
#: persist it. Kept outside the repo and mode 0600.
CREDENTIALS_FILE = Path.home() / ".config" / "trident" / "credentials.env"


def _read_credentials_file() -> tuple[str, str] | None:
    if not CREDENTIALS_FILE.is_file():
        return None
    try:
        values: dict[str, str] = {}
        for line in CREDENTIALS_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        return None
    file_id = values.get("TRIDENT_PT_APP_ID", "")
    file_secret = values.get("TRIDENT_PT_SECRET", "")
    if file_id and file_secret:
        return file_id, file_secret
    return None


def credentials_from_env() -> tuple[str, str] | None:
    """Credential pair for the registered ExApp.

    The **installed registration wins**, because that is the pair Packet Tracer
    actually holds. The environment is used only to fill in values the file does
    not provide, or as the entire source when no file exists.

    This order was inverted in an earlier version, and it caused a working
    install to look broken: a shell that had exported a secret before the helper
    was re-run kept overriding the correct pair on disk, producing an
    authentication failure with a good registration sitting right next to it.

    Set ``TRIDENT_PT_FORCE_ENV=1`` to deliberately prefer the environment.
    """
    file_pair = _read_credentials_file()
    env_id = os.environ.get("TRIDENT_PT_APP_ID", "").strip()
    env_secret = os.environ.get("TRIDENT_PT_SECRET", "").strip()
    env_pair = (env_id, env_secret) if env_id and env_secret else None

    force_env = os.environ.get("TRIDENT_PT_FORCE_ENV", "").strip() not in {"", "0", "false"}
    if force_env and env_pair:
        return env_pair
    if file_pair:
        return file_pair
    return env_pair


class ProcessSupervisor:
    """Owns one Packet Tracer process.

    Responsibilities are deliberately narrow: start it invisibly, wait for the
    IPC listener, notice when it dies, and make shutdown reliable. Anything that
    could hang is bounded by a timeout.
    """

    def __init__(
        self, bundle: Path, ipc_port: int = 0, no_gui: bool = True, startup_timeout: float = 90.0
    ) -> None:
        self.startup_timeout = startup_timeout
        self.bundle = bundle
        self.ipc_port = ipc_port
        self.no_gui = no_gui
        self.process: subprocess.Popen | None = None
        self.log_path: Path | None = None
        self.started_at: float = 0.0
        self._spawned_here = False
        self._chosen_port = False

    def start(self, workspace: Path, timeout_s: float | None = None) -> int:
        """Start Packet Tracer with no window and wait for its listener.

        Returns the port the listener is on. Raises :class:`BackendUnavailable`
        when the process dies or the listener never appears.
        """
        executable = self.bundle / "Contents" / "MacOS" / "PacketTracer"
        if not executable.is_file():
            raise BackendUnavailable(f"no PacketTracer executable under {self.bundle}")

        log = workspace / "packet_tracer.log"
        self.log_path = log
        # Reserve a free port and pass it explicitly, so the listener we later
        # find is provably the one this process opened.
        if not self.ipc_port:
            self.ipc_port = self._choose_port()
            self._chosen_port = True

        args = [str(executable)]
        if self.no_gui:
            args.append("--no-gui")
        if self.ipc_port:
            args.extend(["--ipc-port", str(self.ipc_port)])

        with open(log, "wb") as handle:
            self.process = subprocess.Popen(
                args,
                stdout=handle,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        self._spawned_here = True
        self.started_at = time.monotonic()
        port = self._wait_for_listener(
            timeout_s if timeout_s is not None else self.startup_timeout
        )
        return port

    #: Ports Packet Tracer binds for IPC when none is requested.
    IPC_PORT_RANGE = range(39000, 39010)

    def _choose_port(self) -> int:
        """Pick a port that is currently free, so we never attach to a stranger.

        Accepting "any listener on 39000-39009" is how a foreign Packet Tracer
        instance gets used by mistake: the supervisor sees a live port, returns
        it, and the process *we* spawned silently fails to bind. The session then
        talks to the operator's own instance — wrong lab, wrong state, and a
        cleanup path that could touch something it does not own.

        Choosing a free port up front makes the listener unambiguous: if a
        connection succeeds on it, it is ours, because we reserved it.
        """
        import socket
        import time

        # Retry briefly: a Packet Tracer from the previous test can still be
        # releasing its port for a second or two after its process exits. Failing
        # immediately there produces an intermittent "no backend available" that
        # looks like a code fault and is not.
        deadline = time.monotonic() + 15.0
        while True:
            for port in self.IPC_PORT_RANGE:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    try:
                        probe.bind(("127.0.0.1", port))
                    except OSError:
                        continue
                return port
            if time.monotonic() >= deadline:
                break
            time.sleep(0.5)
        raise BackendUnavailable(
            "no free Packet Tracer IPC port in 39000-39009 after 15 s. Another "
            "Packet Tracer instance is holding them; quit it and retry."
        )

    def _wait_for_listener(self, timeout_s: float) -> int:
        assert self.process is not None
        deadline = time.monotonic() + timeout_s
        candidates = [self.ipc_port] if self.ipc_port else list(self.IPC_PORT_RANGE)
        import socket

        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise BackendUnavailable(
                    f"Packet Tracer exited with status {self.process.returncode} before "
                    f"opening its IPC listener; see {self.log_path}"
                )
            for port in candidates:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                        return port
                except OSError:
                    continue
            time.sleep(0.5)
        self.stop()
        raise BackendUnavailable(
            f"Packet Tracer did not accept connections within {timeout_s}s. "
            "If another Packet Tracer instance is already running, quit it first: "
            "a stale instance holds the IPC ports and the new one cannot bind."
        )

    def is_alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def stop(self, timeout_s: float = 10.0) -> str:
        """Terminate the process group. Returns a shutdown status string."""
        if self.process is None:
            return "NOT_STARTED"
        if self.process.poll() is not None:
            return "ALREADY_EXITED"
        try:
            os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
        except (OSError, ProcessLookupError):
            self.process.terminate()
        try:
            self.process.wait(timeout=timeout_s)
            return "TERMINATED"
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
            except (OSError, ProcessLookupError):
                self.process.kill()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                return "STILL_RUNNING"
            return "KILLED"


# ---------------------------------------------------------------------------
# Backend interface
# ---------------------------------------------------------------------------


class Backend:
    """What a session needs from an observation source."""

    kind: BackendKind = BackendKind.UNAVAILABLE
    version: str = "unknown"

    def capabilities(self) -> frozenset[Capability]:
        return frozenset()

    def devices(self) -> list[dict]:
        raise CapabilityUnsupported("this backend cannot enumerate devices")

    def resolve(self, name: str) -> dict:
        raise CapabilityUnsupported("this backend cannot resolve devices")

    def run_cli(self, device: str, command: str, timeout: float) -> OperationResult:
        raise CapabilityUnsupported("this backend cannot run CLI commands")

    def ping(self, source: str, destination: str, timeout: float) -> OperationResult:
        raise CapabilityUnsupported("this backend cannot test reachability")

    def close(self) -> str:
        return "NOOP"


# ---------------------------------------------------------------------------
# Live backend
# ---------------------------------------------------------------------------


#: Commands the runtime is willing to send autonomously. Anything else is
#: refused before it reaches the simulator.
READ_ONLY_PREFIXES = (
    "show ",
    "ping ",
    "traceroute ",
    "tracert ",
    "display ",
)

_MUTATING_TOKENS = (
    "configure",
    "conf t",
    "no ",
    "write",
    "copy run",
    "erase",
    "delete",
    "reload",
    "shutdown",
    "clear ",
    "debug ",
)


def is_read_only(command: str) -> bool:
    """True when ``command`` is a diagnostic that cannot change state."""
    text = " ".join(command.split()).lower()
    if not text:
        return False
    if any(token in text for token in _MUTATING_TOKENS):
        return False
    return text.startswith(READ_ONLY_PREFIXES)


class LiveBackend(Backend):
    """Drives a real Packet Tracer process over PTMP."""

    kind = BackendKind.SIMULATOR_LIVE

    def __init__(
        self,
        bundle: Path,
        working_copy: Path,
        source_sha256: str,
        session_id: str,
        credentials: tuple[str, str],
        workspace: Path,
        ipc_port: int = 0,
        autostart: bool = True,
    ) -> None:
        self.bundle = bundle
        self.working_copy = working_copy
        self.source_sha256 = source_sha256
        self.session_id = session_id
        self.credentials = credentials
        self.workspace = workspace
        self.version = simulator_version(bundle)
        self.supervisor: ProcessSupervisor | None = None
        self.client: PtmpClient | None = None
        self.ipc_port = ipc_port
        self.autostart = autostart
        self._device_index: dict[str, str] | None = None
        self._pdu_executor = None

    def capabilities(self) -> frozenset[Capability]:
        return frozenset(
            {
                Capability.RUN_CLI,
                Capability.PING,
                Capability.TRACEROUTE,
                Capability.INTERFACE_STATUS,
                Capability.ROUTING_TABLE,
                Capability.VLAN_TABLE,
                Capability.ACL_VIEW,
                Capability.SEND_PDU,
            }
        )

    @property
    def pdu_executor(self):
        """A PDU executor bound to this backend's connection, or ``None``."""
        from .pdu import PduExecutor

        if self.client is None:
            return None
        if getattr(self, "_pdu_executor", None) is None:
            self._pdu_executor = PduExecutor(
                self.client, self._provenance, self.session_id
            )
        return self._pdu_executor

    def connect(self, startup_timeout: float = 45.0) -> None:
        if self.autostart:
            self.supervisor = ProcessSupervisor(self.bundle, self.ipc_port)
            port = self.supervisor.start(self.workspace, timeout_s=startup_timeout)
            # Record the port actually used, so provenance and diagnostics can
            # report it. Without this the backend says 0 even though the session
            # is live on a real port.
            self.ipc_port = port
        else:
            port = self.ipc_port or 39000
        client = PtmpClient(*self.credentials, port=port)
        client.connect()
        self.client = client
        self._open_lab()

    def _open_lab(self) -> None:
        """Load the working copy into Packet Tracer.

        Without this the simulator is running but has no network: every device
        query answers for an empty topology. ``fileOpen`` returns a
        ``FileOpenReturnValue``; anything other than ``OK`` means the lab was not
        loaded, and continuing would silently produce empty evidence.
        """
        if self.client is None:
            raise BackendUnavailable("live backend is not connected")
        # Hide the window *before* opening the file. `fileOpen` activates the
        # application and shows its main window, which steals focus from
        # whatever the operator was doing; `setVisible(false)` beforehand keeps
        # the whole session at zero windows with no focus change, and the lab
        # still loads. This was measured, not assumed: hiding after the open is
        # too late, because focus has already moved.
        try:
            self.client.call(
                ["appWindow", ("setVisible", [(TYPE_BOOL, "false")])], timeout=15.0
            )
        except PtmpError as exc:
            # A backend that cannot hide would break the invisibility promise,
            # so treat it as unavailable rather than silently showing a window.
            raise BackendUnavailable(
                f"could not hide the Packet Tracer window before opening the lab: {exc}"
            ) from exc
        try:
            reply = self.client.call(
                ["appWindow", ("fileOpen", [(9, str(self.working_copy))])],
                timeout=60.0,
            )
        except Exception as exc:
            raise BackendUnavailable(f"could not open the lab in Packet Tracer: {exc}") from exc
        status = reply[0] if reply else ""
        # FileOpenReturnValue.OK serialises as "4" on 9.0.1; older builds use "0".
        if status not in {"0", "4", "OK", ""}:
            raise BackendUnavailable(
                f"Packet Tracer refused to open {self.working_copy.name}: status {status!r}"
            )
        self._loaded = True

    def _provenance(self, device: str | None, interface: str | None, operation: str) -> Provenance:
        return Provenance(
            backend=self.kind,
            simulator_version=self.version,
            session_id=self.session_id,
            source_sha256=self.source_sha256,
            working_copy_sha256=sha256_file(self.working_copy),
            device=device,
            interface=interface,
            operation=operation,
            executed_at=utcnow(),
            parsed_by="raw",
        )

    def devices(self) -> list[dict]:
        if self.client is None:
            raise BackendUnavailable("live backend is not connected")
        raw = self.client.call(["network", "getDeviceCount"])
        try:
            count = int(raw[0]) if raw else 0
        except ValueError:
            count = 0
        out = []
        for index in range(count):
            info = self.client.call(
                ["network", ("getDeviceAt", [(4, index)]), "getName"]
            )
            name = info[0] if info else f"device{index}"
            out.append({"index": index, "name": name})
        self._device_index = {entry["name"]: str(entry["index"]) for entry in out}
        return out

    def resolve(self, name: str) -> dict:
        devices = self.devices()
        lowered = name.strip().lower()
        exact = [d for d in devices if d["name"].lower() == lowered]
        if len(exact) == 1:
            return {**exact[0], "matched_on": "exact"}
        partial = [d for d in devices if lowered in d["name"].lower()]
        if len(partial) == 1:
            return {**partial[0], "matched_on": "substring"}
        if len(partial) > 1:
            raise DeviceAmbiguous(
                f"{name!r} matches {[d['name'] for d in partial]}"
            )
        raise DeviceNotFound(f"no device named {name!r} in this network")

    def run_cli(self, device: str, command: str, timeout: float) -> OperationResult:
        if self.client is None:
            raise BackendUnavailable("live backend is not connected")
        if not is_read_only(command):
            raise CapabilityUnsupported(
                f"{command!r} is not a read-only diagnostic; mutations are disabled"
            )
        try:
            text = self.client.enter_command(device, command)
        except PtmpDisconnected as exc:
            return OperationResult(
                ok=False,
                kind=ObservationKind.CLI_OUTPUT,
                operation=command,
                device=device,
                raw="",
                parsed=None,
                provenance=self._provenance(device, None, command),
                error=str(exc),
            )
        return OperationResult(
            ok=True,
            kind=ObservationKind.CLI_OUTPUT,
            operation=command,
            device=device,
            raw=text,
            parsed=None,
            provenance=self._provenance(device, None, command),
            observed=True,
        )

    def ping(self, source: str, destination: str, timeout: float) -> OperationResult:
        """Test reachability, and report only what the output actually shows.

        Packet Tracer's CLI ``ping`` is interactive: the first line is a prompt,
        the test completes only once simulation time advances, and the summary
        line is what carries the verdict. When that summary is absent the result
        is **inconclusive**, not a failure. Reporting a failure there would be a
        fabricated conclusion, which is exactly what this module exists to
        prevent.
        """
        result = self.run_cli(source, f"ping {destination}", timeout)
        if not result.ok:
            return result
        match = re.search(r"Success rate is (\d+) percent", result.raw)
        if match is None:
            return OperationResult(
                ok=True,
                kind=ObservationKind.REACHABILITY_INCONCLUSIVE,
                operation=f"ping {destination}",
                device=source,
                raw=result.raw,
                parsed={
                    "success_percent": None,
                    "destination": destination,
                    "reason": "no completion summary in the simulator output",
                },
                provenance=self._provenance(source, None, f"ping {destination}"),
                observed=True,
            )
        percent = int(match.group(1))
        return OperationResult(
            ok=True,
            kind=(
                ObservationKind.REACHABILITY_SUCCEEDED
                if percent == 100
                else ObservationKind.REACHABILITY_FAILED
            ),
            operation=f"ping {destination}",
            device=source,
            raw=result.raw,
            parsed={"success_percent": percent, "destination": destination},
            provenance=self._provenance(source, None, f"ping {destination}"),
            observed=True,
        )

    def close(self) -> str:
        status = "NOOP"
        if self.client is not None:
            self.client.close()
            self.client = None
            status = "CLIENT_CLOSED"
        if self.supervisor is not None:
            status = f"{status}+{self.supervisor.stop()}"
            self.supervisor = None
        return status


# ---------------------------------------------------------------------------
# Scripted backend
# ---------------------------------------------------------------------------


class ScriptedBackend(Backend):
    """A deterministic peer for tests and for degraded operation.

    It reads a JSON scenario describing devices and canned CLI text. Results are
    real :class:`OperationResult` objects with real provenance, but
    ``observed`` is ``False`` and the backend kind is ``SCRIPTED``, so nothing
    downstream can present them as simulator observations.
    """

    kind = BackendKind.SCRIPTED
    version = "scripted-1"

    def __init__(self, scenario: dict, working_copy: Path, source_sha256: str, session_id: str) -> None:
        self.scenario = scenario
        self.working_copy = working_copy
        self.source_sha256 = source_sha256
        self.session_id = session_id

    @classmethod
    def from_file(cls, path: Path, **kwargs: object) -> ScriptedBackend:
        data = json.loads(Path(path).read_text())
        return cls(data, **kwargs)  # type: ignore[arg-type]

    def capabilities(self) -> frozenset[Capability]:
        return frozenset(
            {
                Capability.RUN_CLI,
                Capability.PING,
                Capability.INTERFACE_STATUS,
                Capability.ROUTING_TABLE,
                Capability.VLAN_TABLE,
                Capability.ACL_VIEW,
            }
        )

    def devices(self) -> list[dict]:
        return [
            {"index": index, "name": entry["name"]}
            for index, entry in enumerate(self.scenario.get("devices", []))
        ]

    def resolve(self, name: str) -> dict:
        lowered = name.strip().lower()
        exact = [d for d in self.devices() if d["name"].lower() == lowered]
        if len(exact) == 1:
            return {**exact[0], "matched_on": "exact"}
        partial = [d for d in self.devices() if lowered in d["name"].lower()]
        if len(partial) == 1:
            return {**partial[0], "matched_on": "substring"}
        if len(partial) > 1:
            raise DeviceAmbiguous(f"{name!r} matches {[d['name'] for d in partial]}")
        raise DeviceNotFound(f"no device named {name!r} in this network")

    def _provenance(self, device: str | None, interface: str | None, operation: str) -> Provenance:
        return Provenance(
            backend=self.kind,
            simulator_version=self.version,
            session_id=self.session_id,
            source_sha256=self.source_sha256,
            working_copy_sha256=self.source_sha256,
            device=device,
            interface=interface,
            operation=operation,
            executed_at=utcnow(),
            parsed_by="scripted",
            caveats=("scripted backend: not a simulator observation",),
        )

    def run_cli(self, device: str, command: str, timeout: float) -> OperationResult:
        entry = next(
            (d for d in self.scenario.get("devices", []) if d["name"].lower() == device.lower()),
            None,
        )
        if entry is None:
            raise DeviceNotFound(f"no device named {device!r}")
        if not is_read_only(command):
            raise CapabilityUnsupported(
                f"{command!r} is not a read-only diagnostic; mutations are disabled"
            )
        output = (entry.get("commands") or {}).get(" ".join(command.split()))
        if output is None:
            return OperationResult(
                ok=False,
                kind=ObservationKind.CLI_OUTPUT,
                operation=command,
                device=device,
                raw="",
                parsed=None,
                provenance=self._provenance(device, None, command),
                error=f"scripted device {device} has no canned output for {command!r}",
                observed=False,
            )
        return OperationResult(
            ok=True,
            kind=ObservationKind.CLI_OUTPUT,
            operation=command,
            device=device,
            raw=str(output),
            parsed=None,
            provenance=self._provenance(device, None, command),
            observed=False,
        )

    def ping(self, source: str, destination: str, timeout: float) -> OperationResult:
        result = self.run_cli(source, f"ping {destination}", timeout)
        if not result.ok:
            return result
        match = re.search(r"Success rate is (\d+) percent", result.raw)
        if match is None:
            return OperationResult(
                ok=True,
                kind=ObservationKind.REACHABILITY_INCONCLUSIVE,
                operation=f"ping {destination}",
                device=source,
                raw=result.raw,
                parsed={"success_percent": None, "destination": destination},
                provenance=self._provenance(source, None, f"ping {destination}"),
                observed=False,
            )
        percent = int(match.group(1))
        return OperationResult(
            ok=True,
            kind=(
                ObservationKind.REACHABILITY_SUCCEEDED
                if percent == 100
                else ObservationKind.REACHABILITY_FAILED
            ),
            operation=f"ping {destination}",
            device=source,
            raw=result.raw,
            parsed={"success_percent": percent, "destination": destination},
            provenance=self._provenance(source, None, f"ping {destination}"),
            observed=False,
        )

    def close(self) -> str:
        return "SCRIPTED_CLOSED"


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------


def select_backend(
    working_copy: Path,
    source_sha256: str,
    session_id: str,
    workspace: Path,
    *,
    prefer_live: bool = True,
    scripted_scenario: Path | None = None,
    allow_scripted: bool = True,
) -> Backend:
    """Choose the best available backend.

    Live Packet Tracer is preferred. Scripted is used only when the caller
    permits it, and the returned backend's ``kind`` is what downstream code
    branches on — never a configuration flag.
    """
    reasons: list[str] = []
    if prefer_live and not live_allowed():
        reasons.append(
            "live simulator is disabled; set TRIDENT_ALLOW_LIVE_SIMULATOR=1 to "
            "allow Packet Tracer to start"
        )
    elif prefer_live:
        bundle = find_packet_tracer()
        if bundle is None:
            reasons.append("no Packet Tracer install found")
        else:
            credentials = credentials_from_env()
            if credentials is None:
                reasons.append(
                    "TRIDENT_PT_APP_ID / TRIDENT_PT_SECRET are not set, so the ExApp "
                    "is not configured for IPC"
                )
            else:
                backend = LiveBackend(
                    bundle=bundle,
                    working_copy=working_copy,
                    source_sha256=source_sha256,
                    session_id=session_id,
                    credentials=credentials,
                    workspace=workspace,
                )
                try:
                    backend.connect()
                except PtmpAuthRejected as exc:
                    reasons.append(f"live backend failed: {_auth_hint(exc)}")
                    backend.close()
                except (BackendUnavailable, PtmpError) as exc:
                    reasons.append(f"live backend failed: {exc}")
                    backend.close()
                else:
                    return backend
    if allow_scripted and scripted_scenario is not None:
        return ScriptedBackend.from_file(
            scripted_scenario,
            working_copy=working_copy,
            source_sha256=source_sha256,
            session_id=session_id,
        )
    raise BackendUnavailable("; ".join(reasons) or "no backend available")
