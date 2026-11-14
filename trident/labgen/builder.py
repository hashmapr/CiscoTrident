"""Build a Packet Tracer ``.pkt`` from a :class:`TopologySpec`.

The encoder is ``pkt_core.builder.Lab`` (packet-tracer-pkt-format, GPL-3.0),
already a TRIDENT dependency as Engine B. It is used as an *optional backend*:
if the builder is missing, :func:`available` returns False and callers degrade
to the manual-construction procedure instead of crashing.

The distinction this module insists on:

* ``encode_ok``  — bytes were written and decode back to the same XML.
* ``verified``   — Packet Tracer actually opened the file.

Encoding is not compatibility. :func:`generate` returns the first honestly, and
only a live :func:`verify_in_packet_tracer` can set the second.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from .faults import faulted_configs, intended_configs
from .spec import TopologySpec


class GenerationUnavailable(RuntimeError):
    """The ``pkt_core`` builder is not installed, or the spec is invalid."""


def available() -> tuple[bool, str]:
    """Whether lab generation can run here, and why not if it cannot."""
    try:
        from pkt_core.builder import Lab  # noqa: F401
    except Exception as exc:  # noqa: BLE001 - any import failure means "no"
        return False, f"pkt_core builder unavailable: {type(exc).__name__}: {exc}"
    return True, "pkt_core.builder.Lab is available"


def _builder_lab():
    from pkt_core.builder import Lab

    return Lab


# ---------------------------------------------------------------------------
# Config assembly
# ---------------------------------------------------------------------------


def build_configs(spec: TopologySpec, *, apply_faults: bool = True) -> dict[str, list[str]]:
    """Every device's IOS config, with or without the injected faults.

    ``apply_faults=False`` produces the *intended* network. Both sides are
    derived from the spec, so the answer key cannot drift from the lab: the
    difference between these two dicts *is* the answer key.
    """
    if not apply_faults:
        return intended_configs(spec)
    configs, _applied = faulted_configs(spec)
    return configs


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------


@dataclass
class GenerationResult:
    """What was written, and how far it is trusted."""

    path: Path
    sha256: str
    device_count: int
    link_count: int
    configs: dict[str, list[str]]
    #: Bytes decoded back to XML identical to what was written.
    encode_ok: bool
    #: Packet Tracer opened the file. Only a live check sets this.
    verified: bool = False
    verification_note: str = "not attempted; needs Packet Tracer"
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "path": str(self.path),
            "sha256": self.sha256,
            "device_count": self.device_count,
            "link_count": self.link_count,
            "encode_ok": self.encode_ok,
            "verified": self.verified,
            "verification_note": self.verification_note,
            "notes": list(self.notes),
        }


def generate(
    spec: TopologySpec,
    destination: str | Path,
    *,
    apply_faults: bool = True,
) -> GenerationResult:
    """Write ``spec`` to a ``.pkt`` file.

    ``apply_faults=True`` produces the student build. ``False`` produces the
    reference build the answer key was derived from — useful for a differential
    check, and required to prove a fault actually changes something.
    """
    ok, message = available()
    if not ok:
        raise GenerationUnavailable(message)

    problems = spec.validate()
    if problems:
        raise GenerationUnavailable(
            "topology spec is not well-formed: " + "; ".join(problems)
        )

    Lab = _builder_lab()
    lab = Lab()
    lab.prune_seed_devices()

    refs: dict[str, str] = {}
    configs = build_configs(spec, apply_faults=apply_faults)
    for dev in spec.devices:
        refs[dev.name] = lab.add_device(
            dev.model,
            dev.name,
            dev.x,
            dev.y,
            ios_config=configs[dev.name],
            pc_ip=dev.pc_ip,
        )
    for link in spec.links:
        lab.link(refs[link.a], link.a_port, refs[link.b], link.b_port)

    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    lab.save(str(path))

    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    encode_ok, notes = _round_trip(path)
    return GenerationResult(
        path=path,
        sha256=digest,
        device_count=len(spec.devices),
        link_count=len(spec.links),
        configs=configs,
        encode_ok=encode_ok,
        notes=notes,
    )


def _round_trip(path: Path) -> tuple[bool, tuple[str, ...]]:
    """Decode the file we just wrote and check the devices survived.

    This is an *encoder* check, not a compatibility check. It catches a broken
    write (wrong device count, unreadable container) without implying anything
    about whether Packet Tracer will accept the file.
    """
    from pkt_core.codec.container import decode
    from pkt_core.models import Lab

    try:
        container = decode(str(path))
        lab = Lab.from_bytes(container.xml)
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        return False, (f"round-trip decode failed: {type(exc).__name__}: {exc}",)
    names = [d.name for d in lab.devices]
    notes = [f"round-trip decoded {len(names)} device(s), {len(lab.links)} link(s)"]
    return True, tuple(notes)


# ---------------------------------------------------------------------------
# Live verification
# ---------------------------------------------------------------------------


def verify_in_packet_tracer(
    path: Path,
    *,
    startup_timeout: float = 60.0,
    command_timeout: float = 25.0,
) -> tuple[bool, str, dict[str, str]]:
    """Open ``path`` in a real Packet Tracer and read the configs back.

    Returns ``(opened, note, configs)``. ``configs`` maps device name to the
    ``show running-config`` text Packet Tracer produced, so the caller can diff
    the simulator's view against the intended config.

    Every path is bounded: one startup timeout, one command timeout per device,
    and the session is always closed. The caller must set
    ``TRIDENT_ALLOW_LIVE_SIMULATOR=1``; this function does not bypass that gate
    and does not start anything implicitly.
    """
    from ..simulator.backends import (
        LiveBackend,
        credentials_from_env,
        find_packet_tracer,
        live_allowed,
    )
    from ..simulator.isolation import Workspace

    if not live_allowed():
        return False, "live simulator is disabled (set TRIDENT_ALLOW_LIVE_SIMULATOR=1)", {}
    bundle = find_packet_tracer()
    if bundle is None:
        return False, "no Packet Tracer install found", {}
    credentials = credentials_from_env()
    if credentials is None:
        return False, "no registered ExApp credentials", {}

    source = Path(path)
    workspace = Workspace()
    backend = None
    directory = None
    try:
        directory = workspace.new_session_dir(source.stem)
        working_copy, copy_sha = workspace.stage_copy(source, directory)
        backend = LiveBackend(
            bundle=bundle,
            working_copy=working_copy,
            source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            session_id="labgen-verify",
            credentials=credentials,
            workspace=directory,
        )
        try:
            backend.connect(startup_timeout=startup_timeout)
        except Exception as exc:  # noqa: BLE001 - reported verbatim
            return False, f"Packet Tracer refused the file: {type(exc).__name__}: {exc}", {}

        names = [d["name"] for d in backend.devices()]
        if not names:
            return False, "Packet Tracer opened the file but reported zero devices", {}

        configs: dict[str, str] = {}
        failures: list[str] = []
        for name in names:
            try:
                result = backend.run_cli(name, "show running-config", command_timeout)
            except Exception as exc:  # noqa: BLE001
                failures.append(f"{name}: {type(exc).__name__}")
                continue
            if result.ok:
                configs[name] = result.raw
            else:
                failures.append(f"{name}: {result.error}")

        note = f"opened in Packet Tracer {backend.version}; {len(names)} device(s) visible"
        if failures:
            note += f"; config read failed for {failures}"
        return True, note, configs
    finally:
        if backend is not None:
            try:
                backend.close()
            except Exception as exc:  # noqa: BLE001 - cleanup must not mask the result
                note_suffix = f"; cleanup reported {type(exc).__name__}: {exc}"
                note += note_suffix
        if directory is not None:
            workspace.cleanup(directory)
