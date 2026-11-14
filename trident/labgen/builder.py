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
from .spec import DeviceRole, DeviceSpec, TargetKind, TopologySpec, VlanSpec


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
        vlans = _vlans_for(dev, spec, apply_faults=apply_faults)
        if vlans:
            _write_vlans(lab, refs[dev.name], vlans)
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


def _vlans_for(
    dev: DeviceSpec, spec: TopologySpec, *, apply_faults: bool
) -> tuple[VlanSpec, ...]:
    """The VLAN database a switch should carry.

    Explicit ``DeviceSpec.vlans`` wins. Otherwise the VLANs are derived from the
    access ports the spec gives that device, plus any VLAN that a fault removes
    when ``apply_faults`` is false — so the fault's absence is representable in
    the *database*, where Packet Tracer actually reads VLANs from.
    """
    if dev.vlans is not None:
        return dev.vlans
    if dev.role not in {DeviceRole.SWITCH, DeviceRole.L3_SWITCH}:
        return ()
    numbers: dict[int, str] = {}
    explicit_names: dict[int, str] = {}
    for vlan in dev.vlans or ():
        explicit_names[vlan.number] = vlan.name
    for iface in dev.interfaces:
        for line in iface.lines:
            parts = line.split()
            if len(parts) == 4 and parts[:3] == ["switchport", "access", "vlan"] and parts[3].isdigit():
                num = int(parts[3])
                numbers.setdefault(num, _default_vlan_name(num))
            # A trunk carries VLANs that this switch must therefore know about.
            # Without this the access switch has no VLAN 10 at all and the
            # trunk silently drops Administration traffic -- a defect the lab
            # never documented.
            if len(parts) >= 4 and parts[:3] == ["switchport", "trunk", "allowed"] and parts[3] == "vlan":
                for token in ",".join(parts[4:]).split(","):
                    if token.isdigit():
                        numbers.setdefault(int(token), _default_vlan_name(int(token)))
    # VLANs referenced by a fault on this device must exist too, otherwise the
    # fault has nothing to break.
    for fault in spec.faults:
        if fault.device != dev.name:
            continue
        header = (fault.context or "").strip()
        if header.lower().startswith("vlan ") and header.split()[1].isdigit():
            num = int(header.split()[1])
            numbers.setdefault(num, _default_vlan_name(num))
    if not apply_faults:
        # The intended build includes every VLAN a fault removes or renames.
        for fault in spec.faults:
            if fault.device != dev.name:
                continue
            header = " ".join((fault.context or fault.expected or "").split()).lower()
            if not header.startswith("vlan "):
                continue
            parts = header.split()
            if len(parts) > 1 and parts[1].isdigit():
                numbers[int(parts[1])] = _default_vlan_name(int(parts[1]))
    for num, name in explicit_names.items():
        numbers[num] = name

    if apply_faults:
        # VLAN faults edit the *database*, not the config text. IOS keeps VLAN
        # membership in vlan.dat and `show vlan brief` reads only that, so a
        # `name STUDENTS` config line changes nothing observable, and deleting
        # the `vlan 10` block leaves VLAN 10 in place.
        for fault in spec.faults:
            if fault.device != dev.name:
                continue
            header = " ".join((fault.context or "").split()).lower()
            if not header.startswith("vlan "):
                continue
            token = header.split()[1]
            if not token.isdigit():
                continue
            number = int(token)
            if fault.target is TargetKind.VLAN_DB and fault.actual.strip().startswith("!"):
                numbers.pop(number, None)
            elif fault.target is TargetKind.VLAN_DB:
                actual = fault.actual.strip()
                if actual.lower().startswith("name "):
                    numbers[number] = actual[5:].strip()
    # A derived VLAN must not resurrect one a removal fault deleted.
    if apply_faults:
        for fault in spec.faults:
            if fault.device != dev.name or fault.target is not TargetKind.VLAN_DB:
                continue
            if not fault.actual.strip().startswith("!"):
                continue
            header = " ".join((fault.context or "").split()).lower()
            if header.startswith("vlan ") and header.split()[1].isdigit():
                numbers.pop(int(header.split()[1]), None)

    return tuple(VlanSpec(num, name) for num, name in sorted(numbers.items()))


def _default_vlan_name(number: int) -> str:
    return {10: "ADMIN", 20: "STUDENTS", 30: "FACULTY", 99: "MGMT"}.get(number, f"VLAN{number:04d}")


def _write_vlans(lab, dev_ref: str, vlans: tuple[VlanSpec, ...]) -> None:
    """Write VLAN entries into the device's ``<VLANS>`` element.

    ``show running-config`` does not list VLANs; Packet Tracer reads them from
    this element, and ``show vlan brief`` is driven by it. Writing only a
    ``vlan 10`` config line leaves the switch with no VLAN 10 at all.
    """
    from xml.etree import ElementTree as ET

    element = lab._els[dev_ref]
    container = element.find(".//VLANS")
    if container is None:
        return
    existing = {child.get("number") for child in container}
    for vlan in vlans:
        number = str(vlan.number)
        if number in existing:
            continue
        ET.SubElement(container, "VLAN", {"number": number, "name": vlan.name})


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
