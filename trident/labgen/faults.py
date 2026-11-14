"""Apply a spec's faults to its configuration, explicitly and reversibly.

The first version of this module matched an IOS line by "the first two tokens"
and dropped every line that matched. That is how a one-line native-VLAN fault
deleted ``switchport mode trunk``, ``switchport trunk allowed vlan`` and the
port's ``no shutdown`` as well — the student build was broken in ways no fault
described, and the diff was unreviewable.

Faults now carry an explicit :class:`~.spec.TargetKind`:

``INTERFACE_LINE``  one line inside ``interface <iface>``
``CONTEXT_LINE``    one line inside a named block (``vlan 30``, a DHCP pool)
``GLOBAL_LINE``     one device-level line, inserted before ``end``
``ENDHOST``         one NIC field (ip, mask or gateway)

Everything here is deterministic and side-effect free: it returns new config
lists and never mutates the spec.
"""

from __future__ import annotations

from dataclasses import dataclass

from .spec import DeviceSpec, FaultSpec, TargetKind, TopologySpec


class FaultApplicationError(ValueError):
    """A fault could not be applied, so the lab would not contain it.

    This is raised rather than ignored: a fault that silently fails to land
    turns a scored lab into a lie about its own contents.
    """


@dataclass
class AppliedFault:
    """What one fault actually changed."""

    fault_id: str
    device: str
    removed: list[str]
    added: list[str]


#: Patterns that *start* a top-level block. An entry is a prefix of the
#: normalised line, because a header's distinguishing words can be its first
#: three tokens ("ip dhcp pool STUDENTS") while looking like a command
#: ("ip address 192.168.10.1 …") that must stay inside the current block.
_BLOCK_HEADERS = (
    "interface ",
    "vlan ",
    "line ",
    "router ",
    "ip dhcp pool ",
    "ip dhcp excluded-address ",
    "ip route ",
    "ip default-gateway ",
    "ip name-server ",
    "ip domain-name ",
    "hostname ",
    "enable ",
    "username ",
    "service ",
    "aaa ",
    "banner ",
    "logging ",
    "clock ",
    "spanning-tree ",
    "snmp-server ",
    "ntp ",
    "crypto ",
    "access-list ",
    "end",
)


def _is_block_header(line: str) -> bool:
    """Whether ``line`` starts a new top-level block.

    Matched on prefixes of the *normalised* line, so ``ip address …`` (a body
    line) is not a header while ``ip dhcp pool STUDENTS`` is.
    """
    if not line or not line.strip():
        return False
    if line != line.lstrip():
        return False
    normalised = " ".join(line.split()).lower()
    return any(normalised == header or normalised.startswith(header) for header in _BLOCK_HEADERS)


def _block_bounds(lines: list[str], header: str) -> tuple[int, int] | None:
    """Index range ``[start, end)`` for the body of ``header``.

    ``header`` is matched on the whole normalised line, so ``interface Vlan10``
    never matches ``interface Vlan100``. The block runs until the next
    top-level header, which is what makes ``vlan 30`` stop at ``vlan 99``.
    """
    target = " ".join(header.split()).lower()
    for i, line in enumerate(lines):
        if line != line.lstrip():
            continue
        if " ".join(line.split()).lower() != target:
            continue
        j = i + 1
        while j < len(lines) and not _is_block_header(lines[j]):
            j += 1
        return i + 1, j
    return None


def _apply_interface_line(lines: list[str], iface: str, fault: FaultSpec) -> AppliedFault:
    bounds = _block_bounds(lines, f"interface {iface}")
    if bounds is None:
        raise FaultApplicationError(
            f"fault {fault.fault_id}: no 'interface {iface}' block on {fault.device}"
        )
    start, end = bounds
    body = lines[start:end]
    expected = fault.expected.strip().lower()
    actual = fault.actual.strip()

    removed: list[str] = []
    kept: list[str] = []
    for line in body:
        # Replace exactly the line the fault names, matched on the full text of
        # the *expected* line, not on shared prefixes.
        if line.strip().lower() == expected:
            removed.append(line)
            continue
        kept.append(line)

    if expected and not removed:
        # The line the fault claims to change is not there: the spec and the
        # config have drifted apart and the fault cannot be trusted.
        raise FaultApplicationError(
            f"fault {fault.fault_id}: {fault.device} {iface} has no line "
            f"{fault.expected!r} to replace (body: {body!r})"
        )

    added: list[str] = []
    if actual and not actual.startswith("!"):
        added.append(f" {actual}")
    lines[start:end] = kept + added
    return AppliedFault(fault.fault_id, fault.device, removed, added)


def _apply_context_line(lines: list[str], fault: FaultSpec) -> AppliedFault:
    if not fault.context:
        raise FaultApplicationError(
            f"fault {fault.fault_id}: CONTEXT_LINE needs a context block"
        )
    bounds = _block_bounds(lines, fault.context)
    if bounds is None:
        raise FaultApplicationError(
            f"fault {fault.fault_id}: no {fault.context!r} block on {fault.device}"
        )
    start, end = bounds
    body = lines[start:end]
    expected = fault.expected.strip().lower()
    actual = fault.actual.strip()

    removed: list[str] = []
    kept: list[str] = []
    for line in body:
        if line.strip().lower() == expected:
            removed.append(line)
            continue
        kept.append(line)
    if expected and not removed:
        raise FaultApplicationError(
            f"fault {fault.fault_id}: {fault.device} block {fault.context!r} has no "
            f"line {fault.expected!r} (body: {body!r})"
        )
    added: list[str] = []
    if actual and not actual.startswith("!"):
        added.append(f" {actual}")
    lines[start:end] = kept + added
    return AppliedFault(fault.fault_id, fault.device, removed, added)


def _apply_block(lines: list[str], fault: FaultSpec) -> AppliedFault:
    """Delete a whole block, header included.

    Removing only the header (the obvious first implementation) leaves the body
    lines at global level, where they are invalid IOS and silently change the
    device's configuration in ways no fault describes.
    """
    header = fault.context or fault.expected
    if not header:
        raise FaultApplicationError(f"fault {fault.fault_id}: BLOCK needs a context")
    normalised = " ".join(header.split()).lower()
    start = None
    for i, line in enumerate(lines):
        if line != line.lstrip() and " ".join(line.split()).lower() == normalised:
            start = i
            break
        if " ".join(line.split()).lower() == normalised:
            start = i
            break
    if start is None:
        raise FaultApplicationError(
            f"fault {fault.fault_id}: {fault.device} has no {header!r} block to remove"
        )
    end = start + 1
    while end < len(lines) and not _is_block_header(lines[end]):
        end += 1
    removed = lines[start:end]
    lines[start:end] = []
    added: list[str] = []
    if fault.actual.strip() and not fault.actual.strip().startswith("!"):
        lines.insert(start, fault.actual.strip())
        added.append(fault.actual.strip())
    return AppliedFault(fault.fault_id, fault.device, removed, added)


def _apply_global_line(lines: list[str], fault: FaultSpec) -> AppliedFault:
    expected = fault.expected.strip()
    actual = fault.actual.strip()
    removed: list[str] = []
    if expected:
        for i, line in enumerate(lines):
            if line.strip().lower() == expected.lower():
                removed.append(lines.pop(i))
                break
        if not removed:
            raise FaultApplicationError(
                f"fault {fault.fault_id}: {fault.device} has no global line "
                f"{fault.expected!r} to replace"
            )
    added: list[str] = []
    if actual and not actual.startswith("!"):
        # Insert before the trailing ``end`` so Packet Tracer still gets it last.
        if lines and lines[-1].strip() == "end":
            lines.insert(len(lines) - 1, actual)
        else:
            lines.append(actual)
        added.append(actual)
    return AppliedFault(fault.fault_id, fault.device, removed, added)


def apply_faults_to_device(
    dev: DeviceSpec, lines: list[str], faults: list[FaultSpec]
) -> tuple[list[str], list[AppliedFault]]:
    """Apply every fault that belongs to ``dev``. Returns new lines + evidence."""
    out = list(lines)
    applied: list[AppliedFault] = []
    for fault in faults:
        if fault.device != dev.name:
            continue
        if fault.target is TargetKind.INTERFACE_LINE:
            if not fault.interface:
                raise FaultApplicationError(
                    f"fault {fault.fault_id}: INTERFACE_LINE needs an interface"
                )
            applied.append(_apply_interface_line(out, fault.interface, fault))
        elif fault.target is TargetKind.CONTEXT_LINE:
            applied.append(_apply_context_line(out, fault))
        elif fault.target is TargetKind.GLOBAL_LINE:
            applied.append(_apply_global_line(out, fault))
        elif fault.target is TargetKind.BLOCK:
            applied.append(_apply_block(out, fault))
        elif fault.target is TargetKind.ENDHOST:
            # End-host addressing lives in the PC's NIC, not the config text.
            applied.append(AppliedFault(fault.fault_id, fault.device, [], []))
        else:  # pragma: no cover - exhaustive enum
            raise FaultApplicationError(f"unknown target {fault.target}")
    return out, applied


def intended_configs(spec: TopologySpec) -> dict[str, list[str]]:
    """Every device's config exactly as the brief describes it."""
    out: dict[str, list[str]] = {}
    for dev in spec.devices:
        lines: list[str] = list(dev.globals)
        for iface in dev.interfaces:
            lines.append(f"interface {iface.name}")
            lines.extend(iface.lines)
        lines.extend(dev.trailing)
        if lines and lines[-1] != "end":
            lines.append("end")
        out[dev.name] = lines
    return out


def faulted_configs(spec: TopologySpec) -> tuple[dict[str, list[str]], list[AppliedFault]]:
    """Every device's config with all faults applied, plus per-fault evidence."""
    base = intended_configs(spec)
    out: dict[str, list[str]] = {}
    applied: list[AppliedFault] = []
    for dev in spec.devices:
        lines, changes = apply_faults_to_device(dev, base[dev.name], spec.faults)
        out[dev.name] = lines
        applied.extend(changes)
    return out, applied
