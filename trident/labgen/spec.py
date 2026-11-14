"""Topology specifications for generated Packet Tracer labs.

A :class:`TopologySpec` is the *intent*: what the lab should contain and how each
device should be configured. A :class:`FaultSpec` is a deliberate deviation from
that intent, and the two are kept apart on purpose:

* the **student build** writes ``intended`` configuration with the faults applied;
* the **answer key** records intended-vs-actual for every fault.

Generation must never let the fault manifest reach the file it ships to a student.
:func:`generate` therefore writes only the faulted config, and the manifest is
returned as a separate object the caller holds back.

Why a spec at all, rather than a hand-written list of builder calls: a scored
practice lab needs the intended configuration *and* the faulted configuration to
be provably related. Deriving both from one spec makes "the expected value" a
fact about the spec rather than something a human retyped into a rubric.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Literal


class DeviceRole(enum.StrEnum):
    """Coarse device class, so verifiers can reason without model strings."""

    ROUTER = "router"
    L3_SWITCH = "l3_switch"
    SWITCH = "switch"
    PC = "pc"
    SERVER = "server"


class FaultCategory(enum.StrEnum):
    """Where a fault lives. Used for scoring balance, not for grading."""

    ADDRESSING = "addressing"
    VLAN = "vlan"
    TRUNK = "trunk"
    ROUTING = "routing"
    GATEWAY = "gateway"
    DHCP = "dhcp"
    DNS = "dns"
    INTERFACE = "interface"
    SECURITY = "security"
    ACCESS = "access"


class TargetKind(enum.StrEnum):
    """Where a fault edits. Explicit, because inference by string matching is
    how a fault silently edits the wrong line."""

    #: One line inside ``interface <iface>``.
    INTERFACE_LINE = "interface_line"
    #: One line inside a named block given by ``FaultSpec.context``.
    CONTEXT_LINE = "context_line"
    #: A device-level line, inserted before ``end``.
    GLOBAL_LINE = "global_line"
    #: A whole named block, header and body. Used when the defect is the block's
    #: absence: deleting only the header orphans its body into global config.
    BLOCK = "block"
    #: The device's VLAN database (Packet Tracer's ``<VLANS>``, i.e. vlan.dat).
    #: This is where VLAN existence and names actually live: IOS does not print
    #: them in running-config, and ``show vlan brief`` reads only this.
    VLAN_DB = "vlan_db"
    #: An end-host NIC field: ip, mask or gateway.
    ENDHOST = "endhost"


class Severity(enum.StrEnum):
    """How much a fault breaks. Drives the rubric weight."""

    CRITICAL = "critical"
    MAJOR = "major"
    MINOR = "minor"


@dataclass(frozen=True)
class InterfaceSpec:
    """One interface and the IOS lines that configure it.

    ``lines`` is written verbatim under ``interface <name>``. Keeping the raw
    lines rather than a parsed model is deliberate: the point of generation is to
    produce exactly the IOS text Packet Tracer will run, and an intermediate
    object would only introduce opportunities to disagree with it.
    """

    name: str
    lines: tuple[str, ...] = ()
    #: Which fault (if any) replaces ``lines`` in the student build.
    fault_id: str | None = None


@dataclass(frozen=True)
class DeviceSpec:
    """One device: model, placement, and the config that defines it."""

    name: str
    model: str
    role: DeviceRole
    x: int
    y: int
    #: Global config lines, written before any ``interface`` block.
    globals: tuple[str, ...] = ()
    interfaces: tuple[InterfaceSpec, ...] = ()
    #: For end devices: (ip, mask, gateway). None for infrastructure.
    pc_ip: tuple[str, str, str] | None = None
    #: Extra lines appended after the interfaces (``ip route``, ``line vty``…).
    trailing: tuple[str, ...] = ()
    #: VLAN database entries for a switch. ``None`` means "derive from spec".
    vlans: tuple[VlanSpec, ...] | None = None


@dataclass(frozen=True)
class VlanSpec:
    """One VLAN in the switch's VLAN database.

    This is *not* a config line. Packet Tracer keeps the VLAN database in the
    device's ``<VLANS>`` element — the equivalent of ``vlan.dat`` — and IOS does
    not print VLANs in ``show running-config`` at all. A topology that only
    writes ``vlan 10`` as a config line therefore produces a switch whose
    ``show vlan brief`` lists nothing but the defaults, which is exactly what
    the first live run of this lab showed.
    """

    number: int
    name: str


@dataclass(frozen=True)
class LinkSpec:
    a: str
    a_port: str
    b: str
    b_port: str


@dataclass(frozen=True)
class FaultSpec:
    """A deliberate defect, with everything a grader needs to judge it.

    The fields after ``actual`` exist because kind-level grading is too coarse
    for a 12-fault lab: two ``WRONG_VLAN`` faults on different switches are the
    same *kind* but different *findings*, and a report that names the wrong
    switch should not earn full credit.
    """

    fault_id: str
    category: FaultCategory
    severity: Severity
    device: str
    interface: str | None
    #: Human description of what was done.
    description: str
    #: The value the spec intends.
    expected: str
    #: The value actually written to the student build.
    actual: str
    #: What the student should observe as the symptom.
    symptom: str
    #: Points deducted if not found (rubric weights must sum to 100).
    points: int
    hint_1: str
    hint_2: str
    #: How the fault edits the config. Never inferred.
    target: TargetKind = TargetKind.INTERFACE_LINE
    #: Block header that scopes a ``CONTEXT_LINE`` edit, e.g. ``"vlan 30"``.
    context: str | None = None
    #: Which NIC field an ``ENDHOST`` fault changes.
    endhost_field: str | None = None


@dataclass
class TopologySpec:
    """A complete lab definition."""

    name: str
    title: str
    devices: list[DeviceSpec]
    links: list[LinkSpec]
    faults: list[FaultSpec] = field(default_factory=list)
    #: Free-form scenario text for the student brief.
    brief: str = ""
    difficulty: Literal["beginner", "intermediate", "advanced"] = "intermediate"

    def device(self, name: str) -> DeviceSpec:
        for dev in self.devices:
            if dev.name == name:
                return dev
        raise KeyError(f"no device named {name!r} in {self.name}")

    def fault(self, fault_id: str) -> FaultSpec:
        for fault in self.faults:
            if fault.fault_id == fault_id:
                return fault
        raise KeyError(f"no fault {fault_id!r} in {self.name}")

    def point_total(self) -> int:
        return sum(f.points for f in self.faults)

    def by_category(self) -> dict[FaultCategory, list[FaultSpec]]:
        out: dict[FaultCategory, list[FaultSpec]] = {}
        for fault in self.faults:
            out.setdefault(fault.category, []).append(fault)
        return out

    def validate(self) -> list[str]:
        """Structural problems with the spec. Empty means well-formed.

        These are authoring errors, not student-visible faults, so they raise at
        build time rather than being scored.
        """
        problems: list[str] = []
        names = [d.name for d in self.devices]
        if len(names) != len(set(names)):
            problems.append("duplicate device name")
        for link in self.links:
            for endpoint in (link.a, link.b):
                if endpoint not in names:
                    problems.append(f"link references unknown device {endpoint!r}")
        ids = [f.fault_id for f in self.faults]
        if len(ids) != len(set(ids)):
            problems.append("duplicate fault_id")
        for fault in self.faults:
            if fault.device not in names:
                problems.append(f"fault {fault.fault_id} references unknown device")
            if fault.points < 0:
                problems.append(f"fault {fault.fault_id} has negative points")
        total = self.point_total()
        if self.faults and total != 100:
            problems.append(f"fault points total {total}, expected 100")
        return problems
