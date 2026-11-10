"""Analyze Mode: a plain-English, device-by-device assessment of a network.

The user uploads a lab, presses one button, and gets a report they could hand to
a network engineer: what each device is, how it is configured, what questions are
likely to be asked about it, and what deserves investigation.

Design rules, all enforced in code rather than by good intentions:

* **No invented values.** A field the model does not have is omitted, never
  filled with a guess or a placeholder.
* **Evidence status travels with every fact.** Each answered question says whether
  it is a verified configuration fact, a derived fact, an operational observation,
  or unsupported.
* **Absence of findings is not compliance.** A clean report says what was checked
  and what was not, and never reads as "this network is correct".
* **One root cause, one mention.** A finding is attributed to the device that owns
  it; network-wide sections group related symptoms rather than repeating them.
* **Plain English first, evidence behind it.** Sentences like "R1's Gi0/0 uses
  192.168.1.1/24 and connects toward SW1", with the raw evidence in a field the UI
  can expand.
"""

from __future__ import annotations

import enum
import ipaddress
from dataclasses import dataclass, field

from ..deepcore.coverage import CoverageMatrix, Level
from ..diagnostics import diagnose
from ..diagnostics import report as diagnostic_report
from ..models import DeviceInfo, InterfaceInfo, NetworkModel


class Status(enum.StrEnum):
    """How firmly a reported fact is established."""

    #: Three extraction families agreed on the configuration.
    VERIFIED = "VERIFIED"
    #: Derived deterministically from verified facts.
    DERIVED = "DERIVED"
    #: A live simulator reported it.
    OBSERVED = "OBSERVED"
    #: The model suggests a problem but does not prove one.
    SUSPECTED = "SUSPECTED"
    #: A requirement is demonstrably violated.
    VIOLATION = "VIOLATION"
    #: The model cannot answer.
    UNRESOLVED = "UNRESOLVED"
    #: The device or feature is outside what TRIDENT models.
    UNSUPPORTED = "UNSUPPORTED"
    #: Not checked, with the reason.
    NOT_CHECKED = "NOT_CHECKED"


class Severity(enum.StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class QandA:
    """One likely Cisco question and its answer, with status."""

    question: str
    answer: str | None
    status: Status
    evidence: list[str] = field(default_factory=list)
    limitation: str = ""

    def as_dict(self) -> dict:
        return {
            "question": self.question,
            "answer": self.answer,
            "status": self.status.value,
            "evidence": list(self.evidence),
            "limitation": self.limitation,
        }


@dataclass
class DeviceFinding:
    """A problem attributed to one device."""

    severity: Severity
    device: str
    interface: str | None
    description: str
    evidence: str
    why_it_matters: str
    next_commands: list[str] = field(default_factory=list)
    remediation: str | None = None
    status: Status = Status.SUSPECTED
    needs_runtime: bool = False

    def as_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "device": self.device,
            "interface": self.interface,
            "description": self.description,
            "evidence": self.evidence,
            "why_it_matters": self.why_it_matters,
            "next_commands": list(self.next_commands),
            "remediation": self.remediation,
            "status": self.status.value,
            "needs_runtime": self.needs_runtime,
        }


@dataclass
class DeviceSection:
    """Everything the report says about one device."""

    name: str
    display_kind: str
    model: str | None
    heading: str
    basics: list[tuple[str, str]] = field(default_factory=list)
    questions: list[QandA] = field(default_factory=list)
    findings: list[DeviceFinding] = field(default_factory=list)
    neighbors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "display_kind": self.display_kind,
            "model": self.model,
            "heading": self.heading,
            "basics": [{"label": label, "value": value} for label, value in self.basics],
            "questions": [item.as_dict() for item in self.questions],
            "findings": [item.as_dict() for item in self.findings],
            "neighbors": list(self.neighbors),
        }

    def to_text(self) -> str:
        lines = [self.heading, ""]
        if self.basics:
            lines.append("Basic Information")
            for label, value in self.basics:
                lines.append(f"  {label}: {value}")
            lines.append("")
        if self.questions:
            lines.append("Common Cisco Questions")
            for item in self.questions:
                if item.answer is None:
                    lines.append(f"  {item.question}")
                    lines.append(f"    -> {item.status.value}: {item.limitation}")
                else:
                    lines.append(f"  {item.question}")
                    lines.append(f"    -> {item.answer}  [{item.status.value}]")
            lines.append("")
        if self.findings:
            lines.append("Potential Problems")
            for finding in self.findings:
                where = " ".join(x for x in (finding.device, finding.interface) if x)
                lines.append(f"  [{finding.severity.value}] {where}: {finding.description}")
                lines.append(f"    Why it matters: {finding.why_it_matters}")
                if finding.evidence:
                    lines.append(f"    Evidence: {finding.evidence}")
                if finding.next_commands:
                    lines.append(f"    Check with: {', '.join(finding.next_commands)}")
                if finding.remediation:
                    lines.append(f"    Suggested fix: {finding.remediation}")
            lines.append("")
        else:
            lines.append("Potential Problems")
            lines.append("  No problem detected by the checks that were run.")
            lines.append("")
        return "\n".join(lines)


@dataclass
class NetworkReport:
    """The whole report."""

    overview: dict
    sections: list[DeviceSection]
    network_findings: list[DeviceFinding] = field(default_factory=list)
    unsupported_checks: list[str] = field(default_factory=list)
    coverage: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "overview": self.overview,
            "sections": [section.as_dict() for section in self.sections],
            "network_findings": [f.as_dict() for f in self.network_findings],
            "unsupported_checks": list(self.unsupported_checks),
            "coverage": self.coverage,
            "warnings": list(self.warnings),
        }

    def to_text(self) -> str:
        lines = ["TRIDENT NETWORK ANALYSIS", "=" * 24, ""]
        ov = self.overview
        lines.append(f"Devices: {ov.get('device_count', 0)}")
        lines.append(f"  by type: {_format_counts(ov.get('devices_by_type', {}))}")
        lines.append(f"Physical links: {ov.get('link_count', 0)}")
        lines.append(f"Interfaces: {ov.get('interface_count', 0)}")
        lines.append(f"VLANs configured: {ov.get('vlan_count', 0)}")
        lines.append(f"Routing protocols: {', '.join(ov.get('routing_protocols', [])) or 'none detected'}")
        lines.append(f"Findings: {_format_counts(ov.get('findings_by_severity', {}))}")
        lines.append("")
        for section in self.sections:
            lines.append(section.to_text())
        if self.network_findings:
            lines.append("Network-wide issues")
            lines.append("")
            for finding in self.network_findings:
                where = " ".join(x for x in (finding.device, finding.interface) if x) or "network"
                lines.append(f"  [{finding.severity.value}] {where}: {finding.description}")
                if finding.evidence:
                    lines.append(f"    Evidence: {finding.evidence}")
            lines.append("")
        lines.append("What was not checked")
        if self.unsupported_checks:
            for item in self.unsupported_checks:
                lines.append(f"  - {item}")
        else:
            lines.append("  - nothing outstanding")
        lines.append("")
        lines.append(
            "A report with no findings means no check fired. It is not proof that the "
            "network is correct."
        )
        return "\n".join(lines)

    def to_markdown(self) -> str:
        ov = self.overview
        lines = ["# TRIDENT Network Analysis", ""]
        lines.append("## Overview")
        lines.append("")
        lines.append("| Measure | Value |")
        lines.append("|---|---|")
        lines.append(f"| Devices | {ov.get('device_count', 0)} |")
        lines.append(f"| Physical links | {ov.get('link_count', 0)} |")
        lines.append(f"| Interfaces | {ov.get('interface_count', 0)} |")
        lines.append(f"| VLANs | {ov.get('vlan_count', 0)} |")
        lines.append(
            f"| Routing protocols | {', '.join(ov.get('routing_protocols', [])) or 'none detected'} |"
        )
        lines.append(f"| Findings | {_format_counts(ov.get('findings_by_severity', {}))} |")
        lines.append("")
        for section in self.sections:
            lines.append(f"## {section.heading}")
            lines.append("")
            if section.basics:
                lines.append("### Basic Information")
                lines.append("")
                lines.append("| Field | Value |")
                lines.append("|---|---|")
                for label, value in section.basics:
                    lines.append(f"| {label} | {value} |")
                lines.append("")
            if section.questions:
                lines.append("### Common Cisco Questions")
                lines.append("")
                for item in section.questions:
                    answer = item.answer if item.answer is not None else f"_{item.limitation}_"
                    lines.append(f"- **{item.question}** {answer} `{item.status.value}`")
                lines.append("")
            lines.append("### Potential Problems")
            lines.append("")
            if not section.findings:
                lines.append("No problem detected by the checks that were run.")
            for finding in section.findings:
                lines.append(
                    f"- **{finding.severity.value}** `{finding.device}"
                    f"{' ' + finding.interface if finding.interface else ''}`: "
                    f"{finding.description}"
                )
                lines.append(f"  - Why it matters: {finding.why_it_matters}")
                if finding.evidence:
                    lines.append(f"  - Evidence: {finding.evidence}")
                if finding.next_commands:
                    lines.append(f"  - Check with: `{', '.join(finding.next_commands)}`")
            lines.append("")
        if self.network_findings:
            lines.append("## Network-wide issues")
            lines.append("")
            for finding in self.network_findings:
                lines.append(f"- **{finding.severity.value}** {finding.description}")
                if finding.evidence:
                    lines.append(f"  - Evidence: {finding.evidence}")
            lines.append("")
        lines.append("## What was not checked")
        lines.append("")
        for item in self.unsupported_checks or ["nothing outstanding"]:
            lines.append(f"- {item}")
        lines.append("")
        lines.append(
            "> A report with no findings means no check fired. It is not proof that "
            "the network is correct."
        )
        return "\n".join(lines)


def _format_counts(counts: dict) -> str:
    if not counts:
        return "none"
    return ", ".join(f"{value} {key.lower()}" for key, value in sorted(counts.items()))


# ---------------------------------------------------------------------------
# Device classification
# ---------------------------------------------------------------------------


#: How a device type is presented in a heading.
_KIND_LABELS = {
    "router": "Router",
    "switch": "Switch",
    "multilayer": "Multilayer Switch",
    "host": "PC",
    "pc": "PC",
    "server": "Server",
    "firewall": "Firewall",
    "wireless": "Wireless",
    "access point": "Access Point",
    "cloud": "Cloud",
    "unknown": "Device",
}


#: Packet Tracer model strings and the kind they represent.
#:
#: Classification follows the directive's reliability order: an explicit
#: structural type first, then a known model mapping, then conservative
#: inference, then Unknown. Packet Tracer files record no structural device type
#: (the ``<TYPE>`` element carries only a model), so the model mapping is the
#: most reliable source that actually exists in the file.
_MODEL_KINDS: tuple[tuple[str, str], ...] = (
    # Routers
    ("2911", "Router"),
    ("2901", "Router"),
    ("2811", "Router"),
    ("1941", "Router"),
    ("1841", "Router"),
    ("4331", "Router"),
    ("4321", "Router"),
    ("isr4", "Router"),
    ("isr", "Router"),
    ("router", "Router"),
    # Switches
    ("2960", "Switch"),
    ("2950", "Switch"),
    ("3560", "Multilayer Switch"),
    ("3650", "Multilayer Switch"),
    ("3750", "Multilayer Switch"),
    ("switch", "Switch"),
    # Endpoints
    ("pc-pt", "PC"),
    ("laptop", "PC"),
    ("server-pt", "Server"),
    ("server", "Server"),
    ("tablet", "PC"),
    ("smartphone", "PC"),
    # Security
    ("asa", "Firewall"),
    ("firewall", "Firewall"),
    ("5505", "Firewall"),
    ("5506", "Firewall"),
    # Wireless
    ("access point", "Access Point"),
    ("accesspoint", "Access Point"),
    ("aironet", "Access Point"),
    ("wrt", "Wireless Router"),
    ("wireless router", "Wireless Router"),
    ("wlc", "Wireless Controller"),
    # Other
    ("cloud", "Cloud"),
    ("hub-pt", "Hub"),
    ("hub", "Hub"),
    ("power distribution", "Infrastructure"),
    ("sniffer", "Infrastructure"),
    ("modem", "Modem"),
    ("dsl", "Modem"),
    ("cable modem", "Modem"),
)


def _device_kind(device: DeviceInfo) -> str:
    """Classify a device for display, in the directive's reliability order.

    1. An explicit structural type on the model record.
    2. A known hardware-model mapping.
    3. Conservative inference from the model string.
    4. Unknown.

    A type is never manufactured: if nothing matches, the device is reported as
    ``Unknown`` with its model shown, rather than filed under a plausible guess.
    """
    # 1. Structural type, if a future parser populates one.
    structural = (device.device_type or "").strip().lower()
    if structural:
        for key, label in _KIND_LABELS.items():
            if key in structural:
                return label

    # 2. Known model mapping, longest key first so "2960-24TT" beats "2960".
    model = (device.model or "").strip().lower()
    if model:
        for key, label in sorted(_MODEL_KINDS, key=lambda pair: -len(pair[0])):
            if key in model:
                return label
        # 3. Conservative inference: a model string naming a router or switch.
        if "router" in model:
            return "Router"
        if "switch" in model:
            return "Switch"

    # 4. Unknown, with the model preserved so a reader can judge for themselves.
    if device.model:
        return f"Unknown ({device.model})"
    return "Unknown"


class Analyzer:
    """Builds the device-by-device report from a canonical model."""

    def __init__(
        self,
        model: NetworkModel,
        coverage: CoverageMatrix | None = None,
    ) -> None:
        self.model = model
        self.coverage = coverage or CoverageMatrix()
        self._interfaces: dict[str, list[InterfaceInfo]] = {}
        for interface in model.interfaces.values():
            self._interfaces.setdefault(interface.device, []).append(interface)
        self._findings_by_device: dict[str, list[DeviceFinding]] = {}
        for finding in self._collect_findings():
            self._findings_by_device.setdefault(finding.device, []).append(finding)

    # -- public ----------------------------------------------------------

    def build(self) -> NetworkReport:
        sections = [self.section(device) for device in self._ordered_devices()]
        findings = [f for group in self._findings_by_device.values() for f in group]
        overview = self._overview(findings)
        network_findings = [f for f in findings if not f.device or f.device == "network"]
        return NetworkReport(
            overview=overview,
            sections=sections,
            network_findings=network_findings,
            unsupported_checks=self._unsupported_checks(),
            coverage=self.coverage.summary(),
            warnings=list(self.model.warnings),
        )

    def section(self, device: DeviceInfo) -> DeviceSection:
        kind = _device_kind(device)
        heading = f"{kind} — {device.name}"
        section = DeviceSection(
            name=device.name,
            display_kind=kind,
            model=device.model,
            heading=heading,
        )
        section.basics = self._basics(device)
        section.neighbors = self._neighbors(device.name)
        section.questions = self._questions(device)
        section.findings = self._findings_by_device.get(device.name, [])
        return section

    # -- overview --------------------------------------------------------

    def _overview(self, findings: list[DeviceFinding]) -> dict:
        by_type: dict[str, int] = {}
        for device in self.model.devices.values():
            by_type[_device_kind(device)] = by_type.get(_device_kind(device), 0) + 1
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1
        return {
            "device_count": len(self.model.devices),
            "devices_by_type": by_type,
            "link_count": len(self.model.links),
            "interface_count": len(self.model.interfaces),
            "vlan_count": len(self.model.vlans),
            "routing_protocols": self._routing_protocols(),
            "findings_by_severity": by_severity,
            "unsupported_checks": len(self._unsupported_checks()),
            "snapshot_id": self.model.snapshot_id,
            "snapshot_ambiguous": self.model.snapshot_ambiguous,
            "file_sha256": self.model.file_sha256,
        }

    def _routing_protocols(self) -> list[str]:
        names: set[str] = set()
        markers = (
            ("router ospf", "OSPF"),
            ("router eigrp", "EIGRP"),
            ("router rip", "RIP"),
            ("router bgp", "BGP"),
            ("router isis", "IS-IS"),
        )
        for device in self.model.devices.values():
            for line in device.configuration or ():
                lowered = line.strip().lower()
                for marker, name in markers:
                    if lowered.startswith(marker):
                        names.add(name)
        for route in self.model.routes:
            protocol = (route.protocol or "").lower()
            for marker, name in (
                ("ospf", "OSPF"),
                ("eigrp", "EIGRP"),
                ("rip", "RIP"),
                ("bgp", "BGP"),
            ):
                if protocol.startswith(marker):
                    names.add(name)
        return sorted(names)

    def _unsupported_checks(self) -> list[str]:
        items: list[str] = []
        for feature in self.coverage.features:
            if feature.level is Level.UNSUPPORTED:
                detail = feature.limitations[0] if feature.limitations else "not supported"
                items.append(f"{feature.name.replace('_', ' ')}: {detail}")
        return items

    # -- per-device ------------------------------------------------------

    def _ordered_devices(self) -> list[DeviceInfo]:
        """Routers first, then switches, then endpoints, then the rest."""
        order = {
            "Router": 0,
            "Multilayer Switch": 0,
            "Firewall": 1,
            "Switch": 2,
            "Wireless Router": 2,
            "Access Point": 2,
            "PC": 3,
            "Server": 3,
            "Hub": 4,
            "Infrastructure": 9,
            "Cloud": 5,
        }

        def key(device: DeviceInfo):
            return (order.get(_device_kind(device), 4), device.name.lower())

        return sorted(self.model.devices.values(), key=key)

    def _basics(self, device: DeviceInfo) -> list[tuple[str, str]]:
        rows: list[tuple[str, str]] = [("Display name", device.name)]
        if device.hostname and device.hostname != device.name:
            rows.append(("Hostname", device.hostname))
        if device.model:
            rows.append(("Hardware model", device.model))
        rows.append(("Device type", device.device_type or "not stated in the file"))

        interfaces = self._interfaces.get(device.name, [])
        addressed = [i for i in interfaces if i.ipv4_address]
        if addressed:
            rows.append(
                (
                    "Interface addresses",
                    "; ".join(
                        f"{i.name} {i.ipv4_address}/{i.prefix_length}"
                        if i.prefix_length is not None
                        else f"{i.name} {i.ipv4_address}"
                        for i in addressed
                    ),
                )
            )
        down = [i.name for i in interfaces if (i.admin_state or "").lower() in {"administratively down", "down"}]
        if down:
            rows.append(("Administratively disabled", ", ".join(sorted(down))))

        connected = self._connected_networks(device.name)
        if connected:
            rows.append(("Connected networks", ", ".join(connected)))

        routes = [r for r in self.model.routes if r.device == device.name]
        default_routes = [r for r in routes if r.destination in {"0.0.0.0", "0.0.0.0/0"}]
        if default_routes:
            rows.append(
                (
                    "Default route",
                    "; ".join(
                        f"via {r.next_hop}" if r.next_hop else "directly connected"
                        for r in default_routes
                    ),
                )
            )
        static = [r for r in routes if (r.route_type or "").lower() == "static" and r not in default_routes]
        if static:
            rows.append(
                (
                    "Static routes",
                    "; ".join(f"{r.destination} via {r.next_hop or '-'}" for r in static),
                )
            )

        if device.name in self.model.settings.default_gateways:
            rows.append(
                ("Default gateway", self.model.settings.default_gateways[device.name])
            )
        if device.name in self.model.settings.dns_servers:
            rows.append(
                ("DNS servers", ", ".join(self.model.settings.dns_servers[device.name]))
            )

        vlans = self._vlans_for(device.name)
        if vlans:
            rows.append(("VLANs", ", ".join(str(v) for v in vlans)))

        acls = self._acls_for(device.name)
        if acls:
            rows.append(("ACLs applied", "; ".join(acls)))

        neighbors = self._neighbors(device.name)
        if neighbors:
            rows.append(("Direct neighbors", ", ".join(neighbors)))

        return rows

    def _connected_networks(self, device: str) -> list[str]:
        networks: set[str] = set()
        for interface in self._interfaces.get(device, []):
            if not interface.ipv4_address or interface.prefix_length is None:
                continue
            try:
                network = ipaddress.IPv4Interface(
                    f"{interface.ipv4_address}/{interface.prefix_length}"
                ).network
            except ValueError:
                continue
            networks.add(str(network))
        return sorted(networks)

    def _vlans_for(self, device: str) -> list[int]:
        ids: set[int] = set()
        for interface in self._interfaces.get(device, []):
            for raw in interface.vlan_assignments:
                digits = "".join(ch for ch in str(raw) if ch.isdigit())
                if digits:
                    ids.add(int(digits))
        return sorted(ids)

    def _acls_for(self, device: str) -> list[str]:
        items: list[str] = []
        for acl in self.model.acls:
            interface = acl.applied_interface or ""
            if any(i.name == interface for i in self._interfaces.get(device, [])):
                direction = f" {acl.direction}" if acl.direction else ""
                items.append(f"{acl.acl_id}{direction} on {interface}")
        return sorted(set(items))

    def _neighbors(self, device: str) -> list[str]:
        names: list[str] = []
        for link in self.model.links:
            if link.device_a == device:
                names.append(f"{link.device_b} (via {link.interface_a})")
            elif link.device_b == device:
                names.append(f"{link.device_a} (via {link.interface_b})")
        return sorted(set(names))

    # -- questions -------------------------------------------------------

    def _questions(self, device: DeviceInfo) -> list[QandA]:
        """Likely Cisco questions, answered only where the model supports it."""
        items: list[QandA] = []

        items.append(
            QandA(
                question="What is the hostname?",
                answer=device.hostname or device.name,
                status=Status.VERIFIED if device.hostname else Status.UNRESOLVED,
                limitation="" if device.hostname else "the file does not state a hostname",
                evidence=[f"device record {device.name}"],
            )
        )

        if device.model:
            items.append(
                QandA(
                    question="What is the hardware model?",
                    answer=device.model,
                    status=Status.VERIFIED,
                    evidence=["hardware model from the file"],
                )
            )
        else:
            items.append(
                QandA(
                    question="What is the hardware model?",
                    answer=None,
                    status=Status.UNSUPPORTED,
                    limitation="the model is not recorded for this device",
                )
            )

        addressed = [i for i in self._interfaces.get(device.name, []) if i.ipv4_address]
        if addressed:
            items.append(
                QandA(
                    question="What IP address and mask are assigned to each interface?",
                    answer="; ".join(
                        self._address_phrase(i) for i in addressed
                    ),
                    status=Status.VERIFIED,
                    evidence=[f"{i.name} {i.ipv4_address}/{i.prefix_length}" for i in addressed],
                )
            )

        connected = self._connected_networks(device.name)
        if connected:
            items.append(
                QandA(
                    question="What networks are directly connected?",
                    answer=", ".join(connected),
                    status=Status.DERIVED,
                    evidence=["derived from interface addresses and masks"],
                )
            )

        routes = [r for r in self.model.routes if r.device == device.name]
        if routes:
            defaults = [r for r in routes if r.destination in {"0.0.0.0", "0.0.0.0/0"}]
            items.append(
                QandA(
                    question="What is the default route?",
                    answer=(
                        "; ".join(f"via {r.next_hop}" for r in defaults if r.next_hop)
                        if defaults
                        else "no default route is configured"
                    ),
                    status=Status.VERIFIED,
                    evidence=[r.raw_config or f"{r.destination} -> {r.next_hop}" for r in defaults]
                    or ["routing table"],
                )
            )

        protocols = self._device_protocols(device)
        if protocols:
            items.append(
                QandA(
                    question="Which routing protocol is configured?",
                    answer=", ".join(protocols),
                    status=Status.VERIFIED,
                    evidence=["routing configuration"],
                    limitation="a configured protocol does not prove a formed adjacency",
                )
            )

        neighbors = self._neighbors(device.name)
        if neighbors:
            items.append(
                QandA(
                    question="Which devices connect directly?",
                    answer=", ".join(neighbors),
                    status=Status.VERIFIED,
                    evidence=["physical link table"],
                )
            )

        down = [
            i.name
            for i in self._interfaces.get(device.name, [])
            if (i.admin_state or "").lower() in {"administratively down", "down"}
        ]
        if down:
            items.append(
                QandA(
                    question="Which interfaces are administratively disabled?",
                    answer=", ".join(sorted(down)),
                    status=Status.VERIFIED,
                    evidence=["interface administrative state"],
                )
            )

        acls = self._acls_for(device.name)
        if acls:
            items.append(
                QandA(
                    question="Which ACLs are configured and applied?",
                    answer="; ".join(acls),
                    status=Status.VERIFIED,
                    evidence=["access-list configuration"],
                    limitation="ordering between entries is not fully evaluated",
                )
            )

        if device.name in self.model.settings.default_gateways:
            items.append(
                QandA(
                    question="What is the default gateway?",
                    answer=self.model.settings.default_gateways[device.name],
                    status=Status.VERIFIED,
                    evidence=["host ip configuration"],
                )
            )

        return items

    @staticmethod
    def _address_phrase(interface: InterfaceInfo) -> str:
        if interface.prefix_length is None:
            return f"{interface.name} {interface.ipv4_address}"
        return f"{interface.name} {interface.ipv4_address}/{interface.prefix_length}"

    def _device_protocols(self, device: DeviceInfo) -> list[str]:
        names: set[str] = set()
        markers = (
            ("router ospf", "OSPF"),
            ("router eigrp", "EIGRP"),
            ("router rip", "RIP"),
            ("router bgp", "BGP"),
        )
        for line in device.configuration or ():
            lowered = line.strip().lower()
            for marker, name in markers:
                if lowered.startswith(marker):
                    names.add(name)
        return sorted(names)

    # -- findings --------------------------------------------------------

    def _collect_findings(self) -> list[DeviceFinding]:
        """Turn diagnostics output into device-attributed findings."""
        diagnosis = diagnose(self.model)
        findings: list[DeviceFinding] = []
        for entry in diagnostic_report(diagnosis):
            kind = str(entry.get("kind", ""))
            device = entry.get("device") or "network"
            evidence = ""
            supporting = entry.get("supporting") or []
            if supporting:
                evidence = "; ".join(str(item.get("detail", "")) for item in supporting[:2])
            findings.append(
                DeviceFinding(
                    severity=_severity_for(kind),
                    device=device,
                    interface=entry.get("interface"),
                    description=_describe(kind, entry),
                    evidence=evidence,
                    why_it_matters=_why(kind),
                    next_commands=_commands_for(kind),
                    remediation=entry.get("repair_hint"),
                    status=(
                        Status.VIOLATION
                        if entry.get("status") == "CONFIRMED_DEFECT"
                        else Status.SUSPECTED
                    ),
                    needs_runtime=kind in {"MISSING_STATIC_ROUTE", "ACL_BLOCK"},
                )
            )
        return findings


#: Plain-English descriptions, one per defect class.
_DESCRIPTIONS = {
    "WRONG_VLAN": "an access port is in a VLAN that does not match its segment",
    "INVALID_MASK": "an interface has a subnet mask that is not a legal mask",
    "WRONG_GATEWAY": "a default gateway is not an address that exists on this network",
    "MISSING_STATIC_ROUTE": "a router is relied on for transit but has no route to a subnet behind it",
    "SHUTDOWN_INTERFACE": "an interface that should be forwarding is administratively down",
    "ACL_BLOCK": "an ACL deny is bound to an interface and may be blocking intended traffic",
    "TRUNK_MISMATCH": "two ends of a trunk carry different VLAN sets",
    "ROUTING_LOOP": "a route points back at an address on the same device",
    "DHCP_MISCONFIGURATION": "a DHCP pool's default router is not a real address",
    "DUPLICATE_IP": "two interfaces claim the same IP address",
    "OVERLAPPING_SUBNET": "two interface subnets overlap on one device",
}

_WHY = {
    "WRONG_VLAN": "the host cannot reach its gateway, so nothing beyond the segment works",
    "INVALID_MASK": "the device cannot determine which addresses are local, so forwarding fails",
    "WRONG_GATEWAY": "the host sends off-subnet traffic to an address nobody owns",
    "MISSING_STATIC_ROUTE": "returning traffic is dropped, so connections appear to hang",
    "SHUTDOWN_INTERFACE": "nothing on that interface can forward",
    "ACL_BLOCK": "traffic is silently discarded, which looks like a dead link",
    "TRUNK_MISMATCH": "a VLAN is reachable on one switch and not the other",
    "ROUTING_LOOP": "packets circulate until their TTL expires",
    "DHCP_MISCONFIGURATION": "clients receive a gateway they cannot use",
    "DUPLICATE_IP": "two hosts answer for one address, giving intermittent connectivity",
    "OVERLAPPING_SUBNET": "the device cannot tell which interface a destination belongs to",
}

_COMMANDS = {
    "WRONG_VLAN": ["show vlan brief", "show interfaces switchport"],
    "INVALID_MASK": ["show ip interface brief"],
    "WRONG_GATEWAY": ["show ip interface brief", "show ip route"],
    "MISSING_STATIC_ROUTE": ["show ip route"],
    "SHUTDOWN_INTERFACE": ["show interfaces", "show ip interface brief"],
    "ACL_BLOCK": ["show access-lists", "show ip interface"],
    "TRUNK_MISMATCH": ["show interfaces trunk"],
    "ROUTING_LOOP": ["show ip route", "traceroute"],
    "DHCP_MISCONFIGURATION": ["show running-config | section dhcp"],
    "DUPLICATE_IP": ["show ip interface brief", "show arp"],
    "OVERLAPPING_SUBNET": ["show ip interface brief"],
}

_HIGH = {"DUPLICATE_IP", "ROUTING_LOOP", "INVALID_MASK", "OVERLAPPING_SUBNET"}
_MEDIUM = {"WRONG_GATEWAY", "WRONG_VLAN", "MISSING_STATIC_ROUTE", "TRUNK_MISMATCH", "DHCP_MISCONFIGURATION"}
_LOW = {"ACL_BLOCK", "SHUTDOWN_INTERFACE"}


def _severity_for(kind: str) -> Severity:
    if kind in _HIGH:
        return Severity.HIGH
    if kind in _MEDIUM:
        return Severity.MEDIUM
    if kind in _LOW:
        return Severity.LOW
    return Severity.INFO


def _describe(kind: str, entry: dict) -> str:
    base = _DESCRIPTIONS.get(kind, kind.replace("_", " ").lower())
    where = " ".join(x for x in (entry.get("device"), entry.get("interface")) if x)
    return f"{where}: {base}" if where else base


def _why(kind: str) -> str:
    return _WHY.get(kind, "this may prevent expected connectivity")


def _commands_for(kind: str) -> list[str]:
    return list(_COMMANDS.get(kind, []))


#: How an operational check's status is presented in the report.
_RUNTIME_STATUS = {
    "OBSERVED": Status.OBSERVED,
    "INCONCLUSIVE": Status.UNRESOLVED,
    "UNAVAILABLE": Status.NOT_CHECKED,
    "UNSUPPORTED": Status.UNSUPPORTED,
    "FAILED": Status.UNRESOLVED,
    "NOT_ATTEMPTED": Status.NOT_CHECKED,
}


def merge_operational_checks(report: NetworkReport, deep) -> NetworkReport:
    """Fold Deep Analyze results into a report.

    An observed check becomes a fact on both devices; anything else becomes an
    explicit "not checked" or "unresolved" entry. Nothing here can turn a runtime
    result into a configuration fact, and an unavailable simulator produces a
    stated gap rather than a silent absence.
    """
    report.overview["runtime_available"] = bool(getattr(deep, "available", False))
    report.overview["runtime_reason"] = getattr(deep, "reason", "")
    report.overview["runtime_version"] = getattr(deep, "simulator_version", "")
    report.overview["source_intact"] = bool(getattr(deep, "source_intact", True))

    by_name = {section.name: section for section in report.sections}
    for check in getattr(deep, "checks", []):
        status = _RUNTIME_STATUS.get(check.status.value, Status.UNRESOLVED)
        if check.status.value == "OBSERVED":
            answer = check.detail.split(":")[0] if check.detail else check.status.value
            evidence = [
                f"PDU {check.source} -> {check.destination}",
                f"simulator {check.simulator_version}",
                f"session {check.session_id}",
            ]
            for device in (check.source, check.destination):
                section = by_name.get(device)
                if section is None:
                    continue
                section.questions.append(
                    QandA(
                        question=f"Can {device} reach {check.destination if device == check.source else check.source}?",
                        answer=answer,
                        status=Status.OBSERVED,
                        evidence=evidence,
                        limitation="an observed result for this path under these conditions",
                    )
                )
                section.basics.append(
                    (
                        "Operational connectivity",
                        f"{answer} to {check.destination if device == check.source else check.source}",
                    )
                )
        else:
            for device in (check.source, check.destination):
                section = by_name.get(device)
                if section is None:
                    continue
                section.questions.append(
                    QandA(
                        question=f"Can {device} reach the other device?",
                        answer=None,
                        status=status,
                        limitation=check.detail or check.status.value,
                    )
                )
        if not check.observed and check.detail:
            report.unsupported_checks.append(
                f"runtime {check.source}->{check.destination}: {check.status.value} "
                f"({check.detail})"
            )
    return report


def analyze_network(model: NetworkModel, coverage: CoverageMatrix | None = None) -> NetworkReport:
    """Build the full device-by-device report."""
    return Analyzer(model, coverage).build()


def stream_sections(model: NetworkModel, coverage: CoverageMatrix | None = None):
    """Yield ``("overview", dict)``, then ``("section", dict)`` per device, then
    ``("findings", dict)`` and ``("coverage", dict)``.

    This is the shape the streaming endpoint uses. Each device is yielded as soon
    as its own facts are assembled, so a large lab renders progressively instead of
    showing one status line until everything is done.
    """
    analyzer = Analyzer(model, coverage)
    findings: list[DeviceFinding] = [
        finding for group in analyzer._findings_by_device.values() for finding in group
    ]
    yield "overview", analyzer._overview(findings)
    for device in analyzer._ordered_devices():
        yield "section", analyzer.section(device).as_dict()
    yield "findings", {
        "network_findings": [
            f.as_dict() for f in findings if not f.device or f.device == "network"
        ]
    }
    yield "coverage", {
        "unsupported_checks": analyzer._unsupported_checks(),
        "coverage": analyzer.coverage.summary(),
        "warnings": list(model.warnings),
    }


def iter_sections(model: NetworkModel, coverage: CoverageMatrix | None = None):
    """Yield sections one at a time, for streaming.

    Yielding per device is what lets the UI render a device as soon as its facts
    exist, rather than after the whole network is analysed.
    """
    analyzer = Analyzer(model, coverage)
    for device in analyzer._ordered_devices():
        yield analyzer.section(device)


__all__ = [
    "Analyzer",
    "DeviceFinding",
    "DeviceSection",
    "NetworkReport",
    "QandA",
    "Severity",
    "Status",
    "analyze_network",
    "iter_sections",
    "merge_operational_checks",
    "stream_sections",
]
