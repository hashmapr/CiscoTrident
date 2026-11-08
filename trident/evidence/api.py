"""The ingestion entry point: text in, one honest :class:`CliRecord` out.

``parse_cli_output`` is the only function the diagnostics engine needs. It
identifies the artefact, strips prompts, attributes a device when that is
unambiguous, dispatches to the kind-specific parser and records why anything
was not parsed.

It never invents a device, never invents a timestamp and never turns
unrecognised text into a best-effort guess.
"""

from __future__ import annotations

import re

from trident.normalization.configs import parse_running_config

from .detect import detect_kind, resolve_device, strip_prompts
from .parsers import (
    parse_access_lists,
    parse_etherchannel_summary,
    parse_interfaces_trunk,
    parse_ip_interface_brief,
    parse_ip_route,
    parse_ospf_neighbor,
    parse_spanning_tree,
    parse_vlan_brief,
)
from .types import SOURCE_BY_KIND, CliRecord, EvidenceKind, ParseStatus

_RUNTIME_PARSERS = {
    EvidenceKind.IP_INTERFACE_BRIEF: parse_ip_interface_brief,
    EvidenceKind.VLAN_BRIEF: parse_vlan_brief,
    EvidenceKind.INTERFACES_TRUNK: parse_interfaces_trunk,
    EvidenceKind.IP_ROUTE: parse_ip_route,
    EvidenceKind.ACCESS_LISTS: parse_access_lists,
    EvidenceKind.OSPF_NEIGHBOR: parse_ospf_neighbor,
    EvidenceKind.ETHERCHANNEL_SUMMARY: parse_etherchannel_summary,
    EvidenceKind.SPANNING_TREE: parse_spanning_tree,
}

#: Session markers that should appear at most once per pasted artefact.
#: A second occurrence means two outputs were concatenated, not one session.
#:
#: ``show running-config`` prints both "Building configuration..." and
#: "Current configuration : N bytes" as one banner, so the two are handled as a
#: single logical marker by :func:`_count_sessions`.
_SESSION_MARKERS: dict[EvidenceKind, re.Pattern[str]] = {
    EvidenceKind.RUNNING_CONFIG: re.compile(
        r"^(?:Current configuration|Building configuration)", re.IGNORECASE
    ),
    EvidenceKind.IP_INTERFACE_BRIEF: re.compile(
        r"\bIP-Address\b.*\bOK\?.*\bMethod\b.*\bStatus\b.*\bProtocol\b", re.IGNORECASE
    ),
    EvidenceKind.VLAN_BRIEF: re.compile(r"^VLAN\s+Name\s+Status\s+Ports\b", re.IGNORECASE),
    EvidenceKind.IP_ROUTE: re.compile(r"^Gateway of last resort\b", re.IGNORECASE),
    EvidenceKind.OSPF_NEIGHBOR: re.compile(r"^Neighbor\s+ID\s+Pri\b", re.IGNORECASE),
    EvidenceKind.ETHERCHANNEL_SUMMARY: re.compile(
        r"^Group\s+Port-channel\s+Protocol\b", re.IGNORECASE
    ),
}

_CURRENT_CONFIG_RE = re.compile(r"^Current configuration\b", re.IGNORECASE)
_BUILDING_CONFIG_RE = re.compile(r"^Building configuration\b", re.IGNORECASE)


def _count_sessions(kind: EvidenceKind, lines: list[str]) -> int:
    if kind is EvidenceKind.RUNNING_CONFIG:
        current = sum(1 for line in lines if _CURRENT_CONFIG_RE.search(line.strip()))
        if current:
            return current
        return max(1, sum(1 for line in lines if _BUILDING_CONFIG_RE.search(line.strip())))
    marker = _SESSION_MARKERS.get(kind)
    if marker is None:
        return 1
    return sum(1 for line in lines if marker.search(line.strip()))


def _config_to_dict(text_lines: list[str]) -> tuple[dict, bool]:
    cfg = parse_running_config(text_lines)
    parsed: dict = {
        "lines": text_lines,
        "hostname": cfg.hostname,
        "ios_version": cfg.ios_version,
        "default_gateway": cfg.default_gateway,
        "interfaces": {},
        "vlans": [],
        "routes": [],
        "acls": [],
    }
    for canonical, iface in cfg.interfaces.items():
        parsed["interfaces"][canonical] = {
            "name": iface.name,
            "description": iface.description,
            "ipv4_address": iface.ipv4_address,
            "subnet_mask": iface.subnet_mask,
            "prefix_length": iface.prefix_length,
            "ipv6_address": iface.ipv6_address,
            "admin_state": iface.admin_state,
            "speed": iface.speed,
            "duplex": iface.duplex,
            "access_vlan": iface.access_vlan,
            "trunk_allowed": list(iface.trunk_allowed),
            "native_vlan": iface.native_vlan,
            "switchport_mode": iface.switchport_mode,
            "acl_in": iface.acl_in,
            "acl_out": iface.acl_out,
        }
    parsed["vlans"] = [{"vlan_id": v.vlan_id, "name": v.name} for v in cfg.vlans]
    parsed["routes"] = [
        {
            "destination": r.destination,
            "next_hop": r.next_hop,
            "outgoing_interface": r.outgoing_interface,
            "route_type": r.route_type,
            "protocol": r.protocol,
            "raw": r.raw,
        }
        for r in cfg.routes
    ]
    parsed["acls"] = [
        {
            "acl_id": a.acl_id,
            "acl_type": a.acl_type,
            "action": a.action,
            "protocol": a.protocol,
            "source": a.source,
            "destination": a.destination,
            "sequence": a.sequence,
            "raw": a.raw,
        }
        for a in cfg.acls
    ]
    found = bool(cfg.hostname or cfg.interfaces or cfg.vlans or cfg.routes or cfg.acls)
    return parsed, found


def _parse_known(kind: EvidenceKind, lines: list[str]) -> tuple[dict | list, list[str], bool]:
    if kind is EvidenceKind.RUNNING_CONFIG:
        parsed, found = _config_to_dict(lines)
        return parsed, [], found
    parsed, notes, found = _RUNTIME_PARSERS[kind]("\n".join(lines))
    return parsed, list(notes), found


def parse_cli_output(
    text: str,
    *,
    device: str | None = None,
    captured_at: str | None = None,
) -> CliRecord:
    """Parse one pasted CLI artefact into a :class:`CliRecord`.

    ``device`` and ``captured_at`` are caller assertions and are carried through
    unchanged. When ``device`` is omitted the device is taken from an
    unambiguous prompt inside the paste; otherwise the record stays
    unattributed and is marked ``PARTIAL``.
    """
    raw_text = text if isinstance(text, str) else str(text)
    line_count = len(raw_text.splitlines())
    kind, _confidence = detect_kind(raw_text)

    if kind is EvidenceKind.UNKNOWN:
        return CliRecord(
            device=device,
            kind=EvidenceKind.UNKNOWN,
            source=SOURCE_BY_KIND[EvidenceKind.UNKNOWN],
            captured_at=captured_at,
            raw_text=raw_text,
            parsed={},
            status=ParseStatus.UNRECOGNISED,
            notes=("no recognised Cisco IOS show command in this paste",),
            line_count=line_count,
        )

    body_lines, prompt_devices, _echoes = strip_prompts(raw_text)
    notes: list[str] = []

    resolved_device, device_notes = resolve_device(device, prompt_devices)
    notes.extend(device_notes)

    multi_device = len({name.lower() for name in prompt_devices}) > 1
    sessions = _count_sessions(kind, body_lines)
    multi_session = sessions > 1
    if kind is EvidenceKind.RUNNING_CONFIG:
        hostnames = [
            line.strip() for line in body_lines if re.match(r"^hostname\s+\S+", line.strip())
        ]
        if len(hostnames) > 1:
            multi_session = True
            notes.append(
                f"paste contains {len(hostnames)} hostname declarations; "
                "it is not one device's configuration"
            )

    if multi_device or multi_session:
        if multi_session and not multi_device:
            notes.append(
                f"paste contains {sessions} separate command sessions; "
                "they are not merged and no device is attributed"
            )
        return CliRecord(
            device=None,
            kind=kind,
            source=SOURCE_BY_KIND[kind],
            captured_at=captured_at,
            raw_text=raw_text,
            parsed={},
            status=ParseStatus.PARTIAL,
            notes=tuple(notes),
            line_count=line_count,
        )

    parsed, parse_notes, found = _parse_known(kind, body_lines)
    notes.extend(parse_notes)

    if resolved_device is None:
        notes.append(
            "no device was supplied and the paste contains no unambiguous prompt; "
            "the record is unattributed"
        )
    if not found:
        notes.append("no parsable rows were found for the recognised command")

    status = ParseStatus.PARSED if (found and not notes and resolved_device is not None) else ParseStatus.PARTIAL

    return CliRecord(
        device=resolved_device,
        kind=kind,
        source=SOURCE_BY_KIND[kind],
        captured_at=captured_at,
        raw_text=raw_text,
        parsed=parsed,
        status=status,
        notes=tuple(notes),
        line_count=line_count,
    )
