"""Deterministic parser for Cisco IOS running-configuration text.

Every engine ultimately exposes the same artifact: a list of ``LINE`` strings
(the running config). Rather than trusting one engine's interpretation, TRIDENT
parses that artifact itself with a single, well-tested state machine, and records
*which engine supplied the text* as provenance.

This module contains no network I/O and no AI. It is pure and unit-testable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .values import canonical_interface_name, normalize_mac

# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class ParsedInterface:
    name: str
    canonical_name: str
    description: str | None = None
    ipv4_address: str | None = None
    subnet_mask: str | None = None
    prefix_length: int | None = None
    ipv6_address: str | None = None
    mac_address: str | None = None
    admin_state: str | None = None
    operational_state: str | None = None
    speed: str | None = None
    duplex: str | None = None
    access_vlan: str | None = None
    trunk_allowed: list[str] = field(default_factory=list)
    native_vlan: str | None = None
    switchport_mode: str | None = None
    helper_addresses: list[str] = field(default_factory=list)
    acl_in: str | None = None
    acl_out: str | None = None
    raw_lines: list[str] = field(default_factory=list)


@dataclass
class ParsedRoute:
    destination: str
    next_hop: str | None
    outgoing_interface: str | None
    route_type: str
    protocol: str | None
    raw: str


@dataclass
class ParsedVlan:
    vlan_id: int
    name: str | None
    raw: str


@dataclass
class ParsedAclEntry:
    acl_id: str
    acl_type: str
    action: str
    protocol: str | None
    source: str | None
    destination: str | None
    port_conditions: list[str]
    raw: str
    sequence: int | None = None


@dataclass
class ParsedConfig:
    hostname: str | None = None
    ios_version: str | None = None
    interfaces: dict[str, ParsedInterface] = field(default_factory=dict)
    routes: list[ParsedRoute] = field(default_factory=list)
    vlans: list[ParsedVlan] = field(default_factory=list)
    acls: list[ParsedAclEntry] = field(default_factory=list)
    default_gateway: str | None = None
    dns_servers: list[str] = field(default_factory=list)
    dhcp_pools: list[str] = field(default_factory=list)
    management: list[str] = field(default_factory=list)
    ntp_servers: list[str] = field(default_factory=list)
    line_count: int = 0

    def interface(self, name: str) -> ParsedInterface | None:
        key = canonical_interface_name(name)
        for iface in self.interfaces.values():
            if iface.canonical_name == key:
                return iface
        return None


# ---------------------------------------------------------------------------
# Mask helpers
# ---------------------------------------------------------------------------

def _mask_to_prefix(mask: str) -> int | None:
    try:
        parts = [int(p) for p in mask.split(".")]
    except (ValueError, AttributeError):
        return None
    if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
        return None
    bits = "".join(f"{p:08b}" for p in parts)
    if "01" in bits:  # non-contiguous mask
        return None
    return bits.count("1")


_VLAN_RANGE_RE = re.compile(r"^(\d+)(?:\s*-\s*(\d+))?$")


def _expand_vlan_list(text: str) -> list[str]:
    out: list[str] = []
    for chunk in text.replace(",", " ").split():
        m = _VLAN_RANGE_RE.match(chunk)
        if not m:
            continue
        if m.group(2):
            start, end = int(m.group(1)), int(m.group(2))
            if 0 < start <= end <= 4094 and end - start < 512:
                out.extend(str(v) for v in range(start, end + 1))
        else:
            out.append(m.group(1))
    return out


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

_INTERFACE_RE = re.compile(r"^interface\s+(\S+)\s*$", re.IGNORECASE)
_IP_ADDRESS_RE = re.compile(r"^ip address\s+(\d+\.\d+\.\d+\.\d+)\s*(\d+\.\d+\.\d+\.\d+)?", re.IGNORECASE)
_IP_ROUTE_RE = re.compile(
    r"^ip route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)(?:\s+(\d+))?", re.IGNORECASE
)
_VLAN_RE = re.compile(r"^vlan\s+(\d+)\s*$", re.IGNORECASE)
_ROUTE_PROTO_RE = re.compile(r"^(router|ip route)\s+(\S+)", re.IGNORECASE)
_NUMBERED_ACL_RE = re.compile(
    r"^access-list\s+(\d+)\s+(permit|deny)\s+(\S+)\s+(\S+)(?:\s+(\S+))?(?:\s+(.*))?$",
    re.IGNORECASE,
)
_NAMED_ACL_RE = re.compile(
    r"^(permit|deny)\s+(\S+)\s+(\S+)(?:\s+(\S+))?(?:\s+(.*))?$", re.IGNORECASE
)
_ACL_DECL_RE = re.compile(r"^ip access-list\s+(standard|extended)\s+(\S+)", re.IGNORECASE)


def parse_running_config(lines: list[str] | str) -> ParsedConfig:
    """Parse IOS running-config lines into a structured, deterministic model."""
    if isinstance(lines, str):
        lines = [ln.rstrip("\r") for ln in lines.splitlines()]

    cfg = ParsedConfig(line_count=len(lines))
    current: ParsedInterface | None = None
    current_vlan: ParsedVlan | None = None
    current_acl_id: str | None = None
    current_acl_type: str | None = None

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        # In IOS, '!' terminates the current configuration block. Without this,
        # a later top-level directive would be swallowed by the last interface.
        if line == "!":
            current = None
            current_vlan = None
            current_acl_id = None
            current_acl_type = None
            continue

        # ---- interface blocks -------------------------------------------------
        m = _INTERFACE_RE.match(line)
        if m:
            name = m.group(1)
            canonical = canonical_interface_name(name)
            current = ParsedInterface(name=name, canonical_name=canonical)
            cfg.interfaces[canonical] = current
            current_vlan = None
            current_acl_id = None
            continue

        # ---- vlan blocks ------------------------------------------------------
        m = _VLAN_RE.match(line)
        if m:
            vid = int(m.group(1))
            current_vlan = ParsedVlan(vlan_id=vid, name=None, raw=line)
            cfg.vlans.append(current_vlan)
            current = None
            current_acl_id = None
            continue

        # ---- named ACL blocks -------------------------------------------------
        m = _ACL_DECL_RE.match(line)
        if m:
            current_acl_type = m.group(1).lower()
            current_acl_id = m.group(2)
            current = None
            current_vlan = None
            continue

        if line.startswith("hostname "):
            cfg.hostname = line.split(None, 1)[1].strip()
            continue

        if line.startswith("version ") and cfg.ios_version is None:
            tail = line.split(None, 1)[1].strip()
            # 'version 15.1' at the top-level is the IOS version
            cfg.ios_version = tail
            continue

        if line.startswith("ip default-gateway "):
            cfg.default_gateway = line.split(None, 2)[2].strip()
            continue

        if line.startswith("ip name-server "):
            cfg.dns_servers.extend(line.split()[2:])
            continue

        if line.startswith("dns server "):  # Packet Tracer server DNS format is handled elsewhere
            cfg.dns_servers.extend(line.split()[2:])
            continue

        if line.startswith("ntp server "):
            parts = line.split()
            if len(parts) >= 3:
                cfg.ntp_servers.append(parts[2])
            continue

        if line.startswith("ip dhcp pool "):
            cfg.dhcp_pools.append(line.split(None, 3)[3].strip())
            continue

        if line.startswith(("username ", "enable secret ", "enable password ", "aaa ", "ip ssh ")):
            cfg.management.append(line)
            continue

        # ---- inside an interface ---------------------------------------------
        if current is not None:
            current.raw_lines.append(line)

            if line.startswith("description "):
                current.description = line.split(None, 1)[1].strip()
                continue
            if line.startswith("shutdown"):
                current.admin_state = "administratively down"
                continue
            if line.startswith("no shutdown"):
                current.admin_state = "up"
                continue
            if line.startswith("speed "):
                current.speed = line.split(None, 1)[1].strip()
                continue
            if line.startswith("duplex "):
                current.duplex = line.split(None, 1)[1].strip()
                continue
            if line.startswith("mac-address "):
                current.mac_address = normalize_mac(line.split(None, 1)[1].strip())
                continue

            m = _IP_ADDRESS_RE.match(line)
            if m:
                current.ipv4_address = m.group(1)
                if m.group(2):
                    current.subnet_mask = m.group(2)
                    current.prefix_length = _mask_to_prefix(m.group(2))
                else:
                    current.subnet_mask = "255.255.255.255"
                    current.prefix_length = 32
                continue
            if line in {"no ip address", "no ipv4 address"}:
                current.ipv4_address = None
                current.subnet_mask = None
                current.prefix_length = None
                continue

            if line.startswith("ipv6 address "):
                token = line.split()[2]
                if "/" in token and not token.lower().startswith("autoconfig"):
                    current.ipv6_address = token
                continue

            if line.startswith("switchport mode "):
                current.switchport_mode = line.split(None, 2)[2].strip()
                continue
            if line.startswith("switchport access vlan "):
                current.access_vlan = line.split()[-1]
                continue
            if line.startswith("switchport trunk allowed vlan "):
                payload = line[len("switchport trunk allowed vlan "):]
                payload = payload.replace("add", "").replace("remove", "").strip()
                current.trunk_allowed = _expand_vlan_list(payload)
                continue
            if line.startswith("switchport trunk native vlan "):
                current.native_vlan = line.split()[-1]
                continue
            if line.startswith("ip helper-address "):
                current.helper_addresses.append(line.split()[-1])
                continue
            if line.startswith("ip access-group "):
                parts = line.split()
                if len(parts) >= 4:
                    if parts[3].lower() == "in":
                        current.acl_in = parts[2]
                    elif parts[3].lower() == "out":
                        current.acl_out = parts[2]
                continue
            continue

        # ---- inside a VLAN block ---------------------------------------------
        if current_vlan is not None:
            current_vlan.raw += "\n" + line
            if line.startswith("name "):
                current_vlan.name = line.split(None, 1)[1].strip()
            continue

        # ---- inside a named ACL block ----------------------------------------
        if current_acl_id is not None:
            m = _NAMED_ACL_RE.match(line)
            if m:
                action, proto = m.group(1).lower(), m.group(2).lower()
                src = m.group(3) if m.group(3) else None
                dst = m.group(4) if m.group(4) else None
                extra = (m.group(5) or "").split()
                cfg.acls.append(
                    ParsedAclEntry(
                        acl_id=current_acl_id,
                        acl_type=current_acl_type or "extended",
                        action=action,
                        protocol=proto,
                        source=src,
                        destination=dst,
                        port_conditions=extra,
                        raw=line,
                    )
                )
                continue
            # named ACL may end when a non-ACE line appears
            if not line.startswith(("remark", "evaluate", "log")):
                current_acl_id = None

        # ---- top-level numbered ACLs -----------------------------------------
        m = _NUMBERED_ACL_RE.match(line)
        if m:
            num = int(m.group(1))
            cfg.acls.append(
                ParsedAclEntry(
                    acl_id=m.group(1),
                    acl_type="standard" if 1 <= num <= 99 or 1300 <= num <= 1999 else "extended",
                    action=m.group(2).lower(),
                    protocol=m.group(3).lower(),
                    source=m.group(4),
                    destination=m.group(5),
                    port_conditions=(m.group(6) or "").split(),
                    raw=line,
                )
            )
            continue

        # ---- static routes ----------------------------------------------------
        m = _IP_ROUTE_RE.match(line)
        if m:
            cfg.routes.append(
                ParsedRoute(
                    destination=m.group(1),
                    next_hop=m.group(3) if not _looks_like_interface(m.group(3)) else None,
                    outgoing_interface=m.group(3) if _looks_like_interface(m.group(3)) else None,
                    route_type="static",
                    protocol="static",
                    raw=line,
                )
            )
            continue

        # ---- dynamic routing protocols ---------------------------------------
        if line.startswith("router "):
            proto = line.split(None, 1)[1].strip()
            cfg.management.append(f"routing-protocol:{proto}")
            continue

        if line.startswith("network ") and any(
            x.startswith("routing-protocol:") for x in cfg.management
        ):
            cfg.routes.append(
                ParsedRoute(
                    destination=line.split(None, 1)[1].strip(),
                    next_hop=None,
                    outgoing_interface=None,
                    route_type="dynamic",
                    protocol=cfg.management[-1].split(":", 1)[1],
                    raw=line,
                )
            )
            continue

    return cfg


def _looks_like_interface(token: str) -> bool:
    return bool(re.match(r"^[A-Za-z][A-Za-z\-]*\d", token))


def collect_switchport_vlans(cfg: ParsedConfig) -> dict[str, list[str]]:
    """Map VLAN id -> member interface names (access + trunk allowances)."""
    members: dict[str, list[str]] = {}
    for iface in cfg.interfaces.values():
        if iface.access_vlan:
            members.setdefault(iface.access_vlan, []).append(iface.name)
        for v in iface.trunk_allowed:
            members.setdefault(v, []).append(iface.name)
    return members
