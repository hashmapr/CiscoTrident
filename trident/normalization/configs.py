"""Deterministic parser for Cisco IOS running-configuration text.

Every engine ultimately exposes the same artifact: a list of ``LINE`` strings
(the running config). Rather than trusting one engine's interpretation, TRIDENT
parses that artifact itself with a single, well-tested state machine, and records
*which engine supplied the text* as provenance.

This module contains no network I/O and no AI. It is pure and unit-testable.
"""

from __future__ import annotations

import ipaddress
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
    #: Per-pool settings, keyed by pool name, in declaration order.
    dhcp_pool_details: dict[str, dict] = field(default_factory=dict)
    #: Addresses reserved via ``ip dhcp excluded-address``.
    dhcp_excluded: list[str] = field(default_factory=list)
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


def _consume_address(tokens: list[str], index: int) -> tuple[str | None, int]:
    """Read one ACE address operand, returning ``(value, next_index)``.

    IOS writes an address in three shapes:

    * ``any``                       -> ``"any"``
    * ``host 10.1.1.1``             -> ``"host 10.1.1.1"``
    * ``10.0.0.0 0.255.255.255``    -> ``"10.0.0.0 0.255.255.255"``

    The wildcard belongs to the address it qualifies. Treating it as a separate
    operand is what previously put ``0.255.255.255`` into the destination slot and
    pushed the real destination into the port list.
    """
    if index >= len(tokens):
        return None, index
    token = tokens[index]
    low = token.lower()
    if low == "any":
        return "any", index + 1
    if low == "host":
        if index + 1 < len(tokens):
            return f"host {tokens[index + 1]}", index + 2
        return "host", index + 1
    # A bare address followed by a wildcard-shaped token is a network + wildcard.
    if index + 1 < len(tokens) and _looks_like_wildcard(tokens[index + 1]):
        return f"{token} {tokens[index + 1]}", index + 2
    return token, index + 1


def _looks_like_wildcard(token: str) -> bool:
    """True for a dotted-quad mask operand (wildcard or inverted mask)."""
    parts = token.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def parse_ace_tokens(tokens: list[str]) -> tuple[str, str | None, str | None, str | None, list[str]]:
    """Parse one access-control entry body into ``(action, protocol, source, destination, rest)``.

    Handles the standard and extended shapes by position and by operand type, not
    by a single regex with fixed group numbers. A standard ACL carries no
    protocol, so ``permit 192.168.1.0 0.0.0.255`` treats the address as the
    source.
    """
    if not tokens:
        return "", None, None, None, []
    action = tokens[0].lower()
    if action not in {"permit", "deny"}:
        return "", None, None, None, tokens

    body = tokens[1:]
    if not body:
        return action, None, None, None, []

    # Standard ACL: the first operand is already an address rather than a protocol.
    if body[0].lower() in {"any", "host"} or _looks_like_wildcard(body[0]) or _is_ipv4(body[0]):
        source, index = _consume_address(body, 0)
        return action, None, source, None, body[index:]

    protocol = body[0].lower()
    source, index = _consume_address(body, 1)
    destination, index = _consume_address(body, index)
    return action, protocol, source, destination, body[index:]


#: Commands that appear inside an ``ip dhcp pool`` block. Used to recognise a
#: pool body without relying on indentation, which Packet Tracer's XML strips.
_DHCP_BODY_KEYWORDS = frozenset({"network", "default-router", "dns-server", "lease", "domain-name"})


def _is_ipv4(token: str) -> bool:
    try:
        ipaddress.IPv4Address(token)
        return True
    except ValueError:
        return False


def parse_running_config(lines: list[str] | str) -> ParsedConfig:
    """Parse IOS running-config lines into a structured, deterministic model."""
    if isinstance(lines, str):
        lines = [ln.rstrip("\r") for ln in lines.splitlines()]

    cfg = ParsedConfig(line_count=len(lines))
    current: ParsedInterface | None = None
    current_vlan: ParsedVlan | None = None
    current_acl_id: str | None = None
    current_acl_type: str | None = None
    current_dhcp_pool: str | None = None

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

        # ---- line blocks (line vty / line con / line aux) ----------------------
        # These are config blocks, but not interface blocks. They must still
        # *close* an open interface block: without this, `line vty 0 4` left
        # `current` pointing at the last interface, and every later top-level
        # command (`ip route`, `ip default-gateway`, ...) was swallowed as an
        # interface sub-command. That is why R1 parsed with zero routes despite
        # having a perfectly well-formed `ip route` line.
        if line.startswith(("line vty", "line con", "line aux")):
            current = None
            current_vlan = None
            current_acl_id = None
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

        if line.startswith("ip dhcp excluded-address "):
            parts = line.split()
            # `ip dhcp excluded-address A.B.C.D [E.F.G.H]` reserves either one
            # address or an inclusive range; both ends are recorded so a
            # gateway inside the range is recognised as reserved.
            cfg.dhcp_excluded.extend(parts[3:5])
            continue

        # ---- DHCP pool body --------------------------------------------------
        # A pool's `network`, `default-router` and `dns-server` live in its body,
        # not on the `ip dhcp pool NAME` header line. Only the name used to be
        # captured, so no detector could tell a correct pool from a broken one.
        # A pool body carries no reliable indentation once the config has been
        # round-tripped through Packet Tracer's <LINE> elements, which strip it.
        # Recognise the four body keywords instead: they are unambiguous inside
        # a pool and cannot be confused with a top-level command.
        if current_dhcp_pool is not None and line.split(" ", 1)[0] in _DHCP_BODY_KEYWORDS:
            body = line
            details = cfg.dhcp_pool_details.setdefault(current_dhcp_pool, {})
            if body.startswith("network "):
                parts = body.split()
                if len(parts) >= 3:
                    details["network"] = parts[1]
                    details["mask"] = parts[2]
            elif body.startswith("default-router "):
                details["default_router"] = body.split(None, 1)[1].strip()
            elif body.startswith("dns-server "):
                details["dns_servers"] = body.split()[1:]
            elif body.startswith("lease "):
                details["lease"] = body.split(None, 1)[1].strip()
            continue

        if line.startswith("ip dhcp pool "):
            pool_name = line.split(None, 3)[3].strip()
            cfg.dhcp_pools.append(pool_name)
            cfg.dhcp_pool_details.setdefault(pool_name, {})
            current_dhcp_pool = pool_name
            continue
        current_dhcp_pool = None

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
                action, protocol, source, destination, rest = parse_ace_tokens(line.split())
                cfg.acls.append(
                    ParsedAclEntry(
                        acl_id=current_acl_id,
                        acl_type=current_acl_type or "extended",
                        action=action,
                        protocol=protocol,
                        source=source,
                        destination=destination,
                        port_conditions=rest,
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
            action, protocol, source, destination, rest = parse_ace_tokens(
                line.split()[2:]
            )
            cfg.acls.append(
                ParsedAclEntry(
                    acl_id=m.group(1),
                    acl_type="standard" if 1 <= num <= 99 or 1300 <= num <= 1999 else "extended",
                    action=action,
                    protocol=protocol,
                    source=source,
                    destination=destination,
                    port_conditions=rest,
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
            # A `network` statement inside `router rip`/`eigrp`/`ospf` nominates a
            # major network for advertisement; it is not a route entry. Recording
            # it as one invents a forwarding path to the network *address* only
            # (`192.168.1.0` was read as `192.168.1.0/32`), which made a router
            # with no route to 192.168.1.1 look able to reach it.
            #
            # The statement is retained as configuration, so callers can still see
            # that the protocol advertises the network, but it is not a route.
            cfg.management.append(f"advertised-network:{line.split(None, 1)[1].strip()}")
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
