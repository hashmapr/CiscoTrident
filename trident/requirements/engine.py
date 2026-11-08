"""Deterministic extraction of configuration requirements from lab instructions.

This is a **rule engine**, not a language model. Each source line is matched
against a fixed, auditable set of regular expressions. If no rule recognises a
line the line becomes ``UNSUPPORTED``; if a rule recognises the intent but a
required slot (device, interface, address, VLAN id, next hop) is not literally
present the line becomes ``AMBIGUOUS``. No handler ever supplies a value that
the text does not contain, and no handler ever invents a device name.

Purity contract:

* no file reads, no network, no time, no randomness, no model calls;
* the same input always produces the identical list, in source order;
* ids are sequential (``REQ-0001`` ...) so output is stable and diffable.
"""

from __future__ import annotations

import ipaddress
import re

from ..normalization.values import canonical_interface_name, mask_to_prefix
from .model import Requirement, RequirementKind, RequirementStatus

# ---------------------------------------------------------------------------
# Token grammars
# ---------------------------------------------------------------------------

#: A device name as it appears in Packet Tracer / NetAcad lab sheets: R1, SW2,
#: WLC1, PC-A, Core-Router. No dots or slashes so it can never swallow an IP.
_DEVICE = r"[A-Za-z][A-Za-z0-9_-]*"

#: An interface token: Gi0/1, Fa0/5, GigabitEthernet0/0, Se0/0/0, Vlan10.
_IFACE = r"[A-Za-z][A-Za-z-]*\d[\d/.:]*"

_IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"
_CIDR4 = rf"{_IPV4}/\d{{1,2}}"
_CIDR6 = r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,}/\d{1,3}"
_VLAN_ID = r"\d{1,4}"

#: Words that can never be a device name even though they match ``_DEVICE``.
_DEVICE_STOP = {
    "a", "acl", "add", "address", "all", "an", "and", "apply", "as", "assign",
    "be", "between", "bring", "by", "can", "check", "client", "clients",
    "computer", "computers", "configure", "confirm", "connect", "create",
    "default", "device", "devices", "dhcp", "dns", "endpoint", "endpoints",
    "ensure", "everyone", "for", "from", "gateway", "give", "host", "hostname",
    "hosts", "in", "interface", "into", "ip", "ipv4", "ipv6", "it", "its",
    "mask", "move", "nat", "network", "no", "of", "on", "or", "ospf", "pc",
    "pcs", "place", "port", "put", "route", "server", "set", "shutdown", "ssh",
    "ssid", "static", "subnet", "test", "that", "the", "then", "this", "to",
    "trunk", "up", "use", "user", "users", "verify", "vlan", "wlan",
    "wireless", "with", "workstation", "workstations",
    # quantifiers and pronouns that are never device names
    "one", "two", "three", "four", "five", "six", "both", "each", "every",
    "any", "some", "other", "others", "their", "them", "they",
    "these", "those", "same", "own",
    # plural device nouns used in group-scope phrasing
    "routers", "router", "switches", "switch", "firewalls", "firewall",
    "servers", "printers", "laptops", "phones", "tablets", "end",
}

#: Canonical interface prefixes produced by ``canonical_interface_name``.
_IFACE_PREFIXES = {
    "GigabitEthernet", "FastEthernet", "Ethernet", "TenGigabitEthernet",
    "Serial", "Loopback", "Vlan", "Port-channel", "Management", "Tunnel",
    "BVI", "Async", "Wireless", "Wlan-GigabitEthernet", "Cellular", "Dialer",
    "Virtual-Template",
}

_BULLET_RE = re.compile(r"^\s*(?:[-*\u2022]|\d{1,2}[.)])\s*")
_STEP_RE = re.compile(r"^\s*(?:step\s*\d+\s*[:.)-]?)\s*", re.IGNORECASE)
_WS_RE = re.compile(r"\s+")


def _normalise(raw: str) -> str:
    """Collapse whitespace and drop list numbering / step prefixes."""
    line = _WS_RE.sub(" ", (raw or "").strip())
    line = _BULLET_RE.sub("", line)
    line = _STEP_RE.sub("", line)
    return line.strip()


def _canonical_iface(token: str | None) -> str | None:
    """Canonical interface name, or None when the token is not an interface."""
    if not token:
        return None
    canon = canonical_interface_name(token)
    m = re.match(r"([A-Za-z][A-Za-z-]*)", canon)
    if not m:
        return None
    return canon if m.group(1) in _IFACE_PREFIXES else None


def _is_device(token: str | None) -> bool:
    if not token:
        return False
    if token.lower() in _DEVICE_STOP:
        return False
    if _canonical_iface(token) is not None:
        return False
    return bool(re.fullmatch(_DEVICE, token))


def _device_named(line: str) -> str | None:
    """First token in the line that is a plausible, non-interface device name."""
    for match in re.finditer(_DEVICE, line):
        token = match.group(0)
        if _is_device(token):
            return token
    return None


_AFTER_RE = re.compile(
    rf"(?:on|to|for|of)\s+(?:the\s+)?(?:interface\s+|port\s+)?"
    rf"(?P<dev>{_DEVICE})(?:'s)?"
    rf"(?:\s+(?:interface\s+|port\s+)?(?P<iface>{_IFACE}))?",
    re.IGNORECASE,
)
_IFACE_OF_RE = re.compile(
    rf"(?P<iface>{_IFACE})\s+(?:on|of)\s+(?P<dev>{_DEVICE})", re.IGNORECASE
)
_DEV_IFACE_PAIR_RE = re.compile(rf"(?P<dev>{_DEVICE})\s+(?P<iface>{_IFACE})", re.IGNORECASE)


def _target_from(match: re.Match[str] | None) -> tuple[str | None, str | None]:
    if match is None:
        return None, None
    dev = match.groupdict().get("dev")
    iface = match.groupdict().get("iface")
    return (dev if _is_device(dev) else None), _canonical_iface(iface)


def _find_target(line: str, segment: str | None = None) -> tuple[str | None, str | None]:
    """Locate a named device and interface, preferring text after an address.

    Returns ``(device, interface)`` with ``None`` for anything not stated.
    Never substitutes a value.
    """
    if segment:
        dev, iface = _target_from(_AFTER_RE.search(segment))
        if dev or iface:
            return dev, iface

    dev, iface = _target_from(_AFTER_RE.search(line))
    if dev or iface:
        return dev, iface

    dev, iface = _target_from(_IFACE_OF_RE.search(line))
    if dev or iface:
        return dev, iface

    dev, iface = _target_from(_DEV_IFACE_PAIR_RE.search(line))
    if dev or iface:
        return dev, iface

    return None, None


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _req(
    req_id: str,
    kind: RequirementKind,
    *,
    device: str | None,
    interface: str | None,
    expected: str,
    source_text: str,
    source_line: int,
    status: RequirementStatus = RequirementStatus.PARSED,
    confidence: str = "explicit",
    notes: list[str] | None = None,
) -> Requirement:
    return Requirement(
        id=req_id,
        kind=kind,
        device=device,
        interface=interface,
        expected=expected,
        source_text=source_text,
        source_line=source_line,
        status=status,
        confidence=confidence,
        notes=list(notes or []),
    )


def _valid_v4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def _valid_v6(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return True


def _v4_kind(address: str, prefix: int) -> RequirementKind:
    """Classify a v4 value: network address -> SUBNET, host address -> ADDRESS."""
    try:
        net = ipaddress.IPv4Network(f"{address}/{prefix}", strict=False)
    except ValueError:
        return RequirementKind.IPV4_ADDRESS
    if prefix <= 30 and str(net.network_address) == address:
        return RequirementKind.IPV4_SUBNET
    return RequirementKind.IPV4_ADDRESS


# ---------------------------------------------------------------------------
# Rules — each returns a Requirement or None (None = "not my grammar")
# ---------------------------------------------------------------------------

_HOSTNAME_PATTERNS = (
    re.compile(
        rf"\b(?:set|configure|change|assign)\s+(?:the\s+)?hostname\s+(?:of\s+)?"
        rf"(?P<dev>{_DEVICE})\s+(?:to|as)\s+(?P<host>[A-Za-z][A-Za-z0-9_-]*)",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:set|configure|change)\s+(?P<dev>{_DEVICE})(?:'s)?\s+hostname\s+"
        rf"(?:to|as)\s+(?P<host>[A-Za-z][A-Za-z0-9_-]*)",
        re.IGNORECASE,
    ),
)
_HOSTNAME_LOOSE_RE = re.compile(
    r"\bhostname\b.*?\b(?:to|as)\s+(?P<host>[A-Za-z][A-Za-z0-9_-]*)", re.IGNORECASE
)


def _match_hostname(line: str, raw: str, lineno: int, req_id: str) -> Requirement | None:
    """'Set the hostname of SW1 to CoreSwitch' -> SECURITY.

    The enum has no HOSTNAME member; per the Phase 2 contract hostname
    hardening is reported under SECURITY.
    """
    for pattern in _HOSTNAME_PATTERNS:
        m = pattern.search(line)
        if not m:
            continue
        dev = m.group("dev") if _is_device(m.group("dev")) else None
        host = m.group("host")
        if dev is None:
            return _req(
                req_id, RequirementKind.SECURITY, device=None, interface=None,
                expected=f"hostname {host}", source_text=raw, source_line=lineno,
                status=RequirementStatus.AMBIGUOUS,
                notes=["device not named in the instruction"],
            )
        return _req(
            req_id, RequirementKind.SECURITY, device=dev, interface=None,
            expected=f"hostname {host}", source_text=raw, source_line=lineno,
        )

    if "hostname" not in line.lower():
        return None
    m = _HOSTNAME_LOOSE_RE.search(line)
    if not m:
        return None
    return _req(
        req_id, RequirementKind.SECURITY, device=None, interface=None,
        expected=f"hostname {m.group('host')}", source_text=raw, source_line=lineno,
        status=RequirementStatus.AMBIGUOUS,
        notes=["device not named in the instruction"],
    )


_TRUNK_STRICT_RE = re.compile(
    rf"\b(?:create|configure|set\s+up|establish|build)\s+(?:an?\s+)?trunk\s+between\s+"
    rf"(?P<d1>{_DEVICE})\s+(?P<i1>{_IFACE})\s+and\s+(?P<d2>{_DEVICE})\s+(?P<i2>{_IFACE})",
    re.IGNORECASE,
)
_TRUNK_LOOSE_RE = re.compile(r"\btrunk\b\s+between\b|\bbetween\b.*\btrunk\b", re.IGNORECASE)


def _match_trunk(line: str, raw: str, lineno: int, req_id: str) -> Requirement | None:
    m = _TRUNK_STRICT_RE.search(line)
    if m:
        d1, d2 = m.group("d1"), m.group("d2")
        i1, i2 = _canonical_iface(m.group("i1")), _canonical_iface(m.group("i2"))
        if not (_is_device(d1) and _is_device(d2) and i1 and i2):
            return None
        return _req(
            req_id, RequirementKind.TRUNK, device=d1, interface=i1,
            expected=f"trunk {d1} {i1} <-> {d2} {i2}",
            source_text=raw, source_line=lineno,
            notes=[f"peer endpoint: {d2} {i2}"],
        )

    if not _TRUNK_LOOSE_RE.search(line):
        return None
    dev = _device_named(line)
    return _req(
        req_id, RequirementKind.TRUNK, device=dev, interface=None,
        expected="trunk", source_text=raw, source_line=lineno,
        status=RequirementStatus.AMBIGUOUS,
        notes=["both trunk endpoints and their interfaces must be stated"],
    )


_DEFAULT_RE = re.compile(r"\bdefault\s+(?:route|gateway)\b", re.IGNORECASE)
_IP_ROUTE_RE = re.compile(
    rf"\bip\s+route\s+(?P<dest>{_IPV4})\s+(?P<mask>{_IPV4})\s+(?P<nh>{_IPV4})",
    re.IGNORECASE,
)
_DEV_AFTER_RE = re.compile(
    rf"\b(?:on|for|of)\s+(?:the\s+)?(?P<dev>{_DEVICE})(?:'s)?\b", re.IGNORECASE
)
_NH_RE = re.compile(
    rf"\b(?:pointing\s+to|points\s+to|via|through|towards?|to)\s+(?P<nh>{_IPV4})\b",
    re.IGNORECASE,
)
_STATIC_RE = re.compile(r"\bstatic\s+route\b", re.IGNORECASE)
_ROUTE_WORD_RE = re.compile(r"\broute\b", re.IGNORECASE)
_DYNAMIC_PROTO_RE = re.compile(r"\b(?:ospf|eigrp|rip|bgp|isis)\b", re.IGNORECASE)
_NET_IN_TAIL_RE = re.compile(rf"(?P<cidr>{_CIDR4})|(?P<ip>{_IPV4})\s+(?P<mask>{_IPV4})", re.IGNORECASE)


def _route_expected(kind: RequirementKind, network: str | None, nh: str | None) -> str:
    if kind is RequirementKind.DEFAULT_ROUTE:
        return f"0.0.0.0/0 via {nh}" if nh else "0.0.0.0/0"
    if network and nh:
        return f"{network} via {nh}"
    if network:
        return network
    return "static route"


def _match_route(line: str, raw: str, lineno: int, req_id: str) -> Requirement | None:
    """Default route, ``ip route`` form, and explicit static routes."""

    # --- 'default route|gateway' wording -----------------------------------
    if _DEFAULT_RE.search(line):
        dev_m = _DEV_AFTER_RE.search(line)
        dev = dev_m.group("dev") if dev_m and _is_device(dev_m.group("dev")) else None
        nh_m = _NH_RE.search(line)
        nh = nh_m.group("nh") if nh_m and _valid_v4(nh_m.group("nh")) else None
        if dev is None:
            return _req(
                req_id, RequirementKind.DEFAULT_ROUTE, device=None, interface=None,
                expected=_route_expected(RequirementKind.DEFAULT_ROUTE, None, nh),
                source_text=raw, source_line=lineno,
                status=RequirementStatus.AMBIGUOUS,
                notes=["device not named in the instruction"],
            )
        if nh is None:
            return _req(
                req_id, RequirementKind.DEFAULT_ROUTE, device=dev, interface=None,
                expected="0.0.0.0/0", source_text=raw, source_line=lineno,
                status=RequirementStatus.AMBIGUOUS,
                notes=["next hop not stated"],
            )
        return _req(
            req_id, RequirementKind.DEFAULT_ROUTE, device=dev, interface=None,
            expected=_route_expected(RequirementKind.DEFAULT_ROUTE, None, nh),
            source_text=raw, source_line=lineno,
        )

    # --- 'ip route <dest> <mask> <next-hop>' config form --------------------
    m = _IP_ROUTE_RE.search(line)
    if m:
        dest, mask, nh = m.group("dest"), m.group("mask"), m.group("nh")
        prefix = mask_to_prefix(mask)
        if not (_valid_v4(dest) and prefix is not None and _valid_v4(nh)):
            return None
        network = f"{dest}/{prefix}"
        kind = RequirementKind.DEFAULT_ROUTE if prefix == 0 else RequirementKind.STATIC_ROUTE
        dev = _device_named(line)
        if dev is None:
            return _req(
                req_id, kind, device=None, interface=None,
                expected=_route_expected(kind, network, nh),
                source_text=raw, source_line=lineno,
                status=RequirementStatus.AMBIGUOUS,
                notes=["device not named in the instruction"],
            )
        return _req(
            req_id, kind, device=dev, interface=None,
            expected=_route_expected(kind, network, nh),
            source_text=raw, source_line=lineno,
        )

    # --- explicit 'static route' -------------------------------------------
    static_m = _STATIC_RE.search(line)
    inferred = False
    if static_m:
        tail = line[static_m.end():]
    else:
        if not _ROUTE_WORD_RE.search(line) or _DYNAMIC_PROTO_RE.search(line):
            return None
        route_m = _ROUTE_WORD_RE.search(line)
        tail = line[route_m.end():]
        inferred = True

    net_m = _NET_IN_TAIL_RE.search(tail)
    network: str | None = None
    nh_search_from = 0
    if net_m:
        if net_m.group("cidr"):
            raw_net = net_m.group("cidr")
            addr, _, prefix_s = raw_net.partition("/")
            if _valid_v4(addr) and 0 <= int(prefix_s) <= 32:
                network = f"{addr}/{int(prefix_s)}"
                nh_search_from = net_m.end()
        else:
            addr, mask = net_m.group("ip"), net_m.group("mask")
            prefix = mask_to_prefix(mask)
            if _valid_v4(addr) and prefix is not None:
                network = f"{addr}/{prefix}"
                nh_search_from = net_m.end()

    nh_m = _NH_RE.search(tail[nh_search_from:])
    nh = nh_m.group("nh") if nh_m and _valid_v4(nh_m.group("nh")) else None

    dev_m = _DEV_AFTER_RE.search(tail)
    dev = dev_m.group("dev") if dev_m and _is_device(dev_m.group("dev")) else None

    if not static_m and not inferred:
        return None
    if not (static_m or (network and nh)):
        return None

    notes: list[str] = []
    confidence = "explicit"
    if inferred:
        confidence = "inferred"
        notes.append("route type inferred: explicit destination + next hop, no dynamic protocol named")

    if dev is None:
        notes.append("device not named in the instruction")
        return _req(
            req_id, RequirementKind.STATIC_ROUTE, device=None, interface=None,
            expected=_route_expected(RequirementKind.STATIC_ROUTE, network, nh),
            source_text=raw, source_line=lineno,
            status=RequirementStatus.AMBIGUOUS, confidence=confidence, notes=notes,
        )
    if network is None:
        notes.append("destination network not stated")
        return _req(
            req_id, RequirementKind.STATIC_ROUTE, device=dev, interface=None,
            expected="static route", source_text=raw, source_line=lineno,
            status=RequirementStatus.AMBIGUOUS, confidence=confidence, notes=notes,
        )
    if nh is None:
        notes.append("next hop not stated")
        return _req(
            req_id, RequirementKind.STATIC_ROUTE, device=dev, interface=None,
            expected=network, source_text=raw, source_line=lineno,
            status=RequirementStatus.AMBIGUOUS, confidence=confidence, notes=notes,
        )

    kind = RequirementKind.DEFAULT_ROUTE if network == "0.0.0.0/0" else RequirementKind.STATIC_ROUTE
    return _req(
        req_id, kind, device=dev, interface=None,
        expected=_route_expected(kind, network, nh),
        source_text=raw, source_line=lineno, confidence=confidence, notes=notes,
    )


_VLAN_GROUP_RE = re.compile(
    r"\b(?:place|put|assign|move|connect|set)\s+"
    r"(?P<group>(?:all|every)\s+(?:the\s+)?(?:PCs?|hosts?|computers?|workstations?|"
    r"end\s?devices?|endpoints?|users?|clients?)|everyone|all)\s+"
    r"(?:on|in|into|to)\s+vlan\s+(?P<vid>\d{1,4})",
    re.IGNORECASE,
)
_VLAN_GROUP_REVERSED_RE = re.compile(
    r"\b(?:configure|assign|set|apply)\s+vlan\s+(?P<vid>\d{1,4})\s+"
    r"(?:on|for|to)\s+(?P<group>all\s+(?:the\s+)?(?:PCs?|hosts?|computers?|"
    r"workstations?|end\s?devices?)|everyone|all)\b",
    re.IGNORECASE,
)
_VLAN_PORT_RE = re.compile(
    rf"\b(?:assign|set|configure|put|place)\s+(?:the\s+)?(?:vlan\s+)?(?P<vid>{_VLAN_ID})\s+to\s+"
    rf"(?:the\s+)?(?:port\s+|interface\s+)?(?P<iface>{_IFACE})\s+(?:port\s+)?"
    rf"(?:on|of)\s+(?P<dev>{_DEVICE})",
    re.IGNORECASE,
)
_VLAN_IFACE_FIRST_RE = re.compile(
    rf"\b(?:assign|set|configure|put|place|add)\s+(?:the\s+)?(?:port\s+|interface\s+)?"
    rf"(?P<iface>{_IFACE})\s+(?:port\s+)?(?:on\s+(?P<dev>{_DEVICE})\s+)?"
    rf"(?:to|into|in)\s+vlan\s+(?P<vid>{_VLAN_ID})",
    re.IGNORECASE,
)
_VLAN_LOOSE_RE = re.compile(
    rf"\b(?:assign|place|put|set)\s+(?:the\s+)?vlan\s+(?P<vid>{_VLAN_ID})\s+"
    rf"(?:to|on)\s+(?:the\s+)?(?P<dev>{_DEVICE})\b",
    re.IGNORECASE,
)
_VLAN_CREATE_RE = re.compile(
    rf"\b(?:configure|create)\s+vlan\s+(?P<vid>{_VLAN_ID})\s+on\s+(?P<dev>{_DEVICE})\b",
    re.IGNORECASE,
)


def _vlan_problem(vid: int) -> str | None:
    if 1 <= vid <= 4094:
        return None
    return f"VLAN id {vid} is outside the valid 1-4094 range"


def _match_vlan(line: str, raw: str, lineno: int, req_id: str) -> Requirement | None:
    m = _VLAN_GROUP_RE.search(line) or _VLAN_GROUP_REVERSED_RE.search(line)
    if m:
        vid = int(m.group("vid"))
        group = _WS_RE.sub(" ", m.group("group").strip())
        problem = _vlan_problem(vid)
        notes = [f"group scope: {group}; no specific device named"]
        if problem:
            notes.append(problem)
        return _req(
            req_id, RequirementKind.VLAN_ASSIGNMENT, device=None, interface=None,
            expected=f"vlan {vid}", source_text=raw, source_line=lineno,
            status=RequirementStatus.AMBIGUOUS if problem else RequirementStatus.PARSED,
            confidence="inferred", notes=notes,
        )

    m = _VLAN_PORT_RE.search(line) or _VLAN_IFACE_FIRST_RE.search(line)
    if m:
        vid = int(m.group("vid"))
        dev = m.groupdict().get("dev")
        dev = dev if _is_device(dev) else None
        iface = _canonical_iface(m.groupdict().get("iface"))
        problem = _vlan_problem(vid)
        notes = [problem] if problem else []
        if dev is None:
            notes.append("device not named in the instruction")
        if iface is None:
            notes.append("port/interface not stated")
        status = RequirementStatus.PARSED
        if problem or dev is None or iface is None:
            status = RequirementStatus.AMBIGUOUS
        return _req(
            req_id, RequirementKind.VLAN_ASSIGNMENT, device=dev, interface=iface,
            expected=f"vlan {vid}", source_text=raw, source_line=lineno,
            status=status, notes=notes,
        )

    m = _VLAN_LOOSE_RE.search(line)
    if m:
        vid = int(m.group("vid"))
        dev = m.group("dev") if _is_device(m.group("dev")) else None
        notes = ["target port/interface not stated"]
        problem = _vlan_problem(vid)
        if problem:
            notes.append(problem)
        if dev is None:
            notes.append("device not named in the instruction")
        return _req(
            req_id, RequirementKind.VLAN_ASSIGNMENT, device=dev, interface=None,
            expected=f"vlan {vid}", source_text=raw, source_line=lineno,
            status=RequirementStatus.AMBIGUOUS, notes=notes,
        )

    m = _VLAN_CREATE_RE.search(line)
    if m:
        vid = int(m.group("vid"))
        dev = m.group("dev") if _is_device(m.group("dev")) else None
        notes = ["VLAN creation without a port assignment; no interface to test"]
        problem = _vlan_problem(vid)
        if problem:
            notes.append(problem)
        return _req(
            req_id, RequirementKind.VLAN_ASSIGNMENT, device=dev, interface=None,
            expected=f"vlan {vid}", source_text=raw, source_line=lineno,
            status=RequirementStatus.AMBIGUOUS, notes=notes,
        )

    return None


_SSH_RE = re.compile(
    r"\b(?:enable|configure|set\s+up|allow|turn\s+on)\s+(?:the\s+)?ssh\b(.*)$",
    re.IGNORECASE,
)
_SSH_BARE_RE = re.compile(rf"\bssh\s+(?:on|for)\s+(?P<dev>{_DEVICE})\b", re.IGNORECASE)


def _match_ssh(line: str, raw: str, lineno: int, req_id: str) -> Requirement | None:
    m = _SSH_RE.search(line)
    if m:
        tail = m.group(1)
        dev_m = re.search(rf"\b(?:on|for)\s+(?:the\s+)?(?P<dev>{_DEVICE})\b", tail, re.IGNORECASE)
        dev = dev_m.group("dev") if dev_m and _is_device(dev_m.group("dev")) else None
        if dev is None:
            return _req(
                req_id, RequirementKind.SSH, device=None, interface=None,
                expected="ssh enabled", source_text=raw, source_line=lineno,
                status=RequirementStatus.AMBIGUOUS,
                notes=["device not named in the instruction"],
            )
        return _req(
            req_id, RequirementKind.SSH, device=dev, interface=None,
            expected="ssh enabled", source_text=raw, source_line=lineno,
            notes=["SSH requires a local username and domain name; verify both"],
        )

    m = _SSH_BARE_RE.search(line)
    if m and _is_device(m.group("dev")):
        return _req(
            req_id, RequirementKind.SSH, device=m.group("dev"), interface=None,
            expected="ssh enabled", source_text=raw, source_line=lineno,
        )
    return None


_IFACE_ENABLE_RE = re.compile(
    rf"\b(?:enable|bring\s+up|unshut|no\s+shutdown|turn\s+on)\s+(?:the\s+)?"
    rf"(?:interface\s+|port\s+)?(?P<iface>{_IFACE})\s+(?:interface\s+)?"
    rf"(?:on|of)\s+(?P<dev>{_DEVICE})",
    re.IGNORECASE,
)
_NO_SHUT_RE = re.compile(
    rf"\bno\s+shutdown\s+(?:on|of)\s+(?P<dev>{_DEVICE})\s+(?P<iface>{_IFACE})",
    re.IGNORECASE,
)
_IFACE_ENABLE_LOOSE_RE = re.compile(
    rf"\b(?:enable|bring\s+up|unshut|turn\s+on)\s+(?:the\s+)?(?:interface\s+|port\s+)?"
    rf"(?P<iface>{_IFACE})\b",
    re.IGNORECASE,
)


def _match_interface_enable(line: str, raw: str, lineno: int, req_id: str) -> Requirement | None:
    for pattern in (_IFACE_ENABLE_RE, _NO_SHUT_RE):
        m = pattern.search(line)
        if not m:
            continue
        iface = _canonical_iface(m.group("iface"))
        dev = m.group("dev") if _is_device(m.group("dev")) else None
        if iface is None:
            continue
        notes = []
        if dev is None:
            notes.append("device not named in the instruction")
        return _req(
            req_id, RequirementKind.INTERFACE_ENABLE, device=dev, interface=iface,
            expected="no shutdown", source_text=raw, source_line=lineno,
            status=RequirementStatus.PARSED if dev else RequirementStatus.AMBIGUOUS,
            notes=notes,
        )

    m = _IFACE_ENABLE_LOOSE_RE.search(line)
    if m:
        iface = _canonical_iface(m.group("iface"))
        if iface is None:
            return None
        return _req(
            req_id, RequirementKind.INTERFACE_ENABLE, device=None, interface=iface,
            expected="no shutdown", source_text=raw, source_line=lineno,
            status=RequirementStatus.AMBIGUOUS,
            notes=["device not named in the instruction"],
        )
    return None


_OSPF_RE = re.compile(
    r"\b(?:configure|enable|set\s+up|run)\s+(?:the\s+)?ospf"
    r"(?:\s+process\s+(?P<proc>\d+))?\b(?P<tail>.*)$",
    re.IGNORECASE,
)
_OSPF_NETWORK_RE = re.compile(
    rf"network\s+(?P<net>{_IPV4})\s+(?P<wild>{_IPV4})\s+area\s+(?P<area>\d+)", re.IGNORECASE
)


def _match_ospf(line: str, raw: str, lineno: int, req_id: str) -> Requirement | None:
    m = _OSPF_RE.search(line)
    if not m:
        return None
    tail = m.group("tail") or ""
    dev_m = re.search(rf"\b(?:on|for)\s+(?:the\s+)?(?P<dev>{_DEVICE})\b", tail, re.IGNORECASE)
    dev = dev_m.group("dev") if dev_m and _is_device(dev_m.group("dev")) else None

    parts = ["ospf"]
    if m.group("proc"):
        parts.append(f"process {m.group('proc')}")
    net_m = _OSPF_NETWORK_RE.search(tail)
    if net_m:
        parts.append(
            f"network {net_m.group('net')} {net_m.group('wild')} area {net_m.group('area')}"
        )
    expected = " ".join(parts)

    if dev is None:
        return _req(
            req_id, RequirementKind.OSPF, device=None, interface=None,
            expected=expected, source_text=raw, source_line=lineno,
            status=RequirementStatus.AMBIGUOUS,
            notes=["device not named in the instruction"],
        )
    return _req(
        req_id, RequirementKind.OSPF, device=dev, interface=None,
        expected=expected, source_text=raw, source_line=lineno,
    )


_DHCP_RE = re.compile(
    r"\b(?:configure|enable|set\s+up|create|add)\s+(?:a\s+)?dhcp"
    r"(?:\s+(?P<what>pool|server))?\b(?P<tail>.*)$",
    re.IGNORECASE,
)
_DHCP_POOL_RE = re.compile(r"\bpool\s+(?P<pool>[A-Za-z0-9_-]+)", re.IGNORECASE)
_DHCP_NET_RE = re.compile(rf"\bnetwork\s+(?P<net>{_IPV4})\s+(?P<mask>{_IPV4})", re.IGNORECASE)


def _match_dhcp(line: str, raw: str, lineno: int, req_id: str) -> Requirement | None:
    m = _DHCP_RE.search(line)
    if not m:
        return None
    tail = m.group("tail") or ""
    dev_m = re.search(rf"\b(?:on|for)\s+(?:the\s+)?(?P<dev>{_DEVICE})\b", tail, re.IGNORECASE)
    dev = dev_m.group("dev") if dev_m and _is_device(dev_m.group("dev")) else None

    parts = ["dhcp"]
    if m.group("what"):
        parts.append(m.group("what").lower())
    pool_m = _DHCP_POOL_RE.search(tail)
    if pool_m:
        parts.append(pool_m.group("pool"))
    net_m = _DHCP_NET_RE.search(tail)
    if net_m:
        prefix = mask_to_prefix(net_m.group("mask"))
        net = f"{net_m.group('net')}/{prefix}" if prefix is not None else net_m.group("net")
        parts.append(f"network {net}")
    expected = " ".join(parts)

    if dev is None:
        return _req(
            req_id, RequirementKind.DHCP, device=None, interface=None,
            expected=expected, source_text=raw, source_line=lineno,
            status=RequirementStatus.AMBIGUOUS,
            notes=["device not named in the instruction"],
        )
    return _req(
        req_id, RequirementKind.DHCP, device=dev, interface=None,
        expected=expected, source_text=raw, source_line=lineno,
    )


_DNS_RE = re.compile(
    rf"\b(?:configure|set|use|add)\s+(?:a\s+)?dns(?:\s+server)?\s*"
    rf"(?P<server>{_IPV4})?(?P<tail>.*)$",
    re.IGNORECASE,
)


def _match_dns(line: str, raw: str, lineno: int, req_id: str) -> Requirement | None:
    m = _DNS_RE.search(line)
    if not m:
        return None
    server = m.group("server")
    tail = m.group("tail") or ""
    dev_m = re.search(rf"\b(?:on|for)\s+(?:the\s+)?(?P<dev>{_DEVICE})\b", tail, re.IGNORECASE)
    if dev_m is None:
        dev_m = re.search(rf"\b(?:on|for)\s+(?:the\s+)?(?P<dev>{_DEVICE})\b", line, re.IGNORECASE)
    dev = dev_m.group("dev") if dev_m and _is_device(dev_m.group("dev")) else None

    if server is not None and not _valid_v4(server):
        return None
    expected = f"dns server {server}" if server else "dns server configured"

    if dev is None:
        return _req(
            req_id, RequirementKind.DNS, device=None, interface=None,
            expected=expected, source_text=raw, source_line=lineno,
            status=RequirementStatus.AMBIGUOUS,
            notes=["device not named in the instruction"],
        )
    return _req(
        req_id, RequirementKind.DNS, device=dev, interface=None,
        expected=expected, source_text=raw, source_line=lineno,
    )


_NAT_RE = re.compile(
    r"\b(?:configure|enable|set\s+up|apply)\s+(?:the\s+)?"
    r"(?P<kind>static\s+nat|dynamic\s+nat|nat|pat)\b(?P<tail>.*)$",
    re.IGNORECASE,
)


def _match_nat(line: str, raw: str, lineno: int, req_id: str) -> Requirement | None:
    m = _NAT_RE.search(line)
    if not m:
        return None
    kind_word = _WS_RE.sub(" ", m.group("kind").lower())
    tail = m.group("tail") or ""
    dev_m = re.search(rf"\b(?:on|for)\s+(?:the\s+)?(?P<dev>{_DEVICE})\b", tail, re.IGNORECASE)
    dev = dev_m.group("dev") if dev_m and _is_device(dev_m.group("dev")) else None

    if dev is None:
        return _req(
            req_id, RequirementKind.NAT, device=None, interface=None,
            expected=kind_word, source_text=raw, source_line=lineno,
            status=RequirementStatus.AMBIGUOUS,
            notes=["device not named in the instruction"],
        )
    return _req(
        req_id, RequirementKind.NAT, device=dev, interface=None,
        expected=kind_word, source_text=raw, source_line=lineno,
    )


_ACL_NUMBERED_RE = re.compile(
    r"\b(?:configure|create|apply|add)\s+(?:an?\s+)?(?:standard\s+|extended\s+)?acl\s+"
    r"(?P<aclid>\d{1,4})\b(?P<tail>.*)$",
    re.IGNORECASE,
)
_ACL_NAMED_RE = re.compile(
    r"\b(?:configure|create|apply|add)\s+(?:an?\s+)?(?:standard\s+|extended\s+)?"
    r"(?:named\s+acl\s+(?P<name>[A-Za-z][A-Za-z0-9_-]*)|acl)(?P<tail>.*)$",
    re.IGNORECASE,
)


def _match_acl(line: str, raw: str, lineno: int, req_id: str) -> Requirement | None:
    m = _ACL_NUMBERED_RE.search(line)
    aclid: str | None = None
    tail = ""
    if m:
        aclid = m.group("aclid")
        tail = m.group("tail") or ""
    else:
        m = _ACL_NAMED_RE.search(line)
        if not m:
            return None
        aclid = m.group("name")
        tail = m.group("tail") or ""

    dev_m = re.search(rf"\b(?:on|for)\s+(?:the\s+)?(?P<dev>{_DEVICE})\b", tail, re.IGNORECASE)
    dev = dev_m.group("dev") if dev_m and _is_device(dev_m.group("dev")) else None

    expected = f"acl {aclid}" if aclid else "acl"
    if dev is None:
        return _req(
            req_id, RequirementKind.ACL, device=None, interface=None,
            expected=expected, source_text=raw, source_line=lineno,
            status=RequirementStatus.AMBIGUOUS,
            notes=["device not named in the instruction"],
        )
    return _req(
        req_id, RequirementKind.ACL, device=dev, interface=None,
        expected=expected, source_text=raw, source_line=lineno,
    )


_WIRELESS_RE = re.compile(
    r"\b(?:configure|set|create|add)\s+(?:the\s+)?(?:ssid|wireless\s+network|wlan)\b"
    r"\s*(?P<ssid>(?!(?:on|for|to|in|with)\b)[A-Za-z][A-Za-z0-9_-]*)?(?P<tail>.*)$",
    re.IGNORECASE,
)


def _match_wireless(line: str, raw: str, lineno: int, req_id: str) -> Requirement | None:
    m = _WIRELESS_RE.search(line)
    if not m:
        return None
    ssid = m.group("ssid")
    tail = m.group("tail") or ""
    dev_m = re.search(rf"\b(?:on|for)\s+(?:the\s+)?(?P<dev>{_DEVICE})\b", tail, re.IGNORECASE)
    if dev_m is None:
        dev_m = re.search(rf"\b(?:on|for)\s+(?:the\s+)?(?P<dev>{_DEVICE})\b", line, re.IGNORECASE)
    dev = dev_m.group("dev") if dev_m and _is_device(dev_m.group("dev")) else None

    expected = f"ssid {ssid}" if ssid else "ssid configured"
    if dev is None:
        return _req(
            req_id, RequirementKind.WIRELESS, device=None, interface=None,
            expected=expected, source_text=raw, source_line=lineno,
            status=RequirementStatus.AMBIGUOUS,
            notes=["device not named in the instruction"],
        )
    return _req(
        req_id, RequirementKind.WIRELESS, device=dev, interface=None,
        expected=expected, source_text=raw, source_line=lineno,
    )


_CONNECTIVITY_RE = re.compile(
    rf"\b(?:verify|ensure|confirm|check|test)?\s*(?:that\s+)?"
    rf"(?P<src>(?:all|every)\s+(?:the\s+)?(?:PCs?|hosts?|computers?)|{_DEVICE}|everyone)\s+"
    rf"(?:can|should\s+be\s+able\s+to|must\s+be\s+able\s+to|is\s+able\s+to)\s+"
    rf"ping\s+(?P<dst>[A-Za-z0-9_.:-]+)",
    re.IGNORECASE,
)


def _match_connectivity(line: str, raw: str, lineno: int, req_id: str) -> Requirement | None:
    m = _CONNECTIVITY_RE.search(line)
    if not m:
        return None
    src = _WS_RE.sub(" ", m.group("src").strip())
    dst = m.group("dst")
    if _is_device(src):
        return _req(
            req_id, RequirementKind.CONNECTIVITY, device=src, interface=None,
            expected=f"{src} -> {dst} (ping)", source_text=raw, source_line=lineno,
        )
    return _req(
        req_id, RequirementKind.CONNECTIVITY, device=None, interface=None,
        expected=f"{src} -> {dst} (ping)", source_text=raw, source_line=lineno,
        confidence="inferred",
        notes=[f"group scope: {src}; no specific device named"],
    )


_IPV4_CIDR_RE = re.compile(rf"\b(?P<addr>{_IPV4})/(?P<prefix>\d{{1,2}})\b")
_IPV4_MASK_RE = re.compile(rf"\b(?P<addr>{_IPV4})\s+(?P<mask>{_IPV4})\b")
_IPV6_CIDR_RE = re.compile(rf"\b(?P<addr>{_CIDR6})\b")


def _match_address(line: str, raw: str, lineno: int, req_id: str) -> Requirement | None:
    """IPv4 (CIDR or dotted mask), IPv4 subnet, and IPv6 address."""

    # --- IPv6 -------------------------------------------------------------
    m6 = _IPV6_CIDR_RE.search(line)
    if m6 and ":" in m6.group("addr"):
        token = m6.group("addr")
        addr, _, prefix_s = token.partition("/")
        if _valid_v6(addr):
            dev, iface = _find_target(line, line[m6.end():])
            notes = []
            status = RequirementStatus.PARSED
            if dev is None:
                notes.append("device not named in the instruction")
                status = RequirementStatus.AMBIGUOUS
            elif iface is None:
                notes.append("interface not stated")
                status = RequirementStatus.AMBIGUOUS
            return _req(
                req_id, RequirementKind.IPV6_ADDRESS, device=dev, interface=iface,
                expected=f"{ipaddress.IPv6Address(addr)}/{int(prefix_s)}",
                source_text=raw, source_line=lineno, status=status, notes=notes,
            )

    # --- IPv4 CIDR --------------------------------------------------------
    m4 = _IPV4_CIDR_RE.search(line)
    if m4:
        addr, prefix = m4.group("addr"), int(m4.group("prefix"))
        if not _valid_v4(addr) or prefix > 32:
            return _req(
                req_id, RequirementKind.IPV4_ADDRESS, device=None, interface=None,
                expected=f"{addr}/{prefix}", source_text=raw, source_line=lineno,
                status=RequirementStatus.AMBIGUOUS,
                notes=["invalid IPv4 address or prefix length"],
            )
        dev, iface = _find_target(line, line[m4.end():])
        notes = []
        status = RequirementStatus.PARSED
        if dev is None:
            notes.append("device not named in the instruction")
            status = RequirementStatus.AMBIGUOUS
        elif iface is None:
            notes.append("interface not stated")
            status = RequirementStatus.AMBIGUOUS
        return _req(
            req_id, _v4_kind(addr, prefix), device=dev, interface=iface,
            expected=f"{addr}/{prefix}", source_text=raw, source_line=lineno,
            status=status, notes=notes,
        )

    # --- IPv4 + dotted mask ----------------------------------------------
    for m in _IPV4_MASK_RE.finditer(line):
        addr, mask = m.group("addr"), m.group("mask")
        prefix = mask_to_prefix(mask)
        if prefix is None or not _valid_v4(addr):
            continue
        dev, iface = _find_target(line, line[m.end():])
        notes = [f"mask {mask}"]
        status = RequirementStatus.PARSED
        if dev is None:
            notes.append("device not named in the instruction")
            status = RequirementStatus.AMBIGUOUS
        elif iface is None:
            notes.append("interface not stated")
            status = RequirementStatus.AMBIGUOUS
        return _req(
            req_id, _v4_kind(addr, prefix), device=dev, interface=iface,
            expected=f"{addr}/{prefix}", source_text=raw, source_line=lineno,
            status=status, notes=notes,
        )

    return None


#: Rule order matters. Intent keywords are resolved before the generic address
#: rule so that e.g. an ACL body containing ``10.0.0.0/8`` is classified as ACL.
_RULES = (
    _match_hostname,
    _match_trunk,
    _match_route,
    _match_vlan,
    _match_ssh,
    _match_interface_enable,
    _match_ospf,
    _match_dhcp,
    _match_dns,
    _match_nat,
    _match_acl,
    _match_wireless,
    _match_connectivity,
    _match_address,
)


def _unsupported(raw: str, lineno: int, req_id: str) -> Requirement:
    return _req(
        req_id, RequirementKind.UNKNOWN, device=None, interface=None,
        expected="", source_text=raw, source_line=lineno,
        status=RequirementStatus.UNSUPPORTED,
        notes=["no supported requirement grammar matched this line; line ignored"],
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_requirements(text: str) -> list[Requirement]:
    """Translate lab instruction text into structured requirements.

    One source line yields at most one :class:`Requirement`. Blank lines and
    pure list markers are skipped. Every non-blank line is accounted for: it is
    either ``PARSED``, ``AMBIGUOUS`` (intent recognised, slot missing) or
    ``UNSUPPORTED`` (no grammar matched).

    This function is pure: no I/O, no network, no model calls.
    """
    out: list[Requirement] = []
    for lineno, raw in enumerate((text or "").splitlines(), start=1):
        line = _normalise(raw)
        if not line:
            continue
        req_id = f"REQ-{len(out) + 1:04d}"
        requirement: Requirement | None = None
        for rule in _RULES:
            requirement = rule(line, raw.strip(), lineno, req_id)
            if requirement is not None:
                break
        out.append(requirement or _unsupported(raw.strip(), lineno, req_id))
    return out
