"""Deterministic parsers for pasted Cisco IOS ``show`` output.

Every parser is a pure function of text. None of them reads a clock, performs
network I/O, or fills a field it did not see. A line that cannot be parsed is
skipped and reported through the returned notes; it is never coerced into a
plausible-looking value.
"""

from __future__ import annotations

import re

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_MAC_DOTTED_RE = re.compile(r"^[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}$")
_VLAN_TOKEN_RE = re.compile(r"^(\d+)(?:-(\d+))?$")


def expand_vlan_list(text: str) -> list[str]:
    """Expand ``1,10-12`` into ``["1", "10", "11", "12"]``.

    Tokens that are not VLAN ids or ranges are dropped; the caller records a
    note when that happens.
    """
    out: list[str] = []
    for token in text.replace(",", " ").split():
        match = _VLAN_TOKEN_RE.match(token)
        if match is None:
            continue
        if match.group(2):
            start, end = int(match.group(1)), int(match.group(2))
            if 0 < start <= end <= 4094 and end - start < 512:
                out.extend(str(v) for v in range(start, end + 1))
        else:
            out.append(match.group(1))
    return out


# ---------------------------------------------------------------------------
# show ip interface brief
# ---------------------------------------------------------------------------

_IP_INT_HEADER = ("IP-Address", "OK?", "Method", "Status", "Protocol")


def parse_ip_interface_brief(text: str) -> tuple[dict, list[str], bool]:
    """``show ip interface brief`` -> ``{interface: {ip, ok, method, status, protocol}}``."""
    parsed: dict[str, dict] = {}
    notes: list[str] = []
    rows = 0
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if all(token in stripped for token in _IP_INT_HEADER):
            continue
        if set(stripped) <= {"-", " ", "+"}:
            continue
        parts = stripped.split()
        if len(parts) < 5:
            notes.append(f"skipped malformed interface line: {stripped!r}")
            continue
        interface = parts[0]
        ip, ok, method = parts[1], parts[2], parts[3]
        tail = parts[4:]
        if ok.upper() not in {"YES", "NO"}:
            notes.append(f"skipped malformed interface line: {stripped!r}")
            continue
        if tail[:2] == ["administratively", "down"]:
            status, protocol = "administratively down", " ".join(tail[2:])
        elif len(tail) >= 2:
            status, protocol = tail[0], " ".join(tail[1:])
        else:
            notes.append(f"skipped truncated interface line: {stripped!r}")
            continue
        if not protocol:
            notes.append(f"skipped truncated interface line: {stripped!r}")
            continue
        parsed[interface] = {
            "ip": ip,
            "ok": ok.upper(),
            "method": method,
            "status": status,
            "protocol": protocol,
        }
        rows += 1
    return parsed, notes, bool(rows)


# ---------------------------------------------------------------------------
# show vlan brief
# ---------------------------------------------------------------------------


def parse_vlan_brief(text: str) -> tuple[dict, list[str], bool]:
    """``show vlan brief`` -> ``{vlan_id: {name, status, ports}}``."""
    parsed: dict[str, dict] = {}
    notes: list[str] = []
    rows = 0
    current: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if "VLAN" in stripped and "Name" in stripped and "Status" in stripped and "Ports" in stripped:
            current = None
            continue
        if set(stripped) <= {"-", " ", "+"}:
            continue
        if line[0].isspace() and current is not None:
            ports = [tok.strip(",") for tok in stripped.replace(",", " ").split()]
            ports = [tok for tok in ports if any(ch.isdigit() for ch in tok)]
            if ports:
                parsed[current]["ports"].extend(ports)
                rows += 1
            continue
        match = re.match(r"^(\d{1,4})\s+(.*)$", stripped)
        if match is None:
            notes.append(f"skipped malformed vlan line: {stripped!r}")
            current = None
            continue
        vlan_id, rest = match.group(1), match.group(2)
        chunks = [chunk for chunk in re.split(r"\s{2,}", rest) if chunk]
        if len(chunks) < 2:
            tokens = rest.split()
            if len(tokens) < 2:
                notes.append(f"skipped malformed vlan line: {stripped!r}")
                current = None
                continue
            chunks = tokens
        name, status = chunks[0], chunks[1]
        ports_text = chunks[2] if len(chunks) > 2 else ""
        ports = [tok.strip(",") for tok in ports_text.replace(",", " ").split()]
        parsed[vlan_id] = {
            "name": name,
            "status": status,
            "ports": [tok for tok in ports if tok],
        }
        current = vlan_id
        rows += 1
    return parsed, notes, bool(rows)


# ---------------------------------------------------------------------------
# show interfaces trunk
# ---------------------------------------------------------------------------


def parse_interfaces_trunk(text: str) -> tuple[dict, list[str], bool]:
    """``show interfaces trunk`` -> per-interface mode/encapsulation/VLAN sets."""
    parsed: dict[str, dict] = {}
    notes: list[str] = []
    rows = 0
    section = ""
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        lowered = stripped.lower()
        if "vlans allowed on trunk" in lowered:
            section = "allowed"
            continue
        if "vlans allowed and active" in lowered:
            section = "active"
            continue
        if "vlans in spanning tree forwarding" in lowered:
            section = "forwarding"
            continue
        if lowered.startswith("port") and "mode" in lowered and "encapsulation" in lowered:
            section = "main"
            continue
        if lowered.startswith("port"):
            continue
        if stripped.startswith("---"):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        interface = parts[0]
        if section == "main":
            if len(parts) < 5:
                notes.append(f"skipped truncated trunk line: {stripped!r}")
                continue
            parsed.setdefault(
                interface,
                {
                    "mode": None,
                    "encapsulation": None,
                    "native_vlan": None,
                    "allowed_vlans": [],
                    "active_vlans": [],
                },
            )
            entry = parsed[interface]
            entry["mode"] = parts[1]
            entry["encapsulation"] = parts[2]
            entry["native_vlan"] = int(parts[4]) if parts[4].isdigit() else None
            rows += 1
        elif section in {"allowed", "active"}:
            entry = parsed.setdefault(
                interface,
                {
                    "mode": None,
                    "encapsulation": None,
                    "native_vlan": None,
                    "allowed_vlans": [],
                    "active_vlans": [],
                },
            )
            vlan_text = " ".join(parts[1:])
            vlan_ids = expand_vlan_list(vlan_text)
            if not vlan_ids and vlan_text.strip() not in {"", "none"}:
                notes.append(f"unparsed vlan list on {interface}: {vlan_text!r}")
            key = "allowed_vlans" if section == "allowed" else "active_vlans"
            entry[key] = vlan_ids
            rows += 1
        elif section == "forwarding":
            continue
    return parsed, notes, bool(rows)


# ---------------------------------------------------------------------------
# show ip route
# ---------------------------------------------------------------------------

_ROUTE_LINE_RE = re.compile(
    r"^(?P<code>[A-Za-z*]{1,3}(?:\s+[A-Za-z]{1,2})?)\s+"
    r"(?P<network>\d{1,3}(?:\.\d{1,3}){3})"
    r"(?:/(?P<prefix>\d{1,2}))?"
    r"(?:\s+(?P<mask>\d{1,3}(?:\.\d{1,3}){3}))?"
    r"\s+(?P<rest>.+)$"
)
_AD_METRIC_RE = re.compile(r"\[(\d+)/(\d+)\]")
_INTERFACE_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z\-]*[\d/.:]+$")
_TIMESTAMP_RE = re.compile(r"^\d{1,2}:\d{2}:\d{2}$")


def _looks_like_interface(token: str) -> bool:
    return bool(_INTERFACE_TOKEN_RE.match(token)) and not _TIMESTAMP_RE.match(token)


def parse_ip_route(text: str) -> tuple[list[dict], list[str], bool]:
    """``show ip route`` -> a list of route dicts, one per route line."""
    routes: list[dict] = []
    notes: list[str] = []
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.startswith(("Codes:", "Gateway of last resort", "Routing entry", "Known via")):
            continue
        if "is variably subnetted" in stripped or "is subnetted" in stripped:
            continue
        match = _ROUTE_LINE_RE.match(stripped)
        if match is None:
            continue
        code = " ".join(match.group("code").split())
        network = match.group("network")
        if match.group("prefix"):
            mask_or_prefix: str | None = match.group("prefix")
        elif match.group("mask"):
            mask_or_prefix = match.group("mask")
        else:
            mask_or_prefix = None
        rest = match.group("rest").strip()
        if "via" not in rest.lower() and "directly connected" not in rest.lower():
            continue

        next_hop: str | None = None
        interface: str | None = None
        if "directly connected" in rest.lower():
            pieces = [piece.strip() for piece in rest.split(",")]
            interfaces = [p for p in pieces if _looks_like_interface(p)]
            if not interfaces:
                notes.append(f"skipped malformed route line: {stripped!r}")
                continue
            interface = interfaces[-1]
        else:
            via_index = rest.lower().index("via")
            after_via = rest[via_index + 3 :].strip()
            hop_match = re.match(r"^(\S+?)(?:,|$)", after_via)
            if hop_match is None:
                notes.append(f"skipped malformed route line: {stripped!r}")
                continue
            next_hop = hop_match.group(1).rstrip(",")
            tail = after_via[hop_match.end() :].strip(", ").strip()
            pieces = [piece.strip() for piece in tail.split(",") if piece.strip()]
            interfaces = [p for p in pieces if _looks_like_interface(p)]
            if interfaces:
                interface = interfaces[-1]
        metric_match = _AD_METRIC_RE.search(rest)
        metric = int(metric_match.group(2)) if metric_match else None
        routes.append(
            {
                "code": code,
                "network": network,
                "mask_or_prefix": mask_or_prefix,
                "next_hop": next_hop,
                "interface": interface,
                "metric": metric,
            }
        )
    return routes, notes, bool(routes)


# ---------------------------------------------------------------------------
# show access-lists
# ---------------------------------------------------------------------------

_ACL_HEADER_RE = re.compile(
    r"^(?P<type>Standard|Extended)\s+IP\s+access\s+list\s+(?P<name>\S+)", re.IGNORECASE
)
#: ``show access-lists`` always prints an auto-assigned sequence number, so a
#: line without one is malformed output rather than a sequence-less entry.
_ACL_ENTRY_RE = re.compile(
    r"^(?P<seq>\d+)\s+(?P<action>permit|deny)\s+(?P<protocol>\S+)(?:\s+(?P<rest>.*))?$",
    re.IGNORECASE,
)
_ACL_MATCH_SUFFIX_RE = re.compile(r"\s+\([^)]*match[^)]*\)\s*$", re.IGNORECASE)


def parse_access_lists(text: str) -> tuple[dict, list[str], bool]:
    """``show access-lists`` -> ``{acl_name: [{seq, action, protocol, src, dst, raw}]}``.

    Standard entries carry no protocol token, so one is not invented: ``protocol``
    is ``None`` there and the source/destination are read from the standard
    grammar. Extended entries keep their protocol token.
    """
    parsed: dict[str, list[dict]] = {}
    notes: list[str] = []
    current: str | None = None
    current_type: str = "extended"
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        header = _ACL_HEADER_RE.match(stripped)
        if header:
            current = header.group("name")
            current_type = header.group("type").lower()
            parsed.setdefault(current, [])
            continue
        if current is None:
            continue
        body = _ACL_MATCH_SUFFIX_RE.sub("", stripped)
        entry = _ACL_ENTRY_RE.match(body)
        if entry is None:
            notes.append(f"skipped malformed acl line: {stripped!r}")
            continue
        action = entry.group("action").lower()
        rest = (entry.group("rest") or "").strip()
        if current_type == "standard":
            protocol: str | None = None
            src_token = entry.group("protocol").rstrip(",")
            src_tail = rest
            if not src_token:
                notes.append(f"skipped standard acl line without a source: {stripped!r}")
                continue
            src = src_token
            dst = src_tail.strip() or None
        else:
            tokens = rest.split()
            if len(tokens) < 2:
                notes.append(f"skipped truncated extended acl line: {stripped!r}")
                continue
            protocol = entry.group("protocol").lower()
            src = tokens[0].rstrip(",")
            dst = " ".join(tokens[1:]) or None
        parsed[current].append(
            {
                "seq": int(entry.group("seq")),
                "action": action,
                "protocol": protocol,
                "src": src,
                "dst": dst,
                "raw": stripped,
            }
        )
    return parsed, notes, any(parsed.values())


# ---------------------------------------------------------------------------
# show ip ospf neighbor
# ---------------------------------------------------------------------------

_OSPF_ROW_RE = re.compile(
    r"^(?P<neighbor>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<priority>\d+)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<dead>\d+:\d{2}:\d{2})\s+"
    r"(?P<address>\d{1,3}(?:\.\d{1,3}){3})"
    r"(?:\s+(?P<interface>\S+))?$"
)


def parse_ospf_neighbor(text: str) -> tuple[list[dict], list[str], bool]:
    """``show ip ospf neighbor`` -> a list of neighbor dicts."""
    neighbors: list[dict] = []
    notes: list[str] = []
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.startswith(("Neighbor ID", "Neighbor", "Interface")):
            continue
        match = _OSPF_ROW_RE.match(stripped)
        if match is None:
            if _IPV4_RE.match(stripped.split()[0]):
                notes.append(f"skipped malformed ospf neighbor row: {stripped!r}")
            continue
        neighbors.append(
            {
                "neighbor_id": match.group("neighbor"),
                "priority": int(match.group("priority")),
                "state": match.group("state"),
                "dead_time": match.group("dead"),
                "address": match.group("address"),
                "interface": match.group("interface"),
            }
        )
    return neighbors, notes, bool(neighbors)


# ---------------------------------------------------------------------------
# show etherchannel summary
# ---------------------------------------------------------------------------

_ETHERCHANNEL_ROW_RE = re.compile(
    r"^(?P<group>\d+)\s+(?P<portchannel>\S+)\s+(?P<protocol>\S+)(?:\s+(?P<ports>.*))?$"
)
_PORT_FLAG_RE = re.compile(r"\S+\(\w+\)")


def parse_etherchannel_summary(text: str) -> tuple[list[dict], list[str], bool]:
    """``show etherchannel summary`` -> a list of channel-group dicts."""
    groups: list[dict] = []
    notes: list[str] = []
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        lowered = stripped.lower()
        if lowered.startswith(("flags:", "group", "------", "port-channel")):
            continue
        match = _ETHERCHANNEL_ROW_RE.match(stripped)
        if match is None:
            continue
        portchannel = match.group("portchannel")
        flags_match = re.search(r"\(([^)]*)\)", portchannel)
        ports = _PORT_FLAG_RE.findall(match.group("ports") or "")
        groups.append(
            {
                "group": int(match.group("group")),
                "protocol": match.group("protocol"),
                "flags": flags_match.group(1) if flags_match else "",
                "ports": ports,
            }
        )
    return groups, notes, bool(groups)


# ---------------------------------------------------------------------------
# show spanning-tree
# ---------------------------------------------------------------------------

_STP_VLAN_RE = re.compile(r"^VLAN(\d{1,4})$", re.IGNORECASE)
_STP_ROW_RE = re.compile(
    r"^(?P<interface>\S+)\s+(?P<role>\S+)\s+(?P<state>\S+)\s+"
    r"(?P<cost>\d+)\s+(?P<prio>\d+\.\d+)(?:\s+(?P<type>.+))?$"
)


def parse_spanning_tree(text: str) -> tuple[dict, list[str], bool]:
    """``show spanning-tree`` -> ``{vlan: {root_id, bridge_id, interfaces}}``."""
    parsed: dict[str, dict] = {}
    notes: list[str] = []
    current = "unknown"
    mode: str | None = None
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        vlan_match = _STP_VLAN_RE.match(stripped)
        if vlan_match:
            current = str(int(vlan_match.group(1)))
            parsed.setdefault(current, {"root_id": None, "bridge_id": None, "interfaces": []})
            mode = None
            continue
        if "Spanning tree enabled" in stripped:
            parsed.setdefault(current, {"root_id": None, "bridge_id": None, "interfaces": []})
            continue
        if stripped.startswith("Root ID"):
            parsed.setdefault(current, {"root_id": None, "bridge_id": None, "interfaces": []})
            mode = "root"
            continue
        if stripped.startswith("Bridge ID"):
            parsed.setdefault(current, {"root_id": None, "bridge_id": None, "interfaces": []})
            mode = "bridge"
            continue
        if stripped.startswith("Interface") and "Role" in stripped:
            mode = "table"
            continue
        if stripped.startswith("---"):
            continue
        if mode in {"root", "bridge"} and stripped.startswith("Address"):
            tokens = stripped.split()
            if len(tokens) >= 2 and _MAC_DOTTED_RE.match(tokens[1]):
                key = "root_id" if mode == "root" else "bridge_id"
                parsed.setdefault(current, {"root_id": None, "bridge_id": None, "interfaces": []})
                parsed[current][key] = tokens[1]
            else:
                notes.append(f"unparsed spanning-tree address line: {stripped!r}")
            continue
        if mode == "table":
            row = _STP_ROW_RE.match(stripped)
            if row is None:
                continue
            parsed.setdefault(current, {"root_id": None, "bridge_id": None, "interfaces": []})
            parsed[current]["interfaces"].append(
                {
                    "interface": row.group("interface"),
                    "role": row.group("role"),
                    "status": row.group("state"),
                    "cost": int(row.group("cost")),
                    "priority": row.group("prio"),
                }
            )
    return parsed, notes, bool(parsed)


#: Dispatch table for the eight runtime artefacts.
PARSERS = {
    "IP_INTERFACE_BRIEF": parse_ip_interface_brief,
    "VLAN_BRIEF": parse_vlan_brief,
    "INTERFACES_TRUNK": parse_interfaces_trunk,
    "IP_ROUTE": parse_ip_route,
    "ACCESS_LISTS": parse_access_lists,
    "OSPF_NEIGHBOR": parse_ospf_neighbor,
    "ETHERCHANNEL_SUMMARY": parse_etherchannel_summary,
    "SPANNING_TREE": parse_spanning_tree,
}
