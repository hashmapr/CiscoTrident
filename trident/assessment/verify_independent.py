"""Adversarial, independent verification of a diagnosis.

This layer exists to disagree. It does not call the diagnosis' own helpers to
"check" a finding, because re-running the same function that produced the claim
proves only that the function is deterministic, not that it is right. Every
finding is re-derived from the normalised model with the low-level primitives in
:mod:`trident.engined.reachability` -- a fresh :class:`ForwardingTable`,
:func:`vlan_path`, :func:`evaluate_acls` or an interface-state read -- and then
compared with what the diagnosis claimed.

The rules are deliberately asymmetric:

* a finding is ``confirmed`` **only** when the independent derivation reproduces
  it *and* at least one claimed evidence string is present in that derivation;
* a finding is ``rejected`` when its device/interface/requirement cannot exist,
  when it is INCONCLUSIVE-based, or when the independent derivation disproves it;
* anything that cannot be reproduced but also cannot be disproved goes to
  ``alternative_explanations`` -- never to ``confirmed``;
* faults found by independent scanning that the diagnosis omitted go to
  ``missed``.

``trident.assessment.diagnose`` and ``.forensics`` are intentionally **not**
imported. Independence is a property of the evidence path, not of the import
graph; if a future caller wants to cross-reference those modules it can, but this
verifier must stand on the model alone.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from ..engined.reachability import (
    ForwardingTable,
    evaluate_acls,
    router_for_address,
    trace_path,
    vlan_path,
)

#: Kinds that describe a route/path defect. Used for grouping and for deciding
#: which direction an independent probe should travel.
_ROUTE_KINDS = {
    "MISSING_ROUTE",
    "MISSING_FORWARD_ROUTE",
    "MISSING_RETURN_ROUTE",
    "UNREACHABLE_NEXT_HOP",
    "ROUTING_LOOP",
    "UNREACHABLE",
}

_STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "into", "has", "have",
    "not", "but", "its", "their", "does", "was", "were", "are", "is",
}


@dataclass
class VerificationReport:
    """The adversarial verdict on another agent's findings."""

    confirmed: list[dict] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)
    missed: list[dict] = field(default_factory=list)
    alternative_explanations: list[dict] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "confirmed": list(self.confirmed),
            "rejected": list(self.rejected),
            "missed": list(self.missed),
            "alternative_explanations": list(self.alternative_explanations),
            "unsupported": list(self.unsupported),
            "counts": {
                "confirmed": len(self.confirmed),
                "rejected": len(self.rejected),
                "missed": len(self.missed),
                "alternative_explanations": len(self.alternative_explanations),
            },
        }


# ---------------------------------------------------------------------------
# Finding normalisation
# ---------------------------------------------------------------------------


def _get(source, *names, default=None):
    """Read a field from a dict or an object, in priority order."""
    if isinstance(source, dict):
        for name in names:
            value = source.get(name)
            if value is not None:
                return value
        return default
    for name in names:
        value = getattr(source, name, None)
        if value is not None:
            return value
    return default


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _normalise(finding) -> dict:
    evidence = [str(item) for item in _as_list(_get(finding, "evidence")) if str(item).strip()]
    detail = str(_get(finding, "detail", "description", "message", default="") or "")
    if detail and detail not in evidence:
        evidence.insert(0, detail)
    requirement = _get(finding, "requirement", "requirement_id", "requirement_description")
    return {
        "device": str(_get(finding, "device", "host", default="") or ""),
        "interface": _nullable_str(_get(finding, "interface", "port")),
        "kind": str(_get(finding, "kind", "category", "fault_kind", default="") or ""),
        "detail": detail,
        "affected": [str(item) for item in _as_list(_get(finding, "affected", "requirements"))],
        "requirement": requirement,
        "evidence": evidence,
        "status": str(_get(finding, "status", "basis", "evidence_quality", default="") or ""),
        "confidence": str(_get(finding, "confidence", "confidence_level", default="") or ""),
        "uncertainty": [str(item) for item in _as_list(_get(finding, "uncertainty"))],
        "proposed_correction": _get(finding, "proposed_correction", "correction", "fix"),
    }


def _nullable_str(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"none", "null", "n/a", "-"}:
        return None
    return text


def _kind_family(kind: str) -> str:
    text = (kind or "").lower()
    if "shutdown" in text or text in {"interface_down", "admin_down"}:
        return "shutdown"
    if "acl" in text:
        return "acl"
    if "gateway" in text:
        return "gateway"
    if "next_hop" in text or "nexthop" in text:
        return "route"
    if "route" in text or "loop" in text or text == "unreachable":
        return "route"
    if "vlan" in text or "trunk" in text:
        return "vlan"
    return "other"


def _is_inconclusive(finding: dict) -> bool:
    for text in (finding.get("status"), finding.get("confidence"), finding.get("kind")):
        if text and "inconclusive" in str(text).lower():
            return True
    for text in finding.get("uncertainty", []):
        if text and "inconclusive" in str(text).lower():
            return True
    return (finding.get("detail") or "").strip().lower().startswith("inconclusive")


# ---------------------------------------------------------------------------
# Requirement resolution
# ---------------------------------------------------------------------------


def _variants(text) -> set[str]:
    collapsed = " ".join(str(text).lower().split())
    if not collapsed:
        return set()
    arrow = re.sub(r"\s*->\s*", "->", collapsed)
    return {collapsed, arrow}


def _requirement_label(requirement) -> str:
    return f"{requirement.src.device} -> {requirement.dst.device}"


def _requirement_index(model, intent) -> tuple[dict[str, dict], list[dict]]:
    index: dict[str, dict] = {}
    ordered: list[dict] = []
    if intent is None:
        return index, ordered
    try:
        expanded = intent.expand(model)
    except Exception:  # noqa: BLE001 - an unexpandable intent is reported, not fatal
        return index, ordered
    for requirement in expanded:
        entry = {"requirement": requirement, "label": _requirement_label(requirement)}
        key = (
            requirement.src.device,
            requirement.dst.device,
            requirement.description,
            requirement.assertion,
            requirement.operand,
        )
        if key in {(item["requirement"].src.device, item["requirement"].dst.device,
                    item["requirement"].description, item["requirement"].assertion,
                    item["requirement"].operand) for item in ordered}:
            continue
        ordered.append(entry)
        labels = [
            _requirement_label(requirement),
            f"{requirement.src.device}->{requirement.dst.device}",
            requirement.description,
        ]
        for label in labels:
            for variant in _variants(label):
                index.setdefault(variant, entry)
    return index, ordered


def _match_requirement(index: dict[str, dict], text) -> dict | None:
    if text is None:
        return None
    for variant in _variants(text):
        entry = index.get(variant)
        if entry is not None:
            return entry
    return None


def _fuzzy_requirement(index: dict[str, dict], text) -> dict | None:
    """Match an intent requirement by the device names it mentions.

    ``diagnose`` stores the *raw* requirement text, which need not equal our
    canonical label. Two endpoint device names in the right order are a strong
    enough signal, but only when exactly one requirement fits.
    """
    if not text:
        return None
    haystack = str(text).lower()
    hits: list[dict] = []
    seen: set[int] = set()
    for entry in index.values():
        marker = id(entry)
        if marker in seen:
            continue
        seen.add(marker)
        requirement = entry["requirement"]
        source = requirement.src.device.lower()
        destination = requirement.dst.device.lower()
        if (
            source in haystack
            and destination in haystack
            and haystack.find(source) <= haystack.find(destination)
        ):
            hits.append(entry)
    return hits[0] if len(hits) == 1 else None


def _candidate_requirements(finding: dict, index: dict[str, dict]) -> tuple[list[dict], str | None]:
    cited = finding.get("requirement")
    if cited is not None:
        text = cited
        if isinstance(cited, dict):
            source = (cited.get("src") or {}).get("device", "")
            destination = (cited.get("dst") or {}).get("device", "")
            text = f"{source} -> {destination}"
        entry = _match_requirement(index, text) or _fuzzy_requirement(index, text)
        if entry is not None:
            return [entry], None
        # A raw requirement string is not necessarily a canonical label. Only
        # reject when there is nothing else to correlate with either.
        correlated: list[dict] = []
        for affected in finding.get("affected", []):
            match = _match_requirement(index, affected)
            if match is not None and match not in correlated:
                correlated.append(match)
        if correlated:
            return correlated, None
        return [], f"finding cites requirement {str(text)!r}, which is not in the intent"

    matches: list[dict] = []
    for affected in finding.get("affected", []):
        match = _match_requirement(index, affected)
        if match is not None and match not in matches:
            matches.append(match)
    return matches, None


# ---------------------------------------------------------------------------
# Independent re-derivation
# ---------------------------------------------------------------------------


@dataclass
class _Derived:
    reproduced: bool | None
    evidence: list[str] = field(default_factory=list)
    reason: str = ""


def _iface_net(interface) -> ipaddress.IPv4Network | None:
    address = getattr(interface, "ipv4_address", None)
    prefix = getattr(interface, "prefix_length", None)
    if not address or prefix is None:
        return None
    try:
        return ipaddress.IPv4Network(f"{address}/{prefix}", strict=False)
    except ValueError:
        return None


def _peer(model, device: str, interface: str | None):
    if not interface:
        return None
    for link in getattr(model, "links", []):
        if getattr(link, "device_a", None) == device and getattr(link, "interface_a", None) == interface:
            return getattr(link, "device_b", None), getattr(link, "interface_b", None)
        if getattr(link, "device_b", None) == device and getattr(link, "interface_b", None) == interface:
            return getattr(link, "device_a", None), getattr(link, "interface_a", None)
    return None


def _host_switch_port(model, host: str):
    for interface in getattr(model, "interfaces", {}).values():
        if not getattr(interface, "vlan_assignments", None):
            continue
        peer = _peer(model, interface.device, interface.name)
        if peer and peer[0] == host:
            return interface
    return None


def _resolve_endpoint(model, requirement, which: str) -> tuple[str | None, str | None]:
    endpoint = requirement.src if which == "src" else requirement.dst
    try:
        return endpoint.resolve(model), None
    except Exception as exc:  # noqa: BLE001 - unresolved endpoints make evidence weak
        return None, str(exc)


def _derive(model, finding: dict, requirement) -> _Derived:
    family = _kind_family(finding["kind"])
    if family == "shutdown":
        return _derive_shutdown(model, finding)
    if family == "vlan":
        return _derive_vlan(model, finding, requirement)
    if family == "acl":
        return _derive_acl(model, finding, requirement)
    if family == "gateway":
        return _derive_gateway(model, finding, requirement)
    if family == "route":
        return _derive_route(model, finding, requirement)
    return _derive_other(model, finding)


def _derive_shutdown(model, finding: dict) -> _Derived:
    device, interface = finding["device"], finding["interface"]
    if not interface:
        return _Derived(None, reason="finding names a shutdown but no interface to inspect")
    interface_obj = getattr(model, "interfaces", {}).get(f"{device}:{interface}")
    if interface_obj is None:
        return _Derived(False, reason=f"{device} has no interface {interface}")
    state = (getattr(interface_obj, "admin_state", "") or "").lower()
    if "down" in state:
        return _Derived(True, [f"{device}:{interface} is administratively down"])
    return _Derived(
        False,
        [f"{device}:{interface} admin state is {state or 'unstated'}"],
        f"{device}:{interface} is not administratively down",
    )


def _derive_vlan(model, finding: dict, requirement) -> _Derived:
    device, interface = finding["device"], finding["interface"]
    interface_obj = getattr(model, "interfaces", {}).get(f"{device}:{interface}") if interface else None
    if interface_obj is not None:
        state = (getattr(interface_obj, "admin_state", "") or "").lower()
        if "down" in state:
            return _Derived(True, [f"{device}:{interface} is administratively down"])

    host = requirement["requirement"].src.device if requirement else None
    if host is None and interface:
        peer = _peer(model, device, interface)
        host = peer[0] if peer else None
    if host is None:
        return _Derived(None, reason="no host endpoint is attached to the claimed VLAN fault")

    path = vlan_path(model, host)
    if path.blockers:
        for blocker in path.blockers:
            if device and device.lower() in blocker.lower():
                return _Derived(True, list(path.blockers), "")
        return _Derived(
            False,
            list(path.blockers),
            f"VLAN blockers exist but none name {device}:{interface}: {path.blockers}",
        )
    if path.vlan is None:
        return _Derived(
            None,
            [path.detail],
            "no VLAN-configured switch port is modelled for the cited host; the claim cannot be reproduced",
        )
    return _Derived(
        False,
        [path.detail],
        f"vlan_path reports VLAN {path.vlan} reaches its gateway with no blocker",
    )


def _derive_acl(model, finding: dict, requirement) -> _Derived:
    device = finding["device"]
    if requirement is None:
        return _Derived(None, reason="ACL claim cites no resolvable requirement")
    src, src_error = _resolve_endpoint(model, requirement["requirement"], "src")
    dst, dst_error = _resolve_endpoint(model, requirement["requirement"], "dst")
    if src is None or dst is None:
        return _Derived(None, reason=src_error or dst_error or "endpoint could not be resolved")
    decision = evaluate_acls(model, device, src, dst, requirement["requirement"].protocol)
    if decision.action == "deny":
        return _Derived(True, [decision.detail])
    return _Derived(False, [decision.detail], f"{device}'s ACL permits {src} -> {dst}")


def _derive_gateway(model, finding: dict, requirement) -> _Derived:
    device = finding["device"]
    host = requirement["requirement"].src.device if requirement else device
    interfaces = [
        interface
        for interface in getattr(model, "interfaces", {}).values()
        if interface.device == host and getattr(interface, "ipv4_address", None)
    ]
    gateways = [
        getattr(interface, "ipv4_gateway", None)
        for interface in interfaces
        if getattr(interface, "ipv4_gateway", None)
    ]
    if not gateways:
        return _Derived(None, reason=f"{host} has no configured gateway in the model")
    owners = {
        getattr(interface, "ipv4_address", None)
        for interface in getattr(model, "interfaces", {}).values()
        if getattr(interface, "ipv4_address", None)
    }
    for gateway in gateways:
        try:
            ipaddress.IPv4Address(gateway)
        except ValueError:
            continue
        if gateway not in owners:
            return _Derived(
                True,
                [
                    (
                        f"{host} has default gateway {gateway}, which no interface in the "
                        "model owns, so off-subnet traffic is discarded"
                    )
                ],
            )
    return _Derived(False, [f"every configured gateway on {host} is owned by an interface"])


def _derive_route(model, finding: dict, requirement) -> _Derived:
    device = finding["device"]
    table = ForwardingTable(model, device)
    probes: list[tuple[str, str]] = []
    if requirement is not None:
        kind = (finding["kind"] or "").upper()
        if kind == "MISSING_RETURN_ROUTE":
            address, error = _resolve_endpoint(model, requirement["requirement"], "src")
            probes = [(address, "return")] if address else []
        elif kind == "MISSING_FORWARD_ROUTE":
            address, error = _resolve_endpoint(model, requirement["requirement"], "dst")
            probes = [(address, "forward")] if address else []
        else:
            source, source_error = _resolve_endpoint(model, requirement["requirement"], "src")
            destination, destination_error = _resolve_endpoint(model, requirement["requirement"], "dst")
            error = source_error or destination_error
            probes = [(item, direction) for item, direction in
                      ((destination, "forward"), (source, "return")) if item]
        if not probes:
            return _Derived(None, reason=error or "requirement endpoints could not be resolved")
    else:
        target = _get(finding, "destination", "prefix", "operand", "target")
        if target:
            probes = [(str(target).split("/")[0], "forward")]

    if not probes:
        return _Derived(None, reason="route claim cites neither a requirement nor a destination")

    evidence: list[str] = []
    for address, _direction in probes:
        decision = table.decide(address)
        evidence.append(decision.detail)
        if not decision.forwards:
            return _Derived(True, evidence)
    return _Derived(
        False,
        evidence,
        f"{device} forwards toward {', '.join(address for address, _ in probes)}; no route gap reproduced",
    )


def _derive_other(model, finding: dict) -> _Derived:
    interface = finding["interface"]
    if interface:
        interface_obj = getattr(model, "interfaces", {}).get(f"{finding['device']}:{interface}")
        if interface_obj is not None:
            state = (getattr(interface_obj, "admin_state", "") or "").lower()
            if "down" in state:
                return _Derived(True, [f"{finding['device']}:{interface} is administratively down"])
    return _Derived(
        None,
        reason=f"no independent re-derivation rule exists for kind {finding['kind']!r}",
    )


# ---------------------------------------------------------------------------
# Evidence comparison
# ---------------------------------------------------------------------------


def _tokens(text: str) -> set[str]:
    cleaned = re.sub(r"[^a-z0-9]+", " ", text.lower())
    return {
        token
        for token in cleaned.split()
        if len(token) >= 3 and token not in _STOPWORDS
    }


def _item_supported(claim: str, evidence: list[str]) -> bool:
    claimed = _tokens(claim)
    if not claimed:
        return True
    corpus = _tokens(" ".join(evidence))
    hits = len(claimed & corpus)
    if hits / len(claimed) >= 0.5:
        return True
    normalised_claim = " ".join(str(claim).lower().split())
    normalised_corpus = " ".join(" ".join(evidence).lower().split())
    return bool(normalised_claim) and normalised_claim in normalised_corpus


def _evidence_supported(finding: dict, derived: list[str]) -> tuple[bool, str]:
    claims = [item for item in finding.get("evidence", []) if str(item).strip()]
    if not claims:
        return True, ""
    for claim in claims:
        if _item_supported(str(claim), derived):
            return True, ""
    return False, f"claimed evidence {claims!r} is absent from the independent derivation {derived!r}"


# ---------------------------------------------------------------------------
# False-negative scan (faults the diagnosis missed)
# ---------------------------------------------------------------------------


def _add_missed(out: list[dict], seen: set[tuple], entry: dict) -> None:
    key = (entry.get("device"), entry.get("interface"), entry.get("kind"))
    if key in seen:
        return
    seen.add(key)
    out.append(entry)


def _missed_faults(model, requirements: list[dict], findings: list[dict]) -> list[dict]:
    claimed_pairs = {(item["device"], item["interface"]) for item in findings if item["device"]}
    claimed_families = {(item["device"], _kind_family(item["kind"])) for item in findings if item["device"]}

    found: list[dict] = []
    seen: set[tuple] = set()
    path_devices: set[str] = set()
    path_interfaces: set[tuple[str, str]] = set()

    for entry in requirements:
        requirement = entry["requirement"]
        if requirement.assertion:
            continue
        source, _ = _resolve_endpoint(model, requirement, "src")
        destination, _ = _resolve_endpoint(model, requirement, "dst")
        if not source or not destination:
            continue
        start = router_for_address(model, source)
        trace = trace_path(model, source, destination, start_router=start)
        for hop in trace.hops:
            path_devices.add(hop.device)
            if hop.out_interface:
                path_interfaces.add((hop.device, hop.out_interface))
        if trace.fault_device:
            path_devices.add(trace.fault_device)
            if trace.fault_interface:
                path_interfaces.add((trace.fault_device, trace.fault_interface))
        for address in (source, destination):
            serving = router_for_address(model, address)
            if serving:
                path_devices.add(serving)

        for endpoint in (requirement.src, requirement.dst):
            switching = vlan_path(model, endpoint.device)
            port = _host_switch_port(model, endpoint.device)
            if port is not None:
                path_devices.add(port.device)
                path_interfaces.add((port.device, port.name))
            for blocker in switching.blockers:
                _record_blocker(found, seen, blocker, port, endpoint.device)

    # 1. Administratively-down interfaces on the required path.
    for device in sorted(path_devices):
        for interface in getattr(model, "interfaces", {}).values():
            if interface.device != device:
                continue
            state = (getattr(interface, "admin_state", "") or "").lower()
            if "down" not in state:
                continue
            key = (device, interface.name)
            if key in claimed_pairs or (device, "shutdown") in claimed_families:
                continue
            if path_interfaces and key not in path_interfaces:
                continue
            _add_missed(
                found,
                seen,
                {
                    "device": device,
                    "interface": interface.name,
                    "kind": "ADMIN_SHUTDOWN",
                    "detail": f"{device}:{interface.name} is administratively down on a required path",
                    "source": "independent-scan",
                },
            )

    # 2. Access-port VLAN versus the host subnet it must serve.
    for entry in requirements:
        requirement = entry["requirement"]
        for endpoint in (requirement.src, requirement.dst):
            port = _host_switch_port(model, endpoint.device)
            if port is None:
                continue
            host_interface = next(
                (
                    interface
                    for interface in getattr(model, "interfaces", {}).values()
                    if interface.device == endpoint.device and getattr(interface, "ipv4_address", None)
                ),
                None,
            )
            host_net = _iface_net(host_interface) if host_interface is not None else None
            if host_net is None:
                continue
            numbers = [str(value) for value in getattr(port, "vlan_assignments", []) if str(value).isdigit()]
            if not numbers:
                continue
            vlan = int(numbers[0])
            gateway = _gateway_interface(model, vlan, endpoint.device)
            if gateway is None:
                continue
            gateway_net = _iface_net(gateway)
            if gateway_net is None or gateway_net == host_net:
                continue
            if (port.device, port.name) in claimed_pairs:
                continue
            _add_missed(
                found,
                seen,
                {
                    "device": port.device,
                    "interface": port.name,
                    "kind": "VLAN_SUBNET_MISMATCH",
                    "detail": (
                        f"{endpoint.device} is {host_net} but VLAN {vlan} gateway "
                        f"{gateway.device}:{gateway.name} is {gateway_net}"
                    ),
                    "source": "independent-scan",
                },
            )

    # 3. Default gateways that no interface owns.
    owners = {
        getattr(interface, "ipv4_address", None)
        for interface in getattr(model, "interfaces", {}).values()
        if getattr(interface, "ipv4_address", None)
    }
    for entry in requirements:
        requirement = entry["requirement"]
        for endpoint in (requirement.src, requirement.dst):
            for interface in getattr(model, "interfaces", {}).values():
                if interface.device != endpoint.device:
                    continue
                gateway = getattr(interface, "ipv4_gateway", None)
                if not gateway:
                    continue
                try:
                    ipaddress.IPv4Address(gateway)
                except ValueError:
                    continue
                if gateway in owners:
                    continue
                if (endpoint.device, "gateway") in claimed_families:
                    continue
                _add_missed(
                    found,
                    seen,
                    {
                        "device": endpoint.device,
                        "interface": interface.name,
                        "kind": "GATEWAY_UNOWNED",
                        "detail": (
                            f"{endpoint.device} gateway {gateway} is not owned by any "
                            "modelled interface"
                        ),
                        "source": "independent-scan",
                    },
                )

    # 4. Static routes whose next hop is outside every connected subnet.
    for device in sorted(path_devices):
        table = ForwardingTable(model, device)
        for route in table.routes:
            next_hop = getattr(route, "next_hop", None)
            if not next_hop or table.connected_network_for(next_hop) is not None:
                continue
            if (device, "route") in claimed_families:
                continue
            _add_missed(
                found,
                seen,
                {
                    "device": device,
                    "interface": getattr(route, "outgoing_interface", None),
                    "kind": "UNREACHABLE_NEXT_HOP",
                    "detail": (
                        f"{device} route {getattr(route, 'destination', '?')} points at "
                        f"{next_hop}, which is on no connected subnet"
                    ),
                    "source": "independent-scan",
                },
            )
    return found


def _gateway_interface(model, vlan: int, host: str):
    for interface in getattr(model, "interfaces", {}).values():
        if not getattr(interface, "ipv4_address", None):
            continue
        numbers = [
            int(value)
            for value in getattr(interface, "vlan_assignments", [])
            if str(value).isdigit()
        ]
        if vlan in numbers:
            return interface
    host_interface = next(
        (
            interface
            for interface in getattr(model, "interfaces", {}).values()
            if interface.device == host and getattr(interface, "ipv4_address", None)
        ),
        None,
    )
    host_net = _iface_net(host_interface) if host_interface is not None else None
    if host_net is None:
        return None
    for interface in getattr(model, "interfaces", {}).values():
        if interface.device == host:
            continue
        if _iface_net(interface) == host_net:
            return interface
    return None


def _record_blocker(found: list[dict], seen: set[tuple], blocker: str, port, host: str) -> None:
    down = re.match(r"(\S+):(\S+) is administratively down", blocker)
    if down:
        _add_missed(
            found,
            seen,
            {
                "device": down.group(1),
                "interface": down.group(2),
                "kind": "ADMIN_SHUTDOWN",
                "detail": blocker,
                "source": "independent-scan",
            },
        )
        return
    trunk = re.match(r"(\S+):(\S+) trunk does not permit VLAN (\d+)", blocker)
    if trunk:
        _add_missed(
            found,
            seen,
            {
                "device": trunk.group(1),
                "interface": trunk.group(2),
                "kind": "TRUNK_VLAN_GAP",
                "detail": blocker,
                "source": "independent-scan",
            },
        )
        return
    missing = re.match(r"VLAN (\d+) is not defined in the VLAN database", blocker)
    if missing:
        _add_missed(
            found,
            seen,
            {
                "device": port.device if port is not None else host,
                "interface": port.name if port is not None else None,
                "kind": "VLAN_MISSING",
                "detail": blocker,
                "source": "independent-scan",
            },
        )
        return
    no_gateway = re.match(r"no router interface serves VLAN (\d+)", blocker)
    if no_gateway:
        _add_missed(
            found,
            seen,
            {
                "device": port.device if port is not None else host,
                "interface": port.name if port is not None else None,
                "kind": "VLAN_GATEWAY_MISSING",
                "detail": blocker,
                "source": "independent-scan",
            },
        )


# ---------------------------------------------------------------------------
# Dynamic-routing limitation
# ---------------------------------------------------------------------------


def _dynamic_routing_notes(model) -> list[str]:
    notes: list[str] = []
    for name, info in getattr(model, "devices", {}).items():
        for line in getattr(info, "configuration", None) or ():
            text = str(line).strip().lower()
            if text.startswith(("router ospf", "router eigrp", "router rip", "router bgp")):
                notes.append(
                    f"dynamic routing on {name} is not modelled; routed findings involving "
                    f"{name} cannot be independently re-derived"
                )
                break
    return notes


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def challenge(model, intent, findings) -> VerificationReport:
    """Independently re-derive, reject, and look for what the diagnosis missed."""
    report = VerificationReport()
    normalised = [_normalise(finding) for finding in (findings or [])]
    index, requirements = _requirement_index(model, intent)

    if not requirements:
        report.unsupported.append(
            "the intent carries no explicit requirements, so only structural faults can be checked"
        )
    report.unsupported.extend(_dynamic_routing_notes(model))

    for finding in normalised:
        device = finding["device"]
        interface = finding["interface"]

        if not device:
            report.rejected.append(
                {**finding, "reason": "finding names no device, so it cannot be located in the model"}
            )
            continue

        if device not in getattr(model, "devices", {}):
            report.rejected.append(
                {**finding, "reason": f"{device} is not a device in the model"}
            )
            continue

        if interface and f"{device}:{interface}" not in getattr(model, "interfaces", {}):
            report.rejected.append(
                {
                    **finding,
                    "reason": f"{device} has no interface {interface} in the model",
                }
            )
            continue

        if _is_inconclusive(finding):
            report.rejected.append(
                {
                    **finding,
                    "reason": "finding is INCONCLUSIVE-based; an undecided verdict cannot be confirmed",
                }
            )
            continue

        candidates, requirement_error = _candidate_requirements(finding, index)
        if requirement_error:
            report.rejected.append({**finding, "reason": requirement_error})
            continue

        derived = _derive(model, finding, candidates[0] if candidates else None)
        requirement_label = candidates[0]["label"] if candidates else None

        if derived.reproduced is True:
            supported, unsupported_reason = _evidence_supported(finding, derived.evidence)
            if supported:
                report.confirmed.append(
                    {
                        **finding,
                        "requirement": requirement_label or finding.get("requirement"),
                        "independent_evidence": list(derived.evidence),
                    }
                )
            else:
                report.rejected.append(
                    {
                        **finding,
                        "reason": unsupported_reason,
                        "independent_evidence": list(derived.evidence),
                    }
                )
        elif derived.reproduced is False:
            report.rejected.append(
                {
                    **finding,
                    "reason": derived.reason or "independent re-derivation disproved the finding",
                    "independent_evidence": list(derived.evidence),
                }
            )
        else:
            explanations = _possible_explanations(model, finding, candidates)
            report.alternative_explanations.append(
                {
                    **finding,
                    "reason": derived.reason or "the evidence is insufficient to reproduce the finding",
                    "possible_explanations": explanations,
                    "independent_evidence": list(derived.evidence),
                }
            )

    report.missed = _missed_faults(model, requirements, normalised)
    return report


def _possible_explanations(model, finding: dict, candidates: list[dict]) -> list[str]:
    """What else could explain the same observation, stated without confirming it."""
    explanations: list[str] = []
    device = finding["device"]
    for interface in getattr(model, "interfaces", {}).values():
        if interface.device != device:
            continue
        state = (getattr(interface, "admin_state", "") or "").lower()
        if "down" in state:
            explanations.append(
                f"{device}:{interface.name} is administratively down, which alone could explain the symptom"
            )
    if not candidates:
        explanations.append("the finding could not be tied to any requirement in the intent")
    if not explanations:
        explanations.append(
            "the model lacks the fact needed to decide; a live observation would be required"
        )
    return explanations
