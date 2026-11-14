"""Turn visible lab instructions into individually testable requirements.

This module is a *decomposer*, not an interpreter. A practice lab says
"PC-A can ping PC-B" and a verifier needs a concrete requirement it can decide;
it also says "Enable OSPF on all routers", which this layer cannot turn into a
single assertion without guessing at what "enabled" means.

The rule that keeps the assessment honest is therefore simple: **a line that
cannot be matched becomes an UNPARSED line, never a guessed requirement.** An
unparsed line is visible in coverage, so a student sees that the tool did not
understand it instead of silently receiving a verdict about something they
never asked.

The supported phrasings are deliberate. They are the six things the evaluation
corpus and the practice labs actually say:

    PC-A can ping PC-B / PC1 must reach SRV1        reachability
    VLAN 10 must remain isolated from VLAN 20        isolation (must_not_reach)
    R1 must have a route to 10.5.4.0/24              assertion "route"
    SW1 FastEthernet0/2 must be enabled / up         assertion "interface_up"
    SW1 Fa0/2 must be in VLAN 10                     assertion "vlan_membership"
    PC-A gateway must be 10.1.1.1                    assertion "gateway"

Everything else is reported, counted, and left alone.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from trident.engined.intent import Endpoint, NetworkIntent, Requirement

#: Cross-VLAN isolation is tested with representative endpoint pairs. A lab with
#: hundreds of hosts should not produce thousands of traces for one statement.
_MAX_ISOLATION_PAIRS = 16

_INTERFACE_ABBREVIATIONS = {
    "fa": "FastEthernet",
    "gi": "GigabitEthernet",
    "ge": "GigabitEthernet",
    "se": "Serial",
    "eth": "Ethernet",
    "te": "TenGigabitEthernet",
    "po": "Port-channel",
    "lo": "Loopback",
    "vl": "Vlan",
}

_DEVICE = r"[\w.-]+"
_INTERFACE = r"[A-Za-z][\w/.\-]*"
_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
_PREFIX = rf"{_IPV4}/\d{{1,2}}"

_GATEWAY_RE = re.compile(
    rf"^(?P<device>{_DEVICE})(?:'s)?\s+(?:default\s+)?gateway\s+"
    rf"(?:must\s+be|should\s+be|is)\s+(?P<gateway>{_IPV4})\s*\.?$",
    re.IGNORECASE,
)

_VLAN_MEMBERSHIP_RE = re.compile(
    rf"^(?P<device>{_DEVICE})\s+(?P<interface>{_INTERFACE})\s+"
    rf"(?:must\s+be|should\s+be|is|must\s+remain)\s+"
    rf"(?:assigned\s+to\s+|in\s+)?vlan\s*(?P<vlan>\d+)\s*\.?$",
    re.IGNORECASE,
)

_INTERFACE_UP_RE = re.compile(
    rf"^(?P<device>{_DEVICE})\s+(?P<interface>{_INTERFACE})\s+"
    rf"(?:must\s+be|should\s+be|needs\s+to\s+be|is)\s+"
    rf"(?:enabled|up|administratively\s+up|no\s+shutdown)\s*\.?$",
    re.IGNORECASE,
)

_ROUTE_RE = re.compile(
    rf"^(?P<device>{_DEVICE})\s+"
    rf"(?:must\s+have|needs?\s+to\s+have|needs?|has)\s+a\s+route\s+"
    rf"(?:to|for)\s+(?P<prefix>{_PREFIX})\s*\.?$",
    re.IGNORECASE,
)

_DEFAULT_ROUTE_RE = re.compile(
    rf"^(?P<device>{_DEVICE})\s+(?:must\s+have|has|needs?)\s+a\s+default\s+route\s+"
    rf"(?:via|through)\s+(?P<next_hop>\d+\.\d+\.\d+\.\d+)\s*\.?$",
    re.IGNORECASE,
)

_GATEWAY_PING_RE = re.compile(
    rf"^(?P<device>{_DEVICE})\s+(?:can|must\s+be\s+able\s+to)\s+ping\s+"
    r"(?:its\s+)?default\s+gateway\s*\.?$",
    re.IGNORECASE,
)

_NEGATIVE_ROUTE_RE = re.compile(
    rf"^(?P<device>{_DEVICE})\s+(?:holds|has|must\s+have)\s+no\s+route\s+"
    rf"(?:to|into|for)\s+(?:(?P<prefix>{_PREFIX})|(?:a\s+)?private\s+network)\s*\.?$",
    re.IGNORECASE,
)

_VLAN_ISOLATION_RE = re.compile(
    r"^vlan\s*(?P<a>\d+)\s+(?:must|should)\s+(?:remain\s+)?"
    r"(?:be\s+)?(?:isolated\s+from|not\s+(?:be\s+able\s+to\s+)?(?:reach|ping)|not\s+reach)\s+"
    r"(?:vlan\s*)?(?P<b>\d+)\s*\.?$",
    re.IGNORECASE,
)

_DEVICE_ISOLATION_RE = re.compile(
    rf"^(?P<a>{_DEVICE})\s+(?:(?:must|should)\s+not|cannot)\s+"
    rf"(?:be\s+able\s+to\s+)?(?:reach|ping)\s+(?P<b>{_DEVICE})\s*\.?$",
    re.IGNORECASE,
)

_REACHABILITY_RE = re.compile(
    rf"^(?P<a>{_DEVICE})\s+"
    rf"(?:(?:can|must|should|will)\s+(?:be\s+able\s+to\s+)?|is\s+able\s+to\s+)"
    rf"(?:ping|reach)\s+(?P<b>{_DEVICE})\s*\.?$",
    re.IGNORECASE,
)


@dataclass
class ParsedRequirement:
    """One line of visible instruction, and what it was understood to mean.

    ``parsed`` is the load-bearing field. It is ``True`` only when a supported
    phrasing matched; when it is ``False`` the line is retained verbatim so the
    caller can report it as UNPARSED. ``unresolvable`` is set by
    :func:`to_intent` when the phrasing matched but a named device or VLAN is
    absent from the model — the requirement is still retained and reported.
    """

    raw: str
    kind: str = "unparsed"
    parsed: bool = False
    assertion: str | None = None
    src_device: str | None = None
    dst_device: str | None = None
    operand: str | None = None
    protocol: str = "icmp"
    must_not_reach: bool = False
    required: bool = True
    vlan_a: int | None = None
    vlan_b: int | None = None
    unresolvable: str | None = None

    def as_dict(self) -> dict:
        return {
            "raw": self.raw,
            "kind": self.kind,
            "parsed": self.parsed,
            "assertion": self.assertion,
            "src_device": self.src_device,
            "dst_device": self.dst_device,
            "operand": self.operand,
            "protocol": self.protocol,
            "must_not_reach": self.must_not_reach,
            "required": self.required,
            "vlan_a": self.vlan_a,
            "vlan_b": self.vlan_b,
            "unresolvable": self.unresolvable,
        }


# ---------------------------------------------------------------------------
# Line cleaning and matching
# ---------------------------------------------------------------------------


def _clean(line: str) -> str:
    """Remove list furniture, not content.

    Labs paste instructions with bullets and numbering. Stripping them is
    normalisation; it does not decide what the line means.
    """
    text = line.strip()
    text = re.sub(r"^[-*\u2022]\s+", "", text)
    text = re.sub(r"^\d+[.)]\s+", "", text)
    return text.strip()


def _parse_gateway(text: str, raw: str) -> ParsedRequirement | None:
    match = _GATEWAY_RE.match(text)
    if not match:
        return None
    device = match.group("device")
    return ParsedRequirement(
        raw=raw,
        kind="gateway",
        parsed=True,
        assertion="gateway",
        src_device=device,
        dst_device=device,
        operand=match.group("gateway"),
    )


def _parse_vlan_membership(text: str, raw: str) -> ParsedRequirement | None:
    match = _VLAN_MEMBERSHIP_RE.match(text)
    if not match:
        return None
    device = match.group("device")
    interface = match.group("interface")
    vlan = match.group("vlan")
    return ParsedRequirement(
        raw=raw,
        kind="vlan_membership",
        parsed=True,
        assertion="vlan_membership",
        src_device=device,
        dst_device=device,
        operand=f"{device}:{interface}",
        protocol=vlan,
    )


def _parse_interface_up(text: str, raw: str) -> ParsedRequirement | None:
    match = _INTERFACE_UP_RE.match(text)
    if not match:
        return None
    device = match.group("device")
    interface = match.group("interface")
    return ParsedRequirement(
        raw=raw,
        kind="interface_up",
        parsed=True,
        assertion="interface_up",
        src_device=device,
        dst_device=device,
        operand=f"{device}:{interface}",
    )


def _parse_route(text: str, raw: str) -> ParsedRequirement | None:
    match = _ROUTE_RE.match(text)
    if not match:
        return None
    prefix = match.group("prefix")
    try:
        ipaddress.IPv4Network(prefix, strict=False)
    except ValueError:
        # A prefix-shaped string that is not a prefix is not silently
        # reinterpreted; the line stays UNPARSED.
        return None
    device = match.group("device")
    return ParsedRequirement(
        raw=raw,
        kind="route",
        parsed=True,
        assertion="route",
        src_device=device,
        dst_device=device,
        operand=prefix,
    )


def _parse_vlan_isolation(text: str, raw: str) -> ParsedRequirement | None:
    match = _VLAN_ISOLATION_RE.match(text)
    if not match:
        return None
    a = int(match.group("a"))
    b = int(match.group("b"))
    if a == b:
        return None
    return ParsedRequirement(
        raw=raw,
        kind="isolation",
        parsed=True,
        operand=f"vlan:{a}|vlan:{b}",
        must_not_reach=True,
        vlan_a=a,
        vlan_b=b,
    )


def _parse_device_isolation(text: str, raw: str) -> ParsedRequirement | None:
    match = _DEVICE_ISOLATION_RE.match(text)
    if not match:
        return None
    return ParsedRequirement(
        raw=raw,
        kind="isolation",
        parsed=True,
        src_device=match.group("a"),
        dst_device=match.group("b"),
        must_not_reach=True,
    )


def _parse_reachability(text: str, raw: str) -> ParsedRequirement | None:
    match = _REACHABILITY_RE.match(text)
    if not match:
        return None
    return ParsedRequirement(
        raw=raw,
        kind="reachability",
        parsed=True,
        src_device=match.group("a"),
        dst_device=match.group("b"),
    )


def _parse_default_route(text: str, raw: str) -> ParsedRequirement | None:
    """``R1 has a default route via 203.0.113.1``.

    Distinct from the plain route assertion: the next hop is named, so the
    requirement is falsifiable in a stronger way — the route must exist AND its
    next hop must be reachable. A router pointed at an address nobody owns has
    a route line that will never be installed.
    """
    match = _DEFAULT_ROUTE_RE.match(text)
    if not match:
        return None
    try:
        ipaddress.IPv4Address(match.group("next_hop"))
    except ValueError:
        return None
    device = match.group("device")
    return ParsedRequirement(
        raw=raw,
        kind="default_route",
        parsed=True,
        assertion="default_route_via",
        src_device=device,
        dst_device=device,
        operand=match.group("next_hop"),
    )


def _parse_gateway_ping(text: str, raw: str) -> ParsedRequirement | None:
    """``PC1 can ping its default gateway``.

    Testable only if the host has a gateway recorded; otherwise the verifier
    reports INCONCLUSIVE rather than inventing one.
    """
    match = _GATEWAY_PING_RE.match(text)
    if not match:
        return None
    device = match.group("device")
    return ParsedRequirement(
        raw=raw,
        kind="gateway_ping",
        parsed=True,
        assertion="gateway_reachable",
        src_device=device,
        dst_device=device,
    )


def _parse_negative_route(text: str, raw: str) -> ParsedRequirement | None:
    """``ISP-EDGE holds no route to a private network``.

    An isolation requirement expressed against a router rather than a host. It
    is deliberately narrow: only private-space assertions are understood, and a
    stated prefix is required to falsify it.
    """
    match = _NEGATIVE_ROUTE_RE.match(text)
    if not match:
        return None
    device = match.group("device")
    prefix = match.group("prefix") or "10.0.0.0/8"
    try:
        ipaddress.IPv4Network(prefix, strict=False)
    except ValueError:
        return None
    return ParsedRequirement(
        raw=raw,
        kind="no_route",
        parsed=True,
        assertion="route",
        src_device=device,
        dst_device=device,
        operand=prefix,
        must_not_reach=True,
    )


_PARSERS = (
    _parse_gateway,
    _parse_vlan_membership,
    _parse_interface_up,
    _parse_route,
    _parse_vlan_isolation,
    _parse_device_isolation,
    _parse_reachability,
    _parse_default_route,
    _parse_gateway_ping,
    _parse_negative_route,
)


def parse_requirements(lines: list[str]) -> list[ParsedRequirement]:
    """Convert visible instructions into individually testable requirements.

    One output entry per non-blank input line, in input order. A line that no
    parser understands is returned with ``parsed=False`` and its original text
    intact; nothing is inferred from surrounding lines.
    """
    parsed: list[ParsedRequirement] = []
    for raw in lines:
        if not isinstance(raw, str):
            continue
        text = _clean(raw)
        if not text:
            continue
        result = None
        for parser in _PARSERS:
            result = parser(text, raw)
            if result is not None:
                break
        parsed.append(result or ParsedRequirement(raw=raw, kind="unparsed", parsed=False))
    return parsed


# ---------------------------------------------------------------------------
# Model resolution
# ---------------------------------------------------------------------------


def _canonical_device(model, name: str) -> str | None:
    """The model's own name for ``name``, or None if it is not present.

    ``NetworkModel.find_device`` understands hostname aliases; the tiny
    dataclass models used by tests only expose a ``devices`` mapping. Both are
    handled, and neither matches arbitrarily: an ambiguous alias resolves to
    nothing rather than to a guess.
    """
    finder = getattr(model, "find_device", None)
    if callable(finder):
        info = finder(name)
        if info is not None:
            return getattr(info, "name", None) or name
    devices = getattr(model, "devices", {}) or {}
    lowered = name.lower()
    for key, info in devices.items():
        candidates = {str(key).lower()}
        label = getattr(info, "name", None)
        if label:
            candidates.add(str(label).lower())
        if lowered in candidates:
            return getattr(info, "name", None) or key
    return None


def _expand_interface(name: str) -> str:
    """Expand only the alphabetic prefix: ``Fa0/2`` -> ``FastEthernet0/2``."""
    match = re.match(r"^([A-Za-z-]+)(.*)$", name)
    if not match:
        return name
    prefix, rest = match.groups()
    expanded = _INTERFACE_ABBREVIATIONS.get(prefix.lower())
    return f"{expanded}{rest}" if expanded else name


def _canonical_interface(model, device: str, interface: str) -> str:
    """The model's interface name, expanding ``Fa0/2`` to ``FastEthernet0/2``.

    If neither form exists the original text is returned. The verifier then
    reports INCONCLUSIVE ("not in the model") instead of this layer pretending
    the port was found.
    """
    interfaces = getattr(model, "interfaces", {}) or {}
    if f"{device}:{interface}" in interfaces:
        return interface
    wanted = {interface.lower(), _expand_interface(interface).lower()}
    for key, iface in interfaces.items():
        if getattr(iface, "device", None) != device:
            continue
        name = getattr(iface, "name", "")
        if str(name).lower() in wanted:
            return str(name)
    return interface


def _link_peers(model, device: str, interface: str) -> list[str]:
    peers: list[str] = []
    for link in getattr(model, "links", []) or []:
        if link.device_a == device and link.interface_a == interface:
            peers.append(link.device_b)
        elif link.device_b == device and link.interface_b == interface:
            peers.append(link.device_a)
    return peers


def _addressed_devices(model) -> set[str]:
    return {
        iface.device
        for iface in (getattr(model, "interfaces", {}) or {}).values()
        if getattr(iface, "ipv4_address", None)
    }


def _devices_in_vlan(model, vlan: int) -> list[str]:
    """Devices that are actually attached to ``vlan``.

    A VLAN is defined by switch ports, so the endpoints are the devices on the
    far side of those ports. When a link is not modelled, the port's own device
    is used only if it has an address; a bare switch is not a host and would
    make the isolation test meaningless.
    """
    wanted = str(vlan)
    addressed = _addressed_devices(model)
    members: set[str] = set()
    for iface in (getattr(model, "interfaces", {}) or {}).values():
        assigned = [str(v) for v in getattr(iface, "vlan_assignments", []) or []]
        if wanted not in assigned:
            continue
        peers = [p for p in _link_peers(model, iface.device, iface.name) if p in addressed]
        if peers:
            members.update(peers)
        elif iface.device in addressed:
            members.add(iface.device)
    return sorted(members)


def _build_requirements(parsed: ParsedRequirement, model) -> tuple[list[Requirement], str | None]:
    """Requirements for one parsed line, or a reason it cannot be resolved."""
    if not parsed.parsed:
        return [], None

    if parsed.kind == "isolation" and parsed.vlan_a is not None and parsed.vlan_b is not None:
        left = _devices_in_vlan(model, parsed.vlan_a)
        right = _devices_in_vlan(model, parsed.vlan_b)
        if not left:
            return [], f"VLAN {parsed.vlan_a} has no addressed endpoint in the model"
        if not right:
            return [], f"VLAN {parsed.vlan_b} has no addressed endpoint in the model"
        requirements: list[Requirement] = []
        for src in left:
            for dst in right:
                if len(requirements) >= _MAX_ISOLATION_PAIRS:
                    break
                requirements.append(
                    Requirement(
                        src=Endpoint(src),
                        dst=Endpoint(dst),
                        description=f"{parsed.raw} [{src} -> {dst}]",
                        required=parsed.required,
                        must_not_reach=True,
                    )
                )
        return requirements, None

    src = _canonical_device(model, parsed.src_device or "")
    if src is None:
        return [], f"unknown device {parsed.src_device!r}"
    dst = src
    if parsed.kind == "reachability" or (
        parsed.kind == "isolation" and parsed.dst_device is not None
    ):
        dst = _canonical_device(model, parsed.dst_device or "")
        if dst is None:
            return [], f"unknown device {parsed.dst_device!r}"

    if parsed.assertion is not None:
        operand = parsed.operand
        if parsed.assertion in {"interface_up", "vlan_membership"} and operand:
            _, _, interface = operand.partition(":")
            operand = f"{src}:{_canonical_interface(model, src, interface)}"
        return [
            Requirement(
                src=Endpoint(src),
                dst=Endpoint(dst),
                description=parsed.raw,
                required=parsed.required,
                protocol=parsed.protocol,
                assertion=parsed.assertion,
                operand=operand,
                must_not_reach=parsed.must_not_reach,
            )
        ], None

    return [
        Requirement(
            src=Endpoint(src),
            dst=Endpoint(dst),
            description=parsed.raw,
            required=parsed.required,
            protocol=parsed.protocol,
            must_not_reach=parsed.must_not_reach,
        )
    ], None


def to_intent(parsed: ParsedRequirement, model) -> NetworkIntent:
    """Resolve one parsed requirement against ``model``.

    An unresolvable requirement returns an empty intent and records the reason
    on ``parsed.unresolvable``. It is never dropped: the caller still holds the
    object and can report it, which is the difference between "not tested" and
    "passed".
    """
    parsed.unresolvable = None
    requirements, reason = _build_requirements(parsed, model)
    if reason is not None:
        parsed.unresolvable = reason
        return NetworkIntent(name=parsed.raw[:120])
    return NetworkIntent(name=parsed.raw[:120], requirements=requirements)


def coverage(parsed: list[ParsedRequirement], model) -> dict:
    """Counts of what this layer could and could not make testable.

    ``parsed`` counts matched lines including unresolvable ones;
    ``testable`` is what Engine D can actually evaluate. The two differ so a
    model gap cannot hide inside a single "parsed" number.
    """
    total = len(parsed)
    unparsed = sum(1 for item in parsed if not item.parsed)
    unresolvable = 0
    for item in parsed:
        if not item.parsed:
            continue
        _, reason = _build_requirements(item, model)
        if reason is not None:
            unresolvable += 1
    return {
        "total": total,
        "parsed": total - unparsed,
        "unparsed": unparsed,
        "unresolvable": unresolvable,
        "testable": total - unparsed - unresolvable,
    }


__all__ = [
    "ParsedRequirement",
    "coverage",
    "parse_requirements",
    "to_intent",
]
