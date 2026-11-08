"""Requirement model for deterministic lab-instruction extraction.

A :class:`Requirement` is one testable obligation recovered from a practice-lab
instruction sheet. It is deliberately plain: an id, a kind, the named
device/interface it targets (``None`` when the instruction is scoped to a named
group such as "all PCs"), the expected value, and the exact source line.

Nothing here reads files, touches the network, or calls a model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class RequirementKind(StrEnum):
    """The configuration domain a requirement belongs to."""

    IPV4_ADDRESS = "ipv4_address"
    IPV4_SUBNET = "ipv4_subnet"
    IPV6_ADDRESS = "ipv6_address"
    VLAN_ASSIGNMENT = "vlan_assignment"
    TRUNK = "trunk"
    STATIC_ROUTE = "static_route"
    DEFAULT_ROUTE = "default_route"
    OSPF = "ospf"
    DHCP = "dhcp"
    DNS = "dns"
    NAT = "nat"
    ACL = "acl"
    INTERFACE_ENABLE = "interface_enable"
    SSH = "ssh"
    SECURITY = "security"
    WIRELESS = "wireless"
    CONNECTIVITY = "connectivity"
    UNKNOWN = "unknown"


class RequirementStatus(StrEnum):
    """How far the parser got with one source line.

    ``PARSED``      - every required slot was stated explicitly.
    ``AMBIGUOUS``   - the intent was recognised but a required slot (device,
                      interface, address, VLAN id, next hop, ...) is missing or
                      contradictory. The requirement is *not* completed by
                      inference.
    ``UNSUPPORTED`` - no rule recognised the line. The line is preserved for
                      the operator but produces no configuration demand.
    """

    PARSED = "PARSED"
    UNSUPPORTED = "UNSUPPORTED"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True, slots=True)
class Requirement:
    """One testable requirement recovered from a single source line.

    ``device`` is only ever populated from a device name that appears literally
    in the source text. It is ``None`` for group-scoped instructions
    (``"Place all PCs on VLAN 10"``) and for AMBIGUOUS/UNSUPPORTED lines.
    """

    id: str
    kind: RequirementKind
    device: str | None
    interface: str | None
    expected: str
    source_text: str
    source_line: int
    status: RequirementStatus = RequirementStatus.PARSED
    #: ``"explicit"`` when every slot was stated literally, ``"inferred"`` when
    #: a value was derived by rule (group scope, only-IPv4-in-line, ...).
    confidence: str = "explicit"
    notes: list[str] = field(default_factory=list)
