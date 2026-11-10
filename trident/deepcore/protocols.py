"""Typed semantics for advanced IOS protocols.

The base config parser understands addressing, VLANs, trunks, routes and ACLs. This
module adds the protocols that need more than a single line to mean anything: STP,
EtherChannel, NAT and IPv6.

Two rules govern everything here:

* **Absence is not a default.** A switch with no ``spanning-tree`` line has not
  been shown to be in PVST+ at priority 32768. IOS defaults differ by platform and
  the file may simply not record them, so an unstated value stays ``None`` and any
  reasoning that needs it becomes inconclusive rather than assuming IOS's default.
* **Unrecognised lines are preserved.** A command this module does not model is
  kept verbatim on its device, so a later reader can see that something was there
  instead of concluding it never existed.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field

#: IOS default bridge priority when nothing is configured. Recorded as a constant
#: so the reasoning code has to name it deliberately rather than inherit it.
DEFAULT_BRIDGE_PRIORITY = 32768

#: Default STP port cost by speed for the classic (802.1D) cost method.
DEFAULT_PORT_COST = {
    10: 100,
    100: 19,
    1000: 4,
    10000: 2,
}


class StpMode(enum.StrEnum):
    """Spanning-tree variants IOS can run."""

    PVST = "pvst"
    RAPID_PVST = "rapid-pvst"
    MST = "mst"
    UNKNOWN = "unknown"


class PortChannelMode(enum.StrEnum):
    """EtherChannel negotiation modes."""

    ON = "on"
    ACTIVE = "active"
    PASSIVE = "passive"
    DESIRABLE = "desirable"
    AUTO = "auto"
    UNKNOWN = "unknown"


class NatRole(enum.StrEnum):
    """An interface's NAT role."""

    INSIDE = "inside"
    OUTSIDE = "outside"
    NONE = "none"


@dataclass
class StpConfig:
    """Device-level spanning-tree configuration.

    Only values that were actually configured are populated. A ``None`` priority
    means "not stated in this file", not "32768".
    """

    mode: StpMode = StpMode.UNKNOWN
    #: Global bridge priority, when configured.
    priority: int | None = None
    #: Per-VLAN priority overrides.
    vlan_priorities: dict[int, int] = field(default_factory=dict)
    #: True when ``spanning-tree vlan N root primary`` was configured.
    root_primary_vlans: list[int] = field(default_factory=list)
    root_secondary_vlans: list[int] = field(default_factory=list)
    #: Raw lines this model did not interpret.
    unparsed: list[str] = field(default_factory=list)

    def effective_priority(self, vlan: int | None = None) -> int | None:
        """The priority configured for ``vlan``, or ``None`` when unstated."""
        if vlan is not None and vlan in self.vlan_priorities:
            return self.vlan_priorities[vlan]
        return self.priority

    def is_candidate_root(self, vlan: int | None = None) -> bool:
        if vlan is not None and vlan in self.root_primary_vlans:
            return True
        return bool(self.root_primary_vlans) and vlan is None


@dataclass
class StpPortConfig:
    """Per-interface spanning-tree configuration."""

    interface: str
    portfast: bool = False
    bpdu_guard: bool = False
    bpdu_filter: bool = False
    root_guard: bool = False
    loop_guard: bool = False
    #: Configured cost, or ``None`` when unstated.
    cost: int | None = None
    priority: int | None = None
    unparsed: list[str] = field(default_factory=list)


@dataclass
class EtherChannel:
    """One port-channel and its physical members."""

    port_channel: str
    mode: PortChannelMode = PortChannelMode.UNKNOWN
    #: Negotiation protocol: ``lacp``, ``pagp``, or ``static`` for ``mode on``.
    protocol: str = "unknown"
    members: list[str] = field(default_factory=list)
    #: Per-member problems found while parsing (e.g. a mismatched mode).
    issues: list[str] = field(default_factory=list)

    @property
    def negotiates(self) -> bool:
        return self.mode in {
            PortChannelMode.ACTIVE,
            PortChannelMode.PASSIVE,
            PortChannelMode.DESIRABLE,
            PortChannelMode.AUTO,
        }


@dataclass
class NatRule:
    """One NAT translation rule."""

    kind: str  # static | dynamic | overload | pool
    inside: str | None = None
    outside: str | None = None
    pool_name: str | None = None
    acl_id: str | None = None
    overload: bool = False
    raw: str = ""


@dataclass
class NatConfig:
    """Device-level NAT configuration."""

    inside_interfaces: list[str] = field(default_factory=list)
    outside_interfaces: list[str] = field(default_factory=list)
    static_rules: list[NatRule] = field(default_factory=list)
    dynamic_rules: list[NatRule] = field(default_factory=list)
    #: ``ip nat pool NAME start end netmask M`` declarations.
    pools: dict[str, tuple[str, str, str]] = field(default_factory=dict)
    unparsed: list[str] = field(default_factory=list)

    @property
    def configured(self) -> bool:
        return bool(
            self.inside_interfaces
            or self.outside_interfaces
            or self.static_rules
            or self.dynamic_rules
        )

    def role_of(self, interface: str) -> NatRole:
        if interface in self.inside_interfaces:
            return NatRole.INSIDE
        if interface in self.outside_interfaces:
            return NatRole.OUTSIDE
        return NatRole.NONE


@dataclass
class Ipv6Interface:
    """IPv6 configuration on one interface."""

    interface: str
    addresses: list[str] = field(default_factory=list)
    link_local: str | None = None
    #: ``ipv6 enable`` or an address implies forwarding is on for the interface.
    enabled: bool = False
    #: ACL bound to the interface.
    acl_in: str | None = None
    acl_out: str | None = None


@dataclass
class Ipv6Config:
    """Device-level IPv6 configuration."""

    forwarding: bool = False
    interfaces: dict[str, Ipv6Interface] = field(default_factory=dict)
    routes: list[tuple[str, str | None]] = field(default_factory=list)
    unparsed: list[str] = field(default_factory=list)

    @property
    def configured(self) -> bool:
        return self.forwarding or bool(self.addresses)

    @property
    def addresses(self) -> list[str]:
        return [
            address
            for interface in self.interfaces.values()
            for address in interface.addresses
        ]


@dataclass
class ProtocolConfigs:
    """Everything the protocol parser extracted for one device."""

    stp: StpConfig = field(default_factory=StpConfig)
    stp_ports: dict[str, StpPortConfig] = field(default_factory=dict)
    etherchannels: dict[str, EtherChannel] = field(default_factory=dict)
    nat: NatConfig = field(default_factory=NatConfig)
    ipv6: Ipv6Config = field(default_factory=Ipv6Config)
    #: Every line the parser did not understand, kept verbatim.
    unsupported: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

_STP_MODE_RE = re.compile(r"^spanning-tree mode (\S+)")
_STP_PRIORITY_RE = re.compile(r"^spanning-tree vlan ([\d,\-]+) priority (\d+)")
_STP_ROOT_RE = re.compile(r"^spanning-tree vlan ([\d,\-]+) root (primary|secondary)")
_STP_GLOBAL_PRIORITY_RE = re.compile(r"^spanning-tree priority (\d+)")
_CHANNEL_RE = re.compile(r"^channel-group (\d+) mode (\S+)")
_PORT_CHANNEL_RE = re.compile(r"^interface Port-channel(\d+)$", re.IGNORECASE)
_IPV6_ROUTE_RE = re.compile(r"^ipv6 route (\S+)(?: (\S+))?")
_NAT_POOL_RE = re.compile(r"^ip nat pool (\S+) (\S+) (\S+) netmask (\S+)")
_NAT_STATIC_RE = re.compile(r"^ip nat inside source static (\S+) (\S+)")
_NAT_DYNAMIC_RE = re.compile(r"^ip nat inside source list (\S+) (?:pool (\S+)|interface (\S+))(?: overload)?")

#: Interface-level commands, keyed by prefix.
_STP_PORT_PREFIXES: tuple[tuple[str, str], ...] = (
    ("spanning-tree portfast", "portfast"),
    ("spanning-tree bpduguard enable", "bpdu_guard"),
    ("spanning-tree bpdufilter enable", "bpdu_filter"),
    ("spanning-tree guard root", "root_guard"),
    ("spanning-tree guard loop", "loop_guard"),
)


def parse_protocols(configuration: list[str]) -> ProtocolConfigs:
    """Parse advanced protocol configuration from a running config.

    Interface context is tracked so interface-scoped commands land on the right
    entry. ``no`` forms remove a setting rather than adding a contradictory one.
    """
    configs = ProtocolConfigs()
    current_interface: str | None = None

    for raw in configuration:
        line = raw.strip()
        if not line or line.startswith("!"):
            continue

        # --- interface context -------------------------------------------
        if line.lower().startswith("interface "):
            current_interface = line.split(None, 1)[1].strip()
            configs.ipv6.interfaces.setdefault(
                current_interface, Ipv6Interface(interface=current_interface)
            )
            configs.stp_ports.setdefault(
                current_interface, StpPortConfig(interface=current_interface)
            )
            continue
        if line.lower().startswith(("router ", "line ", "ip access-list")):
            # A different context; interface-scoped parsing stops here.
            current_interface = None
            continue

        if current_interface is not None and _parse_interface_line(
            configs, current_interface, line
        ):
            continue

        if _parse_global_line(configs, line):
            continue

        # Nothing claimed this line: keep it so its absence is not mistaken for
        # its never having existed.
        if _is_protocol_line(line):
            configs.unsupported.append(line)

    return configs


def _is_protocol_line(line: str) -> bool:
    markers = (
        "spanning-tree",
        "channel-group",
        "channel-protocol",
        "ip nat",
        "ipv6",
        "port-channel",
        "switchport",
        "standby",
        "vrrp",
        "hsrp",
        "port-security",
        "authentication",
        "standby",
        "vrrp",
    )
    return any(line.lower().startswith(marker) for marker in markers)


def _parse_interface_line(configs: ProtocolConfigs, interface: str, line: str) -> bool:
    lowered = line.lower()

    # STP per-interface
    for prefix, attribute in _STP_PORT_PREFIXES:
        if lowered == prefix or lowered.startswith(prefix + " "):
            setattr(configs.stp_ports[interface], attribute, True)
            return True
    if lowered.startswith("no "):
        stripped = lowered[3:]
        for prefix, attribute in _STP_PORT_PREFIXES:
            if stripped == prefix or stripped.startswith(prefix + " "):
                setattr(configs.stp_ports[interface], attribute, False)
                return True

    if lowered.startswith("spanning-tree cost "):
        try:
            configs.stp_ports[interface].cost = int(line.split()[-1])
        except ValueError:
            configs.stp_ports[interface].unparsed.append(line)
        return True
    if lowered.startswith("spanning-tree port-priority "):
        try:
            configs.stp_ports[interface].priority = int(line.split()[-1])
        except ValueError:
            configs.stp_ports[interface].unparsed.append(line)
        return True

    # EtherChannel membership
    match = _CHANNEL_RE.match(lowered)
    if match:
        number, mode_text = match.group(1), match.group(2)
        channel = configs.etherchannels.setdefault(
            f"Port-channel{number}", EtherChannel(port_channel=f"Port-channel{number}")
        )
        mode = _port_channel_mode(mode_text)
        if channel.mode is PortChannelMode.UNKNOWN:
            channel.mode = mode
            channel.protocol = _negotiation_protocol(mode)
        elif channel.mode is not mode:
            channel.issues.append(
                f"{interface} uses mode {mode.value} but Port-channel{number} is "
                f"{channel.mode.value}"
            )
        channel.members.append(interface)
        return True
    if lowered.startswith("channel-protocol "):
        return True

    # NAT roles
    if lowered == "ip nat inside":
        if interface not in configs.nat.inside_interfaces:
            configs.nat.inside_interfaces.append(interface)
        return True
    if lowered == "ip nat outside":
        if interface not in configs.nat.outside_interfaces:
            configs.nat.outside_interfaces.append(interface)
        return True

    # IPv6
    ipv6 = configs.ipv6.interfaces.setdefault(
        interface, Ipv6Interface(interface=interface)
    )
    if lowered == "ipv6 enable":
        ipv6.enabled = True
        return True
    if lowered.startswith("ipv6 address "):
        token = line.split()[2]
        if token.lower().startswith(("autoconfig", "dhcp")):
            return True
        if token.lower().startswith("fe80"):
            ipv6.link_local = token
        else:
            ipv6.addresses.append(token)
        ipv6.enabled = True
        # An interface address enables IPv6 on that interface but is NOT the same
        # as `ipv6 unicast-routing`, which is the global gate for forwarding
        # between interfaces. Keeping them separate means a device with addresses
        # and no unicast-routing is correctly reported as not forwarding, which is
        # a real and common fault.
        return True
    if lowered.startswith("ipv6 traffic-filter "):
        parts = line.split()
        if len(parts) >= 4:
            # IOS ACL names are case-sensitive, so the original text is kept.
            if parts[3].lower() == "in":
                ipv6.acl_in = parts[2]
            else:
                ipv6.acl_out = parts[2]
        return True

    return False


def _parse_global_line(configs: ProtocolConfigs, line: str) -> bool:
    lowered = line.lower()

    match = _STP_MODE_RE.match(lowered)
    if match:
        configs.stp.mode = _stp_mode(match.group(1))
        return True
    match = _STP_PRIORITY_RE.match(lowered)
    if match:
        for vlan in _expand_vlan_list(match.group(1)):
            configs.stp.vlan_priorities[vlan] = int(match.group(2))
        return True
    match = _STP_GLOBAL_PRIORITY_RE.match(lowered)
    if match:
        configs.stp.priority = int(match.group(1))
        return True
    match = _STP_ROOT_RE.match(lowered)
    if match:
        role = match.group(2)
        target = (
            configs.stp.root_primary_vlans
            if role == "primary"
            else configs.stp.root_secondary_vlans
        )
        for vlan in _expand_vlan_list(match.group(1)):
            if vlan not in target:
                target.append(vlan)
        return True

    match = _NAT_POOL_RE.match(lowered)
    if match:
        configs.nat.pools[match.group(1)] = (
            match.group(2),
            match.group(3),
            match.group(4),
        )
        return True
    match = _NAT_STATIC_RE.match(lowered)
    if match:
        configs.nat.static_rules.append(
            NatRule(kind="static", inside=match.group(1), outside=match.group(2), raw=line)
        )
        return True
    match = _NAT_DYNAMIC_RE.match(lowered)
    if match:
        configs.nat.dynamic_rules.append(
            NatRule(
                kind="dynamic",
                acl_id=match.group(1),
                pool_name=match.group(2),
                outside=match.group(3),
                overload="overload" in lowered,
                raw=line,
            )
        )
        return True

    match = _IPV6_ROUTE_RE.match(lowered)
    if match:
        configs.ipv6.routes.append((match.group(1), match.group(2)))
        configs.ipv6.forwarding = True
        return True
    if lowered == "ipv6 unicast-routing":
        configs.ipv6.forwarding = True
        return True

    return False


def _expand_vlan_list(text: str) -> list[int]:
    """Expand an IOS VLAN list such as ``1,10-12,20`` into ids."""
    out: list[int] = []
    for part in text.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            start, _, end = part.partition("-")
            try:
                low, high = int(start), int(end)
            except ValueError:
                continue
            if low <= high:
                out.extend(range(low, min(high, low + 4094) + 1))
        else:
            try:
                out.append(int(part))
            except ValueError:
                continue
    return out


def _stp_mode(text: str) -> StpMode:
    normalized = text.lower().strip()
    if "rapid" in normalized:
        return StpMode.RAPID_PVST
    if "pvst" in normalized:
        return StpMode.PVST
    if "mst" in normalized:
        return StpMode.MST
    return StpMode.UNKNOWN


def _port_channel_mode(text: str) -> PortChannelMode:
    for mode in PortChannelMode:
        if mode.value == text.lower():
            return mode
    return PortChannelMode.UNKNOWN


def _negotiation_protocol(mode: PortChannelMode) -> str:
    if mode in {PortChannelMode.ACTIVE, PortChannelMode.PASSIVE}:
        return "lacp"
    if mode in {PortChannelMode.DESIRABLE, PortChannelMode.AUTO}:
        return "pagp"
    if mode is PortChannelMode.ON:
        return "static"
    return "unknown"


__all__ = [
    "DEFAULT_BRIDGE_PRIORITY",
    "DEFAULT_PORT_COST",
    "EtherChannel",
    "Ipv6Config",
    "Ipv6Interface",
    "NatConfig",
    "NatRole",
    "NatRule",
    "PortChannelMode",
    "ProtocolConfigs",
    "StpConfig",
    "StpMode",
    "StpPortConfig",
    "parse_protocols",
]
