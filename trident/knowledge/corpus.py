"""Curated offline corpus of Cisco IOS reference material.

Every entry is hand-written reference documentation. Nothing here is derived
from a Packet Tracer file, a device configuration or a parser observation, and
no entry claims anything about a specific device.

Wording rules for this file:

* describe what IOS *does* or *prints*, never what a device *is* configured as
* prefer "a trunk stays up when ..." over "the trunk is up"
* keep ``related`` ids inside this corpus (the index rejects dangling ids)
"""

from __future__ import annotations

from .index import KnowledgeEntry, KnowledgeKind

SOURCE_COMMAND = "Cisco IOS command reference (offline summary)"
SOURCE_CONCEPT = "Cisco networking fundamentals (offline summary)"
SOURCE_PROTOCOL = "IEEE and Cisco protocol documentation (offline summary)"
SOURCE_TROUBLESHOOTING = "Cisco IOS troubleshooting guide (offline summary)"


def _cmd(
    entry_id: str,
    title: str,
    summary: str,
    detail: str,
    related: tuple[str, ...] = (),
    ios_commands: tuple[str, ...] = (),
) -> KnowledgeEntry:
    return KnowledgeEntry(
        id=entry_id,
        kind=KnowledgeKind.COMMAND,
        title=title,
        summary=summary,
        detail=detail,
        related=related,
        ios_commands=ios_commands,
        source=SOURCE_COMMAND,
    )


def _concept(
    entry_id: str,
    title: str,
    summary: str,
    detail: str,
    related: tuple[str, ...] = (),
    ios_commands: tuple[str, ...] = (),
) -> KnowledgeEntry:
    return KnowledgeEntry(
        id=entry_id,
        kind=KnowledgeKind.CONCEPT,
        title=title,
        summary=summary,
        detail=detail,
        related=related,
        ios_commands=ios_commands,
        source=SOURCE_CONCEPT,
    )


def _ts(
    entry_id: str,
    title: str,
    summary: str,
    detail: str,
    related: tuple[str, ...] = (),
    ios_commands: tuple[str, ...] = (),
) -> KnowledgeEntry:
    return KnowledgeEntry(
        id=entry_id,
        kind=KnowledgeKind.TROUBLESHOOTING,
        title=title,
        summary=summary,
        detail=detail,
        related=related,
        ios_commands=ios_commands,
        source=SOURCE_TROUBLESHOOTING,
    )


def _proto(
    entry_id: str,
    title: str,
    summary: str,
    detail: str,
    related: tuple[str, ...] = (),
    ios_commands: tuple[str, ...] = (),
) -> KnowledgeEntry:
    return KnowledgeEntry(
        id=entry_id,
        kind=KnowledgeKind.PROTOCOL,
        title=title,
        summary=summary,
        detail=detail,
        related=related,
        ios_commands=ios_commands,
        source=SOURCE_PROTOCOL,
    )


ENTRIES: tuple[KnowledgeEntry, ...] = (
    # -----------------------------------------------------------------------
    # Commands
    # -----------------------------------------------------------------------
    _cmd(
        "cmd-show-ip-interface-brief",
        "show ip interface brief",
        "One line per interface with IP address, method, link status and line protocol.",
        (
            "Columns are Interface, IP-Address, OK?, Method, Status and Protocol. The status "
            "column is layer 1/2: up, down, administratively down, deleted or reset. The protocol "
            "column is the line protocol: up or down, driven by keepalives and layer 2 state. "
            "'administratively down' means a shutdown command is configured; 'up/down' means the "
            "link exists but the line protocol has not come up. Method reports how the address was "
            "obtained: manual, DHCP, NVRAM, unset or TFTP. The listing omits subnet masks, "
            "secondary addresses and descriptions, so it is a first-look command, not proof of "
            "reachability."
        ),
        related=(
            "ts-interface-down",
            "cmd-show-interfaces-status",
            "concept-svi",
        ),
        ios_commands=("show ip interface brief",),
    ),
    _cmd(
        "cmd-show-running-config",
        "show running-config",
        "The active configuration held in RAM, including settings not yet saved to NVRAM.",
        (
            "Displays every configured feature: interfaces, routing protocols, ACLs, NAT, line "
            "configuration and VLAN settings. This is the current state; startup-config is what "
            "will be loaded after a reload, and the two differ until the configuration is saved. "
            "Output can be scoped with 'show running-config interface GigabitEthernet0/1' or "
            "filtered with a pipe, for example 'show running-config | section router ospf'. "
            "Secrets appear hashed (type 5/8/9) or weakly obfuscated (type 7), never in clear text "
            "unless the configuration was written that way."
        ),
        related=(
            "cmd-show-ip-protocols",
            "concept-default-gateway-vs-default-route",
            "cmd-show-access-lists",
        ),
        ios_commands=(
            "show running-config",
            "show running-config interface GigabitEthernet0/1",
            "show startup-config",
        ),
    ),
    _cmd(
        "cmd-show-vlan-brief",
        "show vlan brief",
        "VLAN table with VLAN id, name, status and the access ports that belong to each VLAN.",
        (
            "Lists VLANs known to the local VLAN database, including VLAN 1, which always exists, "
            "and VLANs that were created but have no ports. The Ports column contains access ports "
            "only: a port in trunk mode does not appear here even though it carries the VLAN. "
            "Status is active, act/unsup or suspended. The output does not show trunk allowed "
            "lists, native VLANs or VLANs learned on trunks from a neighbour, so it describes this "
            "switch's VLAN database, not the VLANs reachable across the network."
        ),
        related=(
            "concept-vlan-vs-trunk-vs-access",
            "cmd-show-interfaces-trunk",
            "proto-vtp",
            "ts-vlan-mismatch",
        ),
        ios_commands=("show vlan brief", "show vlan id 10"),
    ),
    _cmd(
        "cmd-show-interfaces-trunk",
        "show interfaces trunk",
        "Every trunk port with its mode, encapsulation, native VLAN and three allowed-VLAN lists.",
        (
            "Reports Mode (on, desirable, auto, off), Encapsulation (802.1q), Status, Native vlan "
            "and the three VLAN lists: allowed on trunk, allowed and active in management domain, "
            "and in spanning tree. The three lists differ whenever a VLAN is allowed but not yet "
            "active locally, which is a frequent reason for missing connectivity over a working "
            "trunk. A port that negotiated no trunk appears in no row at all, so an empty output "
            "means no port is trunking. Administrative and operational mode can differ while "
            "negotiation is in progress."
        ),
        related=(
            "concept-native-vlan",
            "ts-trunk-not-forming",
            "proto-8021q",
            "ts-native-vlan-mismatch",
        ),
        ios_commands=("show interfaces trunk", "show interfaces GigabitEthernet0/1 switchport"),
    ),
    _cmd(
        "cmd-show-ip-route",
        "show ip route",
        "The IPv4 routing table: route code, prefix, administrative distance/metric, next hop and egress interface.",
        (
            "Codes identify the source: C connected, L local, S static, O OSPF, D EIGRP, R RIP, "
            "S* candidate default. The bracketed pair is administrative distance and metric. "
            "Selection across different prefixes is by longest match, not by the lowest distance; "
            "distance only breaks ties between sources offering the same prefix. Only the best "
            "route per prefix is installed. 'show ip route 0.0.0.0' isolates the default route and "
            "'show ip route ospf' filters by protocol. A route can exist in the configuration and "
            "still be absent from the table when its next hop is unresolvable."
        ),
        related=(
            "concept-administrative-distance",
            "ts-missing-route",
            "proto-ospf",
            "concept-default-gateway-vs-default-route",
        ),
        ios_commands=("show ip route", "show ip route 0.0.0.0", "show ip route ospf"),
    ),
    _cmd(
        "cmd-show-spanning-tree",
        "show spanning-tree",
        "Per-VLAN spanning tree topology: root bridge, bridge ID, and each port's role, state and cost.",
        (
            "Each VLAN block shows the Root ID, the local Bridge ID (priority plus MAC), and a "
            "table of interfaces with Role (Root, Designated, Alternate, Backup), State (FWD, BLK, "
            "LIS, LRN), Cost and neighbour priority. The root bridge is the lowest bridge ID, so "
            "the priority field decides before the MAC address. 'show spanning-tree root' lists the "
            "root per VLAN and 'show spanning-tree vlan 10' scopes the output. A port in BLK is "
            "working as designed, not failing."
        ),
        related=(
            "proto-stp",
            "ts-spanning-tree-root",
            "concept-broadcast-domain",
        ),
        ios_commands=("show spanning-tree", "show spanning-tree vlan 10", "show spanning-tree root"),
    ),
    _cmd(
        "cmd-show-etherchannel-summary",
        "show etherchannel summary",
        "Port-channel bundles with protocol and per-member flags showing whether each link is bundled.",
        (
            "One block per channel group: Group, Port-channel name, Protocol (LACP, PAgP or none "
            "for static) and member ports with flags. Read the flags as pairs: P means the port is "
            "in the bundle, I means standalone, s means suspended, D means down, U means in use, "
            "M means not in use, u means unsuitable and f means a default setting was used. The "
            "protocol column shows SU/SD for LACP and RU/RD for PAgP. Members flagged s or I mean "
            "the bundle did not form, usually because member configuration differs."
        ),
        related=(
            "proto-etherchannel-lacp",
            "ts-etherchannel-not-bundling",
        ),
        ios_commands=("show etherchannel summary", "show etherchannel port-channel"),
    ),
    _cmd(
        "cmd-show-access-lists",
        "show access-lists",
        "Configured ACLs with sequence numbers, match conditions and per-line hit counters.",
        (
            "Standard ACLs (1-99, 1300-1999) match source address only; extended ACLs (100-199, "
            "2000-2699) match protocol, source, destination, ports and flags. Lines are evaluated "
            "top down and the first match wins, so sequence numbers define behaviour. The counter "
            "at the end of each line shows how many packets hit it: the incrementing line is the "
            "one deciding the traffic. Every ACL ends with an implicit deny of all traffic, which "
            "never appears in the output. 'show ip access-lists' produces the same table."
        ),
        related=(
            "concept-acl-direction",
            "ts-acl-blocking-traffic",
            "proto-acl",
        ),
        ios_commands=("show access-lists", "show ip access-lists", "show access-lists 101"),
    ),
    _cmd(
        "cmd-show-ip-ospf-neighbor",
        "show ip ospf neighbor",
        "OSPF adjacencies with neighbour ID, state, dead timer and the local interface used.",
        (
            "States progress DOWN, INIT, 2-WAY, EXSTART, EXCHANGE, LOADING, FULL. On a broadcast "
            "segment only the DR and BDR reach FULL with every other router; two DROTHER routers "
            "correctly stop at 2-WAY. On point-to-point links and loopbacks FULL is expected. The "
            "neighbour ID is the router ID, which is normally the highest loopback or interface "
            "address and need not be the address on the shared link. The dead timer counts down "
            "from the dead interval. Empty output means no hello was accepted at all."
        ),
        related=(
            "concept-ospf-neighbors-vs-network-statement",
            "proto-ospf",
            "ts-ospf-adjacency-not-forming",
        ),
        ios_commands=(
            "show ip ospf neighbor",
            "show ip ospf interface",
            "show ip ospf database",
        ),
    ),
    _cmd(
        "cmd-show-ip-protocols",
        "show ip protocols",
        "Which routing protocols run, what they advertise, and their timers, distances and passive interfaces.",
        (
            "One block per routing process: protocol name, router ID, the networks it is routing "
            "for, passive interfaces, redistribution, maximum paths, administrative distance and "
            "timers. For OSPF the 'Routing for Networks' lines are the network statements as "
            "written, and a network statement enables OSPF on every interface whose address falls "
            "inside the range; it does not advertise one specific prefix verbatim. The output also "
            "shows whether a default originates into the protocol, which is why it is the natural "
            "companion to 'show ip route' when a route is missing."
        ),
        related=(
            "concept-ospf-neighbors-vs-network-statement",
            "cmd-show-ip-route",
            "proto-ospf",
            "ts-missing-route",
        ),
        ios_commands=("show ip protocols",),
    ),
    _cmd(
        "cmd-show-interfaces-status",
        "show interfaces status",
        "One line per switch port: connected state, access VLAN, duplex, speed and media type.",
        (
            "Status is connected, notconnect, err-disabled, disabled or suspended. The Vlan column "
            "shows the access VLAN of the port, not the trunk's allowed list. Duplex and Speed "
            "read a-auto or a fixed setting. err-disabled normally has a recorded cause that "
            "'show interfaces status err-disabled' prints, for example BPDU guard, port security "
            "or link flap. This is a layer 2 view available on switches; routers are normally "
            "inspected with 'show ip interface brief' and 'show interfaces' instead."
        ),
        related=(
            "cmd-show-ip-interface-brief",
            "ts-interface-down",
            "ts-duplex-speed-mismatch",
        ),
        ios_commands=("show interfaces status", "show interfaces status err-disabled"),
    ),
    _cmd(
        "cmd-show-mac-address-table",
        "show mac address-table",
        "The forwarding (CAM) table mapping MAC addresses to switch ports and VLANs.",
        (
            "Type is DYNAMIC for a learned address, STATIC for a manually configured one and "
            "SECURE for an address pinned by port security. The same MAC learned on two different "
            "ports of the same VLAN suggests a loop; a MAC appearing under a VLAN other than the "
            "expected one points at an access-VLAN or trunk mismatch. The table can be scoped with "
            "'show mac address-table interface GigabitEthernet0/1', '... vlan 10' or '... dynamic'. "
            "Entries age out, so an empty table on an idle segment is normal."
        ),
        related=(
            "concept-broadcast-domain",
            "ts-vlan-mismatch",
            "proto-stp",
        ),
        ios_commands=(
            "show mac address-table",
            "show mac address-table interface GigabitEthernet0/1",
            "show mac address-table vlan 10",
        ),
    ),
    # -----------------------------------------------------------------------
    # Concepts
    # -----------------------------------------------------------------------
    _concept(
        "concept-vlan-vs-trunk-vs-access",
        "VLAN vs access port vs trunk port",
        "An access port belongs to one VLAN and sends untagged frames; a trunk carries many VLANs with 802.1Q tags.",
        (
            "A VLAN is a broadcast domain identified by a 12-bit id (1-4094; 1 is the default and "
            "1002-1005 are reserved). An access port has 'switchport mode access' plus a VLAN "
            "assignment, and frames leave it untagged. A trunk port has 'switchport mode trunk' and "
            "tags every frame except traffic in its native VLAN. Trunk modes on, desirable and auto "
            "are not equivalent: 'on' forces trunking with no negotiation and is the predictable "
            "choice for links whose two ends are managed separately. A port is one or the other, "
            "never both; the mode decides how it behaves when a neighbour disagrees."
        ),
        related=(
            "concept-native-vlan",
            "proto-8021q",
            "cmd-show-vlan-brief",
            "cmd-show-interfaces-trunk",
        ),
        ios_commands=("switchport mode trunk", "switchport access vlan 10", "show interfaces switchport"),
    ),
    _concept(
        "concept-native-vlan",
        "Native VLAN",
        "On an 802.1Q trunk, the one VLAN whose frames cross untagged; the value must match on both ends.",
        (
            "The native VLAN defaults to VLAN 1. Frames in that VLAN leave the trunk without a tag, "
            "and the receiving switch places them in its own native VLAN. A mismatch does not bring "
            "the trunk down: tagged VLANs keep working while untagged traffic silently joins two "
            "different broadcast domains, which is the classic 'trunk up, one VLAN broken' fault. "
            "CDP may log a native VLAN mismatch. 'vlan dot1q tag native' removes the ambiguity by "
            "tagging that traffic too. Common practice is to set an unused native VLAN on both ends "
            "and never carry user traffic in it."
        ),
        related=(
            "concept-vlan-vs-trunk-vs-access",
            "proto-8021q",
            "ts-native-vlan-mismatch",
            "cmd-show-interfaces-trunk",
        ),
        ios_commands=("switchport trunk native vlan 99", "show interfaces trunk", "vlan dot1q tag native"),
    ),
    _concept(
        "concept-svi",
        "Switch virtual interface (SVI)",
        "A routed interface for a VLAN, created with interface vlan N, that acts as that VLAN's gateway.",
        (
            "An SVI gives a VLAN an IP address and mask so the switch can route for it. The VLAN "
            "must exist, and the line protocol only comes up when the VLAN is active in hardware, "
            "which normally requires at least one access port in the VLAN or an active trunk "
            "carrying it. Hosts in the VLAN use the SVI address as their default gateway. On a "
            "layer 2 only switch an SVI is for management, not inter-VLAN routing; inter-VLAN "
            "routing needs a layer 3 switch or router-on-a-stick subinterfaces."
        ),
        related=(
            "concept-default-gateway-vs-default-route",
            "cmd-show-ip-interface-brief",
            "ts-interface-down",
            "proto-arp",
        ),
        ios_commands=("interface vlan 10", "show ip interface brief", "show vlan brief"),
    ),
    _concept(
        "concept-default-gateway-vs-default-route",
        "ip default-gateway vs a default route",
        "ip default-gateway is for layer 2 switches; ip route 0.0.0.0/0 is a real routing-table entry.",
        (
            "'ip default-gateway A.B.C.D' gives a device a next hop for its own management traffic "
            "when IP routing is disabled, which is the normal case on a layer 2 switch. It is "
            "ignored once 'ip routing' is enabled. 'ip route 0.0.0.0 0.0.0.0 <next-hop>' installs a "
            "default route in the routing table, shown with an S* code, and is what forwards routed "
            "traffic; an OSPF router can also originate one with default-information originate. On "
            "a router, ip default-gateway does nothing for transit traffic. Mixing them up is a "
            "recurring cause of a switch that can be pinged locally but cannot forward."
        ),
        related=(
            "concept-administrative-distance",
            "ts-missing-route",
            "cmd-show-ip-route",
            "concept-static-vs-dynamic-routing",
        ),
        ios_commands=(
            "ip default-gateway 192.168.1.1",
            "ip route 0.0.0.0 0.0.0.0 192.168.1.1",
            "show ip route 0.0.0.0",
        ),
    ),
    _concept(
        "concept-ospf-neighbors-vs-network-statement",
        "OSPF neighbours vs configured network statements",
        "A network statement enables OSPF on matching interfaces; an adjacency is a separate, negotiated event.",
        (
            "'network 10.0.0.0 0.0.0.255 area 0' matches every interface whose address falls in that "
            "range and runs OSPF on it in area 0. It does not create a neighbour by itself: two "
            "routers must exchange hellos on the same subnet with the same area, hello and dead "
            "timers, authentication and MTU, and the interface must not be passive. Conversely a "
            "FULL adjacency does not prove a prefix is exchanged; that depends on what each router "
            "advertises into the area. Configuration therefore never demonstrates adjacency, and "
            "'show ip ospf neighbor' is the only view that does."
        ),
        related=(
            "proto-ospf",
            "cmd-show-ip-ospf-neighbor",
            "cmd-show-ip-protocols",
            "ts-ospf-adjacency-not-forming",
        ),
        ios_commands=("network 10.0.0.0 0.0.0.255 area 0", "show ip ospf neighbor", "passive-interface GigabitEthernet0/1"),
    ),
    _concept(
        "concept-acl-direction",
        "ACL direction: in and out",
        "in filters traffic entering the router from that interface; out filters traffic leaving it.",
        (
            "'ip access-group 101 in' applies to packets arriving on the interface, before the "
            "routing decision. 'out' applies to packets that have been routed and are leaving "
            "toward that interface. Placing an extended ACL near the source saves transit "
            "bandwidth; a standard ACL should sit near the destination because it can only match "
            "the source and would otherwise block more than intended. Traffic originated by the "
            "router itself is not filtered by an inbound ACL on its own interface. Because every "
            "ACL ends with an implicit deny, a single missing permit can black-hole a whole "
            "direction."
        ),
        related=(
            "proto-acl",
            "ts-acl-blocking-traffic",
            "cmd-show-access-lists",
        ),
        ios_commands=(
            "ip access-group 101 in",
            "show ip interface GigabitEthernet0/1",
            "show access-lists",
        ),
    ),
    _concept(
        "concept-nat-overload",
        "NAT overload (PAT)",
        "Many inside hosts share one outside address, distinguished per flow by source port.",
        (
            "'ip nat inside source list 1 interface GigabitEthernet0/0 overload' translates the "
            "source of matching inside traffic to the outside interface address and remembers a "
            "port mapping per flow. It requires an interface marked 'ip nat inside' and another "
            "marked 'ip nat outside'; with either missing, packets are routed without being "
            "translated. 'show ip nat translations' lists the live mappings and 'show ip nat "
            "statistics' reports hits and misses. Overload does not permit unsolicited inbound "
            "connections, which need a static port mapping instead."
        ),
        related=(
            "proto-nat",
            "ts-nat-not-translating",
            "concept-acl-direction",
        ),
        ios_commands=(
            "ip nat inside source list 1 interface GigabitEthernet0/0 overload",
            "show ip nat translations",
            "show ip nat statistics",
        ),
    ),
    _concept(
        "concept-dhcp-relay",
        "DHCP relay (ip helper-address)",
        "Forwards client broadcasts as unicast toward a central DHCP server and records the client subnet.",
        (
            "A DHCP discover is a broadcast and a router does not forward broadcasts, so clients on "
            "a remote subnet receive nothing unless the router relays. 'ip helper-address A.B.C.D' "
            "on the client-facing interface rewrites the broadcast to unicast toward the server and "
            "fills in giaddr with the interface address, which is how the server selects the right "
            "pool. Relay requires a route to the server and the server must have a route back to "
            "giaddr. The same command relays a small set of other UDP services such as TFTP and "
            "DNS, which is why it is also called the UDP helper."
        ),
        related=(
            "proto-dhcp",
            "ts-dhcp-not-assigned",
            "concept-svi",
        ),
        ios_commands=(
            "ip helper-address 10.10.10.5",
            "show ip interface GigabitEthernet0/1",
            "show ip dhcp binding",
        ),
    ),
    _concept(
        "concept-administrative-distance",
        "Administrative distance",
        "Ranks route sources for the same prefix; the lowest distance wins.",
        (
            "Default distances are connected 0, static 1, eBGP 20, EIGRP 90, OSPF 110, RIP 120 and "
            "iBGP 200. Distance only chooses between candidate routes to the same prefix from "
            "different sources; for different prefixes the longest match decides regardless of "
            "distance, and within one protocol the metric decides. 'show ip route' prints the pair "
            "as [distance/metric]. Configuring a static route with a distance higher than the "
            "dynamic route produces a floating static that is installed only when the dynamic route "
            "disappears."
        ),
        related=(
            "cmd-show-ip-route",
            "concept-default-gateway-vs-default-route",
            "concept-static-vs-dynamic-routing",
        ),
        ios_commands=("show ip route", "ip route 0.0.0.0 0.0.0.0 10.1.1.1 250"),
    ),
    _concept(
        "concept-static-vs-dynamic-routing",
        "Static vs dynamic routing",
        "Static routes are manual and fixed; dynamic protocols learn prefixes and reconverge on failure.",
        (
            "A static route is written by hand ('ip route <prefix> <mask> <next-hop or interface>'), "
            "costs no protocol overhead and needs no neighbour, but does not adapt when a link "
            "fails unless a floating static or object tracking is added. Dynamic protocols (OSPF, "
            "EIGRP, RIP) exchange prefixes with neighbours and reconverge after a change, at the "
            "price of configuration that must agree end to end. A static route configured with only "
            "an egress interface on a multi-access segment makes the router ARP for every "
            "destination; a next hop is the clearer form on broadcast media."
        ),
        related=(
            "concept-administrative-distance",
            "proto-static-routing",
            "proto-ospf",
            "ts-missing-route",
        ),
        ios_commands=("ip route 0.0.0.0 0.0.0.0 10.1.1.1", "show ip route static"),
    ),
    _concept(
        "concept-broadcast-domain",
        "Broadcast domain",
        "The set of ports a broadcast frame reaches: one VLAN, or one routed segment.",
        (
            "A switch floods broadcasts out every port in the VLAN, and routers do not forward them "
            "between interfaces, so each VLAN on a switch is one broadcast domain. A trunk carries "
            "several VLANs between switches without merging their broadcast domains, because the "
            "tag keeps them apart. Splitting a flat network into VLANs shrinks broadcast scope and "
            "gives each subnet a boundary where an ACL or firewall rule can apply. A layer 2 loop "
            "inside one VLAN multiplies broadcasts until spanning tree blocks a port, which is why "
            "loops manifest as broadcast storms rather than as routing problems."
        ),
        related=(
            "concept-vlan-vs-trunk-vs-access",
            "proto-stp",
            "cmd-show-mac-address-table",
        ),
        ios_commands=("show vlan brief", "show spanning-tree"),
    ),
    _concept(
        "concept-arp",
        "ARP resolution",
        "Maps an IPv4 address to a MAC address inside the local subnet only.",
        (
            "A host with a destination IP but no cache entry broadcasts a request for that address "
            "and the owner replies unicast with its MAC. IOS caches entries for minutes, visible "
            "with 'show arp' or 'show ip arp', and incomplete entries expire quickly. ARP is not "
            "routed: a host sends ARP only for destinations inside its own mask and sends "
            "everything else to its default gateway's MAC. A wrong subnet mask therefore shows up "
            "as an unresolved ARP rather than as a routing error. Proxy ARP lets a router answer on "
            "behalf of a subnet it can reach."
        ),
        related=(
            "proto-arp",
            "concept-svi",
            "ts-missing-route",
        ),
        ios_commands=("show arp", "show ip arp", "clear arp-cache"),
    ),
    # -----------------------------------------------------------------------
    # Troubleshooting
    # -----------------------------------------------------------------------
    _ts(
        "ts-interface-down",
        "Interface down or administratively down",
        "Separate a configured shutdown from a physical or line-protocol failure.",
        (
            "Read the two status words before changing anything. 'administratively down' means a "
            "shutdown command is configured and 'no shutdown' is the fix. 'down/down' means no "
            "link at all: cable, patch panel, wrong port, dead NIC or a speed/duplex problem. "
            "'up/down' is subtler: layer 1 exists but the line protocol fails, which points at "
            "keepalives, encapsulation mismatch, a trunk that has not negotiated, or clocking on a "
            "serial link. On a switch, 'notconnect' in 'show interfaces status' means nothing is "
            "plugged in or the far end is down. Error counters such as CRC and runts separate "
            "cabling faults from configuration faults."
        ),
        related=(
            "cmd-show-ip-interface-brief",
            "cmd-show-interfaces-status",
            "ts-duplex-speed-mismatch",
            "concept-svi",
        ),
        ios_commands=(
            "show ip interface brief",
            "show interfaces GigabitEthernet0/1",
            "show interfaces status",
        ),
    ),
    _ts(
        "ts-vlan-mismatch",
        "VLAN mismatch between two hosts",
        "Two hosts in the same subnet cannot reach each other because their ports sit in different VLANs.",
        (
            "Symptoms are no ping inside the subnet, ARP that never resolves, and a router that "
            "places the two addresses in different connected networks. Compare 'show vlan brief' "
            "and 'show interfaces switchport' on both switches to read each port's access VLAN. "
            "Common causes are a port left in VLAN 1, a wrong 'switchport access vlan', VTP "
            "overwriting the local VLAN database, or a trunk that does not allow the VLAN. If the "
            "same MAC appears under a different VLAN on the other switch, the frame crossed a "
            "trunk and landed in the wrong broadcast domain."
        ),
        related=(
            "concept-vlan-vs-trunk-vs-access",
            "cmd-show-vlan-brief",
            "cmd-show-mac-address-table",
            "proto-vtp",
        ),
        ios_commands=("show vlan brief", "show interfaces switchport", "show mac address-table"),
    ),
    _ts(
        "ts-trunk-not-forming",
        "Trunk not forming",
        "The link is up but no VLANs cross it, or the port never appears in show interfaces trunk.",
        (
            "Check both ends with 'show interfaces trunk': a port absent from the output is not "
            "trunking. Frequent causes are one end left in access mode, dynamic auto on both ends "
            "so nobody initiates, mismatched encapsulation, different allowed-VLAN lists, or VTP "
            "pruning a VLAN out of the link. When the trunk forms but one VLAN is missing, compare "
            "the columns for VLANs allowed on the trunk and VLANs allowed and active in the "
            "management domain: a VLAN that is allowed but not active locally cannot pass, and a "
            "VLAN absent from the local VLAN database is never active."
        ),
        related=(
            "concept-native-vlan",
            "cmd-show-interfaces-trunk",
            "proto-8021q",
            "proto-vtp",
        ),
        ios_commands=(
            "show interfaces trunk",
            "show interfaces GigabitEthernet0/1 switchport",
            "show vlan brief",
        ),
    ),
    _ts(
        "ts-native-vlan-mismatch",
        "Native VLAN mismatch on a trunk",
        "The trunk stays up, but untagged traffic lands in a different VLAN at each end.",
        (
            "CDP may log a native VLAN mismatch, and 'show interfaces trunk' prints a different "
            "Native vlan value on the two switches. Tagged VLANs keep working, which is what makes "
            "the fault easy to miss: only untagged traffic, including the switches' own management "
            "traffic when it uses the native VLAN, is misdelivered. The effect is that two separate "
            "broadcast domains appear as one, so hosts in unrelated subnets can answer each other's "
            "ARP. Fix it by matching 'switchport trunk native vlan N' on both ends, or tag the "
            "native VLAN, and keep user traffic out of it."
        ),
        related=(
            "concept-native-vlan",
            "cmd-show-interfaces-trunk",
            "ts-trunk-not-forming",
        ),
        ios_commands=("show interfaces trunk", "switchport trunk native vlan 999"),
    ),
    _ts(
        "ts-missing-route",
        "Missing route on a transit device",
        "A destination is reachable locally but a transit device has no matching entry in its table.",
        (
            "Walk the path with 'show ip route <prefix>' on every hop; a missing entry means no "
            "connected, static or dynamic route covers the prefix. Distinct causes look similar: a "
            "wrong mask makes the connected prefix different from what was intended, OSPF network "
            "statements may not match the interface address, a transit interface may be passive, an "
            "ACL may filter the routing protocol, or a static route may point at an unresolvable "
            "next hop and never install. A default route on one side does not create the return "
            "path, so check both directions."
        ),
        related=(
            "cmd-show-ip-route",
            "concept-default-gateway-vs-default-route",
            "concept-administrative-distance",
            "proto-ospf",
        ),
        ios_commands=("show ip route", "show ip route 10.20.0.0", "show ip protocols"),
    ),
    _ts(
        "ts-acl-blocking-traffic",
        "ACL blocking traffic",
        "Traffic is dropped even though the route exists, because an ACL line is matching it.",
        (
            "First confirm the ACL is applied where you think: 'show ip interface <if>' lists the "
            "inbound and outbound access lists by name or number. Then read 'show access-lists' and "
            "watch the counters while traffic flows; the incrementing line is the one deciding. "
            "Classic mistakes are the wrong direction, the implicit deny catching traffic that "
            "should have been permitted earlier, a standard ACL placed close to the source so it "
            "blocks more than intended, and a permit that omits the port numbers the application "
            "needs. Because the implicit deny is invisible, a list that looks permissive can still "
            "drop everything else."
        ),
        related=(
            "concept-acl-direction",
            "cmd-show-access-lists",
            "proto-acl",
        ),
        ios_commands=(
            "show access-lists",
            "show ip interface GigabitEthernet0/1",
            "show running-config | include access-group",
        ),
    ),
    _ts(
        "ts-dhcp-not-assigned",
        "Clients are not receiving DHCP addresses",
        "A 169.254.x.x address means no reply arrived; the discover never reached a server.",
        (
            "A 169.254/16 address is a link-local fallback, so the client asked and received "
            "nothing. On a remote subnet the router interface facing the client needs 'ip "
            "helper-address <server>' pointing at a reachable server. Then check that a pool exists "
            "for the relay subnet, that it is not exhausted, that the server has a route back to "
            "the relay address, and that no ACL blocks UDP 67 and 68. On the local segment, verify "
            "the switch port is in the expected VLAN and the server or SVI is up. 'show ip dhcp "
            "binding' lists leases actually granted."
        ),
        related=(
            "concept-dhcp-relay",
            "proto-dhcp",
            "ts-vlan-mismatch",
        ),
        ios_commands=(
            "show ip interface GigabitEthernet0/1",
            "show ip dhcp binding",
            "show ip dhcp pool",
        ),
    ),
    _ts(
        "ts-ospf-adjacency-not-forming",
        "OSPF adjacency not forming",
        "Neighbours stall in INIT or EXSTART, or never appear at all.",
        (
            "INIT means hellos are arriving one way, which points at an ACL, a one-way link or a "
            "neighbour that does not accept this router's hello. A stall in EXSTART or EXCHANGE is "
            "usually an MTU mismatch that breaks database description exchange; aligning MTU is "
            "better than masking it with 'ip ospf mtu-ignore'. No neighbour at all means a "
            "different area, a different subnet or mask on the shared link, mismatched hello or "
            "dead timers, an authentication mismatch, or an interface marked passive. On a "
            "broadcast segment only the DR and BDR reach FULL, so two DROTHER routers at 2-WAY are "
            "behaving correctly."
        ),
        related=(
            "concept-ospf-neighbors-vs-network-statement",
            "proto-ospf",
            "cmd-show-ip-ospf-neighbor",
        ),
        ios_commands=(
            "show ip ospf neighbor",
            "show ip ospf interface",
            "show ip ospf interface brief",
        ),
    ),
    _ts(
        "ts-duplex-speed-mismatch",
        "Duplex or speed mismatch",
        "The link is up but slow, with late collisions, CRC errors and loss under load.",
        (
            "The classic case is one end hard-set to 100/full while the other negotiates: the "
            "negotiating end can settle on half duplex, producing late collisions, FCS and CRC "
            "errors, runts and very low throughput that worsens as load rises. Read the duplex and "
            "speed lines in 'show interfaces' and the a-auto markers in 'show interfaces status', "
            "then compare the two ends of the same cable. Fix it by leaving both ends on "
            "autonegotiation or by hard-setting both ends identically; setting one end only is "
            "what creates the mismatch."
        ),
        related=(
            "cmd-show-interfaces-status",
            "ts-interface-down",
        ),
        ios_commands=("show interfaces GigabitEthernet0/1", "show interfaces status"),
    ),
    _ts(
        "ts-etherchannel-not-bundling",
        "EtherChannel members not bundled",
        "Members show suspended or standalone flags instead of joining the port-channel.",
        (
            "In 'show etherchannel summary', members flagged s (suspended) or I (standalone) did "
            "not join the bundle. Members must agree on speed, duplex, switchport mode, allowed and "
            "native VLANs, and none may be configured as a routed port; the channel-group number "
            "must match at both ends and the negotiation must be compatible, since LACP passive on "
            "both ends never forms because nobody initiates. 'show etherchannel port-channel' prints "
            "each member's flags and the reason it was not bundled. Mismatched member "
            "configuration is by far the most common cause."
        ),
        related=(
            "cmd-show-etherchannel-summary",
            "proto-etherchannel-lacp",
        ),
        ios_commands=(
            "show etherchannel summary",
            "show etherchannel port-channel",
            "show interfaces GigabitEthernet0/1 etherchannel",
        ),
    ),
    _ts(
        "ts-nat-not-translating",
        "NAT not translating",
        "Inside hosts cannot reach the outside and the translation table stays empty.",
        (
            "If 'show ip nat translations' is empty while traffic is being sent, no packet matched "
            "the NAT rule. Confirm that at least one interface is marked 'ip nat inside' and the "
            "egress interface is marked 'ip nat outside', that the inside ACL actually matches the "
            "inside source addresses, that a route to the outside exists, and that the outside "
            "interface is up. 'show ip nat statistics' reports hits and shows whether the rule was "
            "evaluated at all. Also check that the same ACL is not applied to an interface in a way "
            "that drops the traffic before translation."
        ),
        related=(
            "concept-nat-overload",
            "proto-nat",
        ),
        ios_commands=(
            "show ip nat translations",
            "show ip nat statistics",
            "show ip interface brief",
        ),
    ),
    _ts(
        "ts-spanning-tree-root",
        "Unexpected spanning-tree root bridge",
        "An access switch became the root, so traffic takes a long path and some links idle.",
        (
            "The root is the lowest bridge ID: priority first, then MAC address. Two switches left "
            "at the default priority of 32768 are separated only by MAC, so an older access switch "
            "can win and become root, pulling traffic across the access layer. 'show spanning-tree' "
            "reveals it when an unexpected switch reports that it is the root, and 'show "
            "spanning-tree root' lists the root per VLAN. Set the intended core switch with "
            "'spanning-tree vlan 10 root primary' and a backup with 'root secondary', then verify "
            "that the root port roles point toward the core."
        ),
        related=(
            "proto-stp",
            "cmd-show-spanning-tree",
        ),
        ios_commands=(
            "show spanning-tree",
            "show spanning-tree root",
            "spanning-tree vlan 10 root primary",
        ),
    ),
    # -----------------------------------------------------------------------
    # Protocols
    # -----------------------------------------------------------------------
    _proto(
        "proto-ospf",
        "OSPF",
        "A link-state interior gateway protocol: neighbours flood link-state advertisements and each router runs SPF.",
        (
            "Hellos are sent every 10 seconds with a 40 second dead interval on broadcast and "
            "point-to-point links, and every 30/120 on NBMA; they go to 224.0.0.5 and 224.0.0.6. On "
            "broadcast segments a DR and BDR are elected so that adjacencies scale with routers "
            "rather than with pairs. Areas confine flooding, and area 0 is the backbone every other "
            "area must reach. Cost is reference bandwidth divided by interface bandwidth, and "
            "administrative distance is 110. A FULL adjacency is necessary but not sufficient for "
            "routes: the prefix must also be advertised into the same area."
        ),
        related=(
            "concept-ospf-neighbors-vs-network-statement",
            "cmd-show-ip-ospf-neighbor",
            "cmd-show-ip-protocols",
            "ts-ospf-adjacency-not-forming",
        ),
        ios_commands=(
            "router ospf 1",
            "network 10.0.0.0 0.0.0.255 area 0",
            "show ip ospf neighbor",
        ),
    ),
    _proto(
        "proto-stp",
        "Spanning Tree Protocol",
        "Blocks redundant layer 2 ports so the active topology is a loop-free tree.",
        (
            "Classic 802.1D elects one root bridge, gives every non-root bridge one root port and "
            "every segment one designated port, and blocks the rest; convergence can take 30 to 50 "
            "seconds. Rapid STP (802.1w) adds alternate and backup roles and reaches forwarding in "
            "well under a second, especially with edge ports. PortFast skips listening and learning "
            "on host ports, and BPDU Guard err-disables a PortFast port that receives a BPDU, "
            "protecting the topology from an unexpected switch. Cisco runs an instance per VLAN "
            "(PVST+ or rapid PVST+), so a port can forward for one VLAN and block for another."
        ),
        related=(
            "cmd-show-spanning-tree",
            "ts-spanning-tree-root",
            "concept-broadcast-domain",
        ),
        ios_commands=(
            "show spanning-tree",
            "spanning-tree mode rapid-pvst",
            "spanning-tree portfast",
        ),
    ),
    _proto(
        "proto-vtp",
        "VTP (VLAN Trunking Protocol)",
        "Distributes VLAN additions, deletions and renames between switches in one management domain.",
        (
            "A server advertises VLAN changes to its clients, which apply them; transparent mode "
            "forwards advertisements but keeps its own database. Advertisements travel over trunks "
            "and are accepted only when the domain name, password and version match. The revision "
            "number is the hazard: a switch reconnected with a higher revision number overwrites "
            "the domain's VLAN database and can delete VLANs that were in use. Modern practice is "
            "transparent mode, or none at all, with VLANs created explicitly on each switch. "
            "'show vtp status' prints mode, domain, version and revision."
        ),
        related=(
            "proto-8021q",
            "ts-trunk-not-forming",
            "cmd-show-vlan-brief",
        ),
        ios_commands=("show vtp status", "vtp mode transparent", "show vlan brief"),
    ),
    _proto(
        "proto-8021q",
        "802.1Q tagging",
        "The IEEE trunking standard: a 4-byte tag carries the VLAN id and priority, except on the native VLAN.",
        (
            "The tag is inserted after the source MAC address and adds 4 bytes to the frame, which "
            "matters for MTU accounting. Its 12-bit VLAN id field allows 4094 usable VLANs. On a "
            "trunk every frame is tagged except frames in the native VLAN, which travel untagged so "
            "that untagged legacy traffic still works. ISL is the older Cisco proprietary "
            "alternative and does not interoperate with 802.1Q. End stations normally send "
            "untagged frames; the access port adds the tag on ingress to a trunk and strips it on "
            "egress to a host."
        ),
        related=(
            "concept-vlan-vs-trunk-vs-access",
            "concept-native-vlan",
            "cmd-show-interfaces-trunk",
        ),
        ios_commands=("switchport trunk encapsulation dot1q", "show interfaces trunk"),
    ),
    _proto(
        "proto-dhcp",
        "DHCP",
        "A UDP protocol that leases addresses together with mask, gateway, DNS and lease timers.",
        (
            "Client uses UDP 68, server UDP 67. The exchange is DORA: DISCOVER broadcast, OFFER, "
            "REQUEST, ACK. Renewal is unicast at T1, half the lease, and rebinding is broadcast at "
            "T2, seven eighths of it. The server selects a pool from giaddr when the request was "
            "relayed, otherwise from the interface that received it. Options carry the mask, "
            "default router, DNS servers, domain name and lease time. A client that gets no answer "
            "falls back to a 169.254/16 link-local address, which is the diagnostic that a reply "
            "never arrived."
        ),
        related=(
            "concept-dhcp-relay",
            "ts-dhcp-not-assigned",
        ),
        ios_commands=("show ip dhcp binding", "show ip dhcp pool", "ip helper-address 10.10.10.5"),
    ),
    _proto(
        "proto-nat",
        "NAT",
        "Translates addresses between inside and outside, either statically, from a pool, or with PAT.",
        (
            "Static NAT maps one inside host to one outside address; dynamic NAT maps many inside "
            "hosts to a pool of outside addresses; overload maps many inside hosts to a single "
            "address, tracking a port per flow. Inside and outside are properties of interfaces, "
            "and translation happens as traffic crosses from inside to outside, with the return "
            "flow reversed from the same table. NAT breaks end-to-end addressing, so payloads that "
            "embed IP addresses need application gateways, and unsolicited inbound connections "
            "require a static port mapping."
        ),
        related=(
            "concept-nat-overload",
            "ts-nat-not-translating",
        ),
        ios_commands=(
            "ip nat inside source list 1 interface GigabitEthernet0/0 overload",
            "show ip nat translations",
        ),
    ),
    _proto(
        "proto-arp",
        "ARP",
        "Resolves an IPv4 address to a MAC address on the local segment.",
        (
            "A request is broadcast and the reply is unicast, after which the pair is cached and "
            "aged out. Incomplete entries expire in minutes, complete entries in hours on IOS. "
            "Gratuitous ARP announces a new MAC for an address, which is how failover is often "
            "detected, and duplicate address detection uses the same mechanism. Proxy ARP lets a "
            "router answer on behalf of an address it can reach, extending a subnet across a router "
            "at the cost of clarity. ARP never crosses a router, so each hop resolves the next hop "
            "separately."
        ),
        related=(
            "concept-arp",
            "concept-svi",
            "ts-missing-route",
        ),
        ios_commands=("show arp", "show ip arp", "clear arp-cache"),
    ),
    _proto(
        "proto-etherchannel-lacp",
        "EtherChannel and LACP",
        "Bundles parallel links into one logical port-channel; LACP is the IEEE 802.3ad negotiation.",
        (
            "LACP modes are active and passive: active initiates negotiation and passive responds, "
            "so passive on both ends never forms a bundle. PAgP is Cisco proprietary (desirable and "
            "auto) and does not interoperate with LACP; static 'on' needs no protocol but has no "
            "negotiation and no mismatch detection. Members must match in speed, duplex, switchport "
            "mode and allowed VLANs. Load balancing is per flow, chosen by a hash of MAC or IP "
            "addresses, so a single flow never exceeds the bandwidth of one member link."
        ),
        related=(
            "cmd-show-etherchannel-summary",
            "ts-etherchannel-not-bundling",
        ),
        ios_commands=("channel-group 1 mode active", "show etherchannel summary"),
    ),
    _proto(
        "proto-acl",
        "Access control lists",
        "Ordered permit and deny statements, applied to an interface in a direction, with an implicit deny at the end.",
        (
            "Standard ACLs match the source address only; extended ACLs match protocol, source, "
            "destination, ports and flags. Evaluation is top down and the first match wins, so "
            "order is the semantics. Every ACL ends with an implicit deny of all traffic, which is "
            "never printed. Wildcard masks are inverted subnet masks: a 0 bit must match and a 255 "
            "bit is ignored. Beyond filtering, ACLs select traffic for NAT, route filtering and QoS "
            "classification. Named ACLs accept insertion by sequence number; numbered ACLs append "
            "and must be rebuilt to reorder."
        ),
        related=(
            "concept-acl-direction",
            "cmd-show-access-lists",
            "ts-acl-blocking-traffic",
        ),
        ios_commands=(
            "access-list 101 permit tcp any host 10.1.1.1 eq 80",
            "show access-lists",
        ),
    ),
    _proto(
        "proto-static-routing",
        "Static routing",
        "Manually written route entries with no protocol, no advertisement and no automatic failover.",
        (
            "Syntax is 'ip route <prefix> <mask> <next-hop or interface> [distance]'. The default "
            "distance of 1 means a static route beats any IGP for the same prefix, and a larger "
            "value such as 250 makes it a floating static that is installed only when the dynamic "
            "route disappears. A route with a next hop is usable only when that next hop is "
            "reachable through a connected route; otherwise it stays out of the table. Static "
            "routes are not transitive: each device on the path needs its own entry toward the "
            "destination."
        ),
        related=(
            "concept-static-vs-dynamic-routing",
            "concept-administrative-distance",
            "ts-missing-route",
        ),
        ios_commands=("ip route 0.0.0.0 0.0.0.0 10.1.1.1", "show ip route static"),
    ),
)
