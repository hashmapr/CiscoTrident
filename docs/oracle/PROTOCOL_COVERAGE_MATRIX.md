# PROTOCOL COVERAGE MATRIX

Date: 2026-11-10 · Branch `development/deepcore` · RC `trident-stream-verify-rc1` = `9d14807`

Levels are ordered, and each claim names its evidence. A level is never inferred
from a module existing; it is claimed only where a named test or captured
simulator output establishes it.

| Level | Meaning |
|---|---|
| UNSUPPORTED | nothing parses or models it |
| PARSED | configuration is parsed into typed facts |
| MODELLED | deterministic reasoning derives conclusions from those facts |
| STATICALLY_VERIFIED | unit/integration tests pin those conclusions |
| SIMULATOR_TESTED | a live Packet Tracer observation agreed with the prediction |

**No protocol in this table is `SIMULATOR_TESTED` for the protocol-semantics work
described below.** The two `SIMULATOR_TESTED` rows are older IPv4 work.

---

## Matrix

| Feature | Level | Live PT? | Why that level |
|---|---|---|---|
| ipv4_addressing | SIMULATOR_TESTED | yes | live PDU differential on sample lab |
| static_routing | SIMULATOR_TESTED | yes | live PDU differential on sample lab |
| subnetting | STATICALLY_VERIFIED | no | longest-prefix tests |
| vlans | STATICALLY_VERIFIED | no | shutdown/access-port semantics tests |
| trunks | STATICALLY_VERIFIED | no | trunk/Native VLAN parsing tests |
| acl | STATICALLY_VERIFIED | config captured live | **3 defects fixed this sprint**; real ACEs from ISP A; no PDU-through-ACL test |
| dhcp | STATICALLY_VERIFIED | no | pool misconfiguration tests |
| **stp** | STATICALLY_VERIFIED | `show` only | parsed + modelled; no lab configures priority or `root primary` |
| **etherchannel** | STATICALLY_VERIFIED | `show` only | parsed + modelled; no lab has a `channel-group` |
| **nat** | STATICALLY_VERIFIED | `show` only | parsed + modelled; no lab has any `ip nat` rule |
| **ipv6** | STATICALLY_VERIFIED | `show` only | parsed + modelled; every lab reports `0 entries` |
| ospf | PARSED | no | network statements recorded; no adjacency or cost model |
| qos | UNSUPPORTED | — | not parsed |
| routing_authentication | UNSUPPORTED | — | not parsed |
| port_security | UNSUPPORTED | — | not parsed |
| device_administration | UNSUPPORTED | — | not parsed |

Counts: UNSUPPORTED 4 · PARSED 1 · MODELLED 0 · STATICALLY_VERIFIED 9 · SIMULATOR_TESTED 2.
Machine-readable: `trident/deepcore/coverage.json`.

---

## Supported IOS command subsets

For each protocol, the exact commands the typed parser understands. Anything
outside this list is preserved verbatim in `unsupported`, so its presence is never
mistaken for its absence.

### STP (`trident/deepcore/protocols.py`, `stp.py`)

Parsed: `spanning-tree mode {pvst|rapid-pvst|mst}`, `spanning-tree vlan <list> priority <n>`,
`spanning-tree vlan <list> root {primary|secondary}`, interface `spanning-tree portfast`,
`spanning-tree bpduguard enable`, `spanning-tree bpdufilter enable`,
`spanning-tree guard root|loop`, interface `spanning-tree cost <n>`,
`spanning-tree port-priority <n>`, and their `no` forms.

Not parsed: MST instance mapping, `spanning-tree vlan ... root primary diameter`,
UplinkFast/BackboneFast semantics, BPDU filter interaction at port vs global.

Prediction depth: root election (priority then MAC), port roles on a given link
list, `UNDECIDED` with the missing fact named when evidence is insufficient.
Roles between non-root bridges use local cost, not full root-path cost.
Not modelled: convergence timing, BPDU contents, PVST per-VLAN independent trees.

### EtherChannel (`etherchannel.py`)

Parsed: `channel-group <n> mode {active|passive|desirable|auto|on}`,
`channel-protocol {lacp|pagp}`, member interfaces, `no channel-group`.

Not parsed: load-balancing hash policy, `port-channel load-balance`, LACP timers,
min-links, member speed/duplex/vlan compatibility beyond recorded facts.

Prediction depth: full negotiation matrix; illegal pairings refused **with the
reason** (`passive/passive`, `auto/auto`, LACP against PAgP, `on` against a
negotiating mode). `assess_all` returns nothing when no channel is configured, so
an ordinary switch is not reported as broken.

### NAT/PAT (`nat.py`)

Parsed: `ip nat inside source static <local> <global>`,
`ip nat inside source list <acl> pool <name> [overload]`,
`ip nat inside source list <acl> interface <if> overload`,
`ip nat pool <name> <start> <end> netmask|prefix-length`,
interface `ip nat inside|outside`, `ip access-group`, numbered ACL ACEs, `no ip nat ...`.

Not parsed: NAT virtual interfaces, `ip nat translation` timeouts, twice NAT,
NAT64, route-maps, port-level static mappings.

Prediction depth: configured translation only. Static, dynamic pool, PAT overload
and ACL-selected traffic. Detects missing inside/outside roles, undefined pools,
and an interface marked both inside and outside, with no packet needed. **PAT port
assignments are never guessed** — the result says the port depends on runtime
allocation order. **No active translation table is consulted.**

### IPv6 (`ipv6.py`)

Parsed: interface `ipv6 address <addr>/<prefix>`, `ipv6 address <addr> link-local`,
`ipv6 enable`, `ipv6 nd ...` (recorded), `ipv6 unicast-routing` (global gate),
`ipv6 route <prefix> <next-hop|interface>`, `ipv6 access-list`, `no ipv6 ...`.

Not parsed: DHCPv6, RA timers, OSPFv3/EIGRPv6 process details, IPv6 ACL ordering
beyond first match, tunnel interfaces.

Prediction depth: on-link by configured prefix (not mask comparison). Link-local
next hop without an outgoing interface is `UNDECIDED`. The same link-local on two
interfaces is normal; only global duplicates are conflicts. **`ipv6 unicast-routing`
is a separate gate from holding an address** — conflating them was defect #1 of
the previous sprint. ND cache contents are runtime state and are not modelled.

### ACL (`trident/normalization/configs.py`, `deepcore/path.py`)

Parsed: `access-list <n> {permit|deny} <proto> <src> [<wildcard>] <dst> [<wildcard>] [ops]`
with `any`, `host a.b.c.d`, network+wildcard, standard and extended numbering;
named `ip access-list {standard|extended} <name>` blocks; `ip access-group <id> {in|out}`.

Fixed this sprint:
1. A wildcard operand is consumed with the address it qualifies, not stored as
   the destination.
2. `ip access-group` binding is transferred to `AclEntry.applied_interface` and
   `.direction`.
3. Both source and destination operands are evaluated; an ACE matches only when
   **all** stated operands match; an unevaluable operand yields `unknown`, never
   `permit`.

Not parsed: object-groups, time-ranges, `established`/`reflexive`, IPv6 ACE
ordering, logging side effects.

Prediction depth: first bound deny wins. **No ordering evaluation beyond the first
matching entry**, and no PDU has been sent through an ACL to confirm the verdict.

---

## Required state for each claim

| Protocol | Claim is valid only when |
|---|---|
| STP | bridge priorities or `root primary` are configured; MACs known for priority ties |
| EtherChannel | interfaces are actually in a `channel-group` |
| NAT | inside/outside roles and a translation rule are configured |
| IPv6 | interface has an address and `ipv6 unicast-routing` is set globally |
| ACL | the ACL is bound to the interface under test, and the traffic's source address is known |
| Routing | for dynamic protocols, the runtime table is unknown, so cross-protocol reachability is `UNKNOWN`, not a drop |

---

## Demonstration level per claim

| Claim | Demonstrated at |
|---|---|
| ACL wildcard/binding/source semantics | unit + real-captured configuration |
| RIP `network` is not a route | unit + live PDU differential |
| Dynamic-protocol reachability is `UNKNOWN` | live PDU differential |
| Cold-ARP drop is not a forwarding failure | live PDU differential |
| STP root election | unit only — **no simulator evidence** |
| EtherChannel negotiation | unit only — **no simulator evidence** |
| NAT/PAT translation | unit only — **no simulator evidence** |
| IPv6 forwarding | unit only — **no simulator evidence** |

---

## Unsupported / unmodelled, stated

* QoS, routing authentication, port security, device administration — not parsed.
* OSPF: network statements recorded; no adjacency, area or cost model.
* Segmentation rules depending on unparsed ACLs: `INCONCLUSIVE`.
* Return path: modelled as a stage, not traced hop by hop against a live simulator.
* Dynamic routing runtime tables (RIP/EIGRP/OSPF installed routes): not modelled
  by construction — they are simulator state.
