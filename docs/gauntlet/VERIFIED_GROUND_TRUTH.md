# VERIFIED GROUND TRUTH — TRIDENT Gauntlet (six levels)

**Status:** every claim below was produced by opening the shipped `.pkt` in Packet Tracer
9.0.1 (build 9.0.1.0858) and reading the device back. Nothing here is inferred from the
specs, the answer keys, or the generator source.

**Verifier:** Agent A (ground-truth verification), session `gt-01` … `gt-06`.
**Date:** 2026-11-14.
**Source labs:** `/Users/tanayshah/Downloads/trident_gauntlet_complete/built/*.pkt`
**Answer keys read:** `instructor_only/*_answer_key.json` (permitted; used to know what to look for).

---

## 1. Scoring rule (read this first)

> **ONLY faults classified `PRESENT` count as benchmark ground truth.**
> A fault classified `ABSENT` is **not in the simulator** and **must not be scored** — not as a
> detection success, not as a missed detection, not as a false positive, and not in any recall
> denominator.
>
> `UNVERIFIABLE` means "the simulator may contain it but no read-only observation exposes it".
> It also must not be scored. (No fault in these six labs ended up UNVERIFIABLE — see §3.)

Aggregate across the six levels: **26 faults named in the keys → 20 PRESENT, 6 ABSENT, 0 UNVERIFIABLE.**
The effective benchmark is therefore **20 faults**, not 26.

---

## 2. Method / provenance

Each level was opened in its own Packet Tracer process, one at a time, from a disposable
copy staged by `trident.simulator.isolation.Workspace`; the backend was closed in a `finally`
block and the temp session directory removed. `sha256` of the source `.pkt` was taken before
and after every session and is identical for all six (see §4).

Read-only command sweep per device (routers/switches): `show running-config`,
`show ip interface brief`, `show interfaces status`, `show ip route`, `show vlan brief`,
`show interfaces trunk`, `show access-lists`.

### End hosts have no CLI in PT 9.0.1

`LiveBackend.run_cli` on a `PC-PT`/`Server-PT` fails before the command is sent:

```
IPC error from enterCommand: ['Pc', 'IPC call "enterCommand" not found']
```

25 candidate read-only accessors were probed on a live `Pc` object (`getIp`, `getIPAddress`,
`getSubnetMask`, `getDefaultGateway`, `getIpConfig`, `getMacAddress`, …). Only `getName` and
`getPortCount` exist. This matches the note already in `trident/labgen/gauntlet.py:160`.

**Therefore host addressing is read through Packet Tracer's own serialisation of the live
network**: `appWindow fileSave` into the *disposable working copy*, then decode with
`pkt_core.codec.decode`. This is PT writing out its in-memory state — it is not the input
file (the file changes: see §5, and the rewritten values prove the round trip happened).

---

## 3. Summary table

| Level | Devices (net) | Links | Faults in key | PRESENT | ABSENT | UNVERIFIABLE |
|---|---:|---:|---:|---:|---:|---:|
| 01_easy | 3 | 2 | 1 | 1 | 0 | 0 |
| 02_basic | 5 | 4 | 2 | 1 | 1 | 0 |
| 03_intermediate | 8 | 7 | 3 | 2 | 1 | 0 |
| 04_advanced | 11 | 11 | 4 | 3 | 1 | 0 |
| 05_expert | 17 | 17 | 6 | 5 | 1 | 0 |
| 06_insane | 26 | 26 | 10 | 8 | 2 | 0 |
| **Total** | **70** | **67** | **26** | **20** | **6** | **0** |

All six levels opened successfully. No level failed to open. Device counts and link counts
match `gauntlet_index.json` exactly; device names match every key's `expected_device_names`
exactly. Each lab additionally contains one Packet Tracer `Power Distribution DeviceN`
pseudo-device, which is why the raw `devices()` count is `expected_devices + 1`.

---

## 4. Source hashes (must be unchanged after every session)

| Level | sha256 (before == after) |
|---|---|
| 01_easy.pkt | `c6140b8265a7cd1c4afbe71822809bd0fc00c7c4b6936abca2b2cd1d14a0c553` |
| 02_basic.pkt | `4032add3756433aa55aff32bb08e3345687c71737eea1f5b7d7fc002c362e5b2` |
| 03_intermediate.pkt | `c187a87e77feb27b9bc67c4e0861985d7fd4aae647fffc7c5addc96cba24513d` |
| 04_advanced.pkt | `28806e680bf840a4824069951ad5d04fe992242ebe8d327a0a858ec6c1a199c8` |
| 05_expert.pkt | `9450753082c9547b7c4a3fbc2cd926b98eeb6afecd96337de55f3e09811f0e68` |
| 06_insane.pkt | `37283abe5b75d3faef4bffa0a3b4d50aa7a4376077505fcb5ff9779dac433c71` |

---

## 5. What Packet Tracer silently rejected

These are real, simulator-side defects. They are **not** injected faults and are **not** in any
answer key. They affect the validity of the labs as exercises.

### 5.1 Every user VLAN is missing from the VLAN database (17 switches, all six levels)

The specs start each switch with `vlan NN` / `name SITE_N`. In the live device **neither the
VLAN object nor the name exists**:

- `show running-config` contains no `^vlan NN` block on any switch in any level.
- `show vlan brief` lists only `1 default` and the `1002–1005` defaults. VLANs 11, 12, 13, 14,
  15, 16, 91 and 92 are all absent.
- `show interfaces trunk` reports `Vlans allowed and active in management domain: none`.
- The *interface-level* statements **did** apply: `switchport access vlan 91`, `switchport
  trunk allowed vlan 11` etc. are all present, and `show interfaces status` even shows the
  port in VLAN 91/92 — a VLAN that does not exist.

Consequence: access ports sit in a non-existent VLAN. `show vlan brief` does not list those
ports under **any** VLAN (e.g. level 02: `Fa0/1, Fa0/2, Fa0/3` appear nowhere, while
`Fa0/4…Fa0/24, Gig0/1` are listed under VLAN 1). Layer-2 forwarding through those ports
cannot be exercised in these labs.

### 5.2 Every end-host default gateway was overwritten (40 hosts, all six levels)

This is the most damaging defect. The generator writes the spec gateway into `<PORT_GATEWAY>`
but leaves the engine-level `<GATEWAY>` at Packet Tracer's template default.

**Observed:** after load, PT's own save reports `<GATEWAY>` and `<PORT_GATEWAY>` both equal to
the template default for every host, and the spec value is gone from the file entirely.
**Inference (mechanism, not directly observed):** `<GATEWAY>` is the field PT's host engine
adopts, and `<PORT_GATEWAY>` is a mirror it rewrites. This is the only reading consistent with
the round trip, because PT discards an explicitly-set port gateway on every host — including
the ones whose spec value was already correct.

Measured in the built file vs the live serialisation (level 02, PC1-3):

| | built `native_xml` | Packet Tracer, live |
|---|---|---|
| `<IP>` | `10.2.1.12` | `10.2.1.12` (survives) |
| `<SUBNET>` | `255.255.255.0` | `255.255.255.0` (survives) |
| `<PORT_GATEWAY>` | `10.2.1.254` | **`1.1.1.2`** |
| `<GATEWAY>` (engine) | `1.1.1.2` (template default) | `1.1.1.2` |

Live gateway of **all 36 PCs = `1.1.1.2`**; **all 4 servers = `192.168.10.1`**. The string
`10.2.1.254` does not occur anywhere in PT's save of level 02.

This means *both* the injected wrong gateways **and** the correct baseline gateways are gone.
No host in any of the six labs has the gateway its answer key or spec asks for, so "does the
host have the right gateway?" is unanswerable in the lab as built — every host is equally wrong.

### 5.3 Not rejections (normal IOS rendering — recorded so nobody mistakes them for defects)

- `no shutdown` never appears in `show running-config` (IOS omits the default admin state).
  It is **not** evidence of a dropped line.
- `switchport trunk allowed vlan 11,12` is rendered `... vlan 11-12` in running-config.
  The spec line was applied.
- Every `ip route` present in the specs is in the live running-config **and** installed in
  `show ip route`. No static route was rejected; no route points at an uncabled next hop.

---

## 6. Per-level ground truth

Legend for **Command used** on host rows: `fileSave→XML` means `appWindow fileSave` on the
disposable working copy, decoded with `pkt_core.codec.decode`, then read from the port's
`<IP>` / `<SUBNET>` / `<PORT_GATEWAY>` elements.

### 6.1 Level 01 — `01_easy.pkt` — opened YES

**Inventory:** 3 network devices + 1 power device, 2 links (expected 3 / 2).
`R1`, `SW1`, `PC1-1`.

| Fault | Device | Interface | Expected | Actual observed (live) | Status | Command used |
|---|---|---|---|---|---|---|
| F01 | R1 | GigabitEthernet0/0 | `no shutdown` → `up/up`, 10.1.1.1/24 | `GigabitEthernet0/0  10.1.1.1  YES manual administratively down down` and running-config shows `ip address 10.1.1.1 255.255.255.0` + `shutdown` | **PRESENT** | `show ip interface brief`; `show running-config` |

Notes: SW1 `vlan 11` block missing (see §5.1). PC1-1 gateway is `1.1.1.2` instead of the spec's
`10.1.1.1` (§5.2); level 01 has no gateway fault in its key, so this affects no score.

### 6.2 Level 02 — `02_basic.pkt` — opened YES

**Inventory:** 5 network devices + 1 power device, 4 links (expected 5 / 4).
`R1`, `SW1`, `PC1-1`, `PC1-2`, `PC1-3`.

| Fault | Device | Interface | Expected | Actual observed (live) | Status | Command used |
|---|---|---|---|---|---|---|
| F02 | PC1-3 | FastEthernet0 | gateway `10.2.1.1` (key says injected `10.2.1.254`) | `<IP>10.2.1.12</IP>`, `<SUBNET>255.255.255.0</SUBNET>`, `<PORT_GATEWAY>1.1.1.2</PORT_GATEWAY>` | **ABSENT** | `fileSave→XML` (`<PORT_GATEWAY>`) |
| F03 | SW1 | FastEthernet0/1 | `switchport access vlan 11` | `Fa0/1  connected  91` and running-config `interface FastEthernet0/1` → `switchport access vlan 91` | **PRESENT** | `show interfaces status`; `show running-config` |

F02 detail: PT reset the gateway to `1.1.1.2` — neither the correct value nor the key's
`10.2.1.254` is present (§5.2). Nothing distinguishes PC1-3 from a "correct" host.

### 6.3 Level 03 — `03_intermediate.pkt` — opened YES

**Inventory:** 8 network devices + 1 power device, 7 links (expected 8 / 7).
`R1`, `R2`, `SW1`, `SW2`, `PC1-1`, `PC1-2`, `PC2-1`, `PC2-2`.

| Fault | Device | Interface | Expected | Actual observed (live) | Status | Command used |
|---|---|---|---|---|---|---|
| F02 | PC2-2 | FastEthernet0 | gateway `10.3.2.1` (key says injected `10.3.2.254`) | `<IP>10.3.2.11</IP>`, `<PORT_GATEWAY>1.1.1.2</PORT_GATEWAY>` | **ABSENT** | `fileSave→XML` |
| F04 | PC1-1 | FastEthernet0 | mask `255.255.255.0` | `<IP>10.3.1.10</IP>`, `<SUBNET>255.255.0.0</SUBNET>` | **PRESENT** | `fileSave→XML` |
| F05 | R1 | — (route) | `ip route 10.3.2.0 255.255.255.0 172.20.30.2` | No static route at all. `show ip route`: only `C 10.3.1.0/24 … GigabitEthernet0/0`, `L 10.3.1.1/32`, `C 172.20.30.0/30 … GigabitEthernet0/1`, `L 172.20.30.1/32`. Running-config has no `ip route` line. | **PRESENT** | `show ip route`; `show running-config` |

Context: R2 does have `ip route 10.3.1.0 255.255.255.0 172.20.30.1`, so the asymmetry is real.

### 6.4 Level 04 — `04_advanced.pkt` — opened YES

**Inventory:** 11 network devices + 1 power device, 11 links (expected 11 / 11).
`R1`, `R2`, `SW1`, `SW2`, `SW3`, `PC1-1`, `PC1-2`, `PC2-1`, `PC2-2`, `PC3-1`, `PC3-2`.

| Fault | Device | Interface | Expected | Actual observed (live) | Status | Command used |
|---|---|---|---|---|---|---|
| F01 | R2 | GigabitEthernet0/1 | `no shutdown` → up/up, 10.4.3.1/24 | `GigabitEthernet0/1  10.4.3.1  YES manual administratively down down`; running-config `shutdown` | **PRESENT** | `show ip interface brief`; `show running-config` |
| F02 | PC3-2 | FastEthernet0 | gateway `10.4.3.1` (key says injected `10.4.3.254`) | `<IP>10.4.3.11</IP>`, `<PORT_GATEWAY>1.1.1.2</PORT_GATEWAY>` | **ABSENT** | `fileSave→XML` |
| F06 | SW2 | GigabitEthernet0/1 | `switchport trunk allowed vlan 11,12` (match SW1) | `show interfaces trunk` → `Gig0/1  11` on SW2 vs `Gig0/1  11-12` on SW1; running-config `switchport trunk allowed vlan 11` | **PRESENT** | `show interfaces trunk` (both ends); `show running-config` |
| F08 | R1 | GigabitEthernet0/0 (in) | permit site-1 PC ICMP echo to its gateway | `show access-lists`: `10 deny icmp 10.4.1.0 0.0.0.255 host 10.4.1.1 echo` / `20 permit ip any any`; applied `ip access-group BLOCK-GATEWAY-ICMP in` on Gi0/0 | **PRESENT** | `show access-lists`; `show running-config` |

### 6.5 Level 05 — `05_expert.pkt` — opened YES

**Inventory:** 17 network devices + 1 power device, 17 links (expected 17 / 17).
`R1`, `R2`, `R3`, `SW1`, `SW2`, `SW3`, `SW4`, `PC1-1`, `PC1-2`, `PC2-1`, `PC2-2`, `PC3-1`,
`PC3-2`, `PC4-1`, `PC4-2`, `SERVER1`, `SERVER4`.

| Fault | Device | Interface | Expected | Actual observed (live) | Status | Command used |
|---|---|---|---|---|---|---|
| F01 | R3 | GigabitEthernet0/2 | `no shutdown` → up/up, 10.5.4.1/24 | `GigabitEthernet0/2  10.5.4.1  YES manual administratively down down`; running-config `shutdown` | **PRESENT** | `show ip interface brief`; `show running-config` |
| F02 | PC4-2 | FastEthernet0 | gateway `10.5.4.1` (key says injected `10.5.4.254`) | `<IP>10.5.4.11</IP>`, `<PORT_GATEWAY>1.1.1.2</PORT_GATEWAY>` | **ABSENT** | `fileSave→XML` |
| F03 | SW2 | FastEthernet0/1 | `switchport access vlan 12` | `Fa0/1  connected  92`; running-config `switchport access vlan 92` | **PRESENT** | `show interfaces status`; `show running-config` |
| F04 | PC1-1 | FastEthernet0 | mask `255.255.255.0` | `<IP>10.5.1.10</IP>`, `<SUBNET>255.255.0.0</SUBNET>` | **PRESENT** | `fileSave→XML` |
| F05 | R1 | — (route) | `ip route 10.5.4.0 255.255.255.0 172.20.50.2` | Running-config has only `ip route 10.5.3.0 255.255.255.0 172.20.50.2`; `show ip route` has `S 10.5.3.0/24` and no `10.5.4.0/24` | **PRESENT** | `show ip route`; `show running-config` |
| F06 | SW2 | GigabitEthernet0/1 | `switchport trunk allowed vlan 11,12` | `show interfaces trunk` → `Gig0/1  11` on SW2 vs `11-12` on SW1 | **PRESENT** | `show interfaces trunk`; `show running-config` |

### 6.6 Level 06 — `06_insane.pkt` — opened YES

**Inventory:** 26 network devices + 1 power device, 26 links (expected 26 / 26).
`R1`, `R2`, `R3`, `R4`, `SW1`…`SW6`, `PC1-1`, `PC1-2`, `PC1-3`, `PC2-1`, `PC2-2`, `PC2-3`,
`PC3-1`, `PC3-2`, `PC4-1`, `PC4-2`, `PC5-1`, `PC5-2`, `PC6-1`, `PC6-2`, `SERVER1`, `SERVER6`.

| Fault | Device | Interface | Expected | Actual observed (live) | Status | Command used |
|---|---|---|---|---|---|---|
| F01 | R4 | GigabitEthernet0/2 | `no shutdown` → up/up, 10.6.6.1/24 | `GigabitEthernet0/2  10.6.6.1  YES manual administratively down down`; running-config `shutdown` | **PRESENT** | `show ip interface brief`; `show running-config` |
| F02 | PC6-2 | FastEthernet0 | gateway `10.6.6.1` (key says injected `10.6.6.254`) | `<IP>10.6.6.11</IP>`, `<PORT_GATEWAY>1.1.1.2</PORT_GATEWAY>` | **ABSENT** | `fileSave→XML` |
| F09 | PC1-1 | FastEthernet0 | gateway `10.6.1.1` (key says injected `10.6.1.253`) | `<IP>10.6.1.10</IP>`, `<PORT_GATEWAY>1.1.1.2</PORT_GATEWAY>` | **ABSENT** | `fileSave→XML` |
| F03 | SW2 | FastEthernet0/1 | `switchport access vlan 12` | `Fa0/1  connected  92`; running-config `switchport access vlan 92` | **PRESENT** | `show interfaces status`; `show running-config` |
| F04 | PC1-1 | FastEthernet0 | mask `255.255.255.0` | `<IP>10.6.1.10</IP>`, `<SUBNET>255.255.0.0</SUBNET>` | **PRESENT** | `fileSave→XML` |
| F05 | R1 | — (route) | `ip route 10.6.6.0 255.255.255.0 172.20.60.2` | Running-config has `ip route` for 10.6.3.0, 10.6.4.0, 10.6.5.0 only; `show ip route` has no `10.6.6.0/24` | **PRESENT** | `show ip route`; `show running-config` |
| F10 | R4 | — (route) | `ip route 10.6.1.0 255.255.255.0 172.20.62.1` | Running-config has `ip route` for 10.6.2.0, 10.6.3.0, 10.6.4.0 only; `show ip route` has no `10.6.1.0/24` | **PRESENT** | `show ip route`; `show running-config` |
| F06 | SW2 | GigabitEthernet0/1 | `switchport trunk allowed vlan 11,12` | `show interfaces trunk` → `Gig0/1  11` on SW2 vs `11-12` on SW1 | **PRESENT** | `show interfaces trunk`; `show running-config` |
| F07 | PC1-2 | FastEthernet0 | `10.6.1.11` (duplicate with PC1-1) | `<IP>PC1-1 = 10.6.1.10` and `<IP>PC1-2 = 10.6.1.10` — same address, same VLAN | **PRESENT** | `fileSave→XML` (both hosts compared) |
| F08 | R1 | GigabitEthernet0/0 (in) | permit site-1 PC ICMP echo to its gateway | `show access-lists`: `10 deny icmp 10.6.1.0 0.0.0.255 host 10.6.1.1 echo` / `20 permit ip any any`; applied `in` on Gi0/0 | **PRESENT** | `show access-lists`; `show running-config` |

---

## 7. What this means for the benchmark

1. **Score 20 faults, not 26.** Drop F02/F09-class gateway faults everywhere: 02/F02, 03/F02,
   04/F02, 05/F02, 06/F02, 06/F09.
2. **A detector cannot "find" the six gateway faults, and must not be penalised for missing
   them.** Equally, a detector that *reports* a wrong gateway on those hosts is reporting the
   real state of the lab (`1.1.1.2`), so it is not a false positive against PT — but it is also
   not the keyed fault, and it cannot be a "correct fix" either, because there is no fixed state.
3. **VLAN-based fault detection is config-level only.** `switchport access vlan 91` /
   `switchport trunk allowed vlan 11` are genuinely present and detectable, but no VLAN in
   these labs exists in the VLAN database, so no *forwarding* evidence can corroborate them.
4. **Host masks and the duplicate address are trustworthy.** `<SUBNET>` and `<IP>` survive the
   PT round trip, so 03/F04, 05/F04, 06/F04, 06/F07 are sound and observable.

## 8. Limits of this verification

- Not performed: link-endpoint-to-endpoint cable verification (only link **counts** were
  confirmed from PT's own save), STP behaviour, and packet-level forwarding.
- `PduExecutor.send` returns `EXECUTION_ERROR` (0 frames) on this build for PC→router probes,
  so no behavioural (ping) corroboration was possible. All classifications rest on device
  configuration/state read back from the simulator.
- PC-side faults have no CLI probe by construction on PT 9.0.1; their evidence class is
  `fileSave→XML`, which is PT's own serialisation but is not a student-visible command.
