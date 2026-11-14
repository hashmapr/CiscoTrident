# Forensics and reconstruction

`trident.assessment.forensics` is the read-only reconstruction phase of the
autonomous assessment workflow. It turns one `.pkt`/`.pka` into a complete,
normalised snapshot with per-fact engine provenance. It is extraction, not
verification: no field is presented as consensus-verified.

```python
from trident.assessment.forensics import reconstruct, write_evidence, load_requirements

evidence = reconstruct("lab.pkt")          # runs the real three-engine pipeline
write_evidence(evidence, "out/")           # out/network_evidence.json
requirements = load_requirements(visible_instruction_text)  # raw lines, no interpretation
```

## What the snapshot contains

`NetworkEvidence.as_dict()` is JSON-serialisable and includes the full
`NetworkModel` under `model` for downstream consumers.

| Field | Shape | Meaning |
| --- | --- | --- |
| `devices` | `DeviceRecord` | name, hardware model, declared device type, role from `engined.reachability.classify_device`, interfaces, config line count, asserting engines |
| `links` | `LinkRecord` | `a_device`, `a_port`, `b_device`, `b_port` plus asserting engines |
| `vlans` | `VlanRecord` | VLAN id, name (when available), owning device, asserting engines |
| `routes` | `RouteRecord` | device, destination, mask, next hop, route kind (static/connected), asserting engines |
| `acls` | `AclRecord` | device, ACL id, action, protocol, source, destination, applied interface, direction, asserting engines |
| `discrepancies` | `Discrepancy` | one entry per disagreeing engine pair and field, with both values |
| `unsupported` | `UnsupportedItem` | capability, reason, state, source (`engine_c`, documented PT limitation) |
| `engines` | `dict` | per engine: state, device count, link count, observation count, message, duration, declared capabilities and limitations |
| `source_sha256` | `str` | SHA-256 of the source file before and after reconstruction |
| `model` | `NetworkModel` | the normalised model the pipeline already built |

Interfaces carry `name`, `ip`, `mask`, `prefix`, `gateway`, `admin_state`,
`vlan_assignments`, `access_mode`, `native_vlan`, and the engines that asserted
them. `prefix` falls back to a conversion of the dotted mask when the parser did
not state a prefix length.

### Integrity

`reconstruct()` reads the source bytes, hashes them, parses an in-memory copy,
then re-hashes the file. A mismatch raises `EvidenceIntegrityError`. The file is
never written to.

### Provenance and consensus

Every record lists the engines that asserted it. Agreement between `engine_a`
and `engine_b` is *two* engines. Under the default `strict` policy, a fact needs
three distinct extraction families to be `VERIFIED`, so with `engine_c`
unavailable nothing from this snapshot can legitimately be called
consensus-verified.

| Record | Engines that may assert it |
| --- | --- |
| device / interface | `engine_a`, `engine_b`, (`engine_c` when available) |
| link | the engines that exposed the physical link |
| route / ACL / VLAN | the engines whose parsed config contained it |

## How discrepancies are surfaced

The unified model keeps every observation from every successful engine. The
forensics layer groups observations by `(entity_type, entity_id, field)`, then
compares engines pairwise. Values are canonicalised with the same rules the
consensus engine uses: MAC addresses normalised, interface names canonicalised,
everything else case-folded and stripped.

Each disagreement becomes:

```
Discrepancy(
    entity_type="interface",
    entity_id="R1:GigabitEthernet0/0",
    field="ipv4_address",
    engine_a="engine_a", value_a="192.168.77.1",
    engine_b="engine_x", value_b="10.99.99.99",
)
```

Rules:

* A pair is recorded only when its canonical value sets differ. Agreeing
  engines produce nothing, so a clean lab yields an empty `discrepancies` list.
* An engine that asserted several values for one field contributes all of them,
  joined with `" | "`; the other value is shown next to it.
* No value is dropped or averaged. The normalised model remains the union of
  engine output; selecting a value is the consumer's job, guided by the
  consensus engine.
* Attribution gaps are recorded rather than guessed. An ACL whose applied
  interface is ambiguous and whose raw line appears in more than one device's
  config is emitted with `device=""` and a warning; the same applies to a VLAN
  that no member port or config block can attribute.

## What is extracted

* Device inventory, hardware model, declared type, and role.
* Interfaces: addresses, masks/prefixes, configured gateway, configured admin
  state, access mode, VLAN assignments, trunk native VLAN.
* Physical links with both ports.
* Static routes from IOS configuration, including the mask token from the
  original `ip route` line.
* ACL entries with the interface and direction that bind them, when the binding
  exists in config.
* VLAN ids and names when the parser sees them, plus ids inferred from interface
  VLAN assignments and member ports.
* Per-engine probe states, device counts, observation counts, messages,
  capabilities, and limitations.
* Documented Packet Tracer limitations (`end_host_cli`, `behavioural_ping`) as
  `UNSUPPORTED`.

## What is not extracted

* **Live state.** This is a static file reconstruction. No simulator is started;
  no `show` command is executed. Interface up/down counters, ARP, CDP/LLDP
  neighbours, DHCP leases, ACL hit counters, NAT translations, and QoS state are
  absent unless they survive in configuration text.
* **VLAN database names.** Packet Tracer stores VLAN names in `<VLANS>`
  (`vlan.dat`), not in `running-config`. `VlanRecord.name` is `None` when only
  membership is known.
* **End-host CLI.** Packet Tracer 9.0.1 implements no CLI on PC-PT/Server-PT, so
  end-host state comes from NIC fields the container exposes, not from command
  output.
* **Behavioural reachability.** No packet is sent. Reachability is a derivation
  over the extracted model, never an observation made here.
* **Engine C's independent decode.** In this environment `engine_c` cannot run,
  so its capabilities (`container-decode`, `ios-config-text`,
  `physical-links-with-real-port-names`, …) are listed under `unsupported` with
  status `UNAVAILABLE` instead of being silently omitted.
* **MAC addresses and interface state not present in config.** The normalised
  model only surfaces what an engine extracted.

## Engine states observed here

Probed with `build_adapters(settings)` and confirmed by a real reconstruction of
a generated `healthy-single-router` lab (4 devices, 3 links):

| Engine | Probe | State in `evidence.engines` | Device count | Observation count | Message |
| --- | --- | --- | --- | --- | --- |
| `engine_a` | ready | `OK` | 4 | 21 | decoded 843,177 bytes of XML |
| `engine_b` | ready | `OK` | 4 | 11 | typed model: 4 devices (snapshot-scoped); configs: 2 devices |
| `engine_c` | not ready | `UNAVAILABLE` | 0 | 0 | pt-convert checkout missing `src/lib/packet-crypto.ts` |

Byte sizes and observation counts vary with the lab. The states do not: with
`engine_c` unavailable, the snapshot is built from two engines and reports that
fact rather than hiding it.

`unsupported` from the same run contains the six `engine_c` capabilities with
status `UNAVAILABLE`, plus `behavioural_ping` and `end_host_cli` with status
`UNSUPPORTED` and their documented PT 9.0.1 reasons.

## Requirement text

`load_requirements(text)` only separates visible instruction text into raw
requirement lines. It strips numbered (`1.`, `2)`) and bullet (`-`, `*`, `•`)
markers, joins wrapped continuation lines, drops blank lines, section headers,
titles, point values, and submission boilerplate such as “Click Submit”. It does
not interpret, prioritise, or convert a requirement into a network intent; that
belongs to the requirements phase.
