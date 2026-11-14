# Blind diagnostic run — CiscoTrident vs six gauntlet labs

**Run date:** 2026-11-14
**Runner:** Agent B (blind). The instructor answer keys, the verified ground-truth
document, and any file named `answer_key`, `ground_truth`, `instructor`, or
`expected_faults` were **never opened**. Only the six built `.pkt` files,
`gauntlet_index.json`, and trident's public API were used.

Disclosure: while isolating the routing gap I also grepped one line of
`built/native_xml/03_intermediate/03_intermediate.xml` (a decoded-document build
artifact, not an answer key) for `ip route`. It held no fault information. The
route-presence result was then re-established independently through trident's own
`pktcrypto.decode_bytes` for all four routing levels, and every prediction in
`BLIND_PREDICTIONS.json` comes from the pipeline output alone.

## Method

For each level, exactly what the task specified:

```python
import asyncio
from pathlib import Path
from trident.ingestion import ingest
from trident.pipeline import analyze
from trident.config import settings
from trident.diagnostics import diagnose

data = Path(p).read_bytes()
out = asyncio.run(analyze(
    ingest(Path(p).name, data),
    "1. What is the hostname of the first router?",
    cfg=settings,
    use_ai=False,
))
diag = diagnose(out.model)          # diag.to_report_dicts() = reported findings
```

Environment: repo `.venv`, Python from `source ~/CiscoTrident/.venv/bin/activate`.
Packet Tracer was **not** started. No engine code was modified, tuned, or
patched before, during, or after the run. Levels were analysed sequentially in
one process, wall-clock timed per level with `time.perf_counter()` around
`asyncio.run(...)`.

Inputs: `/Users/tanayshah/Downloads/trident_gauntlet_complete/built/0{1..6}_*.pkt`.

## Per-level results

| Level | Devices found / expected | Links found / expected | Interfaces | Observations | Findings | Seconds |
|---|---|---|---|---|---|---|
| 01_easy | 3 / 3 | 2 / 2 | 4 | 28 | 1 | 1.07 |
| 02_basic | 5 / 5 | 4 / 4 | 8 | 48 | 2 | 2.40 |
| 03_intermediate | 8 / 8 | 7 / 7 | 14 | 80 | 2 | 1.85 |
| 04_advanced | 11 / 11 | 11 / 11 | 22 | 109 | 7 | 1.94 |
| 05_expert | 17 / 17 | 17 / 17 | 34 | 173 | 7 | 2.02 |
| 06_insane | 26 / 26 | 26 / 26 | 52 | 264 | 13 | 1.50 |

Every level parsed to the exact device and link counts declared in
`gauntlet_index.json`. Total reported findings across all six levels: **32**.
All 32 were `CONFIRMED_DEFECT` with `confidence=HIGH`.

### Findings by level

**01_easy (1)**

- `SHUTDOWN_INTERFACE` R1 Gi0/0 — interface administratively down.

**02_basic (2)**

- `WRONG_VLAN` SW1 Fa0/1 — VLAN 91 while three peers on 10.2.1.0/24 use VLAN 11.
- `WRONG_GATEWAY` PC1-3 — 10.2.1.254 is not an address on the network.

**03_intermediate (2)**

- `INVALID_MASK` PC1-1 — /16 while two peers on VLAN 11 use /24.
- `WRONG_GATEWAY` PC2-2 — 10.3.2.254 is not an address on the network.

**04_advanced (7)**

- `ACL_BLOCK` R1 Gi0/0 — `BLOCK-GATEWAY-ICMP` denies inbound.
- `SHUTDOWN_INTERFACE` R2 Gi0/1.
- `TRUNK_MISMATCH` SW1 Gi0/1 — carries VLAN 12 that peer SW2 Gi0/1 does not.
- `TRUNK_MISMATCH` SW2 Gi0/1 — does not permit VLAN 12 used by three local ports.
- `WRONG_GATEWAY` PC1-1, PC1-2 — 10.4.1.1 absent.
- `WRONG_GATEWAY` PC3-2 — 10.4.3.254 absent.

**05_expert (7)**

- `INVALID_MASK` PC1-1 (/16 vs /24).
- `SHUTDOWN_INTERFACE` R3 Gi0/2.
- `TRUNK_MISMATCH` SW1 Gi0/1 (VLAN 12) and SW2 Gi0/1 (VLAN 12, VLAN 92).
- `WRONG_VLAN` SW2 Fa0/1 — VLAN 92 vs VLAN 12 on 10.5.2.0/24.
- `WRONG_GATEWAY` PC4-2 — 10.5.4.254 absent.

**06_insane (13)**

- `ACL_BLOCK` R1 Gi0/0 (`BLOCK-GATEWAY-ICMP`).
- `DUPLICATE_IP` PC1-1 / PC1-2 share 10.6.1.10.
- `INVALID_MASK` PC1-1 (/16 vs /24).
- `SHUTDOWN_INTERFACE` R4 Gi0/2.
- `TRUNK_MISMATCH` SW1 Gi0/1 (VLAN 12), SW2 Gi0/1 (VLAN 12 and VLAN 92).
- `WRONG_VLAN` SW2 Fa0/1 — VLAN 92 vs VLAN 12 on 10.6.2.0/24.
- `WRONG_GATEWAY` PC1-1 (10.6.1.253), PC1-2 (10.6.1.1), PC1-3 (10.6.1.1),
  SERVER1 (10.6.1.1), PC6-2 (10.6.6.254).

Multiplicity note: a two-ended trunk fault produces one finding per switch, and a
single bad gateway address shared by several hosts produces one finding per host.
That is why findings can outnumber the `fault_count` declared in
`gauntlet_index.json` (04: 7 vs 4, 05: 7 vs 6, 06: 13 vs 10), and why they are
not directly comparable without deduplication.

## Confidence split

| Bucket | Count |
|---|---|
| `CONFIRMED_DEFECT` / HIGH | 32 |
| `SUSPECTED` | 0 |
| `INSUFFICIENT_EVIDENCE` | 0 |

`diagnose()` emitted **no** `SUSPECTED` and **no** `INSUFFICIENT_EVIDENCE`
hypothesis on any level. Detectors that lacked the facts to decide stayed
completely silent rather than emitting an explicit "cannot determine" entry.
That silence is itself a result and is recorded in
`BLIND_PREDICTIONS.json` as empty `inconclusive` lists.

## Engines

| Engine | State on all six levels | Detail |
|---|---|---|
| `engine_a` | OK | decoded 833 K–1.26 M bytes of XML per file |
| `engine_b` | OK | typed model + in-process configs + links (2/2 … 26/26) |
| `engine_c` | **UNAVAILABLE** | `pt-convert checkout missing src/lib/packet-crypto.ts` |

`engine_c` was unavailable for the whole run, so every analysis was two-engine.
No result here is a three-engine consensus.

## What trident could NOT determine

1. **Static routes / routing paths — nothing at all.** `NetworkModel.routes` was
   `0` on every level, including 03, 04, 05 and 06 whose decoded documents do
   contain `ip route` lines (verified by decoding each `.pkt` with trident's own
   `pktcrypto.decode_bytes`: 1, 3, 7 and 16 `ip route` lines respectively).
   Because the route table is empty, the `MISSING_STATIC_ROUTE`,
   `UNREACHABLE_NEXT_HOP` and `ROUTING_LOOP` detectors had no input and could
   not run. Level 03 was declared with three faults and produced two findings;
   the unassessed routing-path class is the obvious gap, but it is **not**
   claimed as a detected fault.

   Root cause isolated during the run (read-only, no patch applied):
   `parse_running_config` (`trident/normalization/configs.py`) closes an
   interface block on `!` and on `line vty/con/aux`, but **not** on `exit`.
   Packet Tracer's `<LINE>` elements strip indentation, so in these labs the
   `ip route ...` line arrives immediately after an `exit` and is swallowed as
   an interface sub-command before the static-route branch is reached. Proven
   with two minimal inputs: the same config parses one route with `!` before
   `ip route` and zero routes with `exit` before it.

2. **Forwarding behaviour.** With no Packet Tracer and no runtime evidence
   bundle, nothing here is end-to-end reachability. The findings are static
   consistency claims over the parsed configuration.

3. **DHCP pool correctness.** No DHCP findings were produced on any level. With
   routing already inert this was not cross-checked against the labs' intent;
   trident simply reported nothing.

4. **Whether any fault was missed.** Only the reported set is a commitment.
   Nothing here says the unseen faults were absent from the labs — only that
   trident did not report them.

5. **Runtime/ping evidence.** `diagnose(out.model)` was called without an
   `EvidenceBundle`, exactly as specified, so runtime cross-checks were absent
   and every conclusion rests on modelled configuration alone.

## Files created by this run

- `docs/gauntlet/BLIND_PREDICTIONS.json` — the commitment (32 findings).
- `docs/gauntlet/BLIND_RUN.md` — this report.
- `tests/test_gauntlet_blind.py` — offline regression: device/link counts and a
  120 s bound per level, skipped when the built labs are absent.
