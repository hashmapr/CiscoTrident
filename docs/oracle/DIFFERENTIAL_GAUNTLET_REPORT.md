# ORACLE DIFFERENTIAL GAUNTLET — REPORT

Date: 2026-11-10
Branch: `development/deepcore`
Release candidate: `trident-stream-verify-rc1` = `9d14807` — **untouched**
Starting HEAD: `8127819`
Simulator: Cisco Packet Tracer **9.0.1.0858** (external volume, registered ExApp)
Host: macOS, Apple Silicon arm64

This report covers a verification sprint: making deterministic DeepCore predictions
face real Packet Tracer behaviour on authorized practice labs, and fixing what broke.

---

## 1. What was verified against the handoff

The handoff was treated as a claim set, not ground truth. Every item below was
checked against the repository.

| Handoff claim | Result |
|---|---|
| Repo `~/CiscoTrident`, branch `development/deepcore` | CONFIRMED |
| `trident-stream-verify-rc1` resolves to `9d14807` | CONFIRMED |
| HEAD `8127819` | CONFIRMED |
| Tree clean | CONFIRMED |
| `docs/oracle/PROTOCOL_FINAL_REPORT.md` exists | CONFIRMED |
| `docs/oracle/CONTINUATION.md` exists | **FALSE — file does not exist** |
| pytest 1483 passed | CONFIRMED (1483 collected offline before this sprint) |
| 260/260 benchmark, 0 false-verified | CONFIRMED (re-run, unchanged) |
| Ruff clean | CONFIRMED |
| `docs/oracle/COMPLETION_TRACKER.md` reflects current state | **FALSE — stale** (predates all protocol work; still lists STP/EtherChannel/NAT/IPv6 as `NOT_STARTED`) |
| `trident/deepcore/coverage.json` reflects current state | **FALSE — stale** (listed 8 protocols `UNSUPPORTED` including ones now modelled) |

Two documents were materially wrong. They have been corrected (§6).

---

## 2. Simulator reachability

Real, authenticated, invisible Packet Tracer was available and used.

```
bundle      /Volumes/AI-Models/Cisco Packet Tracer 9.0.1/Cisco Packet Tracer 9.0.1.app
version     9.0.1
ExApp       registered (~/.config/trident/trident.pta), credentials present
ownership   owned_pids() == [] before and after every session
sources     every lab copied to a disposable workspace; source SHA-256 unchanged
```

`pytest tests/simulator/ -m live_simulator` → **27 passed** in 228 s, including
invisible launch, source preservation, process ownership, and no-focus-theft.

No Packet Tracer process was killed. One `--progress-bar-server` helper process
(PID 50322) was observed during a run; it held no TCP port, was not started by
this work, and was left alone.

---

## 3. Which labs could actually answer a protocol question

Differential testing is only meaningful where a protocol is configured. All five
authorized labs were surveyed live (`docs/oracle/evidence/lab_survey.json`).

| Lab | Size | CLI devices | STP config | EtherChannel | NAT | IPv6 table | ACL |
|---|---|---|---|---|---|---|---|
| CCNA 3 Practice PTSA | 615 KB | 0 | — | — | — | — | — |
| CCNA Mega Lab (Jeremy's IT Lab) | 1.0 MB | 8 | `mode pvst` only | none | none | empty | **1 real ACL** |
| Final_R3_BDSM | 648 KB | 4 | `mode pvst` only | none | none | empty | none |
| Modules_1-13_Image | 30 MB | 0 | — | — | — | — | — |
| R3_OKCUP_24_25_CiscoPT | 2.5 MB | 7 | `mode pvst` only | none | none | empty | 2 ACLs |

Two labs could not be opened at all; both are recorded as blocked, not passed:

* **CCNA 3 Practice PTSA** — `BackendUnavailable: Packet Tracer did not accept
  connections within 45.0s` (IPC port contention).
* **Modules_1-13_Image (30 MB)** — `could not open the lab in Packet Tracer:
  fileOpen timed out after 60.0s`. The same large-file cost noted in the handoff.

### The central finding

**Every authorized lab is an unconfigured student activity.** `spanning-tree
priority` appears nowhere, no `channel-group` exists, no `ip nat` rule exists, and
every `show ipv6 route` returned `IPv6 Routing Table - 0 entries`. Router
interfaces in `Final_R3_BDSM` are `administratively down` with `unassigned`
addresses.

Consequence: STP root election, EtherChannel negotiation, NAT/PAT translation and
IPv6 forwarding **cannot be differential-tested against these labs**, because the
protocol is not present to observe. Claiming otherwise would be the exact
fabrication this directive forbids. They are marked `BLOCKED` with that reason
(§5), not skipped silently.

Write access cannot fix this: `run_cli` calls `is_read_only(command)` and refuses
mutation, and the live backend does not advertise `MUTATE_CONFIG`. Building a
configured lab would require authoring `.pkt` binary content, which is out of
scope for a verification sprint.

---

## 4. What WAS verified live, and what it found

### 4.1 ACL semantics — real config, real ACEs

`ISP A` in the CCNA Mega Lab carries the only real ACL found in any lab:

```
Extended IP access list 100
    10 deny ip 10.0.0.0 0.255.255.255 any
    20 deny ip 172.16.0.0 0.15.255.255 any
    30 deny ip 192.168.0.0 0.0.255.255 any
    40 permit ip any any
```

(verbatim `show access-lists`, captured to
`docs/oracle/evidence/ispA_running-config.txt`)

Feeding that real text through the parser exposed **three defects**.

#### Defect 1 — the wildcard was stored as the destination

```
access-list 100 deny ip 10.0.0.0 0.255.255.255 any
    regex groups -> source=10.0.0.0  destination=0.255.255.255  extra=["any"]
```

`0.255.255.255` is a wildcard mask, not a destination. The real destination
`any` was pushed into `port_conditions`. Positional regex groups could not tell
an extended ACE from a standard one.

Fixed by token-parsing the ACE (`parse_ace_tokens`) so an operand consumes its
own wildcard, and `host`/`any` are recognised.

#### Defect 2 — the interface binding never reached the model

`ip access-group 100 in` was parsed onto the interface as `acl_in`, then never
transferred to `AclEntry.applied_interface`. `_collect_acls` contained a dead
loop (`for iface in model.interfaces.values(): pass`). Every bound deny was
therefore invisible to the reasoning layer, which compares `applied_interface`.

Fixed by binding ACL ids to interfaces during collection.

#### Defect 3 — a source-based ACE denied the entire internet

`acl_verdict` read only the *destination* operand, and treated `any` as a
blanket deny. For `deny ip 10.0.0.0 0.255.255.255 any` this reported **every**
destination as denied, including `8.8.8.8`, which the ACE permits.

Two sub-errors were found while fixing it:

* First attempt used `source_match OR destination_match`. Corrected to AND — an
  ACE matches only when every operand matches.
* When the traffic's source address is not known, the operand is now `None`
  (indeterminate), and the verdict becomes `unknown`, never `permit`. Silently
  returning `permit` for an unevaluated deny is how a blocked path reports as
  healthy.

Verified behaviour after the fix:

| source | destination | verdict | correct? |
|---|---|---|---|
| 10.5.5.5 | 8.8.8.8 | `deny` | yes — 10/8 denied by source |
| 192.168.1.5 | 8.8.8.8 | `permit` | yes — not covered |
| unknown | 8.8.8.8 | `unknown` | yes — cannot be determined |

The journey stage now passes the source address as well as the destination.

Regression: `tests/test_acl_real_config.py` (7 tests, real ACE text).

### 4.2 Routing — a RIP `network` statement was treated as a route

A real PDU from `R2` to `R1` was **DELIVERED** while DeepCore predicted a
**DROP**.

Root cause: inside `router rip`, `network 192.168.1.0` is a statement nominating a
major network for advertisement. It is not a route. The parser recorded it as a
`dynamic` route, and `_route_network("192.168.1.0")` interpreted the bare address
as `192.168.1.0/32`. So the model believed `R2` had a route to the network
*address* while having none to the host.

Fixed: the statement is retained as configuration
(`advertised-network:192.168.1.0`) and is no longer invented as a route.

Second, deeper defect exposed by the same experiment: with only static
configuration in the model, a router running RIP was reported as a **definite
DROP** for "no default gateway". A router does not need a default gateway — it
forwards from its table — and with a dynamic protocol that table is runtime
state the configuration does not contain. The prediction is now `UNKNOWN` naming
the protocol, instead of a definite and wrong drop.

| Pair | Before | After | Simulator |
|---|---|---|---|
| R2 → R1 | definite DROP | `UNKNOWN` (RIP, runtime routes) | DELIVERED |
| R2 → SW1 | definite DROP | `UNKNOWN` (RIP, runtime routes) | DROPPED |

The `R2 → SW1` row is important: the old code was **accidentally right**. It is
now honestly undecided. Trading an accidental pass for a stated gap is the
correct direction, and it removed one false agreement from the score.

### 4.3 PDU methodology — a cold ARP drop was scored as a real failure

`SW1 → R1` on the sample lab reported `DROPPED`, then `DELIVERED` on a second
attempt. The simulator's own trace says why:

```
The next-hop IP address is not in the ARP table. The ARP process tries to send
an ARP request for that IP address and drops this packet.
```

The first packet to an unresolved neighbour is always dropped in Packet Tracer
while ARP resolves. `send_with_warmup` retried only on `INCONCLUSIVE` with zero
frames sent, so a cold-ARP `DROPPED` was reported as final.

Fixed: a drop whose own decision text says it was dropped for an ARP request is
retried once, and the retry is recorded as a caveat. A drop that survives the
retry is still reported as a drop.

---

## 5. Protocol-by-protocol result

| Protocol | Parse | Predict | Live `show` observed | Differential verdict |
|---|---|---|---|---|
| **ACL** | yes | yes | yes (ISP A, real ACEs) | **THREE DEFECTS FOUND AND FIXED** — static, not PDU-tested end to end |
| **IPv4 routing / RIP** | yes | yes | yes | **DEFECT FOUND AND FIXED** — 1 disagreement resolved to `UNKNOWN` |
| **STP** | yes | yes | yes (`show spanning-tree summary` on 15 switches) | **BLOCKED** — no lab configures priority or `root primary`; every device reports `Root bridge for: default` and all VLANs show `0 blocking / 0 forwarding`, i.e. no converged topology |
| **EtherChannel** | yes | yes | yes (`show etherchannel summary`) | **NOT_APPLICABLE** — no lab has a `channel-group`; `Number of channel-groups in use: 0` everywhere |
| **NAT / PAT** | yes | yes | `show ip nat statistics` empty on every device | **BLOCKED** — no NAT configuration exists in any authorized lab |
| **IPv6** | yes | yes | `show ipv6 route` → `0 entries` everywhere | **BLOCKED** — no lab runs IPv6 forwarding |
| **EtherChannel/STP on live PT** | — | — | — | **NOT RUN** — same reason as above |

### A corrected scoring error in this sprint's own harness

The first version of `oracle_differential_stp.py` scored "0 channels configured,
0 aggregators observed" as **AGREES**. That is vacuous confirmation — nothing was
corroborated. It now reports `NOT_APPLICABLE`. The first run's "12/12 EtherChannel
agreement" is withdrawn and must not be cited.

---

## 6. Documents corrected

* `trident/deepcore/coverage.json` — regenerated. STP, EtherChannel, NAT and IPv6
  moved from `UNSUPPORTED` to `STATICALLY_VERIFIED`, each with stated
  limitations saying it is **not** simulator-tested and why.
  `UNSUPPORTED` 8 → 4; `STATICALLY_VERIFIED` 5 → 9.
* `tests/test_coverage_matrix.py` — two tests asserted those protocols were
  `UNSUPPORTED`. Their intent (do not overclaim) was preserved while their
  assertion moved to the new honest invariant: parsed, modelled,
  statically verified, but **not** simulator-tested.

---

## 7. Validation

### Offline suite

```
pytest -q                     1488 passed, 54 deselected
```

Baseline before this sprint was 1483. The delta is new regression tests for the
defects found (ACL real-config suite).

### Live simulator

```
pytest tests/simulator/ -m live_simulator     27 passed
```

### Browser (real Chromium, real server)

```
pytest tests/browser/ -m browser              26 passed, 1 skipped
```

One browser failure was found and fixed: `test_page_loads_with_all_engines_available`
read `#parsers` before the async `GET /api/parsers` had populated it. The endpoint
returns all three engines `AVAILABLE` (verified by curl and by an explicit
`wait_for_function`); the test was racing, so it now waits.

### Benchmark

```
CCNA2_PTSA_P2        65/65  100.0%  0 false-verified
CCNA_MEGA_LAB        65/65  100.0%  0 false-verified
OKCUP_R3_2023_24     65/65  100.0%  0 false-verified
OKCUP_R3_2024_25     65/65  100.0%  0 false-verified
TOTAL               260/260  0 false-verified      (unchanged)
```

**This is not a blind evaluation.** These questions have been run repeatedly and
are used as a regression pack. It says nothing about generalization to unseen
labs, and it is not a national-level assessment.

### Ruff

```
ruff check trident/ tests/     All checks passed
```

The standalone evidence scripts under `scripts/` retain `S110`/`S112` findings for
`try/except/continue` around probe calls. That is deliberate: a probe that cannot
answer is evidence, and the exception text is recorded in the output rather than
raised.

### Source integrity

Every experiment checked `sha256(source)` before and after. All evidence files
record `source_unchanged: true`. No lab was modified.

---

## 8. Test-count accounting

| Category | Count | Notes |
|---|---|---|
| Offline passed | 1488 | includes 7 new ACL regression tests |
| Live simulator passed | 27 | opt-in `-m live_simulator` |
| Browser passed | 26 | opt-in `-m browser`, real Chromium |
| Browser skipped | 1 | pre-existing skip |
| Blocked (protocol differential) | 4 protocols | STP, EtherChannel, NAT, IPv6 — no configuration in any authorized lab |
| Blocked (labs) | 2 labs | IPC port contention; 30 MB `fileOpen` timeout |
| Failed | 0 | |

---

## 9. Remaining defects and open work

Deliberately listed, not fixed in this sprint:

1. **`verify()` was running during a plain `pytest`.** `test_verify_reports_ok_when_the_install_is_valid`
   launched Packet Tracer and opened a file, violating the suite's own promise
   that a default run never starts the simulator. It now carries
   `@pytest.mark.live_simulator`; the default run deselects it (24 passed, 1
   deselected) and it passes when run explicitly (1 passed in 13.4 s).
2. **IPC port contention still causes intermittent live failures.** Two lab opens
   failed with `did not accept connections within 45.0s` after back-to-back
   sessions, and one live test failed then passed on retry. The 30-port range and
   `TIME_WAIT` cooldown are the cause; a longer retry budget or a per-run port
   lease would address it.
3. **`EXECUTION_ERROR` PDU results carry no detail** at the differential level —
   `send_pdu` returns the status but the harness did not surface `pdu.error`. The
   underlying errors were `addSimplePdu timed out after 30.0s` and
   `setSimulationMode timed out after 20.0s` on switch-only topologies.
4. **Large-lab decode is still slow.** `Modules_1-13_Image.pka` (30 MB) did not
   open within 60 s. `test_pktcrypto.py::test_parity_with_pkt_core_on_practice_labs`
   alone takes 381 s. Not profiled in this sprint.
5. **No live PDU test through an ACL.** The ACL fixes are statically verified
   against real ACE text, but no experiment sent traffic through ISP A's ACL 100.
   That is the natural next differential step and only needs the existing lab.
6. **STP/EtherChannel/NAT/IPv6 remain statically verified only.** Until a lab
   with real configuration exists (or a `.pkt` authoring path is accepted), these
   cannot be raised to `SIMULATOR_TESTED`.

---

## 10. Reproduction

```bash
cd ~/CiscoTrident
source .venv/bin/activate

# 1. Baseline
git status --short && git branch --show-current
git rev-parse --short trident-stream-verify-rc1     # 9d14807
python -m pytest -q

# 2. Survey which labs can answer a protocol question
TRIDENT_ALLOW_LIVE_SIMULATOR=1 python scripts/oracle_lab_survey.py

# 3. Protocol-state differential (config -> predict -> live show)
TRIDENT_ALLOW_LIVE_SIMULATOR=1 python scripts/oracle_differential_stp.py \
  --lab "test-labs/incoming/CCNA Mega Lab (Jeremy's IT Lab)(1).pka" \
  --out docs/oracle/evidence/differential_megalab.json

# 4. Real PDU differential (predict -> send PDU -> compare)
TRIDENT_ALLOW_LIVE_SIMULATOR=1 python scripts/oracle_pdu_differential.py \
  --lab tests/fixtures/sample_lab.pkt \
  --out docs/oracle/evidence/pdu_differential_sample.json

# 5. Raw protocol probes
TRIDENT_ALLOW_LIVE_SIMULATOR=1 python scripts/oracle_gauntlet_probe.py \
  --lab "test-labs/incoming/Final_R3_BDSM.pka" \
  --out docs/oracle/evidence/final_r3_bdsm.json --max-devices 5

# 6. Opt-in suites
python -m pytest tests/simulator/ -m live_simulator -q
python -m pytest tests/browser/ -m browser -q

# 7. Benchmark
python -m trident.tools.benchmark_pack --pack ~/Downloads/TRIDENT_4_Network_Benchmark_Pack
```

Evidence: `docs/oracle/evidence/`.

---

## 11. What this sprint actually established

DeepCore's ACL semantics were wrong in three compounding ways when fed a real
Cisco ACL from a real lab, and its routing semantics produced a definite wrong
answer for a router running a dynamic protocol. Those are fixed, with regressions
built from real captured configuration rather than hand-written cases.

Protocol predictions for STP, EtherChannel, NAT and IPv6 remain **unvalidated
against a live simulator**, because no authorized lab contains those
configurations. That gap is now documented with the exact reason for each, rather
than being implied complete by a stale coverage file.
