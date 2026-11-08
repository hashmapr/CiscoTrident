# TRIDENT — PKA Corpus Report

Generated: 2026-11-07
Method: read-only decode and full analysis of every discovered `.pka`/`.pkt` file. Files were never copied, modified, uploaded, or committed. No configuration contents (device passwords, secrets) are reproduced here.

## Corpus discovery

Search was deliberately bounded — the workspace, `tests/fixtures`, and the usual project/download locations. A home-wide scan was not performed.

| Location | Files |
|---|---|
| `tests/fixtures/` | `sample_lab.pkt`, `sample_activity.pka` |
| `~/Downloads/` | `R1_OKCUP_24_25_CiscoPT.pka`, `R1_OKCUP_24_25_CiscoPT(1).pka`, `9.4.2.8 Packet Tracer - Skills Integration Challenge.pka` |
| **Total** | **5** |

`TRIDENT_TEST_CORPUS_DIR` was added so an external corpus can be supplied without copying files:

```bash
TRIDENT_TEST_CORPUS_DIR=/path/to/practice/files
python -m trident.tools.corpus_manifest --json docs/corpus_manifest.json
```

The manifest tool records filename, size, SHA-256, format, decode result, snapshot count, per-block device/link counts and selection verdict.

## File compatibility

| File | Size | Format | PT version | Decode | Snapshots | Selected |
|---|---|---|---|---|---|---|
| `sample_lab.pkt` | 81,474 B | .pkt | 9.0.1.0858 | OK | 1 (7 devices) | `block0` (single) |
| `sample_activity.pka` | 34,226 B | .pka | 9.0.1.0858 | OK | 3, **all empty** | **abstain** (no network) |
| `R1_OKCUP_24_25_CiscoPT.pka` | 1,568,569 B | .pka | 9.0.1.0858 | OK | 3 (21/20/20) | `block0` (template-demoted) |
| `R1_OKCUP_24_25_CiscoPT(1).pka` | 1,531,221 B | .pka | **8.2.2.0400** | OK | 3 (20/20/20) | `block0` (majority agreement) |
| `9.4.2.8 Packet Tracer - Skills Integration Challenge.pka` | 254,841 B | .pka | **6.0.1.0011** | OK | 3 (14/14/14) | `block0` (majority agreement) |

Three Packet Tracer generations are represented (6.0.1, 8.2.2, 9.0.1) and all decode and analyse.

SHA-256 (for traceability, files are not redistributed):

- `sample_lab.pkt` — `4a212faa24258ee7…`
- `sample_activity.pka` — `3b05bf9fb9c0c51b…`
- `R1_OKCUP_24_25_CiscoPT.pka` — `0cf54063eccc493cc4957f49ef87a3607cf8ba7eb768595ff99839de0f1f58b8`
- `R1_OKCUP_24_25_CiscoPT(1).pka` — `cad21b55b661e895…`
- `9.4.2.8 Packet Tracer - Skills Integration Challenge.pka` — `5d7a2b1afca1b9a8…`

All five files decode with the vendored Twofish-EAX decoder. Older container formats (Packet Tracer 5.x and earlier) remain **untested**.

## Snapshot handling

### Snapshot-selection evidence hierarchy

1. **Reference wrappers** (`COMPARISONS`, `INITIALSETUP`, `CLEAN_ACTIVITY`, `ACTIVITY`) are never candidates.
2. **Majority agreement** — several snapshots whose *extracted content* is identical are one network captured more than once (they differ only in volatile internals such as `MEM_ADDR` / `DEV_ADDR`). When a majority agrees and another snapshot dissents, the agreed network is the consistent state and the dissenter is a later reference/answer state.
3. **Template placeholders** — a block with unresolved `[[...]]` assessment placeholders is an unresolved simulation state and is demoted.
4. **Byte-identical duplicates** collapse to the first.
5. Anything else → **abstain**.

Device count is never used as the tie-breaker.

### Snapshot layout per file

| File | Layout | Deciding evidence |
|---|---|---|
| `R1_OKCUP…pka` (9.0.1) | 21 / 20 / 20 devices | only block 0 has resolved names (0 placeholders vs 38/38) |
| `R1_OKCUP…(1).pka` (8.2.2) | 20 / 20 / 20 devices | blocks 0 and 1 extract identically; block 2 differs (graded state) |
| `9.4.2.8 Skills…pka` (6.0.1) | 14 / 14 / 14 devices | blocks 0 and 1 extract identically; block 2 differs (graded state) |

On both new files, `COMPARISONS` holds the graded answer values (e.g. `255.255.255.252` appears 282× in `COMPARISONS` and 18× in block 2 but 0× in block 0), which corroborates that the dissenting block is the completed/answer state. TRIDENT never reads `COMPARISONS`.

### `R1_OKCUP_24_25_CiscoPT.pka` — multi-snapshot with template placeholders

Root element `PACKETTRACER5_ACTIVITY` with three sibling `<PACKETTRACER5>` blocks, followed by `COMPARISONS`, `INITIALSETUP`, `LOCKINGTREE`, `OPTIONS` and `ACTIVITY`.

| Block | Devices | Links | Config lines | `ip address` lines | Unresolved `[[...]]` tokens | Verdict |
|---|---|---|---|---|---|---|
| 0 | 21 | 19 | 2,183 | 9 | 0 | **selected** (shipped network) |
| 1 | 20 | 19 | 2,182 | 9 | 38 | reference/simulation (demoted) |
| 2 | 20 | 19 | 3,717 | 56 | 38 | reference/simulation (demoted; graded config) |

Evidence for the selection is real, not device count: blocks 1 and 2 use unresolved assessment placeholders (`[[pr3-rt_Display_name]]`) and block 2 carries the completed/graded configuration (56 interface addresses vs 9 in the shipped network). Block 0 has fully resolved device names and hostnames.

Pre-fix behaviour merged all three blocks: 40 unique devices from 61 `<DEVICE>` elements, with six conflicting fields. Post-fix behaviour: 21 devices, 207 interfaces, 19 links, **0 conflicts**, all three engines in agreement on the selected snapshot.

### Two additional real files (tested after the initial audit)

`R1_OKCUP_24_25_CiscoPT(1).pka` (PT 8.2.2) and `9.4.2.8 Packet Tracer - Skills Integration Challenge.pka` (PT 6.0.1) both have three same-shaped snapshots where two are semantically identical. Majority agreement selects block 0 in both and reports the dissenting block; neither file is merged and neither produces conflicts.

Full pipeline results:

| File | Devices | Ifaces | Links | VERIFIED | INCOMPLETE | CONFLICT | Time | File unchanged |
|---|---|---|---|---|---|---|---|---|
| `R1_OKCUP…(1).pka` | 20 | 207 | 19 | 34 | 20 | 0 | 219 s | yes |
| `9.4.2.8 Skills…pka` | 14 | 130 | 13 | 32 | 36 | 0 | 42 s | yes |

Answer behaviour on the Skills file (independently checkable from the file itself):

| Question | Result |
|---|---|
| IP of HQ GigabitEthernet0/0 | `VERIFIED` → 172.16.127.254 |
| IP of HQ GigabitEthernet0/1 | `VERIFIED` → 172.16.63.254 |
| Hostname of HQ-SW1 | `VERIFIED` → hq-sw1 (3/3 engines) |
| Devices directly connected to HQ | `VERIFIED_DERIVED` → Branch, HQ-SW1, HQ-SW2, Internet |
| Devices directly connected to Branch | `VERIFIED_DERIVED` → BR-SW1, BR-SW2, HQ |
| IP of HQ-RTR1 | `NOT_AVAILABLE` — **correct**: the router is named `HQ`, not `HQ-RTR1` |
| Default gateway of PC-A | `NOT_AVAILABLE` — **correct**: no such device in this file |
| OSPF DR election | `NOT_AVAILABLE` — unsupported category (protocol behaviour) |

### `sample_activity.pka`
Three `<PACKETTRACER5>` blocks, all empty (82 characters each), with populated `COMPARISONS` / `INITIALSETUP` / `CLEAN_ACTIVITY` wrappers. TRIDENT correctly abstains: no network exists in a readable snapshot, and the answer-key wrappers are never read. Questions return `NOT_AVAILABLE` with an explanatory warning. This is the correct outcome for an activity skeleton, not a failure.

## Engine coverage

| File | Engine A | Engine B | Engine C | Devices | Interfaces | Links |
|---|---|---|---|---|---|---|
| `sample_lab.pkt` | OK (7) | OK (7) | OK (7) | 7 | 37 | 5 |
| `sample_activity.pka` | abstain | abstain | abstain | 0 | 0 | 0 |
| `R1_OKCUP…pka` | OK (21) | OK (21, 11 configs) | OK (21) | 21 | 207 | 19 |
| `R1_OKCUP…(1).pka` | OK (20) | OK (20, 11 configs) | OK (20) | 20 | 207 | 19 |
| `9.4.2.8 Skills…pka` | OK (14) | OK (14, 7 configs) | OK (14) | 14 | 130 | 13 |

Engine B initially returned 0 configs for the real file because pkt-core sanitises filenames (`Hub_Switch_1__Our_Trusty_Sidekick.cfg`); fixed by mapping slugs back to real device names. After the fix: 11 configured devices (the Cisco-device subset; PCs/servers carry no IOS config).

## Consensus results on real files

| File | VERIFIED | INCOMPLETE | CONFLICT | Notes |
|---|---|---|---|---|
| `sample_lab.pkt` | 16 | 14 | 0 | 3 engines contribute; end-host/single-source fields stay INCOMPLETE |
| `R1_OKCUP…pka` | 35 | 23 | 0 | was 21/31/6 before the running-config fix |
| `R1_OKCUP…(1).pka` | 34 | 20 | 0 | PT 8.2.2; 219 s full analysis |
| `9.4.2.8 Skills…pka` | 32 | 36 | 0 | PT 6.0.1; 42 s full analysis |

`INCOMPLETE` items are deliberately fields where fewer than three distinct extraction families agree — chiefly end-host MAC/IP/gateway/DNS values that only Engine A exposes, and per-device fields for non-Cisco devices without IOS configs.

## Real-world answer accuracy

**No accuracy percentage is reported.** A defensible accuracy figure requires an independently labelled question-answer set, and none was available in the workspace (the previously referenced 65-question benchmark is not present). Fabricating a percentage from unlabelled files would violate the project's core rule.

What *is* measurable and independently checkable:

| Question | File | Result | Independently verifiable? |
|---|---|---|---|
| "What is the IP of R1 GigabitEthernet0/0?" | `sample_lab.pkt` | `VERIFIED` → 192.168.1.1 | Yes — three engines agree; raw config line visible in evidence |
| "What is the default gateway of PC-A?" | `sample_lab.pkt` | `INCOMPLETE` (single-source) | Yes — only Engine A exposes end-host settings |
| "Network address of 192.168.1.10 255.255.255.0?" | `sample_lab.pkt` | `VERIFIED_DERIVED` → 192.168.1.0 | Yes — deterministic arithmetic |
| "Which devices connect to SW1?" | `sample_lab.pkt` | `VERIFIED_DERIVED` → PC-A, R1 | Yes — topology traversal over verified links |
| "What is the IP of R9 Gi0/0?" | `sample_lab.pkt` | `NOT_AVAILABLE` | Yes — device absent |

Outcome classes observed:

- **Correct verified answers:** 16 (lab) / 35 (R1) field-level verified facts; no incorrect verified answer was found on re-inspection against raw config.
- **Incorrect verified answers:** 0 found.
- **Correct abstentions:** all single-source end-host facts and the empty activity skeleton.
- **Unnecessary abstentions:** possible for reworded prose questions (exact-text matching is deliberate).
- **Unsupported question categories:** routing-protocol behaviour, simulation outcomes ("would a ping succeed"), ACL evaluation order.
- **Parser failures:** none after fixes (Engine B timeout at the previous 90 s default is resolved by `TRIDENT_PARSER_TIMEOUT=300` and the abstain path).
- **Snapshot failures:** none after fixes.
- **AI interpretation failures:** none observed in the live 5-question run; truncation and unasked-question injection are rejected and tested.

## Reproduce

```bash
python -m trident.tools.corpus_manifest --json /tmp/manifest.json
pytest -q
```

Real-file assertions live in `tests/test_parsers.py` and `tests/test_api.py`; they skip cleanly if an engine is unavailable.
