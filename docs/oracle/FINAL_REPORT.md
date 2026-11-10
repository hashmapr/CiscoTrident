# PROJECT ORACLE — FINAL REPORT

Branch `development/deepcore`. Release candidate `trident-stream-verify-rc1`
untouched at `9d14807`.

---

## 1. Commits

| Phase | Commit |
|---|---|
| Starting point | `1422770` |
| IPC port retry fix | (folded into Analyze Mode commit) |
| Analyze Mode | `4a5a678` |
| Analyze Mode docs + real evidence | `16b4376` |
| Streaming device sections | `65b7106` |

---

## 2. What was built

### Analyze Mode — the product feature

One button, no questions. Upload a lab, press **Analyze Network**, get a
device-by-device assessment.

- **Overview**: devices by type, links, interfaces, VLANs, routing protocols,
  findings by severity, unsupported-check count.
- **One section per device**, ordered routers → firewalls → switches → endpoints →
  infrastructure.
- **Basic information** per device: name, hostname, model, type, interface
  addresses, disabled interfaces, connected networks, default and static routes,
  gateway, DNS, VLANs, applied ACLs, direct neighbours.
- **Common Cisco Questions** with per-answer status.
- **Potential Problems**: severity, exact device and interface, description,
  evidence, why it matters, commands to check with, suggested fix.
- **Network-wide issues**, separate from device findings.
- **What was not checked**, plus the standing caveat that no findings is not proof.
- **Streaming**: overview, then each device section as it is built, then findings,
  coverage and completion.
- **Export**: JSON, Markdown, plain text.

### Supporting work

- **`_choose_port` retries for 15 s.** A Packet Tracer still releasing its port
  was being reported as "no backend available", producing intermittent failures
  that looked like code faults. This was the single failure in the previous
  1252-test run.
- **`to_report_dicts()` now carries evidence.** It returned only kind, device,
  interface and confidence, so a finding could say something was wrong but not
  why, and a reader could not verify it. It now includes supporting and
  contradicting observations, the next command and the repair hint.

---

## 3. Three defects found by building Analyze Mode

1. **`device_type` is never populated.** The parser records `model` (`2911`,
   `2960-24TT`) and leaves `device_type` None. Every device was therefore grouped
   as "Device". Classification now derives kind from the model string.
2. **Evidence was discarded at the report boundary** (above).
3. **Headings read "Device (2911) — R1"** rather than "Router — R1"; same root
   cause as (1).

Each was found by a test or by looking at real output, not by inspection.

---

## 4. Protocol coverage

| Level | Count | Features |
|---|---|---|
| SIMULATOR_TESTED | 2 | IPv4 addressing, static routing |
| STATICALLY_VERIFIED | 5 | subnetting, VLANs, trunks, ACLs, DHCP |
| PARSED | 1 | OSPF |
| UNSUPPORTED | 8 | NAT, STP, EtherChannel, QoS, routing auth, IPv6, port security, device administration |

Two overclaims were caught by the evidence test: NAT and STP had been marked
PARSED because the evidence layer can *hold* a `show` capture. That is not
deriving facts from configuration. Both are now UNSUPPORTED with reasons.

OSPF stays PARSED and not MODELLED: a configured `network` statement does not
imply a formed adjacency.

---

## 5. Packet-path reasoning (DeepCore)

`trident/deepcore/path.py` predicts forwarding deterministically:

- directly-connected destinations resolve before any routing decision;
- longest prefix then administrative distance;
- a router origin routes from its own table, a host uses its default gateway;
- loops detected, shut interfaces named as the failure point with their admin
  state;
- explicit ACL denies evaluated only when bound to a real interface.

Every prediction carries `SIMULATED_PREDICTION`, never an observation kind. It
cannot enter the three-engine consensus. A destination with no parsed address
yields `UNKNOWN` — the common case for hosts Packet Tracer addresses at runtime.

17 tests.

---

## 6. Differential testing against Ghost

`trident/deepcore/differential.py` compares a prediction with a PDU outcome.

Verdicts: `AGREES`, `DISAGREES`, `INSUFFICIENT_EVIDENCE`, `UNTESTABLE`. An
inconclusive experiment never counts as agreement. Real run:

```
PREDICTION   delivered=True  definite=True
OBSERVATION  DELIVERED  observed=True  frames=60
VERDICT      AGREES  trusted=True
PROVENANCE   version=9.0.1  session=2bb842461775
CLEANUP      source=INTACT
```

14 offline tests, 2 live.

---

## 7. EVOLVE

`trident/evolve/strategy.py` turns trusted lessons into planning advice. Only
`PREFER` advice reorders experiments; `DEFER` and `REQUIRE_EVIDENCE` are notes, so
the behavioural effect stays small and auditable. Advice executes nothing. 14
tests.

---

## 8. Real acceptance demonstration

`R3_OKCUP_24_25_CiscoPT(1).pka` in real Chromium, no questions entered:

```
status     Analyzed 33 device(s) in 13.9s
sections   33
headings   Router — Bowser's Castle Router 1
           Router — DK Jungle Router 1
           Multilayer Switch — Rainbow Road Layer 3 Switch 1  ...
overview   visible
```

33 devices, 37 links, 362 interfaces, OSPF and RIP detected, 6 findings
(1 HIGH, 1 MEDIUM, 4 LOW), 8 unsupported checks. Every finding carried exact
evidence; for example the HIGH one named both holders of `35.72.15.10`.

Source SHA-256 unchanged before and after:
`1ff12f2bbeddb1d9f225e176b9672549e5e13cba8fb3dc23829727c1bb41df1f`

---

## 9. Performance

Decode cache from the previous sprint: 43% faster repeats (1449 ms → 832 ms on the
practice lab; 27.68 s → 15.83 s on a 2.5 MB activity).

Analyze Mode itself: 33 devices in 13.9 s, dominated by the 2.5 MB container
decode. Per-device section construction is milliseconds.

---

## 10. Regression results

```
pytest -q                    1287 passed, 0 failed, 26 deselected
browser (Analyze Mode)        7 passed
benchmark_pack              260/260, 0 false-verified, 33.0 s
ruff                        clean
```

The 26 deselected are the browser and live-simulator marks, which are opt-in.

---

## 11. Unsupported scenarios

- NAT, STP, EtherChannel, QoS, routing authentication, IPv6, port security and
  device administration are not parsed. The report says so on every run.
- OSPF adjacency state is not modelled.
- Host addresses are frequently absent because Packet Tracer assigns them at
  runtime; the report marks those facts UNSUPPORTED rather than guessing.
- Deep Analyze does not start a simulator from the browser; runtime evidence comes
  from the CLI path.

---

## 12. Remaining defects

1. **Analyze Mode has no automated test for a genuinely huge lab in a browser.**
   The 33-device run is the largest measured.
2. **Verdict text for findings is generated by a lookup table** keyed on defect
   kind. A new defect class without an entry falls back to a generic sentence
   rather than a specific one.
3. **The streaming UI has no reconnection handling.** If the stream breaks mid-way
   the user sees the sections received so far and an interruption notice; there is
   no resume.

---

## 13. Next priorities

1. Parse and model STP and EtherChannel, which are common in CyberPatriot labs and
   currently contribute nothing but an "unsupported" line.
2. Extend packet-path reasoning to the return path and to ACL ordering.
3. Complete the Oracle phases not reached in this window: formal invariants,
   adversarial network generator, active experiment planner.
4. Wire Deep Analyze to actually run Ghost experiments chosen by the planner.

---

## 14. Honest status

Analyze Mode is complete, tested at three levels (unit, API, real browser) and
demonstrated on a real 33-device lab. DeepCore reasoning and differential
verification work and were proven against live Packet Tracer. The protocol
coverage matrix is honest about what is and is not modelled, having already caught
two of its own overclaims.

The remaining Oracle phases are listed above rather than marked done.
