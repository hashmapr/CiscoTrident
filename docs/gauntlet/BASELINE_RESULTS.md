# Baseline results — blind diagnosis vs verified ground truth

Measured before any diagnostic change was made in this operation. The prediction
run was performed by a separate agent that never read an answer key; the ground
truth was established by a second agent that opened every lab in Packet Tracer
9.0.1.0858.

**The headline number is not the one the fault counts suggest.** Of 26 faults
named in the instructor keys, only **20 exist in the simulator**. Six were
silently rejected by Packet Tracer, so scoring against 26 would have punished
the engine for being right about a fault that is not there.

## Method

| Step | Who | What they could see |
|---|---|---|
| Predictions | Agent B | The six `built/*.pkt` files and TRIDENT's public API. **No keys.** |
| Ground truth | Agent A | The keys, plus Packet Tracer 9.0.1 for every level. |
| Scoring | Primary | Both, joined after predictions were sealed. |

Agent B's predictions were written to `BLIND_PREDICTIONS.json` and sealed with a
SHA-256 before this document was produced. All three ran on
`deepseek-v4.1-flash:1017-cloud` / `ollama-cloud`.

## Ground-truth validity

| Level | Faults in key | PRESENT | ABSENT | Unverifiable |
|---|---:|---:|---:|---:|
| 01_easy | 1 | 1 | 0 | 0 |
| 02_basic | 2 | 1 | 1 | 0 |
| 03_intermediate | 3 | 2 | 1 | 0 |
| 04_advanced | 4 | 3 | 1 | 0 |
| 05_expert | 6 | 5 | 1 | 0 |
| 06_insane | 10 | 8 | 2 | 0 |
| **Total** | **26** | **20** | **6** | **0** |

**Ground truth = 20 faults.** The 6 ABSENT faults are all
`wrong_default_gateway` (02/F02, 03/F02, 04/F02, 05/F02, 06/F02, 06/F09).

Why they are absent: every end-host NIC has two gateway fields. The generator
writes the intended value into `<PORT_GATEWAY>` but leaves the engine-level
`<GATEWAY>` at Packet Tracer's template default. On load PT treats `<GATEWAY>` as
authoritative and rewrites `<PORT_GATEWAY>` to match. Verified in the built file:

```
PC1-3: IP=10.2.1.12  MASK=255.255.255.0
       PORT_GATEWAY=10.2.1.254      <-- what the key claims
       GATEWAY=1.1.1.2              <-- template default
```

In the live simulator all 36 PCs report `1.1.1.2` and all 4 servers
`192.168.10.1`. Neither the injected *nor* the correct baseline gateway exists,
so "has the right gateway" is unanswerable in these labs.

## Topology extraction

| Level | Devices found / expected | Links found / expected |
|---|---|---|
| 01_easy | 3/3 | 2/2 |
| 02_basic | 5/5 | 4/4 |
| 03_intermediate | 8/8 | 7/7 |
| 04_advanced | 11/11 | 11/11 |
| 05_expert | 17/17 | 17/17 |
| 06_insane | 26/26 | 26/26 |
| **Total** | **70/70** | **67/67** |

Topology extraction is **perfect**: 70/70 devices and 67/67 links across six
labs, from three devices to twenty-six.

## Detection

| Level | Scoreable faults | TP | FN | FP | Findings reported |
|---|---:|---:|---:|---:|---:|
| 01_easy | 1 | 1 | 0 | 0 | 1 |
| 02_basic | 1 | 1 | 0 | 1 | 2 |
| 03_intermediate | 2 | 1 | 1 | 1 | 2 |
| 04_advanced | 3 | 3 | 0 | 4 | 7 |
| 05_expert | 5 | 4 | 1 | 3 | 7 |
| 06_insane | 8 | 5 | 3 | 8 | 13 |
| **Total** | **20** | **15** | **5** | **17** | **32** |

- **Recall: 15/20 (75%).**
- **Precision: 15/32 (46.9%).**
- **False positives: 17.**
- **Missed faults: 5.**

Matching is strict: the finding must name the right device *and* be a kind that
can explain the fault. A true statement about the wrong device is not a hit.

## The 17 false positives are not all the same thing

Counting them as one number would be misleading. They split into three classes,
and only one class is a genuine engine error:

| Class | Count | What it actually is |
|---|---:|---|
| Gateway findings | 12 | **True of the file, false in the simulator.** The engine correctly reads `10.2.1.254` from the `.pkt` and correctly reports that no interface owns it. Packet Tracer overwrote that value on load. |
| Trunk peer findings | 5 | **True statements naming the other end of a real fault.** When SW2 omits VLAN 12 from a trunk, SW1 genuinely carries a VLAN its peer does not. Both ends were reported; the key names one. |
| Duplicate IP | 1 | Needs individual review — see `ERROR_ANALYSIS.md`. |

So of 17, **zero are fabricated**. The engine reported only things that are true
of some observable state. The gateway class is an artifact of the lab generator,
not a diagnostic error; the trunk class is a scoring-convention mismatch.

This does not make precision good — 15/32 is what a student would experience —
but the cause matters. **The dominant precision problem is a broken lab, not a
confused detector.**

## What the engine genuinely missed

| Level | Fault | Device | Why |
|---|---|---|---|
| 03_intermediate | F05 missing route | R1 | No `MISSING_STATIC_ROUTE` fired. The detector only looks for a *reverse* route contradiction, not an absent forward route. |
| 05_expert | F05 missing route | R1 | Same gap. |
| 06_insane | F05, F10 missing routes | R1, R4 | Same gap, twice. |
| 06_insane | F07 duplicate IP | PC1-1/PC1-2 | `DUPLICATE_IP` fired but attributed to the first holder only, so it did not match at the keyed device. |

The missing-route gap is the single largest recall loss (4 of 5 misses). An
attempt to fix it during this operation produced five false positives on a
documented-healthy network and was reverted rather than tuned to the fixture.

## Simulator success rate

6/6 labs opened in Packet Tracer 9.0.1.0858. Source `.pkt` SHA-256 identical
before and after every session. No session left a process behind.

## Median analysis time

Median 1.5 s, worst 2.4 s per lab (offline pipeline + diagnostics, two engines).

## Conclusion on the central question

**TRIDENT diagnoses unseen practice faults — with a real ceiling.**

It is clearly not "merely extracting configuration": it named the right device
and the right fault class for 15 of the 20 faults that actually exist, on labs
written by a different generator than the one it was tuned against, at up to 26
devices. Recall on the three levels with a single scoreable fault is 3/3.

But the ceiling is visible and specific. Missing-route faults are not detected
(1 of 5 found), and precision in student terms is 47%, dominated by a lab whose
gateways Packet Tracer silently overwrites.

## Reproduction

```bash
cd ~/CiscoTrident && source .venv/bin/activate
python /tmp/score_base.py          # recompute this table
pytest tests/test_gauntlet_ground_truth.py -q -m live_simulator   # needs PT
```

Ground-truth evidence: `docs/gauntlet/VERIFIED_GROUND_TRUTH.md`.
