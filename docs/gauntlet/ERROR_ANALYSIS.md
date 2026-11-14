# Error analysis — why the engine missed what it missed

Every number here is from the baseline in `BASELINE_RESULTS.md`. Nothing in this
document was tuned to the fixtures; the one attempted fix that failed its own
control was reverted.

## Summary

| Bucket | Count | Nature |
|---|---:|---|
| Genuine engine misses | 5 | Detector absent or misattributed |
| False positives — lab artifact | 12 | True of the `.pkt`, false in the simulator |
| False positives — convention | 5 | True statement naming the other end of a real fault |
| False positives — attribution | 1 | Correct fault, key names the other holder |
| Fabricated findings | **0** | — |

The absence of fabricated findings is the most important line. Every finding the
engine produced was true of some observable state.

## Miss 1–4: missing static route (4 of 5 misses)

**Faults:** 03/F05 (R1 → 10.3.2.0), 05/F05 (R1 → 10.5.4.0), 06/F05 (R1 → 10.6.6.0),
06/F10 (R4 → 10.6.1.0).

**Symptom:** no `MISSING_STATIC_ROUTE` finding. The engine found the *next-hop*
faults on the same devices (`UNREACHABLE_NEXT_HOP`) but not the absent routes.

**Root cause:** `detect_missing_static_route` looks for a **reverse-route
contradiction** — router A sends unknown traffic to router B, B has a connected
subnet A cannot reach, and B has no route back. That is a real defect pattern,
but it is not this one. Here the route is simply absent: R1 has no `ip route` to
a subnet its neighbour can reach.

**Why it was not simply fixed:** an attempt to add
`detect_unreachable_remote_subnet` produced **5 findings on a documented-healthy
network** (`healthy-with-noise`). The reason is fundamental, not a bug: a router
that correctly has no default route, and an ISP edge router that correctly has no
private routes, are indistinguishable from "missing route" by static
configuration alone. Distinguishing them requires knowing the *intended* routing
policy, which is exactly what the answer key holds.

**What the fix would require:** either an intended-routing input (a requirement
statement, not a config), or behavioural evidence — a traceroute or ping that
fails. `PduExecutor.send` returns `EXECUTION_ERROR` on PT 9.0.1, so the
behavioural route is unavailable on this build.

This is recorded as a **known ceiling**, not a bug awaiting a patch.

## Miss 5: duplicate IP attributed to the wrong holder

**Fault:** 06/F07. PC1-1 and PC1-2 both hold `10.6.1.10`.

**Symptom:** `DUPLICATE_IP` fires — correctly — but names `PC1-1`. The key
attributes the fault to `PC1-2` (the machine whose address was *changed* to
create the conflict).

**Root cause:** the detector reports the first holder in iteration order. Both
statements are true; they disagree only about which end is "the fault".

**Why it matters:** strict device matching scores it a miss. A human grader would
accept it instantly. This is an argument for scoring duplicate-IP faults by
*address* rather than by device, which the scoring harness does not yet do.

**Cheap improvement, not applied:** report both holders in one finding, or allow
a duplicate-IP match on either device. Not applied because it would change the
scoring rules after seeing the results, which is precisely the kind of tuning
this operation is meant to avoid.

## False positive class A: gateway findings (12)

**Where:** 02_basic ×1, 03_intermediate ×1, 04_advanced ×3, 05_expert ×1,
06_insane ×5.

**What the engine says:** "Default gateway `10.2.1.254` is not an address that
exists on the network."

**Is it true?** **Yes — of the file.** The `.pkt` genuinely contains
`<PORT_GATEWAY>10.2.1.254`, and no router interface owns `.254`.

**Why it is not a true positive:** Packet Tracer rewrites every end-host gateway
to `1.1.1.2` on load, so in the simulator the host does not have `.254` at all.
The engine read the file; the file disagrees with the running simulator.

**Root cause:** a defect in the **lab generator**, not the diagnostic engine. The
generator sets `<PORT_GATEWAY>` but leaves the engine-level `<GATEWAY>` at the
template default, and PT treats `<GATEWAY>` as authoritative.

**Verified independently:**

```
PC1-3 (built .pkt): IP=10.2.1.12  PORT_GATEWAY=10.2.1.254  GATEWAY=1.1.1.2
PC1-3 (live PT):    IP=10.2.1.12  PORT_GATEWAY=1.1.1.2     GATEWAY=1.1.1.2
```

**Consequence for the benchmark:** this is why all 6 gateway faults are excluded
from ground truth. The lab cannot represent a correct gateway, so it cannot
represent a wrong one either.

## False positive class B: trunk peer (5)

**Where:** 04_advanced ×1, 05_expert ×2, 06_insane ×2.

**What the engine says:** "`SW1:GigabitEthernet0/1` carries VLAN 12 that peer
`SW2:GigabitEthernet0/1` does not."

**Is it true?** **Yes.** When SW2's trunk omits VLAN 12, SW1's trunk genuinely
carries a VLAN its peer does not. Both ends are correctly described.

**Why it scores as FP:** the answer key names one device (SW2, the one that was
misconfigured). Reporting both ends is *more* useful to a student but counts as
one extra finding.

**Assessment:** this is a **scoring-convention mismatch**, not an engine error.
A grading scheme that grouped findings by link would score it correctly.

## False positive class C: duplicate attribution (1)

Covered under Miss 5. Same finding, counted as both a miss and a false positive
because only one device is credited.

## Why precision looks worse than the engine is

Reported precision is 15/32 (46.9%). Broken down:

- **12 of 17** false positives are caused by a lab whose gateways Packet Tracer
  destroys on load. On a lab that loads correctly, these disappear.
- **5 of 17** are true statements about the far end of a real fault.
- **1 of 17** is a correct fault attributed to the other holder.

**Zero** are fabrications. The engine did not invent a single finding.

That is worth stating carefully: 47% precision is what a student experiences, and
it is not good. But the cause is not that the detector hallucinates — it is that
(a) the lab is broken in a way the detector faithfully reports, and (b) the
scoring rule credits one end of a two-ended fault.

## Ranking of real defects worth fixing

1. **Missing-route detection** — 4 of 5 misses, and the honest fix needs
   intended-routing input or behavioural evidence. Largest single gain.
2. **Duplicate-IP attribution** — cheap: report both holders, or match on either.
   Would convert 1 miss + 1 FP into 1 TP.
3. **Lab generator gateway bug** — set `<GATEWAY>` as well as `<PORT_GATEWAY>`.
   Would make 6 currently-unscoreable faults real, raising the benchmark from 20
   to 26 scoreable faults.
4. **Trunk peer convention** — a scoring change, not an engine change.

Items 1–3 are recorded, not applied. Applying them after seeing the results would
invalidate the baseline; the next run should be a fresh measurement.

## What this says about the central question

TRIDENT is not a configuration extractor with a diagnosis label. On labs from a
generator it was never tuned against, at up to 26 devices, it named the right
device and fault class for 15 of 20 faults that genuinely exist — 75% recall —
and produced no fabricated findings.

Its ceiling is specific and explainable: it reasons about configuration and
topology, not about intended policy or observed packet behaviour. Where a fault
is only visible as "this route should exist but does not", configuration alone
cannot decide it.
