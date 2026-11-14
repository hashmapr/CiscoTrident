# Frozen historical baseline — the six-level gauntlet

Frozen at commit `7f43cd5`. This is the number Engine D and the dual-engine work
must be compared against. It is **not** to be retested and described as unseen
generalization: the new validation set is separate.

## Correction to the task brief

The operation brief states the previous result as "15/20 verified faults
identified, 75% recall, **zero reported false positives**".

The first two are correct. The third is **not**. Measured at `98fcac9`:

- **False positives: 17**
- **Precision: 15/32 (46.9%)**

What *is* zero is the count of **fabricated** findings: every one of the 17 was
true of some observable state. That distinction is recorded in
`docs/gauntlet/ERROR_ANALYSIS.md` and is not the same claim. Freezing the
baseline with "zero false positives" would make every later precision number
look like a regression against a target that was never met.

## The frozen numbers

| Metric | Value |
|---|---|
| Ground-truth faults (verified present in PT 9.0.1) | **20** of 26 keyed |
| True positives | 15 |
| False negatives | 5 |
| **Recall** | **15/20 (75.0%)** |
| False positives | 17 |
| **Precision** | **15/32 (46.9%)** |
| Fabricated findings | **0** |
| Topology devices | 70/70 |
| Topology links | 67/67 |
| Labs opened in PT 9.0.1 | 6/6 |
| Median runtime | 1.5 s |
| Worst runtime | 2.4 s |

## False-positive composition (why 17 is not one number)

| Class | Count | Nature |
|---|---:|---|
| Gateway findings | 12 | True of the `.pkt`, false in the simulator (PT overwrites NIC gateway on load) |
| Trunk peer findings | 5 | True statements naming the other end of a real fault |
| Duplicate-IP attribution | 1 | Correct fault, key names the other holder |

## Known misses

| Fault | Kind | Cause |
|---|---|---|
| 03/F05, 05/F05, 06/F05, 06/F10 | missing static route | Detector reasons only about reverse-route contradictions |
| 06/F07 | duplicate IP | Correct finding, attributed to first holder |

The missing-route family is the target of Engine D: a route is a fault only when
*intent* says the path is required.

## Non-negotiable rule for the next measurement

The new validation set must not contain the six gauntlet topologies, nor the
Broken Campus lab, nor the four CCNA3 labs. Reporting accuracy on those and
calling it generalization would be dishonest, and this file exists so that
substitution is visible if it happens.
