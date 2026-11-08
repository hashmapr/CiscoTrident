# PHASE 3 BENCHMARK REPORT

All figures measured on this machine, 2026-11-08, Apple Silicon arm64.

## 1. Regression benchmark — four networks, 260 questions

Run: `python -m trident.tools.benchmark_pack --pack ~/Downloads/TRIDENT_4_Network_Benchmark_Pack`

| Network | Questions | Correct | Verified | False-verified | Devices | Links | Runtime |
|---|---|---|---|---|---|---|---|
| CCNA2_PTSA_P2 | 65 | 65 | 65 | 0 | 24 | 21 | 5.5 s |
| CCNA_MEGA_LAB | 65 | 65 | 65 | 0 | 31 | 41 | 8.8 s |
| OKCUP_R3_2023_24 | 65 | 65 | 65 | 0 | 33 | 37 | 9.2 s |
| OKCUP_R3_2024_25 | 65 | 65 | 65 | 0 | 33 | 37 | 8.6 s |
| **Total** | **260** | **260** | **260** | **0** | | | **31.8 s** |

Accuracy 100.0%, verified precision 100.0%, zero false-verified. Identical to the
pre-Phase 3 baseline recorded in `docs/PHASE3_BASELINE_AUDIT.md`, so Phase 3
changed no static behaviour and no consensus semantics.

Hardware-model coverage: the 28 questions that were `INCOMPLETE` before
`16d78d7` are inside these 260 and now report `VERIFIED`, consistent with the
three-family agreement claim.

## 2. Diagnostics accuracy — fault lab, 12 scenarios

The fault lab grades a report against a held-back answer key. Scoring:
`score = found / (found + missed + spurious)`.

| Scenario | Expected | Reported | Exact |
|---|---|---|---|
| wrong-vlan | WRONG_VLAN | WRONG_VLAN | yes |
| invalid-mask | INVALID_MASK | INVALID_MASK | yes |
| wrong-gateway | WRONG_GATEWAY | WRONG_GATEWAY | yes |
| missing-static-route | MISSING_STATIC_ROUTE | MISSING_STATIC_ROUTE | yes |
| shutdown-interface | SHUTDOWN_INTERFACE | SHUTDOWN_INTERFACE | yes |
| acl-block | ACL_BLOCK | ACL_BLOCK | yes |
| trunk-mismatch | TRUNK_MISMATCH | TRUNK_MISMATCH | yes |
| routing-loop | ROUTING_LOOP | ROUTING_LOOP | yes |
| dhcp-misconfiguration | DHCP_MISCONFIGURATION | DHCP_MISCONFIGURATION | yes |
| duplicate-ip | DUPLICATE_IP | DUPLICATE_IP | yes |
| overlapping-subnet | OVERLAPPING_SUBNET | OVERLAPPING_SUBNET | yes |
| dual-shutdown-gateway | SHUTDOWN_INTERFACE + WRONG_GATEWAY | both | yes |

**12/12 exact, 0 missed, 0 spurious.** The healthy baseline produces **zero**
findings, which is the regression that stops every detector from becoming a
false-positive generator.

This result required two passes. The first detector set fired on the clean
baseline (six spurious `WRONG_VLAN` findings) because it used single-field
patterns; it was replaced with inter-part consistency rules (peer trunk
comparison, gateway against real interface addresses, transit router against its
dependent subnet). The false positives are recorded here rather than hidden.

## 3. Investigation holdout evaluation

The directive asks for a holdout of ≥10 unseen practice networks with multi-fault
cases. **This was not built.** What exists and is measured:

| Aspect | Status |
|---|---|
| Testable uncertainty resolution | implemented; verified against a scripted backend |
| Multi-fault handling | verified — `dual-shutdown-gateway` graded exact |
| Correct abstention | verified — documentation gaps and unavailable runtime abstain |
| Live-diagnosis accuracy | **not measured** — no live simulator available |
| ≥10-network holdout pack | **not built** |

The 90% holdout target therefore **cannot be claimed**. Claiming it from the
12-scenario synthetic lab would be exactly the kind of substitution the directive
forbids.

## 4. Double-check benchmark

| Property | Result |
|---|---|
| Detects an injected fault | yes — `TRUNK_MISMATCH` found in the trunk scenario |
| Invents no fault on a healthy network | yes — zero confirmed findings on the baseline |
| Distinguishes untested from passed | yes — `operationally_checked=0`, `simulator_tested=0` reported separately |
| Claims no fake percentage | yes — no `percent_verified` field exists |
| Reports unsupported vs unresolved vs skipped | yes — three distinct verdicts, all covered by tests |

## 5. Test suite

```
913 passed, 2 skipped in 89.9s
```

The 2 skips are the live-simulator authentication tests. They are recorded as
skips and are **not** counted as passes. Two further live tests pass because they
only require an installed bundle (discovery and version reporting).

| Suite | Tests |
|---|---|
| Phase 1 and shared | 760 (baseline) |
| Diagnostics | 30 |
| Simulator runtime | 27 |
| Simulator adversarial | 32 |
| Investigation | 31 |
| Double-check and what-if | 18 |
| Phase 3 API | 13 |
| Phase 3 demos | 3 |

## 6. Performance

| Metric | Measured |
|---|---|
| Static analysis, 4 networks | 31.8 s total (5.5–9.2 s each) |
| Simulator launch to listener | ~8 s |
| Session creation (copy + hash) | sub-millisecond |
| Scripted operation | sub-millisecond |
| Live diagnostic | **not measured** |
| Memory (static analysis) | unchanged from Phase 2 |

No performance claim is made for live diagnostics because none ran.

## 7. What is not measured, and why

| Gap | Reason |
|---|---|
| Live diagnostic latency | no registered ExApp |
| Live investigation accuracy | same |
| ≥10-network holdout | not built; would need new practice networks with independent answer keys |
| Real double-check on a live network | same |
| Real what-if baseline/after | requires a mutation-capable backend, which this build does not advertise |

Each gap is an environment or scope limitation, and none of them is reported as a
pass anywhere in this repository.
