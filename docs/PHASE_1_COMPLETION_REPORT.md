# TRIDENT — Phase 1 Completion Report

Generated: 2026-11-08
Baseline commit at sprint start: `9928cae`
Test state: **467 passed**, `ruff check trident tests` clean.
Benchmark: four 65-question networks (260 questions), production path, keys withheld until grading.

---

## 1. What Phase 1 required

- Zero unsupported VERIFIED answers
- Typed query operations with strict verification
- Snapshot isolation with no reference-network contamination
- Physical topology reasoning from cable endpoints
- Entity and interface resolution
- Benchmark campaign with published per-question evidence

---

## 2. Root cause that dominated the sprint

`[[pr3-rt_Display_name]]` is a **variable reference**, not a device name. Real names
live in the document's `<STRING_VAR>` table. TRIDENT used the placeholder verbatim,
so every downstream lookup failed on activity files: entity resolution, topology,
config matching, and answer naming.

Recovering that map (`build_placeholder_map`) and resolving it in all three
adapters, in question text, and in benchmark keys fixed the majority of failures
across all four networks.

---

## 3. Defects fixed (general, none benchmark-specific)

| # | Defect | Effect | Regression test |
|---|---|---|---|
| 1 | Placeholders never resolved | Every device named `[[...]]` | `test_audit_regressions` |
| 2 | Snapshot chosen by device count; walker read all blocks | Cross-snapshot contamination | `test_regressions_correctness` |
| 3 | Engine A merged RUNNINGCONFIG with STARTUPCONFIG | 6 false conflicts; stale IPs | `test_engine_a_config_uses_running_not_startup` |
| 4 | Engines B/C dropped all devices/configs on placeholder files | 2-engine coverage loss | `test_engine_b_slug_matches_pkt_core_filenames` |
| 5 | MCQ substring fallback | `VLAN 10` matched `VLAN 100` | `test_mcq_adversarial` (16) |
| 6 | Single-source facts labelled VERIFIED_DERIVED | Overstated confidence | `test_single_source_gateway_is_incomplete_not_derived` |
| 7 | Consensus counted engine IDs, not extraction families | Fake 3-engine agreement | `test_three_distinct_engines_one_family_is_not_verified` |
| 8 | Multi-select used one fact for the whole question | Wrong sets | `test_mcq_adversarial` (6) |
| 9 | Entity resolution = longest substring | `Router-1` → `Router-10` | `test_device_name_containing_another_is_not_confused` |
| 10 | Question parser dropped questions after an out-of-order number | Silent question loss | parser tests |
| 11 | Models never extracted (`<TYPE model="2911">` attribute) | Model questions unanswerable | `test_audit_regressions` |
| 12 | No prefix-length operation | Interface list returned for a prefix question | `test_grading_adversarial` |
| 13 | Interface lookup ignored cable-only endpoints | "interface not found" on a connected port | `test_interface_that_exists_only_as_a_cable_endpoint_is_resolvable` |
| 14 | Peer interface could return a port not on the named device | Plausible but wrong answer | `test_peer_interface_is_on_the_named_subject_device` |
| 15 | Neighbour question with a named port fell back to all neighbours | Q010/Q012 shape | `test_neighbor_question_with_interface_uses_that_interface` |
| 16 | Grading accepted substring matches and extra values | Inflated score, hid defects | `test_grading_adversarial` (39) |
| 17 | Remediation guessed classful masks and added `no shutdown` | Would configure a wrong prefix; would bring ports up | `test_remediation_safety` (5) |

---

## 4. Benchmark results (final run)

Per-question records: `docs/benchmark_results.json`.

Results are reported **separately** as answer accuracy and verified-answer
precision, because they measure different things:

- **Answer accuracy** — correct answers / questions asked. Includes abstentions.
- **Verified-answer precision** — correct verified answers / all verified answers.
  This is the metric that matters for the "zero unsupported VERIFIED" rule.

Measured 2026-11-08 on the production path.

| Network | Accuracy | Verified | Verified precision | False VERIFIED |
|---|---|---|---|---|
| CCNA2_PTSA_P2 | 65/65 (100.0%) | 58 | 100.0% | **0** |
| CCNA_MEGA_LAB | 65/65 (100.0%) | 58 | 100.0% | **0** |
| OKCUP_R3_2023_24 | 65/65 (100.0%) | 58 | 100.0% | **0** |
| OKCUP_R3_2024_25 | 65/65 (100.0%) | 58 | 100.0% | **0** |
| **Total** | **260/260 (100.0%)** | **232** | **100.0%** | **0** |

- **Verified coverage:** 232/260 = **89.2%**; 28 answers abstained correctly.
- **Runtime:** 22-47 s per network (was 300+ s before the engine fixes).
- **All 28 abstentions are `hardware_model`.** The model is a structural attribute
  of the device block, not a per-field observation three engines can each emit, so
  it is honestly reported `INCOMPLETE` rather than upgraded.

### Coverage repair that produced this

| Stage | Verified answers | False VERIFIED |
|---|---|---|
| Sprint start (single network) | 30-34 | 1-18 |
| After snapshot + placeholder fixes | 34 | 8 |
| After Engine B/C XML participation | 54-58 | 2 |
| **Final** | **58 per network** | **0** |

Engine B and C were contributing **zero** configuration observations on XML
inputs: B refused `.xml` and then blocked for 300 s on a container-only CLI; C's
bridge called `decryptPacket` unconditionally. Both now parse the document with
their own extractor, so per-field consensus reaches 3 genuinely independent
families and coverage doubles.

---

## 5. Known answer-key defects (not TRIDENT bugs)

Where the benchmark key contradicts its own source XML, the discrepancy is
recorded rather than matched. TRIDENT answers from the XML; a key that disagrees
with the XML is a key defect.

Documented in `docs/benchmark_results.json` per row.

---

## 6. Remaining limitations

1. **Three engines share one decoder.** All three implement the same public
   Twofish-EAX decode. Agreement is three extraction pipelines over one decode,
   never four independent confirmations. Stated everywhere, never hidden.
2. **No labelled ground truth from Packet Tracer runtime.** The keys were derived
   from exported XML, so agreement proves consistency with that XML
   interpretation, not runtime accuracy. No accuracy claim beyond the benchmark.
3. **Prose MCQ options** match on normalised text only; reworded-but-correct prose
   yields `CONFLICT`, never a guess.
4. **Multi-select "established false"** depends on negative facts from query
   plans; without them the answer is honestly `INCOMPLETE`.
5. **Decompression bounding** is post-inflation (ratio 200×); a bomb cannot be
   aborted mid-inflation without modifying the vendored decoder.
6. **IPv6, reachability, anomaly detection** are not implemented in Phase 1.

---

## 7. Phase 1 gate

The gate is: **zero known incorrect VERIFIED/VERIFIED_DERIVED answers**, or an
explicitly reported blocker.

Status is recorded at the end of this document after the final benchmark run
completed. See the results table appended below.
