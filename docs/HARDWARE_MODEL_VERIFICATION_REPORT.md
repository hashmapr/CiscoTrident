# Hardware Model Verification Report

Generated: 2026-11-08
Scope: the 28 `hardware_model` questions that were `INCOMPLETE` across the
four-network benchmark.

## Result

| | Before | After |
|---|---|---|
| Correct answers | 260/260 | **260/260** |
| Verified-level answers | 232/260 (89.2%) | **260/260 (100%)** |
| `hardware_model` verified | 0/28 | **28/28** |
| False VERIFIED | 0 | **0** |
| Tests | 513 | **529** |

No `VERIFIED_STRUCTURAL` fallback was needed: three-family extraction covers
the field completely, so adding an alternative trust class would have been
unnecessary complexity.

## 1. Where the model lives

Authoritative field, identical across all four networks (PT 6.0.1, 8.2.2, 9.0.1):

```xml
<DEVICE><ENGINE>
  <TYPE model="2911" customModel="">Router</TYPE>
  <NAME>R1</NAME>
</ENGINE></DEVICE>
```

Two separate facts are stored in one element:

| Fact | Source | Example |
|---|---|---|
| Device category | element text | `Router`, `Switch`, `MultiLayerSwitch`, `PC`, `Server` |
| Hardware model | `@model` attribute | `2911`, `2960-24TT`, `3650-24PS`, `PC-PT`, `3702i` |
| IOS image label | `@customModel` | `2960 IOS15` — **not** the hardware model |

The answer keys use `@model`. Every benchmark question was re-read to confirm
this: e.g. OKCUP expects `2960-24TT` for a device whose `customModel` is
`2960 IOS15`.

## 2. Per-adapter extraction (all independent)

| Engine | Path | Source field |
|---|---|---|
| A (`raw-xml-walk`) | `_walk_xml` | `<TYPE model="...">` attribute |
| B (`pkt-core`) | `pkt_core` typed device | `device.model` |
| C (`pt-convert`) | bridge JSON | `devices[name].model` |

Proven for CCNA2 (66 observations = 22 devices × 3 engines):

```
device           A            B            C            all-3-agree
Admin            PC-PT        PC-PT        PC-PT        True
Brand-101        ISR4321      ISR4321      ISR4321      True
Central          ISR4331      ISR4331      ISR4331      True
DNS Server       Server-PT    Server-PT    Server-PT    True
ISP Router       ISR4331      ISR4331      ISR4331      True
LAP-1            3702i        3702i        3702i        True
Laptop           Laptop-PT    Laptop-PT    Laptop-PT    True
...
families: ['pkt-core', 'pt-convert', 'raw-xml-walk']
snapshot: block0
source_path: DEVICE/ENGINE/TYPE/@model = ISR4331
```

No engine reads another's output. Each parses the document with its own
extractor.

## 3. Consensus integration

`hardware_model` is registered as a normal field-level observation. Nothing
special is done to it:

| Agreeing families | Status |
|---|---|
| 3 | `VERIFIED` |
| 2 | `INCOMPLETE` (strict policy, threshold unchanged at 3) |
| 1 | `INCOMPLETE` |
| conflicting values | `CONFLICT` |
| no observations | `NOT_AVAILABLE` |

The threshold was **not** reduced. The shared container-decode caveat still
applies: all three engines read the same decoded document, so agreement is
extraction-level, not independent confirmation of the document's truth.

## 4. The 28 questions, individually

| # | Network | ID | Status | Answer | Expected |
|---|---|---|---|---|---|
| 1 | CCNA2_PTSA_P2 | Q035 | VERIFIED | ISR4331 | ISR4331 |
| 2 | CCNA2_PTSA_P2 | Q036 | VERIFIED | ISR4331 | ISR4331 |
| 3 | CCNA2_PTSA_P2 | Q037 | VERIFIED | ISR4321 | ISR4321 |
| 4 | CCNA2_PTSA_P2 | Q038 | VERIFIED | ISR4321 | ISR4321 |
| 5 | CCNA2_PTSA_P2 | Q039 | VERIFIED | 2960-24TT | 2960-24TT |
| 6 | CCNA2_PTSA_P2 | Q040 | VERIFIED | 2960-24TT | 2960-24TT |
| 7 | CCNA2_PTSA_P2 | Q041 | VERIFIED | 2960-24TT | 2960-24TT |
| 8 | CCNA_MEGA_LAB | Q035 | VERIFIED | 2911 | 2911 |
| 9 | CCNA_MEGA_LAB | Q036 | VERIFIED | 2911 | 2911 |
| 10 | CCNA_MEGA_LAB | Q037 | VERIFIED | 3650-24PS | 3650-24PS |
| 11 | CCNA_MEGA_LAB | Q038 | VERIFIED | 3650-24PS | 3650-24PS |
| 12 | CCNA_MEGA_LAB | Q039 | VERIFIED | 3650-24PS | 3650-24PS |
| 13 | CCNA_MEGA_LAB | Q040 | VERIFIED | 3650-24PS | 3650-24PS |
| 14 | CCNA_MEGA_LAB | Q041 | VERIFIED | 3650-24PS | 3650-24PS |
| 15 | OKCUP_R3_2023_24 | Q035 | VERIFIED | 2911 | 2911 |
| 16 | OKCUP_R3_2023_24 | Q036 | VERIFIED | 2960-24TT | 2960-24TT |
| 17 | OKCUP_R3_2023_24 | Q037 | VERIFIED | 2911 | 2911 |
| 18 | OKCUP_R3_2023_24 | Q038 | VERIFIED | 2960-24TT | 2960-24TT |
| 19 | OKCUP_R3_2023_24 | Q039 | VERIFIED | 3650-24PS | 3650-24PS |
| 20 | OKCUP_R3_2023_24 | Q040 | VERIFIED | PC-PT | PC-PT |
| 21 | OKCUP_R3_2023_24 | Q041 | VERIFIED | PC-PT | PC-PT |
| 22 | OKCUP_R3_2024_25 | Q035 | VERIFIED | 2911 | 2911 |
| 23 | OKCUP_R3_2024_25 | Q036 | VERIFIED | 2960-24TT | 2960-24TT |
| 24 | OKCUP_R3_2024_25 | Q037 | VERIFIED | 2911 | 2911 |
| 25 | OKCUP_R3_2024_25 | Q038 | VERIFIED | 2960-24TT | 2960-24TT |
| 26 | OKCUP_R3_2024_25 | Q039 | VERIFIED | 3650-24PS | 3650-24PS |
| 27 | OKCUP_R3_2024_25 | Q040 | VERIFIED | PC-PT | PC-PT |
| 28 | OKCUP_R3_2024_25 | Q041 | VERIFIED | PC-PT | PC-PT |

All 28 correct, all 28 `VERIFIED` with three agreeing extraction families.

## 5. Full benchmark after the change

| Network | Correct | VERIFIED | VERIFIED_DERIVED | VERIFIED_STRUCTURAL | INCOMPLETE | False VERIFIED |
|---|---|---|---|---|---|---|
| CCNA2_PTSA_P2 | 65/65 | 31 | 34 | 0 | 0 | **0** |
| CCNA_MEGA_LAB | 65/65 | 31 | 34 | 0 | 0 | **0** |
| OKCUP_R3_2023_24 | 65/65 | 31 | 34 | 0 | 0 | **0** |
| OKCUP_R3_2024_25 | 65/65 | 31 | 34 | 0 | 0 | **0** |
| **Total** | **260/260** | **124** (28 are hardware-model) | **136** | **0** | **0** | **0** |

Runtime 22-42 s per network.

## 6. Adversarial coverage

`tests/test_hardware_model.py` (16 tests):

| Case | Assertion |
|---|---|
| Router 2911 vs 1941 | distinct values, correct device attribution |
| Switch 2960 vs 3650 | distinct values |
| Missing `@model` | no model recorded, never a default |
| `customModel` present | not used as the hardware model |
| Conflicting engines | `CONFLICT`, never `VERIFIED` |
| Placeholder device names | resolved before observation |
| Duplicate device names | identity preserved |
| Multiple snapshots | all observations carry the selected snapshot |
| Reference contamination | wrapper blocks never read |
| Malformed XML | no crash, no model |
| Power Distribution Device | excluded from model answers |
| Duplicate evidence from one family | agreement stays at 1 |
| Removing evidence | never raises confidence |
| Wrong-device attribution | operation returns the named device |
| Answer type | `TEXT`, cardinality `ONE` |

## 7. Remaining limitations

1. **Shared decoder.** All three engines decode with the same public Twofish-EAX
   implementation. Model agreement is three independent *extractions* of one
   decoded document -- not three confirmations that the document matches a live
   Packet Tracer instance. Stated in the UI and here.
2. **`customModel` is unused.** It holds an IOS image label (`2960 IOS15`), not a
   hardware model. It is deliberately ignored; using it would answer a different
   question.
3. **Power Distribution Devices** are structural objects without a meaningful
   hardware model; they are excluded from model answers and from device counts
   by the non-network filter.
4. **The keys were derived from the same XML.** Agreement proves consistency with
   that XML interpretation, not runtime truth.
