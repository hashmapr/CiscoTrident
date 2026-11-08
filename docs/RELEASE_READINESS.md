# TRIDENT — Release Readiness

Target: 14 November 2026
Assessed: 2026-11-07
Baseline commit: `9928cae` (audited with uncommitted changes in the working tree)

## Verdict

**Conditionally ready.** The correctness-critical defects found in this audit are
fixed and covered by regression tests. Two deliberate limitations remain
(post-inflation-only decompression bounding, declared-constant extraction families)
and one capability gap (no labelled benchmark for accuracy) means the release
should ship as **beta**, with the limitations documented rather than hidden.

## Completed requirements

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 1 | Zero unsupported verified answers | **Done** | `single-source → INCOMPLETE`; family+snapshot+decoder gates; MCQ substring fallback removed |
| 2 | Repository audit incl. uncommitted changes | **Done** | `docs/FULL_CODE_AUDIT.md`, 12 issues |
| 3 | Corpus discovery + manifest + configurable dir | **Done** | `trident/tools/corpus_manifest.py`, `TRIDENT_TEST_CORPUS_DIR` |
| 4 | Snapshot isolation, no reference contamination, abstain on ambiguity | **Done** | `tests/test_audit_regressions.py`, real-file run |
| 5 | Four-layer provenance (decode / extract / interpret / validate) | **Done** | `Provenance.decoder/extraction_family/interpretation_family/normalization/validation` |
| 6 | No duplicate-family counting; no silent downgrade | **Done** | fixed policy floors; family-count check |
| 7 | Directly-observed single source vs derived distinction | **Done** | `_single_source_fact` → `INCOMPLETE` |
| 8 | MCQ false positives eliminated | **Done** | 16 adversarial tests |
| 9 | Per-option TRUE/FALSE/UNKNOWN multi-select | **Done** | `adjudicate_options`, `match_multi_independent` |
| 10 | Canonical entity resolver | **Done** | `trident/reasoning/entities.py`, ambiguity reporting |
| 11 | AI stays an interpreter | **Done** | plan schema only; facts always from consensus |
| 12 | AI batching / truncation / reconciliation | **Done** | 10/25/65/100 batch tests; live provider run |
| 13 | Read-only + security guarantees | **Done (see limitation)** | `tests/test_security.py`, real HTTP hash check |
| 14 | Full suite + real HTTP upload | **Done** | 220 passed; `/api/analyze` 200 |
| 15 | Four required reports | **Done** | this file + 3 others in `docs/` |

## Partially completed

| Item | What is done | What is missing |
|---|---|---|
| Decompression bomb defence | Post-inflation size + ratio caps (200×, real files are 10–13×) | Pre-inflation abort requires modifying/wrapping the vendored decoder |
| Extraction-family independence | Families are declared per adapter and enforced structurally | Cannot be proven; all engines share the same public Twofish-EAX decode |
| Multi-select completeness | Every option adjudicated; UNKNOWN blocks VERIFIED | No general negative-fact mining, so many multi-select questions end INCOMPLETE |
| Corpus coverage | 3 files, one real multi-snapshot assessment file | Only Packet Tracer 9.0.1.0858 present; older container formats untested |
| AI provider compatibility | Validated against Ollama Cloud (OpenAI-compatible) | Other providers not exercised |

## Unresolved blockers

None that block a beta release.

## Known limitations (documented, not hidden)

1. Three-engine consensus is three **extraction** pipelines over one **shared decode**. Never presented as four independent confirmations.
2. Several populated snapshots without template placeholders → abstention. By design; the operator must supply a single-snapshot file.
3. Prose MCQ options match only on exact normalised text. Reworded answers yield `CONFLICT`, never a guess.
4. Routing-protocol behaviour and simulation outcomes are out of scope (static configuration analysis only).
5. No accuracy percentage is claimed; no labelled benchmark was available.
6. Engine C requires the operator's own pt-convert checkout (All Rights Reserved, never vendored).

## Release checklist

- [x] Full suite green (220 passed)
- [x] `ruff check trident tests` clean
- [x] Real HTTP upload verified, file hash unchanged
- [x] Snapshot isolation verified on a real multi-snapshot `.pka`
- [x] Zero conflicts on the real assessment file
- [x] Live AI flow verified with the configured provider; no key leakage
- [x] Security review recorded
- [x] Four reports written
- [ ] Commit and tag (explicitly **not** done — no automatic push per instructions)
- [ ] Optional: labelled benchmark to enable an accuracy figure

## Recommendation

Ship as **beta**. The blocking correctness issues (snapshot contamination,
running/startup config merge, MCQ substring matching, single-source mislabelling)
are fixed with regression coverage. The remaining items are scope limits that the
application already reports honestly at answer time.
