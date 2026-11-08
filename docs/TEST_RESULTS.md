# Test Results

Recorded on macOS (Apple Silicon), Python 3.12.12, with all three engines installed
(Engine A vendored Twofish build, PKT-CORE 0.2.2, pt-convert bridge via Node 22).

## Current run (2026-11-07, post-audit)

```
$ pytest -q
224 passed in 97.90s

$ ruff check trident tests
All checks passed!
```

`ruff check .` (repository root) reports 5 findings, all inside `vendor/engine_a`
(vendored third-party code). Those files were intentionally not modified; the
audited scope is `trident tests`.

## Previous runs

| Date | Command | Result |
|---|---|---|
| 2026-11-07 (audit start, baseline) | `pytest -q` | 184 passed |
| 2026-11-07 (audit start) | `ruff check .` | 5 errors, all in `vendor/engine_a` |
| 2026-11-07 (snapshot/consensus/MCQ fixes) | `pytest -q` | 206 passed |
| 2026-11-07 (entity resolver, layer provenance) | `pytest -q` | 217 passed |
| 2026-11-07 (final) | `pytest -q` | 220 passed |
| 2026-11-07 (two extra real files, majority-agreement snapshot rule, hostname queries) | `pytest -q` | 224 passed |

## Test suites

| Suite | Purpose |
|---|---|
| `tests/test_security.py` | ingestion limits, path traversal, hash preservation, no shell/eval |
| `tests/test_parsers.py` | adapter probes, snapshot policy, real-file extraction, timeout/crash handling |
| `tests/test_normalization.py` | IOS config parsing, mask validation, device/interface merging |
| `tests/test_consensus.py` | strict/two-engine/deterministic consensus, conflicts, equivalence |
| `tests/test_network_queries.py` | topology, subnets, routes, VLANs, ACLs |
| `tests/test_questions.py` | question parsing, MCQ matching, builder integration |
| `tests/test_mcq_adversarial.py` | substring false positives, entity ambiguity, multi-select adjudication |
| `tests/test_regressions_correctness.py` | snapshot isolation across adapters, family/snapshot consensus gates, multi-select pooling |
| `tests/test_audit_regressions.py` | evidence-based snapshot selection, single-source labelling, AI batching/truncation, running-vs-startup config, slug mapping |
| `tests/test_ai_client.py` | key redaction, digest redaction, malformed output, transport errors |
| `tests/test_api.py` | FastAPI endpoints, real upload end-to-end, file hash preservation |

## Real-file validation (not part of the unit suite)

Commands run manually, results recorded:

| Check | Result |
|---|---|
| `pytest -q` | 220 passed, 0 failed, 0 skipped |
| Real HTTP upload `/api/analyze` on `sample_lab.pkt` | 200; upload SHA-256 matches; file untouched; `Q1 VERIFIED → 192.168.1.1` |
| Reject bad extension / empty questions | 400 / 400 |
| Batch integrity 10 / 25 / 65 / 100 questions | ordered, no drops (10, 25, 65, 100 results) |
| Live AI (Ollama Cloud) 5-question flow | `ai_used=True`; 1 VERIFIED, 2 VERIFIED_DERIVED, 2 INCOMPLETE; no hallucinated facts |
| Real multi-snapshot `.pka` (9.0.1) | `block0` selected by template evidence; 21 devices / 207 interfaces / 19 links; **0 conflicts** |
| Real multi-snapshot `.pka` (8.2.2) `R1_OKCUP…(1)` | `block0` selected by majority agreement; 20 devices / 207 interfaces / 19 links; 34 VERIFIED, 20 INCOMPLETE, **0 conflicts**; 219 s |
| Real activity `.pka` (6.0.1) Skills Integration Challenge | `block0` selected by majority agreement; 14 devices / 130 interfaces / 13 links; 32 VERIFIED, 36 INCOMPLETE, **0 conflicts**; 42 s |
| Well-formed questions on Skills file | IP queries `VERIFIED`; hostname `VERIFIED` (3/3); topology `VERIFIED_DERIVED`; missing entities correctly `NOT_AVAILABLE` |
| Empty activity skeleton | all engines abstain; questions `NOT_AVAILABLE` with explanation |

## What a green suite does and does not establish

It establishes pipeline logic: snapshot isolation, consensus gating, provenance,
MCQ strictness, batching, and read-only guarantees.

It does **not** establish real-file answer accuracy for arbitrary questions.
There is no labelled benchmark in this workspace, so no accuracy percentage is
claimed anywhere. See `docs/PKA_CORPUS_REPORT.md`.
