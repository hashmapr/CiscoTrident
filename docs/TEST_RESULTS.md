# Test Results

Recorded on macOS (Apple Silicon), Python 3.12.12, with all three parser engines
installed (Engine A vendored Twofish build, PKT-CORE 0.2.2, pt-convert bridge via
Node 22).

## Current run

```
$ pytest -q
461 passed in 121.71s

$ ruff check trident tests
All checks passed!
```

`ruff check .` reports findings only inside `vendor/engine_a` (vendored
third-party code). Those files are intentionally not modified; the audited scope
is `trident tests`.

## Test suites

| Suite | Purpose |
|---|---|
| `tests/test_security.py` | ingestion limits, path traversal, hash preservation, no shell/eval |
| `tests/test_parsers.py` | adapter probes, snapshot policy, real-file extraction |
| `tests/test_normalization.py` | IOS config parsing, mask validation, device/interface merging |
| `tests/test_consensus.py` | strict/two-engine/deterministic consensus, equivalence |
| `tests/test_network_queries.py` | topology, subnets, routes, VLANs, ACLs |
| `tests/test_questions.py` | question parsing, MCQ matching, builder integration |
| `tests/test_mcq_adversarial.py` | substring false positives, entity ambiguity, multi-select |
| `tests/test_grading_adversarial.py` | strict typed grading: no substring, no extra values |
| `tests/test_regressions_correctness.py` | snapshot isolation, family/snapshot consensus gates |
| `tests/test_audit_regressions.py` | evidence-based snapshot selection, AI batching, running-vs-startup config |
| `tests/test_okcup_regressions.py` | real-file production-path assertions (skips without the file) |
| `tests/test_ai_client.py` | key redaction, digest redaction, malformed output |
| `tests/test_api.py` | FastAPI endpoints, real upload, file-hash preservation |
| `tests/test_phase2/*` | Phase 2 engines: requirements, compliance, remediation, knowledge, workflow |

## Benchmark campaign (production path, blind questions)

Four 65-question networks from `TRIDENT_4_Network_Benchmark_Pack`, each run
through `pipeline.analyze` with the answer key withheld until grading.

See `docs/benchmark_results.json` for the complete per-question record and
`docs/PHASE_1_COMPLETION_REPORT.md` for the analysis.

## What a green suite does and does not establish

It establishes pipeline logic: snapshot isolation, consensus gating, provenance,
MCQ strictness, typed grading, batching and read-only guarantees.

It does **not** establish real-file answer accuracy against Packet Tracer's own
runtime. The benchmark keys were themselves generated from exported XML, so
agreement proves consistency with that XML interpretation, not runtime truth.
