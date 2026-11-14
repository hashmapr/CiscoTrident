# CyberPatriot Engineering — Baseline (Milestone 0)

Recorded at the start of the `cyberpatriot/readiness` branch. These numbers are the
before-state, not a claim about the current tree.

## Environment

| Item | Value |
| --- | --- |
| Repository | `~/CiscoTrident` |
| Branch at start | `main` |
| Starting commit | `3ddda2c` |
| Engineering branch | `cyberpatriot/readiness` |
| Python (venv) | 3.12.12 |
| OS | Darwin 27.0.0, `arm64` (MacBook Air M4, 16 GB) |
| Packet Tracer | 9.0.1, bundle on `/Volumes/AI-Models` |
| External volume | `/dev/disk6s1`, 1.7 TiB free, write probe succeeded |

### Model identity

`kilo.json` declares:

```json
"model": "ollama-cloud/deepseek-v4.1-flash:1017-cloud",
"small_model": "ollama-cloud/deepseek-v4.1-flash:1017-cloud"
```

This matches the required **Ollama Cloud — DeepSeek V4.1 Flash 1017**. Verified by
reading the active config file, not inferred from behaviour.

## Offline test baseline

```
python -m pytest -q
14 failed, 1470 passed, 4 skipped, 55 deselected in 1124.75s
```

Browser and live-simulator markers are deselected by `pyproject.toml` `addopts`;
Packet Tracer was not launched by this baseline.

### Pre-existing failures (not introduced by this work)

| Test | Count | Area |
| --- | --- | --- |
| `test_engine_coverage.py` (4) | 4 | Engine C requires an external `pt-convert` checkout |
| `test_okcup_regressions.py` | 9 | Question-shape regressions (identity, address family, gateway/VLAN) |
| `test_sse_recovery.py::test_a_corrupt_file_is_reported_as_undecodable_not_as_empty` | 1 | Corruption reporting |

Ruff: `ruff check trident tests` → **All checks passed**.

## Defects found during the audit

### D1 — Ten packages were missing from every wheel (P0, fixed)

`pyproject.toml` carried a hand-written `packages = [...]` list that had drifted from
the source tree. Missing from every built wheel:

```
trident.deepcore      trident.diagnostics   trident.evidence
trident.evolve        trident.faultlab      trident.investigation
trident.pktcrypto     trident.simulator     trident.tracker
trident.wireless
```

A source checkout masked this: `python -m pytest` and `python -m trident` both worked
because the packages were on disk. An installed TRIDENT could not import its own
simulator, fault lab or deep-reasoning engines.

Fixed by switching to `[tool.setuptools.packages.find]` with `include = ["trident*"]`,
and pinned by `tests/test_packaging.py` (14 tests). Verified by building a wheel and
installing it into a fresh Python 3.15 venv: all 21 packages import, `/api/health`,
`/api/parsers` and `/` all return 200.

Engine A reports `UNAVAILABLE` in the clean venv because the vendored Twofish C library
is not packaged. That is the documented degradation path, not a crash.

### D2 — Known Packet Tracer IPC defects (P0, open at baseline)

Documented in `docs/oracle/DIFFERENTIAL_GAUNTLET_REPORT.md`: IPC port exhaustion,
TIME_WAIT contention and intermittent session connection failures. Addressed in
Milestone 2.

## What was deliberately not run

- Browser tests (`-m browser`) — slow, and not needed for a baseline.
- Live simulator tests (`-m live_simulator`) — these start Packet Tracer.
- Full-repository reread — existing reports were treated as historical evidence and
  each code path was read only when a milestone touched it.

## Environment note

Pre-existing Packet Tracer processes (PIDs 40899, 41461, 49542) were already running
before this session started. They were not started by TRIDENT, are not owned by it, and
were not terminated at any point.
