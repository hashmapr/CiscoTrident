# PHASE 3 BASELINE AUDIT

Phase 3.0 deliverable. All figures below were **measured on this machine on
2026-11-08**, not carried over from development reports.

- Host: macOS, Apple Silicon (arm64), MacBook Air M4, 16 GB unified memory
- Repository: `~/CiscoTrident`
- Branch state at audit: `cac30d5` plus 12 staged, uncommitted Phase 2 files

---

## 1. Architecture inventory

### Entry points

| Kind | Path | Notes |
|---|---|---|
| Python package | `trident/` | `trident-pt` 1.0.0, requires Python ≥ 3.11 |
| CLI | `trident/__main__.py:main` | registered as the `trident` console script |
| HTTP API | `trident/server.py` | FastAPI app |
| Frontend | `trident/web/` | `index.html`, `app.js`, `style.css` (no framework, no build step) |

The API surface is deliberately small — `server.py` exposes only
`/api/health`, `/api/parsers`, `/api/analyze`. It is a single-shot analysis
service, not a session/task orchestrator. **Phase 3 needs new endpoints; it
cannot hang investigation off the existing three.**

### Core engine interfaces

| Layer | Module | Role |
|---|---|---|
| Extraction | `trident/parsers/` | three families: `pka_xml.py` (Engine A), `pkt_core.py` (Engine B, via `pkt-core`), `pt_convert.py` (Engine C) |
| Aggregation | `trident/parsers/engine_c_bridge.mjs` | Node bridge for Engine C |
| Snapshotting | `trident/parsers/snapshot.py` | block-level snapshot identity |
| Canonical model | `trident/models.py` | Pydantic: `NetworkModel`, `AnswerStatus`, question kinds |
| Normalisation | `trident/normalization/` | interface/name identity resolution |
| Questions | `trident/reasoning/` | `intent.py`, `mcq.py`, `questions.py`, `network_queries.py`, `operations.py`, `entities.py` |
| Verification | `trident/verification/consensus.py` | three-family consensus → `AnswerStatus` |
| Ingestion | `trident/ingestion.py` | upload handling |

### Consensus and confidence policy (must not change)

`trident/verification/consensus.py` maps agreeing family outputs onto
`AnswerStatus`. The statuses in `trident/models.py:18-25` are
`VERIFIED`, `VERIFIED_DERIVED`, `CONFLICT`, `INCOMPLETE`, `NOT_AVAILABLE`,
`ERROR`.

Phase 3 introduces an **orthogonal** axis for simulator evidence
(`SIMULATOR_OBSERVED`). It does not add a fourth family and does not let one
observation count as consensus.

### Phase 2 module status (all present)

| Module | Package | State |
|---|---|---|
| Knowledge engine | `trident/knowledge/` | implemented |
| Requirements | `trident/requirements/` | implemented |
| Compliance | `trident/compliance/` | implemented |
| Remediation | `trident/remediation/` | implemented |
| Network diff | `trident/diff/` | implemented |
| Operational evidence ingestion | `trident/evidence/` | implemented (`types/api/detect/parsers/bundle`) |
| Wireless / endpoints | `trident/wireless/` | implemented |
| Security auditor | `trident/security/` | implemented |
| Fault lab | `trident/faultlab/` | implemented (`baseline/inject/scenarios/grade/types`) |
| Task tracker | `trident/tracker/` | implemented |
| Workflow | `trident/workflow.py` | implemented (**only called from `trident/tracker/engine.py`**) |

### Root-cause diagnostics — the Phase 3 blocker

`trident/diagnostics/types.py` (87 lines, staged, uncommitted) defines
`HypothesisStatus`, `Confidence`, `Observation`, `Hypothesis`, `Diagnosis`.
There is:

- no `trident/diagnostics/__init__.py`
- no detectors
- no tests
- **no importer anywhere in the tree**

`docs/phase2/OPERATIONAL_EVIDENCE.md` names it as the consumer of the evidence
bundle, and `trident/faultlab/grade.py` is written to grade its
`to_report_dicts()` output. So the contract exists on both sides and the engine
in the middle does not.

**Conclusion: Phase 3.0 prerequisite gate is NOT met.** The diagnostics engine
must be completed before investigation can depend on it. See §5.

### Dependency management

`pyproject.toml`, PEP 621. Runtime deps: `fastapi`, `uvicorn`, `pydantic`,
`python-multipart`, `httpx`, `python-dotenv`, `networkx`, `defusedxml`,
`pkt-core`. Dev extra: `pytest`, `pytest-asyncio`. Virtualenv at `.venv/`.

### Security controls present

`defusedxml` for XML parsing; parsers treat lab files as untrusted; no shell
interpolation into subprocess calls found; uploads handled via
`python-multipart`.

### Test infrastructure

- `tests/test_phase1/`, `tests/test_phase2/`, `tests/test_web_ui.py`
- `docs/benchmark_results.json`; runner `trident/tools/benchmark_pack.py`
- Fixtures: `tests/fixtures/sample_lab.pkt`, `tests/fixtures/sample_activity.pka`

### Benchmark tooling and the external pack

The four-network pack lives outside the repo at
`~/Downloads/TRIDENT_4_Network_Benchmark_Pack/` (4 network directories plus
`source_xml/` and `SUMMARY.json`). It is **present** on this machine.

---

## 2. Measured baseline

### Test suite

```
.venv/bin/python -m pytest -q
760 passed in 90.60s
```

760 passing, 0 failing, 0 skipped, 0 errors. This includes the 12 staged
uncommitted Phase 2 changes.

### Four-network benchmark (revalidated, not quoted)

```
python -m trident.tools.benchmark_pack --pack ~/Downloads/TRIDENT_4_Network_Benchmark_Pack

CCNA2_PTSA_P2    65/65 100.0%  verified 65  precision 100.0%  FALSE-VERIFIED 0  24 devices  21 links  5.5s
CCNA_MEGA_LAB    65/65 100.0%  verified 65  precision 100.0%  FALSE-VERIFIED 0  31 devices  41 links  8.6s
OKCUP_R3_2023_24 65/65 100.0%  verified 65  precision 100.0%  FALSE-VERIFIED 0  33 devices  37 links  9.4s
OKCUP_R3_2024_25 65/65 100.0%  verified 65  precision 100.0%  FALSE-VERIFIED 0  33 devices  37 links  8.6s
```

| Metric | Measured now | Historical report |
|---|---|---|
| Questions | 260 | 260 |
| Correct | 260 | 260 |
| Accuracy | 100.0% | 100% |
| VERIFIED | 260 | 260 |
| False-verified | 0 | 0 |
| Wall clock | 32.1 s | ~142 s |

Two corrections to the directive's premise:

- The report of **232/260 verified with 28 hardware-model questions
  INCOMPLETE** is **superseded**. Post-`16d78d7`, all 260 are `VERIFIED`.
- The historical per-network runtimes (21–42 s each) were measured before the
  hardware-model work; the current tree runs the whole pack in 32 s.

### Hardware-model regression

The 28 hardware-model questions are inside the same 260 and now report
`VERIFIED`, so the three-family agreement claim for `16d78d7` holds on this
tree.

---

## 3. Environment for the simulator track

| Item | Value |
|---|---|
| Packet Tracer installed | yes, **9.0.1.0858** |
| Install path | `/Volumes/AI-Models/Cisco Packet Tracer 9.0.1/Cisco Packet Tracer 9.0.1.app` (external volume) |
| Architecture | universal binary, arm64 + x86_64 |
| Code signature | valid, Gatekeeper-accepted |
| Java | Temurin 21.0.12.1 at `/usr/bin/java` |
| Node | available (Engine C bridge) |

Consequence worth recording: the install lives on `/Volumes/AI-Models`. If that
volume is not mounted, Phase 3 runtime is unavailable while **static analysis
continues to work normally**. This is exactly the degradation the directive
requires, and it is handled by the availability check in the runtime.

---

## 4. Phase 3.1 gate result

Measured, not assumed — full detail in `docs/HEADLESS_RUNTIME_FEASIBILITY.md`.

| Capability | Result |
|---|---|
| Launches with no window (`--no-gui`) | **yes** |
| IPC listener reachable | **yes** (opens ~8 s after launch on the requested port) |
| PTMP negotiation | **yes**, server reports `:PTVER9.0.1.0858` |
| MD5 auth challenge received | **yes** |
| Auth accepted | **NO — app id not registered** |
| Headless ExApp registration | **not possible without a GUI session** |

The blocker is a one-time manual registration in a GUI that requires an
unlocked desktop. The screen was locked for the whole feasibility window, so
even the manual path could not be completed, and no automated path exists:

- the IPC API has no registration call (`IPCManager` only launches/messages);
- Packet Tracer does not scan any user folder for `.pta` at startup (tested by
  placing one in `~/Cisco Packet Tracer 9.0.1/extensions/` and relaunching);
- `--autoloadptsa` is a PTSA player flag, not ExApp registration (tested; auth
  still rejected);
- the registration is persisted into the encrypted `PT.conf` only on a clean
  quit, and that file's key is not the `.pkt` key.

**Gate status: NOT PASSED.** Genuine simulator execution could not be
established in this environment. Per the directive, the runtime is therefore
built and tested against a scripted backend, and nothing is described as
working hardware headless execution.

---

## 5. Work that Phase 3.0 leaves owed

1. **Complete the root-cause engine.** `trident/diagnostics/` needs detectors
   over `EvidenceBundle` + `NetworkModel`, tests, and `__init__.py`. Both the
   evidence bundle and `faultlab.grade` already expect it.
2. **Wire Phase 2 modules to the API.** Nothing but `/api/analyze` is reachable
   over HTTP, and `workflow.py` is only used by the tracker.
3. **Commit the 12 staged files** carrying the web-UI overhaul, the evidence
   refactor and the diagnostics types.

Items 1 and 2 are addressed in this Phase 3 sprint. Item 3 is left as an
explicit decision for the repository owner, since those changes are unrelated
to Phase 3 and were in flight before it started.
