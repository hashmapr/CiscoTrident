# PHASE 3 RELEASE READINESS

Status: **conditional**. Static analysis and diagnostics are release-ready. Live
simulator execution is not, and is not claimed.

## Gate summary

| Gate | Status | Evidence |
|---|---|---|
| 3.0 Baseline audit and Phase 2 prerequisites | **PASSED** | `docs/PHASE3_BASELINE_AUDIT.md`; 913 tests |
| 3.1 Headless feasibility | **FAILED** | `docs/HEADLESS_RUNTIME_FEASIBILITY.md`; auth rejected |
| 3.2 Runtime controller | **PASSED** (scripted), partial (live) | launch and negotiation proven; auth blocked |
| 3.3 Evidence integration | **PASSED** | provenance, tier and conflict tests |
| 3.4 Smart Investigation | **PASSED** (scripted) | 31 investigation tests |
| 3.5 Double-Check | **PASSED** (static + scripted) | 18 audit tests |
| 3.6 What-If | **PASSED** (refusal semantics) | 18 tests; source preserved |
| 3.7 Hardening | **PASSED for what exists** | 913 tests, lint clean, benchmark unchanged |

## What is implemented and tested

- Root-cause diagnostics engine (30 tests, 12/12 fault-lab exact, silent baseline)
- Simulator runtime: isolated copies, budgets, capability discovery, session
  lifecycle, process supervision (59 tests)
- Native PTMP client (protocol round-trip, auth rejection, secret redaction)
- Evidence bridge with tier classification and conflict preservation
- Smart Investigation with deterministic escalation and hypothesis elimination
- Double-Check with honest coverage accounting
- What-If with baseline-before-change and refusal outcomes
- Phase 3 API and UI simulator-status surface
- Demonstration runner locked by 3 tests

## What is tested only with mocks / scripted backend

- Every investigation loop outcome that requires an observation
- Every operational check in the auditor
- Every what-if evaluation path
- Every live-backend code path except launch and negotiation

## What is tested against a real simulator

- Discovery of the installation and version reporting
- Invisible launch: zero windows, listener in ~8 s
- PTMP negotiation: server reports `:PTVER9.0.1.0858`
- MD5 challenge is issued by the real server

## What is not demonstrated

- Authenticated PTMP session with a real Packet Tracer
- `enterCommand` returning real CLI text
- Real ping success and failure observations
- A live investigation end-to-end
- A live double-check
- A live what-if baseline/after comparison

## Release blockers

1. **ExApp registration is a one-time manual step needing an unlocked desktop.**
   Until it is done, every live path above stays blocked. This is the single
   blocker; it is not a code defect.
2. **No holdout benchmark pack.** The ≥10-network, ≥90% diagnostic target in the
   directive cannot be claimed from the 12-scenario synthetic lab.

## Known limitations

- The install lives on `/Volumes/AI-Models`; if unmounted, the runtime is
  unavailable and static analysis continues normally.
- Only Packet Tracer 9.0.1.0858 has been exercised.
- Mutations are refused even when the ExApp grants `CHANGE_NETWORK_INFO`. What-if
  therefore reports `UNSUPPORTED_COMMAND` rather than performing a change.
- One active session per runtime; concurrency above one is untested by design.
- Diagnostics reason about the fault-lab taxonomy; defect classes outside it are
  not named.

## What works today, without Packet Tracer

The full Phase 1 answer pipeline (260/260, 0 false-verified), the diagnostics
engine, static double-check with honest coverage, and the simulator-status UI
surface. Nothing in that path requires the simulator to be present or registered.

## Recommended next steps

1. Register the ExApp once on an unlocked desktop, set `TRIDENT_PT_APP_ID` and
   `TRIDENT_PT_SECRET`, then run
   `pytest tests/simulator/test_live_integration.py -v`. Everything downstream
   should work with no code change; if it does not, that is where to look.
2. Build the holdout pack before making any accuracy claim beyond the fault lab.
3. Only after both, consider advertising live diagnosis in the product surface.
