# OVERNIGHT PROGRESS

Append-only. Newest section last.

Branch: `development/deepcore`. RC tag `trident-stream-verify-rc1` untouched.

---

## Phase 0 — baseline (COMPLETE)

Commit `c292ced`.

Fixed the IPC port-conflict root cause: the supervisor accepted any listener on
39000-39009, so a Packet Tracer the operator already had running was used instead
of the one just spawned. A free port is now reserved and passed explicitly, so a
connection proves ownership.

Also fixed: ghost bundle reported version `unknown` (now 9.0.1 via a source
marker), and `LiveBackend` reported port 0 for a live session.

Verified: 15 live tests, 36 ownership/runtime tests, no leaked processes.

---

## Phase 1 — DeepCore deterministic reasoning (CORE COMPLETE)

Commit pending.

`trident/deepcore/path.py` predicts forwarding behaviour from configuration and
topology with no LLM.

### What it does

- Walks a path from source to destination device.
- Selects routes by longest prefix match, then administrative distance.
- Handles directly-connected destinations before any routing.
- Distinguishes a router origin (routes from its own table) from a host origin
  (uses its default gateway).
- Detects forwarding loops.
- Reports a shut interface as the failure point with its admin state.
- Evaluates explicit ACL denies bound to a specific interface.

### What it refuses to do

- A destination with no parsed address yields `UNKNOWN`, never "delivered". This
  is the common case for hosts whose address Packet Tracer assigns at runtime.
- A next hop outside the model stops the walk with a stated limitation.
- A prediction carries `SIMULATED_PREDICTION`, never an observation kind. It can
  never enter the three-engine consensus.

### Tests

17 tests in `tests/test_deepcore_path.py`, hand-built models with independently
known answers.

One test was corrected rather than the code: a "missing route" case moved R3 onto
a subnet R2 had no interface in. As originally written R2 reached R3 as directly
connected, so no route was needed and the engine was right to deliver.
