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

---

## Phase 2 — differential verification (COMPLETE)

`trident/deepcore/differential.py` compares a DeepCore prediction with a Ghost
observation.

### Verdicts

| Verdict | Meaning |
|---|---|
| `AGREES` | Prediction and observation match |
| `DISAGREES` | They differ; classified and preserved |
| `INSUFFICIENT_EVIDENCE` | The experiment established neither delivery nor failure |
| `UNTESTABLE` | The prediction was not definite to begin with |

`INCONCLUSIVE`, `UNSUPPORTED` and `EXECUTION_ERROR` outcomes always yield
`INSUFFICIENT_EVIDENCE`. They are never counted as agreement.

### Real simulator result

```
PREDICTION   delivered=True  definite=True
             R1 Gi0/1 DELIVER 192.168.2.2 directly connected

OBSERVATION  DELIVERED  observed=True  frames=60

VERDICT      AGREES  trusted=True
PROVENANCE   version=9.0.1  session=2bb842461775
CLEANUP      source=INTACT  CLIENT_CLOSED+TERMINATED
```

The prediction and the simulator independently reached the same conclusion, and
both sides were preserved in the record with full provenance.

### What is deliberately not claimed

Agreement is corroboration, not proof. The record keeps the prediction and the
observation separately; neither overwrites the other, and a single agreement does
not promote anything into the static consensus.

14 offline tests plus 2 live tests.

---

## Phase 3 — EVOLVE strategy (COMPLETE)

`trident/evolve/strategy.py` turns stored lessons into planning advice. Until now
the registry was a diary: it recorded lessons nothing consumed.

- `advise(registry, tags)` returns one `Advice` per cause, with the lesson ids
  that justify it. Only trusted lessons qualify — the registry already requires a
  validated state, consensus-or-better evidence, and a counterexample.
- `reorder_experiments` applies `PREFER` advice. `DEFER` and `REQUIRE_EVIDENCE` are
  notes, not permutations, so the effect on behaviour stays small and auditable.
- Advice is inert: it executes nothing and mutates nothing.

14 tests.

---

## Phase 4 — protocol coverage matrix (COMPLETE)

`trident/deepcore/coverage.py` plus a generated `coverage.json`.

Four independent levels, each earned separately: PARSED, MODELLED,
STATICALLY_VERIFIED, SIMULATOR_TESTED. A feature's level is its highest earned
one, and a claimed level must name the test that establishes it.

| Level | Count | Features |
|---|---|---|
| SIMULATOR_TESTED | 2 | ipv4_addressing, static_routing |
| STATICALLY_VERIFIED | 5 | subnetting, vlans, trunks, acl, dhcp |
| PARSED | 1 | ospf |
| UNSUPPORTED | 8 | nat, stp, etherchannel, qos, routing_authentication, ipv6, port_security, device_administration |

**Two overclaims were caught by the evidence test and corrected.** NAT and STP
were marked PARSED. Neither is parsed into the model — the evidence layer can
*hold* a `show spanning-tree` capture, which is not the same as deriving facts
from configuration. Both are now UNSUPPORTED with the reason stated.

OSPF stays PARSED and not MODELLED: a configured `network` statement does not
imply a formed adjacency, and the matrix says so.

---

## Phase 5 — performance (MEASURED, PARTIALLY IMPROVED)

### Profile, measured not assumed

Practice lab, phased timings:

```
parsing     0.840 s   (93%)
consensus   0.004 s
resolving   0.004 s
answer 1    0.006 s
```

Parsing dominates. Within it, per-engine wall times (they run concurrently):

```
engine_a  230 ms
engine_b  946 ms
engine_c  984 ms   -> 989 ms concurrent wall time
```

Decode alone is **390 ms**, and each engine that needs the document was paying
it separately.

### Change: content-addressed decode cache

`trident/pktcrypto/cache.py`, shared by the engine that uses our decoder. Keyed by
the SHA-256 of the input file, so the key is content, not path; a renamed file
hits and a different file never does. Values are immutable bytes, so sharing them
cannot produce cross-engine state.

Sharing the decoded document does **not** weaken extraction independence.
Independence is about how facts are derived from the document; each engine still
parses the bytes itself.

### Measured effect

| Fixture | First run | Repeat run | Change |
|---|---|---|---|
| sample_lab.pkt (0.6 MB) | 1449 ms | 832 ms | **-43%** |
| R3_OKCUP_24_25 (2.5 MB) | 27.68 s | 15.83 s | **-43%** |

Same device counts, identical answers. The cache is process-local and in-memory
only: no plaintext is written to disk.

### What did not improve, and why

Only one engine uses the shared decoder; the other two use libtwofish and a Node
bridge, so on a *first* analysis there is nothing to share. The 30 MB decode
measured 133.9 s in this session versus 107.6 s earlier — machine load, not a
regression, and the variance is recorded rather than smoothed over.

Further gains would need the native engines to accept a pre-decoded document, which
would couple them to our decoder and is a larger change than this phase allows.
