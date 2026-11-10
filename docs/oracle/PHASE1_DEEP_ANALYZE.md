# PHASE 1 — GHOST-POWERED DEEP ANALYZE

## What Deep Analyze does now

Selecting **Deep Analyze** and pressing Analyze Network runs real experiments in
Packet Tracer and folds the results into the report.

`trident/deepcore/deep.py`:

1. Chooses candidate pairs from devices that have a routed physical interface.
   SVIs, loopbacks and tunnels are excluded — they are not user traffic paths.
   Hosts without a parsed address are excluded because Packet Tracer assigns
   theirs at runtime, so a test against them is unreliable.
2. Creates one isolated session, sends a simple PDU per pair, and records the
   outcome with its session and provenance.
3. Closes the session and verifies the source file hash is unchanged.
4. Reports what happened: `OBSERVED`, `UNAVAILABLE`, `INCONCLUSIVE`,
   `UNSUPPORTED`, `FAILED` or `NOT_ATTEMPTED`.

## Lazy escalation, enforced

A hardware model, a stored hostname or an interface address is answered from the
configuration. Nothing about them starts a simulator. Escalation is limited to
connectivity between routed devices — behaviour that only exists when traffic
flows.

The budget is bounded: at most three experiments, one session, one timeout.

## Evidence handling

An observed check becomes an `OBSERVED` answer on both devices with the simulator
version and session id attached. It never enters the three-engine consensus, so it
cannot raise anything to `VERIFIED`.

An unavailable simulator produces a stated gap, not silence:

```
Deep Analyze could not run experiments: live simulator is disabled ...
```

and an entry in "What was not checked" naming each skipped pair.

## Live demonstration

Real browser, real Chromium, `TRIDENT_ALLOW_LIVE_SIMULATOR=1`:

```
status    Analyzed 7 device(s) in 14.1s
runtime   "Deep Analyze ran operational experiments in Packet Tracer 9.0.1.
           Source file unchanged."
version   visible in the UI
errors    none
```

API-level evidence from the same path:

```
R1 -> R2  OBSERVED  frames=60
          decision: "The Ping process starts the next ping request."
runtime_available True | version 9.0.1 | source_intact True
```

## Tests

12 in `tests/test_deep_analyze.py`, 8 in the Analyze Mode browser suite
(including one that runs with the simulator enabled), and the 34 existing Analyze
Mode tests updated where they asserted the old "never runs" behaviour.

## Limits

- One session, at most three experiments. Deeper investigation still uses the
  investigation engine rather than Analyze Mode.
- Only ICMP connectivity is tested; protocol-specific experiments remain in the
  CLI path.
- A host whose address Packet Tracer assigns at runtime cannot be a PDU endpoint
  from static analysis.
