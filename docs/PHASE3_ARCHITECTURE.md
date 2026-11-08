# PHASE 3 ARCHITECTURE

How the Phase 3 packages fit together, and which parts are proven.

```
                packet tracer file
                        |
                        v
        +-----------------------------------+
        |  Phase 1 extraction (unchanged)    |
        |  engine_a | engine_b | engine_c    |
        |  consensus -> VERIFIED ...         |
        +-----------------------------------+
                        |
                        v
              NetworkModel + AnswerResults
                        |
          +-------------+--------------+
          |                            |
          v                            v
  Phase 2 diagnostics          Phase 3 investigation
  (trident/diagnostics)        (trident/investigation)
          |                            |
          |                    escalation policy
          |                            |
          |                     hypothesis set
          |                            |
          |                   experiment selection
          |                            |
          |                            v
          |                    +---------------+
          |                    |  simulator    |
          |                    |  runtime      |
          |                    +---------------+
          |                      |         |
          |              live PTMP    scripted
          |                      |         |
          |                      v         v
          |                  OperationResult
          |                            |
          +-------------+--------------+
                        v
                 evidence_bridge
            (CliRecord / Observation)
                        |
                        v
                  final report
              (evidence_tier attached)
```

## Packages

| Package | Responsibility | Proven against |
|---|---|---|
| `trident/diagnostics/` | Name defect classes from model + evidence bundle | fault lab, 12/12 exact, silent on baseline |
| `trident/simulator/contracts.py` | Typed results, provenance, budgets | unit tested |
| `trident/simulator/isolation.py` | Disposable copies, path confinement, hash check | unit tested, incl. traversal attacks |
| `trident/simulator/ptmp.py` | Native PTMP wire protocol | negotiation proven against PT 9.0.1; auth blocked |
| `trident/simulator/backends.py` | Live + scripted backends, process supervision | scripted fully tested; live partially (launch + negotiation) |
| `trident/simulator/sessions.py` | Session lifecycle, budgets, capability checks | fully tested |
| `trident/simulator/evidence_bridge.py` | Simulator → Phase 2 evidence, conflict surfacing | fully tested |
| `trident/investigation/escalation.py` | When the simulator is worth starting | fully tested |
| `trident/investigation/hypotheses.py` | Hypothesis tracking, experiment selection | fully tested |
| `trident/investigation/engine.py` | The investigation loop | fully tested against a scripted backend |
| `trident/investigation/doublecheck.py` | Independent audit, coverage counters | fully tested |
| `trident/investigation/whatif.py` | Baseline/after comparison | fully tested |
| `trident/phase3_api.py` | Read-only HTTP surface | fully tested |

## The evidence ladder

Five distinct tiers, and no tier can be silently promoted to another:

1. **Source-file structural facts** — from container decode.
2. **Extracted configuration facts** — three independent families.
3. **Canonical derived facts** — normalised, consensus-checked.
4. **Operational CLI observations** — what a device reports when asked.
5. **Simulator observations** — what actually happened when traffic was sent.

Tier 5 is the only one that can be called `SIMULATOR_OBSERVED`, and only when
every contributing result came from a live backend. The three-family consensus
policy is untouched: a simulator observation never counts as a fourth family and
never turns an answer `VERIFIED`.

## What is proven, and what is not

|Claim|Status|
|---|---|
|Static analysis unchanged by Phase 3|proven — 260/260, 0 false-verified|
|Diagnostics name defects correctly|proven — 12/12 exact, baseline silent|
|Source file never modified|proven — hash verified on every close|
|Budgets enforced before work happens|proven — unit tests|
|Mutations refused by default|proven — command allowlist tests|
|Scripted results never labelled live|proven — provenance tests|
|Invisible launch of real Packet Tracer|proven — zero windows, listener in ~8s|
|PTMP negotiation with real Packet Tracer|proven — server returns `:PTVER9.0.1.0858`|
|Real ExApp authentication|**blocked** — one-time GUI registration|
|Real CLI diagnostics from Packet Tracer|**not demonstrated**|
|Real double-check with live evidence|**not demonstrated**|
|Real what-if with live baseline|**not demonstrated**|

The last four are blocked by the same single cause and would work unchanged once
an ExApp is registered. Nothing in the codebase claims otherwise.

## Design decisions worth recording

**Why a native PTMP client rather than an MCP server.** The directive forbids MCP
as a runtime dependency, and the protocol is small and fully documented in the
shipped Java framework. A direct client is ~330 lines and makes every field
visible for audit.

**Why the scripted backend exists.** Not to fake functionality — it cannot
produce `is_live=True` — but so the isolation, budgeting, evidence-bridging and
investigation logic can be tested deterministically. Without it, none of that
code could be verified in this environment.

**Why detection is read-only.** Every detector indexes the model and never
writes. That is why "the diagnosis did not mutate the network" is a test rather
than a promise.

**Why contradictions eliminate rather than score.** Averaging a contradiction
into a confidence value lets a refuted hypothesis stay "most likely". Elimination
is the only rule that cannot silently produce a wrong answer.
