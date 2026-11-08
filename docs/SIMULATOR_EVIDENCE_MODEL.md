# SIMULATOR EVIDENCE MODEL

How an observation becomes evidence, and what it is allowed to prove.

## Categories

Nine categories exist and are never interchangeable.

| # | Category | Source | Can confirm |
|---|---|---|---|
| 1 | Source-file structural fact | container decode | structure only |
| 2 | Extracted configuration fact | one extraction family | only with consensus |
| 3 | Canonical derived fact | normaliser over agreeing families | yes, per consensus policy |
| 4 | Operational CLI observation | a device's own output | the reported state |
| 5 | Simulator observation | a live PTMP session | the tested behaviour only |
| 6 | Inferred hypothesis | diagnostics engine | nothing; it is a question |
| 7 | Predicted what-if result | reasoning about a candidate | nothing |
| 8 | Observed what-if result | live experiment after a change | the delta, for that test |
| 9 | Scripted result | scripted backend | nothing about the simulator |

Categories 5 and 9 are both `OperationResult`s, and they are distinguished by
`provenance.backend` and `observed`, never by where they were stored.

## Provenance

Every result records:

```
backend              SIMULATOR_LIVE | SCRIPTED | UNAVAILABLE
simulator_version    9.0.1 / scripted-1
session_id           unique per session
source_sha256        hash of the file the session was created from
working_copy_sha256  hash of the copy the simulator actually loaded
device, interface
operation            the exact command or test
executed_at          UTC timestamp
parsed_by            parser identity
caveats              e.g. "scripted backend: not a simulator observation"
```

`source_sha256` and `working_copy_sha256` differing is *expected* — the session
works on a copy. What matters is that `source_sha256` still matches the file on
disk at close, which `Session.close()` verifies.

## What an observation may and may not prove

| Observation | Proves | Does not prove |
|---|---|---|
| Successful ping | connectivity for that path, those conditions | other paths, other services, real-world equivalence |
| Failed ping | connectivity failed | **the cause** — never infer a cause from a failure alone |
| Correct routing table | the table contents | that an application works |
| Candidate repair worked in a copy | the delta in that copy | that every requirement is met |
| Scripted output | nothing about the simulator | anything at all about live behaviour |

A failed ping produces `REACHABILITY_FAILED` and the engine must form hypotheses
and run further experiments. It never concludes "missing route" from a failure.

## Conflict policy

When static and operational evidence disagree:

1. Both are preserved — the static fact is never overwritten.
2. Device and snapshot identity are confirmed first (attribution, not assumption).
3. A warning is added to the merged model naming both sides.
4. A clarifying experiment may be attempted.
5. If still unresolved, the contradiction is reported as a contradiction.

`merge_observations()` implements 1–3. It appends the simulator observation and a
`CONFLICT:` warning; it never edits `model.interfaces`.

## Evidence tiers

`operational_evidence_tier()` returns exactly one of:

| Tier | Condition |
|---|---|
| `SIMULATOR_OBSERVED` | every contributing result came from a live backend |
| `PARTIAL_OPERATIONAL_EVIDENCE` | a mix, or a live result alongside nothing |
| `SCRIPTED_NOT_OBSERVED` | scripted results were used |
| `NO_OPERATIONAL_EVIDENCE` | nothing operational ran |

## The consensus rule is untouched

The three-family extraction consensus in `trident/verification/consensus.py` is
unchanged. A simulator observation:

- does **not** count as a fourth family;
- does **not** upgrade an answer to `VERIFIED`;
- does **not** relax the agreement requirement.

`AnswerStatus` gained no new member. Operational conclusions appear in Phase 3
outcomes (`QuestionOutcome.status` stays `INCOMPLETE` with an `answer` and an
`evidence_tier`), so the two systems cannot be confused.
