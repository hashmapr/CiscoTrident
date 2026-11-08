# INVESTIGATION POLICY

The deterministic rules that decide what TRIDENT does, in the order it decides
them. Every rule is enforced in code and covered by a test; nothing here is a
description of intended behaviour that was not implemented.

## Modes

| Mode | Behaviour |
|---|---|
| `SMART` (default) | Static evidence first; escalate only testable gaps; never re-test a verified answer |
| `DOUBLE_CHECK` | Re-test everything, including verified answers; comprehensive audit |

## Processing order

1. Parse and resolve with the existing pipeline.
2. Keep every already-verified answer as-is. In `SMART`, it is never re-tested.
3. Collect the unresolved questions and their missing evidence.
4. Classify testability.
5. Form hypotheses from the diagnostics engine (never invented).
6. Select the experiment with the best discriminating power.
7. Execute it in the isolated session.
8. Apply the result: support confirms, contradiction eliminates.
9. Repeat only while an unrun, useful experiment remains.
10. Stop with an explicit reason.

## Testability rules

`classify_testability()` is conservative by design.

- Observable markers: reach, connectivity, ping, route/routing, neighbour, trunk,
  VLAN, interface state, ACL/permit/deny, gateway, DHCP, DNS, latency.
- Non-observable markers: requirement, instruction, document, PDF, policy,
  design intent, rubric, grading.
- Anything that matches neither is treated as **not observable**.

Consequence: a question about which requirement the lab document asks for never
starts a simulator, because sending packets cannot answer it.

## Escalation

| Situation | Decision |
|---|---|
| Already `VERIFIED` / `VERIFIED_DERIVED`, `SMART` mode | do not escalate |
| Already verified, `DOUBLE_CHECK` mode | escalate |
| Runtime unavailable | do not escalate; report the real reason |
| Gap is documentation or intent | do not escalate |
| Fix would need a configuration change | do not escalate (that is a what-if) |
| `CONFLICT` with observable evidence | escalate |
| `INCOMPLETE` with observable evidence | escalate |
| Budget exhausted | do not escalate |

`expected_information_gain()` is a scheduling weight used to order candidates.
It is never shown to a user as a probability or a confidence percentage.

## Hypothesis handling

A hypothesis carries supporting evidence, contradicting evidence, missing
evidence, its current status and the experiments tried.

- **Support** with no contradiction → `CONFIRMED_DEFECT`.
- **Any contradiction** → `SUSPECTED`; both sides are kept.
- **Refutation** → `RULED_OUT` and never selected again.
- Confidence is `HIGH`/`MEDIUM`/`LOW`, sourced from the diagnostics engine.
  No percentage is fabricated anywhere.

Crucially, a hypothesis is only reported as operationally confirmed when an
**executed experiment** produced the support (`operationally_supported`). A
static suspicion that no experiment could check is reported as a static suspect
with `answer=None`, not as an observation.

## Experiment selection

Preference order:

1. read-only over mutating (mutations require an explicitly capable backend);
2. an experiment not yet run;
3. the command that discriminates the most hypotheses;
4. lowest cost;
5. stable tie-break by experiment id.

If nothing useful remains, `select_experiment()` returns `None`. That is a normal
outcome and the signal to stop, not an error.

## Shared evidence

`EvidenceLedger` keys results by `(session_id, device, operation)`. Five questions
that need `show ip route` on R1 cause exactly **one** execution per session. A new
session invalidates all keys, so a value can never cross a snapshot boundary.

## Stopping conditions

| Reason | Meaning |
|---|---|
| `SUFFICIENT_EVIDENCE` | A cause is operationally confirmed and nothing plausible remains |
| `NO_USEFUL_EXPERIMENT` | No unrun experiment can reduce uncertainty |
| `BUDGET_EXHAUSTED` | Per-question or total experiment limit reached |
| `RUNTIME_UNAVAILABLE` | The simulator cannot be used; reason attached |
| `NOT_OBSERVABLE` | The gap is documentation or intent |
| `ALREADY_VERIFIED` | The answer was already established statically |
| `SIMULATOR_FAILED` | The session failed mid-experiment |

An unresolved result is always returned with its reason. The engine never guesses
to avoid returning an abstention.
