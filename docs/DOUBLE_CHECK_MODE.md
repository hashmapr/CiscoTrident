# DOUBLE-CHECK MODE

A comprehensive, independent audit. The word *independent* is structural: the
auditor receives a network model, never the investigator's conclusions, so it
cannot simply echo them.

## What it does

1. Re-runs the diagnostics engine itself.
2. Checks identity consistency — every interface must belong to a known device.
3. Turns each static finding into its own check with its own verdict.
4. Runs the operational checks the backend supports.
5. Separates contradictions, unsupported checks and skipped checks.
6. Reports coverage in full.

## Verdicts

| Verdict | Meaning |
|---|---|
| `PASSED` | Checked and consistent |
| `FAILED` | Checked and defective |
| `UNRESOLVED` | Checked but no usable result |
| `UNSUPPORTED` | The backend cannot perform this check |
| `CONTRADICTED` | Two parts of the evidence disagree |
| `SKIPPED` | Not executed because of a resource limit |

## Coverage accounting

```
requirements            total checks considered
statically_checked      resolved from the model alone
operationally_checked   ran a command
simulator_tested        ran on a live simulator
passed / failed / unresolved / unsupported / contradicted / skipped
resolved_fraction       (passed+failed)/requirements
```

There is deliberately **no** `percent_verified` field. `resolved_fraction` counts
checks that produced a definitive verdict, including failed ones. A network with
four unfailable checks and one skipped check never reports 100%.

The three rules that keep this honest:

- only a live result increments `simulator_tested`;
- a check that could not run is `UNSUPPORTED` or `SKIPPED`, never `PASSED`;
- every check carries `evidence_source` and, where relevant, a limitation
  string such as `"not a live simulator observation"`.

## Example, measured

`trunk-mismatch` scenario, no simulator:

```json
{"requirements": 2, "statically_checked": 2, "operationally_checked": 0,
 "simulator_tested": 0, "passed": 1, "failed": 1, "unresolved": 0,
 "unsupported": 0, "contradicted": 0, "skipped": 0, "resolved_fraction": 1.0}
```

The injected `TRUNK_MISMATCH` is detected, and the report makes clear that
nothing was operationally verified.

## Report contents

Each check names: the requirement, device and interface, expected behaviour,
observed behaviour, evidence source, diagnostics executed, suspected root cause,
and limitations. A failed check with no established cause is reported as a failed
check — never with an invented diagnosis.

## Resource limits

`max_checks` bounds the operational phase. Checks beyond the limit are recorded as
`SKIPPED` with the reason, so the limit is visible in the report instead of
looking like full coverage.
