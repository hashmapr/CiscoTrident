# Engine D operational evidence on Packet Tracer 9.0.1

Engine D's static analysis can prove that a requirement holds from the uploaded
configuration. That proof is `Status.DERIVED`: nothing observed the packet move.
`Status.VERIFIED` additionally requires a live simulator observation that agrees
with the prediction. This document records what this build can genuinely observe,
what it cannot, and exactly how the live half is correlated.

The implementation is `trident/engined/observations.py`; the tests are
`tests/test_engined_observations.py`. The live session, collectors and evidence
types are reused from `trident/deepcore/live_evidence.py`; this module does not
re-implement them.

## What is genuinely observable

Packet Tracer 9.0.1 answers the following bounded, read-only commands on routers
and switches. They were exercised live in
`docs/gauntlet/VERIFIED_GROUND_TRUTH.md` (read-only sweep) and
`docs/gauntlet/LIVE_VALIDATION.md` (VLAN and trunk collectors on `SW-DIST` and
`SW-ACCESS`):

| Command | What it establishes | Collector |
| --- | --- | --- |
| `show ip interface brief` | Interface line/protocol state, address, method | `collect_ip_interface_brief` |
| `show running-config` | Intended configuration (file-state, not runtime state) | `collect_running_config` |
| `show vlan brief` | VLAN database and access ports | `collect_vlan_brief` |
| `show interfaces trunk` | Trunk mode, encapsulation, allowed/active VLANs | `collect_interfaces_trunk` |
| `show ip route` | Installed routes: default, connected, static, dynamic | `collect_ip_route` |
| `show interfaces status` | Port status, VLAN, duplex, speed | `collect_interfaces_status` |

Every command is read-only by `trident.simulator.backends.is_read_only`; a
mutating command is refused before it reaches the simulator. Each result keeps
its raw text and `Provenance` (backend, simulator version, session id, source
hash, working-copy hash, execution time) so a parse can be checked against its
source.

Parsed facts are read from those outputs with the Phase 2 parsers
(`trident/evidence/parsers.py`): `parse_ip_route` and
`parse_ip_interface_brief`. Each `RouteObservation` and `InterfaceObservation`
carries `source` (where the raw text came from) and
`derivation=PARSER_DERIVED` (the value is a structured reading of that text).

## What is not observable

### End hosts have no CLI

`PC-PT` and `Server-PT` reject `enterCommand` entirely on 9.0.1. The exact error,
from `docs/gauntlet/VERIFIED_GROUND_TRUTH.md`:

```
IPC error from enterCommand: ['Pc', 'IPC call "enterCommand" not found']
```

Twenty-five candidate read-only accessors were probed on a live `Pc` object
(`getIp`, `getIPAddress`, `getSubnetMask`, `getDefaultGateway`, `getIpConfig`,
`getMacAddress`, …); only `getName` and `getPortCount` exist. Host addressing is
therefore not available as CLI output, and this module never attempts it. Device
names passed to `collect` that are end hosts fail loudly: the command error is
recorded per device and command, and no fact is produced.

### Behavioural ping is not available

`PduExecutor.send` returns `DeliveryStatus.EXECUTION_ERROR` with zero frames on
this build, for the probes recorded in `docs/gauntlet/VERIFIED_GROUND_TRUTH.md`
and `docs/gauntlet/ERROR_ANALYSIS.md`:

```
DeliveryStatus.EXECUTION_ERROR, frames_seen=0
```

There is one other supported path in the codebase: `LiveBackend.ping`, which
issues the device CLI `ping` and parses `Success rate is N percent`
(`trident/simulator/backends.py:860`). That path is itself inconclusive when the
summary is absent — Packet Tracer's CLI ping is interactive and the completion
line is not guaranteed. This module therefore claims **no behavioural
reachability observation**. It never fabricates a ping result and never treats a
missing summary as a failure. Corroboration is limited to device-reported
runtime state (`show` output).

This is a known ceiling on 9.0.1, not a bug awaiting a patch.

### Other limits

- Only one Packet Tracer session may be open at a time. `collect` opens exactly
  one, as a context manager, and closes it in `finally`; the source `.pkt` is
  hashed before and after.
- Interface spelling can differ across Packet Tracer, the parsers and the model
  (`Gi0/1`, `Gig0/1`, `GigabitEthernet0/1`). Matching is the caller's job; this
  module reports the spelling the simulator printed, unmodified.
- `show interfaces status` has no `EvidenceKind` in the ingestion layer, so it
  produces findings but no `CliRecord`. It is still live evidence.
- A `SCRIPTED` backend produces `EvidenceSource.SCRIPTED_BACKEND`, never
  `LIVE_SIMULATOR`. It cannot make runtime state available.

## How predictions are correlated

`prediction_agrees(fact, predicted, observed)` is the only correlation rule:

| `predicted` | `observed` | `Conclusion` | Meaning |
| --- | --- | --- | --- |
| `True` | `True` | `VERIFIED` | Live output agrees with the prediction |
| `True` | `False` | `CONTRADICTED` | Live output positively disagrees |
| `False` | `True` | `CONTRADICTED` | Live output positively disagrees |
| `False` | `False` | `VERIFIED` | Live output agrees with the prediction |
| either | `None` | `INCONCLUSIVE` | No live observation exists to correlate |

The mapping is deliberately symmetric: `False/False` is agreement, not a
failure. A caller must pass `observed=None` when there is no live runtime
observation. `None` is `INCONCLUSIVE`; it is never `DERIVED` here and never
`VERIFIED`.

Engine D's own `_apply_live` in `trident/engined/verify.py` applies the same
rule to a `bool | None`: no observation leaves the verdict `DERIVED`; agreement
promotes it to `VERIFIED`; disagreement produces `CONTRADICTED`.

**Static evidence never yields `VERIFIED`.** A fact read from the uploaded file
or from `show running-config` is file-state. It can support `DERIVED`; it cannot
confirm that the network is forwarding anything. Only a completed live runtime
observation, agreeing with the prediction, produces `VERIFIED`.

## File-state versus runtime-state

`runtime_state_available(observation_set)` is `True` only when at least one live
command completed:

- file-state: the uploaded `.pkt` contents and `show running-config` — what the
  device is configured to do;
- runtime-state: `show ip interface brief`, `show ip route`, `show vlan brief`,
  `show interfaces trunk`, `show interfaces status` — what the device reports it
  is doing now.

A failed command, a timeout, a scripted backend, an empty set, or a collection
error all return `False`. That means "no live half exists", not "unreachable".

## The explicit UNSUPPORTED path

Packet Tracer capabilities that this build cannot answer are named in
`PT_901_LIMITATIONS`, with the evidence for the restriction:

- `end_host_cli` — the exact `enterCommand` error above;
- `behavioural_ping` — the `EXECUTION_ERROR` above.

`support_status(capability)` returns `SUPPORTED` only for the six observable
commands, `UNSUPPORTED` for those two documented limitations, and `UNKNOWN` for
anything else. A command that did not complete is recorded as
`SupportStatus.UNSUPPORTED` for that device and command via
`LiveObservationSet.command_support`, with the error preserved in
`device_errors()`. Nothing is promoted to a fact.

## Isolation and bounds

- The source `.pkt` is hashed on entry and on exit with
  `trident.simulator.isolation.sha256_file`. `LiveObservationSet.source_intact`
  is `True` only when both hashes exist and are equal; a change is a hard
  isolation failure and is recorded in `notes`.
- The simulator only ever opens its own disposable working copy.
- `collect` is bounded by `budget_seconds`, a per-command timeout, and a command
  count (six commands per device). `EvidenceBudget` enforces the ceilings and
  poisons a session after a timeout, because the state after a timeout is
  unknown.

## Test results

Mocked suite (no Packet Tracer starts):

```
source ~/CiscoTrident/.venv/bin/activate
python -m pytest tests/test_engined_observations.py -q -m "not live_simulator"

...............                                                          [100%]
15 passed, 1 deselected
```

Lint:

```
ruff check trident/engined/observations.py tests/test_engined_observations.py
All checks passed!
```

The mocked suite covers:

| Property | Test |
| --- | --- |
| `show ip route` parses a default, a /30, and directly connected routes | `test_parse_show_ip_route_structures_default_thirty_and_connected` |
| `show ip interface brief` parses up/down/administratively down | `test_parse_show_ip_interface_brief_states` |
| Empty or unparsable output produces no rows | `test_empty_output_parses_to_nothing_rather_than_a_guess` |
| Collection assembles live evidence and parsed facts | `test_collect_builds_a_live_observation_set` |
| A failed command is UNSUPPORTED with its error, never a guess | `test_failed_command_is_unsupported_and_never_guessed` |
| A scripted backend is not runtime state | `test_a_scripted_backend_is_not_runtime_state` |
| The source hash is unchanged | `test_source_hash_is_unchanged` |
| `prediction_agrees` truth table, including `None` | `test_prediction_agrees_truth_table` |
| Static-only evidence never yields VERIFIED | `test_static_evidence_never_yields_verified` |
| PT 9.0.1 limitations carry their exact evidence | `test_pt_901_limitations_are_named_with_evidence` |

The single live test is opt-in twice and is **not run** in this validation
window (another session may hold Packet Tracer, and only one session may be
open):

```sh
TRIDENT_ALLOW_LIVE_SIMULATOR=1 TRIDENT_RUN_ENGINE_D_LIVE=1 \
  python -m pytest tests/test_engined_observations.py -q -m live_simulator
```

It additionally skips when `test-labs/broken_campus/broken_campus_student.pkt`
is absent, Packet Tracer is not installed, or no registered ExApp is configured.
A skip is not a pass.

## What is proven versus mocked in this record

Proven by live runs elsewhere, reused here by construction:

- PT 9.0.1 answers the six read-only `show` commands on routers and switches;
- `show vlan brief` and `show interfaces trunk` returned real live output on
  `SW-DIST` and `SW-ACCESS`;
- the source `.pkt` was byte-for-byte unchanged after those sessions;
- end hosts reject `enterCommand` with the exact error above;
- `PduExecutor.send` returns `EXECUTION_ERROR` with zero frames.

Proven by the mocked suite in this change:

- route and interface parsing, including default, /30 and directly connected
  routes;
- source labelling of every fact, and `PARSER_DERIVED` derivation;
- failure handling: `UNSUPPORTED` plus the exact error, no fact produced;
- source-hash preservation and cleanup;
- the full `prediction_agrees` truth table;
- `runtime_state_available` refusing scripted, failed and empty evidence;
- the explicit UNSUPPORTED capability path.

Not proven in this record:

- a live `collect` run through this new module (the live test was not run);
- behavioural reachability of any kind (unavailable on this build);
- end-host state as CLI output (unavailable on this build).
