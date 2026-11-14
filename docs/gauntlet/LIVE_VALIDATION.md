# Live validation: simulator observations to diagnostic hypotheses

This document records what the live-evidence loop actually proves, and what it
does not. It covers the mocked integration suite, the single opt-in live run, the
exact commands used, the Packet Tracer version, and the remaining limitations.

Two layers are described:

* `trident/deepcore/live_evidence.py` — obtains bounded, read-only evidence from
  a real Packet Tracer session and compares it with a prediction.
* `trident/deepcore/evidence_bridge.py` — feeds that evidence into the existing
  diagnostic engine: it assembles an `EvidenceBundle`, promotes or downgrades
  hypotheses, and produces a `LiveDiagnosisReport`.

## Scope

The bridge closes the loop between a static diagnosis and a real simulator:

1. run bounded, read-only `show` commands on the devices in a loaded lab;
2. keep the raw simulator text and backend provenance;
3. add only live records to an `EvidenceBundle` the existing detectors read;
4. compare predictions with live output:
   `VERIFIED` / `DERIVED` / `CONTRADICTED` / `INCONCLUSIVE`;
5. promote an `INSUFFICIENT_EVIDENCE` hypothesis only when a successful live
   command supports it;
6. downgrade a hypothesis positively contradicted by live output;
7. report every unsupported check with its reason;
8. prove the source `.pkt` was not modified.

It does **not** mutate devices, does not use PC-PT CLI (PT 9.0.1 rejects
`enterCommand` on it), and never treats a scripted backend or static analysis as
live.

## Status vocabulary

`trident.diagnostics.types.HypothesisStatus` has no `CONTRADICTED` member. The
bridge therefore maps a live `CONTRADICTED` comparison to
`HypothesisStatus.RULED_OUT`, the existing vocabulary's refuted state, and names
the live conclusion explicitly in the report:

```json
{
  "from_status": "CONFIRMED_DEFECT",
  "to_status": "RULED_OUT",
  "live_conclusion": "CONTRADICTED",
  "reason": "a live simulator command positively contradicted the hypothesis"
}
```

A promoted hypothesis moves from `INSUFFICIENT_EVIDENCE` (or `SUSPECTED` with no
contradiction) to `CONFIRMED_DEFECT` and gains an observation whose
`source == "LIVE_SIMULATOR"`. Static `MODEL` evidence alone never promotes.

## Commands

Mocked integration suite (the default; starts no Packet Tracer):

```sh
source .venv/bin/activate
python -m pytest tests/test_live_diagnosis_integration.py -q -m "not live_simulator"
```

Live integration test (opt-in twice; a skip is never a pass):

```sh
source .venv/bin/activate
TRIDENT_ALLOW_LIVE_SIMULATOR=1 TRIDENT_RUN_LIVE_DIAGNOSIS=1 \
  python -m pytest tests/test_live_diagnosis_integration.py -q -m live_simulator
```

The live test also skips when
`test-labs/broken_campus/broken_campus_student.pkt` is absent, when Packet
Tracer is not installed, or when no registered ExApp is configured. Credentials
live in `~/.config/trident/credentials.env`
(`TRIDENT_PT_APP_ID` / `TRIDENT_PT_SECRET`).

Lint:

```sh
source .venv/bin/activate
ruff check trident/deepcore/evidence_bridge.py tests/test_live_diagnosis_integration.py
```

## Results

### Mocked integration suite

```
...........                                                              [100%]
11 passed, 1 deselected
```

`ruff check` on the bridge and the test file: **All checks passed.**

The mocked suite proves:

| Property | Test |
| --- | --- |
| Bundle assembled from live collectors, six commands per device | `test_build_runtime_bundle_assembles_live_records` |
| Scripted backend contributes no records | `test_build_runtime_bundle_ignores_a_scripted_backend` |
| Live `DERIVED` support promotes `INSUFFICIENT_EVIDENCE` | `test_live_support_promotes_insufficient_evidence` |
| Live `CONTRADICTED` downgrades `CONFIRMED_DEFECT` to `RULED_OUT` | `test_live_contradiction_downgrades_a_confirmed_defect` |
| A hand-built `VERIFIED` comparison from a scripted backend cannot promote | `test_a_verified_comparison_is_not_promotion_without_live_evidence` |
| `MODEL` evidence alone cannot promote | `test_static_model_evidence_alone_cannot_promote` |
| A failed command is recorded as unsupported with its reason | `test_unsupported_check_is_recorded_with_its_reason` |
| `as_dict()` strips instructor/answer-key keys | `test_report_as_dict_never_contains_instructor_manifests` |
| An unmatched hypothesis is returned unchanged | `test_an_unmatched_hypothesis_is_left_untouched` |
| `Gi0/1`, `Gig0/1`, and `GigabitEthernet0/1` can name the same port | `test_interface_spelling_differences_do_not_defeat_matching` |
| An explicit `LiveCheck` pins the hypothesis kind | `test_live_check_can_pin_the_hypothesis_kind` |

### Live run

Packet Tracer **9.0.1** (`/Volumes/AI-Models/Cisco Packet Tracer 9.0.1/`), with
a registered ExApp, opened
`test-labs/broken_campus/broken_campus_student.pkt` once.

The run reached the probes and produced three real live observations:

* `show vlan brief` on `SW-DIST` → `LIVE_SIMULATOR`;
* `show interfaces trunk` on `SW-DIST` → `LIVE_SIMULATOR`;
* `show interfaces trunk` on `SW-ACCESS` → `LIVE_SIMULATOR`.

The following assertions **passed before the failure**:

* every probe was `is_live is True`, `source == LIVE_SIMULATOR`, with non-empty
  raw text;
* VLAN 10 is absent on `SW-DIST` → comparison `CONTRADICTED`, carrying a
  `LIVE_SIMULATOR` observation;
* VLAN 30 is absent from the measured `SW-DIST` trunk allowed list →
  comparison `CONTRADICTED`, carrying a `LIVE_SIMULATOR` observation;
* VLAN 30 is present in the measured `SW-ACCESS` trunk allowed list →
  comparison `DERIVED`, carrying a `LIVE_SIMULATOR` observation.

The test then **failed at the annotation assertion**:

```
assert by_device["SW-DIST"].status is HypothesisStatus.RULED_OUT
E  AssertionError: assert <HypothesisStatus.CONFIRMED_DEFECT> is <HypothesisStatus.RULED_OUT>
```

The hypothesis remained `CONFIRMED_DEFECT`. The live comparisons themselves were
conclusive; the failure is in linking the live trunk row to the model's
hypothesis interface (`Gi0/1`) under auto-inference for that run. This is an
integration limitation, not a simulator result.

Because the run stopped there, the final source-hash assertion was **not
reached** in this run. The source-preservation property is proven separately by
the earlier `tests/test_live_evidence_live.py` run against the same lab
(`942b5e02…a498ccd7` before and after) and by the session-level hash checks in
the mocked suite.

After the run, the live test was hardened to pin the link explicitly with
`LiveCheck(..., hypothesis_kind=TRUNK_MISMATCH, device=..., interface=...)`,
which is the API's intended path when a caller already knows the link. The
auto-inference path remains covered by the mocked tests. **The hardened live
test was not rerun**, because the task allowed one live launch and that launch
was already used. No live pass is claimed.

## What is genuinely proven live

From this run:

* Packet Tracer 9.0.1 answered `show vlan brief` and `show interfaces trunk` on
  the two switches in the generated student lab;
* the live `show vlan brief` output on `SW-DIST` has no VLAN 10;
* the live `show interfaces trunk` output on `SW-DIST` omits VLAN 30 from the
  measured trunk's allowed list;
* the live `show interfaces trunk` output on `SW-ACCESS` includes VLAN 30;
* the module classified those facts as `CONTRADICTED` / `DERIVED` and attached
  `LIVE_SIMULATOR` observations.

From the earlier module validation (same simulator build, same lab):

* `show vlan brief` on `SW-DIST` returned 8 VLANs (1, 20, 30, 99, 1002–1005)
  and no VLAN 10;
* the source `.pkt` was byte-for-byte identical after the session
  (`942b5e029ad7eab56e7980d0c3c358d9851e2819f30d5efeefed7e64a498ccd7`);
* the backend closed and the disposable working directory was cleaned.

## What remains mocked or static

* The **annotation mechanism** (promotion, downgrade, unmatched hypotheses,
  static-data prohibition, unsupported-check reporting, report hygiene) is
  proven by the 11 mocked tests, not by the failed live run.
* Four of the six collectors (`show ip interface brief`, `show running-config`,
  `show ip route`, `show interfaces status`) were exercised only against
  deterministic fake output in the integration suite. The VLAN and trunk
  collectors were exercised live on both switches.
* Command failure, timeout, budget exhaustion, scripted-backend behaviour,
  cleanup on exception, and static-vs-live labelling are unit-tested only.
* `show interfaces status` has no `EvidenceKind` in `trident/evidence/types.py`,
  so no `CliRecord` is produced for it. Its parser is covered by mocked tests
  only.
* PC-PT devices are not used: PT 9.0.1 rejects `enterCommand` on them.

## Remaining limitations

1. **Interface naming across the boundary.** Packet Tracer, the parsers, and
   the model may spell the same port `Gi0/1`, `Gig0/1`, or
   `GigabitEthernet0/1`. The bridge normalises common aliases and matches a
   shared slot/port suffix, and `LiveCheck` can pin the link explicitly. The
   live run showed that auto-inference still failed to link one row in that
   environment; pinning is the reliable path until the cause is reproduced.
2. **One live launch per validation window.** The failure above cannot be
   re-probed without another simulator launch. The hardened test is therefore
   not live-verified in this record.
3. **Simulator timeout.** `LiveBackend.run_cli(device, command, timeout)`
   accepts a timeout but does not pass it to `PtmpClient.enter_command`, which
   hard-codes 60 s. `LiveEvidenceSession` enforces its own wall-clock bound and
   poisons the session after a timeout. The simulator layer should honour the
   timeout it advertises (see the patch below).

Proposed simulator patch (not applied — `trident/simulator/**` is owned by the
lead):

```diff
--- a/trident/simulator/ptmp.py
+++ b/trident/simulator/ptmp.py
@@ -328,7 +328,13 @@ class PtmpClient:
-    def enter_command(self, device_name: str, command: str, mode: str = "enable") -> str:
+    def enter_command(
+        self,
+        device_name: str,
+        command: str,
+        mode: str = "enable",
+        timeout: float = 60.0,
+    ) -> str:
@@
-            timeout=60.0,
+            timeout=timeout,
```

```diff
--- a/trident/simulator/backends.py
+++ b/trident/simulator/backends.py
@@ -? @@ class LiveBackend:
-            text = self.client.enter_command(device, command)
+            text = self.client.enter_command(device, command, timeout=timeout)
```

## Design invariants

- `EvidenceSource.LIVE_SIMULATOR` is set only when `ok`, `observed`, and
  `provenance.backend is BackendKind.SIMULATOR_LIVE` are all true.
- A scripted backend is `SCRIPTED_BACKEND` and can never produce `VERIFIED`.
- A failed, timed-out, refused, or non-observed command is `UNAVAILABLE` and
  compares as `INCONCLUSIVE` with the error attached.
- `VERIFIED` means the live output states the fact directly; `DERIVED` means a
  documented rule (set membership, status combination) applied to live output;
  `CONTRADICTED` requires positive live evidence of the negation.
- `build_runtime_bundle` adds only records whose evidence `is_live`.
- `INSUFFICIENT_EVIDENCE` → `CONFIRMED_DEFECT` requires live support; static
  `MODEL` evidence is never enough.
- A live contradiction maps to `RULED_OUT` and the report names
  `live_conclusion: "CONTRADICTED"`.
- `LiveDiagnosisReport.as_dict()` strips any key containing `manifest`,
  `instructor`, or `answer_key`.
- The source is hashed in `__enter__` and again in `close()`, and `close()` runs
  from `__exit__` even when the body raises.
- Every command is read-only, bounded per command, and bounded by an overall
  budget and a command count.
