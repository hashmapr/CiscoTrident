# OMEGA results — gauntlet detection quality

Measured on branch `cyberpatriot/readiness`, HEAD `5c78790`, against
`main` `3ddda2c`. Every percentage below carries its numerator and denominator.
Nothing here is projected, estimated, or carried over from an earlier run: the
tables are the verbatim output of the commands in
[Reproduction commands](#reproduction-commands), run at the commit above.

---

## Baseline

The comparison point is `main` at `3ddda2c` (`docs: record the two live-test
defects in the gauntlet report`). This branch is **16 commits** ahead of it.

Two baseline facts, both taken from the branch's own commit history rather than
re-measured here:

* `6cab4ae` — `fix(diagnosis): six real defects that hid 12 of 15 faults`. On the
  baseline detector set, only 3 of the 15 live-verified faults were being
  detected.
* `3195b6d` — `feat(diagnosis): mask and native-vlan detectors, recall 73.3% on
  broken campus`, reported against the single 15-fault lab (11/15).

I did **not** re-run the benchmark against `main`, so the baseline numbers above
are cited from commit messages, not independently reproduced in this report. The
only numbers this document stands behind as observed are in the tables below.

Before this branch there were also no graduated labs at all: one
`operation-broken-campus` topology and no difficulty ramp.

---

## What changed

`git log --oneline main..HEAD` (16 commits, newest first):

```
5c78790 feat(gauntlet): six labs from easy to insane, built only from verified faults
2e081df feat(diagnosis): live simulator evidence can confirm or refute a finding
3195b6d feat(diagnosis): mask and native-vlan detectors, recall 73.3% on broken campus
6cab4ae fix(diagnosis): six real defects that hid 12 of 15 faults
48062e9 test(okcup): gate the status assertions, never the answers
e18f6c3 test(consensus): pin the three-family rules and document the engine c blocker
db32f23 docs: cyberpatriot readiness, with the failures left visible
0062b2a docs(practice): student brief, instructor key and setup procedure
3e2862f feat(practice): trident practice, a scored and non-leaking practice mode
7063916 fix(streaming): never report a corrupt file as an empty analysis
4114c92 fix(parsers): engine b now reports links, and a renamed container fails fast
64f351a feat(labgen): operation broken campus opens in packet tracer 9.0.1
661876b feat(labgen): generate .pkt labs from a spec, with faults that provably land
792d159 fix(simulator): prove the IPC listener is ours, and pin port isolation
da9c069 fix(simulator): bound the IPC read loop and never leak a started process
ca8599c fix(packaging): ship every package, not a drifted hand-written list
```

The change relevant to this report is the last three in that list: six labs built
from the 15 verified faults, the detection fixes, and the two new detectors
(`INVALID_MASK`, native-VLAN mismatch). The six labs are defined in
`trident/labgen/gauntlet.py` and measured by `trident/gauntlet_bench.py`.

---

## Measured detection results

Scoring is strict: a finding counts only when it names the device the manifest
names, fires the detector declared for that exact fault id in `EXACT_DETECTOR`
(`trident/gauntlet_bench.py:168`), and — where the fault names an interface —
names the same interface. A finding on a device with no manifest fault is a false
positive even when factually true.

```
difficulty    faults  TP  FP  FN  precision      recall
easy          4       4   0   0   4/4   (100.0%)  4/4   (100.0%)
basic         6       6   0   0   6/6   (100.0%)  6/6   (100.0%)
intermediate  8       8   0   0   8/8   (100.0%)  8/8   (100.0%)
advanced      11      10  0   1   10/10 (100.0%)  10/11 (90.9%)
expert        13      11  0   2   11/11 (100.0%)  11/13 (84.6%)
insane        15      11  2   4   11/13 (84.6%)   11/15 (73.3%)
```

| lab | faults | TP | FP | FN | precision | recall | consequence findings | seconds |
|---|---:|---:|---:|---:|---|---|---:|---:|
| easy | 4 | 4 | 0 | 0 | 4/4 (100.0%) | 4/4 (100.0%) | 0 | 5.62 |
| basic | 6 | 6 | 0 | 0 | 6/6 (100.0%) | 6/6 (100.0%) | 0 | 3.12 |
| intermediate | 8 | 8 | 0 | 0 | 8/8 (100.0%) | 8/8 (100.0%) | 0 | 4.63 |
| advanced | 11 | 10 | 0 | 1 | 10/10 (100.0%) | 10/11 (90.9%) | 0 | 3.34 |
| expert | 13 | 11 | 0 | 2 | 11/11 (100.0%) | 11/13 (84.6%) | 0 | 5.85 |
| insane | 15 | 11 | 2 | 4 | 11/13 (84.6%) | 11/15 (73.3%) | 2 | 3.62 |

**Aggregate across all six labs:** 50 true positives / 57 manifest faults
(recall **87.7%**), 50 / 52 precision denominator (precision **96.2%**), 2 false
positives, 7 false negatives.

**Timing:** median 4.13 s per lab, worst 5.85 s (expert). All six ran to
completion with no error.

### The 7 misses, named

| lab | fault | reason recorded by the harness |
|---|---|---|
| advanced | `vlan-missing-on-dist` | only unrelated kinds: `['SHUTDOWN_INTERFACE']` |
| expert | `vlan-missing-on-dist` | only unrelated kinds: `['SHUTDOWN_INTERFACE']` |
| expert | `trunk-vlan-list-missing` | only unrelated kinds: `['SHUTDOWN_INTERFACE']` |
| insane | `vlan-faculty-port-wrong` | detector fired but interface did not match |
| insane | `vlan-missing-on-dist` | only unrelated kinds: `['SHUTDOWN_INTERFACE']` |
| insane | `trunk-vlan-list-missing` | only unrelated kinds: `['SHUTDOWN_INTERFACE']` |
| insane | `addr-router-subif-wrong` | detector fired but interface did not match |

### The 2 findings counted against precision (insane only)

Both are factually true statements about the lab, not manifest faults:

* `DUPLICATE_IP` on `R1` — true (Gi0/0.20 and Gi0/0.30 both carry
  192.168.20.1) but not matched to `addr-router-subif-wrong`, because the finding
  does not name `GigabitEthernet0/0.30`.
* `WRONG_GATEWAY` on `PC-FACULTY-2` — true, and is a consequence of that same R1
  subinterface fault; `PC-FACULTY-2` has no fault in the manifest.

`Benchmark.consequence_findings` and `Benchmark.false_positives`
(`trident/gauntlet_bench.py:92` and `:112`) apply the same rule, so the two counts
coincide on this run. The consequence count is not independent corroboration of
the false-positive count.

---

## Test results

```
$ python -m pytest tests/test_gauntlet.py -q
......................................................................   [100%]
70 passed in 61.81s (0:01:01)

$ python -m pytest tests/test_consensus_three_engine.py -q
..................                                                       [100%]
18 passed in 0.47s
```

88 tests passed, 0 failed, 0 skipped, 0 errors in these two files. No test in
either file was modified, skipped or xfailed as part of producing this report.

Lab totals were also asserted directly:

```
$ python -c "from trident.labgen.gauntlet import all_labs; [print(d, len(l.faults), l.point_total()) for d,l in all_labs().items()]"
easy 4 100
basic 6 100
intermediate 8 100
advanced 11 100
expert 13 100
insane 15 100
```

---

## Known limitations

1. **Four faults account for all seven misses.** `vlan-missing-on-dist` (3 labs),
   `trunk-vlan-list-missing` (2), `vlan-faculty-port-wrong` (1) and
   `addr-router-subif-wrong` (1). Two are interface-attribution failures — the
   right detector fired on the right device but named the wrong interface — and
   two are absences on `SW-DIST` that no detector reports at all.
2. **Two end-host faults have no executable probe.** `addr-mask-admin-pc` and
   `gw-faculty-pc-wrong` nominally probe `ipconfig`, but Packet Tracer 9.0.1
   rejects `enterCommand` on `PC-PT` ("IPC call not found"). They are detected by
   the offline engine and by the generated configuration, not by a live CLI probe.
   See `docs/gauntlet/FAULT_COVERAGE_MATRIX.md`.
3. **`probes_for()` and its own docstring disagree.** The docstring at
   `trident/labgen/gauntlet.py:160` says end-host faults are excluded;
   `_PROBE_TABLE` includes them, so `probes_for("insane")` returns 15/15 probes,
   two of which cannot be run. The returned count overstates live coverage by 2.
4. **This benchmark is offline.** `run_benchmark` generates a `.pkt`, ingests the
   bytes with `use_ai=False`, and runs `diagnose()` on the resulting model. It is
   not a live simulator run; live behaviour is covered separately in
   `docs/gauntlet/LIVE_VALIDATION.md`.
5. **`consequence_findings` is not an independent measurement**, for the reason
   given above.
6. **The baseline (3/15) was not re-measured.** It is cited from commit
   `6cab4ae`, so the improvement from baseline to 50/57 aggregate is asserted on
   commit-message evidence, not on a controlled re-run.

---

## Reproduction commands

```bash
cd /Users/tanayshah/CiscoTrident && source .venv/bin/activate

# Detection metrics, all six labs
python -c "
from trident.gauntlet_bench import run_benchmark
from trident.labgen.gauntlet import DIFFICULTIES, lab_for
import json, statistics, time
rows=[];times=[]
for d in DIFFICULTIES:
    t0=time.monotonic(); b=run_benchmark(lab_for(d), verbose=False); e=time.monotonic()-t0
    times.append(e); m=b.as_dict()
    rows.append({'difficulty':d,'faults':m['faults_total'],'tp':m['true_positives'],
      'fp':m['false_positives'],'fn':m['false_negatives'],'precision':m['precision'],
      'precision_pct':m['precision_pct'],'recall':m['recall'],'recall_pct':m['recall_pct'],
      'consequences':m['consequence_findings'],'seconds':round(e,2)})
print(json.dumps({'rows':rows,'median_s':round(statistics.median(times),2),'worst_s':round(max(times),2)},indent=1))
"

# Lab shape
python -c "from trident.labgen.gauntlet import all_labs; [print(d, len(l.faults), l.point_total()) for d,l in all_labs().items()]"

# Tests
python -m pytest tests/test_gauntlet.py -q
python -m pytest tests/test_consensus_three_engine.py -q

# History this report cites
git log --oneline main..HEAD
```

---

## Verdict

**CONDITIONALLY READY.**

Evidence for:

* All six labs generate, encode and score without error; every lab totals exactly
  100 points.
* Perfect precision on five of six labs: 4/4, 6/6, 8/8, 10/10, 11/11 (100.0% each).
* Perfect recall on three of six: 4/4, 6/6, 8/8. Advanced 10/11 (90.9%), expert
  11/13 (84.6%), insane 11/15 (73.3%).
* 88 tests pass across the two suites run; no failures, skips or errors.
* Worst-case runtime 5.85 s for a 15-fault lab, which makes the whole ramp cheap
  to run in CI or on a student laptop.

Evidence against:

* 7 false negatives out of 57 (12.3% of faults missed), concentrated in four
  fault ids, two of which (`vlan-missing-on-dist`, `trunk-vlan-list-missing`) no
  detector reports at all on `SW-DIST`.
* 2 findings on `insane` are factually true but not manifest faults, so precision
  there is 11/13 (84.6%), not 100%.
* 2 of 15 faults cannot be probed on PT 9.0.1, and `probes_for()` still counts
  them, so its returned probe count overstates live coverage.

Not READY, because recall at the two hardest rungs is 11/13 and 11/15 and the
misses are concentrated rather than scattered — a student following the detector
would be told the lab is clean while two faults remain. Not NOT READY, because the
easy through intermediate rungs are 18/18 with zero false positives, every fault
is a real verified one, scoring is strict on device and interface, and the
limitations are documented rather than hidden. The ramp is fit for practice use
with the four-fault gap stated up front; it is not fit for a claim that all 15
faults are detectable.


---

## Post-audit corrections (commit `341d2fc`)

An independent verifier audited ten claims in this branch and disproved or
weakened six. Five were fixed rather than filed. Two changed numbers here:

- **Package count.** This document and `CYBERPATRIOT_READINESS.md` said "21
  packages"; the tree has **23**. The interpreter was Python 3.12.12, not 3.15.
- **Packaging test strength.** `tests/test_packaging.py` compared the source
  package set with itself and could not fail. It now builds a wheel and inspects
  it, and also evaluates setuptools' real include/exclude rules.

The live-instance claim about port 39001 had no committed evidence and was
replaced with the reproducible regression test that covers the same behaviour.

### Final measured metrics (after the false-positive fixes)

| difficulty | TP / faults | precision | wall clock |
|---|---|---|---|
| easy | 4/4 | 4/4 | 3.02 s |
| basic | 6/6 | 6/6 | 3.18 s |
| intermediate | 8/8 | 8/8 | 2.22 s |
| advanced | 10/11 | 10/10 | 2.61 s |
| expert | 11/13 | 11/11 | 2.91 s |
| insane | 11/15 | 11/13 | 2.98 s |

Aggregate: **recall 50/57 (87.7%), precision 50/52 (96.2%)**. Median 2.94 s,
worst 3.18 s.

Three false positives in the new detectors were found by the adversarial holdout
suite and fixed in `3049ab8`. They were not visible to the gauntlet, which shares
the same fault vocabulary as the generator: an independent corpus caught what the
self-consistent one could not.

### Verdict

**CONDITIONALLY READY.** Recall on the three easiest rungs is perfect (18/18)
and precision is perfect on five of six. Recall falls to 11/15 on the hardest
rung, where four faults need detectors that do not exist yet
(`vlan-missing-on-dist` and `trunk-vlan-list-missing` on a distribution switch,
plus two interface-attribution gaps). Two faults have no executable probe
because PT 9.0.1 rejects `enterCommand` on `PC-PT`.
