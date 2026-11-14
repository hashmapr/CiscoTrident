# Claim audit — `cyberpatriot/readiness`

Auditor: Agent F (independent verifier)
Date: 2026-11-14
Branch: `cyberpatriot/readiness`
HEAD audited: `5c78790 feat(gauntlet): six labs from easy to insane, built only from verified faults`

Scope: the ten claims assigned to this audit. Source was read, not modified. Tests were
run in the checked-out environment (Python 3.12.12). No Packet Tracer process was started.

Provenance note: `docs/gauntlet/FAULT_COVERAGE_MATRIX.md` and `docs/gauntlet/OMEGA_RESULTS.md`
are present in the working tree but are **untracked** (`git status` shows `??`). They appeared
during this audit and are not part of any commit on this branch. They are included in the
Claim 10 sweep because they live under `docs/gauntlet/`, and are marked as untracked there.

---

## Verdict table

| # | Claim | Command run | Actual result | Supported? | Note |
|---|---|---|---|---|---|
| 1 | The IPC read loop is bounded (deadline + frame cap) | `python -m pytest tests/simulator/test_ipc_bounds.py -q` | `8 passed, 1 warning in 1.55s`; source has `deadline = time.monotonic() + timeout` and `remaining <= 0` raise, plus `skipped > self.MAX_SKIPPED_FRAMES` raise (`MAX_SKIPPED_FRAMES = 5000`) at `trident/simulator/ptmp.py:282-315` | **YES** | Both bounds are real and independently enforced. |
| 2 | No foreign Packet Tracer attachment | `python -m pytest tests/simulator/test_ipc_concurrency.py -q` | `6 passed, 1 warning in 0.22s`; `ProcessSupervisor.start` sets `was_refused = _connection_refused(...)` **before** `Popen`, then fails with `BackendUnavailable` if `not was_refused` (`trident/simulator/backends.py:419,437-444`) | **PARTIAL** | The pre-spawn refusal check exists as claimed. The stronger "no foreign attachment" is **not fully guaranteed**: there is no post-spawn re-check, despite the inline comment promising one. See D3. |
| 3 | Ten packages were missing from the wheel | packaging one-liner (below) + `python -m pytest tests/test_packaging.py -q` | `packages config: {'find': {'include': ['trident*']}}`; `real packages: 23`; `14 passed, 1 warning in 0.32s` | **YES** (historical fact and current config) | At fix commit `ca8599c` there were 22 packages and the old hand-written list had 12 → exactly 10 missing. Current config omits nothing: all 23 packages match `trident*`. But the regression test is tautological (D1), and the readiness doc says "21 packages" (D2). |
| 4 | Engine C is genuinely unavailable | `python -c "from trident.config import settings; from trident.parsers.pt_convert import EngineCAdapter; print(EngineCAdapter(settings).probe())"` + `ls .../src/lib/` | `(False, 'pt-convert checkout missing src/lib/packet-crypto.ts')`; `src/lib/` is `total 0` (empty); `git rev-parse` → `fatal: not a git repository (or any of the parent directories): .git`; `packet-crypto.ts` and `xml-simplifier.ts` both `No such file or directory` | **YES** | Missing implementation modules confirmed. Nuance on the "no history" and license wording in D5. |
| 5 | Detection is 11/15 on the broken campus lab | `python -m trident.gauntlet_bench 2>&1 \| tail -25` | `recall    11/15 = 73.3%`; `precision 11/13 = 84.6%`; `false positives: 2` (implies TP=11, FP=2, FN=4) | **YES** | Exact match to the claim. |
| 6 | Six gauntlet labs each total exactly 100 points | `python -c "from trident.labgen.gauntlet import all_labs; ..."` | `easy 4 100 OK` / `basic 6 100 OK` / `intermediate 8 100 OK` / `advanced 11 100 OK` / `expert 13 100 OK` / `insane 15 100 OK` | **YES** | Six labs, point_total 100 each, `validate()` returns `OK`. |
| 7 | Answer keys never reach student output | source read + `python -m pytest tests/test_practice.py -q -k "leak or hide"` | `2 passed, 27 deselected, 1 warning in 0.46s`; `as_dict()` pops `expected`/`actual` when `not include_key and not line.correct`; `render_markdown()` prints only `evidence_hint` for missed lines | **YES** | Confirmed in both code paths. |
| 8 | Live evidence can confirm/refute a finding | `python -m pytest tests/test_live_diagnosis_integration.py -q -m "not live_simulator"` | `11 passed, 1 deselected, 1 warning in 0.53s` — includes `test_live_support_promotes_insufficient_evidence` and `test_live_contradiction_downgrades_a_confirmed_defect` | **YES** | Mocked suite only; no Packet Tracer started. Real live path remains unverified offline. |
| 9 | The okcup failures are gating, not weakening | `python -m pytest tests/test_okcup_regressions.py -q` | `9 passed, 10 skipped, 1 warning in 23.87s`; ungated `test_every_audited_answer_is_correct_at_any_engine_count` asserts all audited values; the 3 `@requires_three_engines` tests account for the 10 skips | **PARTIAL** | An ungated value assertion exists, and it covers every value. But "only status assertions are gated" is literally false: the three skipped tests also assert values. See D4. |
| 10 | Docs contain no unsupported success claims | `grep -rn "100%\|fully\|complete\|verified\|READY" docs/gauntlet/ docs/CYBERPATRIOT_READINESS.md` | 20 matching lines; no bare percentages (every `%` has a numerator/denominator); most "verified" claims carry a test/file path | **PARTIAL** | Two numeric/evidence problems (D2, D7), plus a license claim with no artifact (D5). Details below. |

---

## Command evidence

### Claim 3 — packaging

```
$ python -c "... tomllib ..."
packages config: {'find': {'include': ['trident*']}}
real packages: 23

$ python -m pytest tests/test_packaging.py -q
14 passed, 1 warning in 0.32s
```

Historical check against the fix commit:

```
$ git ls-tree -r --name-only ca8599c | grep "__init__.py" | grep "^trident/" | ... | wc -l
22                      # 22 packages at ca8599c; old 12-entry list -> 10 missing
```

Current config coverage check:

```
total 23
not matching trident*: []      # every real package matches the discovery pattern
```

### Claim 4 — Engine C

```
$ python -c "... EngineCAdapter(settings).probe()"
(False, 'pt-convert checkout missing src/lib/packet-crypto.ts')

$ ls -la "$(settings.pt_convert_dir)/src/lib/" | head -3
total 0
drwxr-xr-x@ 2 tanayshah  staff   64 Nov 11 03:42 .
drwxr-xr-x@ 7 tanayshah  staff  224 Nov  7 10:03 ..
```

### Claim 5 — gauntlet bench

```
recall    11/15 = 73.3%
precision 11/13 = 84.6%
false positives: 2
```

### Claim 6 — lab totals

```
easy 4 100 OK
basic 6 100 OK
intermediate 8 100 OK
advanced 11 100 OK
expert 13 100 OK
insane 15 100 OK
```

### Claim 9 — okcup gating

```
9 passed, 10 skipped, 1 warning in 23.87s
```

The 10 skips are exactly the three `@requires_three_engines` functions:
`test_identity_questions` (3 params), `test_address_family_is_distinguished`
(6 params), `test_gateway_and_vlan_answers` (1). The ungated
`test_every_audited_answer_is_correct_at_any_engine_count` passed with two
engines available and asserts the same 12 values.

### Claim 10 — docs sweep

`grep -rn "100%\|fully\|complete\|verified\|READY" docs/gauntlet/ docs/CYBERPATRIOT_READINESS.md | head -40`
returned 20 lines. Representative output:

```
docs/gauntlet/ENGINE_C_CONSENSUS_STATUS.md:33:Three independent reasons, all verified in this environment:
docs/gauntlet/ENGINE_C_CONSENSUS_STATUS.md:97:### Properties verified by `tests/test_consensus_three_engine.py`
docs/gauntlet/FAULT_COVERAGE_MATRIX.md:3:Every fault below is drawn from the **15 faults independently verified observable
docs/gauntlet/FAULT_COVERAGE_MATRIX.md:4:in Packet Tracer 9.0.1** (`tests/test_labgen_live.py`).
docs/gauntlet/LIVE_VALIDATION.md:89:...........                                                              [100%]
docs/CYBERPATRIOT_READINESS.md:5:**Verdict: CONDITIONALLY READY.**
docs/CYBERPATRIOT_READINESS.md:6:Tracer 9.0.1, and every one of its 15 faults was verified observable in the
docs/CYBERPATRIOT_READINESS.md:43:Fixed with `packages.find`. Verified by building a wheel and importing all 21
docs/CYBERPATRIOT_READINESS.md:63:Verified against the live instance holding port 39001 on this machine.
docs/CYBERPATRIOT_READINESS.md:168:would be the key. Verified in both directions: no fault's actual value appears
```

Percentage audit: `grep "%" ... | grep -v "/"` returned **no bare percentages**.
Every reported percentage has its fraction on the same line (`11/15 (73.3%)`,
`50/57` → `87.7%`, `7/57` → `12.3%`, etc.). `LIVE_VALIDATION.md:89` is pytest's
progress output (`[100%]`), not a success claim.

"Verified" claims and their evidence paths:

| Claim | Evidence path | Offline status |
|---|---|---|
| Properties verified by `tests/test_consensus_three_engine.py` | named test file/table | Path present; not run in this audit |
| 15 faults verified observable in PT 9.0.1 | `tests/test_labgen_live.py` | Path present; **live**, cannot run offline |
| Answer-key separation verified both directions | `STUDENT_BRIEF.md` + `ANSWER_KEY.json` | Checked offline: 15 faults, `point_total: 100`, **0** actual values in the brief |
| "importing all 21 packages" | none | **No artifact; wrong count (23).** D2 |
| "Verified against the live instance holding port 39001" | none | **No evidence path; live.** D7 |
| Engine C "three independent reasons, all verified in this environment" | inline commands only | Reasons 1–2 reproduce; reason 3 has no license artifact. D5 |

---

## Discrepancies found

**D1 — `tests/test_packaging.py` cannot catch a wheel omission.**
`_configured_packages()` asserts `include == ["trident*"]` and then returns
`_real_packages()` itself. Therefore
`test_every_source_package_is_configured_for_packaging` computes
`missing = real - real`, which is always empty, and
`test_previously_omitted_packages_are_covered` only checks membership in the
same source set. No test in the file builds or inspects a wheel. The
"pinned so it cannot regress" claim is therefore weaker than stated: the test
pins the *config string*, not the *built artifact*. (The current config is
still correct; this is a test-strength discrepancy, not a packaging defect.)

**D2 — "all 21 packages" is the wrong number.**
`docs/CYBERPATRIOT_READINESS.md:43` says "importing all 21 packages in a fresh
Python 3.15 venv". The source tree at the referenced commit `0062b2a` has
**23** packages, and all 23 import successfully in the current environment
(`total 23 import ok 23 fail 0`). No wheel or build log is committed
(`dist/` does not exist), so the exact 21-package run is not reproducible from
the repo.

**D3 — the foreign-attachment guard is weaker than its own comment.**
`trident/simulator/backends.py:412-418` says the port is checked refused
"*before* spawn" and then "require[d] to be refused again right after: only
once we see it go refused -> listening can we call the listener ours." The
implementation only records `was_refused` once, before `Popen`, and checks that
stale value after spawn. There is no second `_connection_refused` after
`Popen`, and `_wait_for_listener` accepts any connection that succeeds. A
process that binds between the check and `Popen` still produces a successful
connection to a foreign listener. The tests in `test_ipc_concurrency.py` cover
`_choose_port` only; none exercises this race. The pre-spawn check is real; the
absolute "no foreign attachment" guarantee is not.

**D4 — "only status assertions are gated" is inaccurate.**
In `tests/test_okcup_regressions.py`, the three `@requires_three_engines` tests
also assert values, and all 10 skips come from them:
`test_identity_questions` asserts `actual == expected`,
`test_address_family_is_distinguished` asserts `actual == expected`, and
`test_gateway_and_vlan_answers` asserts the VLAN/gateway values. Those value
assertions do not run in this environment. The compensating ungated test
(`test_every_audited_answer_is_correct_at_any_engine_count`) covers the same 12
values and passed, so no wrong value can hide — but the sentence "Only the
status assertions are gated" is literally false as written.

**D5 — Engine C "three independent reasons, all verified" overstates reason 3.**
Reason 1 is confirmed (`src/lib/` is empty; both `.ts` files absent). Reason 2 is
confirmed by the exact failing command, though the checkout contains a `.git/`
directory skeleton (`hooks`, `info`, `logs`, `objects`, `refs`) with no `HEAD`
or `config`; `git rev-parse` fails exactly as quoted. Reason 3 ("pt-convert is
All-Rights-Reserved") has no license/COPYING file and no `license` field in
`package.json` in that checkout, so it cannot be verified from the artifacts
present. The unavailability conclusion is correct; the "all verified" wording is
not fully supported.

**D6 — untracked docs.** `docs/gauntlet/FAULT_COVERAGE_MATRIX.md` and
`docs/gauntlet/OMEGA_RESULTS.md` are untracked working-tree files, not part of
the branch. Their claims were audited above, but they would not ship with this
branch as committed.

**D7 — the live-instance claim has no evidence path.**
`docs/CYBERPATRIOT_READINESS.md:63` ("Verified against the live instance holding
port 39001 on this machine") cites no test, log, or transcript, and cannot be
reproduced offline. It may be true; it is not checkable from the repository.

---

## Claims I could not verify offline

1. **15 faults verified observable in Packet Tracer 9.0.1** — requires starting
   Packet Tracer and running `tests/test_labgen_live.py -m live_simulator`.
   Not run, by instruction.
2. **"Verified against the live instance holding port 39001"** — no artifact;
   live-only.
3. **Wheel built and all packages imported in a "fresh Python 3.15 venv"** — no
   `dist/` artifact or log in the repo, and Python 3.15 is not the environment
   used here (3.12.12). The 23-package import check was run against the source
   tree instead, and passed.
4. **Live diagnosis against a real simulator** — the mocked path was verified
   (11 passed, 1 deselected); the real path was deliberately not started.
5. **`pytest -q --ignore=tests/browser` → "1611 passed, 9 known failures"**
   (`docs/CYBERPATRIOT_READINESS.md:220`) — full-suite reproduction was outside
   this audit's command list; not confirmed.
