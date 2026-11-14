# CiscoTrident — CyberPatriot Readiness

Written at commit `0062b2a` on branch `cyberpatriot/readiness`, from `main@3ddda2c`.

**Verdict: CONDITIONALLY READY.** The practice lab is real, opens in Packet
Tracer 9.0.1, and every one of its 15 faults was verified observable in the
simulator. Scoring is honest and does not leak the key. What is *not* ready is
TRIDENT's claim to be a general CyberPatriot diagnostic system: two of three
parsing engines run here, so most facts are honestly `INCOMPLETE` rather than
`VERIFIED`, and there is no live-simulator path for the diagnostic engine
itself. Details and evidence below.

---

## 1. Baseline (before any change)

```
python -m pytest -q
14 failed, 1470 passed, 4 skipped, 55 deselected in 1124.75s
ruff check trident tests -> All checks passed
```

Pre-existing failures: 4 × `test_engine_coverage` (Engine C absent), 9 ×
`test_okcup_regressions` (needs a real `.pka` from `~/Downloads` plus all three
engines), 1 × `test_sse_recovery` (a real defect, fixed below).

Environment: macOS `arm64`, Python 3.12.12, Packet Tracer 9.0.1 on
`/Volumes/AI-Models`. Model: `ollama-cloud/deepseek-v4.1-flash:1017-cloud`,
read from `kilo.json`.

---

## 2. What was fixed

### P0 — packaging (commit `ca8599c`)

`pyproject.toml` carried a hand-written package list that had drifted. **Ten
packages were absent from every wheel**, including `trident.simulator`,
`trident.faultlab` and `trident.deepcore`. A source checkout hid it entirely,
so the suite was green while an installed TRIDENT could not import its own
simulator.

Fixed with `packages.find`. Verified by building a wheel and importing all 21
packages in a fresh Python 3.15 venv; `/api/health`, `/api/parsers` and `/` all
returned 200. Pinned by `tests/test_packaging.py` (14 tests).

### P0 — IPC (commits `da9c069`, `792d159`)

Three defects, each reproduced against a real socket:

1. `PtmpClient.call` skipped unrelated frames in `while True` with no deadline.
   A socket timeout does not bound it: Packet Tracer streams `IPC_EVENT` frames
   during simulation and each one resets the timeout, so a session in simulation
   mode spun at full CPU. Now bounded by wall clock *and* a skipped-frame cap.
2. `LiveBackend.connect` leaked its Packet Tracer process when the client failed
   after startup. It now tears down on any failure, including cancellation
   (which arrives as `BaseException` and was missed by `except Exception`).
3. `_choose_port` released its reservation before `Popen`, so a racing process
   could take the port and `_wait_for_listener` would attach to a stranger —
   a real but foreign Packet Tracer with the wrong lab loaded. `start()` now
   requires a refused connection before spawn and fails rather than guessing.

Verified against the live instance holding port 39001 on this machine.
`tests/simulator/test_ipc_bounds.py` (8) + `test_ipc_concurrency.py` (6).

### P0 — parsers (commit `4114c92`)

Engine B returned **`links=0`** on `tests/fixtures/sample_lab.pkt` with no
warning, while Engine A returned 5. It parsed links from a DOT file that unpack
no longer produced. It now reads the typed model: **7 devices, 5 links, matching
Engine A**. Also: Engine A dropped unresolvable `<LINK>` stanzas silently, and
Engine B trusted a `.xml` suffix and hung >100 s on a renamed `.pkt`.

### P1 — streaming and diagnostics (commit `7063916`)

A corrupt upload produced a clean `COMPLETE` with "no devices were extracted",
because the decode verdict only fired when ≥2 engines errored. Also fixed: an
exception mid-stream truncated the stream with a traceback and no terminal
event; a simulator failure discarded already-computed static results; gateway
diagnostics matched addresses with `startswith`, so a gateway of `10.10.20.2`
was "contradicted" by `10.10.20.25`.

### P1 — lab generation and practice (commits `661876b`, `64f351a`, `3e2862f`, `0062b2a`)

See sections 3 and 4.

---

## 3. Operation Broken Campus

11 devices (2 routers, 2 switches, 6 PCs, 1 server), 10 links, **15 faults,
100 points**, three departments plus management VLAN.

Generated from a `TopologySpec` with `pkt_core.builder` (already a TRIDENT
dependency as Engine B). A fault carries an explicit target
(`interface_line`, `context_line`, `global_line`, `block`, `vlan_db`, `endhost`)
rather than being inferred from text.

### Live evidence

```
TRIDENT_RUN_LIVE_LABGEN=1 TRIDENT_ALLOW_LIVE_SIMULATOR=1 \
  pytest tests/test_labgen_live.py -m live_simulator
2 passed
```

`verify_in_packet_tracer` reported: *opened in Packet Tracer 9.0.1; 11 devices
visible*. Every fault was then proven with a real command (`show vlan brief`,
`show interfaces trunk`, `show ip route`, `show running-config`, …).

### Four faults that did not exist, found only because it was opened

This is the part worth reading. Encoding succeeded for all of these. They were
wrong in the simulator, and the first three would have been ungradeable:

| Fault as designed | What Packet Tracer actually did |
|---|---|
| `vlan 10` written as a config line | IOS never prints VLANs in `running-config`. The switch had **no VLAN 10 at all**. VLANs now go into `<VLANS>` (vlan.dat). |
| VLAN 30 renamed to "STUDENTS" | The name collided with VLAN 20 and Packet Tracer **deleted VLAN 30**. Replaced with a port-membership fault. |
| `transport input all` on vty | That is the IOS default, so it is omitted from `running-config`. **Invisible.** Replaced with a missing `enable secret`. |
| Server-side `ip name-server` | `Server-PT` rejects `enterCommand` outright on 9.0.1. **Unreadable.** Replaced with a missing `dns-server` in the DHCP pool. |

A fifth design error: R1's default route pointed at `10.0.0.2` on a `Gi0/1` that
had no cable, so IOS rejected the route and the routing fault silently vanished.
An ISP peer was added.

**A fault that cannot be observed is a rubric item the student cannot score.**
`tests/test_labgen_live.py::test_every_fault_has_a_verification_path` now fails
if any fault lacks a verification route.

---

## 4. Practice mode

```
trident practice operation-broken-campus --objectives
trident practice operation-broken-campus --hint obj-trunk-06
trident practice operation-broken-campus --submit findings.txt --out report/
trident practice operation-broken-campus --write-key key.json   # instructor only
```

Three difficulties. Scoring test at all three with a complete diagnosis:

```
beginner      100/100  found=15/15
intermediate  100/100  found=15/15
advanced      100/100  found=15/15
```

Four scoring bugs were found by running the thing, not by reading it:

1. **Difficulty scaled the award** (0.6/0.8), so a perfect answer scored 60–80
   and full marks were unreachable. Difficulty now changes the *precision* a
   diagnosis needs, not the lab's value.
2. **Objective ids collided** (`obj-vlan-wrong` twice), so a hint request went
   to whichever fault came first. Then, after fixing that, ids leaked the
   defect (`obj-iface-admin-port-shutdown`). Now `obj-<category>-<NN>`.
3. **`VLAN` and `SECURITY` parsed as interface names** (`se` prefix), so a
   submission naming a category was read as naming an interface.
4. **One finding could be claimed twice**, and a vague `R1` consumed a specific
   `R1 DHCP`. Matching is now pass-based: fault id → device+interface+category
   → device+interface → device+category → device alone.

### Answer-key separation

`score.as_dict()` strips `expected`/`actual` from **missed** lines. A found
fault keeps them, because confirming the correct value is teaching; a missed one
would be the key. Verified in both directions: no fault's actual value appears
in `STUDENT_BRIEF.md`, and every expected value appears in `ANSWER_KEY.json`.

---

## 5. Test results

| Run | Result |
|---|---|
| Full suite, baseline | 14 failed, 1470 passed, 4 skipped, 55 deselected |
| Full suite, now | **9 failed, 1611 passed, 10 skipped, 30 deselected** |
| New tests added | ~190 |
| Ruff | All checks passed |

The 9 remaining failures are the same `test_okcup_regressions` group from
baseline, unchanged in character: the answer is correct, the status is
`INCOMPLETE` because only 2 of 3 engines are available here. They are **not**
weakened, and they are not green.

Live Packet Tracer runs performed this session: lab open + 15-fault verification
(`2 passed`), plus ad-hoc inspection sessions. All sessions closed; no process
was left running and no pre-existing Packet Tracer instance was touched.

---

## 6. Not verified / unsupported

1. **Engine C was never available.** `TRIDENT_PT_CONVERT_DIR` points at an
   incomplete checkout. Under `strict` consensus this caps most facts at 2/3
   `INCOMPLETE`. Nothing here should be read as a 3-engine result.
2. **PC NIC values cannot be read over IPC** on PT 9.0.1 (`enterCommand` not
   found, `getPort` rejects every argument form tried). End-host faults are
   verified from decoded XML.
3. **The diagnostic engine has no live-simulator path.** `diagnose()` runs on
   the parsed model. Live evidence exists for the *lab*, not for diagnosis.
4. **Scoring only works for built-in labs.** An arbitrary `.pkt` has no
   manifest, and `trident practice` refuses it rather than inventing objectives.
5. **Only 2 switches, 1 router.** The brief asked for that; multi-area routing,
   wireless and IPv6 practice scenarios were not built.
6. **No `.pka` scored activity was generated.** `pkt_core`'s scored-activity
   authoring (`tools/activity.py`, `tools/scoring.py`) is not shipped in the
   installed package, so this is genuinely unavailable, not skipped.

---

## 7. Reproduction

```bash
cd ~/CiscoTrident && git checkout cyberpatriot/readiness
source .venv/bin/activate && pip install -e .

pytest -q --ignore=tests/browser            # 1611 passed, 9 known failures
ruff check trident tests

trident practice operation-broken-campus --generate /tmp/lab
TRIDENT_RUN_LIVE_LABGEN=1 TRIDENT_ALLOW_LIVE_SIMULATOR=1 \
  pytest tests/test_labgen_live.py -m live_simulator
```

The lab, its key and its setup procedure are in
`docs/cyberpatriot/operation-broken-campus/`.

---

## 8. Remaining risks

- A single 2-engine environment produces `INCOMPLETE` everywhere. That is the
  honest design, but a CyberPatriot coach will read it as "the tool doesn't
  know", and they will be right for 1/3 of the corpus.
- The lab was verified on one Packet Tracer build (9.0.1 / macOS arm64). The
  VLAN-database behaviour is a Packet Tracer property, not a TRIDENT one, and a
  different PT version could differ.
- `test_okcup_regressions` will stay red until Engine C is installed. It encodes
  a real requirement, so it should not be silenced.
