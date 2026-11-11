# ORACLE CONTINUATION

Date: 2026-11-10 · Branch `development/deepcore` · RC `trident-stream-verify-rc1` = `9d14807` (untouched)

This file did not exist before this session despite being referenced by the
handoff. It is written now so the next session has a verified starting point
instead of a claim set.

---

## 1. State at this checkpoint

```
branch       development/deepcore
RC tag       trident-stream-verify-rc1 -> 9d14807   (unmodified)
simulator    Cisco Packet Tracer 9.0.1.0858, registered ExApp, external volume
offline      pytest -q  -> 1488 passed, 54 deselected
live         pytest tests/simulator/ -m live_simulator -> 27 passed
browser      pytest tests/browser/ -m browser -> 26 passed, 1 skipped
benchmark    260/260, 0 false-verified  (regression pack, NOT a blind evaluation)
ruff         trident/ tests/ clean
```

Read `docs/oracle/DIFFERENTIAL_GAUNTLET_REPORT.md` before doing anything else. It
records what was actually demonstrated versus what remains blocked.

---

## 2. The one thing to understand first

**No authorized lab configures STP priority, EtherChannel, NAT or IPv6.**
All five labs in `test-labs/incoming/` are unconfigured student activities:

```
spanning-tree priority    nowhere
channel-group             nowhere
ip nat                    nowhere
show ipv6 route           0 entries on every device
```

So those four protocols are `STATICALLY_VERIFIED` and cannot be raised to
`SIMULATOR_TESTED` without a lab that actually contains the configuration. Do not
claim a simulator test for them. `docs/oracle/PROTOCOL_COVERAGE_MATRIX.md` states
the exact command subset each parser supports, which is what a future experiment
would need.

---

## 3. What this sprint fixed

Six defects, all found by feeding real captured configuration to the code:

| # | Defect | File |
|---|---|---|
| 1 | ACL wildcard stored as the destination operand | `trident/normalization/configs.py` |
| 2 | `ip access-group` binding never reached `AclEntry` | `trident/normalization/devices.py` |
| 3 | ACL evaluated destination only; `any` became blanket deny; no source operand; unevaluable must be `unknown` not `permit` | `trident/deepcore/path.py`, `journey.py` |
| 4 | RIP `network` statement recorded as a route; bare network read as `/32` | `trident/normalization/configs.py` |
| 5 | Cold-ARP drop treated as a real forwarding failure | `trident/simulator/pdu.py` |
| 6 | `verify()` ran inside a plain `pytest`, starting Packet Tracer | `tests/simulator/test_registration.py` |

Plus one test-race fix (`tests/browser/test_browser_stream.py`) and one stale-data
correction (`trident/deepcore/coverage.json` + its two tests).

Defect 4 had a second half: a router running a dynamic protocol was reported as a
**definite** drop for "no default gateway". It is now `UNKNOWN`, naming the
protocol. Note this changed `R2 -> SW1` from an *accidentally correct* DROP to an
honest `UNKNOWN`. That is the intended direction.

---

## 4. Highest-value next work

### 4.1 Send a PDU through a real ACL (ready now, no new lab needed)

ISP A in the CCNA Mega Lab has a real ACL 100 bound inbound on `Gi0/0/0`. The
ACL fixes are statically verified only. The next differential step is to send a
PDU whose source falls inside `10.0.0.0 0.255.255.255` and confirm Packet Tracer
drops it, then one outside and confirm delivery. That converts `acl` from
`STATICALLY_VERIFIED` to `SIMULATOR_TESTED` with real evidence.

### 4.2 Fix IPC port contention (blocks reliable live runs)

Two lab opens failed with `did not accept connections within 45.0s`, and one live
test failed then passed on retry. The 30-port range plus a `TIME_WAIT` cooldown is
the cause. Options: a longer retry budget, or holding a port lease across the
session. Do not widen the range blindly — measure first.

### 4.3 Surface PDU execution detail

`send_pdu` returns `EXECUTION_ERROR` with no detail at the harness level.
Underlying causes observed: `addSimplePdu timed out after 30.0s` and
`setSimulationMode timed out after 20.0s` on switch-only topologies. Carrying
`pdu.error` into the differential record would make these diagnosable instead of
opaque.

### 4.4 Large-lab decode

`Modules_1-13_Image.pka` (30 MB) does not open within 60 s. Profile before
optimising; the handoff's ~107 s figure has not been re-measured.

### 4.5 Protocols that need a configured lab

STP root election, EtherChannel negotiation, NAT/PAT translation and IPv6
forwarding all need a lab with real configuration. Either obtain one, or decide
whether authoring `.pkt` content is in scope. Do not lower the evidence bar to
close these.

---

## 5. Reproduce this checkpoint

```bash
cd ~/CiscoTrident && source .venv/bin/activate

git status --short
git rev-parse --short trident-stream-verify-rc1     # 9d14807
python -m pytest -q

TRIDENT_ALLOW_LIVE_SIMULATOR=1 python scripts/oracle_lab_survey.py
TRIDENT_ALLOW_LIVE_SIMULATOR=1 python scripts/oracle_differential_stp.py \
  --lab "test-labs/incoming/CCNA Mega Lab (Jeremy's IT Lab)(1).pka" \
  --out docs/oracle/evidence/differential_megalab.json
TRIDENT_ALLOW_LIVE_SIMULATOR=1 python scripts/oracle_pdu_differential.py \
  --lab tests/fixtures/sample_lab.pkt \
  --out docs/oracle/evidence/pdu_differential_sample.json

python -m pytest tests/simulator/ -m live_simulator -q
python -m pytest tests/browser/ -m browser -q
python -m trident.tools.benchmark_pack --pack ~/Downloads/TRIDENT_4_Network_Benchmark_Pack
```

Sleep ~45 s between back-to-back live sessions; the IPC ports need to leave
`TIME_WAIT`.

---

## 6. Documents in this directory

| File | Status |
|---|---|
| `DIFFERENTIAL_GAUNTLET_REPORT.md` | current — read first |
| `PROTOCOL_COVERAGE_MATRIX.md` | current — command subsets and evidence levels |
| `CONTINUATION.md` | this file, new |
| `PROTOCOL_FINAL_REPORT.md` | historical, accurate for its commit range |
| `FINAL_COMPLETION_REPORT.md` | historical |
| `COMPLETION_TRACKER.md` | **stale** — predates the protocol work; do not use as truth |
| `PROGRESS.md`, `FINAL_REPORT.md` | historical |
| `ANALYZE_MODE.md`, `PHASE1_DEEP_ANALYZE.md`, `PHASE2_STREAMING.md` | historical |

`trident/deepcore/coverage.json` is generated from `coverage.py`; regenerate it
after changing `FEATURES` rather than editing the JSON.

---

## 7. Standing constraints

* Never modify the release candidate tag.
* Never mutate a source lab; always work on a disposable copy and verify the hash.
* Never kill a Packet Tracer process this project did not start.
* Never let a plain `pytest` start Packet Tracer — live tests carry
  `@pytest.mark.live_simulator`.
* Do not call the 260-question pack blind or national-level.
* Commit locally at validated milestones; do not push, merge or deploy.
* The standalone XML → PKA converter is a separate project. Do not add it here.
