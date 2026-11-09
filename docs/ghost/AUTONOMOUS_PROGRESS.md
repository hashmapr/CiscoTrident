# PROJECT GHOST — AUTONOMOUS PROGRESS

Append-only record of autonomous work. Newest section last.

Latest commit: see `git log -1`.
Status: **headless runtime operational**; remaining work is breadth, not blockers.

---

## Milestone 1 — Engine B timeout (COMPLETE)

### Symptom
`test-labs/incoming/Modules_1-13_Image.pka` (30 MB) made Engine B exceed its
timeout. Engine B reported `TIMEOUT` while A and C succeeded.

### Investigation
Stage timings measured directly, not inferred:

| Stage | Time | Notes |
|---|---|---|
| `pkt_core.decode_bytes` | **215.0 s** | pure-Python AES-EAX over 30 MB |
| `select_snapshot` | 1.6 s | |
| `build_placeholder_map` | 0.1 s | 0 entries on this file |
| `pkt_core.open_lab` | **221.8 s** | decodes the container **again** |
| `pkt_core.cli.main unpack` (subprocess) | **219.1 s** | decodes a **third** time |

Peak RSS stayed low (0.29 GB decode, 0.90 GB after Lab parse). This was never a
memory problem: it is **the same expensive decode performed three times**.

### Root cause
The container decode is inherent — pure-Python AES-EAX, no native acceleration
available in this `pkt-core` build. Doing it three times was the defect:

1. `decode_bytes` for the snapshot and placeholder map,
2. `open_lab` for the typed model,
3. a `pkt_core.cli.main unpack` subprocess for configs.

### Fix
`trident/parsers/pkt_core.py`:

- the decoded XML is kept in a local and handed to `Lab.from_bytes(decoded)`
  instead of calling `open_lab` — **222 s → 4.5 s**,
- the CLI subprocess is replaced with in-process extraction of each device's
  `ENGINE/RUNNINGCONFIG` node, which is exactly what the CLI does after
  decoding. Config bytes are decoded to text at that boundary.

### Result

| | Before | After |
|---|---|---|
| Engine B, 30 MB fixture | ~452 s (TIMEOUT) | **220 s (OK)** |
| Decodes per run | 3 | **1** |
| Devices / configs / interfaces | — | 29 / 18 / 216 (unchanged) |

Remaining 220 s is the single unavoidable decode. The default timeout is
*not* raised; the redundant work is gone.

### Regression coverage
`tests/test_engine_b_single_decode.py`:
- asserts **zero** subprocesses are spawned,
- asserts `decode_bytes` is called exactly once and `open_lab` zero times,
- asserts devices, configs and interface counts are unchanged,
- a large-fixture timing guard that fails if the third decode returns.

---

## Milestone 2 — SHUTDOWN_INTERFACE false positives (COMPLETE)

### Symptom
Every switch in every `.pka` reported its management SVI as a defect:
`Vlan1` appeared in 10 findings across two real labs.

### Root cause
An SVI's administrative state is **derived** from its member ports, not chosen.
Treating it as configuration intent flagged normal equipment. Separately, the
evidence ladder ranked "holds an address" above "assigned to a VLAN", so an
addressed SVI looked like proof of intent.

### Fix
`trident/diagnostics/__init__.py`:

- `_is_svi()` — a `Vlan<N>` interface is never proof of intent.
- `_proves_intended_service()` now ranks:
  `vlan` (access port in a VLAN, or trunk) → `address` (routed port) → `cable`.
  Only `vlan` and `address` confirm; `cable` alone does not.

### Result
`R3_OKCUP_24_25`: 10 findings → **6**, all `Vlan1` entries gone, the real
duplicate-IP, four addressed-port shutdowns and one gateway finding retained.
Fault lab still **12/12 exact**.

### Regression coverage
`tests/adversarial/test_shutdown_semantics.py` — 13 cases, both directions:
management SVI, addressed SVI, unused port, cabled-but-unconfigured, unused
serial, entirely spare router, access port in a service VLAN, trunk, addressed
routed port, mixed noise plus one real fault, report shape, runtime contradiction.

---

## Milestone 3 — Simulator ownership (COMPLETE)

### Requirement
Never terminate a Packet Tracer the operator started.

### Findings
- Library code was already correct: `ProcessSupervisor.stop()` uses
  `os.killpg(os.getpgid(own_pid))` and targets only the process it spawned.
- The risk was ad-hoc shell usage during development, which is now banned in the
  package and checked by a test.
- Added `SimulatorRuntime.owned_pids()` and wired `close_all()` into the lab
  inspector's `finally`, so an inspected lab cannot leave an owned process.

### Regression coverage
`tests/simulator/test_ownership.py` — 8 tests:
no owned PIDs before a session; one owned PID during; none after; the simulator
runs in its own process group (not the caller's); **a foreign process survives
our shutdown**; idempotent stop; stop-before-start; repeated sessions leave
nothing; and a source scan that fails if `pkill`/`killall` by name ever appears.

---

## Milestone 4 — Headless runtime (OPERATIONAL)

### The window problem
`--no-gui` alone is not enough. Measured:

| Step | Windows | Frontmost |
|---|---|---|
| launch `--no-gui` | 0 | `zen` |
| connect | 0 | `zen` |
| **`fileOpen`** | 0 | **`PacketTracer`** ← focus stolen |
| `setVisible(false)` then `fileOpen` | **0** | **`zen`** |

Hiding the window **before** opening the file is the fix. Hiding after is too
late: focus has already moved.

The stock bundle also has no `LSUIElement`, so it always gets a Dock icon.

### Ghost app
`trident/simulator/ghost.py` builds a **separate** copy of the bundle with
`LSUIElement` set. macOS then reports it as `type="UIElement"` — a background
agent with no Dock icon, no Cmd-Tab entry, no window and no focus change.

```bash
python -m trident.simulator.ghost            # build (clonefile, ~42 s, ~0 disk)
python -m trident.simulator.ghost --status
python -m trident.simulator.ghost --remove
```

Safety: the original installation is never modified (test compares `Info.plist`
bytes before and after). Editing the copy's plist invalidates Cisco's signature,
so the **copy** is ad-hoc re-signed. That re-signs our own file; it does not
touch or bypass protection on the installed product, and no system security
setting is changed.

### Acceptance gate — PASSED on a real `.pka`

`test-labs/incoming/Final_R3_BDSM.pka` (648 KB):

| Gate step | Result |
|---|---|
| Invisible start | windows **0**, frontmost **Code** throughout |
| Disposable copy | yes; source untouched |
| Device enumeration | **22** real devices (PC1–PC4, CSwitch1, Router4, …) |
| Genuine diagnostic | `Router4# show ip interface brief` → **1876 bytes** of real IOS output |
| Attribution | `provenance.session_id` matches; backend `SIMULATOR_LIVE` |
| Clean shutdown | `CLEANED/backend=CLIENT_CLOSED+TERMINATED/source=INTACT` |
| Owned processes after | **none** |

Earlier run on `sample_lab.pkt` returned 2277 bytes of `show version`
(`Cisco IOS Software, C2900 … 15.1(4)M4`) and 390 bytes of interface output.

---

## Known limitations

- Container decode is ~215 s for 30 MB and is inherent to pure-Python AES-EAX.
  Options if it matters: raise `TRIDENT_PARSER_TIMEOUT` for large files, or
  upstream a native AES-EAX path into `pkt-core`.
- `provenance.simulator_version` reads `unknown` for the ghost copy; the real
  version is known (9.0.1.0858) and is carried by the PTMP handshake.
- Ping remains `INCONCLUSIVE` from CLI because Packet Tracer's `ping` is
  interactive and needs simulation advancement; the runtime refuses to invent a
  verdict.

## Next actionable tasks

1. Revalidating all five networks after these fixes, with per-finding evidence.
2. TRIDENT EVOLVE registry foundation.
3. Full regression + 260-question benchmark + 11-network holdout.
