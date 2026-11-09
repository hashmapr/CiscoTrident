# PROJECT GHOST — CONTINUATION BRIEF

Read this first if resuming. It is deliberately short and concrete.

## Current state

**The headless runtime works.** Packet Tracer runs invisibly (no Dock icon, no
window, no focus change), loads a disposable copy of a lab, executes real CLI
diagnostics, returns genuine IOS output, and shuts down leaving no process
behind. This was demonstrated on a real `.pka`, not mocked.

Latest commit: `git log -1`.

## How to run the live acceptance gate

```bash
export TRIDENT_ALLOW_LIVE_SIMULATOR=1
export TRIDENT_USE_GHOST_APP=1
.venv/bin/python -m trident.simulator.ghost           # build once, ~45s
pytest tests/simulator/test_live_integration.py -v   # 6 live tests
```

One-time prerequisites, already done on this machine:

- the ExApp meta file is installed at
  `<bundle>/Contents/extensions/trident.pta`
- credentials are at `~/.config/trident/credentials.env`
- the ghost copy is at `~/.local/share/trident/ghost-app/PTGhost.app`

## Verify the install is healthy

```bash
python -m trident.simulator.registration --verify
```

## Key commands

```bash
# static-only lab inspection (never starts Packet Tracer)
python -m trident.tools.inspect_labs test-labs/incoming

# ghost app management
python -m trident.simulator.ghost --status
python -m trident.simulator.ghost --remove

# regression
.venv/bin/python -m pytest -q
.venv/bin/python -m ruff check trident tests
.venv/bin/python -m trident.tools.benchmark_pack \
  --pack ~/Downloads/TRIDENT_4_Network_Benchmark_Pack
```

## Architecture decisions worth not re-litigating

1. **`--no-gui` alone is not enough.** `fileOpen` activates the app and shows its
   window. `appWindow.setVisible(false)` must be called *before* `fileOpen`.
   Hiding after the open is too late: focus has already moved.
2. **The stock bundle always gets a Dock icon** (no `LSUIElement`). The ghost copy
   is a separate bundle with that flag set, re-signed ad-hoc because editing the
   plist invalidates Cisco's signature. The original is never modified.
3. **Launch is opt-in** (`TRIDENT_ALLOW_LIVE_SIMULATOR=1`). It briefly defaulted
   to live and opened Packet Tracer on the operator's desktop mid-task.
4. **Engine B decodes once.** Container decode is ~215 s for 30 MB of pure-Python
   AES-EAX. It used to run three times (snapshot, `open_lab`, CLI subprocess).
   Do not reintroduce `open_lab` or the CLI subprocess in that path.
5. **An SVI being down is not a fault.** `Vlan<N>` state follows member ports.
6. **A ping with no summary line is `INCONCLUSIVE`, never `FAILED`.**
7. **Only owned processes are terminated**, by PID and process group. Broad
   `pkill`/`killall` by name is banned in `trident/simulator` and a test enforces
   it.

## Known limitations

- 30 MB container decode is ~215 s and unavoidable in this `pkt-core` build.
  For large files, raise `TRIDENT_PARSER_TIMEOUT`.
- `provenance.simulator_version` shows `unknown` for the ghost bundle; the real
  version (9.0.1.0858) comes from the PTMP handshake.
- CLI `ping` cannot complete without simulation-time advancement, so it reports
  inconclusive. Building real PDU-level connectivity tests is the next big step.

## Next actionable work

1. PDU-level connectivity testing via `simulation` mode + `FrameInstance`
   inspection, to get real success/failure verdicts rather than inconclusive.
2. Wire the EVOLVE registry into the investigation planner as a read-only
   advisory query (`Registry.relevant(tags)`).
3. Extend the fault taxonomy (STP loops, EtherChannel, routing authentication).

## Test and benchmark baseline

```
pytest -q                        1068 passed
ruff check trident tests         All checks passed
benchmark_pack                   260/260, 0 false-verified, 32.0s
adversarial+holdout+simulator    238 passed
five practice networks           all 3 engines OK, originals unchanged
```
