# DEEPCORE BASELINE

Phase 0 of the overnight program. Captured 2026-11-10.

## Release candidate preserved

| Item | Value |
|---|---|
| RC tag | `trident-stream-verify-rc1` |
| RC commit | `9d14807` |
| Development branch | `development/deepcore` |
| Branch point | `719371c` |
| Working tree | clean at branch creation |

The tag was not moved or force-updated, and nothing in this program touches it.

## Test baseline

```
pytest -q                1179 passed, 1 environment-related failure
```

The failure was `test_live_session_launches_invisibly_and_preserves_the_source`,
caused by a leftover Packet Tracer process holding the IPC ports. That is now
diagnosed and fixed rather than worked around — see below.

## The IPC port conflict, root cause

The supervisor probed ports 39000-39009 and accepted **any** listener:

```python
for port in candidates:
    with socket.create_connection(("127.0.0.1", port), timeout=0.3):
        return port          # <- whoever is listening wins
```

If the operator — or a previous test — had a Packet Tracer running, the
supervisor attached to *that* instance. The process it had just spawned then
failed to bind its own listener and sat there doing nothing. The session talked
to the wrong simulator, and cleanup could have targeted a process it did not own.

### Fix

A free port is chosen before launch and passed explicitly with `--ipc-port`, so a
successful connection proves the listener belongs to the process this supervisor
started. When the whole range is busy the supervisor reports that plainly instead
of guessing.

Verified: with 39000 and 39001 occupied, `_choose_port()` returns 39002. With the
entire range occupied it raises `BackendUnavailable` naming the reason.

Two regression tests pin both behaviours.

## Two further defects found during the audit

### Ghost bundle reported no version

`find_packet_tracer()` prefers the ghost copy when `TRIDENT_USE_GHOST_APP` is set.
The copy is named `PTGhost.app`, whose name carries no version, so
`simulator_version()` returned `unknown` — and that value goes into every
observation's provenance.

`ghost.build()` now writes a `.trident-source` marker recording the bundle it was
cloned from, and `simulator_version()` reads it. The ghost copy now reports
**9.0.1**.

### Backend reported port 0

`LiveBackend.connect()` stored the port inside the supervisor but never copied it
back, so diagnostics and provenance reported port 0 for a live session. Now
recorded.

## Clean-environment verification

```
tests/simulator/test_live_integration.py        6 passed
  + tests/simulator/test_pdu_live.py           15 passed  (together)
tests/simulator/test_ownership.py             10 passed
tests/simulator/test_runtime.py               26 passed
```

No Packet Tracer process remained 5 seconds after the suite finished; the
transient count immediately after was a process mid-shutdown, not a leak.

## What this establishes

The baseline is stable, the RC is isolated, and the environment failure is fixed at
its cause rather than being re-run until it passed. Phase 1 may proceed.
