# ORACLE FINAL COMPLETION REPORT

Branch `development/deepcore`. RC `trident-stream-verify-rc1` at `9d14807`, untouched.

| | Commit |
|---|---|
| Starting | `ece0221` |
| Ending | `b9b406f` |
| Milestones | 6 |

---

## 1. What was completed

### Deep Analyze (Phase 1) — `c45d199`

Selecting Deep Analyze now runs real experiments in Packet Tracer, not a warning
that it cannot.

- **Lazy**: hardware model, hostname and interface address are answered from
  configuration and never start the simulator.
- **Targeted**: only devices with a routed physical interface are tested. SVIs,
  loopbacks and tunnels excluded; hosts whose addresses Packet Tracer assigns at
  runtime excluded, because a test against them is unreliable.
- **Bounded**: three experiments, one session, one timeout.
- **Honest**: an observed PDU becomes an `OBSERVED` answer on both devices carrying
  simulator version and session id, and never enters the three-engine consensus. An
  unavailable simulator produces a stated gap naming each skipped pair.

**Live, in a real browser:**

```
Analyzed 7 device(s) in 14.1s
"Deep Analyze ran operational experiments in Packet Tracer 9.0.1.
 Source file unchanged."
no JS errors
```

API evidence: `R1 -> R2 OBSERVED, frames=60`, plus Packet Tracer's own decision
text.

### Reliable streaming (Phase 2) — `a4a646e`

Session ids, monotonic sequence numbers carried as SSE `id:`, and a replay
endpoint. A dropped connection resumes from the last event actually seen: no
duplicates, no gaps, no restart. Retention is bounded (32 sessions, 2000 events,
30 min) and expiry is reported explicitly rather than handing back half a report.

A disconnect does not cancel. Only `POST /cancel` does.

### Device classification (Phase 3) — `e1ad8f2`

Classification follows the directive's order: structural type, then known model
mapping, then conservative inference, then Unknown. Verified against the file:
Packet Tracer records **no** structural device type — the `<TYPE>` element carries
only a model — so the model mapping is the most reliable source that exists.

An unmatched model reports `Unknown (model)`. It is never filed under a plausible
family.

### Formal invariants (Phase 5) — `0d3543d`

Five declarative claims with four outcomes (`PROVEN`, `VIOLATED`, `INCONCLUSIVE`,
`UNSUPPORTED`) and machine-readable counterexamples.

A proof carries its assumptions, and an isolation proof names what it did *not*
consider. No SMT solver: reachability over tens of nodes is decidable by
enumeration, and a solver would add a dependency without adding correctness. That
choice is recorded in the module.

**On the real 33-device lab the invariants found three genuine violations:**

| Invariant | Counterexample |
|---|---|
| unique-addresses | `35.72.15.10` claimed by 2 interfaces |
| gateways-exist | `38.72.11.1` held by no interface |
| addressed-interfaces-up | 4 addressed interfaces administratively down |

### Three infrastructure defects found and fixed — `b9b406f`

1. **The IPC port range was ten ports.** Each closed port sits in TIME_WAIT for a
   minute, so a test run exhausted it and every live test failed. Widened to
   thirty.
2. **The port probe used `SO_REUSEADDR`**, which lets `bind()` succeed on a port in
   TIME_WAIT. A port was chosen that Packet Tracer could not serve, and the PTMP
   handshake timed out.
3. **The opt-in tests detected Packet Tracer with `pgrep -f`**, which matches the
   calling shell's own command line. Fixed to compare the executable path exactly.
   That also exposed a genuinely orphaned Packet Tracer from an earlier run.

---

## 2. Validation

```
pytest -q                    1368 passed, 0 failed, 27 deselected
benchmark_pack              260/260, 0 false-verified
ruff                        clean
live simulator              15 passed (6 integration + 9 PDU)
browser (Analyze Mode)       8 passed
```

The 27 deselected are the `browser` and `live_simulator` marks, which are opt-in
and were run separately above.

---

## 3. Not completed

Honest list. None of these is claimed as done.

| Phase | Status |
|---|---|
| 4 — STP, EtherChannel, NAT, IPv6 semantics | NOT STARTED |
| 6 — Active experiment planner | NOT STARTED (a bounded escalation exists; a hypothesis-driven planner does not) |
| 7 — Adversarial network generator | NOT STARTED |
| 8 — EVOLVE expansion beyond strategy advice | NOT STARTED |
| 10 — Performance beyond the decode cache | NOT STARTED |

Phase 4 needs typed parsing for each protocol before any semantics can be modelled,
which is a substantially larger change than the phases completed here. Claiming it
in this window would have meant writing detectors that look like support without
being support — the exact failure the directive forbids.

---

## 4. Known limitations

1. Deep Analyze runs at most three experiments and tests ICMP connectivity only.
2. Streaming replay is process-local; a backend restart surfaces as expiry.
3. Invariants cover IPv4 reachability, address uniqueness, gateway validity and
   interface state. Segmentation rules that depend on unparsed ACLs are reported
   `INCONCLUSIVE` or `PROVEN` with that limitation stated.
4. Protocol coverage remains: 2 simulator-tested, 5 statically verified, 1
   parsed-only (OSPF), 8 unsupported.

---

## 5. Demonstrations delivered

| | Demonstration | Evidence |
|---|---|---|
| A | Quick Analyze, no simulator | 33 devices, 13.9 s, real browser |
| B | Deep Analyze with real Ghost | 7 devices, PT 9.0.1, runtime line in UI |
| C | Protocol intelligence | DeepCore multi-hop prediction, 17 tests |
| D | Formal invariant | 3 real violations with counterexamples |
| E | Active investigation | Bounded escalation; hypothesis planner NOT delivered |
| F | Adversarial generator | NOT delivered |
| G | EVOLVE | Strategy advice from trusted lessons, 14 tests |
| H | Reliability | Replay with exact cursor, 23 tests |

E and F are partial or absent, and are listed as such rather than implied.
