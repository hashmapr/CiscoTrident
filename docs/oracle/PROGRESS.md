# PROJECT ORACLE — PROGRESS

Branch `development/deepcore`. RC tag `trident-stream-verify-rc1` untouched.

---

## Phase 0 — DeepCore validation (COMPLETE)

Full regression: **1252 passed, 1 failed**. The failure was the live differential
test reporting "no free IPC port" because a Packet Tracer from a previous test was
still releasing its port. Fixed at the cause: `_choose_port()` now retries for up
to 15 s before reporting exhaustion. The live suite then passed.

---

## Analyze Mode (COMPLETE) — commit `4a5a678`

`trident/deepcore/analyze.py` plus `/api/network/analyze` and a frontend button.

One button, no questions. Produces a network overview, one section per device
ordered routers first, basic information, likely Cisco questions with per-answer
evidence status, potential problems with evidence and consequence, network-wide
issues, and an explicit list of what was not checked.

### Three defects found by building it

1. **`device_type` is never populated.** The parser records `model` (e.g. `2911`)
   and leaves `device_type` None, so every device grouped as "Device". Kind is now
   derived from the model string.
2. **`to_report_dicts()` discarded the evidence.** It returned only kind, device,
   interface and confidence, so a report could say something was wrong but not
   why, and a reader could not verify it. It now carries supporting and
   contradicting observations, the next command and the repair hint.
3. Heading inconsistency, same root cause as (1).

### Tests

30 unit tests, 7 real-browser tests. Exports verified in JSON, Markdown and text.

---

## Remaining Oracle phases

Not yet started, in the order the directive specifies:

1. Canonical digital twin (extend the model with L2 domains, trunk permissions,
   native VLAN, NAT boundaries, DHCP relay paths, STP, EtherChannel, IPv6).
2. Full packet-journey reasoning (return path, ACL ordering, NAT translation).
3. Protocol state machines (STP election, OSPF adjacency, EtherChannel).
4. Active experiment planner (hypothesis-driven selection, measured against a
   fixed checklist).
5. Formal invariants (declarative policy checks with counterexamples).
6. Differential testing report against Ghost.
7. EVOLVE expansion.
8. Adversarial network generator.
9. Performance work beyond the decode cache.
10. Final validation.
