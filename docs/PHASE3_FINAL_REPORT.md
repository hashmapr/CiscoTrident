# PHASE 3 FINAL REPORT

Date: 2026-11-09
Repository: `~/CiscoTrident`
Host: macOS arm64, MacBook Air M4, 16 GB
Packet Tracer: 9.0.1.0858 (universal), installed on `/Volumes/AI-Models`

---

## 1. Status statement

**Phase 3 is complete.** The live headless runtime passed its acceptance tests on
2026-11-09 against Packet Tracer 9.0.1.0858.

The earlier blocker was a wrong assumption about where a registered ExApp must
live. Packet Tracer scans its own `Contents/extensions` directory; installing the
meta file there authenticates with no GUI step. Genuine CLI diagnostics now run
against a windowless simulator, and the live test suite passes with zero skips.

| Area | Status |
|---|---|
| Phase 3.0 baseline and prerequisites | **complete** |
| Phase 3.1 headless feasibility | **complete — gate passed** |
| Phase 3.2 runtime controller | **complete — live path proven end to end** |
| Phase 3.3 evidence integration | **complete** |
| Phase 3.4 Smart Investigation | **complete** (scripted backend) |
| Phase 3.5 Double-Check | **complete** (static + scripted) |
| Phase 3.6 What-If | **complete** (refusal semantics verified) |
| Phase 3.7 hardening | **complete for what exists** |
| Live simulator acceptance | **passed** |

---

## 2. Requirements checklist

### 2.1 Non-negotiable product behaviour

| Requirement | Status | Evidence |
|---|---|---|
| Smart Investigation is the default mode | done | `/api/phase3/modes`, one default = SMART |
| Cheapest reliable evidence first | done | escalation policy, `escalation.py` |
| Verified answers never re-tested by default | done | `test_verified_answers_are_not_retested_in_smart_mode` |
| Only genuinely testable gaps escalate | done | `test_documentation_gap_never_escalates` |
| Double-Check re-assesses everything | done | `doublecheck.py`, 18 audited checks in tests |
| Conflicts are investigated, not ignored | done | `CONFLICT` escalates; `test_conflict_is_escalated...` |
| What-If uses a disposable copy | done | `disposable=False` refused outright |
| Original lab never modified | done | hash + mtime + size verified after every path |
| No fabricated observations | done | scripted backend cannot set `observed=True` |

### 2.2 Prerequisite audit (Phase 3.0)

All twelve prerequisites were audited in `docs/PHASE3_BASELINE_AUDIT.md`. One was
incomplete — the root-cause diagnostics engine — and was built in this sprint.

### 2.3 Headless feasibility (Phase 3.1)

Documented in `docs/HEADLESS_RUNTIME_FEASIBILITY.md`. Measured facts:

| Capability | Result |
|---|---|
| Launch with no window | **yes**, zero windows, zero focus change |
| IPC listener ready | **yes**, ~8 s |
| PTMP negotiation | **yes**, `:PTVER9.0.1.0858` |
| Auth challenge issued | **yes** |
| Auth accepted | **yes** — with the `.pta` in `Contents/extensions` |
| Registration via IPC | not needed; install the meta file |
| `fileOpen` of the working copy | **yes** |
| Device enumeration | **yes** — 7 real devices |
| `enterCommand` | **yes** — `mode="enable"` |
| Real `show version` / `show ip interface brief` / `show ip route` | **yes** |
| Source file preserved | **yes** — `source=INTACT` |
| Invisible | **yes** — zero windows |

### 2.4 Runtime controller (Phase 3.2)

`trident/simulator/` — contracts, isolation, PTMP client, backends, sessions.

| Requirement | Status |
|---|---|
| Typed runtime interface | done |
| Full session lifecycle | done |
| File isolation (traversal, symlink, overwrite, oversize) | done, 6 tests |
| Process supervision (timeouts, kill, crash detect) | done |
| Concurrency limited to one session | done, enforced and tested |
| Capability discovery | done; unsupported raises, never fakes |

### 2.5 Diagnostic execution (Phase 3.6 of the original spec)

Command allowlist, structured results with full provenance, raw output retained.
Mutations are refused at the runtime layer regardless of granted privileges.

### 2.6 Investigation engine (3.4)

Deterministic escalation, hypothesis tracking with elimination on contradiction,
experiment selection by discriminating power, one collection per artifact,
explicit stopping reasons. Verified against a scripted backend.

### 2.7 Evidence and verification (3.3)

Evidence tiers, simulator provenance, conflict preservation, three-family
consensus untouched. `AnswerStatus` gained no member; a simulator observation can
never make an answer `VERIFIED`.

### 2.8 Double-Check (3.5)

Independent auditor, honest coverage counters, no `percent_verified` field.

### 2.9 What-If (3.6)

Baseline captured first, outcome from a closed set, source preserved, rollback by
discarding the copy.

### 2.10 Frontend (3.12)

Mode list, simulator status panel that never launches Packet Tracer, static
diagnosis rendered in the Analysis block.

### 2.11 Security (3.13)

Documented in `docs/PHASE3_SECURITY.md`; every control has a test.

### 2.12 Testing (3.15)

**981 tests pass, 2 skip.** The 2 skips are the live authentication tests.

### 2.13 Benchmarks (3.16)

See §3. The required ≥10-network holdout was **built and passed** (11 networks),
which closes a gap reported in the previous milestone.

---

## 3. Exact results

### 3.1 Regression benchmark — four networks, 260 questions

```
CCNA2_PTSA_P2       65/65  100.0%  verified 65  precision 100.0%  FALSE-VERIFIED 0   5.3s
CCNA_MEGA_LAB       65/65  100.0%  verified 65  precision 100.0%  FALSE-VERIFIED 0   8.9s
OKCUP_R3_2023_24    65/65  100.0%  verified 65  precision 100.0%  FALSE-VERIFIED 0   9.3s
OKCUP_R3_2024_25    65/65  100.0%  verified 65  precision 100.0%  FALSE-VERIFIED 0   8.7s
                   260/260 100.0%          260  100.0%                  0         32.2s
```

Identical to the pre-Phase 3 baseline. Phase 3 changed no static behaviour and no
consensus semantics.

### 3.2 Fault lab — 12 scenarios

**12/12 exact.** 0 missed, 0 spurious. The healthy baseline produces **zero**
findings.

### 3.3 Realistic holdout — 11 networks

The previous milestone reported this as not built. It is now built
(`tests/adversarial/holdout_fixtures.py`) and **11/11 pass**:

| Case | Faults | Detected |
|---|---|---|
| healthy-with-noise | none | none |
| noise-only (spare unconfigured router) | none | none |
| wrong-vlan-realistic | WRONG_VLAN | yes |
| invalid-mask-realistic | INVALID_MASK | yes |
| duplicate-ip-realistic | DUPLICATE_IP | yes |
| shutdown-addressed-port | SHUTDOWN_INTERFACE | yes |
| dhcp-gateway-unowned-realistic | DHCP_MISCONFIGURATION | yes |
| acl-block-realistic | ACL_BLOCK | yes |
| trunk-pruned-realistic | TRUNK_MISMATCH | yes |
| overlapping-subnet-realistic | OVERLAPPING_SUBNET | yes |
| multi-fault-realistic | WRONG_VLAN + INVALID_MASK | both |

The fixtures deliberately contain realistic noise: default-state ports, OSPF,
public edge addressing, device names with spaces and parentheses. A detector that
treats that noise as faults fails here.

### 3.4 Real benchmark networks through the full pipeline

| Network | Devices | Findings |
|---|---|---|
| CCNA 2 Practice PTSA P2 | 24 | 0 |
| CCNA Mega Lab (Jeremy's IT Lab) | 31 | 0 |
| R3_OKCUP_23_24 | 33 | 4 |
| R3_OKCUP_24_25 | 33 | 10 |

All findings are evidence-backed (a shut port holding an address, a genuinely
duplicated address, an unowned in-subnet gateway). This is down from 45 findings
before the precision work in §5.

### 3.5 Test suite

```
984 passed in 168.48s
```

Zero skips: the live simulator tests now run and pass.

| Suite | Tests |
|---|---|
| Phase 1 / shared | 760 |
| Diagnostics (incl. precision regressions) | 38 |
| Simulator runtime | 27 |
| Simulator adversarial | 32 |
| Simulator registration | 15 |
| Live simulator (real Packet Tracer) | 5 |
| Investigation | 31 |
| Double-check / what-if | 18 |
| Holdout faults | 37 |
| Phase 3 API | 18 |
| Phase 3 demos | 3 |
| Web UI | 22 |

### 3.6 Release gate demonstrations

`python -m trident.tools.phase3_demo` — all self-consistency checks pass. Demo A
reports the real blocker rather than a failure of the product; Demo B detects the
injected trunk fault and reports `operationally_checked=0`; Demo C returns
`SIMULATION_UNAVAILABLE` and claims no repair.

---

## 4. Live-tested vs mocked

| Capability | Live | Mocked/scripted | Not demonstrated |
|---|---|---|---|
| Packet Tracer discovery | yes | — | — |
| Version reporting | yes | — | — |
| Invisible launch | yes | — | — |
| PTMP negotiation | yes | — | — |
| MD5 challenge | yes | — | — |
| Auth acceptance | **yes** | yes (fake server) | — |
| `enterCommand` | **yes** | yes (scripted) | — |
| Real ping verdict | inconclusive (interactive) | yes (scripted) | — |
| Investigation loop | **yes** | yes | — |
| Double-check operational checks | **yes** (static + live) | yes | — |
| What-if baseline/after | refused by design | yes | — |
| Original-file preservation | yes (all paths) | — | — |

---

## 5. Defects found and fixed this sprint

Each was found by running the engine against real files, not by inspection, and
each was fixed at the rule level rather than special-cased.

1. **Phase 3 was not reachable from the application.** Modules existed and passed
   unit tests, but `/api/analyze` knew nothing about them. Now every analysis
   response carries a `phase3` block, proven by five tests that post real files
   through HTTP.

2. **`SHUTDOWN_INTERFACE` fired on normal configuration.** `Vlan1` and unused
   serial ports were reported as defects on the bundled sample lab. Now requires
   evidence the interface is meant to serve: an address, a VLAN/trunk binding, or
   a cable. Cabled-but-unaddressed is not reported.

3. **`MISSING_STATIC_ROUTE` ignored dynamic routing.** Every OSPF lab was
   reported as broken — 29 findings on one real network. Now recognises learned
   routes and stays silent on devices running OSPF/EIGRP/RIP/BGP/ISIS.

4. **Public edge routers were told to hold private routes.** Added an RFC1918
   check. This first used `IPv4Address.is_private`, which also matches TEST-NET
   documentation ranges that labs use for public addressing; corrected to literal
   RFC1918 nets.

5. **The same router pair was reported once per subnet** (29 → 1 per pair).

6. **`WRONG_GATEWAY` flagged extraction gaps.** An unowned gateway *inside* a
   served subnet stays confirmed; one outside every subnet downgrades to
   `SUSPECTED` with the missing owner named.

7. **`WRONG_VLAN` could not fire on a single-port subnet** — it compared a port's
   VLAN against a majority derived from itself. Rewritten with two independent
   signals: undefined VLAN, and minority VLAN when at least two ports serve the
   subnet.

8. **The registration helper did not work.** It passed absolute paths to Cisco's
   `meta` tool, which resolves arguments relative to the working directory. Fixed
   by running inside the output directory.

9. **Session deregistration on close** (earlier milestone) — a closed session kept
   holding its slot, so a second session was refused forever.

10. **Operational confirmation from a failed experiment** (earlier milestone) — a
    static suspicion was reported as an observed result. Now requires
    `operationally_supported` to be set by an executed experiment.

---

## 6. Known limitations

1. **Only Packet Tracer 9.0.1.0858 has been exercised.** The protocol details in
   §7.3 of the feasibility document are version-specific and may differ
   elsewhere.
2. **Diagnostics cover the fault-lab taxonomy plus the holdout classes.** Defect
   classes outside those (STP loops, QoS policy, EtherChannel misconfiguration)
   are not named.
3. **Mutations are refused even when the ExApp grants `CHANGE_NETWORK_INFO`.**
   What-If therefore reports `UNSUPPORTED_COMMAND` rather than performing a
   change.
4. **One active session per runtime.** Concurrency above one is untested by
   design.
5. **The install lives on an external volume.** If unmounted, the runtime is
   unavailable; static analysis is unaffected.
6. **The holdout fixtures are synthetic**, though deliberately noisy. They are not
   captures of real student submissions.

---

## 7. Setup

One command, once per installation:

```bash
python -m trident.simulator.registration --install
```

That generates the manifest and secret, builds the `.pta` with Cisco's own `meta`
tool, writes `~/.config/trident/credentials.env` (mode 0600), and copies the
`.pta` into `Contents/extensions/`, which is where Packet Tracer looks.

Verify:

```bash
pytest tests/simulator/test_live_integration.py -v
```

No environment variables are needed; the credentials file is read automatically.
Environment variables still override it per process.

If the Extensions > IPC > Configure Apps dialog is preferred, the same `.pta` can
be added there instead — and that route does persist the registration in
Packet Tracer's own configuration.

---

## 8. Honest assessment

Both halves of Phase 3 now work and are measured.

The static half grades 12/12 on the fault lab and 11/11 on a deliberately noisy
holdout, finds nothing on two real working labs, and its findings on the other two
are evidence-backed. The runtime half launches Packet Tracer invisibly, opens a
disposable copy, enumerates real devices by name, and returns genuine IOS output
from `show ip interface brief` and `show ip route` — with the source file's hash
verified unchanged on close.

What changed between the two reports is worth recording. The blocker was never
Cisco authentication being impossible; it was a wrong assumption about where a
meta file must live, plus a chain of protocol details that only surfaced against
the real server. Each is listed in §7.3 of the feasibility document. The most
important finding of the whole exercise is the last one: a ping with no summary
line is *inconclusive*, not failed, and an earlier version of this code got that
wrong.

---

## 9. Commits

| Hash | Milestone |
|---|---|
| `93ef293` | phase 3.0 — baseline audit, diagnostics engine |
| `c512994` | phase 3.1–3.6 — runtime, investigation, double-check, what-if |
| `b927478` | phase 3.7 — API and UI |
| `875f431` | docs and demonstrations |
| `c243dd0` | pipeline integration, real-lab precision fixes |
| `9a5756a` | realistic holdout, VLAN detector rewrite |
| `bcf408e` | UI diagnosis, API integration tests |
| (next) | live runtime gate passed, correctness fixes |

Not pushed to GitHub, as required.
