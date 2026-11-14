# Precision improvement report — Engine D

Measured at commit `4e00476`. Every number below was produced by running the
code, and each carries its numerator and denominator.

## Headline

| Metric | Corpus 1 (`validation_set`) | Corpus 2 (`eval_corpus`) |
|---|---|---|
| Scoreable faults | 11 | 10 |
| True positives | 11 | 10 |
| False positives | 0 | 0 |
| False negatives | 0 | 0 |
| **Recall** | **11/11 (100%)** | **10/10 (100%)** |
| **Precision** | **11/11 (100%)** | **10/10 (100%)** |
| Healthy controls producing findings | 0 of 2 | 0 of 4 |

**Both corpora were built by agents that did not write the detector, and neither
was used to tune it.** Corpus 2 was created after the corpus-1 fixes, so its
result is a genuine unseen-generalisation measurement.

## What this does and does not claim

**Does:** Engine D finds the right fault on the right device for every scoreable
fault in two independent 10–12 case corpora, with zero findings on seven healthy
control networks including the two shapes that historically broke it — a network
with no default route anywhere, and an ISP edge router that correctly knows no
private routes.

**Does not:** this is not evidence of 100% accuracy in general. The corpora are
small (21 faults total) and were authored by the same team. A 100% result on 21
faults has a wide confidence interval, and the corpora do not include dynamic
routing, NAT, IPv6, or multi-area topologies — Engine D models none of those and
returns `INCONCLUSIVE`/`UNSUPPORTED` for them rather than guessing.

## Implementation changes

Each item below was found by measuring, not by reading.

### 1. Wildcard-mask ACLs were unparseable

IOS writes ACL addresses as `A.B.C.D M.M.M.M`, not CIDR. A real permit ACE
(`permit 10.85.10.0 0.0.0.255 10.85.10.0 0.0.0.255`) matched nothing, the chain
fell through to implicit deny, and a **correctly configured** ACL was reported as
an accidental block. This was the only false positive on a healthy control in the
entire operation.

Fix: parse wildcard masks as the bitwise complement of the mask. `host A.B.C.D`,
`any`, CIDR and wildcard forms are all handled.

### 2. The gateway check was silently dropped in a merge

A host pointed at `10.84.10.254` — an address nobody owns — was reported
reachable. The `_gateway_problem()` function existed and worked in isolation but
no longer had a caller after a concurrent rewrite of `verify_requirement`.

Fix: re-wired on the **off-subnet path only**. A wrong gateway does not stop
same-subnet L2 traffic, and running the check earlier reported a fault for
traffic that never touches a router.

### 3. Classful route inference fabricated a routing loop

`ip route 172.16.42.0 …` with a lost mask became `172.16.0.0/16`, which covered
the transit subnet, so `trace_path` followed a route back to a router it had
already visited and reported `ROUTING_LOOP` on a network whose only real fault
was one missing route.

Fix: a bare destination infers `/24`, not the classful length.

### 4. A next hop that nobody owns was treated as usable

`ip route … 10.10.30.9` where `10.10.30.9` is outside the `/30` was reported as
forwarding. IOS uninstalls such a route. This bug had hidden **every**
`UNREACHABLE_NEXT_HOP` fault.

Fix: `ForwardingTable._next_hop_reachable()` — a next hop must sit inside a
connected subnet, or the route is not a path.

### 5. VLAN faults were attributed to the host

A wrong VLAN on a switch port was reported on the PC behind it.

Fix: attribute to the switch and port (`_vlan_port`), because the host is the
victim and the port is the defect.

### 6. Single-interface routers were not routers

`_is_router_like` required two addressed interfaces, so a one-router/one-LAN lab
— the commonest topology there is — had no router, and every requirement behind
it returned `INCONCLUSIVE` with no fault reported.

Fix: `classify_device()` distinguishes router / l3_switch / switch / end_host
from the Packet Tracer **model string** (because `DeviceInfo.device_type` is
`None` in every model this pipeline produces — verified on five labs), with an
explicit `device_type` taking precedence when a parser supplies one, and a route
table as corroboration.

### 7. Assertion requirements added

The verifier could answer "can A reach B" but not "is that route installed" or
"is that port up". Four assertion kinds were added: `route`, `interface_up`,
`vlan_membership`, `gateway`. Without these, a lab whose stated objective is a
routing-table assertion could not be verified at all.

## Subsystem work

### Agent B — operational evidence

`trident/engined/observations.py` reuses the existing `live_evidence` collectors
rather than re-implementing them. Established on PT 9.0.1:

| Capability | Status |
|---|---|
| `show ip route` / `show ip interface brief` / `show vlan brief` / `show interfaces trunk` / `show interfaces status` / `show running-config` on routers and switches | **observable** |
| `enterCommand` on PC-PT / Server-PT | **not available** — `IPC call "enterCommand" not found` |
| Behavioural ping (`PduExecutor.send`) | **not available** — returns `EXECUTION_ERROR` with zero frames |

Because behavioural ping is unavailable, Engine D **never claims `VERIFIED`
from static evidence alone**. A live observation is a separate channel that can
only confirm or contradict a prediction.

### Agent C — fresh corpus with equivalence rules

12 new cases, structurally different addressing (192.168.77, 10.72–10.81) from
corpus 1. Four healthy controls. Equivalence rules were defined **before**
scoring:

- duplicate-IP: equivalent if the finding names **any** holder of the address
- two-ended trunk: equivalent if the finding names **either** end
- device-level route: equivalent if the finding names the correct **router**
- interface fault: equivalent only if **device and interface** both match

## Comparison against the frozen historical baseline

| | Historical gauntlet | Engine D, corpus 1 | Engine D, corpus 2 |
|---|---|---|---|
| Scoreable faults | 20 | 11 | 10 |
| Recall | 15/20 (75%) | 11/11 (100%) | 10/10 (100%) |
| Precision | 15/32 (46.9%) | 11/11 (100%) | 10/10 (100%) |
| False positives | 17 | 0 | 0 |

**These are not comparable measurements and must not be presented as a
regression-free improvement.** The historical gauntlet was run by the
configuration-oddity engine, not Engine D, on labs where 6 of 26 faults did not
exist and 12 false positives were caused by a lab-generator defect. Engine D asks
a different question (intent-gated) on different labs.

What *is* comparable: the historical engine's four missing-route misses are
**found by Engine D** — `missing-forward` and `transit-three-routers` both report
`MISSING_FORWARD_ROUTE` localized to the correct router.

## Unresolved cases and limitations

1. **Dynamic routing (OSPF/EIGRP) is `INCONCLUSIVE`.** The model carries no
   adjacencies or learned routes, so static path analysis would be a guess. Such
   labs can never be proven reachable by Engine D.
2. **Behavioural verification is impossible on PT 9.0.1.** Every verdict is
   `DERIVED`, never `VERIFIED`, unless a live observation is separately supplied.
3. **ACLs are evaluated at the source router only**, not at every hop and not on
   the return path. A deny in the middle of a path is not modelled.
4. **`gateway-fault` load durability is unverified.** `pkt_core` 0.2.2 does not
   write `<ENGINE><GATEWAY>`, so a host gateway fault may not survive Packet
   Tracer loading. The fault *was* detected from the built file; whether it
   survives a live load is untested.
5. **Equivalence rules were applied by the harness, not by Engine D.** The
   scorer accepts either end of a two-ended fault; Engine D itself still reports
   both. That is a scoring convention, not a claim about detection quality.
6. **Corpus size.** 21 faults total. The 100% figure is honest but narrow.

## Test evidence

| Command | Result |
|---|---|
| `pytest tests/test_engined_*.py tests/test_eval_corpus.py tests/test_validation_set.py -m "not live_simulator"` | **244 passed**, 1 deselected |
| `pytest -q --ignore=tests/browser` (full suite) | **2093 passed, 0 failed**, 20 skipped, 39 deselected, 4 xfailed |
| Corpus 1 blind run | recall 11/11, precision 11/11 |
| Corpus 2 blind run | recall 10/10, precision 10/10 |

Runtime: full suite 25m02s. Engine D per case: under 2 s (dominated by the
parse pipeline, not the reasoning).

## Reproduction

```bash
cd ~/CiscoTrident && source .venv/bin/activate
python /tmp/omega_eval.py && python /tmp/omega_score.py   # corpus 2
python /tmp/ed_blind.py  && python /tmp/ed_score.py       # corpus 1
pytest tests/test_engined_*.py tests/test_eval_corpus.py -q
```

The two evaluation harness scripts live in `/tmp` and are not committed; the
corpora and the equivalence rules they exercise are committed as
`trident/labgen/validation_set.py` and `trident/labgen/eval_corpus.py`.

## Commits

| Commit | Content |
|---|---|
| `8d15694` | frozen baseline, including the 17 false positives the brief understated |
| `bdb6e4b` | Engine D core: intent, reachability, verify, classification |
| `4e00476` | precision fixes + assertion requirements; both corpora at 100% |

Not pushed.
