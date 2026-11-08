# Fault-Injection Practice Laboratory

Phase 2 · `trident/faultlab/`

A diagnostic engine that is never tested against a known answer is not a
diagnostic engine — it is an opinion. This module manufactures networks with
**known** defects and grades an engine on whether it finds the actual root
cause.

> **The scenarios are synthetic.** Every network is constructed in memory from
> `baseline_lab()`. These are *not* Packet Tracer `.pkt`/`.pka` files, not
> captures from real equipment, and not parser fixtures. The topology is
> invented so that each defect has exactly one attributable cause.

```python
from trident.faultlab import grade, scenarios

for scenario in scenarios():
    report = my_engine.diagnose(scenario.model)   # hand ONLY the model over
    result = grade(scenario, report)
    print(f"{scenario.name:26} score={result.score:.2f} exact={result.exact_match}")
```

---

## 1. The two halves that must never touch

```python
@dataclass(frozen=True)
class Scenario:
    name: str
    model: NetworkModel        # the faulty network — the only thing a solver sees
    faults: tuple[Fault, ...]  # THE ANSWER KEY — never passed to the solver
    single_fault: bool
```

The laboratory is split along one hard boundary:

| Object | Who may see it | What it carries |
| --- | --- | --- |
| `Scenario.model` | the diagnostic engine under test | an ordinary `NetworkModel` whose *values* are wrong |
| `Scenario.faults` | the grader, and a human reading the answer key | the manifest: what was injected and why |

### Rule 1 — the manifest is not on the wire

`inject()` builds a plain `NetworkModel` and writes **only ordinary field
values** into it. It never adds:

* a new attribute, field, or extra model key;
* a `warnings` or `snapshot_notes` entry;
* a `Provenance` record;
* a device description, interface description, or `raw_config` line that names
  the defect.

The test suite enforces this by dumping `scenario.model` to JSON and asserting
that no `FaultKind` value, no `fault_id`, no `description` and no
`expected_symptom` string appears anywhere in the payload
(`tests/test_phase2/test_faultlab.py::test_model_does_not_leak_the_manifest`).
It also asserts that the model exposes no attribute outside
`NetworkModel.model_fields`.

A defect is therefore discoverable only by **inference** — comparing the
observed configuration against what a correct configuration would be. That is
precisely the skill the lab is meant to measure.

### Rule 2 — precision is scored as strictly as recall

Every reported kind that is not in the manifest is *spurious* and reduces the
score. An engine cannot win by reporting all eleven kinds, and it cannot win by
reporting one thing it half-believes.

---

## 2. Public surface

Everything below is exported from `trident.faultlab`:

```python
from trident.faultlab import (
    FaultKind, Fault, Scenario, Grade,
    baseline_lab, inject, inject_many, scenarios, grade,
    InjectionError, BASELINE_SNAPSHOT,
)
```

### `FaultKind`

A `StrEnum` of defect *classes*, not instances:

| Value | What is wrong |
| --- | --- |
| `WRONG_VLAN` | An access port is in a VLAN that does not match its host's subnet. |
| `INVALID_MASK` | An interface carries a mask that is not a legal, contiguous subnet mask. |
| `WRONG_GATEWAY` | A host's default gateway is not a live LAN interface. |
| `MISSING_STATIC_ROUTE` | A required static route is absent from the routing table. |
| `SHUTDOWN_INTERFACE` | An interface is administratively down. |
| `ACL_BLOCK` | An ACL bound to an interface drops traffic that should pass. |
| `TRUNK_MISMATCH` | Two ends of a trunk disagree about which VLANs are allowed. |
| `ROUTING_LOOP` | A static route sends traffic back along the path it arrived on. |
| `DHCP_MISCONFIGURATION` | A DHCP pool hands out a gateway or network that cannot work. |
| `DUPLICATE_IP` | Two hosts on the same segment claim the same address. |
| `OVERLAPPING_SUBNET` | Two interfaces on one router have overlapping connected networks. |

Grading compares **kinds**. A scenario therefore may not contain two faults of
the same kind — `Scenario.__post_init__` rejects that, because kind-level
grading could not tell the duplicates apart.

### `Fault`

```python
@dataclass(frozen=True)
class Fault:
    fault_id: str
    kind: FaultKind
    device: str
    interface: str | None     # None for device-level defects (gateway, DHCP, route)
    description: str          # for the human reading the key
    expected_symptom: str     # what a user would observe
```

### `Scenario`

Frozen dataclass. Validates its own consistency on construction:

* `single_fault=True` requires exactly one fault;
* `single_fault=False` requires at least two;
* fault kinds within a scenario must be distinct.

### `baseline_lab() -> NetworkModel`

Returns a **fresh** defect-free reference network on every call. Nothing is
cached and nothing is shared, so `inject()` can never contaminate a previously
returned model.

Topology (synthetic):

```
                 203.0.113.0/30
                       |
                     [R1]
                       | Gi0/1 ── Fa0/24 [SW1] Gi0/1 ══ Gi0/1 [SW2]
                                                        │
                                          ┌─────────────┼──────────────┬─────────┐
                                        Fa0/1         Fa0/2        Fa0/3     Fa0/4
                                        [PC1]         [PC2]        [SRV1]     │
                                              VLAN 20 (10.10.20.0/24)        [R2] Gi0/0
                                                                             │
                                                                          Gi0/1 10.10.10.0/24
```

Addressing:

| Network | Use |
| --- | --- |
| `203.0.113.0/30` | R1 WAN link |
| `10.10.10.0/24` | R1 ↔ R2 transit (VLAN 10) |
| `10.10.20.0/24` | user VLAN 20 behind R2 |

### `inject(fault) -> NetworkModel`

Starts from a fresh `baseline_lab()`, applies **exactly one** defect, and
returns the result. It raises `InjectionError` when the fault names an entity
that is not in the lab, so a typo in a scenario definition fails loudly instead
of silently producing a clean network that would grade every engine as wrong.

`inject_many(faults)` applies several defects and rejects two faults that target
the same `(device, interface)`, since the second would mask the first.

### `scenarios() -> tuple[Scenario, ...]`

Returns the built-in catalogue. Each call rebuilds fresh `Scenario` objects.

### `grade(scenario, reported) -> Grade`

```python
@dataclass(frozen=True)
class Grade:
    scenario: str
    found_kinds: tuple[FaultKind, ...]     # present and reported
    missed_kinds: tuple[FaultKind, ...]    # present, not reported
    spurious_kinds: tuple[FaultKind, ...]  # reported, not present
    exact_match: bool
    score: float                           # 0..1
```

`reported` is the shape a diagnostics engine naturally emits:

```python
[
    {"kind": "WRONG_VLAN", "device": "SW2", "interface": "FastEthernet0/1",
     "confidence": "high"},
]
```

Only `kind` is graded. `device`, `interface` and `confidence` are carried along
for a human reviewer but do not affect the score.

---

## 3. Scoring

Let

* `found` = manifest kinds the report named,
* `missed` = manifest kinds it did not name,
* `spurious` = kinds it named that are not in the manifest (including strings
  outside the taxonomy).

Then:

```
score = found / (found + missed + spurious)
```

Properties, each covered by a test:

| Report | found | missed | spurious | score | exact_match |
| --- | --- | --- | --- | --- | --- |
| all correct kinds | n | 0 | 0 | **1.0** | `True` |
| empty list | 0 | n | 0 | **0.0** | `False` |
| correct + one invented | n | 0 | 1 | n/(n+1) | `False` |
| all correct but one missing | n-1 | 1 | 0 | (n-1)/n | `False` |
| only wrong kinds | 0 | n | k | **0.0** | `False` |
| nothing expected at all | 0 | 0 | 0 | **0.0** | `False` |

Deliberate choices:

* **An empty report is safe.** It returns `0.0`; it never raises. A harness may
  call `grade` on a crashed engine without special-casing it.
* **Unknown kinds count as spurious.** Reporting `"POWER_SUPPLY_ON_FIRE"` is a
  wrong answer and costs one unit of the denominator; it is not silently
  ignored.
* **Duplicate entries collapse.** Reporting `WRONG_VLAN` three times is one
  claim, and scores exactly as one claim does.
* **A scenario with no faults can never score 1.0.** Otherwise an engine that
  reports nothing would look perfect on a clean network.
* `exact_match` additionally requires that the report named *only* real kinds,
  so `exact_match` and `score == 1.0` agree.

---

## 4. Scenario catalogue

Twelve scenarios ship: eleven single-fault and one two-fault.

| Name | Kind | Target | Expected symptom |
| --- | --- | --- | --- |
| `wrong-vlan` | `WRONG_VLAN` | SW2 Fa0/1 | PC1 sits in VLAN 30 while its address belongs to VLAN 20. |
| `invalid-mask` | `INVALID_MASK` | R2 Gi0/1 | Gateway mask `255.255.0.255` is non-contiguous; no prefix derives. |
| `wrong-gateway` | `WRONG_GATEWAY` | PC1 | Gateway `10.10.20.254` is not a live LAN interface. |
| `missing-static-route` | `MISSING_STATIC_ROUTE` | R1 | No route for `10.10.20.0/24`; WAN side cannot reach the LAN. |
| `shutdown-interface` | `SHUTDOWN_INTERFACE` | SW2 Fa0/2 | PC2's port is administratively down. |
| `acl-block` | `ACL_BLOCK` | R2 Gi0/1 | ACL 101 denies TCP/443 to `10.10.20.50`; ICMP still works. |
| `trunk-mismatch` | `TRUNK_MISMATCH` | SW2 Gi0/1 | Trunk allows 10 and 30 but not 20, while the peer allows all three. |
| `routing-loop` | `ROUTING_LOOP` | R2 | Static `10.10.10.0/24` points at `10.10.20.1`, back into the LAN. |
| `dhcp-misconfiguration` | `DHCP_MISCONFIGURATION` | R2 | Pool advertises gateway `10.10.20.254`. |
| `duplicate-ip` | `DUPLICATE_IP` | PC2 | Claims `10.10.20.10`, already held by PC1. |
| `overlapping-subnet` | `OVERLAPPING_SUBNET` | R2 Loopback0 | `10.10.20.129/25` overlaps R2 Gi0/1 `10.10.20.0/24`. |
| `dual-shutdown-gateway` | `SHUTDOWN_INTERFACE` + `WRONG_GATEWAY` | SW2 Fa0/3, PC2 | SRV1 is down *and* PC2 has a dead gateway. `single_fault=False`. |

All eight required single-fault families are present, plus three useful extras
(`ROUTING_LOOP`, `DHCP_MISCONFIGURATION`, `OVERLAPPING_SUBNET`) that exercise
route-table and device-level reasoning rather than interface-level mistakes.

The two-fault scenario exists to check that an engine which stops at the first
finding is penalised: reporting only one of its two faults scores `0.5`, not
`1.0`.

---

## 5. Using the lab in a test harness

```python
from trident.faultlab import grade, scenarios

failures = []
for scenario in scenarios():
    report = engine.diagnose(scenario.model)      # never pass scenario.faults
    result = grade(scenario, report)
    if not result.exact_match:
        failures.append((scenario.name, result))

for name, result in failures:
    print(f"{name}: score={result.score:.2f}")
    print(f"  found     {[k.value for k in result.found_kinds]}")
    print(f"  missed    {[k.value for k in result.missed_kinds]}")
    print(f"  spurious  {[k.value for k in result.spurious_kinds]}")
```

The engine is handed a model whose **values** are wrong but whose **shape** is
correct. Everything it needs is derivable: the mask is non-contiguous, the
gateway is outside the subnet, the trunk lists disagree, two interfaces claim
the same address. Nothing it needs is labelled.

### A note on `WRONG_GATEWAY` vs `DHCP_MISCONFIGURATION`

Both make a host point at `10.10.20.254`, because they are genuinely similar
faults seen from different layers: one is configured on the host, the other
handed out by the server. They are kept separate and never appear together in a
single-fault scenario, so an engine is never asked to distinguish them from the
same evidence.

---

## 6. Extending the catalogue

A new scenario is one entry in `trident/faultlab/scenarios.py`:

```python
Fault(
    fault_id="my-fault-01",
    kind=FaultKind.WRONG_VLAN,
    device="SW2",
    interface="FastEthernet0/1",
    description="...",
    expected_symptom="...",
)
```

Rules to respect when adding one:

1. **One kind per scenario.** Kind-level grading cannot separate duplicates.
2. **The fault must be observable in the model.** If `inject` cannot express it
   as changed field values, the engine could never find it.
3. **Do not write the answer into the model.** No description, warning, note or
   raw-config line may name the defect. The leak test will catch it.
4. **`inject` must be deterministic.** The same `Fault` must always yield the
   same model, or two runs of the harness disagree.

---

## 7. Tests

`tests/test_phase2/test_faultlab.py` covers:

* every required kind has a scenario, and the catalogue has at least eight
  single-fault entries;
* every scenario builds, has at least one fault, and has devices, interfaces
  and links;
* `inject` changes only the intended device/interface, verified by a recursive
  structural diff against a pristine baseline;
* shutdown flips both admin and operational state;
* `WRONG_VLAN` moves one port and leaves its neighbours alone;
* `MISSING_STATIC_ROUTE` removes exactly one route;
* `DUPLICATE_IP` produces an address collision with an existing host;
* `inject` rejects unknown entities and never mutates the caller's scenario;
* the model JSON leaks no fault kind, fault id, description or expected
  symptom, and gains no attribute outside `NetworkModel.model_fields`;
* perfect report → `1.0`, `exact_match=True`;
* empty report → `0.0`, no exception;
* one spurious extra → `0.5` on a single-fault scenario;
* one missed fault → `0.0` on a single-fault scenario;
* duplicates deduplicate; unknown kinds count as spurious;
* the two-fault scenario needs **both** faults for `1.0` and scores `2/3` with
  an extra invention;
* `grade` is pure — it never mutates the scenario model.

Run them with:

```bash
.venv/bin/python -m pytest tests/test_phase2/test_faultlab.py -q
```
