# EVAL_CORPUS — a second, independent evaluation set

`trident/labgen/eval_corpus.py` is a **new** twelve-case corpus and an
equivalence-aware scorer. It is separate from `validation_set`, the six-level
gauntlet, Broken Campus and the CCNA3 labs: different addressing, different
device counts, different topology shapes.

> This corpus was authored after `validation_set` and was **not used to tune any
> detector**. No accuracy figure measured here is a restatement of a figure
> measured there. It is a measurement instrument, not a regression suite written
> beside the engine.

Conventions:

- A faulted case scores **exactly 100 points**.
- A control carries **zero faults** and zero points.
- `blind_view(name)` exposes topology + requirements only.
- `ground_truth(name)` returns the private manifest: every fault with device,
  interface, kind, expected and actual, plus `requirements` and `control`.

## The twelve cases

| # | Case | Control | Devices | Links | Faults | Points |
|---|------|:-------:|---------|-------|--------|--------|
| 1 | `healthy-single-router` | yes | 4 (1 router, 1 switch, 2 PC) | 3 | 0 | 0 |
| 2 | `healthy-no-default` | yes | 7 (2 router, 2 switch, 3 PC) | 6 | 0 | 0 |
| 3 | `isp-edge-legit` | yes | 6 (3 router, 1 switch, 2 PC) | 5 | 0 | 0 |
| 4 | `missing-forward` | no | 7 (2 router, 2 switch, 3 PC) | 6 | 1 | 100 |
| 5 | `missing-return` | no | 7 (2 router, 2 switch, 3 PC) | 6 | 1 | 100 |
| 6 | `wrong-next-hop` | no | 7 (2 router, 2 switch, 3 PC) | 6 | 1 | 100 |
| 7 | `admin-shutdown` | no | 7 (2 router, 2 switch, 3 PC) | 6 | 1 | 100 |
| 8 | `gateway-fault` | no | 7 (2 router, 2 switch, 3 PC) | 6 | 1 | 100 |
| 9 | `acl-intentional-isolation` | yes | 7 (1 router, 2 switch, 4 PC) | 6 | 0 | 0 |
| 10 | `acl-accidental-deny` | no | 7 (1 router, 2 switch, 4 PC) | 6 | 1 | 100 |
| 11 | `multi-fault` | no | 7 (2 router, 2 switch, 3 PC) | 6 | 3 | 100 (40+30+30) |
| 12 | `transit-three-routers` | no | 7 (3 router, 2 switch, 2 PC) | 6 | 1 | 100 |

### 1. `healthy-single-router` — control

One router, one access switch, two PCs on `192.168.77.0/24` (R1 Gi0/0 `.1`,
PC1 `.10`, PC2 `.11`). No faults. Requirements: PC1↔PC2, each PC reaches its
gateway. **A healthy LAN must produce zero findings.**

### 2. `healthy-no-default` — control

Two routers joined by `10.72.1.0/30`. LAN-A `10.72.11.0/24` (R1, PC1, PC2),
LAN-B `10.72.22.0/24` (R2, PC3). Each router has an explicit static route to the
far LAN; **neither router has a default route, and neither needs one.** This is
the shape that broke a naive "every router must have a default" heuristic. No
faults.

### 3. `isp-edge-legit` — control

Enterprise R1 (`10.73.10.0/24`, PCs) connects through `203.0.113.0/30` to
ISP-EDGE, which connects through `198.51.100.0/30` to ISP-CORE. R1 has a default
route via ISP-EDGE; ISP-EDGE has a default route via ISP-CORE. **ISP-EDGE holds
no private routes — that is correct**, because it is a public edge. No faults.
This is the control that a "router is missing private routes" heuristic fails.

### 4. `missing-forward` — 1 fault

LAN-A `10.74.10.0/24` (R1), LAN-B `10.74.20.0/24` (R2), transit `10.74.1.0/30`.
`F1` (R1, routing, 100): R1 lacks the forward route to `10.74.20.0/24`.

### 5. `missing-return` — 1 fault

LAN-A `10.81.10.0/24` (R1), LAN-B `10.81.20.0/24` (R2), transit `10.81.1.0/30`.
`F1` (R2, routing, 100): the forward route exists, but R2 lacks the return route
to `10.81.10.0/24`.

### 6. `wrong-next-hop` — 1 fault

LAN-A `10.82.10.0/24`, LAN-B `10.82.20.0/24`, transit `10.82.1.0/30`.
`F1` (R1, routing, 100): R1's route to LAN-B points at `10.82.1.9`, an address
on no connected subnet.

### 7. `admin-shutdown` — 1 fault

LAN-A `10.83.10.0/24`, LAN-B `10.83.20.0/24`, transit `10.83.1.0/30`.
`F1` (R1 `GigabitEthernet0/1`, interface, 100): the transit interface is
administratively shut down.

### 8. `gateway-fault` — 1 fault

LAN-A `10.84.10.0/24`, LAN-B `10.84.20.0/24`, transit `10.84.1.0/30`.
`F1` (PC2, gateway, 100): PC2's default gateway is `10.84.10.254`, not the
router's `10.84.10.1`. The faulty value is authored directly into the NIC
because `pkt_core` cannot rewrite an end-host field after the spec is built.

**load-durability: unverified.** `pkt_core` 0.2.2 does not write
`<ENGINE><GATEWAY>`, so this fault may not survive a Packet Tracer load. It is
recorded in the manifest and still built.

### 9. `acl-intentional-isolation` — control

One router serves DEPT-A `10.85.10.0/24` (A1, A2) and DEPT-B `10.85.20.0/24`
(B1, B2). Isolation is expressed as permit-list ACLs (`100` on Gi0/0, `101` on
Gi0/1) whose implicit deny blocks the A↔B pair. The isolation is **intended and
correct**. No faults. This is the control that an "any bound deny is a fault"
heuristic fails.

### 10. `acl-accidental-deny` — 1 fault

DEPT-A `10.86.10.0/24`, DEPT-B `10.86.20.0/24`, one router. `F1`
(R1 `GigabitEthernet0/0`, access, 100): the inter-department ACL entry is a
`deny` where the required policy is a `permit`, so A1 cannot reach B1.

### 11. `multi-fault` — 3 faults

LAN-A `10.87.10.0/24` (R1, PC1, PC2), LAN-B `10.87.20.0/24` (R2, PC3), transit
`10.87.1.0/30`. Three faults on three devices:

- `F1` (R1, routing, 40): missing forward route to LAN-B.
- `F2` (R2 `GigabitEthernet0/1`, interface, 30): transit interface shut down.
- `F3` (PC3, gateway, 30): wrong default gateway.

Total 40 + 30 + 30 = 100.

### 12. `transit-three-routers` — 1 fault

LAN-1 `10.89.10.0/24` (R1, PC1), TRANSIT-12 `10.89.12.0/30` (R1↔R2),
TRANSIT-23 `10.89.23.0/30` (R2↔R3), LAN-3 `10.89.30.0/24` (R3, PC3). `F1`
(R2, routing, 100): the middle router is missing its route to LAN-3.

## Equivalence-aware scoring

A finding is a claim about where a defect lives, and two claims can name the
same defect from different, equally correct angles. The rules are fixed before
scoring and live in the module:

```python
DEFAULT_RULES = {
    "duplicate_ip_any_holder": True,
    "trunk_either_end": True,
    "device_route_ignore_interface": True,
    "interface_requires_both": True,
    "kind_aliases": {},
}
```

Kind compatibility is a gate before any attribution rule. Kinds match exactly
unless `rules["kind_aliases"]` maps a truth kind to acceptable synonyms.

### Rule a — duplicate IP, any holder

> A duplicate-address fault is equivalent when the finding names **any** holder
> of the duplicated address. Both interfaces are genuinely wrong; naming the
> second one is not an error. `truth` may carry `holders` (a list of device
> names); when it does, membership decides.

### Rule b — two-ended trunk, either end

> A trunk fault exists on a link, and both ends are true statements about it.
> The finding matches when it names **either** endpoint. `truth` may carry
> `ends` (`[{device, interface}, ...]`).

### Rule c — device-level route, router only

> A static-route fault is a property of the **router's routing table**, not of
> one interface. When the finding names the correct router, the interface field
> is ignored. The device must match.

### Rule d — interface fault, device and interface

> An interface fault is equivalent **only** when both the device and the
> interface match. Nothing weaker counts.

Anything else (gateway, ACL, VLAN, DHCP, DNS, …) is device-level: the device
must match, and if the truth names an interface it must match too.

### `score(predictions, truth)`

`predictions` maps a case name to a list of findings. `truth` maps a case name
to a manifest (with `faults`) or a fault list. `score` returns:

- `tp`, `fp`, `fn` — integer totals, plus per-case `cases[name]`;
- `recall` — `{numerator: tp, denominator: tp + fn}`;
- `precision` — `{numerator: tp, denominator: tp + fp}`;
- `correct_device` — `{numerator, denominator: tp}`;
- `correct_interface` — `{numerator, denominator: number of truth faults that
  name an interface}`.

It **never** returns a bare percentage.

## Verification

`tests/test_eval_corpus.py` is offline only and asserts:

- all twelve cases exist and are valid specs;
- controls have zero faults; faulted cases total exactly 100 points;
- `faulted_configs()` applies every fault with no `FaultApplicationError`;
- `generate()` round-trips all twelve when `pkt_core` is available, one unique
  temp file per case;
- every clean control produces zero findings from
  `trident.diagnostics.diagnose()`;
- `blind_view()` carries no `actual`/`expected`/`kind` fault data;
- rules a, b, c and d each with hand-built pairs;
- `score()` arithmetic exactly on perfect, one-FP and one-FN scenarios.
