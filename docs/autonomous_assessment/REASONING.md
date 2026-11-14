# Assessment Reasoning: Visible Requirements to Testable Intent

This layer sits between the text a student can see in a practice lab and the
verifier in `trident.engined`. It answers two questions in order:

1. **What was actually asked?** (`requirements.py`)
2. **Where does the network fail that request?** (`diagnose.py`)

It does not reimplement reachability, ACL evaluation, VLAN path analysis, or
status semantics. All of that belongs to Engine D and is reused unchanged.

```
visible instruction text
        |
        v
parse_requirements() -> list[ParsedRequirement]      # decomposition
        |
        v
to_intent(parsed, model) -> NetworkIntent            # resolution
        |
        v
verify_intent(model, intent) -> IntentReport         # Engine D
        |
        v
diagnose(model, parsed) -> AssessmentDiagnosis       # reduction
```

## 1. Decomposition: six phrasings, no guesses

A requirement is only produced when a supported phrasing matches. The supported
set is deliberately small, because it is what the practice labs and the
evaluation corpus actually say:

| Visible phrasing | Parsed as |
|---|---|
| `PC-A can ping PC-B`, `PC1 must reach SRV1`, `PC-A must be able to ping PC-B` | reachability (`Requirement` with no assertion) |
| `VLAN 10 must remain isolated from VLAN 20`, `VLAN 10 must not reach VLAN 20` | isolation (`must_not_reach=True`) |
| `PC-A must not reach PC-B`, `PC-A cannot ping PC-B` | isolation between two devices |
| `R1 must have a route to 10.5.4.0/24` | assertion `route`, operand the prefix |
| `SW1 FastEthernet0/2 must be enabled`, `... must be up`, `... must be no shutdown` | assertion `interface_up` |
| `SW1 Fa0/2 must be in VLAN 10`, `... must be assigned to VLAN 10` | assertion `vlan_membership` |
| `PC-A gateway must be 10.1.1.1`, `PC-A's gateway is 10.1.1.1` | assertion `gateway` |

### What this layer refuses to guess

Anything outside the table becomes a `ParsedRequirement` with:

```python
parsed=False
assertion=None
kind="unparsed"
raw=<the original line>
```

It is never converted into a reachability check, a route check, or a default
route. Examples that are intentionally left UNPARSED:

* `Enable OSPF on all routers` — "enabled" has no single assertion.
* `PC1 can ping its default gateway` — "its gateway" is not a device name; the
  model would have to decide which endpoint was meant.
* `ISP-EDGE holds no route to a private network` — a negative route assertion,
  which the verifier does not support.
* `R1 has a default route via 203.0.113.1` — the phrasing names a specific next
  hop, but the `route` assertion only tests coverage. Parsing it would silently
  drop the `via` clause, so the line is left alone.

Coverage makes the refusal visible:

```python
coverage(parsed, model)
# {"total": 8, "parsed": 7, "unparsed": 1,
#  "unresolvable": 1, "testable": 6}
```

`parsed` counts matched lines **including** unresolvable ones. `testable` is
what Engine D can actually evaluate. The gap between them is the point: a model
gap cannot hide inside one "parsed" number.

## 2. Resolution: the model decides names, not the text

`to_intent(parsed, model)` resolves every named device against the model
(`find_device` when available, exact names otherwise). Interface operands are
resolved through the model too, expanding abbreviations such as `Fa0/2` to the
model's own `FastEthernet0/2`.

Resolution never invents:

* An **unknown device** makes the requirement *unresolvable*, not dropped. The
  object stays in the caller's list with a reason, and `diagnose` reports it in
  `unsupported` / `unresolvable`.
* An **unknown interface** is not turned into a fault. The operand is passed
  through and Engine D returns `INCONCLUSIVE` ("interface is not in the model"),
  which is recorded as inconclusive, never as a failure.
* **VLAN isolation** resolves to concrete endpoint pairs that are actually
  attached to those VLANs. If either VLAN has no addressed endpoint, the
  requirement is unresolvable rather than tested against an empty set.

## 3. Diagnosis: findings only for failed requirements

`diagnose` iterates the requirements and verifies each one. The false-positive
guard is structural, not a filter:

> With no requirement, there is nothing to fail.

A missing route on a network nobody asked about is never reported. The tests
build exactly that network (`R1` has no route to `10.0.2.0/24`) and assert zero
findings both with an empty requirement list and with a line that parsed as
UNPARSED.

Status handling:

| Verdict status | Result |
|---|---|
| `VERIFIED` (live observation agrees, requirement failed) | finding, confidence `HIGH` |
| `DERIVED` (static analysis, requirement failed) | finding, confidence `MEDIUM` |
| `CONTRADICTED` (live disagrees) | finding, confidence `LOW` |
| `INCONCLUSIVE` | entry in `inconclusive`; **never** a pass, **never** a fault |
| `UNSUPPORTED` | entry in `unsupported` with the reason |

`passed` counts only `VERIFIED`/`DERIVED` verdicts that did not fail. An
inconclusive verdict contributes to neither side.

## 4. Findings and root causes

A `Finding` carries:

* the original requirement text;
* the deciding device and interface from the verdict;
* a category (`MISSING_FORWARD_ROUTE`, `ADMIN_SHUTDOWN`, `ACL_DENY`,
  `ISOLATION_VIOLATION`, `WRONG_GATEWAY`, ...);
* evidence copied verbatim from the verdict;
* confidence and explicit uncertainty reasons;
* a `proposed_correction` stating the expected value;
* the verdict status.

`root_causes()` groups findings by `(device, interface, category)`. Three hosts
behind one administratively-down transit port become **one** root cause with
three findings, because that is the smallest unit an operator can repair.

Evidence is never composed in this layer. A test asserts that every evidence
string on a finding is present in the verdict it points at
(`verdict_index`). If the verifier does not say it, the diagnosis does not say
it.

Corrections are derived from existing facts:

* missing route -> destination prefix and a real next hop taken from a
  neighbouring router interface already in the model;
* shut port -> `no shutdown` on the port named by the verdict;
* wrong gateway -> the expected address from the requirement and the actual
  value from the model;
* VLAN mismatch -> the expected VLAN and the VLANs the interface has now.

No correction names a device that is absent from the model.

## 5. Known limits

* The parser is phrase-based, not semantic. Re-worded instructions outside the
  table are reported as UNPARSED instead of being interpreted.
* Negative route assertions and next-hop-specific route statements are not
  supported and are refused rather than partially tested.
* Cross-VLAN isolation is tested with up to 16 representative endpoint pairs.
  This is a sampling decision for large labs, not a claim that every pair was
  traced.
* An interface named in the instructions but absent from the model yields
  `INCONCLUSIVE`, because the model cannot decide it — not a guessed fault.

## 6. Tests

`tests/test_assessment_requirements.py` covers every phrasing, the unparseable
refusals, unknown-device resolution, interface abbreviation, VLAN resolution,
and exact coverage counts.

`tests/test_assessment_diagnose.py` covers the healthy control, a missing
forward route with and without a requirement, an inconclusive requirement,
three victims behind one shut port, evidence provenance, confidence discipline,
and JSON serialisation. Models are hand-built dataclasses; no Packet Tracer
process is started.
