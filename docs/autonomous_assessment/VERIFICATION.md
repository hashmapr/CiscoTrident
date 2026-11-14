# Independent verification and safe remediation

This document describes the adversarial layer that sits after diagnosis:

- `trident/assessment/verify_independent.py` — challenges the diagnosis.
- `trident/assessment/remediation.py` — turns confirmed faults into reversible changes.

Both consume the normalised model (`devices`, `interfaces`, `routes`, `links`,
`vlans`, `acls`) and the stated `NetworkIntent`. Neither starts Packet Tracer,
writes source files, or imports the diagnosis module at import time.

## 1. Why an adversarial layer at all

A diagnosis can be wrong in three ways:

1. it reports a fault that is not there;
2. it reports the right symptom on the wrong device or interface;
3. it misses a fault entirely.

A verifier that calls the same helper as the diagnosis only proves the helper is
deterministic. `challenge()` therefore re-derives every claim from the low-level
primitives in `trident.engined.reachability`: a fresh `ForwardingTable`,
`vlan_path`, `evaluate_acls`, `trace_path`, or a direct interface-state read.

## 2. Verification outcomes

`challenge(model, intent, findings) -> VerificationReport` produces five buckets.

| Bucket | Meaning |
| --- | --- |
| `confirmed` | Independently reproduced, and at least one claimed evidence string is present in the re-derivation. |
| `rejected` | The claim cannot stand: unknown device/interface, unknown requirement, INCONCLUSIVE basis, or the re-derivation disproves it. |
| `missed` | Faults found by independent scanning that the diagnosis did not report. |
| `alternative_explanations` | Evidence is insufficient to reproduce the claim; the report names what else could explain it. |
| `unsupported` | Things this layer cannot decide (dynamic routing, no explicit requirements). |

A finding is **never** confirmed on the basis of another agent's evidence. If it
cannot be reproduced it goes to `alternative_explanations`, even when it looks
plausible.

### Rejection rules

A finding is rejected when any of the following holds:

- the device is not in the model;
- the named interface does not exist on the device;
- the cited requirement is neither an exact intent label nor resolvable by the
  endpoint device names it mentions;
- the finding is INCONCLUSIVE-based (`status`, `confidence`, `uncertainty`, or a
  kind/detail that says so);
- the independent derivation succeeds but the claimed evidence is absent from it;
- the independent derivation actively disproves the claim (for example, the ACL
  permits the flow, the route exists, the interface is up).

`diagnose.Finding.requirement` stores the *raw* requirement text, which need not
equal our canonical `"src -> dst"` label. Rather than reject every such finding,
the verifier falls back to matching the endpoint device names in order, and only
rejects when that finds nothing and `affected` gives no match either.

## 3. False-negative scanning

The `missed` bucket is produced by scanning the required paths independently of
the findings:

1. **Administratively-down interfaces on a required path** — every hop the
   independent `trace_path` visits, plus the port a VLAN path crosses.
2. **Access-port VLAN versus host subnet mismatch** — a host and the gateway that
   serves its VLAN must share a subnet.
3. **Default gateways no interface owns** — the host's configured gateway must be
   an address the model actually assigns.
4. **Next hops outside every connected subnet** — IOS does not install those
   routes; the device holding one is named.
5. **VLAN-path blockers** — missing VLAN, trunk not permitting the VLAN, no
   router serving the VLAN, and down inter-switch links.

An interface already named by any finding is not reported again as `missed`, so
the same fault cannot inflate the count twice.

## 4. Remediation safety guarantees

### Read-only is the default

`read_only_plan(findings)` returns markdown and **writes nothing**. It is the
default path in the orchestrator; applying changes requires an explicit
`apply_to_copy` call.

### The source is never modified

`apply_to_copy(spec, changes, dest)`:

1. loads the source into memory (path, `TopologySpec`, mapping, or `None`);
2. hashes the source before any work;
3. deep-copies the config and applies every change to the copy;
4. writes a **distinct** destination — a destination that resolves to the source
   is refused with `ValueError`;
5. re-hashes the source and the original snapshot, and raises `RuntimeError` if
   either changed.

`ChangeLog.source_unchanged` records the before/after comparison.

### Every change is reversible

Each `ChangeRecord` stores `(device, interface, kind, old, new)` and the old
value is never `None` (an absent line is recorded as `"(not present)"`). The
`ChangeLog` also stores the exact original payload bytes, so `rollback(log)`
restores the copy byte-for-byte. `rollback` re-checks the source hash first and
refuses if the source moved underneath it.

### One change per root cause

`plan()` keys changes on `(device, interface, kind, proposed)`. Two findings that
describe the same shut port for different victim requirements collapse to one
`no shutdown`. A finding with no device produces no change, and no correction
value is invented: when a route or gateway value is unknown, `proposed` stays
`None` and the read-only plan says an operator must supply it.

### Regressions are not fixes

`verify_remediation(original_findings, post_findings)` returns:

- `fixed` — original root causes that disappeared;
- `still_broken` — original root causes still present;
- `introduced_regressions` — new root causes.

A new finding is attributed to a disappeared finding on the same device (or the
same affected requirement). When that happens the disappeared finding is **not**
counted as `fixed`; it is reported as part of the regression. This prevents
"fixed 1, broke 1" from being scored as a success.

## 5. Limitations (what this layer cannot verify)

- **Dynamic routing.** OSPF/EIGRP/RIP/BGP adjacencies and learned routes are not
  modelled. Any routed finding involving such a device is listed in
  `unsupported` rather than guessed at.
- **Live state.** Static analysis cannot see ARP, STP convergence, DHCP leases,
  NAT translations, or a cable that is physically unplugged but modelled as up.
  A finding that depends on those facts lands in `alternative_explanations`.
- **Raw requirement phrasing.** Fuzzy requirement matching uses device names. If
  two requirements share the same endpoint pair with different operands, the
  match is ambiguous and the finding is not silently attached to one of them.
- **Text-level remediation only.** `apply_to_copy` edits IOS config text. It does
  not encode a `.pkt`, does not update VLAN databases stored outside the text,
  and does not verify the result in Packet Tracer.

## 6. Tests

`tests/test_assessment_verify.py` covers:

- a true finding confirmed by independent re-derivation;
- a finding naming an absent interface rejected with a reason;
- a finding citing a requirement outside the intent rejected;
- an INCONCLUSIVE-based finding rejected;
- a shut interface missing from the diagnosis reported in `missed`;
- confirmed findings distinguished from `alternative_explanations`.

`tests/test_assessment_remediation.py` covers:

- one change per root cause, not one per victim;
- the source file hash unchanged by `apply_to_copy`;
- an old value recorded for every change, and `rollback` restoring it;
- a clean fix counted as `fixed`;
- a new finding counted as a regression, not a fix;
- `read_only_plan` with no side effects;
- refusal to write over the source;
- operation with no source bundle (`None`).
