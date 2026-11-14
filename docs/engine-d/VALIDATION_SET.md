# Blind Validation Set (Agent C)

`trident/labgen/validation_set.py` defines ten new labs for blind measurement of
the diagnostic engine. Each lab carries a **private** ground-truth manifest
(device, interface, kind, expected, actual, symptom) and a set of observable
requirements stating which end-to-end checks must pass or fail.

## These labs are new

These ten cases were authored for this validation set. They were **not** used to
tune, train, or regression-test any detector, and the engine had not seen them
before this file existed. They deliberately use different addressing, device
counts and topology shapes from `gauntlet`, `broken_campus` and `ccna3`.

## Scoring convention

* **Faulted cases:** exactly 100 points, rebalanced so the total is exact.
* **Clean controls:** zero faults, zero points.

There is no third convention: a clean case never carries a scored defect, and a
faulted case never totals 99 or 101.

## Cases

| # | Case | Devices | Links | Faults | Intent summary |
|---|------|--------:|------:|-------:|----------------|
| 1 | `clean-baseline` | 6 | 5 | 0 | Two routers, one transit, one LAN each; PC1/PC2 reach PC3 and back. |
| 2 | `clean-segmented` | 7 | 6 | 0 | Two business segments on one transit; each is healthy, neither is routed to the other. |
| 3 | `wrong-gateway` | 6 | 5 | 2 | PC1's gateway is `172.16.30.254`, a real-subnet address nobody owns; R2's return route also has an off-subnet next hop. |
| 4 | `missing-static-route` | 7 | 6 | 1 | Hub R1 has no route to spoke LAN `172.16.42.0/24`; the other spoke still works. |
| 5 | `wrong-next-hop` | 6 | 5 | 1 | R1's route to `172.16.52.0/24` points at `10.10.50.9`, outside the /30 transit. |
| 6 | `broken-return-path` | 6 | 5 | 1 | R1 forwards to LAN-B, but R2 has no route back to LAN-A, so replies die. |
| 7 | `admin-shutdown` | 5 | 4 | 1 | SW1's uplink to the edge switch is administratively down; PC2 is isolated. |
| 8 | `vlan-mismatch` | 4 | 3 | 1 | PC2's access port is in VLAN 20 while its subnet and the router uplink are VLAN 10. |
| 9 | `acl-deny` | 4 | 3 | 1 | ACL 110 should permit clients to servers; the permit is replaced by `deny ip any any`. |
| 10 | `multi-fault` | 7 | 6 | 3 | Wrong VLAN on SW1, missing route on R1, and an ACL deny on R2, each on a different device. |

Totals: 10 cases, 58 devices, 48 links, 11 injected faults (two clean controls
have zero faults).

## Public and private surfaces

* `blind_manifest()` returns per case: case name, title, difficulty, brief,
  device inventory, links and observable requirements. It contains no fault
  list, no fault identifiers, no expected/actual pairs, no symptoms and no
  hints.
* `ground_truth()` returns the private manifests used by the grader. Tests also
  assert that each manifest's `fault_count` matches the spec and that every
  fault record has a non-empty device, kind, expected and actual value.

## Known simulator limitation

`pkt_core` 0.2.2 does not write `<ENGINE><GATEWAY>`, so a PC default gateway may
not survive a Packet Tracer load. `wrong-gateway` therefore carries a second,
independent routing fault and records this limitation in its manifest notes. No
case's only value is a gateway fault.

End-host faults (`TargetKind.ENDHOST`) are declared in the spec and recorded by
`faulted_configs`, but the faulty NIC value is authored directly into
`DeviceSpec.pc_ip` because the builder does not rewrite NIC fields after
construction. This is stated in the manifest notes rather than hidden.

## Test coverage

`tests/test_validation_set.py` runs offline and never starts Packet Tracer:

* every case validates, follows the 100/0 scoring convention, cables every
  device and never uses a port twice;
* `faulted_configs()` applies every declared fault without
  `FaultApplicationError`;
* generation round-trips with matching device names when `pkt_core` is
  available (skipped otherwise), with a unique temporary path per case;
* both clean controls produce zero findings from `trident.diagnostics.diagnose()`;
* the blind manifest carries no answer-key keys or actual values;
* the ground truth is complete for every fault and every requirement states
  `pass` or `fail`.

Run only this file:

```sh
python -m pytest tests/test_validation_set.py -q
```
