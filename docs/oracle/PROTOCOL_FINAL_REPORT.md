# ORACLE PROTOCOL FINAL REPORT

Branch `development/deepcore`. RC `trident-stream-verify-rc1` at `9d14807`, untouched.

| | Commit |
|---|---|
| Starting | `00c1fd8` |
| Ending | `0c416cf` |
| Milestones | 6 |

---

## 1. Completed

### Typed IOS semantics — `d124e5a`

`trident/deepcore/protocols.py`: typed models for STP, EtherChannel, NAT and IPv6.

Two rules in code, not comments:

- **Absence is not a default.** An unstated bridge priority is `None`, never
  32768. `DEFAULT_BRIDGE_PRIORITY` is a named constant so the reasoning layer has
  to opt in deliberately, and any prediction built on it says so.
- **Unrecognised protocol lines are preserved** verbatim, so a reader can see a
  command existed rather than concluding it never did.

Interface context is tracked; `no` forms clear settings. VLAN lists expand
(`1,10-12` → 1,10,11,12). ACL names keep their case, because IOS matches them
case-sensitively.

### STP — `66794f3`

Root election by priority then MAC; port roles by topology and cost.

Where evidence is missing the answer is `UNDECIDED` with the missing fact named:
a priority tie with no MAC, an equal-cost link away from the root, a link whose
both ends are one bridge. The root's own ports are designated regardless of cost,
decided before cost is consulted.

### EtherChannel — `bfa4754`

Full negotiation matrix. `active/active` and `active/passive` over LACP;
`desirable/desirable` and `desirable/auto` over PAgP; `on/on` only with itself.
Both-passive and both-auto are refused *with the reason*. LACP against PAgP cannot
form.

Independent interfaces are never assessed — `assess_all` returns nothing when no
channel exists, so an ordinary switch is not reported as broken.

### NAT/PAT — `afc4c7b`

Configured translation: static, dynamic pool, PAT overload, ACL-selected traffic.
Missing roles, undefined pools and an interface marked both inside and outside are
detected without any packet.

PAT port assignments are never guessed; the result says the port depends on
runtime allocation order.

### IPv6 — `2cd7704`

On-link by configured prefix, not mask comparison. Link-local next hops reported
`UNDECIDED` without an outgoing interface. The same link-local on two interfaces
is normal; only global duplicates are conflicts.

### Multi-protocol journey — `72b8b2d`

Stages in packet order: routing → ACL → layer 2 → NAT → return path. **The first
failing stage is named as the cause with its own evidence**, so a blocked VLAN is
not reported as a missing route.

### Analyze Mode integration — `0c416cf`

Device sections now carry STP mode and priorities, EtherChannel details, NAT roles
and counts, IPv6 addresses/routes/forwarding. On the real 33-device lab, 18
sections carry protocol rows.

---

## 2. Four real defects found by tests

1. **IPv6 forwarding conflated with holding an address.** The parser set
   `forwarding=True` for any interface address. In IOS, `ipv6 unicast-routing` is
   a separate global gate — conflating them made a common real fault look healthy.
2. **ACL wildcards treated as addresses.** `permit ip 10.0.0.0 0.0.0.255 any`
   has a wildcard, not an address, at index 3. No dynamic NAT rule could match.
3. **PAT returned the interface name as the translated address.** A name is not an
   address; without the real one the result is now `UNDECIDED`.
4. **The journey passed a device name to ACL matching.** An ACL matches addresses,
   so every deny was silently reported as a pass.

Each was found by a test failing, not by inspection.

---

## 3. Validation

```
pytest -q                    1483 passed, 0 failed, 54 deselected
benchmark_pack              260/260, 0 false-verified
ruff                        clean
Packet Tracer launches      0
```

The 54 deselected are browser and live-simulator tests, both opt-in after the
earlier fix that stopped a default run launching Packet Tracer.

---

## 4. Not completed

| Phase | Status |
|---|---|
| 6 — additional coverage (OSPF auth, DHCP relay, port security, wireless, QoS) | NOT STARTED |
| 8 — hypothesis-driven planner | NOT STARTED |
| 9 — adversarial generator | NOT STARTED |
| 10 — EVOLVE expansion | NOT STARTED |
| 11 — further performance | NOT STARTED |

These need either live simulator comparison to be meaningful (8, 9) or typed
parsing for protocols not yet modelled (6). None is claimed.

---

## 5. Honest limits

1. STP roles between non-root bridges use local cost, not full root-path cost; the
   approximation is recorded in `assumptions`.
2. NAT is configured-translation only. No active translation table is consulted.
3. IPv6 reasoning does not model ND cache contents, which are runtime state.
4. Journey L2 stage checks blocked and shut ports; it does not trace a full
   forwarding tree.
5. Coverage matrix still lists 8 unsupported features, now with STP and
   EtherChannel modelled but not simulator-tested.
