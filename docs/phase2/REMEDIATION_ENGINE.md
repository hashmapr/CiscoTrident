# IOS Remediation Generator

Phase 2 · `trident/remediation/`

The remediation generator turns **one** compliance verdict into an ordered,
reviewable set of Cisco IOS configuration commands.

> It is a *planner*, not an orchestrator. It never connects to a device, never
> opens a socket, never shells out, and never executes a command. Its output is
> advice a human or change-control process may choose to apply.

---

## 1. Public surface

```python
from trident.remediation import (
    Confidence, RemediationPlan, RemediationStep,
    FORBIDDEN_VERBS, REMEDIABLE_KINDS,
    assert_safe_commands, generate_plan,
)

plan = generate_plan(compliance_result)   # -> RemediationPlan | None
```

`generate_plan` accepts a `trident.compliance.ComplianceResult` and returns a
`RemediationPlan`, or `None` when there is nothing safe to suggest.

### `Confidence`

| Value | Meaning |
| --- | --- |
| `HIGH` | The previously observed value is known in full **and** the required value is unambiguous, so both the change and the rollback are exact. |
| `MEDIUM` | The change is exact but derived — e.g. a classful mask synthesised for a requirement that names only an address. |
| `LOW` | At least one input is unknown. The plan carries **no** rollback (see §4). |

### `RemediationStep`

```python
@dataclass(frozen=True)
class RemediationStep:
    order: int
    commands: tuple[str, ...]   # IOS commands, configuration mode
    rationale: str
```

A step may carry zero commands when the plan can only explain why no command is
safe (for example, an `ipv4_subnet` repair whose current address is unknown and
for which IOS has no mask-only command). Such a step is always paired with
`Confidence.LOW`.

### `RemediationPlan`

```python
@dataclass(frozen=True)
class RemediationPlan:
    device: str
    interface: str | None
    current_state: str
    required_state: str
    steps: tuple[RemediationStep, ...]
    verification_commands: tuple[str, ...]
    rollback_commands: tuple[str, ...]
    confidence: Confidence
    evidence: tuple[str, ...]
    advisory_only: bool = True
```

`advisory_only` can never be `False`: `RemediationPlan.__post_init__` raises
`ValueError` for any other value. "This engine never executes" is therefore a
property of the type, not a promise in a docstring.

---

## 2. When a plan is produced

| Verdict status | Plan |
| --- | --- |
| `UNSATISFIED` | Yes, when the `requirement_kind` has a repair strategy. |
| `PARTIALLY_SATISFIED` | Yes — there is still a concrete delta to correct. |
| `SATISFIED` | **`None`** — nothing to fix. |
| `UNSUPPORTED` | **`None`** — the snapshot cannot speak to the requirement. |
| `INDETERMINATE` | **`None`** — the verdict is ambiguous or missing evidence; acting on it would be a guess. |

A kind outside `REMEDIABLE_KINDS`, a missing device, or requirement text that
cannot be turned into a valid IOS command also yields `None`.

---

## 3. Supported repairs (`REMEDIABLE_KINDS`)

| Kind | Commands (configuration mode) |
| --- | --- |
| `ipv4_address` | `interface <if>` → `ip address <ip> <mask>` → `no shutdown` |
| `ipv4_subnet` | `interface <if>` → `ip address <current-ip> <corrected-mask>` |
| `hostname` | `hostname <name>` |
| `default_route` | `ip route 0.0.0.0 0.0.0.0 <next-hop>` |
| `vlan_assignment` | `interface <if>` → `switchport mode access` → `switchport access vlan <id>` |
| `ssh` | `ip domain-name <domain>` → `crypto key generate rsa modulus 2048` → `ip ssh version 2` → `line vty 0 4` → `transport input ssh` |

Notes on individual kinds:

* **`ipv4_address`** — when the requirement states a prefix (`/24`) or a mask,
  that mask is used and confidence is `HIGH`. When it states only an address, a
  classful default mask is derived, confidence is `MEDIUM`, and the plan says so.
* **`ipv4_subnet`** — IOS has no mask-only command, so the repair re-issues
  `ip address <current-ip> <mask>`. The current address is recovered from the
  verdict and its evidence. If it cannot be recovered, the step carries no
  commands and the plan is `LOW` with no rollback.
* **`ssh`** — only the "SSH should be enabled" direction is repaired. Disabling
  SSH would require key destruction, which is out of scope and unsafe.
  `trident.local` is a placeholder domain that must be replaced.

---

## 4. Safety rules

1. **Never executes.** `advisory_only` is always `True`; the dataclass refuses
   any other value. There is no device connection code in this package.
2. **No destructive verbs.** `FORBIDDEN_VERBS` — `reload`, `erase`, `delete`,
   `format`, `wipe`, `zeroize`, `factory-reset` — are rejected by
   `assert_safe_commands`. Every generated plan is validated against that
   blocklist at construction time (`_make_plan`), so a planner bug cannot emit
   one.
3. **Rollback restores the prior value, or is empty.** When the previous value
   is known, `rollback_commands` restores it exactly. When it is unknown,
   `rollback_commands` is `()` and confidence is `LOW`. A plan that is not `LOW`
   *must* carry a rollback; a `LOW` plan *must not*. Both directions are enforced
   in `_make_plan`.
4. **`HIGH` only on complete knowledge.** `HIGH` requires a known current state
   **and** an unambiguous required value. Anything derived or partially known is
   `MEDIUM` or `LOW`.

Invariants enforced in code:

```python
if rollback_commands and confidence is Confidence.LOW:  raise ValueError(...)
if not rollback_commands and confidence is not Confidence.LOW: raise ValueError(...)
assert_safe_commands(all_commands)
```

---

## 5. Example

```python
from trident.compliance import evaluate
from trident.remediation import generate_plan

result = evaluate(
    model,
    kind="ipv4_address",
    device="R1",
    interface="GigabitEthernet0/0",
    expected="10.0.0.1 255.255.255.0",
)

plan = generate_plan(result)
if plan is not None:
    print(plan.confidence)               # Confidence.HIGH
    for step in plan.steps:
        print(step.order, step.commands, "—", step.rationale)
    print(plan.rollback_commands)
    print(plan.verification_commands)
```

Rendered output for the case above:

```
1 ('interface GigabitEthernet0/0',) — enter the configuration context ...
2 ('ip address 10.0.0.1 255.255.255.0',) — set the required address ...
3 ('no shutdown',) — ensure the interface is administratively up ...
('interface GigabitEthernet0/0', 'ip address 10.0.0.9 255.255.255.0')
('show running-config interface GigabitEthernet0/0', 'show ip interface brief')
```

---

## 6. Tests

`tests/test_phase2/test_remediation.py` covers:

* a plan for every supported kind
* `None` for `SATISFIED`, `UNSUPPORTED`, `INDETERMINATE`, and unsupported kinds
* `advisory_only` is `True` on every plan, and cannot be constructed `False`
* the destructive-verb blocklist, checked both directly and against every
  generated plan
* empty rollback + `LOW` confidence when the prior state is unknown
