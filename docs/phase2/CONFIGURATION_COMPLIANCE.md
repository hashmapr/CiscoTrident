# Configuration Compliance Engine

Phase 2 · `trident/compliance/`

The compliance engine answers a single question for every requirement:

> Given the trusted `NetworkModel` this snapshot produced, does this device (and
> optionally this interface) satisfy the requirement as stated?

It is a **pure function of the model**. No AI, no network I/O, no mutation, and no
import of `trident.requirements` — a requirement arrives as data
(`kind: str`, `device`, `interface`, `expected`), so the requirements layer can be
built and versioned independently.

---

## 1. Public surface

```python
from trident.compliance import (
    ComplianceStatus, ComplianceResult, Evidence, evaluate, SUPPORTED_KINDS,
)

result = evaluate(
    model,
    kind="ipv4_address",
    device="R1",
    interface="GigabitEthernet0/0",
    expected="10.0.0.1 255.255.255.0",
)
```

### `ComplianceStatus`

| Value | Meaning |
| --- | --- |
| `SATISFIED` | The model positively confirms the requirement. Always carries evidence. |
| `UNSATISFIED` | The model has a value for this entity and it differs from the expectation. |
| `PARTIALLY_SATISFIED` | Some of the requirement holds (e.g. right address, wrong prefix; a subset of VLANs; extra VLANs on a trunk). |
| `INDETERMINATE` | The model cannot decide: ambiguous entity, missing value, or evidence the snapshot does not contain. The `reason` names what is missing. |
| `UNSUPPORTED` | The snapshot does not contain the entity, or the engine has no strategy for this `kind`. Never the same as `UNSATISFIED`. |

### `Evidence`

```python
@dataclass(frozen=True)
class Evidence:
    device: str | None
    interface: str | None
    detail: str
    source: str   # e.g. "running-config line 14: ip address 10.0.0.1 255.255.255.0"
```

`source` names the exact origin of the fact: a numbered running-config line when
one exists, otherwise a named normalised model field
(`"normalized model: InterfaceInfo.ipv4_address"`).

### `ComplianceResult`

```python
@dataclass(frozen=True)
class ComplianceResult:
    requirement_kind: str      # opaque string, echoed from the caller
    device: str | None
    interface: str | None
    expected: str
    actual: str | None
    status: ComplianceStatus
    evidence: tuple[Evidence, ...]
    reason: str
```

Both dataclasses are frozen: a verdict cannot be edited after the fact.

`requirement_kind` is a plain `str` on purpose. Importing the requirement model
would couple this package to a module that is developed separately; the engine
therefore treats the kind as an opaque key into its own handler table.

---

## 2. Supported kinds

| `kind` | Reads | Expectation forms |
| --- | --- | --- |
| `ipv4_address` | `InterfaceInfo.ipv4_address`, cross-checked with the interface's `ip address` line | `10.0.0.1`, `10.0.0.1/24`, `10.0.0.1 255.255.255.0` |
| `ipv4_subnet` | `InterfaceInfo.subnet_mask` / `prefix_length` | `255.255.255.0`, `/24`, `24` |
| `hostname` | top-level `hostname` line, then consensus observations, then `DeviceInfo.hostname` | `R1` |
| `default_route` | `RouteInfo` records whose `device` is the device and whose destination is `0.0.0.0` | next hop IP, or outgoing interface |
| `vlan_assignment` | `InterfaceInfo.vlan_assignments`, falling back to the interface's `switchport` lines | `10`, `10,20`, `10-20` |
| `ssh` | `ip ssh` / `transport input ssh` lines in the device configuration | `enabled`, `present`, `disabled`, `absent` |
| `trunk` | `InterfaceInfo.access_mode`, then `switchport mode` / trunk allowance lines, then `VlanInfo.trunk_allowances` | `trunk`, `access` |

Any other `kind` returns `UNSUPPORTED` with the supported list in the reason.

---

## 3. Honesty rules

These are the contract, not implementation details. Each is covered by a test.

1. **Unknown device → `UNSUPPORTED`.** A requirement about a device that is not in
   the snapshot cannot be judged; it is not a violation.
2. **Ambiguous device → `INDETERMINATE`.** When a name matches two devices the
   engine refuses to pick one and lists the candidates.
3. **Unknown interface → `UNSUPPORTED`.**
4. **Recorded value differs → `UNSATISFIED`.** This is the only path to a failing
   verdict: the model holds a real value and it is wrong.
5. **Cannot determine → `INDETERMINATE`,** with the missing evidence named in
   `reason` (e.g. "no subnet mask is recorded … `InterfaceInfo.subnet_mask` and
   `prefix_length` are both empty").
6. **No `SATISFIED` without evidence.** Enforced twice: every handler builds
   evidence before returning `SATISFIED`, and `_finalize` downgrades any
   `SATISFIED` result with an empty evidence tuple to `INDETERMINATE`. A future
   handler cannot accidentally ship an unsupported positive.

### Why absence is not always a violation

`UNSATISFIED` is reserved for cases where the model **positively** records a
contradiction:

- an explicit `no ip address` line under the interface;
- a default route that exists with a different next hop;
- a switchport that is explicitly in access mode when trunk is required.

Where the snapshot is simply silent — no route records for the device at all, no
running-configuration for the device, an interface with no address fields — the
verdict is `INDETERMINATE`, because "we did not see it" is not "it is not there".

---

## 4. Entity resolution

Device lookup follows the same discipline as `trident.reasoning.operations`:

1. exact key,
2. case-insensitive key,
3. hostname,
4. a single unambiguous alias (strip one `_`-separated segment),
5. otherwise not found — never a nearest guess.

Interface lookup canonicalises the name (`Gi0/0` → `GigabitEthernet0/0`) through
`trident.normalization.values.canonical_interface_name`, then falls back to a
normalised name match. Multiple hits are reported as ambiguous.

---

## 5. Worked examples

### Satisfied

```python
evaluate(model, kind="ipv4_subnet", device="R1",
         interface="Gi0/0", expected="/24")
```

```
status   SATISFIED
actual   255.255.255.0
evidence (Evidence(device='R1', interface='GigabitEthernet0/0',
          detail='GigabitEthernet0/0 subnet mask is 255.255.255.0 (/24)',
          source='running-config line 5: ip address 10.0.0.1 255.255.255.0'),)
```

### Unsatisfied

```python
evaluate(model, kind="hostname", device="R1", interface=None, expected="CORE-R1")
```

```
status   UNSATISFIED
actual   R1
evidence (Evidence(device='R1', interface=None, detail='configured hostname is R1',
          source='running-config line 2: hostname R1'),)
```

### Unsupported

```python
evaluate(model, kind="hostname", device="R99", interface=None, expected="R99")
```

```
status   UNSUPPORTED
actual   None
reason   "device 'R99' is not present in this snapshot (device not found)"
```

### Indeterminate

```python
evaluate(model, kind="trunk", device="R1",
         interface="GigabitEthernet0/1", expected="trunk")
# when only a negotiated mode was recorded
```

```
status   INDETERMINATE
reason   "trunk state of R1 GigabitEthernet0/1 is not determinable: no explicit
          switchport mode, trunk allowance or resolved access_mode was recorded"
```

---

## 6. Partial satisfaction

`PARTIALLY_SATISFIED` exists so a near miss is not flattened into a pass or a fail:

| Kind | Partial when |
| --- | --- |
| `ipv4_address` | address matches, prefix does not (or is unrecorded) — `10.0.0.1/16` vs `10.0.0.1/24` |
| `vlan_assignment` | some expected VLANs present, others missing |
| `vlan_assignment` | all expected VLANs present but extra VLANs also assigned |

---

## 7. Relationship to other layers

```
parsers ──▶ normalization ──▶ NetworkModel ──▶ reasoning (query answers)
                                    │
                                    └────────▶ compliance (requirement verdicts)
                                    │
                                    └────────▶ knowledge (offline reference only)
```

Compliance never re-parses files and never consults the knowledge corpus. It
consumes the normalised model plus the raw `DeviceInfo.configuration` lines that
the model already carries, so every verdict is traceable to a snapshot artifact.

---

## 8. Tests

`tests/test_phase2/test_compliance.py`

- satisfied case for each of the seven kinds
- unsatisfied (wrong value) per kind, plus partial cases
- unsupported for an unknown device, unknown interface and unknown kind
- indeterminate for a missing interface, an ambiguous device, an unrepresented
  route table, an undeterminable trunk and a device with no configuration
- a parametrised invariant asserting every `SATISFIED` carries evidence
- a whole-matrix sweep scanning all probe pairs for an evidence-free `SATISFIED`
- an explicit assertion that `UNSUPPORTED is not UNSATISFIED`
- frozen-dataclass check

Run:

```bash
.venv/bin/python -m pytest tests/test_phase2/test_compliance.py -q
.venv/bin/python -m ruff check trident/compliance tests/test_phase2
```
