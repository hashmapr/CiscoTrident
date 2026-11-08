# Configuration Security Auditor

Phase 2 · `trident/security/`

The security auditor reads the **recorded running-configuration text** of every
device in the trusted `NetworkModel` and reports evidence-based findings against
a named baseline.

It is a *pure function of the model*: no device connection, no socket, no shell,
no mutation, and no AI. `remediation_hint` is advisory prose — nothing in this
package executes, applies, or queues anything.

---

## 1. Public surface

```python
from trident.security import audit, AuditReport, Finding, FindingStatus, Severity

report = audit(model)                       # baseline="cisco-basic"
report = audit(model, baseline="cisco-basic")

report.findings          # tuple[Finding, ...]
report.checked_devices   # int
report.baseline          # str
report.by_severity()     # {"CRITICAL": n, "HIGH": n, "MEDIUM": n, "LOW": n}
report.violations()      # only CONFIRMED_VIOLATION findings
```

### `FindingStatus`

| Value | Meaning |
| --- | --- |
| `CONFIRMED_VIOLATION` | An explicitly bad directive is present in the recorded config (or, for "missing X" checks, the required directive is verifiably absent). |
| `HARDENING_SUGGESTION` | A good practice is not shown by the config. Absence alone — never a confirmed violation except where the check *is* "missing X". |
| `COMPLIANT` | A real configuration line positively satisfies the check. Always carries that line as evidence. |
| `INDETERMINATE` | The recorded text supports neither the good nor the bad state (e.g. a presence check with no counter-directive to cite). |
| `UNSUPPORTED` | The device records no configuration at all. Never `COMPLIANT`. |

### `Severity`

`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. Severity is a property of the baseline
check, not of the auditor's confidence — an `INDETERMINATE` finding keeps its
check's weight so unreviewed risk is not silently downgraded.

### `Finding`

```python
@dataclass(frozen=True)
class Finding:
    check_id: str
    device: str | None
    interface: str | None
    status: FindingStatus
    severity: Severity
    summary: str
    evidence: tuple[str, ...]   # "running-config line N: <text>" or "not present: ..."
    baseline: str
    remediation_hint: str       # advisory text only
```

There is deliberately **no** `commands`, `apply`, `execute`, `deploy` or
`dry_run` field. "This auditor never executes" is a property of the type, not a
promise in a docstring.

### `AuditReport`

```python
@dataclass(frozen=True)
class AuditReport:
    findings: tuple[Finding, ...]
    checked_devices: int
    baseline: str
```

`by_severity()` always returns all four keys (zero-filled), so a caller never
has to distinguish "no critical findings" from "critical was not counted".

---

## 2. Checks in the `cisco-basic` baseline

| `check_id` | Rule | Severity | Status when it fires |
| --- | --- | --- | --- |
| `telnet-enabled` | A vty block has `transport input telnet`/`all`, or has **no** `transport input` at all (the IOS default permits Telnet). `transport input ssh` is compliant. | HIGH | `CONFIRMED_VIOLATION` |
| `ssh-missing` | `ip ssh version 2` absent on a device with vty lines. `no ip ssh version 2` is an explicit violation. | MEDIUM | `CONFIRMED_VIOLATION` |
| `no-enable-secret` | Neither `enable secret` nor `enable password` recorded. With `enable secret` → compliant; with only `enable password` → hardening suggestion pointing at the cleartext check. | HIGH | `CONFIRMED_VIOLATION` |
| `password-in-config` | A cleartext `enable password` line is present. | CRITICAL | `CONFIRMED_VIOLATION` |
| `vty-no-acl` | A vty block has no `access-class`. | MEDIUM | `HARDENING_SUGGESTION` |
| `unused-ports-open` | An access port has neither `description` nor `shutdown`. | LOW | `HARDENING_SUGGESTION` |
| `port-security-missing` | An access port has no `switchport port-security`. | LOW | `HARDENING_SUGGESTION` |
| `cdp-enabled-global` | `no cdp run` is absent (CDP on, which is the IOS default). | LOW | `HARDENING_SUGGESTION` |
| `http-server` | `ip http server` present. | HIGH | `CONFIRMED_VIOLATION` |
| `snmp-public` | `snmp-server community public` present. | CRITICAL | `CONFIRMED_VIOLATION` |

`telnet-enabled`, `ssh-missing` and `vty-no-acl` report once per device (the worst
vty block governs). `unused-ports-open` and `port-security-missing` report once
per access port and set `Finding.interface`.

### Notes on judgement calls

- **Presence checks with no counter-directive are `INDETERMINATE`, not
  `COMPLIANT`.** If the config contains neither `ip http server` nor
  `no ip http server`, the recorded text does not state the good state, so the
  auditor says so rather than inferring it.
- **`snmp-public` covers only the literal `public` community string.** Its
  `INDETERMINATE` summary says that explicitly, so a green result here is never
  read as "SNMP is safe".
- **"Access port" means `switchport mode access` is explicitly present.** A
  routed port (`no switchport`) or a port with no mode statement is not audited
  for port security, because the recorded text does not establish the mode.
- **Credential values are never echoed.** `enable password`/`enable secret`
  evidence is emitted as `running-config line N: enable password <redacted>`.

---

## 3. Honesty rules (enforced, not documented)

1. **No configuration ⇒ no verdict.** A device whose `DeviceInfo.configuration`
   is empty gets one `UNSUPPORTED` finding per baseline check. There is no path
   that turns an empty config into `COMPLIANT`.
2. **`COMPLIANT` requires positive evidence.** `Finding.__post_init__` raises if
   a `COMPLIANT` finding has no evidence entry that is a real configuration line
   (an absence note alone is rejected).
3. **Every finding has evidence.** A finding with zero evidence entries cannot
   be constructed.
4. **Absence ≠ violation.** Only `ssh-missing` and `no-enable-secret` — checks
   whose definition is literally "missing X" — report a confirmed violation
   built on an absence note. Everywhere else absence is a hardening suggestion
   or an indeterminate.
5. **One baseline per report.** A finding that cites a baseline other than the
   report's baseline is rejected at construction.
6. **Never a compromise claim.** Findings are configuration observations.
   Summaries describe directives and their absence; nothing asserts that a
   device has been breached, is attacker-controlled, or is currently exposed.
7. **Advisory only.** `remediation_hint` is text. The `Finding` type has no field
   that could name an executed command.

---

## 4. Worked example

```python
from trident.models import DeviceInfo, NetworkModel
from trident.security import audit

model = NetworkModel(devices={
    "SW1": DeviceInfo(id="SW1", name="SW1", configuration=[
        "hostname SW1",
        "enable password cisco",
        "ip http server",
        "snmp-server community public RO",
        "line vty 0 4",
        " transport input telnet",
    ]),
    "SW2": DeviceInfo(id="SW2", name="SW2", configuration=[
        "hostname SW2",
        "enable secret 9 $9$x",
        "ip ssh version 2",
        "no cdp run",
        "line vty 0 4",
        " access-class 10 in",
        " transport input ssh",
    ]),
    "SW3": DeviceInfo(id="SW3", name="SW3", configuration=[]),
})

report = audit(model)
print(report.checked_devices)   # 3 devices in the model
print(report.by_severity())     # {'CRITICAL': 6, 'HIGH': 9, 'MEDIUM': 6, 'LOW': 5}
for finding in report.violations():
    print(finding.check_id, finding.severity.value)
```

Real output from the implementation above (three devices: one insecure, one
hardened, one with no recorded config):

```
checked_devices: 3 | baseline: cisco-basic
by_severity: {'CRITICAL': 6, 'HIGH': 9, 'MEDIUM': 6, 'LOW': 5}
violations: 5 ['telnet-enabled', 'ssh-missing', 'password-in-config', 'http-server', 'snmp-public']
CONFIRMED_VIOLATION | HIGH     | telnet-enabled     | ('running-config line 6: transport input telnet',)
CONFIRMED_VIOLATION | CRITICAL | password-in-config | ('running-config line 2: enable password <redacted>',)
SW3 statuses: ['UNSUPPORTED']
```

The last line is the honesty rule in practice: the device with no recorded
configuration is unsupported for all ten checks, and contributes nothing to
`violations()`.

---

## 5. Ordering and determinism

Findings are emitted in a fixed order: devices sorted by model key, checks in
baseline order, then per-interface findings in configuration order. Auditing the
same model twice produces equal `AuditReport` values.

---

## 6. Extending

Add a check by writing a function `(_Ctx, _ParsedConfig) -> tuple[Finding, ...]`
and appending a `_Check` entry to `_CISCO_BASIC` (or a new baseline tuple in
`BASELINES`). A new baseline is additive: `BASELINES["my-baseline"] = (...)` and
`CHECK_IDS` follows automatically.

`audit()` raises `ValueError` for an unknown baseline rather than silently
falling back — an empty report is not an acceptable substitute for "I do not
know that baseline".
