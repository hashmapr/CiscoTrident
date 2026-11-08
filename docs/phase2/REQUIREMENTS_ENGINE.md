# RequirementEngine — Phase 2

Deterministic translation of a practice-lab instruction sheet (free text, e.g. a
CyberPatriot / NetAcad lab page) into structured, testable configuration
requirements.

```
free text ──► parse_requirements() ──► list[Requirement]
```

This is a **rule engine, not a language model**. Every line is matched against a
fixed set of audited regular expressions. There is no I/O, no network access, no
randomness, and no model call. The same input always returns the identical list,
in source order, with sequential ids (`REQ-0001`, `REQ-0002`, ...).

## Public API

```python
from trident.requirements import (
    Requirement, RequirementKind, RequirementStatus, parse_requirements,
)

def parse_requirements(text: str) -> list[Requirement]: ...
```

### `Requirement`

```python
@dataclass(frozen=True, slots=True)
class Requirement:
    id: str                     # REQ-0001, sequential in source order
    kind: RequirementKind
    device: str | None          # only ever a name literally present in the text
    interface: str | None       # canonicalised (Gi0/1 -> GigabitEthernet0/1)
    expected: str               # the testable value
    source_text: str            # verbatim source line
    source_line: int            # 1-based line number in the input
    status: RequirementStatus   # PARSED | UNSUPPORTED | AMBIGUOUS
    confidence: str             # "explicit" | "inferred"
    notes: list[str]            # reasons, group scope, peer endpoints, ...
```

### `RequirementKind`

`IPV4_ADDRESS`, `IPV4_SUBNET`, `IPV6_ADDRESS`, `VLAN_ASSIGNMENT`, `TRUNK`,
`STATIC_ROUTE`, `DEFAULT_ROUTE`, `OSPF`, `DHCP`, `DNS`, `NAT`, `ACL`,
`INTERFACE_ENABLE`, `SSH`, `SECURITY`, `WIRELESS`, `CONNECTIVITY`, `UNKNOWN`.

### `RequirementStatus`

| Status | Meaning |
| --- | --- |
| `PARSED` | Every required slot was stated literally; the requirement is testable as written. |
| `AMBIGUOUS` | The intent was recognised but a required slot (device, interface, address, next-hop, VLAN id, trunk endpoint) is missing or invalid. The requirement is **not** completed by inference. |
| `UNSUPPORTED` | No grammar matched. `kind` is `UNKNOWN`, `expected` is `""`, `device`/`interface` are `None`. The line is preserved for the operator and produces no configuration demand. |

At most one `Requirement` is emitted per non-blank source line. Blank lines and
pure list markers are skipped; line numbers always refer to the original input.

## Supported grammar

List bullets (`-`, `*`, `•`, `1.`, `1)`) and `Step N:` prefixes are stripped
before matching. Matching is case-insensitive.

### IPv4 / IPv6 address

| Example | Result |
| --- | --- |
| `Configure 192.168.10.1/24 on R1 GigabitEthernet0/0` | `IPV4_ADDRESS`, R1 / GigabitEthernet0/0 / `192.168.10.1/24` |
| `Configure 10.0.0.1/30 on R2 Gi0/1` | `IPV4_ADDRESS`, interface canonicalised to `GigabitEthernet0/1` |
| `Configure 192.168.1.1 255.255.255.0 on R1 Fa0/0` | `IPV4_ADDRESS`, expressed as `192.168.1.1/24` |
| `Configure 192.168.10.0/24 on R1 Gi0/0` | `IPV4_SUBNET` (network address, prefix ≤ 30) |
| `Configure 2001:db8::1/64 on R1 GigabitEthernet0/0` | `IPV6_ADDRESS` |

Address classification: a v4 value whose address equals the network address of
its prefix (and prefix ≤ 30) is `IPV4_SUBNET`; otherwise `IPV4_ADDRESS`. Mask
input is normalised to CIDR in `expected`, with the original mask recorded in
`notes`.

### Hostname → `SECURITY`

The enum has no `HOSTNAME` member, so hostname instructions are reported under
`SECURITY` per the Phase 2 contract.

| Example | Result |
| --- | --- |
| `Set the hostname of SW1 to CoreSwitch` | `SECURITY`, SW1, `hostname CoreSwitch` |
| `Set SW1's hostname to CoreSwitch` | `SECURITY`, SW1 |
| `Set the hostname to CoreSwitch` | `SECURITY`, `AMBIGUOUS` — device not named |

### VLAN assignment

| Example | Result |
| --- | --- |
| `Assign VLAN 20 to the Fa0/5 port on SW2` | `VLAN_ASSIGNMENT`, SW2 / `FastEthernet0/5` / `vlan 20` |
| `Assign Fa0/5 on SW2 to VLAN 20` | `VLAN_ASSIGNMENT`, SW2 / `FastEthernet0/5` / `vlan 20` |
| `Place all PCs on VLAN 10` | `VLAN_ASSIGNMENT`, `device=None`, `confidence="inferred"`, note `group scope: all PCs; no specific device named` |
| `Assign VLAN 9999 to the Fa0/5 port on SW2` | `AMBIGUOUS` — VLAN id outside 1–4094 |

Group-scoped instructions never pick a representative device. The only group
forms accepted are `all/every <PCs|hosts|computers|workstations|end devices|
endpoints|users|clients>` and `everyone`/`all`.

### Trunk

| Example | Result |
| --- | --- |
| `Create a trunk between SW1 Gi0/1 and SW2 Gi0/1` | `TRUNK`, SW1 / `GigabitEthernet0/1`, `expected="trunk SW1 GigabitEthernet0/1 <-> SW2 GigabitEthernet0/1"`, peer recorded in `notes` |
| `Configure a trunk between SW1 and SW2` | `AMBIGUOUS` — both endpoints and their interfaces must be stated |

### Routes

| Example | Result |
| --- | --- |
| `Configure a default route on R1 pointing to 10.1.1.2` | `DEFAULT_ROUTE`, R1, `0.0.0.0/0 via 10.1.1.2` |
| `Configure a default route on R1` | `AMBIGUOUS` — next hop not stated |
| `On R1 configure ip route 0.0.0.0 0.0.0.0 10.1.1.2` | `DEFAULT_ROUTE`, R1, `0.0.0.0/0 via 10.1.1.2` |
| `On R1 configure ip route 172.16.0.0 255.255.0.0 10.1.1.2` | `STATIC_ROUTE`, R1, `172.16.0.0/16 via 10.1.1.2` |
| `Configure a static route on R1 to 172.16.0.0/16 via 10.1.1.2` | `STATIC_ROUTE`, R1 |

Next-hop connectors recognised: `pointing to`, `points to`, `via`, `through`,
`towards`, `to`. If a route line names a dynamic protocol (`OSPF`, `EIGRP`,
`RIP`, `BGP`, `IS-IS`) the static-route rule declines, so the line is not
misclassified.

### SSH

| Example | Result |
| --- | --- |
| `Enable SSH on R1` | `SSH`, R1, `ssh enabled` |
| `Enable SSH` | `AMBIGUOUS` — device not named |

`PARSED` SSH requirements carry the note that a local username and domain name
are also required.

### Interface enable

| Example | Result |
| --- | --- |
| `Enable interface Gi0/2 on SW1` | `INTERFACE_ENABLE`, SW1 / `GigabitEthernet0/2`, `no shutdown` |
| `No shutdown on R1 Gi0/2` | `INTERFACE_ENABLE`, R1 / `GigabitEthernet0/2` |

### Other kinds

| Example | Result |
| --- | --- |
| `Configure OSPF on R1` | `OSPF`, R1 |
| `Configure OSPF process 1 on R1 network 10.0.0.0 0.0.0.255 area 0` | `OSPF`, R1, process and network captured |
| `Configure DHCP pool LAN on R1` | `DHCP`, R1 |
| `Configure DNS server 8.8.8.8 on R1` | `DNS`, R1, `dns server 8.8.8.8` |
| `Configure NAT on R1` | `NAT`, R1 |
| `Configure ACL 101 on R1` | `ACL`, R1, `acl 101` |
| `Configure SSID CorpWifi on WLC1` | `WIRELESS`, WLC1 |
| `Verify that PC1 can ping 192.168.10.1` | `CONNECTIVITY`, PC1 |
| `Verify that all PCs can ping 192.168.10.1` | `CONNECTIVITY`, `device=None`, `confidence="inferred"` |

## Refusal semantics

These are the guarantees the tests pin down.

1. **Never invent a device.** `device` is populated only from a token that is
   literally in the text *and* passes the device-name filter. The filter rejects
   an explicit stopword list (quantifiers, pronouns, interface nouns, protocol
   names, verbs), rejects anything that canonicalises to a known interface
   prefix (`Gi0/0` is an interface, not a device), and rejects tokens that do not
   match `[A-Za-z][A-Za-z0-9_-]*` (so dotted quads are never devices).
2. **Never fill a missing slot.** Missing device → `AMBIGUOUS`. Missing next
   hop, interface, VLAN id, or trunk endpoint → `AMBIGUOUS`. No defaults, no
   "closest match", no guessing from a nearby device name.
3. **Never promote prose.** A line no rule recognises is `UNSUPPORTED` with
   `kind=UNKNOWN` and a note saying the line was ignored. It is not
   heuristically reclassified.
4. **Nothing is silently dropped.** Every non-blank line yields exactly one
   `Requirement`, so an operator can audit the full instruction sheet against
   the parse result.
5. **Invalid values are surfaced, not repaired.** An out-of-range VLAN id or an
   invalid IPv4 address yields `AMBIGUOUS` with a note, never a corrected value.

Examples of lines that deliberately come back `UNSUPPORTED`:

```
Review the lab topology diagram before starting
Save the configuration before you close the window
Ask the instructor to check your progress
Open Packet Tracer
```

## Integration

`Requirement` is independent of `NetworkModel`; the intended Phase 2 flow is
`parse_requirements(text)` → filter to `PARSED` → compare each requirement's
`device` / `interface` / `expected` against the model built by
`Normalizer.build()`. Group-scoped and `AMBIGUOUS` requirements are reported to
the operator rather than auto-verified, because they name no concrete target.

## Tests

`tests/test_phase2/test_requirements.py` covers:

* a happy path for every `RequirementKind`;
* dotted-mask, IPv6, `ip route` syntax, and interface canonicalisation;
* VLAN range validation;
* `UNSUPPORTED` for prose (`parametrized`);
* `AMBIGUOUS` for missing device / next hop / trunk endpoint / interface;
* empty and whitespace-only input returning `[]`;
* blank-line skipping with source line numbers preserved;
* a dedicated no-fabrication test asserting no device-less instruction ever
  produces a `device`;
* interface tokens never being mistaken for devices;
* sequential, stable ids and deterministic repeat output;
* the frozen dataclass contract.

Verify:

```bash
.venv/bin/python -m pytest tests/test_phase2/test_requirements.py -q
.venv/bin/python -m ruff check trident/requirements tests/test_phase2
```

## Files

| File | Purpose |
| --- | --- |
| `trident/requirements/__init__.py` | Public exports |
| `trident/requirements/model.py` | `Requirement`, `RequirementKind`, `RequirementStatus` |
| `trident/requirements/engine.py` | Rule engine and `parse_requirements` |
| `tests/test_phase2/test_requirements.py` | Test suite |
| `docs/phase2/REQUIREMENTS_ENGINE.md` | This document |
